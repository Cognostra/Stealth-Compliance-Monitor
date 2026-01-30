/**
 * Smart False Positive Filter
 *
 * Post-processor service that reduces false positives in scan results:
 * - Duplicate merging (same URL + type across scanners)
 * - Environment noise filtering (localhost, dev builds, test fixtures)
 * - Correlation boosting (XSS + missing CSP = higher confidence)
 * - Severity adjustment (findings behind auth = lower risk)
 * - Confidence scoring based on evidence quality
 */

import { logger } from '../utils/logger.js';

export interface RawFinding {
    scanner: string;
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
    description: string;
    evidence: string;
    url: string;
    directive?: string;
    endpoint?: string;
    [key: string]: unknown;
}

export interface FilteredFinding {
    original: RawFinding;
    scanner: string;
    confidence: number;
    falsePositiveProbability: number;
    correlatedWith: string[];
    adjustedSeverity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
    deduplicatedCount: number;
    filterReasons: string[];
}

export interface FilterConfig {
    threshold: number;
    enableDedup: boolean;
    enableNoiseFilter: boolean;
    enableCorrelation: boolean;
    enableSeverityAdjust: boolean;
}

const DEFAULT_CONFIG: FilterConfig = {
    threshold: 0.3,
    enableDedup: true,
    enableNoiseFilter: true,
    enableCorrelation: true,
    enableSeverityAdjust: true,
};

// Patterns indicating noise / dev environment
const NOISE_PATTERNS = [
    /localhost(:\d+)?/i,
    /127\.0\.0\.1/,
    /0\.0\.0\.0/,
    /\.local(:\d+)?$/,
    /\.dev(:\d+)?$/,
    /\.test$/,
    /\.example\./,
    /webpack-dev-server/i,
    /hot-update/i,
    /__webpack_hmr/i,
    /\.map$/,
    /sourcemap/i,
    /devtools/i,
    /react-devtools/i,
    /chrome-extension:\/\//,
    /moz-extension:\/\//,
];

// Correlation rules: if both findings exist, boost confidence
const CORRELATION_RULES: Array<{
    findingA: { scanner?: string; type: string };
    findingB: { scanner?: string; type: string };
    boostA: number;
    boostB: number;
    description: string;
}> = [
    {
        findingA: { type: 'xss' },
        findingB: { type: 'missing-csp' },
        boostA: 0.2,
        boostB: 0.1,
        description: 'XSS finding correlated with missing CSP',
    },
    {
        findingA: { type: 'xss' },
        findingB: { type: 'unsafe-inline' },
        boostA: 0.15,
        boostB: 0.1,
        description: 'XSS finding correlated with unsafe-inline CSP',
    },
    {
        findingA: { type: 'sensitive-data' },
        findingB: { type: 'plaintext' },
        boostA: 0.2,
        boostB: 0.15,
        description: 'Sensitive data over plaintext connection',
    },
    {
        findingA: { type: 'introspection' },
        findingB: { type: 'mutation-auth' },
        boostA: 0.1,
        boostB: 0.2,
        description: 'GraphQL introspection with mutation auth bypass',
    },
    {
        findingA: { type: 'sqli' },
        findingB: { type: 'error-disclosure' },
        boostA: 0.15,
        boostB: 0.1,
        description: 'SQL injection correlated with error disclosure',
    },
];

// Base confidence by severity
const SEVERITY_CONFIDENCE: Record<string, number> = {
    critical: 0.9,
    high: 0.8,
    medium: 0.6,
    low: 0.4,
    informational: 0.2,
};

export class FalsePositiveFilter {
    private config: FilterConfig;

    constructor(config: Partial<FilterConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Filter and deduplicate findings from all scanners.
     */
    filter(findings: RawFinding[]): FilteredFinding[] {
        let processed = findings.map(f => this.initFilteredFinding(f));

        if (this.config.enableDedup) {
            processed = this.deduplicateFindings(processed);
        }

        if (this.config.enableNoiseFilter) {
            processed = this.filterNoise(processed);
        }

        if (this.config.enableCorrelation) {
            this.applyCorrelations(processed);
        }

        if (this.config.enableSeverityAdjust) {
            this.adjustSeverities(processed);
        }

        // Filter out findings below confidence threshold
        const filtered = processed.filter(f => f.confidence >= this.config.threshold);

        const removed = processed.length - filtered.length;
        if (removed > 0) {
            logger.info(`[FalsePositiveFilter] Filtered ${removed}/${processed.length} low-confidence findings`);
        }

        return filtered;
    }

    private initFilteredFinding(raw: RawFinding): FilteredFinding {
        return {
            original: raw,
            scanner: raw.scanner,
            confidence: SEVERITY_CONFIDENCE[raw.severity] || 0.5,
            falsePositiveProbability: 0,
            correlatedWith: [],
            adjustedSeverity: raw.severity,
            deduplicatedCount: 1,
            filterReasons: [],
        };
    }

    /**
     * Merge duplicate findings from different scanners or same scanner.
     */
    private deduplicateFindings(findings: FilteredFinding[]): FilteredFinding[] {
        const groups = new Map<string, FilteredFinding[]>();

        for (const finding of findings) {
            const url = finding.original.url || finding.original.endpoint || '';
            const key = `${finding.original.type}:${normalizeUrl(url)}`;
            const existing = groups.get(key);
            if (existing) {
                existing.push(finding);
            } else {
                groups.set(key, [finding]);
            }
        }

        const deduped: FilteredFinding[] = [];
        for (const [, group] of groups) {
            // Keep the highest-confidence finding, merge metadata
            group.sort((a, b) => b.confidence - a.confidence);
            const primary = group[0];
            primary.deduplicatedCount = group.length;

            if (group.length > 1) {
                // Multiple scanners found the same issue = higher confidence
                primary.confidence = Math.min(1.0, primary.confidence + 0.1 * (group.length - 1));
                primary.filterReasons.push(`Merged ${group.length} duplicate findings`);

                for (let i = 1; i < group.length; i++) {
                    if (group[i].scanner !== primary.scanner) {
                        primary.correlatedWith.push(`${group[i].scanner}:${group[i].original.type}`);
                    }
                }
            }

            deduped.push(primary);
        }

        return deduped;
    }

    /**
     * Filter out findings that match noise patterns.
     */
    private filterNoise(findings: FilteredFinding[]): FilteredFinding[] {
        for (const finding of findings) {
            const url = finding.original.url || finding.original.endpoint || '';

            for (const pattern of NOISE_PATTERNS) {
                if (pattern.test(url)) {
                    finding.confidence *= 0.3;
                    finding.falsePositiveProbability += 0.5;
                    finding.filterReasons.push(`URL matches noise pattern: ${pattern.source}`);
                    break;
                }
            }

            // Dev build indicators in evidence
            const evidence = finding.original.evidence || '';
            if (/development|debug|dev\s*mode/i.test(evidence)) {
                finding.confidence *= 0.5;
                finding.falsePositiveProbability += 0.3;
                finding.filterReasons.push('Evidence suggests development environment');
            }

            // Test data patterns
            if (/test@|example\.com|john\s*doe|jane\s*doe|lorem\s*ipsum/i.test(evidence)) {
                finding.confidence *= 0.4;
                finding.falsePositiveProbability += 0.4;
                finding.filterReasons.push('Evidence contains test/placeholder data');
            }
        }

        return findings;
    }

    /**
     * Apply correlation rules to boost confidence of related findings.
     */
    private applyCorrelations(findings: FilteredFinding[]): void {
        for (const rule of CORRELATION_RULES) {
            const matchesA = findings.filter(f => matchesFindingPattern(f, rule.findingA));
            const matchesB = findings.filter(f => matchesFindingPattern(f, rule.findingB));

            if (matchesA.length > 0 && matchesB.length > 0) {
                for (const a of matchesA) {
                    a.confidence = Math.min(1.0, a.confidence + rule.boostA);
                    a.correlatedWith.push(rule.description);
                    a.filterReasons.push(`Boosted by correlation: ${rule.description}`);
                }
                for (const b of matchesB) {
                    b.confidence = Math.min(1.0, b.confidence + rule.boostB);
                    b.correlatedWith.push(rule.description);
                    b.filterReasons.push(`Boosted by correlation: ${rule.description}`);
                }
            }
        }
    }

    /**
     * Adjust severity based on context (auth, environment, etc).
     */
    private adjustSeverities(findings: FilteredFinding[]): void {
        for (const finding of findings) {
            const url = finding.original.url || '';

            // Findings on authenticated endpoints may be less severe
            if (finding.original.evidence?.includes('behind auth') || finding.original.evidence?.includes('authenticated')) {
                if (finding.adjustedSeverity === 'medium') {
                    finding.adjustedSeverity = 'low';
                    finding.filterReasons.push('Severity lowered: behind authentication');
                }
            }

            // Rate limiting findings are less severe when behind auth
            if (finding.original.type === 'rate-limit' && url.includes('/api/')) {
                finding.confidence *= 0.8;
                finding.filterReasons.push('Rate limiting finding on API endpoint - may be intentional');
            }

            // Informational findings with low confidence
            if (finding.adjustedSeverity === 'informational' || finding.adjustedSeverity === 'low') {
                finding.falsePositiveProbability = Math.max(finding.falsePositiveProbability, 0.3);
            }
        }
    }
}

/**
 * Normalize URL for deduplication.
 */
function normalizeUrl(url: string): string {
    try {
        const parsed = new URL(url);
        // Remove query params and fragments for grouping
        return `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, '');
    } catch {
        return url.replace(/[?#].*$/, '').replace(/\/+$/, '');
    }
}

/**
 * Check if a finding matches a pattern.
 */
function matchesFindingPattern(
    finding: FilteredFinding,
    pattern: { scanner?: string; type: string }
): boolean {
    const typeMatch = finding.original.type === pattern.type ||
        finding.original.type.includes(pattern.type) ||
        finding.original.description?.toLowerCase().includes(pattern.type);

    if (pattern.scanner) {
        return typeMatch && finding.scanner === pattern.scanner;
    }
    return typeMatch;
}
