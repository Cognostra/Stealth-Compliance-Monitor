/**
 * Performance Baseline
 * Store, compare, and track Lighthouse performance scores over time
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Lighthouse score metrics
 */
export interface LighthouseScores {
    performance: number;
    accessibility: number;
    bestPractices: number;
    seo: number;
    pwa?: number;
}

/**
 * Baseline entry for a single URL
 */
export interface PerformanceBaselineEntry {
    url: string;
    scores: LighthouseScores;
    timestamp: string;
    version: string;
}

/**
 * Full baseline file format
 */
export interface PerformanceBaselineFile {
    version: string;
    createdAt: string;
    updatedAt: string;
    entries: Record<string, PerformanceBaselineEntry>;
}

/**
 * Comparison result for a single metric
 */
export interface MetricComparison {
    metric: keyof LighthouseScores;
    baseline: number;
    current: number;
    delta: number;
    percentChange: number;
    status: 'improved' | 'regressed' | 'stable';
}

/**
 * Comparison result for a URL
 */
export interface BaselineComparison {
    url: string;
    hasBaseline: boolean;
    metrics: MetricComparison[];
    overallStatus: 'improved' | 'regressed' | 'stable' | 'new';
    regressionCount: number;
}

const BASELINE_VERSION = '1.0';
const DEFAULT_BASELINE_FILE = '.performance-baseline.json';

/**
 * Threshold for considering a change significant (percentage points)
 */
const REGRESSION_THRESHOLD = -5; // 5% regression triggers warning
const IMPROVEMENT_THRESHOLD = 5;  // 5% improvement is notable

/**
 * Performance Baseline Service
 */
export class PerformanceBaseline {
    private baselinePath: string;
    private baseline: PerformanceBaselineFile | null = null;

    constructor(baselinePath?: string) {
        this.baselinePath = baselinePath || DEFAULT_BASELINE_FILE;
    }

    /**
     * Load baseline from file
     */
    load(): boolean {
        const fullPath = path.isAbsolute(this.baselinePath)
            ? this.baselinePath
            : path.resolve(process.cwd(), this.baselinePath);

        if (!fs.existsSync(fullPath)) {
            return false;
        }

        try {
            const content = fs.readFileSync(fullPath, 'utf-8');
            this.baseline = JSON.parse(content) as PerformanceBaselineFile;
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Save baseline to file
     */
    save(): boolean {
        if (!this.baseline) {
            this.baseline = this.createEmptyBaseline();
        }

        const fullPath = path.isAbsolute(this.baselinePath)
            ? this.baselinePath
            : path.resolve(process.cwd(), this.baselinePath);

        try {
            this.baseline.updatedAt = new Date().toISOString();
            fs.writeFileSync(fullPath, JSON.stringify(this.baseline, null, 2), 'utf-8');
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Update or add a baseline entry for a URL
     */
    update(url: string, scores: LighthouseScores): void {
        if (!this.baseline) {
            this.baseline = this.createEmptyBaseline();
        }

        this.baseline.entries[url] = {
            url,
            scores,
            timestamp: new Date().toISOString(),
            version: BASELINE_VERSION,
        };
    }

    /**
     * Compare current scores against baseline
     */
    compare(url: string, current: LighthouseScores): BaselineComparison {
        const entry = this.baseline?.entries[url];

        if (!entry) {
            return {
                url,
                hasBaseline: false,
                metrics: [],
                overallStatus: 'new',
                regressionCount: 0,
            };
        }

        const metrics: MetricComparison[] = [];
        let regressionCount = 0;
        let improvementCount = 0;

        // Compare each metric
        for (const metric of Object.keys(entry.scores) as (keyof LighthouseScores)[]) {
            const baseline = entry.scores[metric];
            const currentScore = current[metric];

            if (baseline === undefined || currentScore === undefined) {
                continue;
            }

            const delta = currentScore - baseline;
            const percentChange = baseline > 0 ? (delta / baseline) * 100 : 0;

            let status: 'improved' | 'regressed' | 'stable' = 'stable';
            if (delta <= REGRESSION_THRESHOLD) {
                status = 'regressed';
                regressionCount++;
            } else if (delta >= IMPROVEMENT_THRESHOLD) {
                status = 'improved';
                improvementCount++;
            }

            metrics.push({
                metric,
                baseline,
                current: currentScore,
                delta,
                percentChange,
                status,
            });
        }

        // Determine overall status
        let overallStatus: 'improved' | 'regressed' | 'stable' | 'new' = 'stable';
        if (regressionCount > 0) {
            overallStatus = 'regressed';
        } else if (improvementCount > 0 && regressionCount === 0) {
            overallStatus = 'improved';
        }

        return {
            url,
            hasBaseline: true,
            metrics,
            overallStatus,
            regressionCount,
        };
    }

    /**
     * Get baseline entry for a URL
     */
    get(url: string): PerformanceBaselineEntry | undefined {
        return this.baseline?.entries[url];
    }

    /**
     * Check if baseline exists for URL
     */
    has(url: string): boolean {
        return !!this.baseline?.entries[url];
    }

    /**
     * Get all URLs in baseline
     */
    getUrls(): string[] {
        return Object.keys(this.baseline?.entries || {});
    }

    /**
     * Format comparison as markdown
     */
    formatMarkdown(comparison: BaselineComparison): string {
        if (!comparison.hasBaseline) {
            return `**${comparison.url}**: No baseline (first scan)`;
        }

        const statusEmoji = comparison.overallStatus === 'improved' ? '📈'
            : comparison.overallStatus === 'regressed' ? '📉' : '⚖️';

        let md = `### ${statusEmoji} ${comparison.url}\n\n`;
        md += `| Metric | Baseline | Current | Change |\n`;
        md += `|--------|----------|---------|--------|\n`;

        for (const m of comparison.metrics) {
            const arrow = m.delta > 0 ? '↑' : m.delta < 0 ? '↓' : '→';
            const change = `${arrow} ${m.delta > 0 ? '+' : ''}${m.delta.toFixed(1)} (${m.percentChange.toFixed(1)}%)`;
            md += `| ${m.metric} | ${m.baseline} | ${m.current} | ${change} |\n`;
        }

        return md;
    }

    /**
     * Create empty baseline file structure
     */
    private createEmptyBaseline(): PerformanceBaselineFile {
        return {
            version: BASELINE_VERSION,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            entries: {},
        };
    }
}

/**
 * Parse baseline CLI arguments
 */
export function parseBaselineArgs(args: string[]): {
    load: boolean;
    save: boolean;
    path?: string;
} {
    const loadFlag = args.includes('--baseline') || args.includes('--baseline-compare');
    const saveFlag = args.includes('--baseline-save') || args.includes('--baseline-update');
    const pathArg = args.find(a => a.startsWith('--baseline-path='));
    const path = pathArg ? pathArg.split('=')[1] : undefined;

    return { load: loadFlag, save: saveFlag, path };
}
