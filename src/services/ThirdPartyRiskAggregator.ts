/**
 * Third-Party Risk Aggregator
 *
 * Aggregates security risk data from third-party vendors and service providers
 * to provide a unified risk assessment.
 *
 * Features:
 * - Vendor security score integration (SecurityScorecard, BitSight, etc.)
 * - SOC 2/ISO 27001 status tracking
 * - Data processing agreement compliance
 * - Sub-processor chain analysis
 * - Concentration risk detection
 * - Risk-weighted vendor portfolio view
 */

import { logger } from '../utils/logger.js';
import { fetchJson, fetchWithRetry } from '../utils/api-client.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface Vendor {
    id: string;
    name: string;
    category: string;
    criticality: 'critical' | 'high' | 'medium' | 'low';
    services: string[];
    dataAccess: 'none' | 'minimal' | 'moderate' | 'extensive';
    contracts: {
        hasDpa: boolean;
        hasBaa: boolean; // Business Associate Agreement (HIPAA)
        hasSla: boolean;
        terminationDays: number;
    };
}

export interface VendorRiskScore {
    vendorId: string;
    source: 'security-scorecard' | 'bitsight' | 'manual' | 'questionnaire';
    overallScore: number; // 0-100
    grades: Record<string, string>; // Category grades
    lastUpdated: string;
    trend: 'improving' | 'stable' | 'degrading';
}

export interface ComplianceCertification {
    vendorId: string;
    type: 'soc2-type1' | 'soc2-type2' | 'iso27001' | 'gdpr' | 'hipaa' | 'pci-dss';
    status: 'valid' | 'pending' | 'expired' | 'not-applicable';
    issuedDate: string;
    expiryDate: string;
    auditor: string;
    scope: string;
}

export interface SubProcessor {
    vendorId: string;
    name: string;
    parentVendorId: string;
    dataAccess: string;
    location: string;
    gdprCompliant: boolean;
}

export interface AggregatedRisk {
    vendor: Vendor;
    riskScore: VendorRiskScore | null;
    certifications: ComplianceCertification[];
    subProcessors: SubProcessor[];
    calculatedRisk: {
        inherentRisk: number; // 0-100
        residualRisk: number; // 0-100
        riskTier: 'low' | 'medium' | 'high' | 'critical';
        recommendation: 'approve' | 'conditional' | 'review' | 'reject';
    };
}

export interface RiskAggregationConfig {
    scorecardApiKey?: string;
    bitsightApiKey?: string;
    riskThresholds: {
        critical: number;
        high: number;
        medium: number;
    };
    autoApproveThreshold: number;
    autoRejectThreshold: number;
}

export interface PortfolioSummary {
    totalVendors: number;
    byTier: Record<string, number>;
    byCriticality: Record<string, number>;
    averageScore: number;
    atRiskVendors: string[];
    complianceGaps: Array<{
        vendorId: string;
        gap: string;
        severity: string;
    }>;
    concentrationRisk: Array<{
        category: string;
        vendorCount: number;
        marketShare: number;
    }>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class ThirdPartyRiskAggregator {
    private config: RiskAggregationConfig;
    private vendorCache: Map<string, Vendor> = new Map();
    private scoreCache: Map<string, VendorRiskScore> = new Map();
    private certCache: Map<string, ComplianceCertification[]> = new Map();

    constructor(config?: Partial<RiskAggregationConfig>) {
        this.config = {
            riskThresholds: { critical: 20, high: 40, medium: 60 },
            autoApproveThreshold: 80,
            autoRejectThreshold: 30,
            ...config,
        };
    }

    /**
     * Register a vendor in the system.
     */
    registerVendor(vendor: Vendor): void {
        this.vendorCache.set(vendor.id, vendor);
        logger.debug(`[RiskAggregator] Registered vendor: ${vendor.name}`);
    }

    /**
     * Fetch risk score from SecurityScorecard.
     */
    async fetchSecurityScorecard(vendorId: string, domain: string): Promise<VendorRiskScore | null> {
        if (!this.config.scorecardApiKey) {
            logger.warn('[RiskAggregator] SecurityScorecard API key not configured');
            return null;
        }

        try {
            const response = await fetchWithRetry<{
                entries: Array<{
                    score: number;
                    grades: Record<string, string>;
                    last_event_time: string;
                }>;
            }>(
                `https://api.securityscorecard.io/api/v1/companies/${domain}/overall-score`,
                {
                    method: 'GET',
                    headers: {
                        Authorization: `Token ${this.config.scorecardApiKey}`,
                    },
                }
            );

            if (response?.entries && response.entries.length > 0) {
                const entry = response.entries[0];
                const score: VendorRiskScore = {
                    vendorId,
                    source: 'security-scorecard',
                    overallScore: entry.score,
                    grades: entry.grades,
                    lastUpdated: entry.last_event_time,
                    trend: 'stable',
                };
                this.scoreCache.set(vendorId, score);
                return score;
            }

            return null;
        } catch (error) {
            logger.error(`[RiskAggregator] SecurityScorecard fetch failed: ${(error as Error).message}`);
            return null;
        }
    }

    /**
     * Fetch risk score from BitSight.
     */
    async fetchBitSight(vendorId: string, companyGuid: string): Promise<VendorRiskScore | null> {
        if (!this.config.bitsightApiKey) {
            logger.warn('[RiskAggregator] BitSight API key not configured');
            return null;
        }

        try {
            const response = await fetchWithRetry<{
                ratings: Array<{
                    rating: number;
                    rating_date: string;
                }>;
            }>(
                `https://api.bitsighttech.com/ratings/v1/companies/${companyGuid}/ratings`,
                {
                    method: 'GET',
                    headers: {
                        Authorization: `Basic ${Buffer.from(this.config.bitsightApiKey + ':').toString('base64')}`,
                    },
                }
            );

            if (response?.ratings && response.ratings.length > 0) {
                const rating = response.ratings[0];
                const score: VendorRiskScore = {
                    vendorId,
                    source: 'bitsight',
                    overallScore: rating.rating * 10, // BitSight uses 0-10, normalize to 0-100
                    grades: {},
                    lastUpdated: rating.rating_date,
                    trend: 'stable',
                };
                this.scoreCache.set(vendorId, score);
                return score;
            }

            return null;
        } catch (error) {
            logger.error(`[RiskAggregator] BitSight fetch failed: ${(error as Error).message}`);
            return null;
        }
    }

    /**
     * Add compliance certification for a vendor.
     */
    addCertification(cert: ComplianceCertification): void {
        const existing = this.certCache.get(cert.vendorId) || [];
        existing.push(cert);
        this.certCache.set(cert.vendorId, existing);
    }

    /**
     * Calculate aggregated risk for a vendor.
     */
    calculateVendorRisk(vendorId: string): AggregatedRisk | null {
        const vendor = this.vendorCache.get(vendorId);
        if (!vendor) {
            logger.warn(`[RiskAggregator] Vendor not found: ${vendorId}`);
            return null;
        }

        const riskScore = this.scoreCache.get(vendorId) || null;
        const certifications = this.certCache.get(vendorId) || [];

        // Calculate inherent risk based on criticality and data access
        const inherentRisk = this.calculateInherentRisk(vendor);

        // Calculate residual risk considering controls and certifications
        const residualRisk = this.calculateResidualRisk(
            inherentRisk,
            riskScore,
            certifications,
            vendor
        );

        const riskTier = this.determineRiskTier(residualRisk);
        const recommendation = this.generateRecommendation(residualRisk, certifications, vendor);

        return {
            vendor,
            riskScore,
            certifications,
            subProcessors: [], // Would be populated from sub-processor registry
            calculatedRisk: {
                inherentRisk,
                residualRisk,
                riskTier,
                recommendation,
            },
        };
    }

    /**
     * Generate portfolio-wide risk summary.
     */
    generatePortfolioSummary(): PortfolioSummary {
        const vendors = Array.from(this.vendorCache.values());
        const aggregatedRisks = vendors.map(v => this.calculateVendorRisk(v.id)).filter(Boolean) as AggregatedRisk[];

        // Group by tier
        const byTier: Record<string, number> = {};
        for (const risk of aggregatedRisks) {
            const tier = risk.calculatedRisk.riskTier;
            byTier[tier] = (byTier[tier] || 0) + 1;
        }

        // Group by criticality
        const byCriticality: Record<string, number> = {};
        for (const vendor of vendors) {
            byCriticality[vendor.criticality] = (byCriticality[vendor.criticality] || 0) + 1;
        }

        // Calculate average score
        const scores = aggregatedRisks
            .map(r => r.riskScore?.overallScore)
            .filter((s): s is number => s !== undefined && s !== null);
        const averageScore = scores.length > 0
            ? scores.reduce((a, b) => a + b, 0) / scores.length
            : 0;

        // Identify at-risk vendors
        const atRiskVendors = aggregatedRisks
            .filter(r => r.calculatedRisk.riskTier === 'critical' || r.calculatedRisk.riskTier === 'high')
            .map(r => r.vendor.name);

        // Identify compliance gaps
        const complianceGaps: PortfolioSummary['complianceGaps'] = [];
        for (const risk of aggregatedRisks) {
            if (risk.vendor.dataAccess !== 'none' && !risk.vendor.contracts.hasDpa) {
                complianceGaps.push({
                    vendorId: risk.vendor.id,
                    gap: 'Missing Data Processing Agreement',
                    severity: risk.vendor.criticality,
                });
            }

            const hasValidSoc2 = risk.certifications.some(
                c => c.type === 'soc2-type2' && c.status === 'valid'
            );
            if (risk.vendor.criticality === 'critical' && !hasValidSoc2) {
                complianceGaps.push({
                    vendorId: risk.vendor.id,
                    gap: 'Missing SOC 2 Type II certification',
                    severity: 'high',
                });
            }
        }

        // Detect concentration risk
        const categoryCounts: Record<string, number> = {};
        for (const vendor of vendors) {
            categoryCounts[vendor.category] = (categoryCounts[vendor.category] || 0) + 1;
        }
        const concentrationRisk = Object.entries(categoryCounts)
            .filter(([, count]) => count > 3)
            .map(([category, count]) => ({
                category,
                vendorCount: count,
                marketShare: (count / vendors.length) * 100,
            }));

        return {
            totalVendors: vendors.length,
            byTier,
            byCriticality,
            averageScore,
            atRiskVendors,
            complianceGaps,
            concentrationRisk,
        };
    }

    /**
     * Generate risk report for a specific vendor.
     */
    generateVendorReport(vendorId: string): string {
        const risk = this.calculateVendorRisk(vendorId);
        if (!risk) return 'Vendor not found';

        return `
# Third-Party Risk Report: ${risk.vendor.name}

## Risk Summary
- **Risk Tier:** ${risk.calculatedRisk.riskTier.toUpperCase()}
- **Inherent Risk:** ${risk.calculatedRisk.inherentRisk}/100
- **Residual Risk:** ${risk.calculatedRisk.residualRisk}/100
- **Recommendation:** ${risk.calculatedRisk.recommendation.toUpperCase()}

## External Risk Scores
${risk.riskScore ? `
- **Source:** ${risk.riskScore.source}
- **Overall Score:** ${risk.riskScore.overallScore}/100
- **Last Updated:** ${risk.riskScore.lastUpdated}
` : 'No external risk scores available'}

## Compliance Certifications
${risk.certifications.length > 0
                ? risk.certifications.map(c => `- **${c.type}:** ${c.status} (expires ${c.expiryDate})`).join('\n')
                : 'No certifications on file'}

## Contract Status
- **DPA:** ${risk.vendor.contracts.hasDpa ? '✓' : '✗'}
- **BAA:** ${risk.vendor.contracts.hasBaa ? '✓' : '✗'}
- **SLA:** ${risk.vendor.contracts.hasSla ? '✓' : '✗'}
- **Termination:** ${risk.vendor.contracts.terminationDays} days

## Data Access
**Level:** ${risk.vendor.dataAccess}
**Services:** ${risk.vendor.services.join(', ')}
        `.trim();
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PRIVATE METHODS
    // ═══════════════════════════════════════════════════════════════════════════════

    private calculateInherentRisk(vendor: Vendor): number {
        let risk = 0;

        // Criticality weight
        risk += vendor.criticality === 'critical' ? 40 :
            vendor.criticality === 'high' ? 30 :
                vendor.criticality === 'medium' ? 20 : 10;

        // Data access weight
        risk += vendor.dataAccess === 'extensive' ? 30 :
            vendor.dataAccess === 'moderate' ? 20 :
                vendor.dataAccess === 'minimal' ? 10 : 0;

        return Math.min(100, risk);
    }

    private calculateResidualRisk(
        inherentRisk: number,
        riskScore: VendorRiskScore | null,
        certifications: ComplianceCertification[],
        vendor: Vendor
    ): number {
        let risk = inherentRisk;

        // Adjust based on external risk score (if available)
        if (riskScore) {
            const scoreModifier = (100 - riskScore.overallScore) * 0.3;
            risk = risk * 0.7 + scoreModifier;
        }

        // Reduce risk for certifications
        const hasSoc2 = certifications.some(c => c.type === 'soc2-type2' && c.status === 'valid');
        const hasIso27001 = certifications.some(c => c.type === 'iso27001' && c.status === 'valid');

        if (hasSoc2) risk *= 0.8;
        if (hasIso27001) risk *= 0.9;

        // Increase risk for missing contracts
        if (vendor.dataAccess !== 'none' && !vendor.contracts.hasDpa) {
            risk *= 1.2;
        }

        return Math.min(100, Math.max(0, risk));
    }

    private determineRiskTier(residualRisk: number): AggregatedRisk['calculatedRisk']['riskTier'] {
        if (residualRisk >= this.config.riskThresholds.critical) return 'critical';
        if (residualRisk >= this.config.riskThresholds.high) return 'high';
        if (residualRisk >= this.config.riskThresholds.medium) return 'medium';
        return 'low';
    }

    private generateRecommendation(
        residualRisk: number,
        certifications: ComplianceCertification[],
        vendor: Vendor
    ): AggregatedRisk['calculatedRisk']['recommendation'] {
        if (residualRisk <= this.config.autoApproveThreshold) return 'approve';
        if (residualRisk >= this.config.autoRejectThreshold) return 'reject';
        if (vendor.criticality === 'critical' && !certifications.some(c => c.status === 'valid')) return 'review';
        return 'conditional';
    }
}

export default ThirdPartyRiskAggregator;
