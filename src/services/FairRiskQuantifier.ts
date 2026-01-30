/**
 * FAIR Risk Quantification Service
 *
 * Implements the FAIR (Factor Analysis of Information Risk) methodology
 * to quantify risk in financial terms ($) rather than qualitative ratings.
 *
 * FAIR Components:
 * - Threat Event Frequency (TEF)
 * - Vulnerability (Threat Capability vs Control Strength)
 * - Loss Event Frequency (LEF)
 * - Primary Loss Magnitude (PLM)
 * - Secondary Loss Magnitude (SLM)
 * - Risk = LEF × (PLM + SLM)
 *
 * Features:
 * - Annualized Loss Expectancy (ALE) calculation
 * - Monte Carlo simulation for uncertainty ranges
 * - Finding-to-risk conversion
 * - Executive reporting in financial terms
 */

import { logger } from '../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface FairRiskInput {
    findingType: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    likelihood: number; // 0-1 probability of occurrence
    assetValue: number; // In dollars
    exposureFactor: number; // 0-1 percentage of asset value at risk
    secondaryLossFactor?: number; // Additional losses (reputation, legal)
}

export interface FairRiskResult {
    annualizedLossExpectancy: number;
    lossEventFrequency: number; // Events per year
    primaryLossMagnitude: number;
    secondaryLossMagnitude: number;
    vulnerability: number; // 0-1
    threatEventFrequency: number;
    confidenceInterval: {
        low: number;
        high: number;
        confidence: number;
    };
    riskHeatMapPosition: {
        frequency: 'low' | 'medium' | 'high';
        magnitude: 'low' | 'medium' | 'high' | 'critical';
    };
}

export interface RiskMatrix {
    findings: Array<{
        id: string;
        type: string;
        ale: number;
        probability: number;
        impact: number;
    }>;
    aggregateALE: number;
    maxSingleLoss: number;
    riskDistribution: Record<string, number>;
}

export interface FairConfig {
    defaultAssetValue: number;
    monteCarloIterations: number;
    confidenceLevel: number;
    organizationRevenue?: number; // Used for secondary loss calculation
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG: FairConfig = {
    defaultAssetValue: 1000000, // $1M default asset value
    monteCarloIterations: 10000,
    confidenceLevel: 0.95,
    organizationRevenue: 10000000, // $10M default
};

// Severity to base loss magnitude mapping (in dollars)
const SEVERITY_BASE_LOSS: Record<string, number> = {
    critical: 5000000,
    high: 1000000,
    medium: 250000,
    low: 50000,
};

// Finding type to threat capability mapping
const THREAT_CAPABILITY: Record<string, number> = {
    'xss': 0.8,
    'sql-injection': 0.9,
    'rce': 0.95,
    'data-exposure': 0.7,
    'auth-bypass': 0.85,
    'missing-csp': 0.6,
    'csrf': 0.7,
    'ssrf': 0.75,
    'idor': 0.65,
    'default': 0.5,
};

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class FairRiskQuantifier {
    private config: FairConfig;

    constructor(config?: Partial<FairConfig>) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Quantify risk for a single finding using FAIR methodology.
     */
    quantifyRisk(input: FairRiskInput): FairRiskResult {
        // Calculate Threat Event Frequency (TEF)
        // Based on historical data or threat intelligence
        const tef = this.calculateTEF(input.likelihood, input.findingType);

        // Calculate Vulnerability
        // Vulnerability = Threat Capability - Control Strength
        const vulnerability = this.calculateVulnerability(input.findingType, input.severity);

        // Calculate Loss Event Frequency (LEF)
        // LEF = TEF × Vulnerability
        const lef = tef * vulnerability;

        // Calculate Primary Loss Magnitude (PLM)
        // Direct losses: system downtime, data recovery, incident response
        const plm = this.calculatePrimaryLoss(input);

        // Calculate Secondary Loss Magnitude (SLM)
        // Indirect losses: reputation, legal, regulatory fines
        const slm = this.calculateSecondaryLoss(input, plm);

        // Run Monte Carlo simulation for uncertainty
        const simulation = this.runMonteCarloSimulation(input, lef, plm, slm);

        // Annualized Loss Expectancy
        const ale = lef * (plm + slm);

        logger.debug(`[FAIR] Quantified risk: ALE=$${ale.toLocaleString()}, LEF=${lef.toFixed(2)}, PLM=$${plm.toLocaleString()}`);

        return {
            annualizedLossExpectancy: ale,
            lossEventFrequency: lef,
            primaryLossMagnitude: plm,
            secondaryLossMagnitude: slm,
            vulnerability,
            threatEventFrequency: tef,
            confidenceInterval: simulation,
            riskHeatMapPosition: this.determineHeatMapPosition(lef, plm + slm),
        };
    }

    /**
     * Quantify aggregate risk for multiple findings.
     */
    quantifyAggregateRisk(inputs: FairRiskInput[]): RiskMatrix {
        const findings = inputs.map((input, index) => {
            const result = this.quantifyRisk(input);
            return {
                id: `finding-${index}`,
                type: input.findingType,
                ale: result.annualizedLossExpectancy,
                probability: result.lossEventFrequency,
                impact: result.primaryLossMagnitude + result.secondaryLossMagnitude,
            };
        });

        const aggregateALE = findings.reduce((sum, f) => sum + f.ale, 0);
        const maxSingleLoss = Math.max(...findings.map(f => f.impact), 0);

        // Calculate risk distribution by category
        const riskDistribution: Record<string, number> = {};
        for (const finding of findings) {
            const category = this.categorizeFinding(finding.type);
            riskDistribution[category] = (riskDistribution[category] || 0) + finding.ale;
        }

        logger.info(`[FAIR] Aggregate risk: ALE=$${aggregateALE.toLocaleString()}, max single loss=$${maxSingleLoss.toLocaleString()}`);

        return {
            findings,
            aggregateALE,
            maxSingleLoss,
            riskDistribution,
        };
    }

    /**
     * Convert audit findings to FAIR risk inputs.
     */
    convertFindingsToRiskInputs(
        findings: Array<{
            type: string;
            severity: string;
            url?: string;
            evidence?: string;
        }>,
        assetValues?: Record<string, number>
    ): FairRiskInput[] {
        return findings.map(finding => {
            const baseAssetValue = assetValues?.[finding.type] || this.config.defaultAssetValue;
            const likelihood = this.estimateLikelihood(finding.severity, finding.evidence);

            return {
                findingType: finding.type,
                severity: this.normalizeSeverity(finding.severity),
                likelihood,
                assetValue: baseAssetValue,
                exposureFactor: this.estimateExposureFactor(finding.type),
                secondaryLossFactor: this.estimateSecondaryLossFactor(finding.severity),
            };
        });
    }

    /**
     * Generate executive summary in financial terms.
     */
    generateExecutiveSummary(riskMatrix: RiskMatrix): {
        totalRiskExposure: number;
        riskInRevenueTerms: string;
        topRisks: Array<{ type: string; ale: number; percentage: number }>;
        recommendations: string[];
    } {
        const totalRiskExposure = riskMatrix.aggregateALE;
        const revenue = this.config.organizationRevenue || 10000000;
        const riskPercentage = (totalRiskExposure / revenue) * 100;

        // Top 5 risks by ALE
        const topRisks = [...riskMatrix.findings]
            .sort((a, b) => b.ale - a.ale)
            .slice(0, 5)
            .map(f => ({
                type: f.type,
                ale: f.ale,
                percentage: (f.ale / totalRiskExposure) * 100,
            }));

        // Generate recommendations
        const recommendations: string[] = [];
        if (totalRiskExposure > revenue * 0.1) {
            recommendations.push('IMMEDIATE ACTION: Risk exposure exceeds 10% of annual revenue');
        }
        if (topRisks[0]?.ale > revenue * 0.05) {
            recommendations.push(`Prioritize remediation of ${topRisks[0].type} (single risk > 5% revenue)`);
        }
        if (riskMatrix.findings.some(f => f.impact > revenue * 0.2)) {
            recommendations.push('Catastrophic single-loss scenarios identified - consider cyber insurance');
        }

        return {
            totalRiskExposure,
            riskInRevenueTerms: `${riskPercentage.toFixed(1)}% of annual revenue`,
            topRisks,
            recommendations,
        };
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PRIVATE METHODS
    // ═══════════════════════════════════════════════════════════════════════════════

    private calculateTEF(likelihood: number, findingType: string): number {
        // Annualize the likelihood
        // Assume likelihood is for a single event, convert to annual frequency
        const baseFrequency = likelihood * 12; // Monthly likelihood to annual
        const threatModifier = THREAT_CAPABILITY[findingType] || THREAT_CAPABILITY.default;
        return baseFrequency * (0.5 + threatModifier / 2);
    }

    private calculateVulnerability(findingType: string, severity: string): number {
        const threatCap = THREAT_CAPABILITY[findingType] || THREAT_CAPABILITY.default;
        // Control strength inversely proportional to severity
        const controlStrength = severity === 'critical' ? 0.1 :
            severity === 'high' ? 0.3 :
                severity === 'medium' ? 0.5 : 0.7;
        return Math.max(0, Math.min(1, threatCap - controlStrength));
    }

    private calculatePrimaryLoss(input: FairRiskInput): number {
        return input.assetValue * input.exposureFactor;
    }

    private calculateSecondaryLoss(input: FairRiskInput, primaryLoss: number): number {
        const secondaryFactor = input.secondaryLossFactor || 0.3;
        // Secondary losses often scale with organization size
        const revenueFactor = Math.min(1, (this.config.organizationRevenue || 10000000) / 100000000);
        return primaryLoss * secondaryFactor * (0.5 + revenueFactor);
    }

    private runMonteCarloSimulation(
        input: FairRiskInput,
        lef: number,
        plm: number,
        slm: number
    ): FairRiskResult['confidenceInterval'] {
        const iterations = this.config.monteCarloIterations;
        const results: number[] = [];

        for (let i = 0; i < iterations; i++) {
            // Add uncertainty to parameters
            const uncertainLEF = lef * (0.8 + Math.random() * 0.4); // ±20%
            const uncertainPLM = plm * (0.7 + Math.random() * 0.6); // ±30%
            const uncertainSLM = slm * (0.5 + Math.random() * 1.0); // ±50%

            results.push(uncertainLEF * (uncertainPLM + uncertainSLM));
        }

        results.sort((a, b) => a - b);

        const confidence = this.config.confidenceLevel;
        const lowerIndex = Math.floor((1 - confidence) / 2 * iterations);
        const upperIndex = Math.floor((1 - (1 - confidence) / 2) * iterations);

        return {
            low: results[lowerIndex],
            high: results[upperIndex],
            confidence: confidence * 100,
        };
    }

    private determineHeatMapPosition(
        lef: number,
        totalLoss: number
    ): FairRiskResult['riskHeatMapPosition'] {
        const frequency: FairRiskResult['riskHeatMapPosition']['frequency'] =
            lef < 1 ? 'low' : lef < 12 ? 'medium' : 'high';

        const magnitude: FairRiskResult['riskHeatMapPosition']['magnitude'] =
            totalLoss < 100000 ? 'low' :
                totalLoss < 500000 ? 'medium' :
                    totalLoss < 2000000 ? 'high' : 'critical';

        return { frequency, magnitude };
    }

    private categorizeFinding(findingType: string): string {
        const categories: Record<string, string> = {
            'xss': 'Application Security',
            'sql-injection': 'Data Security',
            'rce': 'Infrastructure Security',
            'data-exposure': 'Data Security',
            'auth-bypass': 'Access Control',
            'missing-csp': 'Application Security',
            'csrf': 'Application Security',
            'ssrf': 'Infrastructure Security',
        };
        return categories[findingType] || 'Other';
    }

    private estimateLikelihood(severity: string, evidence?: string): number {
        // Base likelihood on severity
        let base = severity === 'critical' ? 0.8 :
            severity === 'high' ? 0.5 :
                severity === 'medium' ? 0.3 : 0.1;

        // Adjust based on evidence
        if (evidence?.includes('exploited') || evidence?.includes('confirmed')) {
            base *= 1.5;
        }

        return Math.min(1, base);
    }

    private estimateExposureFactor(findingType: string): number {
        // How much of the asset is at risk
        const factors: Record<string, number> = {
            'xss': 0.3,
            'sql-injection': 0.8,
            'rce': 0.95,
            'data-exposure': 0.7,
            'auth-bypass': 0.6,
            'missing-csp': 0.2,
        };
        return factors[findingType] || 0.4;
    }

    private estimateSecondaryLossFactor(severity: string): number {
        return severity === 'critical' ? 0.8 :
            severity === 'high' ? 0.5 :
                severity === 'medium' ? 0.3 : 0.1;
    }

    private normalizeSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
        const s = severity.toLowerCase();
        if (s === 'critical') return 'critical';
        if (s === 'high') return 'high';
        if (s === 'medium') return 'medium';
        return 'low';
    }
}

export default FairRiskQuantifier;
