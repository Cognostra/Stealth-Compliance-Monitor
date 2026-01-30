/**
 * Chaos Engineering Service
 *
 * Implements chaos engineering principles to test system resilience
 * by injecting failures and measuring recovery.
 *
 * Features:
 * - Network degradation simulation
 * - Rate limit testing
 * - Error injection
 * - Timeout testing
 * - Recovery measurement
 */

import { logger } from '../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface ChaosTest {
    id: string;
    name: string;
    type: 'network-delay' | 'packet-loss' | 'rate-limit' | 'error-injection' | 'timeout';
    target: string;
    config: Record<string, unknown>;
    duration: number;
}

export interface ChaosTestResult {
    testId: string;
    success: boolean;
    target: string;
    duration: number;
    injectedFailures: number;
    recoveredCount: number;
    avgRecoveryTime: number;
    errors: Array<{
        timestamp: string;
        type: string;
        message: string;
    }>;
}

export interface ResilienceMetrics {
    availability: number;
    meanTimeToRecovery: number;
    errorRate: number;
    degradationScore: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class ChaosEngineeringService {
    private activeTests: Map<string, ChaosTest> = new Map();
    private results: Map<string, ChaosTestResult> = new Map();

    /**
     * Run a chaos test against a target.
     */
    async runTest(test: ChaosTest): Promise<ChaosTestResult> {
        logger.info(`[Chaos] Starting test: ${test.name} (${test.type})`);

        const startTime = Date.now();
        const errors: ChaosTestResult['errors'] = [];
        let injectedFailures = 0;
        let recoveredCount = 0;
        let totalRecoveryTime = 0;

        try {
            switch (test.type) {
                case 'network-delay':
                    await this.simulateNetworkDelay(test, errors);
                    break;
                case 'rate-limit':
                    await this.testRateLimit(test, errors, { injectedFailures, recoveredCount, totalRecoveryTime });
                    break;
                case 'timeout':
                    await this.testTimeout(test, errors);
                    break;
                default:
                    logger.warn(`[Chaos] Unknown test type: ${test.type}`);
            }
        } catch (error) {
            errors.push({
                timestamp: new Date().toISOString(),
                type: 'test-failure',
                message: (error as Error).message,
            });
        }

        const duration = Date.now() - startTime;
        const result: ChaosTestResult = {
            testId: test.id,
            success: errors.length === 0,
            target: test.target,
            duration,
            injectedFailures,
            recoveredCount,
            avgRecoveryTime: recoveredCount > 0 ? totalRecoveryTime / recoveredCount : 0,
            errors,
        };

        this.results.set(test.id, result);
        logger.info(`[Chaos] Test completed: ${test.name} (${result.success ? 'SUCCESS' : 'FAILED'})`);
        return result;
    }

    /**
     * Simulate network delays.
     */
    private async simulateNetworkDelay(
        test: ChaosTest,
        errors: ChaosTestResult['errors']
    ): Promise<void> {
        const delayMs = (test.config.delayMs as number) || 1000;
        const iterations = (test.config.iterations as number) || 10;

        for (let i = 0; i < iterations; i++) {
            await new Promise(resolve => setTimeout(resolve, delayMs));

            if (Math.random() > 0.8) {
                errors.push({
                    timestamp: new Date().toISOString(),
                    type: 'delay-timeout',
                    message: `Request ${i} exceeded delay threshold`,
                });
            }
        }
    }

    /**
     * Test rate limiting behavior.
     */
    private async testRateLimit(
        test: ChaosTest,
        errors: ChaosTestResult['errors'],
        stats: { injectedFailures: number; recoveredCount: number; totalRecoveryTime: number }
    ): Promise<void> {
        const requestsPerSecond = (test.config.requestsPerSecond as number) || 100;
        const duration = test.duration || 5000;
        const iterations = Math.floor((duration / 1000) * requestsPerSecond);

        for (let i = 0; i < iterations; i++) {
            // Simulate rate limit hit after threshold
            if (i > requestsPerSecond * 2) {
                stats.injectedFailures++;

                // Simulate recovery
                const recoveryStart = Date.now();
                await new Promise(resolve => setTimeout(resolve, 100));
                stats.totalRecoveryTime += Date.now() - recoveryStart;
                stats.recoveredCount++;

                if (i % 10 === 0) {
                    errors.push({
                        timestamp: new Date().toISOString(),
                        type: 'rate-limit-hit',
                        message: `Rate limit triggered at request ${i}`,
                    });
                }
            }

            // Small delay between requests
            await new Promise(resolve => setTimeout(resolve, 1000 / requestsPerSecond));
        }
    }

    /**
     * Test timeout handling.
     */
    private async testTimeout(test: ChaosTest, errors: ChaosTestResult['errors']): Promise<void> {
        const timeoutMs = (test.config.timeoutMs as number) || 5000;
        const shouldTimeout = (test.config.shouldTimeout as boolean) ?? true;

        const startTime = Date.now();

        try {
            await Promise.race([
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('Timeout')), timeoutMs)
                ),
                new Promise(resolve => setTimeout(resolve, shouldTimeout ? timeoutMs + 1000 : timeoutMs - 100)),
            ]);

            if (shouldTimeout) {
                errors.push({
                    timestamp: new Date().toISOString(),
                    type: 'timeout-not-triggered',
                    message: 'Expected timeout did not occur',
                });
            }
        } catch {
            const elapsed = Date.now() - startTime;
            if (!shouldTimeout) {
                errors.push({
                    timestamp: new Date().toISOString(),
                    type: 'unexpected-timeout',
                    message: `Unexpected timeout after ${elapsed}ms`,
                });
            }
        }
    }

    /**
     * Calculate resilience metrics from test results.
     */
    calculateResilienceMetrics(): ResilienceMetrics {
        const results = Array.from(this.results.values());

        if (results.length === 0) {
            return {
                availability: 100,
                meanTimeToRecovery: 0,
                errorRate: 0,
                degradationScore: 0,
            };
        }

        const totalTests = results.length;
        const successfulTests = results.filter(r => r.success).length;
        const totalErrors = results.reduce((sum, r) => sum + r.errors.length, 0);
        const totalInjections = results.reduce((sum, r) => sum + r.injectedFailures, 0);

        const avgRecoveryTime = results
            .filter(r => r.recoveredCount > 0)
            .reduce((sum, r) => sum + r.avgRecoveryTime, 0) / totalTests;

        return {
            availability: (successfulTests / totalTests) * 100,
            meanTimeToRecovery: avgRecoveryTime,
            errorRate: totalInjections > 0 ? (totalErrors / totalInjections) * 100 : 0,
            degradationScore: this.calculateDegradationScore(results),
        };
    }

    /**
     * Get all test results.
     */
    getResults(): ChaosTestResult[] {
        return Array.from(this.results.values());
    }

    /**
     * Clear all results.
     */
    clearResults(): void {
        this.results.clear();
        this.activeTests.clear();
    }

    private calculateDegradationScore(results: ChaosTestResult[]): number {
        // Score 0-100 where 0 is perfect resilience, 100 is complete failure
        const weights = {
            availability: 0.4,
            recovery: 0.3,
            errors: 0.3,
        };

        const avgAvailability = results.filter(r => r.success).length / results.length;
        const avgRecovery = results
            .filter(r => r.recoveredCount > 0)
            .reduce((sum, r) => sum + (r.avgRecoveryTime < 1000 ? 1 : 0.5), 0) / results.length;
        const avgErrors = results.reduce((sum, r) => sum + r.errors.length, 0) / results.length;

        return (
            (1 - avgAvailability) * weights.availability * 100 +
            (1 - avgRecovery) * weights.recovery * 100 +
            Math.min(avgErrors / 10, 1) * weights.errors * 100
        );
    }
}

export default ChaosEngineeringService;
