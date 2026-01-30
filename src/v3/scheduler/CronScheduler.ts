/**
 * Cron Scheduler
 * Continuous monitoring orchestration
 */

import cron from 'node-cron';
import { Logger } from '../../types/index.js';

/**
 * Circuit breaker configuration
 */
interface CircuitBreakerConfig {
    /** Maximum consecutive failures before circuit opens */
    maxFailures: number;
    /** Reset failure count after this many consecutive successes */
    resetThreshold: number;
}

export class CronScheduler {
    private task: cron.ScheduledTask | null = null;
    private isRunning: boolean = false; // Mutex to prevent overlapping executions
    private consecutiveFailures: number = 0;
    private consecutiveSuccesses: number = 0;
    private circuitOpen: boolean = false;

    private readonly circuitBreakerConfig: CircuitBreakerConfig = {
        maxFailures: 5,
        resetThreshold: 3,
    };

    constructor(private readonly logger: Logger) {}

    /**
     * Start the scheduler with mutex and circuit breaker protection
     *
     * @param schedule Cron expression
     * @param callback Function to execute on schedule
     * @throws Error if schedule is invalid
     */
    start(schedule: string, callback: () => Promise<void> | void): void {
        if (!cron.validate(schedule)) {
            throw new Error(`Invalid cron schedule: "${schedule}"`);
        }

        this.logger.info(`Starting Continuous Monitoring (Schedule: "${schedule}")`);

        this.task = cron.schedule(schedule, async () => {
            // Circuit breaker: Stop if too many consecutive failures
            if (this.circuitOpen) {
                this.logger.error(
                    '⚠️ Circuit breaker OPEN - Scheduler stopped due to excessive failures. ' +
                    `Failed ${this.consecutiveFailures} times consecutively. ` +
                    'Manual intervention required.'
                );
                this.stop();
                return;
            }

            // Mutex: Prevent overlapping executions
            if (this.isRunning) {
                this.logger.warn(
                    '⏭️  Skipping scheduled run - previous execution still in progress. ' +
                    'Consider adjusting cron schedule or optimizing scan performance.'
                );
                return;
            }

            this.logger.info('⏰ Triggering scheduled compliance scan...');
            this.isRunning = true;

            try {
                await callback();

                // Success: Reset failure counter and increment success counter
                this.consecutiveFailures = 0;
                this.consecutiveSuccesses++;

                // Reset circuit breaker if enough consecutive successes
                if (this.consecutiveSuccesses >= this.circuitBreakerConfig.resetThreshold) {
                    if (this.circuitOpen) {
                        this.logger.info('✅ Circuit breaker CLOSED - System recovered');
                        this.circuitOpen = false;
                    }
                }

                this.logger.info('✅ Scheduled scan completed successfully');
            } catch (err) {
                // Failure: Increment failure counter and reset success counter
                this.consecutiveFailures++;
                this.consecutiveSuccesses = 0;

                const errorMessage = err instanceof Error ? err.message : String(err);
                this.logger.error(
                    `❌ Scheduled scan failed (${this.consecutiveFailures}/${this.circuitBreakerConfig.maxFailures} failures)`,
                    { error: errorMessage }
                );

                // Open circuit breaker if threshold exceeded
                if (this.consecutiveFailures >= this.circuitBreakerConfig.maxFailures) {
                    this.circuitOpen = true;
                    this.logger.error(
                        '🔥 Circuit breaker TRIGGERED - Maximum consecutive failures reached. ' +
                        'Scheduler will be stopped on next run.'
                    );
                }
            } finally {
                this.isRunning = false;
            }
        });
    }

    /**
     * Stop the scheduled task execution
     *
     * Gracefully stops the cron scheduler and clears the running state.
     * Safe to call multiple times (idempotent).
     * Does not reset circuit breaker state - use resetCircuitBreaker() if needed.
     *
     * @example
     * ```typescript
     * const scheduler = new CronScheduler(logger);
     * scheduler.start('0/5 * * * *', async () => {
     *   await runComplianceScan();
     * });
     *
     * // Later, when shutting down
     * scheduler.stop();
     * ```
     */
    stop(): void {
        if (this.task) {
            this.task.stop();
            this.task = null;
            this.isRunning = false;
            this.logger.info('Cron Scheduler stopped');
        }
    }

    /**
     * Manually reset the circuit breaker state
     *
     * Clears all failure/success counters and reopens the circuit.
     * Use this after fixing underlying issues that caused failures
     * (e.g., network problems, permission issues, external service outages).
     *
     * **Important:** Only reset after confirming the root cause is resolved,
     * otherwise the circuit will trip again immediately.
     *
     * @example
     * ```typescript
     * const scheduler = new CronScheduler(logger);
     *
     * // Check status
     * const status = scheduler.getStatus();
     * if (status.circuitOpen) {
     *   console.log('Circuit breaker is open!');
     *
     *   // After fixing the issue...
     *   scheduler.resetCircuitBreaker();
     *   console.log('Circuit breaker reset - scheduler will resume');
     * }
     * ```
     */
    resetCircuitBreaker(): void {
        this.circuitOpen = false;
        this.consecutiveFailures = 0;
        this.consecutiveSuccesses = 0;
        this.logger.info('Circuit breaker manually reset');
    }

    /**
     * Get current scheduler status and health information
     *
     * Returns real-time status for monitoring, alerting, and diagnostics.
     * Use this to check scheduler health and circuit breaker state.
     *
     * @returns Status object containing:
     *   - isRunning: true if a scan is currently executing
     *   - circuitOpen: true if circuit breaker has tripped
     *   - consecutiveFailures: Number of failures since last success
     *   - consecutiveSuccesses: Number of successes since last failure
     *
     * @example
     * ```typescript
     * const scheduler = new CronScheduler(logger);
     * scheduler.start('0/5 * * * *', scanTask);
     *
     * // Monitor scheduler health
     * setInterval(() => {
     *   const status = scheduler.getStatus();
     *
     *   if (status.circuitOpen) {
     *     console.error('⚠️ Circuit breaker OPEN - scheduler stopped!');
     *     notifyOps('Scheduler circuit breaker tripped');
     *   }
     *
     *   if (status.consecutiveFailures >= 3) {
     *     console.warn(`⚠️ ${status.consecutiveFailures} consecutive failures`);
     *   }
     *
     *   if (status.isRunning) {
     *     console.log('Scan in progress...');
     *   }
     * }, 60000);
     * ```
     */
    getStatus(): {
        isRunning: boolean;
        circuitOpen: boolean;
        consecutiveFailures: number;
        consecutiveSuccesses: number;
    } {
        return {
            isRunning: this.isRunning,
            circuitOpen: this.circuitOpen,
            consecutiveFailures: this.consecutiveFailures,
            consecutiveSuccesses: this.consecutiveSuccesses,
        };
    }
}
