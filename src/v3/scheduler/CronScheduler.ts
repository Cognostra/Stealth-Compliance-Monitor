/**
 * Cron Scheduler
 * Continuous monitoring orchestration
 */

import cron from 'node-cron';
import { Logger } from '../../types/index.js';

export class CronScheduler {
    private task: cron.ScheduledTask | null = null;
    
    constructor(private readonly logger: Logger) {}

    /**
     * Start the scheduler
     * @param schedule Cron expression
     * @param callback Function to execute on schedule
     */
    start(schedule: string, callback: () => Promise<void> | void): void {
        if (!cron.validate(schedule)) {
            throw new Error(`Invalid cron schedule: "${schedule}"`);
        }

        this.logger.info(`Starting Continuous Monitoring (Schedule: "${schedule}")`);
        
        this.task = cron.schedule(schedule, async () => {
            this.logger.info('⏰ Triggering scheduled compliance scan...');
            try {
                await callback();
                this.logger.info('✅ Scheduled scan completed');
            } catch (err) {
                this.logger.error('❌ Scheduled scan failed', { error: err instanceof Error ? err.message : String(err) });
            }
        });
    }

    /**
     * Stop the scheduler
     */
    stop(): void {
        if (this.task) {
            this.task.stop();
            this.task = null;
            this.logger.info('Cron Scheduler stopped');
        }
    }
}
