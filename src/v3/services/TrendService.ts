/**
 * Trend Service
 *
 * Manages historical compliance data to enable trend analysis.
 * Stores history in a JSON file (lightweight persistence).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { z } from 'zod';
import { Logger } from '../../types/index.js';
import { isReservedKeyword, isValidUrl, isInRange } from '../utils/validation.js';
import { LIMITS, RETENTION } from '../utils/constants.js';

export interface TrendDataPoint {
    timestamp: string;
    runId: string;
    targetUrl: string;
    overallScore: number;
    performanceScore: number;
    securityCritical: number;
}

export interface TrendHistory {
    [targetUrl: string]: TrendDataPoint[];
}

/**
 * Zod schema for validating TrendDataPoint at runtime
 *
 * Prevents:
 * - Invalid URLs
 * - Out-of-range scores
 * - Missing required fields
 * - Prototype pollution via reserved keywords
 */
const TrendDataPointSchema = z.object({
    timestamp: z.string().datetime(),
    runId: z.string().min(1),
    targetUrl: z.string().url(),
    overallScore: z.number().min(0).max(100),
    performanceScore: z.number().min(0).max(100),
    securityCritical: z.number().min(0),
});

export class TrendService {
    private readonly historyPath: string;
    private history: TrendHistory = {};

    constructor(
        private readonly logger: Logger,
        private readonly storageDir: string = '.compliance-history'
    ) {
        this.historyPath = path.resolve(process.cwd(), storageDir, 'history.json');
        
        if (!fs.existsSync(this.storageDir)) {
            fs.mkdirSync(this.storageDir, { recursive: true });
        }
        
        this.load();
    }

    private load(): void {
        if (fs.existsSync(this.historyPath)) {
            try {
                const content = fs.readFileSync(this.historyPath, 'utf-8');
                this.history = JSON.parse(content);
            } catch (error) {
                // Specific error handling for common filesystem issues
                if (error instanceof Error) {
                    if ((error as NodeJS.ErrnoException).code === 'EACCES') {
                        this.logger.error(`Permission denied reading history file: ${this.historyPath}`);
                    } else if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
                        this.logger.warn(`History file not found: ${this.historyPath} (will be created on save)`);
                    } else if (error instanceof SyntaxError) {
                        this.logger.error(`Corrupted history file (invalid JSON): ${this.historyPath} - starting fresh`);
                    } else {
                        this.logger.error(`Failed to load history: ${error.message}`);
                    }
                } else {
                    this.logger.error(`Failed to load history: ${String(error)}`);
                }
                this.history = {};
            }
        }
    }

    private save(): void {
        try {
            fs.writeFileSync(this.historyPath, JSON.stringify(this.history, null, 2));
        } catch (error) {
            // Specific error handling for common filesystem issues
            if (error instanceof Error) {
                const nodeError = error as NodeJS.ErrnoException;
                if (nodeError.code === 'EACCES') {
                    this.logger.error(`Permission denied writing history file: ${this.historyPath}`);
                } else if (nodeError.code === 'ENOSPC') {
                    this.logger.error(`Disk full - cannot save history file: ${this.historyPath}`);
                } else if (nodeError.code === 'EROFS') {
                    this.logger.error(`Read-only filesystem - cannot save history: ${this.historyPath}`);
                } else if (nodeError.code === 'EMFILE' || nodeError.code === 'ENFILE') {
                    this.logger.error(`Too many open files - cannot save history: ${this.historyPath}`);
                } else {
                    this.logger.error(`Failed to save history: ${error.message}`);
                }
            } else {
                this.logger.error(`Failed to save history: ${String(error)}`);
            }
        }
    }

    /**
     * Record a new run with input validation
     *
     * @param record - The trend data point to record
     * @throws Error if validation fails
     */
    addRecord(record: TrendDataPoint): void {
        // Validate input with Zod schema
        try {
            TrendDataPointSchema.parse(record);
        } catch (error) {
            if (error instanceof z.ZodError) {
                const issues = error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join(', ');
                throw new Error(`Invalid trend data point: ${issues}`);
            }
            throw error;
        }

        // Additional validation for reserved keywords (prototype pollution prevention)
        if (isReservedKeyword(record.targetUrl)) {
            throw new Error(`Invalid targetUrl: "${record.targetUrl}" is a reserved keyword`);
        }

        // Additional URL validation using native URL constructor
        if (!isValidUrl(record.targetUrl)) {
            throw new Error(`Invalid targetUrl: "${record.targetUrl}" is not a valid URL`);
        }

        // Additional range validation
        if (!isInRange(record.overallScore, 0, 100)) {
            throw new Error(`Invalid overallScore: ${record.overallScore} must be between 0 and 100`);
        }

        if (!isInRange(record.performanceScore, 0, 100)) {
            throw new Error(`Invalid performanceScore: ${record.performanceScore} must be between 0 and 100`);
        }

        if (record.securityCritical < 0) {
            throw new Error(`Invalid securityCritical: ${record.securityCritical} must be >= 0`);
        }

        // Initialize history for this URL if needed
        if (!this.history[record.targetUrl]) {
            this.history[record.targetUrl] = [];
        }

        this.history[record.targetUrl].push(record);

        // Keep only last N runs per target to prevent unlimited growth
        if (this.history[record.targetUrl].length > LIMITS.TREND_MAX_RECORDS_PER_TARGET) {
            this.history[record.targetUrl] = this.history[record.targetUrl].slice(-LIMITS.TREND_MAX_RECORDS_PER_TARGET);
        }

        this.save();
    }

    /**
     * Get historical trend data for a specific target URL
     *
     * Returns all recorded data points for the given target, ordered chronologically.
     * Limited to the most recent TREND_MAX_RECORDS_PER_TARGET (50) records.
     *
     * @param targetUrl - The target URL to get history for
     * @returns Array of trend data points (empty array if no history exists)
     *
     * @example
     * ```typescript
     * const history = trendService.getHistory('https://example.com');
     * console.log(`Found ${history.length} historical records`);
     * history.forEach(record => {
     *   console.log(`${record.timestamp}: Score ${record.overallScore}`);
     * });
     * ```
     */
    getHistory(targetUrl: string): TrendDataPoint[] {
        return this.history[targetUrl] || [];
    }

    /**
     * Get aggregate statistics and trend analysis for a target
     *
     * Calculates average score across all historical records and determines
     * trend direction by comparing the two most recent scores.
     *
     * @param targetUrl - The target URL to analyze
     * @returns Object containing average score and trend direction
     *   - avgScore: Mean of all overall scores (0 if no history)
     *   - trend: 'up' if improving, 'down' if degrading, 'stable' if unchanged or insufficient data
     *
     * @example
     * ```typescript
     * const stats = trendService.getStats('https://example.com');
     * console.log(`Average Score: ${stats.avgScore.toFixed(1)}`);
     * console.log(`Trend: ${stats.trend}`);
     *
     * if (stats.trend === 'down') {
     *   console.warn('Site health is degrading!');
     * }
     * ```
     */
    getStats(targetUrl: string): { avgScore: number, trend: 'up' | 'down' | 'stable' } {
        const records = this.getHistory(targetUrl);
        if (records.length === 0) return { avgScore: 0, trend: 'stable' };

        const total = records.reduce((sum, r) => sum + r.overallScore, 0);
        const avgScore = total / records.length;

        let trend: 'up' | 'down' | 'stable' = 'stable';
        if (records.length >= 2) {
            const last = records.at(-1)!.overallScore;
            const prev = records.at(-2)!.overallScore;
            if (last > prev) trend = 'up';
            else if (last < prev) trend = 'down';
        }

        return { avgScore, trend };
    }

    /**
     * Get complete history map for all targets
     *
     * Returns the entire history object containing data for all monitored URLs.
     * Useful for bulk export, reporting, or cross-target analysis.
     *
     * @returns Complete history map keyed by target URL
     *
     * @example
     * ```typescript
     * const allHistory = trendService.getAllHistory();
     * const targetCount = Object.keys(allHistory).length;
     * console.log(`Monitoring ${targetCount} targets`);
     *
     * for (const [url, records] of Object.entries(allHistory)) {
     *   console.log(`${url}: ${records.length} records`);
     * }
     * ```
     */
    getAllHistory(): TrendHistory {
        return this.history;
    }

    /**
     * Clean up old records beyond retention period
     *
     * Removes records older than RETENTION.TREND_MAX_AGE_DAYS (90 days) to prevent
     * unbounded memory growth.
     *
     * @returns Number of records removed
     */
    cleanupOldRecords(): number {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - RETENTION.TREND_MAX_AGE_DAYS);
        const cutoffTimestamp = cutoffDate.toISOString();

        let removedCount = 0;

        for (const targetUrl in this.history) {
            const originalLength = this.history[targetUrl].length;

            // Filter out records older than cutoff date
            this.history[targetUrl] = this.history[targetUrl].filter(
                (record) => record.timestamp >= cutoffTimestamp
            );

            const newLength = this.history[targetUrl].length;
            removedCount += originalLength - newLength;

            // Remove target entry if no records remain
            if (newLength === 0) {
                delete this.history[targetUrl];
            }
        }

        if (removedCount > 0) {
            this.save();
            this.logger.info(`Cleaned up ${removedCount} old trend records (older than ${RETENTION.TREND_MAX_AGE_DAYS} days)`);
        }

        return removedCount;
    }

    /**
     * Get cleanup statistics without performing cleanup
     *
     * @returns Information about records that would be removed
     */
    getCleanupStats(): {
        totalRecords: number;
        oldRecords: number;
        targetsAffected: number;
        cutoffDate: string;
    } {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - RETENTION.TREND_MAX_AGE_DAYS);
        const cutoffTimestamp = cutoffDate.toISOString();

        let totalRecords = 0;
        let oldRecords = 0;
        const targetsWithOldRecords = new Set<string>();

        for (const targetUrl in this.history) {
            for (const record of this.history[targetUrl]) {
                totalRecords++;
                if (record.timestamp < cutoffTimestamp) {
                    oldRecords++;
                    targetsWithOldRecords.add(targetUrl);
                }
            }
        }

        return {
            totalRecords,
            oldRecords,
            targetsAffected: targetsWithOldRecords.size,
            cutoffDate: cutoffTimestamp,
        };
    }
}
