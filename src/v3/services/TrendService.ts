/**
 * Trend Service
 * 
 * Manages historical compliance data to enable trend analysis.
 * Stores history in a JSON file (lightweight persistence).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { Logger } from '../../types/index.js';

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
                this.logger.error(`Failed to load history: ${error}`);
                this.history = {};
            }
        }
    }

    private save(): void {
        try {
            fs.writeFileSync(this.historyPath, JSON.stringify(this.history, null, 2));
        } catch (error) {
            this.logger.error(`Failed to save history: ${error}`);
        }
    }

    /**
     * record a new run
     */
    addRecord(record: TrendDataPoint): void {
        if (!this.history[record.targetUrl]) {
            this.history[record.targetUrl] = [];
        }
        
        this.history[record.targetUrl].push(record);
        
        // Keep only last 50 runs per target to prevent unlimited growth
        if (this.history[record.targetUrl].length > 50) {
           this.history[record.targetUrl] = this.history[record.targetUrl].slice(-50);
        }

        this.save();
    }

    /**
     * Get history for a target
     */
    getHistory(targetUrl: string): TrendDataPoint[] {
        return this.history[targetUrl] || [];
    }

    /**
     * Get aggregate stats for a target
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
     * Get full history map
     */
    getAllHistory(): TrendHistory {
        return this.history;
    }
}
