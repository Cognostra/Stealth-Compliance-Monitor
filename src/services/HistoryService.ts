/**
 * History Service
 * Tracks historical run data for trend analysis
 */

import * as fs from 'fs';
import * as path from 'path';
import { EnvConfig, getConfig } from '../config/env';
import { logger } from '../utils/logger';

export interface RunSummary {
    timestamp: string;
    targetUrl: string;
    overallScore: number;
    performanceScore: number;
    accessibilityScore: number;
    securityScore: number;
    metrics: {
        criticalIssues: number;
        highIssues: number;
        passed: boolean;
        duration: number;
        pagesVisited: number;
    };
}

export class HistoryService {
    private config: EnvConfig;
    private historyFile: string;

    constructor() {
        this.config = getConfig();
        // Ensure reports dir exists
        if (!fs.existsSync(this.config.REPORTS_DIR)) {
            fs.mkdirSync(this.config.REPORTS_DIR, { recursive: true });
        }
        this.historyFile = path.join(this.config.REPORTS_DIR, 'history.json');
    }

    /**
     * Save the current run Summary to history
     */
    saveRun(summary: RunSummary): void {
        try {
            const history = this.getTrendData();

            // Add new run
            history.push(summary);

            // Keep only last 30 runs to prevent infinite growth
            if (history.length > 30) {
                history.shift(); // Remove oldest
            }

            fs.writeFileSync(this.historyFile, JSON.stringify(history, null, 2));
            logger.info('Run summary saved to history.json');
        } catch (error) {
            logger.error(`Failed to save history: ${error}`);
        }
    }

    /**
     * Get historical trend data (last 30 runs)
     */
    getTrendData(): RunSummary[] {
        try {
            if (!fs.existsSync(this.historyFile)) {
                return [];
            }

            const content = fs.readFileSync(this.historyFile, 'utf-8');
            return JSON.parse(content);
        } catch (error) {
            logger.warn(`Failed to load history: ${error}`);
            return [];
        }
    }
}
