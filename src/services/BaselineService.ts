/**
 * BaselineService
 * 
 * Manages false positives and accepted risks.
 * Loads ignore rules from .complianceignore.json
 */

import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger.js';

export interface IgnoreRule {
    ruleId: string;
    selector?: string;
    path?: string;
    reason: string;
    expires?: string;
}

export class BaselineService {
    private ignoreRules: IgnoreRule[] = [];
    private readonly ignoreFilePath: string;

    constructor(rootPath: string = process.cwd()) {
        this.ignoreFilePath = path.join(rootPath, '.complianceignore.json');
        this.loadRules();
    }

    private loadRules(): void {
        try {
            if (fs.existsSync(this.ignoreFilePath)) {
                const content = fs.readFileSync(this.ignoreFilePath, 'utf-8');
                this.ignoreRules = JSON.parse(content);
                logger.info(`Loaded ${this.ignoreRules.length} baseline rules from .complianceignore.json`);
            } else {
                logger.debug('No .complianceignore.json found, starting with empty baseline.');
            }
        } catch (error) {
            logger.error(`Failed to load .complianceignore.json: ${error}`);
        }
    }

    /**
     * Check if an issue should be ignored
     * @param ruleId - Unique ID of the rule
     * @param selector - The specific target selector (optional)
     * @param path - The URL path where issue was found (optional)
     */
    shouldIgnore(ruleId: string, selector?: string, path?: string): boolean {
        const now = new Date();

        return this.ignoreRules.some(rule => {
            // 1. Check Rule ID match
            if (rule.ruleId !== ruleId) return false;

            // 2. Check Selector match (if rule has a selector, the issue must match it)
            if (rule.selector) {
                if (!selector || !selector.includes(rule.selector)) {
                    return false;
                }
            }

            // 3. Check Path match (if rule has a path, the issue url must contain it)
            if (rule.path) {
                if (!path || !path.includes(rule.path)) {
                    return false;
                }
            }

            // 4. Check Expiration (if rule has an expiration date)
            if (rule.expires) {
                const expirationDate = new Date(rule.expires);
                if (now > expirationDate) {
                    logger.warn(`Ignore rule for ${ruleId} has expired on ${rule.expires}`);
                    return false;
                }
            }

            return true;
        });
    }
}

export const baselineService = new BaselineService();
