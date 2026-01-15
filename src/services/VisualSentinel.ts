/**
 * VisualSentinel Service
 * 
 * Performs visual regression testing by comparing current screenshots against a baseline.
 * Uses 'pixelmatch' to detect pixel-level differences.
 * 
 * Features:
 * - Automatic Baseline Creation: First run saves as "Golden Master".
 * - Visual Diff Generation: Highlights changes in Red.
 * - Threshold-based alerting: Flags regression if diff > 5%.
 */

import * as fs from 'fs';
import * as path from 'path';
import { PNG } from 'pngjs';
import pixelmatch from 'pixelmatch';
import { logger } from '../utils/logger';

export interface VisualTestResult {
    pageName: string;
    isBaseline: boolean; // True if this was the first run (baseline created)
    passed: boolean;
    diffPercentage: number;
    diffImagePath?: string;
    baselinePath: string;
    currentPath: string;
    error?: string;
}

const VISUAL_CONFIG = {
    baselineDir: 'snapshots/baseline',
    currentDir: 'snapshots/current',
    diffDir: 'snapshots/diff',
    threshold: 0.05, // 5% pixel difference allowed
};

export class VisualSentinel {
    constructor() {
        this.ensureDirectories();
    }

    /**
     * Compare a new screenshot against the baseline
     * @param pageName Unique identifier for the page (e.g., 'dashboard', 'loadout-m4')
     * @param currentScreenshotPath Path to the just-captured screenshot
     */
    async checkVisual(pageName: string, currentScreenshotPath: string): Promise<VisualTestResult> {
        const safeName = pageName.replace(/[^a-z0-9-]/gi, '_').toLowerCase();
        const baselinePath = path.resolve(VISUAL_CONFIG.baselineDir, `${safeName}.png`);
        const currentPath = path.resolve(VISUAL_CONFIG.currentDir, `${safeName}.png`);

        // Copy the current screenshot to the structured 'current' directory
        fs.copyFileSync(currentScreenshotPath, currentPath);

        // 1. Baseline Creation Check
        if (!fs.existsSync(baselinePath)) {
            logger.info(`VisualSentinel: No baseline found for '${pageName}'. Creating Golden Master.`);
            // Copy current as baseline
            fs.copyFileSync(currentPath, baselinePath);

            return {
                pageName,
                isBaseline: true,
                passed: true,
                diffPercentage: 0,
                baselinePath,
                currentPath
            };
        }

        // 2. Perform Comparison
        try {
            return await this.compareImages(baselinePath, currentPath, safeName);
        } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            logger.error(`VisualSentinel Error: ${msg}`);
            return {
                pageName,
                isBaseline: false,
                passed: false,
                diffPercentage: 0,
                baselinePath,
                currentPath,
                error: msg
            };
        }
    }

    /**
     * Compare two images using pixelmatch
     */
    private async compareImages(baselinePath: string, currentPath: string, safeName: string): Promise<VisualTestResult> {
        const img1 = PNG.sync.read(fs.readFileSync(baselinePath));
        const img2 = PNG.sync.read(fs.readFileSync(currentPath));
        const { width, height } = img1;
        const diff = new PNG({ width, height });

        // Handle dimension mismatch
        if (img1.width !== img2.width || img1.height !== img2.height) {
            logger.warn('VisualSentinel: Image dimensions mismatch. Comparing intersecting area.');
            // Resize logic is complex, for MVP we often fail or crop. 
            // Pixelmatch throws if sizes differ. We will skip if sizes differ for safety.
            // Or we could resize. For simplicity, we'll return failure.
            return {
                pageName: safeName,
                isBaseline: false,
                passed: false,
                diffPercentage: 100,
                baselinePath,
                currentPath,
                error: 'Dimension Mismatch detected'
            };
        }

        const numDiffPixels = pixelmatch(
            img1.data,
            img2.data,
            diff.data,
            width,
            height,
            { threshold: 0.1 } // Sensitivity for individual pixel comparison
        );

        const totalPixels = width * height;
        const diffPercentage = numDiffPixels / totalPixels;
        const passed = diffPercentage <= VISUAL_CONFIG.threshold;

        let diffImagePath: string | undefined;

        if (!passed) {
            // Save diff image
            diffImagePath = path.resolve(VISUAL_CONFIG.diffDir, `${safeName}_diff.png`);
            fs.writeFileSync(diffImagePath, PNG.sync.write(diff));
            logger.warn(`Visual Regression: ${safeName} differs by ${(diffPercentage * 100).toFixed(2)}%`);
        } else {
            logger.info(`Visual Check Passed: ${safeName} (${(diffPercentage * 100).toFixed(2)}%)`);
        }

        return {
            pageName: safeName,
            isBaseline: false,
            passed,
            diffPercentage,
            diffImagePath,
            baselinePath,
            currentPath
        };
    }

    /**
     * Ensure storage directories exist
     */
    private ensureDirectories() {
        [VISUAL_CONFIG.baselineDir, VISUAL_CONFIG.currentDir, VISUAL_CONFIG.diffDir].forEach(dir => {
            const fullPath = path.resolve(dir);
            if (!fs.existsSync(fullPath)) {
                fs.mkdirSync(fullPath, { recursive: true });
            }
        });
    }
}
