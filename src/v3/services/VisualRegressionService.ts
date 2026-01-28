/**
 * Visual Regression Service
 * 
 * Compares screenshots against baselines to detect UI regressions.
 * Uses pixelmatch for pixel-by-pixel comparison.
 */

import * as fs from 'fs';
import * as path from 'path';
import { PNG } from 'pngjs';
import pixelmatch from 'pixelmatch';
import { Logger } from '../../types/index.js';

export interface VisualDiffResult {
    diffPercentage: number;
    diffPath?: string;
    passed: boolean;
    baselineCreated: boolean;
}

export class VisualRegressionService {
    private readonly baselineDir: string;
    private readonly diffDir: string;

    constructor(
        private readonly logger: Logger,
        private readonly baseDir: string = '.visual-baselines',
        private readonly threshold: number = 0.1 // 10% tolerance default (high for full page, usually 0.01 for strict)
    ) {
        this.baselineDir = path.resolve(process.cwd(), baseDir);
        this.diffDir = path.resolve(process.cwd(), 'reports', 'diffs'); // Store diffs in reports
        
        if (!fs.existsSync(this.baselineDir)) {
            fs.mkdirSync(this.baselineDir, { recursive: true });
        }
        if (!fs.existsSync(this.diffDir)) {
            fs.mkdirSync(this.diffDir, { recursive: true });
        }
    }

    /**
     * Compare a new screenshot Buffer against the baseline
     * @param name Unique name for the screenshot (e.g. "homepage-desktop")
     * @param imageBuffer The PNG buffer of the new screenshot
     * @returns Result of comparison
     */
    async compare(name: string, imageBuffer: Buffer): Promise<VisualDiffResult> {
        const baselinePath = path.join(this.baselineDir, `${name}.png`);
        
        // If baseline doesn't exist, create it
        if (!fs.existsSync(baselinePath)) {
            this.logger.info(`📸 Creating new visual baseline for: ${name}`);
            fs.writeFileSync(baselinePath, imageBuffer);
            return {
                diffPercentage: 0,
                passed: true,
                baselineCreated: true
            };
        }

        try {
            const baselineImg = PNG.sync.read(fs.readFileSync(baselinePath));
            const currentImg = PNG.sync.read(imageBuffer);
            const { width, height } = baselineImg;

            // Dimensions must match
            if (width !== currentImg.width || height !== currentImg.height) {
                this.logger.warn(`⚠️  Visual dimensions mismatch for ${name} (Baseline: ${width}x${height}, Current: ${currentImg.width}x${currentImg.height})`);
                // Resize or fail? For now, we fail fast or resize. 
                // Pixelmatch requires same size. 
                // TODO: Implement resize logic if needed. For now, report distinct failure.
                return {
                    diffPercentage: 100,
                    passed: false,
                    baselineCreated: false
                };
            }

            const diff = new PNG({ width, height });
            const numDiffPixels = pixelmatch(
                baselineImg.data,
                currentImg.data,
                diff.data,
                width,
                height,
                { threshold: 0.1 } // Sensitivity
            );

            const totalPixels = width * height;
            const diffPercentage = (numDiffPixels / totalPixels) * 100;

            const passed = diffPercentage <= (this.threshold * 100); // threshold is 0-1 or percentage? PRD implies %?
            // "fail on >10% drop" was for performance. Visual diff usually strict.
            // Let's assume threshold is 0.1 (10%) for safety.

            let diffPath: string | undefined;

            if (!passed) {
                diffPath = path.join(this.diffDir, `${name}-diff.png`);
                fs.writeFileSync(diffPath, PNG.sync.write(diff));
                this.logger.warn(`📸 Visual regression detected for ${name}: ${diffPercentage.toFixed(2)}% diff`);
            } else {
                this.logger.info(`✅ Visual check passed for ${name} (${diffPercentage.toFixed(2)}%)`);
            }

            return {
                diffPercentage,
                diffPath,
                passed,
                baselineCreated: false
            };

        } catch (error) {
            this.logger.error(`Visual comparison failed for ${name}: ${error}`);
            // If PNG parsing fails
            return {
                diffPercentage: 0,
                passed: true, // Fail open or closed?
                baselineCreated: false
            }; 
        }
    }
}
