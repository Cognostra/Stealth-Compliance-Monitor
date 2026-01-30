/**
 * Visual AI Compliance Service
 *
 * Post-processing service that analyzes screenshots for visual compliance:
 * - WCAG color contrast ratio violations
 * - Missing alt text on images
 * - Brand color validation against a reference palette
 * - Text-as-image detection (accessibility concern)
 */

import { readFileSync, existsSync } from 'node:fs';
import type { Page } from 'playwright';
import { logger } from '../utils/logger.js';
import { safeEvaluate } from '../utils/page-helpers.js';

export interface VisualComplianceFinding {
    type: 'text-as-image' | 'contrast-violation' | 'ui-hierarchy' | 'brand-violation' | 'missing-alt-text';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    url: string;
    region?: { x: number; y: number; width: number; height: number };
    wcagCriteria?: string;
    remediation?: string;
}

export interface BrandColorPalette {
    primary: string[];
    secondary: string[];
    accent: string[];
    forbidden: string[];
}

interface ContrastResult {
    element: string;
    foreground: string;
    background: string;
    ratio: number;
    fontSize: number;
    fontWeight: string;
    required: number;
    passes: boolean;
}

interface ImageInfo {
    src: string;
    alt: string | null;
    width: number;
    height: number;
    isDecorative: boolean;
    role: string | null;
    ariaLabel: string | null;
    ariaHidden: boolean;
}

/**
 * Parse a CSS color string to RGB values.
 */
function parseColor(color: string): [number, number, number] | null {
    // rgb(r, g, b) or rgba(r, g, b, a)
    const rgbMatch = color.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
    if (rgbMatch) {
        return [parseInt(rgbMatch[1]), parseInt(rgbMatch[2]), parseInt(rgbMatch[3])];
    }
    // Hex
    const hexMatch = color.match(/^#([0-9a-f]{6})$/i);
    if (hexMatch) {
        const hex = hexMatch[1];
        return [parseInt(hex.slice(0, 2), 16), parseInt(hex.slice(2, 4), 16), parseInt(hex.slice(4, 6), 16)];
    }
    const shortHexMatch = color.match(/^#([0-9a-f]{3})$/i);
    if (shortHexMatch) {
        const hex = shortHexMatch[1];
        return [
            parseInt(hex[0] + hex[0], 16),
            parseInt(hex[1] + hex[1], 16),
            parseInt(hex[2] + hex[2], 16),
        ];
    }
    return null;
}

/**
 * Calculate relative luminance per WCAG 2.1.
 */
function relativeLuminance(r: number, g: number, b: number): number {
    const [rs, gs, bs] = [r / 255, g / 255, b / 255].map(c =>
        c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)
    );
    return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
}

/**
 * Calculate contrast ratio between two colors.
 */
function contrastRatio(color1: [number, number, number], color2: [number, number, number]): number {
    const l1 = relativeLuminance(...color1);
    const l2 = relativeLuminance(...color2);
    const lighter = Math.max(l1, l2);
    const darker = Math.min(l1, l2);
    return (lighter + 0.05) / (darker + 0.05);
}

/**
 * Get required contrast ratio based on font size and weight (WCAG 2.1 Level AA).
 */
function getRequiredContrast(fontSize: number, fontWeight: string): number {
    const isBold = parseInt(fontWeight) >= 700 || fontWeight === 'bold';
    const isLargeText = fontSize >= 24 || (fontSize >= 18.66 && isBold);
    return isLargeText ? 3.0 : 4.5;
}

export class VisualAiCompliance {
    private findings: VisualComplianceFinding[] = [];
    private brandPalette: BrandColorPalette | null = null;

    constructor(brandGuidePath?: string) {
        if (brandGuidePath && existsSync(brandGuidePath)) {
            try {
                this.brandPalette = JSON.parse(readFileSync(brandGuidePath, 'utf-8')) as BrandColorPalette;
                logger.debug('[VisualAiCompliance] Loaded brand color palette');
            } catch {
                logger.warn('[VisualAiCompliance] Failed to parse brand guide file');
            }
        }
    }

    /**
     * Run all visual compliance checks on a page.
     */
    async analyze(page: Page): Promise<VisualComplianceFinding[]> {
        const url = page.url();
        this.findings = [];

        await Promise.all([
            this.checkContrastRatios(page, url),
            this.checkMissingAltText(page, url),
            this.checkTextAsImage(page, url),
        ]);

        if (this.brandPalette) {
            await this.checkBrandCompliance(page, url);
        }

        logger.info(`[VisualAiCompliance] ${this.findings.length} findings on ${url}`);
        return [...this.findings];
    }

    /**
     * Check color contrast ratios for text elements.
     */
    private async checkContrastRatios(page: Page, url: string): Promise<void> {
        const results = await safeEvaluate<ContrastResult[]>(page, () => {
            const textElements = document.querySelectorAll(
                'p, span, a, h1, h2, h3, h4, h5, h6, li, td, th, label, button, input, textarea, select, summary, figcaption, blockquote, dt, dd'
            );

            const contrastResults: ContrastResult[] = [];
            const checked = new Set<string>();

            for (const el of textElements) {
                if (contrastResults.length >= 100) break;

                const text = el.textContent?.trim();
                if (!text || text.length === 0) continue;

                const style = window.getComputedStyle(el);
                if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') continue;

                const fg = style.color;
                const bg = style.backgroundColor;
                const key = `${fg}:${bg}:${style.fontSize}:${style.fontWeight}`;
                if (checked.has(key)) continue;
                checked.add(key);

                contrastResults.push({
                    element: `<${el.tagName.toLowerCase()}>${text.slice(0, 50)}`,
                    foreground: fg,
                    background: bg,
                    ratio: 0,
                    fontSize: parseFloat(style.fontSize),
                    fontWeight: style.fontWeight,
                    required: 0,
                    passes: true,
                });
            }

            return contrastResults;
        });

        if (!results) return;

        for (const result of results) {
            const fg = parseColor(result.foreground);
            const bg = parseColor(result.background);
            if (!fg || !bg) continue;

            // Skip transparent backgrounds (rgba with 0 alpha)
            if (result.background.includes('rgba') && result.background.match(/,\s*0\s*\)/)) continue;

            const ratio = contrastRatio(fg, bg);
            const required = getRequiredContrast(result.fontSize, result.fontWeight);

            if (ratio < required) {
                this.addFinding({
                    type: 'contrast-violation',
                    severity: ratio < 2.0 ? 'critical' : ratio < 3.0 ? 'high' : 'medium',
                    description: `Text contrast ratio ${ratio.toFixed(2)}:1 is below WCAG AA requirement of ${required}:1`,
                    evidence: `Element ${result.element} - foreground: ${result.foreground}, background: ${result.background}`,
                    url,
                    wcagCriteria: 'WCAG 2.1 SC 1.4.3 (Contrast Minimum)',
                    remediation: `Increase contrast ratio to at least ${required}:1. Current ratio: ${ratio.toFixed(2)}:1`,
                });
            }
        }
    }

    /**
     * Check for images missing alt text.
     */
    private async checkMissingAltText(page: Page, url: string): Promise<void> {
        const images = await safeEvaluate<ImageInfo[]>(page, () => {
            const imgs = document.querySelectorAll('img, [role="img"], svg[role="img"]');
            return Array.from(imgs).slice(0, 200).map(img => ({
                src: (img as HTMLImageElement).src || '',
                alt: img.getAttribute('alt'),
                width: (img as HTMLImageElement).naturalWidth || (img as HTMLElement).clientWidth || 0,
                height: (img as HTMLImageElement).naturalHeight || (img as HTMLElement).clientHeight || 0,
                isDecorative: img.getAttribute('role') === 'presentation' || img.getAttribute('aria-hidden') === 'true',
                role: img.getAttribute('role'),
                ariaLabel: img.getAttribute('aria-label'),
                ariaHidden: img.getAttribute('aria-hidden') === 'true',
            }));
        });

        if (!images) return;

        for (const img of images) {
            // Skip decorative images
            if (img.isDecorative || img.ariaHidden) continue;
            // Skip tiny images (likely icons/spacers)
            if (img.width < 10 && img.height < 10) continue;

            if (img.alt === null && !img.ariaLabel) {
                this.addFinding({
                    type: 'missing-alt-text',
                    severity: img.width > 100 || img.height > 100 ? 'high' : 'medium',
                    description: 'Image is missing alt text, making it inaccessible to screen readers',
                    evidence: `<img src="${img.src.slice(0, 200)}"> (${img.width}x${img.height})`,
                    url,
                    wcagCriteria: 'WCAG 2.1 SC 1.1.1 (Non-text Content)',
                    remediation: 'Add descriptive alt attribute, or role="presentation" if decorative',
                });
            } else if (img.alt !== null && img.alt.trim() === '' && !img.isDecorative) {
                // Empty alt without presentation role
                if (img.width > 50 && img.height > 50) {
                    this.addFinding({
                        type: 'missing-alt-text',
                        severity: 'low',
                        description: 'Significant image has empty alt text but is not marked as decorative',
                        evidence: `<img src="${img.src.slice(0, 200)}" alt=""> (${img.width}x${img.height})`,
                        url,
                        wcagCriteria: 'WCAG 2.1 SC 1.1.1 (Non-text Content)',
                        remediation: 'Add descriptive alt text or mark as decorative with role="presentation"',
                    });
                }
            }
        }
    }

    /**
     * Detect potential text rendered as images (accessibility concern).
     */
    private async checkTextAsImage(page: Page, url: string): Promise<void> {
        const suspects = await safeEvaluate<Array<{ src: string; width: number; height: number; context: string }>>(page, () => {
            const results: Array<{ src: string; width: number; height: number; context: string }> = [];
            const imgs = document.querySelectorAll('img');

            for (const img of imgs) {
                if (results.length >= 50) break;
                const w = img.naturalWidth || img.clientWidth;
                const h = img.naturalHeight || img.clientHeight;

                // Heuristic: wide, short images in content areas are likely text banners
                if (w > 200 && h > 20 && h < 150 && w / h > 3) {
                    const parent = img.parentElement;
                    const inContent = parent?.closest('main, article, section, [role="main"]');
                    if (inContent) {
                        results.push({
                            src: img.src.slice(0, 200),
                            width: w,
                            height: h,
                            context: parent?.tagName.toLowerCase() || 'unknown',
                        });
                    }
                }

                // Also check for images with text-like alt text that are large
                const alt = img.getAttribute('alt') || '';
                if (alt.length > 20 && w > 100 && h > 30) {
                    results.push({
                        src: img.src.slice(0, 200),
                        width: w,
                        height: h,
                        context: `alt="${alt.slice(0, 80)}"`,
                    });
                }
            }

            return results;
        });

        if (!suspects) return;

        for (const suspect of suspects) {
            this.addFinding({
                type: 'text-as-image',
                severity: 'medium',
                description: 'Possible text rendered as image detected - inaccessible to screen readers and not scalable',
                evidence: `Image ${suspect.src} (${suspect.width}x${suspect.height}) in ${suspect.context}`,
                url,
                wcagCriteria: 'WCAG 2.1 SC 1.4.5 (Images of Text)',
                remediation: 'Replace image of text with actual HTML text styled with CSS',
            });
        }
    }

    /**
     * Check page colors against brand palette.
     */
    private async checkBrandCompliance(page: Page, url: string): Promise<void> {
        if (!this.brandPalette) return;

        const pageColors = await safeEvaluate<string[]>(page, () => {
            const elements = document.querySelectorAll('*');
            const colors = new Set<string>();

            for (const el of elements) {
                if (colors.size >= 200) break;
                const style = window.getComputedStyle(el);
                if (style.color && style.color !== 'rgba(0, 0, 0, 0)') colors.add(style.color);
                if (style.backgroundColor && style.backgroundColor !== 'rgba(0, 0, 0, 0)') colors.add(style.backgroundColor);
                if (style.borderColor && style.borderColor !== 'rgba(0, 0, 0, 0)') colors.add(style.borderColor);
            }

            return Array.from(colors);
        });

        if (!pageColors) return;

        const forbidden = this.brandPalette.forbidden || [];
        for (const color of pageColors) {
            const rgb = parseColor(color);
            if (!rgb) continue;

            for (const forbiddenColor of forbidden) {
                const forbiddenRgb = parseColor(forbiddenColor);
                if (!forbiddenRgb) continue;

                if (colorDistance(rgb, forbiddenRgb) < 15) {
                    this.addFinding({
                        type: 'brand-violation',
                        severity: 'low',
                        description: `Color ${color} matches forbidden brand color ${forbiddenColor}`,
                        evidence: `Forbidden color detected on page: ${color}`,
                        url,
                        remediation: `Replace color ${color} with an approved brand color`,
                    });
                }
            }
        }
    }

    private addFinding(finding: VisualComplianceFinding): void {
        const key = `${finding.type}:${finding.evidence.slice(0, 80)}`;
        if (!this.findings.some(f => `${f.type}:${f.evidence.slice(0, 80)}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): VisualComplianceFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
    }
}

/**
 * Euclidean distance between two RGB colors.
 */
function colorDistance(c1: [number, number, number], c2: [number, number, number]): number {
    return Math.sqrt(
        Math.pow(c1[0] - c2[0], 2) +
        Math.pow(c1[1] - c2[1], 2) +
        Math.pow(c1[2] - c2[2], 2)
    );
}
