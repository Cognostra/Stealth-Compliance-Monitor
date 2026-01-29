/**
 * FlutterSemanticsScanner - Flutter Web Accessibility Inspector
 *
 * Flutter web renders to HTML5 Canvas but generates a separate DOM tree
 * of `flt-semantics` elements with ARIA attributes for screen readers.
 * This scanner inspects those elements to verify accessibility compliance.
 *
 * Gracefully skips non-Flutter pages (returns empty results).
 * Implements IScanner for registry-based lifecycle management.
 */

import { Page, Response } from 'playwright';
import { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface FlutterSemanticsIssue {
    type: 'missing-semantics' | 'incomplete-aria' | 'missing-focus' | 'missing-label' | 'missing-role' | 'missing-live-region';
    severity: 'high' | 'medium' | 'low';
    element: string;
    description: string;
    url?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCANNER IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class FlutterSemanticsScanner implements IScanner {
    readonly name = 'FlutterSemanticsScanner';

    private issues: FlutterSemanticsIssue[] = [];
    private page: Page | null = null;
    private isFlutterApp = false;
    private flutterDetected = false;

    // ═══════════════════════════════════════════════════════════════════════════
    // IScanner Lifecycle Hooks
    // ═══════════════════════════════════════════════════════════════════════════

    onPageCreated(page: Page): void {
        if (this.page === page) return;
        this.page = page;
        this.isFlutterApp = false;
        this.flutterDetected = false;
        logger.debug('FlutterSemanticsScanner attached to page');
    }

    async onResponse(response: Response): Promise<void> {
        // Detect Flutter service worker as a strong indicator
        if (!this.flutterDetected && response.url().includes('flutter_service_worker.js')) {
            this.flutterDetected = true;
            this.isFlutterApp = true;
            logger.info('  🦋 Flutter web app detected via service worker');
        }
    }

    onClose(): void {
        logger.debug(`FlutterSemanticsScanner: Collected ${this.issues.length} issues`);
    }

    getResults(): FlutterSemanticsIssue[] {
        return [...this.issues];
    }

    clear(): void {
        this.issues = [];
        this.isFlutterApp = false;
        this.flutterDetected = false;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PAGE-LEVEL CHECKS (call after page load)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Run all Flutter semantics checks on the current page.
     * Returns empty array if this is not a Flutter web app.
     */
    async runPageChecks(page: Page): Promise<FlutterSemanticsIssue[]> {
        const pageIssues: FlutterSemanticsIssue[] = [];

        // Detect Flutter if not already detected via service worker
        if (!this.isFlutterApp) {
            this.isFlutterApp = await this.detectFlutter(page);
        }

        if (!this.isFlutterApp) {
            logger.debug('FlutterSemanticsScanner: Not a Flutter web app, skipping');
            return [];
        }

        logger.info('  🦋 Running Flutter semantics accessibility checks');

        // Check semantics tree presence
        const treeIssues = await this.checkSemanticsTree(page);
        pageIssues.push(...treeIssues);

        // If no semantics tree, remaining checks are moot
        if (treeIssues.some(i => i.type === 'missing-semantics')) {
            this.issues.push(...pageIssues);
            return pageIssues;
        }

        // Run detailed checks
        const ariaIssues = await this.checkAriaCompleteness(page);
        pageIssues.push(...ariaIssues);

        const focusIssues = await this.checkFocusManagement(page);
        pageIssues.push(...focusIssues);

        const liveRegionIssues = await this.checkLiveRegions(page);
        pageIssues.push(...liveRegionIssues);

        this.issues.push(...pageIssues);
        return pageIssues;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DETECTION
    // ═══════════════════════════════════════════════════════════════════════════

    private async detectFlutter(page: Page): Promise<boolean> {
        try {
            return await page.evaluate(() => {
                // Check for Flutter-specific DOM elements
                const glassPane = document.querySelector('flt-glass-pane');
                const textHost = document.querySelector('flt-text-editing-host');
                const flutterView = document.querySelector('flutter-view');

                // Check for Flutter's semantics host
                const semanticsHost = document.querySelector('flt-semantics-host');

                // Check for Flutter-specific scripts
                const scripts = Array.from(document.querySelectorAll('script[src]'));
                const hasFlutterScript = scripts.some(s =>
                    (s as HTMLScriptElement).src.includes('flutter') ||
                    (s as HTMLScriptElement).src.includes('main.dart.js')
                );

                return !!(glassPane || textHost || flutterView || semanticsHost || hasFlutterScript);
            });
        } catch {
            return false;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SEMANTICS TREE CHECKS
    // ═══════════════════════════════════════════════════════════════════════════

    private async checkSemanticsTree(page: Page): Promise<FlutterSemanticsIssue[]> {
        const issues: FlutterSemanticsIssue[] = [];

        try {
            const treeInfo = await page.evaluate(() => {
                const semanticsHost = document.querySelector('flt-semantics-host');
                if (!semanticsHost) {
                    return { exists: false, childCount: 0, hasContent: false };
                }

                const semanticsNodes = semanticsHost.querySelectorAll('flt-semantics');
                return {
                    exists: true,
                    childCount: semanticsNodes.length,
                    hasContent: semanticsNodes.length > 0,
                };
            });

            if (!treeInfo.exists) {
                issues.push({
                    type: 'missing-semantics',
                    severity: 'high',
                    element: 'flt-semantics-host',
                    description: 'Flutter semantics tree not found. Accessibility semantics may be disabled. Enable semantics in your Flutter web build.',
                    url: page.url(),
                });
            } else if (!treeInfo.hasContent) {
                issues.push({
                    type: 'missing-semantics',
                    severity: 'high',
                    element: 'flt-semantics-host',
                    description: 'Flutter semantics host exists but contains no semantics nodes. Ensure SemanticsBinding is initialized.',
                    url: page.url(),
                });
            }
        } catch {
            // Page evaluation may fail
        }

        return issues;
    }

    private async checkAriaCompleteness(page: Page): Promise<FlutterSemanticsIssue[]> {
        const issues: FlutterSemanticsIssue[] = [];

        try {
            const ariaProblems = await page.evaluate(() => {
                const problems: { element: string; issue: string; type: string }[] = [];
                const semanticsHost = document.querySelector('flt-semantics-host');
                if (!semanticsHost) return problems;

                const nodes = semanticsHost.querySelectorAll('flt-semantics');
                nodes.forEach((node, index) => {
                    const el = node as HTMLElement;
                    const role = el.getAttribute('role');
                    const ariaLabel = el.getAttribute('aria-label');
                    const textContent = el.textContent?.trim();
                    const isInteractive = role === 'button' || role === 'link' || role === 'textbox' ||
                        role === 'checkbox' || role === 'radio' || role === 'slider' ||
                        role === 'tab' || role === 'menuitem';

                    // Check interactive elements have roles
                    if (el.hasAttribute('flt-tappable') && !role) {
                        problems.push({
                            element: `flt-semantics[${index}]`,
                            issue: 'Tappable element missing ARIA role',
                            type: 'missing-role',
                        });
                    }

                    // Check interactive elements have labels
                    if (isInteractive && !ariaLabel && !textContent) {
                        problems.push({
                            element: `flt-semantics[${index}] role="${role}"`,
                            issue: `Interactive element (role="${role}") missing aria-label or text content`,
                            type: 'missing-label',
                        });
                    }

                    // Check text nodes have content or label
                    if (role === 'text' && !ariaLabel && !textContent) {
                        problems.push({
                            element: `flt-semantics[${index}] role="text"`,
                            issue: 'Text semantics node has no label or content',
                            type: 'missing-label',
                        });
                    }

                    // Check headings have appropriate levels
                    if (role === 'heading' && !el.getAttribute('aria-level')) {
                        problems.push({
                            element: `flt-semantics[${index}] role="heading"`,
                            issue: 'Heading element missing aria-level attribute',
                            type: 'incomplete-aria',
                        });
                    }

                    // Check images have alt text
                    if (role === 'img' && !ariaLabel) {
                        problems.push({
                            element: `flt-semantics[${index}] role="img"`,
                            issue: 'Image element missing aria-label (alt text)',
                            type: 'missing-label',
                        });
                    }
                });

                return problems;
            });

            for (const problem of ariaProblems) {
                const severityMap: Record<string, 'high' | 'medium' | 'low'> = {
                    'missing-role': 'high',
                    'missing-label': 'medium',
                    'incomplete-aria': 'medium',
                };

                issues.push({
                    type: problem.type as FlutterSemanticsIssue['type'],
                    severity: severityMap[problem.type] || 'medium',
                    element: problem.element,
                    description: problem.issue,
                    url: page.url(),
                });
            }
        } catch {
            // Page evaluation may fail
        }

        return issues;
    }

    private async checkFocusManagement(page: Page): Promise<FlutterSemanticsIssue[]> {
        const issues: FlutterSemanticsIssue[] = [];

        try {
            const focusProblems = await page.evaluate(() => {
                const problems: { element: string; issue: string }[] = [];
                const semanticsHost = document.querySelector('flt-semantics-host');
                if (!semanticsHost) return problems;

                const interactiveNodes = semanticsHost.querySelectorAll(
                    'flt-semantics[role="button"], flt-semantics[role="link"], ' +
                    'flt-semantics[role="textbox"], flt-semantics[role="checkbox"], ' +
                    'flt-semantics[role="radio"], flt-semantics[role="tab"]'
                );

                interactiveNodes.forEach((node, index) => {
                    const el = node as HTMLElement;
                    const tabIndex = el.getAttribute('tabindex');

                    // Interactive elements should be focusable
                    if (tabIndex === null && !el.hasAttribute('contenteditable')) {
                        problems.push({
                            element: `flt-semantics[role="${el.getAttribute('role')}"][${index}]`,
                            issue: `Interactive element (role="${el.getAttribute('role')}") missing tabindex for keyboard navigation`,
                        });
                    }
                });

                return problems;
            });

            for (const problem of focusProblems) {
                issues.push({
                    type: 'missing-focus',
                    severity: 'medium',
                    element: problem.element,
                    description: problem.issue,
                    url: page.url(),
                });
            }
        } catch {
            // Page evaluation may fail
        }

        return issues;
    }

    private async checkLiveRegions(page: Page): Promise<FlutterSemanticsIssue[]> {
        const issues: FlutterSemanticsIssue[] = [];

        try {
            const liveRegionProblems = await page.evaluate(() => {
                const problems: { element: string; issue: string }[] = [];
                const semanticsHost = document.querySelector('flt-semantics-host');
                if (!semanticsHost) return problems;

                // Check for nodes marked as live regions
                const liveRegions = semanticsHost.querySelectorAll('flt-semantics[aria-live]');

                // Check nodes with role="alert" or role="status" have aria-live
                const alertNodes = semanticsHost.querySelectorAll(
                    'flt-semantics[role="alert"], flt-semantics[role="status"]'
                );

                alertNodes.forEach((node, index) => {
                    const el = node as HTMLElement;
                    if (!el.getAttribute('aria-live')) {
                        problems.push({
                            element: `flt-semantics[role="${el.getAttribute('role')}"][${index}]`,
                            issue: `Dynamic content element (role="${el.getAttribute('role')}") missing aria-live attribute`,
                        });
                    }
                });

                // Check for snackbar/toast patterns without live region
                const dynamicContainers = semanticsHost.querySelectorAll(
                    'flt-semantics[flt-is-live-region]'
                );
                dynamicContainers.forEach((node, index) => {
                    const el = node as HTMLElement;
                    if (!el.getAttribute('aria-live')) {
                        problems.push({
                            element: `flt-semantics[flt-is-live-region][${index}]`,
                            issue: 'Flutter live region marker present but missing aria-live attribute',
                        });
                    }
                });

                return problems;
            });

            for (const problem of liveRegionProblems) {
                issues.push({
                    type: 'missing-live-region',
                    severity: 'medium',
                    element: problem.element,
                    description: problem.issue,
                    url: page.url(),
                });
            }
        } catch {
            // Page evaluation may fail
        }

        return issues;
    }
}

export default FlutterSemanticsScanner;
