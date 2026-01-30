/**
 * ShadowDomScanner - Web Components & Shadow DOM Accessibility/Security Scanner
 *
 * Detects accessibility and security issues in Web Components:
 * - Slot content accessibility (missing aria-labels, focus management)
 * - Shadow boundary information leakage (CSS custom properties)
 * - Custom element security (constructor side effects, disconnectedCallback cleanup)
 * - Shadow DOM CSS isolation verification
 * - Form association in custom elements (formdata event)
 * - ARIA delegation patterns in shadow DOM
 *
 * Implements IScanner for registry-based lifecycle management.
 */

import { Page } from 'playwright';
import { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export type ShadowDomFindingType =
    | 'inaccessible-slot'
    | 'aria-missing'
    | 'shadow-leak'
    | 'custom-element-error'
    | 'form-association-missing';

export interface ShadowDomFinding {
    type: ShadowDomFindingType;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    element: string;
    details: string;
    remediation: string;
}

interface SlotAccessibilityInfo {
    slotName: string;
    hasAriaLabel: boolean;
    hasAriaLabelledBy: boolean;
    hasTabIndex: boolean;
    focusableContent: boolean;
    missingFocusManagement: boolean;
}

interface ShadowBoundaryInfo {
    customElementTag: string;
    shadowMode: 'open' | 'closed';
    cssCustomProperties: string[];
    potentialLeaks: string[];
}

interface FormAssociationInfo {
    customElementTag: string;
    hasFormAssociated: boolean;
    hasFormDataCallback: boolean;
    hasAttachInternals: boolean;
    missingFormAssociation: boolean;
}

interface AriaDelegationInfo {
    customElementTag: string;
    hasAriaDelegation: boolean;
    ariaAttributes: string[];
    missingDelegation: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCANNER IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class ShadowDomScanner implements IScanner {
    readonly name = 'ShadowDomScanner';

    private findings: ShadowDomFinding[] = [];
    private page: Page | null = null;
    private scannedPages = new Set<string>();

    // ═══════════════════════════════════════════════════════════════════════════
    // IScanner Lifecycle Hooks
    // ═══════════════════════════════════════════════════════════════════════════

    onPageCreated(page: Page): void {
        this.page = page;
        logger.info('  🕸️ Shadow DOM Scanner attached to browser session');
    }

    onClose(): void {
        logger.debug(`ShadowDomScanner: Collected ${this.findings.length} findings`);
    }

    getResults(): ShadowDomFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
        this.scannedPages.clear();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PUBLIC SCAN METHODS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Run all Shadow DOM and Web Components checks on a page.
     * Call after page navigation.
     */
    async scanPage(page: Page, url: string): Promise<ShadowDomFinding[]> {
        if (this.scannedPages.has(url)) {
            return this.findings.filter(f => f.element.includes(url));
        }
        this.scannedPages.add(url);

        const pageFindings: ShadowDomFinding[] = [];

        logger.info(`  🕸️ Scanning Shadow DOM on ${url}...`);

        // Check slot accessibility
        const slotFindings = await this.checkSlotAccessibility(page);
        pageFindings.push(...slotFindings);

        // Check shadow boundary information leakage
        const leakFindings = await this.checkShadowBoundaryLeaks(page);
        pageFindings.push(...leakFindings);

        // Check custom element security
        const securityFindings = await this.checkCustomElementSecurity(page);
        pageFindings.push(...securityFindings);

        // Check form association
        const formFindings = await this.checkFormAssociation(page);
        pageFindings.push(...formFindings);

        // Check ARIA delegation patterns
        const ariaFindings = await this.checkAriaDelegation(page);
        pageFindings.push(...ariaFindings);

        // Check CSS isolation
        const cssFindings = await this.checkCssIsolation(page);
        pageFindings.push(...cssFindings);

        this.findings.push(...pageFindings);

        if (pageFindings.length > 0) {
            logger.warn(`  ⚠️ Found ${pageFindings.length} Shadow DOM/Web Components issues`);
        } else {
            logger.info(`  ✅ Shadow DOM scan passed`);
        }

        return pageFindings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SLOT CONTENT ACCESSIBILITY
    // ═══════════════════════════════════════════════════════════════════════════

    private async checkSlotAccessibility(page: Page): Promise<ShadowDomFinding[]> {
        const findings: ShadowDomFinding[] = [];

        try {
            const slotIssues = await page.evaluate(() => {
                const issues: Array<{
                    slotName: string;
                    customElement: string;
                    missingAria: boolean;
                    missingFocus: boolean;
                    reason: string;
                }> = [];

                // Find all custom elements with shadow roots
                const allElements = document.querySelectorAll('*');
                const customElements: Element[] = [];

                allElements.forEach(el => {
                    if (el.tagName.includes('-') || (el as HTMLElement).shadowRoot) {
                        customElements.push(el);
                    }
                });

                customElements.forEach(customEl => {
                    const shadowRoot = (customEl as HTMLElement).shadowRoot;
                    if (!shadowRoot) return;

                    // Find all slots in shadow DOM
                    const slots = shadowRoot.querySelectorAll('slot');

                    slots.forEach(slot => {
                        const slotName = slot.getAttribute('name') || 'default';
                        const hasAriaLabel = slot.hasAttribute('aria-label');
                        const hasAriaLabelledBy = slot.hasAttribute('aria-labelledby');
                        const hasTabIndex = slot.hasAttribute('tabindex');

                        // Check if slotted content is focusable
                        const assignedNodes = (slot as HTMLSlotElement).assignedNodes({ flatten: true });
                        let hasFocusableContent = false;

                        assignedNodes.forEach(node => {
                            if (node.nodeType === Node.ELEMENT_NODE) {
                                const el = node as HTMLElement;
                                if (
                                    el.tagName === 'A' ||
                                    el.tagName === 'BUTTON' ||
                                    el.tagName === 'INPUT' ||
                                    el.tagName === 'SELECT' ||
                                    el.tagName === 'TEXTAREA' ||
                                    el.hasAttribute('tabindex') ||
                                    el.getAttribute('contenteditable') === 'true'
                                ) {
                                    hasFocusableContent = true;
                                }
                            }
                        });

                        // Check for missing ARIA
                        if (!hasAriaLabel && !hasAriaLabelledBy && slotName !== 'default') {
                            issues.push({
                                slotName,
                                customElement: customEl.tagName.toLowerCase(),
                                missingAria: true,
                                missingFocus: false,
                                reason: `Named slot "${slotName}" missing aria-label or aria-labelledby`,
                            });
                        }

                        // Check for focus management issues
                        if (hasFocusableContent && !hasTabIndex) {
                            // Check if parent custom element handles focus
                            const parentHasFocusMethod =
                                typeof (customEl as HTMLElement).focus === 'function';
                            if (!parentHasFocusMethod) {
                                issues.push({
                                    slotName,
                                    customElement: customEl.tagName.toLowerCase(),
                                    missingAria: false,
                                    missingFocus: true,
                                    reason: `Slot with focusable content lacks tabindex or delegated focus management`,
                                });
                            }
                        }
                    });
                });

                return issues;
            });

            for (const issue of slotIssues) {
                findings.push({
                    type: 'inaccessible-slot',
                    severity: issue.missingAria ? 'medium' : 'low',
                    description: issue.missingAria
                        ? `Named slot missing accessibility attributes`
                        : `Slot focus management issue`,
                    element: `${issue.customElement} > slot[name="${issue.slotName}"]`,
                    details: issue.reason,
                    remediation: issue.missingAria
                        ? 'Add aria-label or aria-labelledby to named slots to describe their purpose to assistive technologies.'
                        : 'Add tabindex to slots with focusable content or implement focus delegation in the custom element.',
                });
            }
        } catch (error) {
            logger.debug(`ShadowDomScanner: Error checking slot accessibility: ${error}`);
        }

        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SHADOW BOUNDARY INFORMATION LEAKAGE
    // ═══════════════════════════════════════════════════════════════════════════

    private async checkShadowBoundaryLeaks(page: Page): Promise<ShadowDomFinding[]> {
        const findings: ShadowDomFinding[] = [];

        try {
            const leaks = await page.evaluate(() => {
                const leakInfo: Array<{
                    customElement: string;
                    properties: string[];
                    severity: 'high' | 'medium';
                }> = [];

                // Get all custom elements with shadow roots
                const allElements = document.querySelectorAll('*');
                const customElements: HTMLElement[] = [];

                allElements.forEach(el => {
                    if (el.tagName.includes('-')) {
                        customElements.push(el as HTMLElement);
                    }
                });

                customElements.forEach(el => {
                    const shadowRoot = el.shadowRoot;
                    if (!shadowRoot) return;

                    // Check for CSS custom properties that might leak information
                    const computedStyle = window.getComputedStyle(el);
                    const customProps: string[] = [];

                    // Iterate through all CSS properties to find custom properties
                    for (let i = 0; i < computedStyle.length; i++) {
                        const prop = computedStyle[i];
                        if (prop.startsWith('--')) {
                            const value = computedStyle.getPropertyValue(prop).trim();
                            // Check for sensitive values
                            if (
                                value.includes('token') ||
                                value.includes('key') ||
                                value.includes('secret') ||
                                value.includes('password') ||
                                value.includes('api') ||
                                value.includes('auth') ||
                                /^[a-f0-9]{32,}$/i.test(value) || // Looks like a hash/key
                                /^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/i.test(value) // JWT pattern
                            ) {
                                customProps.push(`${prop}: ${value.substring(0, 20)}...`);
                            }
                        }
                    }

                    if (customProps.length > 0) {
                        leakInfo.push({
                            customElement: el.tagName.toLowerCase(),
                            properties: customProps,
                            severity: 'high',
                        });
                    }

                    // Check if shadow DOM exposes sensitive internal structure
                    const allStyles = shadowRoot.querySelectorAll('style');
                    allStyles.forEach(style => {
                        const cssText = style.textContent || '';
                        if (
                            cssText.includes('password') ||
                            cssText.includes('token') ||
                            cssText.includes('secret')
                        ) {
                            leakInfo.push({
                                customElement: el.tagName.toLowerCase(),
                                properties: ['Shadow DOM CSS contains sensitive keywords'],
                                severity: 'medium',
                            });
                        }
                    });
                });

                return leakInfo;
            });

            for (const leak of leaks) {
                findings.push({
                    type: 'shadow-leak',
                    severity: leak.severity,
                    description: `Potential information leakage through CSS custom properties`,
                    element: leak.customElement,
                    details: `Exposed properties: ${leak.properties.join(', ')}`,
                    remediation: 'Never store sensitive data in CSS custom properties. Use JavaScript private fields or secure storage mechanisms instead.',
                });
            }
        } catch (error) {
            logger.debug(`ShadowDomScanner: Error checking shadow boundary leaks: ${error}`);
        }

        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CUSTOM ELEMENT SECURITY
    // ═══════════════════════════════════════════════════════════════════════════

    private async checkCustomElementSecurity(page: Page): Promise<ShadowDomFinding[]> {
        const findings: ShadowDomFinding[] = [];

        try {
            const securityIssues = await page.evaluate(() => {
                const issues: Array<{
                    customElement: string;
                    issue: string;
                    severity: 'critical' | 'high' | 'medium';
                    details: string;
                }> = [];

                // Get all custom element definitions
                const customElementsRegistry = (window as unknown as { customElements: CustomElementRegistry }).customElements;

                if (!customElementsRegistry) {
                    return issues;
                }

                // Get all defined custom element names
                const definedElements = customElementsRegistry.get
                    ? Object.keys(customElementsRegistry)
                    : [];

                // Check for constructor side effects by examining element instances
                const allElements = document.querySelectorAll('*');
                const checkedConstructors = new Set<string>();

                allElements.forEach(el => {
                    const tagName = el.tagName.toLowerCase();
                    if (!tagName.includes('-')) return;
                    if (checkedConstructors.has(tagName)) return;
                    checkedConstructors.add(tagName);

                    const shadowRoot = (el as HTMLElement).shadowRoot;
                    if (!shadowRoot) return;

                    // Check for global side effects in shadow DOM
                    const scripts = shadowRoot.querySelectorAll('script');
                    scripts.forEach(script => {
                        const content = script.textContent || '';
                        if (
                            content.includes('document.write') ||
                            content.includes('eval(') ||
                            content.includes('Function(') ||
                            content.includes('setTimeout(') ||
                            content.includes('setInterval(')
                        ) {
                            issues.push({
                                customElement: tagName,
                                issue: 'Constructor side effects detected',
                                severity: 'critical',
                                details: `Shadow DOM contains inline script with potential side effects: ${content.substring(0, 50)}...`,
                            });
                        }
                    });

                    // Check for disconnectedCallback cleanup issues
                    // This is a heuristic - we can't easily check if cleanup is missing
                    // but we can check for common patterns that indicate resources
                    const hasEventListeners =
                        shadowRoot.querySelectorAll('[onclick], [onchange], [oninput]').length > 0;
                    const hasObservers =
                        shadowRoot.querySelectorAll('iframe, video, audio').length > 0;

                    if (hasEventListeners || hasObservers) {
                        // Flag as potential issue - can't verify cleanup without runtime analysis
                        issues.push({
                            customElement: tagName,
                            issue: 'Potential cleanup issues',
                            severity: 'medium',
                            details: `Custom element has event listeners or observers in shadow DOM. Ensure disconnectedCallback properly cleans up resources.`,
                        });
                    }

                    // Check for closed shadow DOM accessibility barriers
                    const closedShadowElements = shadowRoot.querySelectorAll('*');
                    let hasAriaInClosedShadow = false;
                    closedShadowElements.forEach(innerEl => {
                        if (
                            innerEl.hasAttribute('aria-label') ||
                            innerEl.hasAttribute('role') ||
                            innerEl.hasAttribute('aria-labelledby')
                        ) {
                            hasAriaInClosedShadow = true;
                        }
                    });

                    if (hasAriaInClosedShadow) {
                        issues.push({
                            customElement: tagName,
                            issue: 'ARIA in closed shadow DOM',
                            severity: 'high',
                            details: `Closed shadow DOM contains ARIA attributes which may not be accessible to assistive technologies. Use ARIA delegation instead.`,
                        });
                    }
                });

                return issues;
            });

            for (const issue of securityIssues) {
                findings.push({
                    type: 'custom-element-error',
                    severity: issue.severity,
                    description: issue.issue,
                    element: issue.customElement,
                    details: issue.details,
                    remediation: issue.issue.includes('side effects')
                        ? 'Move side effects out of constructor/connectedCallback. Use lazy initialization patterns.'
                        : issue.issue.includes('cleanup')
                            ? 'Implement proper cleanup in disconnectedCallback. Remove event listeners, disconnect observers, and cancel pending operations.'
                            : 'Use ARIA delegation via ElementInternals or expose ARIA attributes on the host element rather than inside closed shadow DOM.',
                });
            }
        } catch (error) {
            logger.debug(`ShadowDomScanner: Error checking custom element security: ${error}`);
        }

        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FORM ASSOCIATION CHECKS
    // ═══════════════════════════════════════════════════════════════════════════

    private async checkFormAssociation(page: Page): Promise<ShadowDomFinding[]> {
        const findings: ShadowDomFinding[] = [];

        try {
            const formIssues = await page.evaluate(() => {
                const issues: Array<{
                    customElement: string;
                    missingCallbacks: string[];
                    hasFormInput: boolean;
                }> = [];

                // Find all custom elements that might be form-associated
                const allElements = document.querySelectorAll('*');
                const checkedElements = new Set<string>();

                allElements.forEach(el => {
                    const tagName = el.tagName.toLowerCase();
                    if (!tagName.includes('-')) return;
                    if (checkedElements.has(tagName)) return;
                    checkedElements.add(tagName);

                    const shadowRoot = (el as HTMLElement).shadowRoot;
                    if (!shadowRoot) return;

                    // Check if element contains form-like inputs
                    const hasFormInput =
                        shadowRoot.querySelectorAll('input, select, textarea').length > 0;

                    if (hasFormInput) {
                        // Check if element is form-associated
                        const isFormAssociated = (el as HTMLElement).getAttribute('form') !== null ||
                            el.closest('form') !== null;

                        if (!isFormAssociated) {
                            issues.push({
                                customElement: tagName,
                                missingCallbacks: ['formAssociated', 'formDataCallback', 'attachInternals'],
                                hasFormInput: true,
                            });
                        }
                    }
                });

                // Also check for elements that look like form controls but aren't properly associated
                const formAssociatedElements = document.querySelectorAll('[form]');
                formAssociatedElements.forEach(el => {
                    const tagName = el.tagName.toLowerCase();
                    if (!tagName.includes('-')) return;

                    // Check if it implements formAssociated callback
                    const proto = Object.getPrototypeOf(el);
                    const hasFormAssociated = 'formAssociated' in proto || 'formAssociatedCallback' in proto;

                    if (!hasFormAssociated) {
                        issues.push({
                            customElement: tagName,
                            missingCallbacks: ['formAssociatedCallback'],
                            hasFormInput: true,
                        });
                    }
                });

                return issues;
            });

            for (const issue of formIssues) {
                findings.push({
                    type: 'form-association-missing',
                    severity: 'high',
                    description: `Custom element with form inputs missing form association`,
                    element: issue.customElement,
                    details: `Element contains form inputs but missing: ${issue.missingCallbacks.join(', ')}`,
                    remediation: 'Implement ElementInternals.attachInternals() and formAssociated/formData callbacks to properly participate in form submission.',
                });
            }
        } catch (error) {
            logger.debug(`ShadowDomScanner: Error checking form association: ${error}`);
        }

        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ARIA DELEGATION PATTERNS
    // ═══════════════════════════════════════════════════════════════════════════

    private async checkAriaDelegation(page: Page): Promise<ShadowDomFinding[]> {
        const findings: ShadowDomFinding[] = [];

        try {
            const ariaIssues = await page.evaluate(() => {
                const issues: Array<{
                    customElement: string;
                    missingDelegation: boolean;
                    ariaAttributes: string[];
                    shadowMode: string;
                }> = [];

                const allElements = document.querySelectorAll('*');
                const checkedElements = new Set<string>();

                allElements.forEach(el => {
                    const tagName = el.tagName.toLowerCase();
                    if (!tagName.includes('-')) return;
                    if (checkedElements.has(tagName)) return;
                    checkedElements.add(tagName);

                    const shadowRoot = (el as HTMLElement).shadowRoot;
                    if (!shadowRoot) return;

                    const shadowMode = shadowRoot.mode;

                    // Collect ARIA attributes on the host element
                    const hostAriaAttrs: string[] = [];
                    const hostAria = el.attributes;
                    for (let i = 0; i < hostAria.length; i++) {
                        const attr = hostAria[i];
                        if (attr.name.startsWith('aria-') || attr.name === 'role') {
                            hostAriaAttrs.push(attr.name);
                        }
                    }

                    // Check if ARIA is properly delegated to shadow DOM
                    // In modern Shadow DOM, ARIA attributes should be automatically delegated
                    // but we need to verify the element handles them correctly
                    const hasRole = el.hasAttribute('role');
                    const hasAriaLabel = el.hasAttribute('aria-label');
                    const hasAriaLabelledBy = el.hasAttribute('aria-labelledby');

                    // Check for missing aria-label on interactive custom elements
                    const isInteractive =
                        shadowRoot.querySelectorAll('button, a, input, select, textarea, [tabindex]:not([tabindex="-1"])').length > 0;

                    if (isInteractive && !hasAriaLabel && !hasAriaLabelledBy) {
                        issues.push({
                            customElement: tagName,
                            missingDelegation: true,
                            ariaAttributes: hostAriaAttrs,
                            shadowMode,
                        });
                    }

                    // Check for ARIA in closed shadow DOM without proper delegation
                    if (shadowMode === 'closed') {
                        const shadowElements = shadowRoot.querySelectorAll('*');
                        let hasAriaInShadow = false;
                        shadowElements.forEach(innerEl => {
                            if (
                                innerEl.hasAttribute('aria-label') ||
                                innerEl.hasAttribute('role') ||
                                innerEl.hasAttribute('aria-labelledby') ||
                                innerEl.hasAttribute('aria-describedby')
                            ) {
                                hasAriaInShadow = true;
                            }
                        });

                        if (hasAriaInShadow && !hasRole) {
                            issues.push({
                                customElement: tagName,
                                missingDelegation: true,
                                ariaAttributes: hostAriaAttrs,
                                shadowMode,
                            });
                        }
                    }
                });

                return issues;
            });

            for (const issue of ariaIssues) {
                findings.push({
                    type: 'aria-missing',
                    severity: issue.shadowMode === 'closed' ? 'high' : 'medium',
                    description: `Missing ARIA attributes on custom element`,
                    element: issue.customElement,
                    details: issue.ariaAttributes.length > 0
                        ? `Has ARIA on host: ${issue.ariaAttributes.join(', ')}`
                        : 'Interactive custom element missing aria-label or aria-labelledby',
                    remediation: 'Add aria-label or aria-labelledby to the custom element host, or use ARIA reflection to delegate ARIA from host to shadow DOM.',
                });
            }
        } catch (error) {
            logger.debug(`ShadowDomScanner: Error checking ARIA delegation: ${error}`);
        }

        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CSS ISOLATION VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════════

    private async checkCssIsolation(page: Page): Promise<ShadowDomFinding[]> {
        const findings: ShadowDomFinding[] = [];

        try {
            const isolationIssues = await page.evaluate(() => {
                const issues: Array<{
                    customElement: string;
                    issue: string;
                    details: string;
                }> = [];

                const allElements = document.querySelectorAll('*');
                const checkedElements = new Set<string>();

                allElements.forEach(el => {
                    const tagName = el.tagName.toLowerCase();
                    if (!tagName.includes('-')) return;
                    if (checkedElements.has(tagName)) return;
                    checkedElements.add(tagName);

                    const shadowRoot = (el as HTMLElement).shadowRoot;
                    if (!shadowRoot) return;

                    // Check for CSS isolation issues
                    const hostStyles = window.getComputedStyle(el);

                    // Check if shadow DOM styles are leaking
                    const shadowStyles = shadowRoot.querySelectorAll('style');
                    shadowStyles.forEach(style => {
                        const cssText = style.textContent || '';

                        // Check for :host-context which can leak styles
                        if (cssText.includes(':host-context')) {
                            issues.push({
                                customElement: tagName,
                                issue: 'Style leakage via :host-context',
                                details: 'Using :host-context can cause styles to leak based on external context',
                            });
                        }

                        // Check for ::slotted() with overly broad selectors
                        if (cssText.includes('::slotted(*)') || cssText.includes('::slotted(:is')) {
                            issues.push({
                                customElement: tagName,
                                issue: 'Broad ::slotted() selector',
                                details: 'Using ::slotted(*) or ::slotted(:is()) can affect unexpected elements',
                            });
                        }
                    });

                    // Check for slotted elements with important styles
                    const slots = shadowRoot.querySelectorAll('slot');
                    slots.forEach(slot => {
                        const assignedElements = (slot as HTMLSlotElement).assignedElements();
                        assignedElements.forEach(slotted => {
                            const slottedStyle = window.getComputedStyle(slotted);
                            // Check if slotted element has styles that might be overridden by host
                            const allProperties = slottedStyle.cssText;
                            if (allProperties.includes('!important')) {
                                issues.push({
                                    customElement: tagName,
                                    issue: 'Style specificity conflict',
                                    details: `Slotted element ${slotted.tagName.toLowerCase()} has !important styles that may conflict with ::slotted() styling`,
                                });
                            }
                        });
                    });
                });

                return issues;
            });

            for (const issue of isolationIssues) {
                findings.push({
                    type: 'custom-element-error',
                    severity: 'low',
                    description: `CSS isolation issue: ${issue.issue}`,
                    element: issue.customElement,
                    details: issue.details,
                    remediation: 'Use specific selectors in ::slotted(), avoid :host-context when possible, and ensure slotted content styles are well-defined.',
                });
            }
        } catch (error) {
            logger.debug(`ShadowDomScanner: Error checking CSS isolation: ${error}`);
        }

        return findings;
    }
}

export default ShadowDomScanner;
