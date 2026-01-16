/**
 * GDPR Cookie Consent Checker
 * 
 * Validates that websites comply with GDPR cookie consent requirements:
 * - Cookie banner present before setting non-essential cookies
 * - Clear accept/reject options
 * - Preference management link
 * - No tracking cookies set before consent
 * 
 * @author Community
 * @version 1.0.0
 * @tags gdpr, privacy, cookies, compliance
 */

import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../../src/core/CustomCheckLoader';

// Common cookie banner selectors
const COOKIE_BANNER_SELECTORS = [
    '[class*="cookie"]',
    '[id*="cookie"]',
    '[class*="consent"]',
    '[id*="consent"]',
    '[class*="gdpr"]',
    '[id*="gdpr"]',
    '[aria-label*="cookie"]',
    '[aria-label*="consent"]',
    '#CybotCookiebotDialog',
    '.cc-window',
    '#onetrust-banner-sdk',
    '.evidon-banner',
];

// Common accept/reject button patterns
const ACCEPT_BUTTON_PATTERNS = [
    'accept all',
    'accept cookies',
    'i agree',
    'allow all',
    'got it',
    'ok',
    'agree',
];

const REJECT_BUTTON_PATTERNS = [
    'reject all',
    'decline',
    'deny',
    'refuse',
    'only necessary',
    'essential only',
];

export async function check(page: Page, context: CustomCheckContext): Promise<CustomCheckViolation[]> {
    const violations: CustomCheckViolation[] = [];

    context.logger.debug(`[GDPR] Checking cookie consent compliance on: ${context.currentUrl}`);

    try {
        // 1. Check for cookie banner presence
        let bannerFound = false;
        let bannerSelector = '';

        for (const selector of COOKIE_BANNER_SELECTORS) {
            const element = await page.$(selector);
            if (element) {
                const isVisible = await element.isVisible().catch(() => false);
                if (isVisible) {
                    bannerFound = true;
                    bannerSelector = selector;
                    break;
                }
            }
        }

        if (!bannerFound) {
            violations.push({
                id: 'gdpr-no-cookie-banner',
                title: 'Cookie Consent Banner Not Found',
                severity: 'high',
                description: 'No cookie consent banner was detected. GDPR requires informed consent before setting non-essential cookies.',
                remediation: 'Implement a cookie consent banner that appears before any non-essential cookies are set.',
                url: context.currentUrl,
            });
        } else {
            context.logger.debug(`[GDPR] Cookie banner found: ${bannerSelector}`);

            // 2. Check for accept button
            const pageText = await page.textContent('body') || '';
            const lowerText = pageText.toLowerCase();
            
            const hasAcceptButton = ACCEPT_BUTTON_PATTERNS.some(pattern => 
                lowerText.includes(pattern)
            );

            // 3. Check for reject/decline option (GDPR requires equal prominence)
            const hasRejectButton = REJECT_BUTTON_PATTERNS.some(pattern => 
                lowerText.includes(pattern)
            );

            if (!hasRejectButton) {
                violations.push({
                    id: 'gdpr-no-reject-option',
                    title: 'Missing Cookie Reject Option',
                    severity: 'high',
                    description: 'Cookie consent banner does not provide a clear option to reject non-essential cookies. GDPR requires rejecting to be as easy as accepting.',
                    remediation: 'Add a "Reject All" or "Only Essential" button with equal prominence to the accept button.',
                    selector: bannerSelector,
                    url: context.currentUrl,
                });
            }

            // 4. Check for cookie preferences/settings link
            const hasPreferencesLink = lowerText.includes('manage') || 
                                       lowerText.includes('preferences') ||
                                       lowerText.includes('settings') ||
                                       lowerText.includes('customize');

            if (!hasPreferencesLink) {
                violations.push({
                    id: 'gdpr-no-preferences-link',
                    title: 'Missing Cookie Preferences Option',
                    severity: 'medium',
                    description: 'No option to manage individual cookie preferences was found.',
                    remediation: 'Add a "Manage Preferences" or "Cookie Settings" option to allow granular control.',
                    selector: bannerSelector,
                    url: context.currentUrl,
                });
            }
        }

        // 5. Check for tracking cookies set before consent
        const cookies = await page.context().cookies();
        const trackingCookies = cookies.filter(cookie => {
            const name = cookie.name.toLowerCase();
            return name.includes('_ga') ||
                   name.includes('_gid') ||
                   name.includes('_fbp') ||
                   name.includes('_gcl') ||
                   name.includes('hubspot') ||
                   name.includes('intercom') ||
                   name.includes('amplitude');
        });

        if (trackingCookies.length > 0 && !bannerFound) {
            violations.push({
                id: 'gdpr-tracking-before-consent',
                title: 'Tracking Cookies Set Before Consent',
                severity: 'critical',
                description: `${trackingCookies.length} tracking cookie(s) were set without obtaining user consent.`,
                remediation: 'Delay setting tracking cookies until the user has given explicit consent.',
                evidence: `Cookies found: ${trackingCookies.map(c => c.name).join(', ')}`,
                url: context.currentUrl,
            });
        }

        // 6. Check for privacy policy link
        const privacyLinks = await page.$$('a[href*="privacy"], a[href*="datenschutz"], a:text-matches("privacy policy", "i")');
        if (privacyLinks.length === 0) {
            violations.push({
                id: 'gdpr-no-privacy-policy-link',
                title: 'Privacy Policy Link Not Found',
                severity: 'medium',
                description: 'No link to a privacy policy was found on the page.',
                remediation: 'Add a clearly visible link to your privacy policy.',
                url: context.currentUrl,
            });
        }

    } catch (error) {
        context.logger.warn(`[GDPR] Check failed: ${error}`);
    }

    return violations;
}
