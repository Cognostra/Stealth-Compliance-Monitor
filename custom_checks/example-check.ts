/**
 * Example Custom Check: Meta Description Validation
 * 
 * Verifies that the page has a meta description and that it meets length requirements.
 */

import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../src/core/CustomCheckLoader.js';

export async function check(page: Page, context: CustomCheckContext): Promise<CustomCheckViolation[]> {
    const violations: CustomCheckViolation[] = [];

    context.logger.debug(`[CustomCheck] Validating meta description on: ${context.currentUrl}`);

    try {
        const metaDescription = await page.$eval(
            'meta[name="description"]',
            (el) => el.getAttribute('content')
        ).catch(() => null);

        if (!metaDescription) {
            violations.push({
                id: 'meta-description-missing',
                title: 'Meta Description Missing',
                severity: 'medium',
                description: 'The page is missing a meta description tag, which is important for SEO.',
                remediation: 'Add a <meta name="description" content="..."> tag to the head.',
                selector: 'head'
            });
        } else {
            if (metaDescription.length < 50) {
                violations.push({
                    id: 'meta-description-too-short',
                    title: 'Meta Description Too Short',
                    severity: 'low',
                    description: `Meta description is ${metaDescription.length} characters long. Recommended minimum is 50.`,
                    remediation: 'Expand the meta description to provide more context.',
                    evidence: `Current content: "${metaDescription}"`
                });
            } else if (metaDescription.length > 160) {
                violations.push({
                    id: 'meta-description-too-long',
                    title: 'Meta Description Too Long',
                    severity: 'low',
                    description: `Meta description is ${metaDescription.length} characters long. Recommended maximum is 160.`,
                    remediation: 'Shorten the meta description to avoid truncation in search results.',
                    evidence: `Current content: "${metaDescription}"`
                });
            }
        }
    } catch (e) {
        context.logger.warn(`Failed to check meta description: ${e}`);
    }

    return violations;
}
