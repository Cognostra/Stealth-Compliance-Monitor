/**
 * Form Validation & UX Checker
 * 
 * Validates form accessibility and user experience:
 * - Labels associated with inputs
 * - Required field indicators
 * - Error message handling
 * - Submit button presence
 * - Input types and autocomplete
 * 
 * @author Community
 * @version 1.0.0
 * @tags accessibility, forms, ux, wcag
 */

import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../../src/core/CustomCheckLoader';

export async function check(page: Page, context: CustomCheckContext): Promise<CustomCheckViolation[]> {
    const violations: CustomCheckViolation[] = [];

    context.logger.debug(`[FormCheck] Validating forms on: ${context.currentUrl}`);

    try {
        // Get all forms on the page
        const formData = await page.evaluate(() => {
            const forms = document.querySelectorAll('form');
            const results: Array<{
                id: string;
                inputs: Array<{
                    type: string;
                    name: string;
                    id: string;
                    hasLabel: boolean;
                    labelText: string;
                    required: boolean;
                    hasRequiredIndicator: boolean;
                    autocomplete: string;
                    placeholder: string;
                    ariaLabel: string;
                    ariaDescribedby: string;
                }>;
                hasSubmitButton: boolean;
                hasAction: boolean;
                method: string;
            }> = [];

            forms.forEach((form, index) => {
                const inputs = form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]), select, textarea');
                const inputData: typeof results[0]['inputs'] = [];

                inputs.forEach(input => {
                    const inputEl = input as HTMLInputElement;
                    const id = inputEl.id;
                    
                    // Check for associated label
                    let hasLabel = false;
                    let labelText = '';
                    
                    if (id) {
                        const label = document.querySelector(`label[for="${id}"]`);
                        if (label) {
                            hasLabel = true;
                            labelText = label.textContent?.trim() || '';
                        }
                    }
                    
                    // Check if wrapped in label
                    const parentLabel = inputEl.closest('label');
                    if (parentLabel) {
                        hasLabel = true;
                        labelText = labelText || parentLabel.textContent?.trim() || '';
                    }

                    // Check for required indicator (asterisk in label or aria-required)
                    const hasRequiredIndicator = labelText.includes('*') || 
                                                 inputEl.getAttribute('aria-required') === 'true' ||
                                                 inputEl.required;

                    inputData.push({
                        type: inputEl.type || inputEl.tagName.toLowerCase(),
                        name: inputEl.name,
                        id: id,
                        hasLabel,
                        labelText,
                        required: inputEl.required,
                        hasRequiredIndicator,
                        autocomplete: inputEl.autocomplete || '',
                        placeholder: inputEl.placeholder || '',
                        ariaLabel: inputEl.getAttribute('aria-label') || '',
                        ariaDescribedby: inputEl.getAttribute('aria-describedby') || '',
                    });
                });

                const submitButton = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
                
                results.push({
                    id: form.id || `form-${index}`,
                    inputs: inputData,
                    hasSubmitButton: !!submitButton,
                    hasAction: !!form.action && form.action !== window.location.href,
                    method: form.method.toUpperCase(),
                });
            });

            return results;
        });

        if (formData.length === 0) {
            context.logger.debug('[FormCheck] No forms found on page');
            return violations;
        }

        for (const form of formData) {
            // Check each input
            for (const input of form.inputs) {
                // Input without label (accessibility issue)
                if (!input.hasLabel && !input.ariaLabel) {
                    violations.push({
                        id: 'form-input-no-label',
                        title: 'Form Input Missing Label',
                        severity: 'high',
                        description: `Input "${input.name || input.id || input.type}" has no associated label or aria-label.`,
                        remediation: 'Add a <label for="input-id"> element or aria-label attribute.',
                        selector: input.id ? `#${input.id}` : `form input[name="${input.name}"]`,
                        url: context.currentUrl,
                    });
                }

                // Required field without visual indicator
                if (input.required && !input.hasRequiredIndicator) {
                    violations.push({
                        id: 'form-required-no-indicator',
                        title: 'Required Field Missing Visual Indicator',
                        severity: 'medium',
                        description: `Required input "${input.name || input.id}" lacks a visual indicator (asterisk, "Required" text).`,
                        remediation: 'Add a visual indicator like * to the label, or add descriptive text.',
                        selector: input.id ? `#${input.id}` : `form input[name="${input.name}"]`,
                        url: context.currentUrl,
                    });
                }

                // Email input without proper type
                if (input.name?.toLowerCase().includes('email') && input.type !== 'email') {
                    violations.push({
                        id: 'form-email-wrong-type',
                        title: 'Email Field Should Use type="email"',
                        severity: 'low',
                        description: `Input "${input.name}" appears to be an email field but uses type="${input.type}".`,
                        remediation: 'Change input type to "email" for better validation and mobile keyboard support.',
                        selector: input.id ? `#${input.id}` : `form input[name="${input.name}"]`,
                        url: context.currentUrl,
                    });
                }

                // Password field without autocomplete
                if (input.type === 'password' && !input.autocomplete) {
                    violations.push({
                        id: 'form-password-no-autocomplete',
                        title: 'Password Field Missing Autocomplete',
                        severity: 'low',
                        description: 'Password field should have autocomplete="current-password" or "new-password".',
                        remediation: 'Add autocomplete="current-password" for login forms or "new-password" for registration.',
                        selector: input.id ? `#${input.id}` : `form input[type="password"]`,
                        url: context.currentUrl,
                    });
                }

                // Check for proper autocomplete values
                const autocompleteMap: Record<string, string> = {
                    email: 'email',
                    phone: 'tel',
                    tel: 'tel',
                    name: 'name',
                    firstname: 'given-name',
                    lastname: 'family-name',
                    address: 'street-address',
                    city: 'address-level2',
                    zip: 'postal-code',
                    postal: 'postal-code',
                    country: 'country',
                };

                const inputNameLower = input.name?.toLowerCase() || '';
                for (const [pattern, expectedAutocomplete] of Object.entries(autocompleteMap)) {
                    if (inputNameLower.includes(pattern) && input.autocomplete !== expectedAutocomplete) {
                        violations.push({
                            id: 'form-missing-autocomplete',
                            title: 'Input Missing Appropriate Autocomplete',
                            severity: 'low',
                            description: `Input "${input.name}" should have autocomplete="${expectedAutocomplete}".`,
                            remediation: `Add autocomplete="${expectedAutocomplete}" for better autofill support.`,
                            selector: input.id ? `#${input.id}` : `form input[name="${input.name}"]`,
                            url: context.currentUrl,
                        });
                        break;
                    }
                }
            }

            // Form without submit button
            if (!form.hasSubmitButton && form.inputs.length > 0) {
                violations.push({
                    id: 'form-no-submit-button',
                    title: 'Form Missing Submit Button',
                    severity: 'medium',
                    description: `Form "${form.id}" has no visible submit button.`,
                    remediation: 'Add a <button type="submit"> or <input type="submit"> element.',
                    selector: form.id ? `#${form.id}` : 'form',
                    url: context.currentUrl,
                });
            }

            // Login form security check
            const hasEmailOrUsername = form.inputs.some(i => 
                i.type === 'email' || 
                i.name?.toLowerCase().includes('email') ||
                i.name?.toLowerCase().includes('user')
            );
            const hasPassword = form.inputs.some(i => i.type === 'password');
            
            if (hasEmailOrUsername && hasPassword && form.method !== 'POST') {
                violations.push({
                    id: 'form-login-not-post',
                    title: 'Login Form Should Use POST Method',
                    severity: 'high',
                    description: 'Login form appears to use GET method, which exposes credentials in URL.',
                    remediation: 'Change form method to POST to prevent credential exposure.',
                    selector: form.id ? `#${form.id}` : 'form',
                    url: context.currentUrl,
                });
            }
        }

    } catch (error) {
        context.logger.warn(`[FormCheck] Check failed: ${error}`);
    }

    return violations;
}
