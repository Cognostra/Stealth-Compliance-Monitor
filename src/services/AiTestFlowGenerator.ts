/**
 * AI-Generated Test Flow Generator
 *
 * Service that uses LLM (Ollama or compatible API) to generate
 * test flows from page DOM structure:
 * - Extracts interactive elements, forms, navigation from page
 * - Sends structure to LLM for test flow generation
 * - Parses response into executable FlowStep arrays
 * - Optionally executes generated flows via UserFlowRunner
 */

import type { Page } from 'playwright';
import { logger } from '../utils/logger.js';
import { safeEvaluate } from '../utils/page-helpers.js';

export interface FlowStep {
    action: 'navigate' | 'click' | 'type' | 'wait' | 'verify' | 'screenshot' | 'scroll' | 'hover' | 'select';
    selector?: string;
    value?: string;
    url?: string;
    description: string;
    timeout?: number;
}

export interface GeneratedFlow {
    name: string;
    description: string;
    steps: FlowStep[];
    confidence: number;
    rationale: string;
    category: 'authentication' | 'form-submission' | 'navigation' | 'data-entry' | 'checkout' | 'search' | 'general';
}

interface PageStructure {
    url: string;
    title: string;
    forms: FormInfo[];
    links: LinkInfo[];
    buttons: ButtonInfo[];
    inputs: InputInfo[];
    navigation: NavigationInfo[];
    headings: string[];
}

interface FormInfo {
    id: string;
    action: string;
    method: string;
    inputs: Array<{ type: string; name: string; placeholder: string; required: boolean; label: string }>;
    submitButton: string | null;
}

interface LinkInfo {
    text: string;
    href: string;
    isNavigation: boolean;
}

interface ButtonInfo {
    text: string;
    type: string;
    selector: string;
}

interface InputInfo {
    type: string;
    name: string;
    placeholder: string;
    label: string;
    selector: string;
}

interface NavigationInfo {
    text: string;
    href: string;
    isActive: boolean;
}

export interface AiTestFlowConfig {
    provider: 'ollama' | 'anthropic';
    ollamaUrl?: string;
    ollamaModel?: string;
    anthropicApiKey?: string;
    maxFlows?: number;
    timeout?: number;
}

const DEFAULT_CONFIG: AiTestFlowConfig = {
    provider: 'ollama',
    ollamaUrl: 'http://localhost:11434',
    ollamaModel: 'codellama:13b',
    maxFlows: 5,
    timeout: 60000,
};

export class AiTestFlowGenerator {
    private config: AiTestFlowConfig;

    constructor(config: Partial<AiTestFlowConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Extract page structure and generate test flows.
     */
    async generateFlows(page: Page): Promise<GeneratedFlow[]> {
        const structure = await this.extractPageStructure(page);
        if (!structure) {
            logger.warn('[AiTestFlowGenerator] Could not extract page structure');
            return [];
        }

        const prompt = this.buildPrompt(structure);
        const response = await this.queryLlm(prompt);
        if (!response) return [];

        const flows = this.parseFlows(response, structure.url);
        logger.info(`[AiTestFlowGenerator] Generated ${flows.length} test flows for ${structure.url}`);
        return flows;
    }

    /**
     * Extract interactive elements and structure from the page.
     */
    private async extractPageStructure(page: Page): Promise<PageStructure | null> {
        return safeEvaluate<PageStructure>(page, () => {
            const getLabel = (el: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement): string => {
                if (el.labels && el.labels.length > 0) return el.labels[0].textContent?.trim() || '';
                const ariaLabel = el.getAttribute('aria-label');
                if (ariaLabel) return ariaLabel;
                return '';
            };

            const getSelector = (el: Element): string => {
                if (el.id) return `#${el.id}`;
                const classes = Array.from(el.classList).slice(0, 2).join('.');
                if (classes) return `${el.tagName.toLowerCase()}.${classes}`;
                return el.tagName.toLowerCase();
            };

            // Extract forms
            const forms: FormInfo[] = Array.from(document.querySelectorAll('form')).slice(0, 10).map(form => ({
                id: form.id || '',
                action: form.action || '',
                method: form.method || 'get',
                inputs: Array.from(form.querySelectorAll('input, select, textarea')).slice(0, 20).map((input: Element) => {
                    const el = input as HTMLInputElement;
                    return {
                        type: el.type || 'text',
                        name: el.name || '',
                        placeholder: el.placeholder || '',
                        required: el.required || false,
                        label: getLabel(el),
                    };
                }),
                submitButton: (() => {
                    const btn = form.querySelector('button[type="submit"], input[type="submit"]');
                    return btn ? (btn.textContent?.trim() || btn.getAttribute('value') || 'Submit') : null;
                })(),
            }));

            // Extract navigation links
            const navLinks: NavigationInfo[] = [];
            const navElements = document.querySelectorAll('nav a, [role="navigation"] a, header a');
            for (const link of navElements) {
                if (navLinks.length >= 20) break;
                const anchor = link as HTMLAnchorElement;
                navLinks.push({
                    text: anchor.textContent?.trim() || '',
                    href: anchor.href || '',
                    isActive: anchor.classList.contains('active') || anchor.getAttribute('aria-current') === 'page',
                });
            }

            // Extract buttons
            const buttons: ButtonInfo[] = Array.from(
                document.querySelectorAll('button:not([type="submit"]), [role="button"]')
            ).slice(0, 20).map(btn => ({
                text: btn.textContent?.trim().slice(0, 50) || '',
                type: btn.getAttribute('type') || 'button',
                selector: getSelector(btn),
            }));

            // Extract standalone inputs (not in forms)
            const inputs: InputInfo[] = Array.from(
                document.querySelectorAll('input:not(form input), textarea:not(form textarea), select:not(form select)')
            ).slice(0, 20).map((el: Element) => {
                const input = el as HTMLInputElement;
                return {
                    type: input.type || 'text',
                    name: input.name || '',
                    placeholder: input.placeholder || '',
                    label: getLabel(input),
                    selector: getSelector(input),
                };
            });

            // Extract content links
            const links: LinkInfo[] = Array.from(
                document.querySelectorAll('main a, article a, [role="main"] a, .content a')
            ).slice(0, 30).map(a => {
                const anchor = a as HTMLAnchorElement;
                return {
                    text: anchor.textContent?.trim().slice(0, 50) || '',
                    href: anchor.href || '',
                    isNavigation: false,
                };
            });

            // Extract headings for context
            const headings = Array.from(document.querySelectorAll('h1, h2, h3'))
                .slice(0, 10)
                .map(h => h.textContent?.trim() || '')
                .filter(Boolean);

            return {
                url: window.location.href,
                title: document.title,
                forms,
                links,
                buttons,
                inputs,
                navigation: navLinks,
                headings,
            };
        });
    }

    /**
     * Build a prompt from the page structure.
     */
    private buildPrompt(structure: PageStructure): string {
        return `You are a QA engineer analyzing a web page to generate test flows. Generate up to ${this.config.maxFlows} test flows as JSON.

Page URL: ${structure.url}
Page Title: ${structure.title}
Headings: ${structure.headings.join(', ')}

Forms (${structure.forms.length}):
${structure.forms.map(f => `  Form "${f.id || 'unnamed'}" (${f.method} ${f.action}): inputs=[${f.inputs.map(i => `${i.type}:${i.name || i.label}`).join(', ')}], submit="${f.submitButton || 'none'}"`).join('\n')}

Navigation (${structure.navigation.length}):
${structure.navigation.slice(0, 10).map(n => `  "${n.text}" -> ${n.href}`).join('\n')}

Buttons (${structure.buttons.length}):
${structure.buttons.slice(0, 10).map(b => `  "${b.text}" (${b.selector})`).join('\n')}

Inputs outside forms (${structure.inputs.length}):
${structure.inputs.slice(0, 10).map(i => `  ${i.type} "${i.label || i.name || i.placeholder}" (${i.selector})`).join('\n')}

Respond ONLY with a JSON array of test flows. Each flow must have:
- name: short test name
- description: what the test verifies
- category: one of "authentication", "form-submission", "navigation", "data-entry", "checkout", "search", "general"
- confidence: 0.0-1.0 how confident the flow is correct
- rationale: why this test is important
- steps: array of {action, selector?, value?, description}

Actions: "click", "type", "verify", "wait", "scroll", "navigate"

Example:
[{"name":"Login Flow","description":"Test login form submission","category":"authentication","confidence":0.8,"rationale":"Login is critical path","steps":[{"action":"type","selector":"#email","value":"test@example.com","description":"Enter email"},{"action":"type","selector":"#password","value":"TestPass123!","description":"Enter password"},{"action":"click","selector":"button[type=submit]","description":"Click login"},{"action":"verify","selector":".dashboard","description":"Verify dashboard loads"}]}]

JSON:`;
    }

    /**
     * Query the LLM for test flow generation.
     */
    private async queryLlm(prompt: string): Promise<string | null> {
        try {
            if (this.config.provider === 'ollama') {
                return await this.queryOllama(prompt);
            }
            logger.warn(`[AiTestFlowGenerator] Unsupported provider: ${this.config.provider}`);
            return null;
        } catch (error) {
            logger.debug(`[AiTestFlowGenerator] LLM query failed: ${(error as Error).message}`);
            return null;
        }
    }

    private async queryOllama(prompt: string): Promise<string | null> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.config.timeout || 60000);

        try {
            const response = await fetch(`${this.config.ollamaUrl}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: this.config.ollamaModel,
                    prompt,
                    stream: false,
                    options: { temperature: 0.3, num_predict: 2048 },
                }),
                signal: controller.signal,
            });

            clearTimeout(timer);

            if (!response.ok) return null;

            const data = await response.json() as { response?: string };
            return data.response || null;
        } catch {
            clearTimeout(timer);
            return null;
        }
    }

    /**
     * Parse LLM response into GeneratedFlow array.
     */
    private parseFlows(response: string, pageUrl: string): GeneratedFlow[] {
        const flows: GeneratedFlow[] = [];

        try {
            // Extract JSON array from response (LLM may include surrounding text)
            const jsonMatch = response.match(/\[[\s\S]*\]/);
            if (!jsonMatch) return flows;

            const parsed = JSON.parse(jsonMatch[0]) as Array<{
                name?: string;
                description?: string;
                category?: string;
                confidence?: number;
                rationale?: string;
                steps?: Array<{
                    action?: string;
                    selector?: string;
                    value?: string;
                    description?: string;
                }>;
            }>;

            if (!Array.isArray(parsed)) return flows;

            for (const item of parsed.slice(0, this.config.maxFlows || 5)) {
                if (!item.name || !item.steps || !Array.isArray(item.steps)) continue;

                const validSteps: FlowStep[] = [];
                for (const step of item.steps) {
                    if (!step.action || !step.description) continue;
                    const validActions = ['navigate', 'click', 'type', 'wait', 'verify', 'screenshot', 'scroll', 'hover', 'select'];
                    if (!validActions.includes(step.action)) continue;

                    validSteps.push({
                        action: step.action as FlowStep['action'],
                        selector: step.selector,
                        value: step.value,
                        description: step.description,
                    });
                }

                if (validSteps.length === 0) continue;

                const validCategories = ['authentication', 'form-submission', 'navigation', 'data-entry', 'checkout', 'search', 'general'];
                flows.push({
                    name: item.name,
                    description: item.description || '',
                    steps: validSteps,
                    confidence: typeof item.confidence === 'number' ? Math.min(1, Math.max(0, item.confidence)) : 0.5,
                    rationale: item.rationale || '',
                    category: (validCategories.includes(item.category || '') ? item.category : 'general') as GeneratedFlow['category'],
                });
            }
        } catch (error) {
            logger.debug(`[AiTestFlowGenerator] Failed to parse LLM response: ${(error as Error).message}`);
        }

        return flows;
    }
}
