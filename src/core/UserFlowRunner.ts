/**
 * User Flow Runner
 * Executes predefined user flows (Login -> Dashboard -> Logout)
 */

import { BrowserService } from '../services/BrowserService';
import { UserFlow, UserFlowResult, FlowStepResult, FlowStep, Logger } from '../types';

/**
 * Default user flows for testing
 */
export const DEFAULT_FLOWS: UserFlow[] = [
    {
        name: 'Homepage Load',
        description: 'Verify homepage loads correctly',
        steps: [
            { name: 'Navigate to homepage', action: 'navigate', value: '/' },
            { name: 'Wait for page load', action: 'wait', timeout: 5000 },
            { name: 'Capture homepage', action: 'screenshot' },
        ],
    },
    {
        name: 'Login Flow',
        description: 'Test login -> dashboard -> logout flow',
        steps: [
            { name: 'Navigate to login', action: 'navigate', value: '/login' },
            { name: 'Wait for login form', action: 'wait', selector: 'input[type="email"], input[name="email"], #email' },
            { name: 'Enter email', action: 'type', selector: 'input[type="email"], input[name="email"], #email', value: '{{TEST_EMAIL}}' },
            { name: 'Enter password', action: 'type', selector: 'input[type="password"], input[name="password"], #password', value: '{{TEST_PASSWORD}}' },
            { name: 'Click login button', action: 'click', selector: 'button[type="submit"], input[type="submit"], .login-btn, #login-btn' },
            { name: 'Wait for dashboard', action: 'wait', timeout: 10000 },
            { name: 'Verify logged in', action: 'verify', selector: '.dashboard, .user-menu, .logout, [data-testid="dashboard"]' },
            { name: 'Capture dashboard', action: 'screenshot' },
        ],
    },
];

export class UserFlowRunner {
    private readonly browserService: BrowserService;
    private readonly baseUrl: string;
    private readonly logger: Logger;
    private readonly credentials: { email: string; password: string };

    constructor(
        browserService: BrowserService,
        baseUrl: string,
        credentials: { email: string; password: string },
        logger: Logger
    ) {
        this.browserService = browserService;
        this.baseUrl = baseUrl;
        this.credentials = credentials;
        this.logger = logger;
    }

    /**
     * Run a single user flow
     */
    async runFlow(flow: UserFlow): Promise<UserFlowResult> {
        this.logger.info(`Starting flow: ${flow.name}`);
        const startTime = Date.now();
        const stepResults: FlowStepResult[] = [];
        let flowPassed = true;
        let screenshotPath: string | undefined;

        for (const step of flow.steps) {
            const stepResult = await this.executeStep(step);
            stepResults.push(stepResult);

            if (!stepResult.passed) {
                flowPassed = false;
                this.logger.error(`Step failed: ${step.name}`, { error: stepResult.error });

                // Take failure screenshot
                try {
                    const result = await this.browserService.screenshot(`failure_${flow.name.replace(/\s+/g, '_')}`);
                    screenshotPath = result.path;
                } catch (e) {
                    this.logger.warn('Failed to capture failure screenshot');
                }

                break; // Stop flow on first failure
            }
        }

        const duration = Date.now() - startTime;

        this.logger.info(`Flow completed: ${flow.name}`, {
            passed: flowPassed,
            duration: `${duration}ms`,
            stepsCompleted: stepResults.length,
        });

        return {
            name: flow.name,
            steps: stepResults,
            passed: flowPassed,
            duration,
            screenshotPath,
        };
    }

    /**
     * Execute a single flow step
     */
    private async executeStep(step: FlowStep): Promise<FlowStepResult> {
        const startTime = Date.now();

        try {
            switch (step.action) {
                case 'navigate': {
                    const url = step.value?.startsWith('http')
                        ? step.value
                        : `${this.baseUrl}${step.value}`;
                    // Use goto() instead of navigate() - enforces human delay
                    await this.browserService.goto(url);
                    break;
                }

                case 'click': {
                    await this.browserService.waitForSelector(step.selector!, step.timeout || 10000);
                    await this.browserService.click(step.selector!);
                    break;
                }

                case 'type': {
                    await this.browserService.waitForSelector(step.selector!, step.timeout || 10000);
                    const value = this.interpolateValue(step.value!);
                    // Use fill() for faster input, type() is also available for keystroke simulation
                    const typeResult = await this.browserService.fill(step.selector!, value);
                    if (!typeResult.success) {
                        throw new Error(typeResult.error);
                    }
                    break;
                }

                case 'wait': {
                    if (step.selector) {
                        await this.browserService.waitForSelector(step.selector, step.timeout || 10000);
                    } else {
                        await new Promise(resolve => setTimeout(resolve, step.timeout || 2000));
                    }
                    break;
                }

                case 'verify': {
                    const exists = await this.browserService.elementExists(step.selector!);
                    if (!exists) {
                        throw new Error(`Element not found: ${step.selector}`);
                    }
                    break;
                }

                case 'screenshot': {
                    const screenshotName = step.value || `step_${Date.now()}`;
                    await this.browserService.screenshot(screenshotName);
                    break;
                }

                default:
                    throw new Error(`Unknown action: ${step.action}`);
            }

            return {
                name: step.name,
                action: step.action,
                selector: step.selector,
                passed: true,
                duration: Date.now() - startTime,
            };
        } catch (error) {
            return {
                name: step.name,
                action: step.action,
                selector: step.selector,
                passed: false,
                error: error instanceof Error ? error.message : String(error),
                duration: Date.now() - startTime,
            };
        }
    }

    /**
     * Interpolate template variables in step values
     */
    private interpolateValue(value: string): string {
        return value
            .replace('{{TEST_EMAIL}}', this.credentials.email)
            .replace('{{TEST_PASSWORD}}', this.credentials.password);
    }

    /**
     * Run all default flows
     */
    async runAllFlows(flows: UserFlow[] = DEFAULT_FLOWS): Promise<UserFlowResult[]> {
        const results: UserFlowResult[] = [];

        for (const flow of flows) {
            // Skip login flow if no credentials
            if (flow.name === 'Login Flow' && (!this.credentials.email || !this.credentials.password)) {
                this.logger.warn('Skipping Login Flow - no credentials provided');
                continue;
            }

            const result = await this.runFlow(flow);
            results.push(result);
        }

        return results;
    }
}

export default UserFlowRunner;
