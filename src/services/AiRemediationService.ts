/**
 * AI Remediation Service
 * Generates context-aware code fixes using OpenAI
 */

import { EnvConfig, getConfig } from '../config/env';
import { logger } from '../utils/logger';

export interface RemediationRequest {
    type: string;
    details: string;
    context?: string;
    severity: string;
}

export class AiRemediationService {
    private config: EnvConfig;
    private enabled: boolean;
    private apiKey: string;

    constructor() {
        this.config = getConfig();
        this.enabled = this.config.ENABLE_AI;
        this.apiKey = this.config.OPENAI_API_KEY;
    }

    /**
     * Generate a code fix for a specific issue
     */
    async generateFix(issue: RemediationRequest, techStack: string[] = ['React', 'TypeScript', 'Next.js']): Promise<string> {
        // Return mock response if AI is disabled
        if (!this.enabled || !this.apiKey) {
            return this.getMockFix(issue);
        }

        try {
            logger.info(`Generating AI fix for ${issue.type} issue...`);

            const prompt = this.constructPrompt(issue, techStack);
            const solution = await this.callOpenAi(prompt);

            return solution || this.getMockFix(issue);
        } catch (error) {
            logger.error(`AI Remediation failed: ${error}`);
            return this.getMockFix(issue);
        }
    }

    /**
     * Call OpenAI API
     */
    private async callOpenAi(prompt: string): Promise<string | null> {
        try {
            const response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.apiKey}`
                },
                body: JSON.stringify({
                    model: 'gpt-4',
                    messages: [
                        {
                            role: 'system',
                            content: 'You are a senior full-stack engineer and security expert. Provide concise, secure, and production-ready code solutions.'
                        },
                        {
                            role: 'user',
                            content: prompt
                        }
                    ],
                    temperature: 0.2, // Low temperature for deterministic code
                    max_tokens: 500
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`OpenAI API Error: ${response.status} - ${errorText}`);
            }

            const data = await response.json() as any;
            return data.choices[0]?.message?.content?.trim() || null;

        } catch (error) {
            throw error;
        }
    }

    /**
     * Construct the Prompt
     */
    private constructPrompt(issue: RemediationRequest, techStack: string[]): string {
        return `
You are a senior developer. The user has a ${issue.type.toUpperCase()} error in a ${techStack.join(', ')} application.
The specific error is: "${issue.details}".
Context: ${issue.context || 'N/A'}

Provide a concise code fix or configuration change to resolve this ${issue.severity} issue.
Focus on modern best practices. Return ONLY the code or specific configuration with brief comments.
        `.trim();
    }

    /**
     * Return a static mock fix (Cost Saving)
     */
    private getMockFix(issue: RemediationRequest): string {
        return `// [AI REMEDIATION DISABLED]
// To enable AI-generated fixes, set ENABLE_AI=true and provide OPENAI_API_KEY in .env

// Suggested general fix for ${issue.type}:
// 1. Identify the component causing "${issue.details.substring(0, 50)}..."
// 2. Review best practices for ${issue.type} mitigation
// 3. Apply standard remediation patterns`;
    }
}
