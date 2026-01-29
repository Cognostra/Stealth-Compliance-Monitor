/**
 * OllamaService - Local LLM Remediation via Ollama
 *
 * Connects to a local Ollama instance to generate remediation code snippets
 * for audit findings. Keeps sensitive audit data local (no cloud API calls).
 *
 * API Reference: https://github.com/ollama/ollama/blob/main/docs/api.md
 */

import { logger } from '../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface OllamaConfig {
    baseUrl: string;
    model: string;
    timeout: number;
}

export interface OllamaModel {
    name: string;
    size: number;
    digest: string;
    modified_at: string;
}

export interface RemediationRequest {
    findingType: string;
    severity: string;
    description: string;
    evidence?: string;
    url?: string;
    technology?: string;
}

export interface RemediationResult {
    finding: RemediationRequest;
    remediation: string;
    model: string;
    duration: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROMPT TEMPLATE
// ═══════════════════════════════════════════════════════════════════════════════

function buildPrompt(finding: RemediationRequest): string {
    return `You are a security engineer reviewing web application audit findings.
Generate a concise remediation code snippet for the following vulnerability.

**Finding Type:** ${finding.findingType}
**Severity:** ${finding.severity}
**Description:** ${finding.description}
${finding.evidence ? `**Evidence:** ${finding.evidence}` : ''}
${finding.url ? `**URL:** ${finding.url}` : ''}
${finding.technology ? `**Technology Stack:** ${finding.technology}` : ''}

Provide:
1. A brief explanation of the vulnerability (1-2 sentences)
2. A code snippet showing the fix (use the most relevant language/framework)
3. Any additional configuration changes needed

Keep your response concise and actionable.`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class OllamaService {
    private readonly config: OllamaConfig;

    constructor(options: Partial<OllamaConfig> = {}) {
        this.config = {
            baseUrl: options.baseUrl || process.env.OLLAMA_URL || 'http://localhost:11434',
            model: options.model || process.env.OLLAMA_MODEL || 'codellama:13b',
            timeout: options.timeout || 120000, // 2 minute default for LLM generation
        };
    }

    /**
     * Check if Ollama is running and accessible.
     */
    async isAvailable(): Promise<boolean> {
        try {
            const response = await fetch(`${this.config.baseUrl}/api/tags`, {
                method: 'GET',
                signal: AbortSignal.timeout(5000),
            });
            return response.ok;
        } catch {
            return false;
        }
    }

    /**
     * List available models on the Ollama instance.
     */
    async listModels(): Promise<OllamaModel[]> {
        try {
            const response = await fetch(`${this.config.baseUrl}/api/tags`, {
                method: 'GET',
                signal: AbortSignal.timeout(10000),
            });

            if (!response.ok) {
                throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
            }

            const data = await response.json() as { models: OllamaModel[] };
            return data.models || [];
        } catch (error) {
            if (error instanceof Error && error.name === 'TimeoutError') {
                throw new Error('Ollama API request timed out');
            }
            throw error;
        }
    }

    /**
     * Check if a specific model is available.
     */
    async hasModel(modelName: string): Promise<boolean> {
        const models = await this.listModels();
        return models.some(m => m.name === modelName || m.name.startsWith(modelName));
    }

    /**
     * Generate remediation for a single finding.
     */
    async generateRemediation(finding: RemediationRequest): Promise<RemediationResult> {
        const startTime = Date.now();
        const prompt = buildPrompt(finding);

        try {
            const response = await fetch(`${this.config.baseUrl}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: this.config.model,
                    prompt,
                    stream: false,
                    options: {
                        temperature: 0.3, // Lower temperature for more deterministic code
                        top_p: 0.9,
                        num_predict: 1024,
                    },
                }),
                signal: AbortSignal.timeout(this.config.timeout),
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Ollama generation failed: ${response.status} - ${errorText}`);
            }

            const data = await response.json() as { response: string; model: string };
            const duration = Date.now() - startTime;

            return {
                finding,
                remediation: data.response,
                model: data.model || this.config.model,
                duration,
            };
        } catch (error) {
            const duration = Date.now() - startTime;

            if (error instanceof Error && error.name === 'TimeoutError') {
                return {
                    finding,
                    remediation: `[Generation timed out after ${this.config.timeout}ms. Try a smaller model or simpler prompt.]`,
                    model: this.config.model,
                    duration,
                };
            }

            throw error;
        }
    }

    /**
     * Generate remediations for multiple findings sequentially.
     * Rate-limited: one request per finding to avoid overwhelming the local LLM.
     */
    async generateRemediations(
        findings: RemediationRequest[],
        options: { maxFindings?: number; onProgress?: (current: number, total: number) => void } = {}
    ): Promise<RemediationResult[]> {
        const maxFindings = options.maxFindings || 10;
        const limitedFindings = findings.slice(0, maxFindings);
        const results: RemediationResult[] = [];

        logger.info(`Generating remediations for ${limitedFindings.length} findings using ${this.config.model}`);

        for (let i = 0; i < limitedFindings.length; i++) {
            const finding = limitedFindings[i];
            options.onProgress?.(i + 1, limitedFindings.length);

            try {
                logger.debug(`Generating remediation ${i + 1}/${limitedFindings.length}: ${finding.findingType}`);
                const result = await this.generateRemediation(finding);
                results.push(result);
                logger.debug(`Remediation generated in ${result.duration}ms`);
            } catch (error) {
                logger.error(`Failed to generate remediation for ${finding.findingType}: ${error instanceof Error ? error.message : String(error)}`);
                results.push({
                    finding,
                    remediation: `[Error: ${error instanceof Error ? error.message : String(error)}]`,
                    model: this.config.model,
                    duration: 0,
                });
            }
        }

        return results;
    }

    /**
     * Get the configured model name.
     */
    getModel(): string {
        return this.config.model;
    }

    /**
     * Get the Ollama base URL.
     */
    getBaseUrl(): string {
        return this.config.baseUrl;
    }
}

export default OllamaService;
