/**
 * AI Remediation Service
 * Generates context-aware code fixes using OpenAI with enhanced capabilities
 */

import { EnvConfig, getConfig } from '../config/env.js';
import { logger } from '../utils/logger.js';

export interface RemediationRequest {
    /** Type of issue (e.g., 'XSS', 'SQLi', 'a11y-contrast') */
    type: string;
    /** Detailed description of the issue */
    details: string;
    /** Additional context (code snippet, URL, etc.) */
    context?: string;
    /** Severity level */
    severity: string;
    /** Affected element or selector */
    element?: string;
    /** Current value causing the issue */
    currentValue?: string;
    /** Compliance standards affected */
    complianceTags?: string[];
}

export interface RemediationResponse {
    /** Generated code fix */
    code: string;
    /** Explanation of the fix */
    explanation: string;
    /** Confidence level (0-100) */
    confidence: number;
    /** Alternative approaches */
    alternatives?: string[];
    /** Estimated effort level */
    effort: 'low' | 'medium' | 'high';
    /** References and documentation links */
    references?: string[];
    /** Whether AI was used */
    isAiGenerated: boolean;
}

export interface BatchRemediationResult {
    /** Successfully generated fixes */
    fixes: Array<{ request: RemediationRequest; response: RemediationResponse }>;
    /** Failed requests */
    failed: Array<{ request: RemediationRequest; error: string }>;
    /** Total tokens used */
    tokensUsed?: number;
    /** Processing time in ms */
    duration: number;
}

/**
 * Issue type to remediation template mapping
 */
const REMEDIATION_TEMPLATES: Record<string, {
    prompt: string;
    references: string[];
    effort: 'low' | 'medium' | 'high';
}> = {
    'xss': {
        prompt: 'Generate a secure fix for Cross-Site Scripting (XSS) vulnerability. Focus on proper output encoding and CSP headers.',
        references: [
            'https://owasp.org/www-community/xss-filter-evasion-cheatsheet',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        ],
        effort: 'medium',
    },
    'sqli': {
        prompt: 'Generate a secure fix for SQL Injection vulnerability. Use parameterized queries and prepared statements.',
        references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
        ],
        effort: 'medium',
    },
    'csrf': {
        prompt: 'Generate a fix for CSRF vulnerability. Include CSRF token implementation and validation.',
        references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
        ],
        effort: 'medium',
    },
    'a11y-contrast': {
        prompt: 'Fix the color contrast accessibility issue to meet WCAG 2.1 AA standards (4.5:1 for normal text, 3:1 for large text).',
        references: [
            'https://www.w3.org/WAI/WCAG21/Understanding/contrast-minimum.html',
        ],
        effort: 'low',
    },
    'a11y-alt': {
        prompt: 'Add meaningful alternative text to images for screen readers. Consider the context and purpose of the image.',
        references: [
            'https://www.w3.org/WAI/tutorials/images/',
        ],
        effort: 'low',
    },
    'a11y-label': {
        prompt: 'Add proper ARIA labels or associated labels to form controls for accessibility.',
        references: [
            'https://www.w3.org/WAI/tutorials/forms/labels/',
        ],
        effort: 'low',
    },
    'secret-leak': {
        prompt: 'Remove the exposed secret and implement secure secret management using environment variables or a secrets manager.',
        references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
        ],
        effort: 'high',
    },
    'vulnerable-library': {
        prompt: 'Provide upgrade instructions for the vulnerable library including compatibility considerations.',
        references: [
            'https://snyk.io/vuln/',
        ],
        effort: 'medium',
    },
    'missing-header': {
        prompt: 'Add the missing security header with proper configuration.',
        references: [
            'https://owasp.org/www-project-secure-headers/',
        ],
        effort: 'low',
    },
    'rate-limiting': {
        prompt: 'Implement rate limiting to prevent abuse. Include Redis-based or in-memory approaches.',
        references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html',
        ],
        effort: 'high',
    },
};

export class AiRemediationService {
    private config: EnvConfig;
    private enabled: boolean;
    private apiKey: string;
    private model: string;
    private totalTokensUsed: number = 0;

    constructor() {
        this.config = getConfig();
        this.enabled = this.config.ENABLE_AI;
        this.apiKey = this.config.OPENAI_API_KEY;
        this.model = process.env.OPENAI_MODEL || 'gpt-4';
    }

    /**
     * Generate a code fix for a specific issue
     */
    async generateFix(
        issue: RemediationRequest, 
        techStack: string[] = ['React', 'TypeScript', 'Next.js']
    ): Promise<RemediationResponse> {
        const startTime = Date.now();

        // Get template for issue type
        const issueType = this.normalizeIssueType(issue.type);
        const template = REMEDIATION_TEMPLATES[issueType];

        // Return mock response if AI is disabled
        if (!this.enabled || !this.apiKey) {
            return this.getMockFix(issue, template);
        }

        try {
            logger.info(`Generating AI fix for ${issue.type} issue...`);

            const prompt = this.constructPrompt(issue, techStack, template);
            const response = await this.callOpenAi(prompt);

            if (!response) {
                return this.getMockFix(issue, template);
            }

            // Parse AI response
            const parsed = this.parseAiResponse(response, template);
            
            logger.info(`AI fix generated in ${Date.now() - startTime}ms`);
            
            return {
                ...parsed,
                isAiGenerated: true,
            };
        } catch (error) {
            logger.error(`AI Remediation failed: ${error}`);
            return this.getMockFix(issue, template);
        }
    }

    /**
     * Generate fixes for multiple issues in batch
     */
    async generateBatchFixes(
        issues: RemediationRequest[],
        techStack: string[] = ['React', 'TypeScript', 'Next.js']
    ): Promise<BatchRemediationResult> {
        const startTime = Date.now();
        const fixes: BatchRemediationResult['fixes'] = [];
        const failed: BatchRemediationResult['failed'] = [];

        // Process in parallel with rate limiting (max 3 concurrent)
        const BATCH_SIZE = 3;
        for (let i = 0; i < issues.length; i += BATCH_SIZE) {
            const batch = issues.slice(i, i + BATCH_SIZE);
            
            const results = await Promise.allSettled(
                batch.map(issue => this.generateFix(issue, techStack))
            );

            results.forEach((result, index) => {
                const issue = batch[index];
                if (result.status === 'fulfilled') {
                    fixes.push({ request: issue, response: result.value });
                } else {
                    failed.push({ request: issue, error: result.reason?.message || 'Unknown error' });
                }
            });

            // Rate limit delay between batches
            if (i + BATCH_SIZE < issues.length) {
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }

        return {
            fixes,
            failed,
            tokensUsed: this.totalTokensUsed,
            duration: Date.now() - startTime,
        };
    }

    /**
     * Call OpenAI API
     */
    private async callOpenAi(prompt: string): Promise<string | null> {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.apiKey}`
            },
            body: JSON.stringify({
                model: this.model,
                messages: [
                    {
                        role: 'system',
                        content: `You are a senior full-stack engineer and security expert specializing in web application security and accessibility.
Your task is to provide secure, production-ready code fixes.
Always follow these principles:
1. Security by default - never trust user input
2. Use modern best practices
3. Consider edge cases
4. Provide clear comments explaining the fix
5. Include any necessary imports

Format your response as:
CODE:
\`\`\`
[your code here]
\`\`\`

EXPLANATION:
[brief explanation]

ALTERNATIVES:
[optional alternative approaches]`
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                temperature: 0.2, // Low temperature for deterministic code
                max_tokens: 1000,
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`OpenAI API Error: ${response.status} - ${errorText}`);
        }

        type OpenAiChatResponse = {
            choices?: Array<{ message?: { content?: string } }>;
            usage?: { total_tokens?: number };
        };
        const data = await response.json() as OpenAiChatResponse;
        
        // Track token usage
        if (data.usage) {
            this.totalTokensUsed += data.usage.total_tokens;
        }

        return data.choices[0]?.message?.content?.trim() || null;
    }

    /**
     * Normalize issue type to match templates
     */
    private normalizeIssueType(type: string): string {
        const normalized = type.toLowerCase()
            .replace(/[_\s-]+/g, '-')
            .replace(/cross.?site.?scripting/i, 'xss')
            .replace(/sql.?injection/i, 'sqli')
            .replace(/accessibility/i, 'a11y');
        
        // Check for partial matches
        for (const key of Object.keys(REMEDIATION_TEMPLATES)) {
            if (normalized.includes(key)) {
                return key;
            }
        }
        
        return normalized;
    }

    /**
     * Construct the Prompt
     */
    private constructPrompt(
        issue: RemediationRequest, 
        techStack: string[],
        template?: typeof REMEDIATION_TEMPLATES[string]
    ): string {
        const parts: string[] = [];

        parts.push(`Tech Stack: ${techStack.join(', ')}`);
        parts.push(`Issue Type: ${issue.type.toUpperCase()}`);
        parts.push(`Severity: ${issue.severity}`);
        parts.push(`Details: ${issue.details}`);

        if (issue.context) {
            parts.push(`Context: ${issue.context}`);
        }

        if (issue.element) {
            parts.push(`Affected Element: ${issue.element}`);
        }

        if (issue.currentValue) {
            parts.push(`Current Value: ${issue.currentValue}`);
        }

        if (issue.complianceTags && issue.complianceTags.length > 0) {
            parts.push(`Compliance Standards: ${issue.complianceTags.join(', ')}`);
        }

        if (template) {
            parts.push(`\nSpecific Guidance: ${template.prompt}`);
        }

        parts.push('\nProvide a secure, production-ready fix with clear comments.');

        return parts.join('\n');
    }

    /**
     * Parse AI response into structured format
     */
    private parseAiResponse(
        response: string,
        template?: typeof REMEDIATION_TEMPLATES[string]
    ): Omit<RemediationResponse, 'isAiGenerated'> {
        // Extract code block
        const codeMatch = response.match(/CODE:\s*```[\w]*\n?([\s\S]*?)```/i) ||
                         response.match(/```[\w]*\n?([\s\S]*?)```/);
        const code = codeMatch ? codeMatch[1].trim() : response;

        // Extract explanation
        const explanationMatch = response.match(/EXPLANATION:\s*([\s\S]*?)(?=ALTERNATIVES:|$)/i);
        const explanation = explanationMatch 
            ? explanationMatch[1].trim() 
            : 'See code comments for explanation.';

        // Extract alternatives
        const alternativesMatch = response.match(/ALTERNATIVES:\s*([\s\S]*?)$/i);
        const alternatives = alternativesMatch 
            ? alternativesMatch[1].trim().split('\n').filter(a => a.trim())
            : undefined;

        return {
            code,
            explanation,
            confidence: 85,
            alternatives,
            effort: template?.effort || 'medium',
            references: template?.references,
        };
    }

    /**
     * Return a static mock fix (when AI is disabled)
     */
    private getMockFix(
        issue: RemediationRequest,
        template?: typeof REMEDIATION_TEMPLATES[string]
    ): RemediationResponse {
        const issueType = this.normalizeIssueType(issue.type);
        
        // Generate context-aware mock fixes
        const mockFixes: Record<string, string> = {
            'xss': `// XSS Prevention Fix
// Use DOMPurify to sanitize user input before rendering
import DOMPurify from 'dompurify';

// Instead of:
// element.innerHTML = userInput;

// Use:
element.innerHTML = DOMPurify.sanitize(userInput);

// Or with React:
// <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />`,

            'sqli': `// SQL Injection Prevention
// Use parameterized queries instead of string concatenation

// Instead of:
// const query = \`SELECT * FROM users WHERE id = \${userId}\`;

// Use:
const query = 'SELECT * FROM users WHERE id = $1';
const result = await db.query(query, [userId]);`,

            'a11y-contrast': `/* Accessibility: Color Contrast Fix */
/* Ensure 4.5:1 contrast ratio for normal text, 3:1 for large text */

/* Instead of: */
.text {
  color: #999999; /* Low contrast against white */
}

/* Use: */
.text {
  color: #595959; /* 7:1 contrast ratio against white */
}`,

            'a11y-alt': `<!-- Accessibility: Image Alt Text -->
<!-- Instead of: -->
<img src="product.jpg">

<!-- Use descriptive alt text: -->
<img src="product.jpg" alt="Red wireless headphones with noise cancellation">

<!-- For decorative images: -->
<img src="decoration.jpg" alt="" role="presentation">`,

            'secret-leak': `// Secret Management Fix
// Never hardcode secrets in source code

// Instead of:
// const API_KEY = 'sk-abc123...';

// Use environment variables:
const API_KEY = process.env.API_KEY;

// Ensure .env is in .gitignore
// Use a secrets manager for production (AWS Secrets Manager, HashiCorp Vault)`,

            'missing-header': `// Security Headers Configuration (Express.js)
import helmet from 'helmet';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  frameguard: { action: 'deny' },
  xssFilter: true,
  noSniff: true,
}));`,
        };

        const code = mockFixes[issueType] || `// [AI REMEDIATION DISABLED]
// To enable AI-generated fixes, set ENABLE_AI=true and provide OPENAI_API_KEY in .env

// Suggested general fix for ${issue.type}:
// 1. Identify the component causing "${issue.details.substring(0, 50)}..."
// 2. Review best practices for ${issue.type} mitigation
// 3. Apply standard remediation patterns
// 4. Test the fix thoroughly before deployment`;

        return {
            code,
            explanation: `This is a template fix for ${issue.type}. Enable AI for context-aware solutions.`,
            confidence: 60,
            effort: template?.effort || 'medium',
            references: template?.references || [
                'https://owasp.org/www-project-top-ten/',
                'https://cheatsheetseries.owasp.org/',
            ],
            isAiGenerated: false,
        };
    }

    /**
     * Get total tokens used in this session
     */
    getTotalTokensUsed(): number {
        return this.totalTokensUsed;
    }

    /**
     * Check if AI is enabled
     */
    isEnabled(): boolean {
        return this.enabled && !!this.apiKey;
    }

    /**
     * Reset token counter
     */
    resetTokenCounter(): void {
        this.totalTokensUsed = 0;
    }
}
