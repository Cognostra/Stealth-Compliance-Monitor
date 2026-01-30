/**
 * Postman/Newman Integration Service
 *
 * Integrates with Postman for running API collections and
 * Newman for CI/CD integration.
 *
 * Features:
 * - Postman API integration (collections, environments)
 * - Newman CLI integration
 * - Collection to audit flow conversion
 * - Test result synchronization
 */

import { logger } from '../../utils/logger.js';
import { fetchJson, fetchWithRetry } from '../../utils/api-client.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface PostmanConfig {
    apiKey: string;
    baseUrl: string;
}

export interface PostmanCollection {
    id: string;
    name: string;
    description?: string;
    item: PostmanItem[];
    variable?: PostmanVariable[];
}

export interface PostmanItem {
    name: string;
    request?: PostmanRequest;
    response?: PostmanResponse[];
    item?: PostmanItem[];
}

export interface PostmanRequest {
    method: string;
    header: Array<{ key: string; value: string }>;
    url: string | { raw: string; host: string[]; path: string[] };
    body?: { mode: string; raw?: string };
}

export interface PostmanResponse {
    code: number;
    body: string;
}

export interface PostmanVariable {
    key: string;
    value: string;
    type: string;
}

export interface NewmanOptions {
    collection: string | PostmanCollection;
    environment?: string;
    reporters?: string[];
    reporterOptions?: Record<string, unknown>;
    timeout?: number;
    bail?: boolean;
    suppressExitCode?: boolean;
}

export interface NewmanSummary {
    run: {
        stats: {
            requests: { total: number; pending: number; failed: number };
            assertions: { total: number; pending: number; failed: number };
        };
        timings: {
            started: string;
            completed: string;
            responseAverage: number;
        };
        failures: Array<{
            source: string;
            error: { message: string; test?: string };
        }>;
    };
}

export interface ConvertedAuditFlow {
    name: string;
    description: string;
    endpoints: Array<{
        method: string;
        url: string;
        headers: Record<string, string>;
        body?: string;
    }>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class PostmanIntegrationService {
    private config: PostmanConfig;

    constructor(config?: Partial<PostmanConfig>) {
        this.config = {
            apiKey: config?.apiKey || process.env.POSTMAN_API_KEY || '',
            baseUrl: config?.baseUrl || process.env.POSTMAN_BASE_URL || 'https://api.getpostman.com',
        };
    }

    /**
     * Check if Postman integration is configured.
     */
    isConfigured(): boolean {
        return !!this.config.apiKey;
    }

    /**
     * List all collections from Postman workspace.
     */
    async listCollections(): Promise<Array<{ id: string; name: string; description?: string }>> {
        if (!this.isConfigured()) {
            throw new Error('Postman API key not configured');
        }

        try {
            const response = await fetchWithRetry<{ collections: Array<{ id: string; name: string; description?: string }> }>(
                `${this.config.baseUrl}/collections`,
                {
                    method: 'GET',
                    headers: {
                        'X-Api-Key': this.config.apiKey,
                        'Content-Type': 'application/json',
                    },
                }
            );

            return response?.collections || [];
        } catch (error) {
            logger.error(`[PostmanIntegration] Failed to list collections: ${(error as Error).message}`);
            return [];
        }
    }

    /**
     * Get a specific collection by ID.
     */
    async getCollection(collectionId: string): Promise<PostmanCollection | null> {
        if (!this.isConfigured()) {
            throw new Error('Postman API key not configured');
        }

        try {
            const response = await fetchWithRetry<{ collection: PostmanCollection }>(
                `${this.config.baseUrl}/collections/${collectionId}`,
                {
                    method: 'GET',
                    headers: {
                        'X-Api-Key': this.config.apiKey,
                        'Content-Type': 'application/json',
                    },
                }
            );

            return response?.collection || null;
        } catch (error) {
            logger.error(`[PostmanIntegration] Failed to get collection: ${(error as Error).message}`);
            return null;
        }
    }

    /**
     * Convert a Postman collection to audit flow format.
     */
    convertCollectionToAuditFlow(collection: PostmanCollection): ConvertedAuditFlow {
        const endpoints: ConvertedAuditFlow['endpoints'] = [];

        const extractEndpoints = (items: PostmanItem[]) => {
            for (const item of items) {
                if (item.request) {
                    const url = typeof item.request.url === 'string'
                        ? item.request.url
                        : item.request.url.raw;

                    const headers: Record<string, string> = {};
                    for (const header of item.request.header || []) {
                        headers[header.key] = header.value;
                    }

                    endpoints.push({
                        method: item.request.method,
                        url,
                        headers,
                        body: item.request.body?.raw,
                    });
                }

                if (item.item) {
                    extractEndpoints(item.item);
                }
            }
        };

        extractEndpoints(collection.item);

        logger.info(`[PostmanIntegration] Converted ${endpoints.length} endpoints from collection`);

        return {
            name: collection.name,
            description: collection.description || '',
            endpoints,
        };
    }

    /**
     * Run Newman CLI on a collection file.
     * Note: This requires newman to be installed as a dependency or globally.
     */
    async runNewman(options: NewmanOptions): Promise<NewmanSummary | null> {
        // Dynamic import of newman to avoid loading if not used
        try {
            const { default: newman } = await import('newman');

            return new Promise((resolve, reject) => {
                newman.run(
                    {
                        collection: options.collection,
                        environment: options.environment,
                        reporters: options.reporters || ['cli'],
                        reporter: options.reporterOptions || {},
                        timeout: options.timeout || 30000,
                        bail: options.bail ?? true,
                        suppressExitCode: options.suppressExitCode ?? true,
                    },
                    (err: Error | null, summary: NewmanSummary) => {
                        if (err) {
                            reject(err);
                            return;
                        }
                        resolve(summary);
                    }
                );
            });
        } catch {
            logger.warn('[PostmanIntegration] Newman not available. Install with: npm install newman');
            return null;
        }
    }

    /**
     * Generate Newman options from a Postman collection.
     */
    generateNewmanOptions(
        collection: PostmanCollection,
        environment?: string
    ): NewmanOptions {
        return {
            collection: JSON.stringify(collection),
            environment,
            reporters: ['cli', 'json'],
            reporterOptions: {
                json: {
                    export: './newman-report.json',
                },
            },
            timeout: 60000,
            bail: false,
            suppressExitCode: true,
        };
    }

    /**
     * Extract security findings from Newman results.
     */
    extractFindingsFromNewmanResults(summary: NewmanSummary): Array<{
        type: string;
        message: string;
        endpoint?: string;
        severity: 'high' | 'medium' | 'low';
    }> {
        const findings: Array<{
            type: string;
            message: string;
            endpoint?: string;
            severity: 'high' | 'medium' | 'low';
        }> = [];

        for (const failure of summary.run.failures) {
            const severity = failure.error.test?.includes('security') ? 'high' : 'medium';
            findings.push({
                type: 'postman-test-failure',
                message: failure.error.message,
                endpoint: failure.source,
                severity,
            });
        }

        // Check for insecure protocols
        if (summary.run.stats.requests.total > 0) {
            // Would need to inspect actual requests for this
            findings.push({
                type: 'info',
                message: `Ran ${summary.run.stats.requests.total} requests, ${summary.run.stats.requests.failed} failed`,
                severity: 'low',
            });
        }

        return findings;
    }

    /**
     * Create a new collection from audit endpoints.
     */
    createCollectionFromEndpoints(
        name: string,
        endpoints: Array<{ method: string; url: string; headers?: Record<string, string> }>
    ): PostmanCollection {
        const items: PostmanItem[] = endpoints.map((ep, index) => ({
            name: `${ep.method} ${ep.url}`,
            request: {
                method: ep.method,
                header: Object.entries(ep.headers || {}).map(([key, value]) => ({
                    key,
                    value,
                })),
                url: ep.url,
            },
        }));

        return {
            id: `audit-${Date.now()}`,
            name,
            description: 'Auto-generated collection from security audit',
            item: items,
        };
    }

    /**
     * Sync collection to Postman workspace.
     */
    async syncCollectionToPostman(collection: PostmanCollection): Promise<boolean> {
        if (!this.isConfigured()) {
            throw new Error('Postman API key not configured');
        }

        try {
            await fetchJson(
                `${this.config.baseUrl}/collections`,
                {
                    method: 'POST',
                    headers: {
                        'X-Api-Key': this.config.apiKey,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ collection }),
                }
            );

            logger.info(`[PostmanIntegration] Synced collection "${collection.name}" to Postman`);
            return true;
        } catch (error) {
            logger.error(`[PostmanIntegration] Failed to sync collection: ${(error as Error).message}`);
            return false;
        }
    }
}

export default PostmanIntegrationService;
