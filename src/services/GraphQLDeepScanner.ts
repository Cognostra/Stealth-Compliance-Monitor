/**
 * GraphQL Deep Scanner
 *
 * IScanner that detects GraphQL endpoints and performs deep security analysis:
 * - Query depth/complexity analysis (DoS vector detection)
 * - Introspection query testing
 * - Field suggestion enumeration attacks
 * - Batch query detection
 * - Mutation authorization bypass detection
 */

import type { Page, Request, Response } from 'playwright';
import type { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';
import { safeReadResponseBody } from '../utils/response-reader.js';

export interface GraphQLFinding {
    type: 'depth-limit' | 'complexity' | 'field-suggestion' | 'introspection' | 'mutation-auth' | 'subscription-leak' | 'batching' | 'schema-stitching';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    endpoint: string;
    remediation?: string;
}

interface DetectedEndpoint {
    url: string;
    method: string;
    hasAuth: boolean;
}

const INTROSPECTION_QUERY = '{"query":"{ __schema { types { name kind fields { name } } } }"}';

const DEPTH_TEST_QUERY = `{"query":"{ __schema { types { name fields { name type { name fields { name type { name fields { name } } } } } } } }"}`;

const BATCH_TEST = '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]';

export class GraphQLDeepScanner implements IScanner {
    readonly name = 'GraphQLDeepScanner';
    private findings: GraphQLFinding[] = [];
    private detectedEndpoints: Map<string, DetectedEndpoint> = new Map();
    private analyzedUrls: Set<string> = new Set();

    async onRequest(request: Request): Promise<void> {
        const url = request.url();
        const method = request.method();

        // Detect GraphQL endpoints
        if (this.isGraphQLRequest(request)) {
            const key = `${method}:${url}`;
            if (!this.detectedEndpoints.has(key)) {
                const hasAuth = !!(request.headers()['authorization'] || request.headers()['cookie']);
                this.detectedEndpoints.set(key, { url, method, hasAuth });
                logger.debug(`[GraphQLDeepScanner] Detected endpoint: ${url}`);
            }
        }
    }

    async onResponse(response: Response): Promise<void> {
        if (!this.isGraphQLRequest(response.request())) return;

        const url = response.url();
        if (this.analyzedUrls.has(url)) return;
        this.analyzedUrls.add(url);

        const body = await safeReadResponseBody(response, 1024 * 1024);
        if (!body) return;

        this.analyzeResponse(body, url);
    }

    /**
     * Run active GraphQL probes against detected endpoints.
     * Called post-navigation from ComplianceRunner.
     */
    async runActiveProbes(cookies?: string): Promise<GraphQLFinding[]> {
        const newFindings: GraphQLFinding[] = [];

        for (const [, endpoint] of this.detectedEndpoints) {
            const headers: Record<string, string> = {
                'Content-Type': 'application/json',
            };
            if (cookies) headers['Cookie'] = cookies;

            // Test 1: Introspection
            const introResult = await this.probeEndpoint(endpoint.url, INTROSPECTION_QUERY, headers);
            if (introResult && !introResult.includes('"errors"')) {
                const finding: GraphQLFinding = {
                    type: 'introspection',
                    severity: 'medium',
                    description: 'GraphQL introspection is enabled, exposing full schema to attackers',
                    evidence: `Introspection query returned schema data from ${endpoint.url}`,
                    endpoint: endpoint.url,
                    remediation: 'Disable introspection in production: `introspection: false` in Apollo Server config',
                };
                this.findings.push(finding);
                newFindings.push(finding);
            }

            // Test 2: Query depth
            const depthResult = await this.probeEndpoint(endpoint.url, DEPTH_TEST_QUERY, headers);
            if (depthResult && !depthResult.includes('"errors"')) {
                const finding: GraphQLFinding = {
                    type: 'depth-limit',
                    severity: 'high',
                    description: 'No query depth limit detected - vulnerable to deeply nested query DoS attacks',
                    evidence: `Deep nested query (5+ levels) succeeded at ${endpoint.url}`,
                    endpoint: endpoint.url,
                    remediation: 'Implement query depth limiting (e.g., graphql-depth-limit package, max depth 10)',
                };
                this.findings.push(finding);
                newFindings.push(finding);
            }

            // Test 3: Batch queries
            const batchResult = await this.probeEndpoint(endpoint.url, BATCH_TEST, headers);
            if (batchResult) {
                try {
                    const parsed = JSON.parse(batchResult);
                    if (Array.isArray(parsed) && parsed.length > 1) {
                        const finding: GraphQLFinding = {
                            type: 'batching',
                            severity: 'medium',
                            description: 'GraphQL batch queries are enabled - can be used for brute-force attacks',
                            evidence: `Batch query with 3 operations returned ${parsed.length} results`,
                            endpoint: endpoint.url,
                            remediation: 'Limit batch query size or disable batching in production',
                        };
                        this.findings.push(finding);
                        newFindings.push(finding);
                    }
                } catch {
                    // Not a valid batch response
                }
            }

            // Test 4: Field suggestion enumeration
            const enumResult = await this.probeEndpoint(
                endpoint.url,
                '{"query":"{ usr }"}',
                headers
            );
            if (enumResult && enumResult.includes('Did you mean')) {
                const finding: GraphQLFinding = {
                    type: 'field-suggestion',
                    severity: 'low',
                    description: 'GraphQL field suggestions are enabled - aids schema enumeration',
                    evidence: `Field suggestion returned for misspelled field at ${endpoint.url}`,
                    endpoint: endpoint.url,
                    remediation: 'Disable field suggestions in production to prevent schema enumeration',
                };
                this.findings.push(finding);
                newFindings.push(finding);
            }

            // Test 5: Mutation without auth
            if (endpoint.hasAuth) {
                const noAuthResult = await this.probeEndpoint(
                    endpoint.url,
                    '{"query":"mutation { __typename }"}',
                    { 'Content-Type': 'application/json' } // No auth headers
                );
                if (noAuthResult && !noAuthResult.includes('"errors"') && !noAuthResult.includes('Unauthorized') && !noAuthResult.includes('Forbidden')) {
                    const finding: GraphQLFinding = {
                        type: 'mutation-auth',
                        severity: 'critical',
                        description: 'GraphQL mutations accessible without authentication',
                        evidence: `Mutation succeeded without auth headers at ${endpoint.url}`,
                        endpoint: endpoint.url,
                        remediation: 'Ensure all mutations require authentication via middleware or resolver guards',
                    };
                    this.findings.push(finding);
                    newFindings.push(finding);
                }
            }
        }

        return newFindings;
    }

    private analyzeResponse(body: string, url: string): void {
        try {
            const data = JSON.parse(body);
            // Check for overly verbose error messages
            if (data.errors && Array.isArray(data.errors)) {
                for (const error of data.errors) {
                    if (error.message && error.message.includes('Did you mean')) {
                        this.addFinding({
                            type: 'field-suggestion',
                            severity: 'low',
                            description: 'GraphQL field suggestions detected in error response',
                            evidence: `Error contains suggestion: "${error.message.slice(0, 200)}"`,
                            endpoint: url,
                            remediation: 'Disable field suggestions in production',
                        });
                    }
                }
            }

            // Check for exposed schema in responses
            if (data.data?.__schema) {
                this.addFinding({
                    type: 'introspection',
                    severity: 'medium',
                    description: 'Schema data found in GraphQL response',
                    evidence: `Response contains __schema object with ${data.data.__schema.types?.length || 0} types`,
                    endpoint: url,
                    remediation: 'Disable introspection in production environments',
                });
            }
        } catch {
            // Not valid JSON
        }
    }

    private isGraphQLRequest(request: Request): boolean {
        const url = request.url().toLowerCase();
        if (url.includes('/graphql') || url.includes('/gql')) return true;
        if (request.method() === 'POST') {
            const contentType = request.headers()['content-type'] || '';
            if (contentType.includes('json')) {
                try {
                    const postData = request.postData();
                    if (postData && (postData.includes('"query"') || postData.includes('"mutation"'))) {
                        return true;
                    }
                } catch {
                    // Can't read post data
                }
            }
        }
        return false;
    }

    private async probeEndpoint(url: string, body: string, headers: Record<string, string>): Promise<string | null> {
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 5000);
            const response = await fetch(url, {
                method: 'POST',
                headers,
                body,
                signal: controller.signal,
            });
            clearTimeout(timer);
            if (!response.ok) return null;
            return await response.text();
        } catch {
            return null;
        }
    }

    private addFinding(finding: GraphQLFinding): void {
        const key = `${finding.type}:${finding.endpoint}`;
        if (!this.findings.some(f => `${f.type}:${f.endpoint}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): GraphQLFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
        this.detectedEndpoints.clear();
        this.analyzedUrls.clear();
    }

    onClose(): void {
        logger.info(`  [GraphQL] ${this.detectedEndpoints.size} endpoints, ${this.findings.length} findings`);
    }
}
