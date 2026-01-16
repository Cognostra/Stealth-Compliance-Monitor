/**
 * API Endpoint Testing Service
 * 
 * Provides automated testing for backend APIs (REST/GraphQL).
 * Can discover endpoints via:
 * - OpenAPI/Swagger specification files
 * - Network request interception during crawl
 * - Manual endpoint configuration
 * 
 * Tests common security issues:
 * - Authentication bypass
 * - Rate limiting
 * - Data exposure
 * - Error handling
 * 
 * Routes requests through ZAP proxy for security scanning.
 */

import { APIRequestContext, request as playwrightRequest, BrowserContext } from 'playwright';
import { Logger } from '../types/index.js';
import { EnvConfig } from '../config/env.js';
import { retryNetwork } from '../utils/retry.js';
import { humanDelay } from '../utils/throttle.js';

/**
 * Discovered API endpoint
 */
export interface ApiEndpoint {
    /** HTTP method */
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';
    /** Full URL path */
    url: string;
    /** Path pattern (e.g., /api/users/{id}) */
    pathPattern?: string;
    /** Request content type */
    contentType?: string;
    /** Whether endpoint requires authentication */
    requiresAuth?: boolean;
    /** Source of discovery */
    source: 'openapi' | 'network' | 'manual';
    /** Sample request body (for POST/PUT) */
    sampleBody?: unknown;
    /** Expected response status codes */
    expectedStatus?: number[];
}

/**
 * API test finding
 */
export interface ApiFinding {
    /** Finding unique ID */
    id: string;
    /** Finding title */
    title: string;
    /** Severity level */
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    /** Endpoint that was tested */
    endpoint: string;
    /** HTTP method */
    method: string;
    /** Description of the issue */
    description: string;
    /** Response status code */
    statusCode?: number;
    /** Evidence/details */
    evidence?: string;
    /** Remediation guidance */
    remediation?: string;
}

/**
 * API test result summary
 */
export interface ApiTestResult {
    /** Endpoints tested */
    endpointsTested: number;
    /** Endpoints discovered */
    endpointsDiscovered: ApiEndpoint[];
    /** Findings from tests */
    findings: ApiFinding[];
    /** Test duration in ms */
    duration: number;
    /** Summary by severity */
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
}

/**
 * OpenAPI Specification structure (minimal)
 */
interface OpenApiSpec {
    openapi?: string;
    swagger?: string;
    info?: {
        title?: string;
        version?: string;
    };
    servers?: Array<{ url: string }>;
    paths?: Record<string, Record<string, {
        summary?: string;
        operationId?: string;
        parameters?: unknown[];
        requestBody?: {
            content?: Record<string, { schema?: unknown }>;
        };
        responses?: Record<string, unknown>;
        security?: unknown[];
    }>>;
}

export class ApiEndpointTester {
    private readonly config: EnvConfig;
    private readonly logger: Logger;
    private readonly discoveredEndpoints: ApiEndpoint[] = [];
    private readonly findings: ApiFinding[] = [];
    private apiContext: APIRequestContext | null = null;
    private readonly useProxy: boolean;

    // Rate limiting
    private readonly REQUEST_DELAY_MS = 1000;
    private readonly RATE_LIMIT_TEST_REQUESTS = 10;

    constructor(config: EnvConfig, logger: Logger, useProxy: boolean = true) {
        this.config = config;
        this.logger = logger;
        this.useProxy = useProxy;
    }

    /**
     * Initialize API request context
     */
    async initialize(): Promise<void> {
        const contextOptions: Parameters<typeof playwrightRequest.newContext>[0] = {
            baseURL: this.config.LIVE_URL,
            extraHTTPHeaders: {
                'Accept': 'application/json',
                'User-Agent': this.config.USER_AGENT,
            },
            ignoreHTTPSErrors: true,
        };

        // Route through ZAP proxy if enabled
        if (this.useProxy && this.config.ZAP_PROXY_URL) {
            contextOptions.proxy = {
                server: this.config.ZAP_PROXY_URL,
            };
        }

        this.apiContext = await playwrightRequest.newContext(contextOptions);
        this.logger.info('[API] API testing context initialized');
    }

    /**
     * Load endpoints from OpenAPI/Swagger specification
     */
    async loadFromOpenApiSpec(specPathOrUrl: string): Promise<number> {
        this.logger.info(`[API] Loading OpenAPI spec from: ${specPathOrUrl}`);

        try {
            let spec: OpenApiSpec;

            if (specPathOrUrl.startsWith('http://') || specPathOrUrl.startsWith('https://')) {
                // Fetch from URL
                const response = await fetch(specPathOrUrl);
                if (!response.ok) {
                    throw new Error(`Failed to fetch spec: ${response.status}`);
                }
                spec = await response.json() as OpenApiSpec;
            } else {
                // Load from file
                const fs = await import('fs');
                const content = fs.readFileSync(specPathOrUrl, 'utf-8');
                spec = JSON.parse(content) as OpenApiSpec;
            }

            // Determine base URL
            let baseUrl = this.config.LIVE_URL;
            if (spec.servers && spec.servers.length > 0) {
                const serverUrl = spec.servers[0].url;
                if (serverUrl.startsWith('http')) {
                    baseUrl = serverUrl;
                } else if (serverUrl.startsWith('/')) {
                    baseUrl = new URL(serverUrl, this.config.LIVE_URL).toString();
                }
            }

            // Extract endpoints
            if (spec.paths) {
                for (const [pathTemplate, pathItem] of Object.entries(spec.paths)) {
                    for (const [method, operation] of Object.entries(pathItem)) {
                        if (['get', 'post', 'put', 'patch', 'delete', 'options', 'head'].includes(method.toLowerCase())) {
                            const endpoint: ApiEndpoint = {
                                method: method.toUpperCase() as ApiEndpoint['method'],
                                url: new URL(pathTemplate, baseUrl).toString(),
                                pathPattern: pathTemplate,
                                requiresAuth: !!(operation.security && operation.security.length > 0),
                                source: 'openapi',
                            };

                            // Extract content type for POST/PUT
                            if (operation.requestBody?.content) {
                                const contentTypes = Object.keys(operation.requestBody.content);
                                endpoint.contentType = contentTypes[0];
                            }

                            this.discoveredEndpoints.push(endpoint);
                        }
                    }
                }
            }

            this.logger.info(`[API] Loaded ${this.discoveredEndpoints.length} endpoints from OpenAPI spec`);
            return this.discoveredEndpoints.length;

        } catch (error) {
            this.logger.error(`[API] Failed to load OpenAPI spec: ${error instanceof Error ? error.message : String(error)}`);
            return 0;
        }
    }

    /**
     * Discover endpoints from network requests during browsing
     */
    addDiscoveredEndpoint(
        method: string,
        url: string,
        contentType?: string,
        body?: unknown
    ): void {
        // Filter for API-like endpoints
        const urlObj = new URL(url);
        const isApi = urlObj.pathname.includes('/api/') ||
            urlObj.pathname.includes('/graphql') ||
            urlObj.pathname.includes('/v1/') ||
            urlObj.pathname.includes('/v2/') ||
            (contentType?.includes('application/json') ?? false);

        if (!isApi) return;

        // Check for duplicates
        const exists = this.discoveredEndpoints.some(
            ep => ep.url === url && ep.method === method.toUpperCase()
        );

        if (!exists) {
            this.discoveredEndpoints.push({
                method: method.toUpperCase() as ApiEndpoint['method'],
                url,
                contentType,
                source: 'network',
                sampleBody: body,
            });
            this.logger.debug(`[API] Discovered endpoint: ${method} ${url}`);
        }
    }

    /**
     * Add endpoints manually
     */
    addEndpoints(endpoints: ApiEndpoint[]): void {
        for (const endpoint of endpoints) {
            this.discoveredEndpoints.push({
                ...endpoint,
                source: endpoint.source || 'manual',
            });
        }
        this.logger.info(`[API] Added ${endpoints.length} manual endpoints`);
    }

    /**
     * Run all API security tests
     */
    async runTests(authToken?: string): Promise<ApiTestResult> {
        const startTime = Date.now();
        this.logger.info(`[API] Starting API security tests on ${this.discoveredEndpoints.length} endpoints`);

        if (!this.apiContext) {
            await this.initialize();
        }

        // Set auth header if provided
        if (authToken && this.apiContext) {
            this.apiContext = await playwrightRequest.newContext({
                baseURL: this.config.LIVE_URL,
                extraHTTPHeaders: {
                    'Accept': 'application/json',
                    'User-Agent': this.config.USER_AGENT,
                    'Authorization': `Bearer ${authToken}`,
                },
                ignoreHTTPSErrors: true,
                proxy: this.useProxy && this.config.ZAP_PROXY_URL
                    ? { server: this.config.ZAP_PROXY_URL }
                    : undefined,
            });
        }

        // Test each endpoint
        for (const endpoint of this.discoveredEndpoints) {
            await this.testEndpoint(endpoint, authToken);
            await humanDelay(this.REQUEST_DELAY_MS, this.REQUEST_DELAY_MS * 2);
        }

        // Run global tests
        await this.testRateLimiting();
        await this.testCommonEndpoints();

        const duration = Date.now() - startTime;

        const result: ApiTestResult = {
            endpointsTested: this.discoveredEndpoints.length,
            endpointsDiscovered: this.discoveredEndpoints,
            findings: this.findings,
            duration,
            summary: {
                critical: this.findings.filter(f => f.severity === 'critical').length,
                high: this.findings.filter(f => f.severity === 'high').length,
                medium: this.findings.filter(f => f.severity === 'medium').length,
                low: this.findings.filter(f => f.severity === 'low').length,
                info: this.findings.filter(f => f.severity === 'info').length,
            },
        };

        this.logger.info(`[API] Tests completed: ${result.findings.length} findings in ${(duration / 1000).toFixed(2)}s`);
        return result;
    }

    /**
     * Test a single endpoint
     */
    private async testEndpoint(endpoint: ApiEndpoint, authToken?: string): Promise<void> {
        if (!this.apiContext) return;

        this.logger.debug(`[API] Testing: ${endpoint.method} ${endpoint.url}`);

        try {
            // Test 1: Normal request
            const response = await this.apiContext.fetch(endpoint.url, {
                method: endpoint.method,
                headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : undefined,
            });

            // Check for sensitive data exposure in error responses
            if (response.status() >= 400) {
                const body = await response.text();
                await this.checkErrorDisclosure(endpoint, response.status(), body);
            }

            // Test 2: Auth bypass (if endpoint requires auth)
            if (endpoint.requiresAuth && authToken) {
                await this.testAuthBypass(endpoint);
            }

            // Test 3: Method manipulation
            await this.testMethodManipulation(endpoint);

            // Test 4: Parameter pollution (for endpoints with path params)
            if (endpoint.pathPattern?.includes('{')) {
                await this.testParameterPollution(endpoint);
            }

        } catch (error) {
            this.logger.warn(`[API] Error testing ${endpoint.url}: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Check for information disclosure in error responses
     */
    private async checkErrorDisclosure(endpoint: ApiEndpoint, status: number, body: string): Promise<void> {
        // Check for stack traces
        if (body.includes('at ') && (body.includes('.js:') || body.includes('.ts:'))) {
            this.addFinding({
                id: 'api-stack-trace-disclosure',
                title: 'Stack Trace Exposed in API Response',
                severity: 'medium',
                endpoint: endpoint.url,
                method: endpoint.method,
                description: 'The API returns stack traces in error responses, potentially revealing internal implementation details.',
                statusCode: status,
                evidence: body.substring(0, 500),
                remediation: 'Configure error handling to return generic error messages in production.',
            });
        }

        // Check for SQL errors
        if (/sql|syntax|query|database|mysql|postgres|oracle/i.test(body)) {
            this.addFinding({
                id: 'api-sql-error-disclosure',
                title: 'Database Error Exposed in API Response',
                severity: 'high',
                endpoint: endpoint.url,
                method: endpoint.method,
                description: 'The API exposes database error messages, potentially revealing schema or query details.',
                statusCode: status,
                evidence: body.substring(0, 500),
                remediation: 'Implement proper error handling to hide database errors from API responses.',
            });
        }

        // Check for internal paths
        if (/\/home\/|\/var\/|C:\\|\/usr\/|node_modules/i.test(body)) {
            this.addFinding({
                id: 'api-path-disclosure',
                title: 'Internal Path Exposed in API Response',
                severity: 'low',
                endpoint: endpoint.url,
                method: endpoint.method,
                description: 'The API exposes internal file system paths.',
                statusCode: status,
                evidence: body.substring(0, 500),
                remediation: 'Remove internal paths from error messages.',
            });
        }
    }

    /**
     * Test authentication bypass
     */
    private async testAuthBypass(endpoint: ApiEndpoint): Promise<void> {
        if (!this.apiContext) return;

        try {
            // Create context without auth
            const noAuthContext = await playwrightRequest.newContext({
                baseURL: this.config.LIVE_URL,
                extraHTTPHeaders: {
                    'Accept': 'application/json',
                    'User-Agent': this.config.USER_AGENT,
                },
                ignoreHTTPSErrors: true,
            });

            const response = await noAuthContext.fetch(endpoint.url, {
                method: endpoint.method,
            });

            // If we get 2xx without auth on an endpoint that requires it
            if (response.status() >= 200 && response.status() < 300) {
                this.addFinding({
                    id: 'api-auth-bypass',
                    title: 'API Authentication Bypass',
                    severity: 'critical',
                    endpoint: endpoint.url,
                    method: endpoint.method,
                    description: 'The API endpoint returns successful response without authentication when it should require it.',
                    statusCode: response.status(),
                    remediation: 'Implement proper authentication middleware for all protected endpoints.',
                });
            }

            await noAuthContext.dispose();

        } catch (error) {
            // Connection errors are expected for some endpoints
        }
    }

    /**
     * Test HTTP method manipulation
     */
    private async testMethodManipulation(endpoint: ApiEndpoint): Promise<void> {
        if (!this.apiContext) return;

        // Only test safe methods with alternative methods
        if (endpoint.method !== 'GET') return;

        try {
            // Try DELETE on a GET endpoint
            const response = await this.apiContext.fetch(endpoint.url, {
                method: 'DELETE',
            });

            if (response.status() >= 200 && response.status() < 300) {
                this.addFinding({
                    id: 'api-method-confusion',
                    title: 'HTTP Method Confusion',
                    severity: 'high',
                    endpoint: endpoint.url,
                    method: 'DELETE (original: GET)',
                    description: 'The API accepts DELETE requests on an endpoint that was observed as GET, potentially allowing unauthorized data deletion.',
                    statusCode: response.status(),
                    remediation: 'Implement explicit method whitelisting for each endpoint.',
                });
            }

        } catch (error) {
            // Expected for most endpoints
        }
    }

    /**
     * Test parameter pollution
     */
    private async testParameterPollution(endpoint: ApiEndpoint): Promise<void> {
        if (!this.apiContext) return;

        // Add duplicate query parameters
        const urlWithDuplicates = `${endpoint.url}?id=1&id=2&admin=true`;

        try {
            const response = await this.apiContext.fetch(urlWithDuplicates, {
                method: endpoint.method,
            });

            if (response.status() >= 200 && response.status() < 300) {
                const body = await response.text();

                // Check if admin parameter had effect
                if (body.includes('"admin":true') || body.includes('"role":"admin"')) {
                    this.addFinding({
                        id: 'api-parameter-pollution',
                        title: 'HTTP Parameter Pollution',
                        severity: 'high',
                        endpoint: endpoint.url,
                        method: endpoint.method,
                        description: 'The API is vulnerable to parameter pollution, accepting injected admin parameters.',
                        statusCode: response.status(),
                        remediation: 'Implement strict parameter validation and reject unexpected parameters.',
                    });
                }
            }

        } catch (error) {
            // Expected
        }
    }

    /**
     * Test rate limiting
     */
    private async testRateLimiting(): Promise<void> {
        if (!this.apiContext) return;
        if (this.discoveredEndpoints.length === 0) return;

        const endpoint = this.discoveredEndpoints.find(e => e.method === 'GET') || this.discoveredEndpoints[0];
        this.logger.info('[API] Testing rate limiting...');

        let successCount = 0;
        const responses: number[] = [];

        for (let i = 0; i < this.RATE_LIMIT_TEST_REQUESTS; i++) {
            try {
                const response = await this.apiContext.fetch(endpoint.url, {
                    method: endpoint.method,
                });
                responses.push(response.status());
                if (response.status() === 200) {
                    successCount++;
                }
            } catch {
                responses.push(0);
            }
        }

        // If all requests succeeded, rate limiting might not be in place
        if (successCount === this.RATE_LIMIT_TEST_REQUESTS) {
            this.addFinding({
                id: 'api-no-rate-limiting',
                title: 'No Rate Limiting Detected',
                severity: 'medium',
                endpoint: endpoint.url,
                method: endpoint.method,
                description: `${this.RATE_LIMIT_TEST_REQUESTS} rapid requests all succeeded without rate limiting.`,
                evidence: `Status codes: ${responses.join(', ')}`,
                remediation: 'Implement rate limiting to prevent abuse and DoS attacks.',
            });
        } else {
            const rateLimited = responses.some(s => s === 429);
            if (rateLimited) {
                this.logger.info('[API] Rate limiting detected (429 responses)');
            }
        }
    }

    /**
     * Test common sensitive endpoints
     */
    private async testCommonEndpoints(): Promise<void> {
        if (!this.apiContext) return;

        const sensitiveEndpoints = [
            '/api/admin',
            '/api/users',
            '/api/config',
            '/api/settings',
            '/api/debug',
            '/api/health',
            '/api/metrics',
            '/api/env',
            '/graphql',
            '/.well-known/openid-configuration',
            '/swagger.json',
            '/openapi.json',
            '/api-docs',
        ];

        this.logger.info('[API] Testing common sensitive endpoints...');

        for (const path of sensitiveEndpoints) {
            try {
                const url = new URL(path, this.config.LIVE_URL).toString();
                const response = await this.apiContext.fetch(url, { method: 'GET' });

                if (response.status() === 200) {
                    const body = await response.text();

                    // Check for sensitive content
                    if (path.includes('debug') || path.includes('env')) {
                        this.addFinding({
                            id: `api-sensitive-endpoint-${path.replace(/\//g, '-')}`,
                            title: `Sensitive Endpoint Exposed: ${path}`,
                            severity: 'high',
                            endpoint: url,
                            method: 'GET',
                            description: `The sensitive endpoint ${path} is accessible and returns data.`,
                            statusCode: 200,
                            evidence: body.substring(0, 200),
                            remediation: 'Restrict access to sensitive endpoints using authentication and IP whitelisting.',
                        });
                    } else if (path.includes('swagger') || path.includes('openapi')) {
                        this.addFinding({
                            id: 'api-spec-exposed',
                            title: 'API Specification Publicly Accessible',
                            severity: 'info',
                            endpoint: url,
                            method: 'GET',
                            description: 'The API specification is publicly accessible, which may reveal internal API structure.',
                            statusCode: 200,
                            remediation: 'Consider restricting access to API documentation in production.',
                        });
                    }
                }

                await humanDelay(200, 400);

            } catch {
                // Expected for most endpoints
            }
        }
    }

    /**
     * Add a finding
     */
    private addFinding(finding: ApiFinding): void {
        // Avoid duplicates
        const exists = this.findings.some(f => f.id === finding.id && f.endpoint === finding.endpoint);
        if (!exists) {
            this.findings.push(finding);
            this.logger.warn(`[API] Finding: ${finding.title} (${finding.severity}) - ${finding.endpoint}`);
        }
    }

    /**
     * Get discovered endpoints
     */
    getDiscoveredEndpoints(): ApiEndpoint[] {
        return [...this.discoveredEndpoints];
    }

    /**
     * Get findings
     */
    getFindings(): ApiFinding[] {
        return [...this.findings];
    }

    /**
     * Cleanup
     */
    async dispose(): Promise<void> {
        if (this.apiContext) {
            await this.apiContext.dispose();
            this.apiContext = null;
        }
    }
}

export default ApiEndpointTester;
