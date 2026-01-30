/**
 * API Contract Tester
 *
 * Service that validates API implementations against their OpenAPI/Swagger contracts:
 * - OpenAPI schema validation
 * - Request/response contract compliance
 * - Endpoint coverage analysis
 * - Schema drift detection
 * - Security scheme validation
 */

import { logger } from '../utils/logger.js';
import { fetchWithRetry } from '../utils/api-client.js';

export interface ContractFinding {
    type: 'schema-mismatch' | 'missing-endpoint' | 'undocumented-endpoint' | 'response-violation' | 'request-violation' | 'security-missing' | 'invalid-example';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    endpoint: string;
    method: string;
    evidence: string;
    remediation?: string;
}

interface OpenAPISpec {
    openapi: string;
    info: {
        title: string;
        version: string;
    };
    paths: Record<string, {
        get?: Operation;
        post?: Operation;
        put?: Operation;
        delete?: Operation;
        patch?: Operation;
    }>;
    components?: {
        schemas?: Record<string, unknown>;
        securitySchemes?: Record<string, SecurityScheme>;
    };
}

interface Operation {
    operationId?: string;
    summary?: string;
    parameters?: Array<{
        name: string;
        in: 'query' | 'path' | 'header' | 'cookie';
        required?: boolean;
        schema?: unknown;
    }>;
    requestBody?: {
        content?: Record<string, { schema?: unknown }>;
    };
    responses: Record<string, {
        description: string;
        content?: Record<string, { schema?: unknown }>;
    }>;
    security?: Array<Record<string, string[]>>;
}

interface SecurityScheme {
    type: 'http' | 'apiKey' | 'oauth2' | 'openIdConnect';
    scheme?: string;
    in?: string;
    name?: string;
    flows?: unknown;
    openIdConnectUrl?: string;
}

interface TestResult {
    endpoint: string;
    method: string;
    statusCode: number;
    passed: boolean;
    errors: string[];
    responseTime: number;
}

export class ApiContractTester {
    private findings: ContractFinding[] = [];
    private openAPISpec: OpenAPISpec | null = null;
    private baseUrl: string = '';

    /**
     * Load and validate OpenAPI specification
     */
    async loadSpec(specUrlOrPath: string): Promise<boolean> {
        try {
            if (specUrlOrPath.startsWith('http')) {
                const response = await fetchWithRetry<OpenAPISpec>(specUrlOrPath);
                this.openAPISpec = response;
            } else {
                // Would read from filesystem if needed
                logger.warn(`[ApiContractTester] Local file loading not implemented: ${specUrlOrPath}`);
                return false;
            }

            logger.info(`[ApiContractTester] Loaded OpenAPI spec: ${this.openAPISpec?.info.title} v${this.openAPISpec?.info.version}`);
            return true;
        } catch (error) {
            logger.error(`[ApiContractTester] Failed to load spec: ${(error as Error).message}`);
            return false;
        }
    }

    /**
     * Test API contract compliance
     */
    async testContract(baseUrl: string, options: {
        testMethods?: string[];
        skipAuth?: boolean;
        maxEndpoints?: number;
    } = {}): Promise<ContractFinding[]> {
        this.findings = [];
        this.baseUrl = baseUrl;

        if (!this.openAPISpec) {
            logger.error('[ApiContractTester] No OpenAPI spec loaded');
            return this.findings;
        }

        const paths = Object.entries(this.openAPISpec.paths);
        const testMethods = options.testMethods || ['get', 'post', 'put', 'delete', 'patch'];
        const maxEndpoints = options.maxEndpoints || 50;

        let testedCount = 0;

        for (const [path, methods] of paths.slice(0, maxEndpoints)) {
            for (const method of testMethods) {
                const operation = methods[method as keyof typeof methods] as Operation | undefined;
                if (!operation) continue;

                testedCount++;
                await this.testEndpoint(path, method, operation, options.skipAuth);
            }
        }

        // Check for security scheme compliance
        this.validateSecuritySchemes();

        logger.info(`[ApiContractTester] ${this.findings.length} contract findings from ${testedCount} endpoint tests`);
        return [...this.findings];
    }

    private async testEndpoint(
        path: string,
        method: string,
        operation: Operation,
        skipAuth?: boolean
    ): Promise<void> {
        const fullUrl = `${this.baseUrl}${path}`;
        
        try {
            const startTime = Date.now();
            
            // Build request based on operation parameters
            const requestInit: RequestInit = {
                method: method.toUpperCase(),
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                },
            };

            // Add example request body if available
            if (operation.requestBody?.content?.['application/json']?.schema) {
                const exampleBody = this.generateExampleBody(
                    operation.requestBody.content['application/json'].schema
                );
                if (exampleBody) {
                    requestInit.body = JSON.stringify(exampleBody);
                }
            }

            const response = await fetch(fullUrl, requestInit);
            const responseTime = Date.now() - startTime;

            // Validate response status
            const declaredResponses = Object.keys(operation.responses);
            const actualStatus = response.status.toString();

            if (!declaredResponses.includes(actualStatus)) {
                this.addFinding({
                    type: 'response-violation',
                    severity: 'high',
                    description: `Undocumented response status code: ${actualStatus}`,
                    endpoint: path,
                    method: method.toUpperCase(),
                    evidence: `Declared: ${declaredResponses.join(', ')}, Got: ${actualStatus}`,
                    remediation: 'Add the missing response code to the OpenAPI spec or fix the API to return documented codes',
                });
            }

            // Check if response schema is defined
            const responseSpec = operation.responses[actualStatus];
            if (!responseSpec) {
                this.addFinding({
                    type: 'missing-endpoint',
                    severity: 'medium',
                    description: `Response ${actualStatus} not documented for ${method.toUpperCase()} ${path}`,
                    endpoint: path,
                    method: method.toUpperCase(),
                    evidence: `No response specification for status ${actualStatus}`,
                    remediation: 'Add response definition to the OpenAPI specification',
                });
            }

            // Validate response content type
            const contentType = response.headers.get('content-type') || '';
            if (responseSpec?.content && !Object.keys(responseSpec.content).some(ct => contentType.includes(ct))) {
                this.addFinding({
                    type: 'response-violation',
                    severity: 'medium',
                    description: `Response Content-Type doesn't match specification`,
                    endpoint: path,
                    method: method.toUpperCase(),
                    evidence: `Expected: ${Object.keys(responseSpec.content).join(', ')}, Got: ${contentType}`,
                    remediation: 'Ensure API returns documented Content-Type',
                });
            }

            // Check response time
            if (responseTime > 5000) {
                logger.warn(`[ApiContractTester] Slow response: ${method.toUpperCase()} ${path} took ${responseTime}ms`);
            }

        } catch (error) {
            this.addFinding({
                type: 'missing-endpoint',
                severity: 'critical',
                description: `Endpoint unreachable or failed`,
                endpoint: path,
                method: method.toUpperCase(),
                evidence: `Error: ${(error as Error).message}`,
                remediation: 'Ensure the endpoint is implemented and accessible',
            });
        }
    }

    private generateExampleBody(schema: unknown): unknown {
        // Generate example from JSON schema
        if (!schema || typeof schema !== 'object') return null;

        const schemaObj = schema as Record<string, unknown>;

        if (schemaObj.example) {
            return schemaObj.example;
        }

        if (schemaObj.type === 'object' && schemaObj.properties) {
            const example: Record<string, unknown> = {};
            const properties = schemaObj.properties as Record<string, unknown>;
            
            for (const [key, propSchema] of Object.entries(properties)) {
                example[key] = this.generateExampleValue(propSchema);
            }
            return example;
        }

        if (schemaObj.type === 'array' && schemaObj.items) {
            const itemExample = this.generateExampleBody(schemaObj.items);
            return itemExample ? [itemExample] : [];
        }

        return null;
    }

    private generateExampleValue(schema: unknown): unknown {
        if (!schema || typeof schema !== 'object') return null;

        const schemaObj = schema as Record<string, unknown>;

        if (schemaObj.example !== undefined) return schemaObj.example;

        switch (schemaObj.type) {
            case 'string':
                if (schemaObj.format === 'email') return 'test@example.com';
                if (schemaObj.format === 'date') return '2024-01-01';
                if (schemaObj.format === 'date-time') return '2024-01-01T00:00:00Z';
                if (schemaObj.enum && Array.isArray(schemaObj.enum) && schemaObj.enum.length > 0) {
                    return schemaObj.enum[0];
                }
                return 'string';
            case 'integer':
            case 'number':
                return schemaObj.minimum || 0;
            case 'boolean':
                return false;
            case 'object':
                return this.generateExampleBody(schema);
            case 'array':
                return this.generateExampleBody(schema);
            default:
                return null;
        }
    }

    private validateSecuritySchemes(): void {
        if (!this.openAPISpec?.components?.securitySchemes) {
            this.addFinding({
                type: 'security-missing',
                severity: 'medium',
                description: 'No security schemes defined in OpenAPI spec',
                endpoint: 'global',
                method: 'N/A',
                evidence: 'components.securitySchemes is missing',
                remediation: 'Define security schemes for API authentication/authorization',
            });
            return;
        }

        const schemes = this.openAPISpec.components.securitySchemes;

        for (const [name, scheme] of Object.entries(schemes)) {
            if (scheme.type === 'http' && scheme.scheme === 'bearer') {
                logger.debug(`[ApiContractTester] Bearer auth scheme: ${name}`);
            }

            if (scheme.type === 'apiKey' && !scheme.in) {
                this.addFinding({
                    type: 'security-missing',
                    severity: 'medium',
                    description: `API Key scheme '${name}' missing 'in' parameter`,
                    endpoint: 'global',
                    method: 'N/A',
                    evidence: `apiKey scheme without 'in' location`,
                    remediation: "Specify where API key is passed: 'header', 'query', or 'cookie'",
                });
            }
        }
    }

    /**
     * Detect drift between implementation and spec
     */
    async detectDrift(discoveredEndpoints: Array<{ path: string; methods: string[] }>): Promise<ContractFinding[]> {
        const driftFindings: ContractFinding[] = [];

        if (!this.openAPISpec) {
            return driftFindings;
        }

        const specPaths = new Set(Object.keys(this.openAPISpec.paths));
        const discoveredPaths = new Set(discoveredEndpoints.map(e => e.path));

        // Find undocumented endpoints
        for (const path of discoveredPaths) {
            if (!specPaths.has(path)) {
                const endpoint = discoveredEndpoints.find(e => e.path === path);
                driftFindings.push({
                    type: 'undocumented-endpoint',
                    severity: 'medium',
                    description: `Endpoint exists but not documented in OpenAPI spec`,
                    endpoint: path,
                    method: (endpoint?.methods || ['GET']).join(','),
                    evidence: `Discovered: ${path}, Not in spec`,
                    remediation: 'Add the endpoint to the OpenAPI specification',
                });
            }
        }

        // Find missing endpoints
        for (const path of specPaths) {
            if (!discoveredPaths.has(path)) {
                driftFindings.push({
                    type: 'missing-endpoint',
                    severity: 'high',
                    description: `Documented endpoint not found in implementation`,
                    endpoint: path,
                    method: 'N/A',
                    evidence: `In spec: ${path}, Not discovered`,
                    remediation: 'Implement the missing endpoint or remove from spec',
                });
            }
        }

        this.findings.push(...driftFindings);
        return driftFindings;
    }

    private addFinding(finding: ContractFinding): void {
        const key = `${finding.type}:${finding.endpoint}:${finding.method}:${finding.description.slice(0, 40)}`;
        if (!this.findings.some(f => `${f.type}:${f.endpoint}:${f.method}:${f.description.slice(0, 40)}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): ContractFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
        this.openAPISpec = null;
        this.baseUrl = '';
    }
}
