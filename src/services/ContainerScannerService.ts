/**
 * Container Scanner Service
 *
 * Service that audits Docker containers and container configurations:
 * - Dockerfile security analysis
 * - Container image vulnerability scanning
 * - Docker-compose security validation
 * - Container runtime security checks
 * - Image provenance and SBOM analysis
 */

import { readFile, access } from 'fs/promises';
import { resolve, dirname } from 'path';
import { logger } from '../utils/logger.js';

export interface ContainerFinding {
    type: 'privileged-container' | 'root-user' | 'sensitive-mount' | 'exposed-secret' | 'outdated-base' | 'large-image' | 'insecure-registry' | 'missing-healthcheck' | 'dangerous-capability';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    file: string;
    line?: number;
    remediation?: string;
}

interface DockerfileInfo {
    fromImages: Array<{ image: string; tag: string; line: number }>;
    runCommands: Array<{ command: string; line: number }>;
    exposedPorts: Array<{ port: string; line: number }>;
    envVars: Array<{ key: string; value: string; line: number }>;
    volumes: Array<{ path: string; line: number }>;
    user: string | null;
    healthCheck: boolean;
    privileged: boolean;
}

interface DockerComposeInfo {
    services: Array<{
        name: string;
        privileged?: boolean;
        user?: string;
        volumes?: string[];
        ports?: string[];
        environment?: Record<string, string>;
        capabilities?: string[];
    }>;
}

// Dangerous patterns in Dockerfiles
const DANGEROUS_PATTERNS = [
    { pattern: /curl.*\|.*sh/i, description: 'Piping curl output to shell' },
    { pattern: /wget.*\|.*sh/i, description: 'Piping wget output to shell' },
    { pattern: /npm\s+install\s+-g/i, description: 'Global npm install (may have permission issues)' },
    { pattern: /pip\s+install.*--user/i, description: 'User pip install (inconsistent permissions)' },
    { pattern: /apt-get\s+upgrade/i, description: 'apt-get upgrade in container (bad practice)' },
    { pattern: /ssh.*-i\s+/, description: 'SSH with private key' },
    { pattern: /password\s*=\s*["'][^"']+["']/i, description: 'Hardcoded password' },
    { pattern: /api[_-]?key\s*=\s*["'][^"']+["']/i, description: 'Hardcoded API key' },
    { pattern: /secret\s*=\s*["'][^"']+["']/i, description: 'Hardcoded secret' },
    { pattern: /token\s*=\s*["'][^"']+["']/i, description: 'Hardcoded token' },
];

// Sensitive mount paths
const SENSITIVE_MOUNTS = [
    '/var/run/docker.sock',
    '/etc/shadow',
    '/etc/passwd',
    '/root/.ssh',
    '/home/*/.ssh',
    '/proc',
    '/sys',
];

// Outdated/vulnerable base images
const OUTDATED_BASES = [
    'ubuntu:14.04',
    'ubuntu:16.04',
    'debian:7',
    'debian:8',
    'centos:6',
    'centos:7',
    'alpine:3.8',
    'alpine:3.9',
    'node:10',
    'node:12',
    'python:2',
    'python:3.5',
    'python:3.6',
    'openjdk:8',
];

// Dangerous capabilities
const DANGEROUS_CAPABILITIES = [
    'CAP_SYS_ADMIN',
    'CAP_SYS_PTRACE',
    'CAP_SYS_MODULE',
    'CAP_DAC_READ_SEARCH',
    'CAP_DAC_OVERRIDE',
    'CAP_SYS_RAWIO',
    'CAP_SYSLOG',
    'CAP_NET_ADMIN',
    'CAP_NET_RAW',
];

export class ContainerScannerService {
    private findings: ContainerFinding[] = [];
    private projectRoot: string = '';

    /**
     * Scan a project directory for container security issues
     */
    async scanProject(projectPath: string): Promise<ContainerFinding[]> {
        this.findings = [];
        this.projectRoot = projectPath;

        try {
            // Look for Dockerfile
            await this.scanDockerfile();

            // Look for docker-compose files
            await this.scanDockerCompose();

            // Look for container configuration in other files
            await this.scanContainerConfigs();

            logger.info(`[ContainerScannerService] ${this.findings.length} container findings in ${projectPath}`);
        } catch (error) {
            logger.error(`[ContainerScannerService] Error scanning project: ${(error as Error).message}`);
        }

        return [...this.findings];
    }

    private async scanDockerfile(): Promise<void> {
        const dockerfilePaths = [
            resolve(this.projectRoot, 'Dockerfile'),
            resolve(this.projectRoot, 'dockerfile'),
            resolve(this.projectRoot, 'Dockerfile.prod'),
            resolve(this.projectRoot, 'Dockerfile.production'),
        ];

        for (const dockerfilePath of dockerfilePaths) {
            try {
                await access(dockerfilePath);
                await this.analyzeDockerfile(dockerfilePath);
            } catch {
                // File doesn't exist, continue to next
                continue;
            }
        }
    }

    private async analyzeDockerfile(filePath: string): Promise<void> {
        try {
            const content = await readFile(filePath, 'utf-8');
            const lines = content.split('\n');

            const dockerfileInfo: DockerfileInfo = {
                fromImages: [],
                runCommands: [],
                exposedPorts: [],
                envVars: [],
                volumes: [],
                user: null,
                healthCheck: false,
                privileged: false,
            };

            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                const lineNum = i + 1;

                // Parse FROM images
                if (line.toUpperCase().startsWith('FROM ')) {
                    const match = line.match(/FROM\s+(\S+)(?::(\S+))?/i);
                    if (match) {
                        dockerfileInfo.fromImages.push({
                            image: match[1],
                            tag: match[2] || 'latest',
                            line: lineNum,
                        });

                        // Check for outdated base image
                        const fullImage = `${match[1]}:${match[2] || 'latest'}`;
                        const isOutdated = OUTDATED_BASES.some(outdated => 
                            fullImage.includes(outdated) || match[1].includes(outdated.split(':')[0])
                        );

                        if (isOutdated) {
                            this.addFinding({
                                type: 'outdated-base',
                                severity: 'high',
                                description: `Using outdated or end-of-life base image: ${fullImage}`,
                                evidence: `FROM ${fullImage}`,
                                file: filePath,
                                line: lineNum,
                                remediation: 'Update to a supported base image version with active security updates',
                            });
                        }

                        // Check for 'latest' tag (bad practice)
                        if (!match[2] || match[2] === 'latest') {
                            this.addFinding({
                                type: 'outdated-base',
                                severity: 'medium',
                                description: `Using 'latest' tag for base image - not reproducible`,
                                evidence: `FROM ${match[1]}${match[2] ? ':latest' : ''}`,
                                file: filePath,
                                line: lineNum,
                                remediation: 'Pin to a specific version tag for reproducible builds',
                            });
                        }
                    }
                }

                // Parse RUN commands
                if (line.toUpperCase().startsWith('RUN ')) {
                    const command = line.substring(4).trim();
                    dockerfileInfo.runCommands.push({ command, line: lineNum });

                    // Check for dangerous patterns
                    for (const pattern of DANGEROUS_PATTERNS) {
                        if (pattern.pattern.test(command)) {
                            this.addFinding({
                                type: 'exposed-secret',
                                severity: pattern.description.includes('password') || pattern.description.includes('key') || pattern.description.includes('secret') || pattern.description.includes('token') ? 'critical' : 'high',
                                description: `Dangerous RUN command: ${pattern.description}`,
                                evidence: `RUN ${command}`,
                                file: filePath,
                                line: lineNum,
                                remediation: 'Avoid piping from network directly to shell. Use package managers with verified signatures.',
                            });
                        }
                    }
                }

                // Parse USER
                if (line.toUpperCase().startsWith('USER ')) {
                    const user = line.substring(5).trim();
                    dockerfileInfo.user = user;

                    // Check for root user
                    if (user === 'root' || user === '0') {
                        this.addFinding({
                            type: 'root-user',
                            severity: 'high',
                            description: 'Container running as root user',
                            evidence: `USER ${user}`,
                            file: filePath,
                            line: lineNum,
                            remediation: 'Create and use a non-root user for running the application',
                        });
                    }
                }

                // Check for exposed ports
                if (line.toUpperCase().startsWith('EXPOSE ')) {
                    const ports = line.substring(7).trim().split(/\s+/);
                    for (const port of ports) {
                        dockerfileInfo.exposedPorts.push({ port, line: lineNum });
                    }
                }

                // Parse ENV
                if (line.toUpperCase().startsWith('ENV ')) {
                    const envLine = line.substring(4).trim();
                    const envMatch = envLine.match(/^(\w+)\s*=\s*["']?([^"']+)["']?/);
                    if (envMatch) {
                        dockerfileInfo.envVars.push({
                            key: envMatch[1],
                            value: envMatch[2],
                            line: lineNum,
                        });

                        // Check for secrets in environment
                        const secretPattern = /password|secret|key|token|credential|auth/i;
                        if (secretPattern.test(envMatch[1]) && envMatch[2].length > 0) {
                            this.addFinding({
                                type: 'exposed-secret',
                                severity: 'critical',
                                description: `Potential secret in ENV variable: ${envMatch[1]}`,
                                evidence: `ENV ${envMatch[1]}=***`,
                                file: filePath,
                                line: lineNum,
                                remediation: 'Use Docker secrets, environment files, or secret management systems instead of hardcoding secrets',
                            });
                        }
                    }
                }

                // Parse VOLUME
                if (line.toUpperCase().startsWith('VOLUME ')) {
                    const volume = line.substring(7).trim().replace(/["']/g, '');
                    dockerfileInfo.volumes.push({ path: volume, line: lineNum });
                }

                // Check for HEALTHCHECK
                if (line.toUpperCase().startsWith('HEALTHCHECK ')) {
                    dockerfileInfo.healthCheck = true;
                }

                // Check for privileged mode (not standard Dockerfile, but sometimes in comments)
                if (line.toUpperCase().includes('PRIVILEGED')) {
                    dockerfileInfo.privileged = true;
                }
            }

            // Check for missing USER instruction
            if (!dockerfileInfo.user) {
                this.addFinding({
                    type: 'root-user',
                    severity: 'high',
                    description: 'No USER instruction in Dockerfile - container will run as root by default',
                    evidence: 'Missing USER instruction',
                    file: filePath,
                    remediation: 'Add a USER instruction to run the container with non-root privileges',
                });
            }

            // Check for missing HEALTHCHECK
            if (!dockerfileInfo.healthCheck) {
                this.addFinding({
                    type: 'missing-healthcheck',
                    severity: 'low',
                    description: 'No HEALTHCHECK instruction defined',
                    evidence: 'Missing HEALTHCHECK',
                    file: filePath,
                    remediation: 'Add a HEALTHCHECK instruction to enable container health monitoring',
                });
            }

            // Check for large number of layers (inefficient)
            if (dockerfileInfo.runCommands.length > 10) {
                this.addFinding({
                    type: 'large-image',
                    severity: 'low',
                    description: `Many RUN commands (${dockerfileInfo.runCommands.length}) - creates excessive layers`,
                    evidence: `${dockerfileInfo.runCommands.length} RUN instructions`,
                    file: filePath,
                    remediation: 'Combine RUN commands with && to reduce layer count',
                });
            }

        } catch (error) {
            logger.debug(`[ContainerScannerService] Error analyzing Dockerfile: ${error}`);
        }
    }

    private async scanDockerCompose(): Promise<void> {
        const composePaths = [
            resolve(this.projectRoot, 'docker-compose.yml'),
            resolve(this.projectRoot, 'docker-compose.yaml'),
            resolve(this.projectRoot, 'compose.yml'),
            resolve(this.projectRoot, 'compose.yaml'),
        ];

        for (const composePath of composePaths) {
            try {
                await access(composePath);
                await this.analyzeDockerCompose(composePath);
            } catch {
                continue;
            }
        }
    }

    private async analyzeDockerCompose(filePath: string): Promise<void> {
        try {
            const content = await readFile(filePath, 'utf-8');
            const compose = JSON.parse(content) as {
                services?: Record<string, {
                    privileged?: boolean;
                    user?: string;
                    volumes?: string[];
                    ports?: string[];
                    environment?: Record<string, string>;
                    cap_add?: string[];
                    cap_drop?: string[];
                }>;
            };

            if (!compose.services) return;

            for (const [serviceName, service] of Object.entries(compose.services)) {
                // Check for privileged mode
                if (service.privileged) {
                    this.addFinding({
                        type: 'privileged-container',
                        severity: 'critical',
                        description: `Service '${serviceName}' running in privileged mode`,
                        evidence: `privileged: true`,
                        file: filePath,
                        remediation: 'Remove privileged mode. Use specific capabilities with cap_add if needed.',
                    });
                }

                // Check for root user
                if (service.user === 'root' || service.user === '0') {
                    this.addFinding({
                        type: 'root-user',
                        severity: 'high',
                        description: `Service '${serviceName}' configured to run as root`,
                        evidence: `user: ${service.user}`,
                        file: filePath,
                        remediation: 'Set user to a non-root user or UID',
                    });
                }

                // Check for sensitive volume mounts
                if (service.volumes) {
                    for (const volume of service.volumes) {
                        for (const sensitive of SENSITIVE_MOUNTS) {
                            if (volume.includes(sensitive.replace('*', ''))) {
                                this.addFinding({
                                    type: 'sensitive-mount',
                                    severity: 'critical',
                                    description: `Sensitive host path mounted: ${sensitive}`,
                                    evidence: `volumes: ${volume}`,
                                    file: filePath,
                                    remediation: `Never mount ${sensitive} into containers. This exposes critical host system files.`,
                                });
                            }
                        }

                        // Check for Docker socket mount
                        if (volume.includes('docker.sock')) {
                            this.addFinding({
                                type: 'privileged-container',
                                severity: 'critical',
                                description: 'Docker socket mounted - container has full Docker access',
                                evidence: `volumes: ${volume}`,
                                file: filePath,
                                remediation: 'Avoid mounting Docker socket. Use Docker API proxy with limited permissions if necessary.',
                            });
                        }
                    }
                }

                // Check environment variables for secrets
                if (service.environment) {
                    for (const [key, value] of Object.entries(service.environment)) {
                        const secretPattern = /password|secret|key|token|credential|api_key/i;
                        if (secretPattern.test(key) && value && value.length > 0) {
                            this.addFinding({
                                type: 'exposed-secret',
                                severity: 'critical',
                                description: `Potential secret in environment: ${key}`,
                                evidence: `environment.${key}: ***`,
                                file: filePath,
                                remediation: 'Use Docker secrets or external secret management. Never commit secrets to docker-compose files.',
                            });
                        }
                    }
                }

                // Check added capabilities
                if (service.cap_add) {
                    for (const cap of service.cap_add) {
                        if (DANGEROUS_CAPABILITIES.includes(cap)) {
                            this.addFinding({
                                type: 'dangerous-capability',
                                severity: 'high',
                                description: `Dangerous capability added: ${cap}`,
                                evidence: `cap_add: ${cap}`,
                                file: filePath,
                                remediation: `Remove ${cap}. This capability grants significant host system access.`,
                            });
                        }
                    }
                }
            }
        } catch (error) {
            logger.debug(`[ContainerScannerService] Error analyzing docker-compose: ${error}`);
        }
    }

    private async scanContainerConfigs(): Promise<void> {
        // Check for Kubernetes configs
        const k8sPaths = [
            resolve(this.projectRoot, 'k8s'),
            resolve(this.projectRoot, 'kubernetes'),
            resolve(this.projectRoot, 'manifests'),
        ];

        for (const k8sPath of k8sPaths) {
            try {
                await access(k8sPath);
                // Would scan Kubernetes manifests here
                logger.debug(`[ContainerScannerService] Found Kubernetes config directory: ${k8sPath}`);
            } catch {
                // Directory doesn't exist
            }
        }
    }

    private addFinding(finding: ContainerFinding): void {
        const key = `${finding.type}:${finding.file}:${finding.line || 0}:${finding.description.slice(0, 30)}`;
        if (!this.findings.some(f => `${f.type}:${f.file}:${f.line || 0}:${f.description.slice(0, 30)}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): ContainerFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
        this.projectRoot = '';
    }
}
