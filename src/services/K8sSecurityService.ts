/**
 * Kubernetes Security Service
 *
 * Service that audits Kubernetes manifests and configurations:
 * - Pod Security Standards compliance
 * - RBAC configuration analysis
 * - Network Policy validation
 * - Secret management auditing
 * - Container security context verification
 * - Resource limit verification
 */

import { readFile, access, readdir } from 'fs/promises';
import { resolve, join } from 'path';
import { logger } from '../utils/logger.js';

export interface K8sFinding {
    type: 'privileged-pod' | 'root-container' | 'missing-security-context' | 'host-namespace' | 'sensitive-mount' | 'no-resource-limits' | 'exposed-secret' | 'rbac-escalation' | 'missing-network-policy' | 'insecure-capability';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    file: string;
    resource?: string;
    namespace?: string;
    remediation?: string;
}

interface K8sResource {
    apiVersion: string;
    kind: string;
    metadata: {
        name: string;
        namespace?: string;
    };
    spec?: Record<string, unknown>;
    data?: Record<string, string>;
    rules?: unknown[];
    subjects?: unknown[];
    roleRef?: Record<string, string>;
}

// Dangerous security context settings
const DANGEROUS_SETTINGS = {
    privileged: 'Container running in privileged mode',
    runAsRoot: 'Container configured to run as root (UID 0)',
    hostPID: 'Pod sharing host PID namespace',
    hostNetwork: 'Pod using host network namespace',
    hostIPC: 'Pod sharing host IPC namespace',
    allowPrivilegeEscalation: 'Privilege escalation allowed',
    readOnlyRootFilesystem: 'Root filesystem not read-only',
    runAsNonRoot: 'Container not required to run as non-root',
};

// Sensitive host paths
const SENSITIVE_HOST_PATHS = [
    '/etc/kubernetes',
    '/var/run/docker.sock',
    '/var/run/containerd.sock',
    '/root/.ssh',
    '/etc/shadow',
    '/etc/passwd',
    '/proc',
    '/sys',
    '/',
    '/etc',
    '/var',
];

// Dangerous capabilities
const DANGEROUS_CAPABILITIES = [
    'SYS_ADMIN',
    'SYS_PTRACE',
    'SYS_MODULE',
    'DAC_READ_SEARCH',
    'DAC_OVERRIDE',
    'SYS_RAWIO',
    'SYSLOG',
    'NET_ADMIN',
    'NET_RAW',
    'ALL',
];

export class K8sSecurityService {
    private findings: K8sFinding[] = [];
    private manifestsDir: string = '';
    private foundResources: Map<string, K8sResource[]> = new Map();

    /**
     * Scan Kubernetes manifests in a directory
     */
    async scanManifests(manifestsPath: string): Promise<K8sFinding[]> {
        this.findings = [];
        this.manifestsDir = manifestsPath;
        this.foundResources.clear();

        try {
            // Verify directory exists
            await access(manifestsPath);

            // Find all YAML files
            const files = await this.findYamlFiles(manifestsPath);

            for (const file of files) {
                await this.analyzeManifest(file);
            }

            // Cross-reference resources
            this.crossReferenceResources();

            logger.info(`[K8sSecurityService] ${this.findings.length} K8s findings in ${files.length} manifest files`);
        } catch (error) {
            logger.error(`[K8sSecurityService] Error scanning manifests: ${(error as Error).message}`);
        }

        return [...this.findings];
    }

    private async findYamlFiles(dir: string): Promise<string[]> {
        const yamlFiles: string[] = [];

        try {
            const entries = await readdir(dir, { withFileTypes: true });

            for (const entry of entries) {
                const fullPath = join(dir, entry.name);

                if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
                    const subFiles = await this.findYamlFiles(fullPath);
                    yamlFiles.push(...subFiles);
                } else if (entry.isFile() && (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml'))) {
                    yamlFiles.push(fullPath);
                }
            }
        } catch (error) {
            logger.debug(`[K8sSecurityService] Error reading directory ${dir}: ${error}`);
        }

        return yamlFiles;
    }

    private async analyzeManifest(filePath: string): Promise<void> {
        try {
            const content = await readFile(filePath, 'utf-8');
            
            // Split multi-document YAML
            const documents = content.split(/^---\s*$/m);

            for (const doc of documents) {
                if (!doc.trim()) continue;

                try {
                    const resource = this.parseYaml(doc) as K8sResource;
                    if (!resource || !resource.kind) continue;

                    // Store resource for cross-referencing
                    const kind = resource.kind;
                    if (!this.foundResources.has(kind)) {
                        this.foundResources.set(kind, []);
                    }
                    this.foundResources.get(kind)?.push(resource);

                    // Analyze based on resource type
                    switch (resource.kind) {
                        case 'Pod':
                            await this.analyzePod(resource, filePath);
                            break;
                        case 'Deployment':
                        case 'StatefulSet':
                        case 'DaemonSet':
                        case 'ReplicaSet':
                        case 'Job':
                        case 'CronJob':
                            await this.analyzeWorkload(resource, filePath);
                            break;
                        case 'Secret':
                            await this.analyzeSecret(resource, filePath);
                            break;
                        case 'ServiceAccount':
                            await this.analyzeServiceAccount(resource, filePath);
                            break;
                        case 'Role':
                        case 'ClusterRole':
                            await this.analyzeRole(resource, filePath);
                            break;
                        case 'RoleBinding':
                        case 'ClusterRoleBinding':
                            await this.analyzeRoleBinding(resource, filePath);
                            break;
                        case 'NetworkPolicy':
                            await this.analyzeNetworkPolicy(resource, filePath);
                            break;
                        case 'PodSecurityPolicy':
                            await this.analyzePodSecurityPolicy(resource, filePath);
                            break;
                    }
                } catch (parseError) {
                    logger.debug(`[K8sSecurityService] Error parsing YAML in ${filePath}: ${parseError}`);
                }
            }
        } catch (error) {
            logger.debug(`[K8sSecurityService] Error reading manifest ${filePath}: ${error}`);
        }
    }

    private parseYaml(content: string): unknown {
        // Simple YAML parser for basic structures
        // In production, use a proper YAML parser like js-yaml
        const lines = content.split('\n');
        const result: Record<string, unknown> = {};
        let currentKey: string | null = null;
        let currentObj: Record<string, unknown> = result;
        const stack: Array<{ key: string; obj: Record<string, unknown> }> = [];

        for (const line of lines) {
            if (!line.trim() || line.trim().startsWith('#')) continue;

            const indent = line.search(/\S/);
            const trimmedLine = line.trim();

            // Parse key-value pairs
            const match = trimmedLine.match(/^([^:]+):\s*(.*)$/);
            if (match) {
                const key = match[1].trim();
                const value = match[2].trim();

                // Handle indentation
                while (stack.length > 0 && stack[stack.length - 1].obj !== currentObj && indent <= 0) {
                    const popped = stack.pop();
                    if (popped) {
                        currentObj = popped.obj;
                    }
                }

                if (value) {
                    // Try to parse as number or boolean
                    if (value === 'true') {
                        currentObj[key] = true;
                    } else if (value === 'false') {
                        currentObj[key] = false;
                    } else if (/^\d+$/.test(value)) {
                        currentObj[key] = parseInt(value, 10);
                    } else if (value.startsWith('[') && value.endsWith(']')) {
                        // Simple array parsing
                        currentObj[key] = value.slice(1, -1).split(',').map(s => s.trim().replace(/["']/g, ''));
                    } else {
                        currentObj[key] = value.replace(/["']/g, '');
                    }
                } else {
                    // Nested object
                    currentObj[key] = {};
                    stack.push({ key, obj: currentObj });
                    currentObj = currentObj[key] as Record<string, unknown>;
                }
            }
        }

        return result;
    }

    private async analyzePod(resource: K8sResource, filePath: string): Promise<void> {
        const spec = resource.spec || {};
        const metadata = resource.metadata || {};

        // Check host namespaces
        if (spec.hostPID) {
            this.addFinding({
                type: 'host-namespace',
                severity: 'critical',
                description: 'Pod sharing host PID namespace - complete process visibility',
                evidence: 'hostPID: true',
                file: filePath,
                resource: metadata.name,
                namespace: metadata.namespace,
                remediation: 'Remove hostPID. Use process namespace isolation.',
            });
        }

        if (spec.hostNetwork) {
            this.addFinding({
                type: 'host-namespace',
                severity: 'high',
                description: 'Pod using host network namespace',
                evidence: 'hostNetwork: true',
                file: filePath,
                resource: metadata.name,
                namespace: metadata.namespace,
                remediation: 'Remove hostNetwork. Use pod networking with proper NetworkPolicies.',
            });
        }

        if (spec.hostIPC) {
            this.addFinding({
                type: 'host-namespace',
                severity: 'high',
                description: 'Pod sharing host IPC namespace',
                evidence: 'hostIPC: true',
                file: filePath,
                resource: metadata.name,
                namespace: metadata.namespace,
                remediation: 'Remove hostIPC. Isolate inter-process communication.',
            });
        }

        // Analyze containers
        const containers = [
            ...((spec.containers || []) as Array<Record<string, unknown>>),
            ...((spec.initContainers || []) as Array<Record<string, unknown>>),
        ];

        for (const container of containers) {
            await this.analyzeContainer(container, resource, filePath);
        }

        // Check for volumes
        const volumes = spec.volumes as Array<Record<string, unknown>> || [];
        for (const volume of volumes) {
            if (volume.hostPath) {
                const hostPath = (volume.hostPath as Record<string, string>).path || '';
                
                for (const sensitive of SENSITIVE_HOST_PATHS) {
                    if (hostPath === sensitive || hostPath.startsWith(sensitive + '/')) {
                        this.addFinding({
                            type: 'sensitive-mount',
                            severity: 'critical',
                            description: `Sensitive host path mounted: ${hostPath}`,
                            evidence: `hostPath: ${hostPath}`,
                            file: filePath,
                            resource: metadata.name,
                            namespace: metadata.namespace,
                            remediation: `Never mount ${hostPath}. Use more specific paths or emptyDir volumes.`,
                        });
                    }
                }
            }
        }
    }

    private async analyzeWorkload(resource: K8sResource, filePath: string): Promise<void> {
        const spec = resource.spec || {};
        const template = (spec.template || {}) as Record<string, unknown>;
        const templateSpec = (template.spec || {}) as Record<string, unknown>;

        // Create synthetic pod resource for analysis
        const podResource: K8sResource = {
            apiVersion: 'v1',
            kind: 'Pod',
            metadata: {
                name: `${resource.metadata.name}-pod`,
                namespace: resource.metadata.namespace,
            },
            spec: templateSpec,
        };

        await this.analyzePod(podResource, filePath);

        // Check resource limits
        const containers = templateSpec.containers as Array<Record<string, unknown>> || [];
        
        for (const container of containers) {
            const resources = container.resources as Record<string, unknown> || {};
            const limits = resources.limits as Record<string, string> || {};
            
            if (!limits.cpu && !limits.memory) {
                this.addFinding({
                    type: 'no-resource-limits',
                    severity: 'medium',
                    description: `Container '${container.name}' has no resource limits defined`,
                    evidence: 'No resources.limits.cpu or resources.limits.memory',
                    file: filePath,
                    resource: resource.metadata.name,
                    namespace: resource.metadata.namespace,
                    remediation: 'Add resource limits to prevent resource exhaustion attacks',
                });
            }
        }
    }

    private async analyzeContainer(container: Record<string, unknown>, resource: K8sResource, filePath: string): Promise<void> {
        const securityContext = container.securityContext as Record<string, unknown> || {};
        const podSpec = resource.spec || {};
        const podSecurityContext = podSpec.securityContext as Record<string, unknown> || {};

        // Check privileged mode
        if (securityContext.privileged === true) {
            this.addFinding({
                type: 'privileged-pod',
                severity: 'critical',
                description: `Container '${container.name}' running in privileged mode`,
                evidence: 'securityContext.privileged: true',
                file: filePath,
                resource: resource.metadata.name,
                namespace: resource.metadata.namespace,
                remediation: 'Remove privileged mode. Use specific capabilities with capabilities.add if needed.',
            });
        }

        // Check for root user
        const runAsUser = securityContext.runAsUser || podSecurityContext.runAsUser;
        if (runAsUser === 0 || securityContext.runAsRoot === true) {
            this.addFinding({
                type: 'root-container',
                severity: 'high',
                description: `Container '${container.name}' configured to run as root`,
                evidence: `runAsUser: ${runAsUser}, runAsRoot: ${securityContext.runAsRoot}`,
                file: filePath,
                resource: resource.metadata.name,
                namespace: resource.metadata.namespace,
                remediation: 'Set securityContext.runAsNonRoot: true and specify a non-zero runAsUser.',
            });
        }

        // Check for missing security context
        if (!container.securityContext && !podSpec.securityContext) {
            this.addFinding({
                type: 'missing-security-context',
                severity: 'medium',
                description: `Container '${container.name}' has no security context defined`,
                evidence: 'Missing securityContext',
                file: filePath,
                resource: resource.metadata.name,
                namespace: resource.metadata.namespace,
                remediation: 'Add securityContext with allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, and runAsNonRoot: true',
            });
        }

        // Check for privilege escalation
        if (securityContext.allowPrivilegeEscalation !== false && !securityContext.privileged) {
            this.addFinding({
                type: 'missing-security-context',
                severity: 'high',
                description: `Container '${container.name}' allows privilege escalation`,
                evidence: 'allowPrivilegeEscalation not set to false',
                file: filePath,
                resource: resource.metadata.name,
                namespace: resource.metadata.namespace,
                remediation: 'Set securityContext.allowPrivilegeEscalation: false',
            });
        }

        // Check capabilities
        const capabilities = securityContext.capabilities as Record<string, string[]> || {};
        const addedCaps = capabilities.add || [];

        for (const cap of addedCaps) {
            if (DANGEROUS_CAPABILITIES.includes(cap)) {
                this.addFinding({
                    type: 'insecure-capability',
                    severity: 'high',
                    description: `Dangerous capability added: ${cap}`,
                    evidence: `capabilities.add: [${cap}]`,
                    file: filePath,
                    resource: resource.metadata.name,
                    namespace: resource.metadata.namespace,
                    remediation: `Remove ${cap}. This grants significant host system access.`,
                });
            }
        }

        // Check read-only root filesystem
        if (securityContext.readOnlyRootFilesystem !== true) {
            this.addFinding({
                type: 'missing-security-context',
                severity: 'medium',
                description: `Container '${container.name}' root filesystem is not read-only`,
                evidence: 'readOnlyRootFilesystem not set to true',
                file: filePath,
                resource: resource.metadata.name,
                namespace: resource.metadata.namespace,
                remediation: 'Set securityContext.readOnlyRootFilesystem: true. Use volumes for writable directories.',
            });
        }
    }

    private async analyzeSecret(resource: K8sResource, filePath: string): Promise<void> {
        const metadata = resource.metadata || {};
        const data = resource.data || {};

        // Check for unencrypted sensitive data
        for (const [key, value] of Object.entries(data)) {
            const decodedValue = Buffer.from(value, 'base64').toString();
            
            if (decodedValue.length > 0 && decodedValue.length < 8) {
                this.addFinding({
                    type: 'exposed-secret',
                    severity: 'medium',
                    description: `Secret '${key}' may have a weak value`,
                    evidence: `Secret key: ${key}`,
                    file: filePath,
                    resource: metadata.name,
                    namespace: metadata.namespace,
                    remediation: 'Ensure secrets are strong and properly managed. Consider using external secret management.',
                });
            }
        }

        // Check for secrets in default namespace
        if (!metadata.namespace || metadata.namespace === 'default') {
            this.addFinding({
                type: 'exposed-secret',
                severity: 'low',
                description: 'Secret stored in default namespace',
                evidence: 'namespace: default',
                file: filePath,
                resource: metadata.name,
                namespace: 'default',
                remediation: 'Use dedicated namespaces for secrets and applications.',
            });
        }
    }

    private async analyzeServiceAccount(resource: K8sResource, filePath: string): Promise<void> {
        // Check for automountServiceAccountToken
        // Would need full YAML parsing for this
    }

    private async analyzeRole(resource: K8sResource, filePath: string): Promise<void> {
        const rules = resource.rules || [];

        for (const rule of rules) {
            const ruleObj = rule as Record<string, unknown>;
            const verbs = ruleObj.verbs as string[] || [];
            const resources = ruleObj.resources as string[] || [];

            // Check for wildcards
            if (verbs.includes('*') && resources.includes('*')) {
                this.addFinding({
                    type: 'rbac-escalation',
                    severity: 'critical',
                    description: 'Role grants wildcard permissions on all resources',
                    evidence: 'verbs: ["*"], resources: ["*"]',
                    file: filePath,
                    resource: resource.metadata.name,
                    remediation: 'Use least-privilege principle. Specify exact verbs and resources needed.',
                });
            }

            // Check for dangerous verbs on sensitive resources
            if (resources.some(r => ['secrets', 'pods', 'serviceaccounts'].includes(r))) {
                if (verbs.some(v => ['create', 'delete', 'update', 'patch'].includes(v))) {
                    this.addFinding({
                        type: 'rbac-escalation',
                        severity: 'high',
                        description: `Role allows modifying sensitive resources: ${resources.join(', ')}`,
                        evidence: `resources: ${JSON.stringify(resources)}, verbs: ${JSON.stringify(verbs)}`,
                        file: filePath,
                        resource: resource.metadata.name,
                        remediation: 'Limit write access to sensitive resources. Use read-only access where possible.',
                    });
                }
            }
        }
    }

    private async analyzeRoleBinding(resource: K8sResource, filePath: string): Promise<void> {
        const subjects = resource.subjects || [];
        const roleRef = resource.roleRef || {};

        // Check for binding to cluster-admin
        if (roleRef.name === 'cluster-admin') {
            this.addFinding({
                type: 'rbac-escalation',
                severity: 'critical',
                description: 'RoleBinding references cluster-admin role',
                evidence: 'roleRef.name: cluster-admin',
                file: filePath,
                resource: resource.metadata.name,
                remediation: 'Never bind to cluster-admin. Create custom roles with minimal permissions.',
            });
        }

        // Check for service account bindings
        for (const subject of subjects) {
            const subj = subject as Record<string, string>;
            if (subj.kind === 'ServiceAccount' && subj.name === 'default') {
                this.addFinding({
                    type: 'rbac-escalation',
                    severity: 'high',
                    description: 'RoleBinding to default service account',
                    evidence: 'subject: { kind: ServiceAccount, name: default }',
                    file: filePath,
                    resource: resource.metadata.name,
                    remediation: 'Create dedicated service accounts for each application.',
                });
            }
        }
    }

    private async analyzeNetworkPolicy(resource: K8sResource, filePath: string): Promise<void> {
        // Network policies are good - we'd check for overly permissive ones here
        // But having a NetworkPolicy is generally positive
    }

    private async analyzePodSecurityPolicy(resource: K8sResource, filePath: string): Promise<void> {
        const spec = resource.spec || {};

        // Check for overly permissive PSP
        if (spec.privileged === true) {
            this.addFinding({
                type: 'privileged-pod',
                severity: 'critical',
                description: 'PodSecurityPolicy allows privileged containers',
                evidence: 'privileged: true',
                file: filePath,
                resource: resource.metadata.name,
                remediation: 'Set privileged: false. Use specific security contexts.',
            });
        }

        if (spec.allowPrivilegeEscalation !== false) {
            this.addFinding({
                type: 'missing-security-context',
                severity: 'high',
                description: 'PodSecurityPolicy allows privilege escalation',
                evidence: 'allowPrivilegeEscalation not false',
                file: filePath,
                resource: resource.metadata.name,
                remediation: 'Set allowPrivilegeEscalation: false',
            });
        }
    }

    private crossReferenceResources(): void {
        // Check for pods without network policies
        const pods = this.foundResources.get('Pod') || [];
        const deployments = this.foundResources.get('Deployment') || [];
        const networkPolicies = this.foundResources.get('NetworkPolicy') || [];

        // If there are workloads but no network policies, flag it
        const allWorkloads = [...pods, ...deployments];
        if (allWorkloads.length > 0 && networkPolicies.length === 0) {
            // This would be an informational finding
            logger.debug(`[K8sSecurityService] Found ${allWorkloads.length} workloads without any NetworkPolicies`);
        }

        // Check for secrets mounted in pods
        // This would require matching secret references to pod volumes
    }

    private addFinding(finding: K8sFinding): void {
        const key = `${finding.type}:${finding.file}:${finding.resource || 'unknown'}:${finding.description.slice(0, 40)}`;
        if (!this.findings.some(f => `${f.type}:${f.file}:${f.resource || 'unknown'}:${f.description.slice(0, 40)}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): K8sFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
        this.manifestsDir = '';
        this.foundResources.clear();
    }
}
