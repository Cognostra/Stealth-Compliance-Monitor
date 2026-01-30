/**
 * Extension Audit Scanner
 *
 * Service that analyzes Chrome Extension source code for security issues:
 * - Manifest.json permission analysis (overbroad permissions, dangerous APIs)
 * - Content script injection analysis (CSRF risks, DOM pollution)
 * - Background service worker security (event listener patterns)
 * - External messaging validation (postMessage security)
 * - CSP for extensions validation
 * - Storage API security (localStorage vs chrome.storage)
 *
 * This is for extension developers testing their own extensions - NOT a page scanner.
 */

import { readFile } from 'fs/promises';
import { resolve, dirname, join } from 'path';
import { glob } from 'glob';
import { logger } from '../utils/logger.js';

export type ExtensionFindingType =
    | 'overbroad-permission'
    | 'dangerous-api'
    | 'unsafe-eval'
    | 'remote-code'
    | 'insecure-csp'
    | 'missing-csp';

export interface ExtensionFinding {
    type: ExtensionFindingType;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    file: string;
    line?: number;
    remediation?: string;
}

interface ManifestV3 {
    manifest_version: number;
    name: string;
    version: string;
    permissions?: string[];
    optional_permissions?: string[];
    host_permissions?: string[];
    content_scripts?: Array<{
        matches?: string[];
        js?: string[];
        css?: string[];
        run_at?: string;
        all_frames?: boolean;
        match_about_blank?: boolean;
    }>;
    background?: {
        service_worker?: string;
        scripts?: string[];
    };
    action?: {
        default_popup?: string;
    };
    web_accessible_resources?: Array<{
        resources?: string[];
        matches?: string[];
    }>;
    content_security_policy?: {
        extension_pages?: string;
        sandbox?: string;
    } | string;
    externally_connectable?: {
        matches?: string[];
        ids?: string[];
        accepts_tls_channel_id?: boolean;
    };
    oauth2?: Record<string, unknown>;
}

// Dangerous permissions that require careful consideration
const DANGEROUS_PERMISSIONS = [
    {
        permission: '<all_urls>',
        severity: 'critical' as const,
        description: 'Grants access to all URLs including internal chrome:// pages',
        remediation: 'Use specific host_permissions instead of <all_urls>',
    },
    {
        permission: '*://*/*',
        severity: 'high' as const,
        description: 'Broad host permission allows access to any website',
        remediation: 'Specify only required domains in host_permissions',
    },
    {
        permission: 'webRequestBlocking',
        severity: 'high' as const,
        description: 'Blocking webRequest can impact browser performance and security',
        remediation: 'Use declarativeNetRequest instead for blocking/modifying requests',
    },
    {
        permission: 'debugger',
        severity: 'critical' as const,
        description: 'debugger API provides complete control over the browser',
        remediation: 'Only use debugger for development, never in production extensions',
    },
    {
        permission: 'nativeMessaging',
        severity: 'high' as const,
        description: 'Native messaging can communicate with system-level processes',
        remediation: 'Validate all messages from native host and sanitize inputs',
    },
    {
        permission: 'downloads',
        severity: 'medium' as const,
        description: 'Can download and save files to user system',
        remediation: 'Validate download URLs and restrict file types',
    },
    {
        permission: 'cookies',
        severity: 'medium' as const,
        description: 'Access to all cookies including httpOnly',
        remediation: 'Use specific cookie host permissions, avoid accessing sensitive cookies',
    },
    {
        permission: 'bookmarks',
        severity: 'low' as const,
        description: 'Can read and modify user bookmarks',
        remediation: 'Ensure bookmark operations are user-initiated',
    },
    {
        permission: 'history',
        severity: 'medium' as const,
        description: 'Access to full browsing history',
        remediation: 'Minimize history access, clear when not needed',
    },
    {
        permission: 'tabs',
        severity: 'low' as const,
        description: 'Can access tab URLs and content (requires host permissions for sensitive data)',
        remediation: 'Request specific host permissions for sensitive tab data',
    },
    {
        permission: 'storage',
        severity: 'low' as const,
        description: 'Can store data persistently',
        remediation: 'Use chrome.storage.local for sensitive data, not localStorage',
    },
];

// Patterns for dangerous code
const DANGEROUS_PATTERNS = [
    {
        pattern: /eval\s*\(/,
        type: 'unsafe-eval' as ExtensionFindingType,
        severity: 'critical' as const,
        description: 'eval() usage detected',
        remediation: 'Replace eval() with JSON.parse() for data, or use safer alternatives',
    },
    {
        pattern: /new\s+Function\s*\(/,
        type: 'unsafe-eval' as ExtensionFindingType,
        severity: 'critical' as const,
        description: 'Function constructor usage detected',
        remediation: 'Avoid Function constructor, use static functions instead',
    },
    {
        pattern: /setTimeout\s*\(\s*["'`]/,
        type: 'unsafe-eval' as ExtensionFindingType,
        severity: 'high' as const,
        description: 'setTimeout with string argument (implicit eval)',
        remediation: 'Use function reference instead of string in setTimeout/setInterval',
    },
    {
        pattern: /setInterval\s*\(\s*["'`]/,
        type: 'unsafe-eval' as ExtensionFindingType,
        severity: 'high' as const,
        description: 'setInterval with string argument (implicit eval)',
        remediation: 'Use function reference instead of string in setTimeout/setInterval',
    },
    {
        pattern: /innerHTML\s*=|outerHTML\s*=/,
        type: 'dangerous-api' as ExtensionFindingType,
        severity: 'high' as const,
        description: 'innerHTML/outerHTML assignment detected',
        remediation: 'Use textContent or sanitize HTML with a trusted library like DOMPurify',
    },
    {
        pattern: /document\.write\s*\(|document\.writeln\s*\(/,
        type: 'dangerous-api' as ExtensionFindingType,
        severity: 'high' as const,
        description: 'document.write/writeln usage detected',
        remediation: 'Avoid document.write, use DOM manipulation methods instead',
    },
    {
        pattern: /fetch\s*\(\s*["'`][^"'`]*\$\{|\.fetch\s*\(\s*[^"'`]*\+/,
        type: 'dangerous-api' as ExtensionFindingType,
        severity: 'medium' as const,
        description: 'Dynamic URL construction in fetch()',
        remediation: 'Validate and sanitize URLs before fetch(), use URL constructor',
    },
    {
        pattern: /XMLHttpRequest|\.open\s*\(\s*["'`][^"'`]*\$\{/,
        type: 'dangerous-api' as ExtensionFindingType,
        severity: 'medium' as const,
        description: 'XMLHttpRequest with dynamic URL',
        remediation: 'Validate URLs, prefer fetch() API with proper error handling',
    },
    {
        pattern: /chrome\.(?:tabs|windows)\.executeScript/,
        type: 'dangerous-api' as ExtensionFindingType,
        severity: 'high' as const,
        description: 'executeScript API usage detected',
        remediation: 'Avoid executeScript with code strings, use content scripts declared in manifest',
    },
    {
        pattern: /chrome\.devtools/, // Note: this is a broad pattern, specific APIs should be reviewed
        type: 'dangerous-api' as ExtensionFindingType,
        severity: 'medium' as const,
        description: 'DevTools API usage detected',
        remediation: 'Ensure DevTools panels are not exposing sensitive functionality',
    },
];

// Patterns for remote code loading
const REMOTE_CODE_PATTERNS = [
    {
        pattern: /fetch\s*\(\s*["'`][^"'`]*\.js["'`]\s*\)|import\s*\(\s*["'`][^"'`]*["'`]\s*\)/,
        type: 'remote-code' as ExtensionFindingType,
        severity: 'critical' as const,
        description: 'Dynamic script loading detected',
        remediation: 'Never load remote code. Bundle all scripts with the extension',
    },
    {
        pattern: /<script[^>]+src\s*=\s*["'`][^"'`]*https?:\/\//,
        type: 'remote-code' as ExtensionFindingType,
        severity: 'critical' as const,
        description: 'Remote script tag detected',
        remediation: 'Remove external script references. All code must be bundled',
    },
    {
        pattern: /script\.src\s*=\s*["'`][^"'`]*https?:\/\//,
        type: 'remote-code' as ExtensionFindingType,
        severity: 'critical' as const,
        description: 'Dynamic remote script injection detected',
        remediation: 'Never inject remote scripts. All code must be bundled',
    },
    {
        pattern: /importScripts\s*\(\s*["'`][^"'`]*https?:\/\//,
        type: 'remote-code' as ExtensionFindingType,
        severity: 'critical' as const,
        description: 'importScripts with remote URL detected',
        remediation: 'importScripts must use bundled scripts only, never remote URLs',
    },
];

// Patterns for postMessage security issues
const POSTMESSAGE_PATTERNS = [
    {
        pattern: /window\.addEventListener\s*\(\s*["'`]message["'`]/,
        hasOriginCheck: /event\.origin\s*===?|event\.origin\s*!==?|\.origin\s*===?/,
        severity: 'high' as const,
        description: 'postMessage listener without origin validation',
        remediation: 'Always validate event.origin against expected domains',
    },
    {
        pattern: /\.postMessage\s*\(/,
        hasTargetOrigin: /postMessage\s*\([^,]+,\s*["'`][^"'`*]+["'`]/,
        severity: 'medium' as const,
        description: 'postMessage without explicit target origin',
        remediation: 'Always specify target origin, never use "*"',
    },
];

// Patterns for localStorage usage (discouraged in extensions)
const LOCALSTORAGE_PATTERNS = [
    {
        pattern: /localStorage\.|sessionStorage\./,
        severity: 'medium' as const,
        description: 'localStorage/sessionStorage usage detected',
        remediation: 'Use chrome.storage.local or chrome.storage.sync instead for extension data',
    },
];

// CSP patterns for extension validation
const DANGEROUS_CSP_VALUES = [
    { value: "'unsafe-eval'", severity: 'critical' as const, description: 'unsafe-eval allows eval()' },
    { value: "'unsafe-inline'", severity: 'high' as const, description: 'unsafe-inline allows inline scripts' },
    { value: '*', severity: 'critical' as const, description: 'Wildcard allows any source' },
    { value: 'http:', severity: 'high' as const, description: 'http: scheme allows insecure content' },
    { value: 'https://*', severity: 'medium' as const, description: 'Wildcard HTTPS allows any domain' },
    { value: 'data:', severity: 'medium' as const, description: 'data: scheme can be abused' },
    { value: 'blob:', severity: 'medium' as const, description: 'blob: scheme can be abused' },
];

export class ExtensionAuditScanner {
    private findings: ExtensionFinding[] = [];
    private extensionRoot: string = '';

    /**
     * Audit a Chrome Extension by analyzing its manifest and source files.
     */
    async auditExtension(manifestPath: string): Promise<ExtensionFinding[]> {
        this.findings = [];
        this.extensionRoot = dirname(resolve(manifestPath));

        try {
            // Read and parse manifest
            const manifestContent = await readFile(manifestPath, 'utf-8');
            const manifest: ManifestV3 = JSON.parse(manifestContent);

            // Validate manifest version
            if (manifest.manifest_version !== 3) {
                this.addFinding({
                    type: 'dangerous-api',
                    severity: 'high',
                    description: `Extension uses Manifest V${manifest.manifest_version}. V3 is recommended for security.`,
                    evidence: `manifest_version: ${manifest.manifest_version}`,
                    file: manifestPath,
                    remediation: 'Migrate to Manifest V3 for better security controls',
                });
            }

            // Analyze permissions
            this.analyzePermissions(manifest, manifestPath);

            // Analyze CSP
            this.analyzeCsp(manifest, manifestPath);

            // Analyze content scripts
            await this.analyzeContentScripts(manifest);

            // Analyze background service worker
            await this.analyzeBackgroundScript(manifest);

            // Analyze externally_connectable
            this.analyzeExternalMessaging(manifest, manifestPath);

            // Scan all JavaScript files for security patterns
            await this.scanJavaScriptFiles();

            // Scan HTML files for security patterns
            await this.scanHtmlFiles();

            logger.info(`[ExtensionAuditScanner] ${this.findings.length} findings in ${manifest.name || 'extension'}`);
        } catch (error) {
            logger.error(`[ExtensionAuditScanner] Failed to audit extension: ${(error as Error).message}`);
            throw error;
        }

        return [...this.findings];
    }

    /**
     * Analyze manifest permissions for security issues.
     */
    private analyzePermissions(manifest: ManifestV3, manifestPath: string): void {
        const allPermissions = [
            ...(manifest.permissions || []),
            ...(manifest.optional_permissions || []),
            ...(manifest.host_permissions || []),
        ];

        for (const permission of allPermissions) {
            // Check for dangerous permissions
            const dangerous = DANGEROUS_PERMISSIONS.find(
                dp => dp.permission === permission || permission.includes(dp.permission)
            );

            if (dangerous) {
                this.addFinding({
                    type: 'dangerous-api',
                    severity: dangerous.severity,
                    description: `Permission "${permission}": ${dangerous.description}`,
                    evidence: `permissions array contains: ${permission}`,
                    file: manifestPath,
                    remediation: dangerous.remediation,
                });
            }

            // Check for broad host permissions
            if (permission.includes('://*') || permission.includes('://*.') || permission === '<all_urls>') {
                const isAlreadyReported = DANGEROUS_PERMISSIONS.some(dp => dp.permission === permission);
                if (!isAlreadyReported) {
                    this.addFinding({
                        type: 'overbroad-permission',
                        severity: 'high',
                        description: `Broad host permission "${permission}" allows access to multiple domains`,
                        evidence: `host_permissions contains: ${permission}`,
                        file: manifestPath,
                        remediation: 'Specify exact domains needed (e.g., https://example.com/*)',
                    });
                }
            }
        }

        // Check for missing content security policy in manifest
        if (!manifest.content_security_policy) {
            this.addFinding({
                type: 'missing-csp',
                severity: 'medium',
                description: 'No content_security_policy defined in manifest',
                evidence: 'content_security_policy field is missing',
                file: manifestPath,
                remediation: 'Add content_security_policy with restrictive settings',
            });
        }
    }

    /**
     * Analyze Content Security Policy for extension pages.
     */
    private analyzeCsp(manifest: ManifestV3, manifestPath: string): void {
        const csp = manifest.content_security_policy;

        if (!csp) return;

        let policyString: string;

        if (typeof csp === 'string') {
            policyString = csp;
        } else {
            policyString = csp.extension_pages || '';
        }

        if (!policyString) {
            this.addFinding({
                type: 'missing-csp',
                severity: 'high',
                description: 'No CSP policy for extension_pages',
                evidence: 'content_security_policy.extension_pages is empty',
                file: manifestPath,
                remediation: 'Add a restrictive CSP for extension_pages',
            });
            return;
        }

        // Check for dangerous CSP values
        for (const dangerous of DANGEROUS_CSP_VALUES) {
            if (policyString.includes(dangerous.value)) {
                this.addFinding({
                    type: 'insecure-csp',
                    severity: dangerous.severity,
                    description: `CSP contains dangerous value "${dangerous.value}": ${dangerous.description}`,
                    evidence: `content_security_policy: ${policyString}`,
                    file: manifestPath,
                    remediation: `Remove ${dangerous.value} from CSP and use specific allowed sources`,
                });
            }
        }

        // Extension CSP should not allow remote scripts
        if (policyString.includes('http://') || policyString.includes('https://')) {
            const hasRemote = /https?:\/\/[^\s;"']+/.test(policyString);
            if (hasRemote) {
                this.addFinding({
                    type: 'remote-code',
                    severity: 'critical',
                    description: 'CSP allows loading scripts from remote URLs',
                    evidence: `content_security_policy allows remote sources: ${policyString}`,
                    file: manifestPath,
                    remediation: 'Remove all remote URLs from CSP. Extension must be self-contained',
                });
            }
        }
    }

    /**
     * Analyze content scripts for security issues.
     */
    private async analyzeContentScripts(manifest: ManifestV3): Promise<void> {
        if (!manifest.content_scripts || manifest.content_scripts.length === 0) return;

        for (const script of manifest.content_scripts) {
            // Check for overly broad matches
            if (script.matches) {
                for (const match of script.matches) {
                    if (match === '<all_urls>' || match === '*://*/*' || match.includes('://*.')) {
                        this.addFinding({
                            type: 'overbroad-permission',
                            severity: 'high',
                            description: `Content script with broad match pattern "${match}"`,
                            evidence: `content_scripts matches: ${match}`,
                            file: resolve(this.extensionRoot, 'manifest.json'),
                            remediation: 'Use specific match patterns for content scripts',
                        });
                    }
                }
            }

            // Check all_frames and match_about_blank
            if (script.all_frames) {
                this.addFinding({
                    type: 'dangerous-api',
                    severity: 'medium',
                    description: 'Content script runs in all_frames including iframes',
                    evidence: 'content_scripts.all_frames: true',
                    file: resolve(this.extensionRoot, 'manifest.json'),
                    remediation: 'Set all_frames: false unless specifically required, validate frame URLs',
                });
            }

            if (script.match_about_blank) {
                this.addFinding({
                    type: 'dangerous-api',
                    severity: 'high',
                    description: 'Content script runs in about:blank pages',
                    evidence: 'content_scripts.match_about_blank: true',
                    file: resolve(this.extensionRoot, 'manifest.json'),
                    remediation: 'Avoid match_about_blank unless required. Validate page context carefully',
                });
            }

            // Analyze the actual content script files
            if (script.js) {
                for (const jsFile of script.js) {
                    const filePath = resolve(this.extensionRoot, jsFile);
                    await this.scanFileForPatterns(filePath, [...DANGEROUS_PATTERNS, ...REMOTE_CODE_PATTERNS]);
                    await this.scanFileForPostMessage(filePath);
                    await this.scanFileForStorage(filePath);
                }
            }
        }
    }

    /**
     * Analyze background service worker for security issues.
     */
    private async analyzeBackgroundScript(manifest: ManifestV3): Promise<void> {
        const backgroundScript = manifest.background?.service_worker || manifest.background?.scripts?.[0];

        if (!backgroundScript) return;

        const filePath = resolve(this.extensionRoot, backgroundScript);

        // Check for common security issues in service worker
        await this.scanFileForPatterns(filePath, DANGEROUS_PATTERNS);
        await this.scanFileForRemoteCode(filePath);

        // Service workers should validate message sources
        try {
            const content = await readFile(filePath, 'utf-8');

            if (content.includes('chrome.runtime.onMessage')) {
                const hasSenderCheck = /sender\.(id|url|origin)/.test(content) || /sender\.tab/.test(content);
                if (!hasSenderCheck) {
                    this.addFinding({
                        type: 'dangerous-api',
                        severity: 'medium',
                        description: 'Background script handles messages without validating sender',
                        evidence: 'chrome.runtime.onMessage listener without sender validation',
                        file: filePath,
                        remediation: 'Always validate message sender before processing',
                    });
                }
            }

            if (content.includes('chrome.runtime.onConnect')) {
                const hasPortValidation = /port\.(sender|name)/.test(content);
                if (!hasPortValidation) {
                    this.addFinding({
                        type: 'dangerous-api',
                        severity: 'medium',
                        description: 'Background script handles port connections without validation',
                        evidence: 'chrome.runtime.onConnect listener without port validation',
                        file: filePath,
                        remediation: 'Validate port.sender before processing messages',
                    });
                }
            }
        } catch {
            // File might not exist
        }
    }

    /**
     * Analyze external messaging configuration.
     */
    private analyzeExternalMessaging(manifest: ManifestV3, manifestPath: string): void {
        const external = manifest.externally_connectable;

        if (!external) return;

        // Check for overly broad external connections
        if (external.matches) {
            for (const match of external.matches) {
                if (match === '<all_urls>' || match === '*://*/*' || match.includes('*://*.')) {
                    this.addFinding({
                        type: 'overbroad-permission',
                        severity: 'critical',
                        description: `externally_connectable allows any website to send messages: "${match}"`,
                        evidence: `externally_connectable.matches: ${match}`,
                        file: manifestPath,
                        remediation: 'Specify exact domains in externally_connectable.matches',
                    });
                }
            }
        }

        // Check for all IDs allowed
        if (external.ids && external.ids.includes('*')) {
            this.addFinding({
                type: 'overbroad-permission',
                severity: 'critical',
                description: 'externally_connectable allows any extension to connect',
                evidence: 'externally_connectable.ids contains "*"',
                file: manifestPath,
                remediation: 'Specify exact extension IDs, never use "*"',
            });
        }
    }

    /**
     * Scan all JavaScript files in the extension.
     */
    private async scanJavaScriptFiles(): Promise<void> {
        try {
            const jsFiles = await glob('**/*.js', {
                cwd: this.extensionRoot,
                absolute: true,
                ignore: ['node_modules/**', 'test*/**', '*test*.js'],
            });

            for (const file of jsFiles) {
                await this.scanFileForPatterns(file, DANGEROUS_PATTERNS);
                await this.scanFileForRemoteCode(file);
                await this.scanFileForPostMessage(file);
                await this.scanFileForStorage(file);
            }
        } catch (error) {
            logger.debug(`[ExtensionAuditScanner] Error scanning JS files: ${(error as Error).message}`);
        }
    }

    /**
     * Scan HTML files for security issues.
     */
    private async scanHtmlFiles(): Promise<void> {
        try {
            const htmlFiles = await glob('**/*.html', {
                cwd: this.extensionRoot,
                absolute: true,
                ignore: ['node_modules/**'],
            });

            for (const file of htmlFiles) {
                const content = await readFile(file, 'utf-8');

                // Check for inline scripts (should be minimized in extensions)
                const inlineScriptMatches = content.match(/<script[^>]*>([^]*?)<\/script>/gi);
                if (inlineScriptMatches) {
                    for (const script of inlineScriptMatches) {
                        if (!script.includes('src=')) {
                            this.addFinding({
                                type: 'dangerous-api',
                                severity: 'low',
                                description: 'Inline script detected in HTML',
                                evidence: `Inline script in ${file}`,
                                file,
                                remediation: 'Move JavaScript to external .js files for better CSP compatibility',
                            });
                        }
                    }
                }

                // Check for remote scripts
                for (const pattern of REMOTE_CODE_PATTERNS) {
                    if (pattern.pattern.test(content)) {
                        this.addFinding({
                            type: pattern.type,
                            severity: pattern.severity,
                            description: pattern.description,
                            evidence: `Remote code pattern found in HTML: ${content.match(pattern.pattern)?.[0]?.slice(0, 100)}`,
                            file,
                            remediation: pattern.remediation,
                        });
                    }
                }
            }
        } catch (error) {
            logger.debug(`[ExtensionAuditScanner] Error scanning HTML files: ${(error as Error).message}`);
        }
    }

    /**
     * Scan a file for security pattern matches.
     */
    private async scanFileForPatterns(
        filePath: string,
        patterns: typeof DANGEROUS_PATTERNS
    ): Promise<void> {
        try {
            const content = await readFile(filePath, 'utf-8');
            const lines = content.split('\n');

            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];

                for (const pattern of patterns) {
                    if (pattern.pattern.test(line)) {
                        // Check if it's in a comment
                        const isComment = /(^\s*\/\/|^\s*\/\*|^\s*\*)/.test(line);
                        if (isComment) continue;

                        this.addFinding({
                            type: pattern.type,
                            severity: pattern.severity,
                            description: pattern.description,
                            evidence: line.trim().slice(0, 150),
                            file: filePath,
                            line: i + 1,
                            remediation: pattern.remediation,
                        });
                    }
                }
            }
        } catch {
            // File might not exist or be readable
        }
    }

    /**
     * Scan for remote code loading patterns specifically.
     */
    private async scanFileForRemoteCode(filePath: string): Promise<void> {
        try {
            const content = await readFile(filePath, 'utf-8');
            const lines = content.split('\n');

            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];

                for (const pattern of REMOTE_CODE_PATTERNS) {
                    if (pattern.pattern.test(line)) {
                        const isComment = /(^\s*\/\/|^\s*\/\*|^\s*\*)/.test(line);
                        if (isComment) continue;

                        this.addFinding({
                            type: pattern.type,
                            severity: pattern.severity,
                            description: pattern.description,
                            evidence: line.trim().slice(0, 150),
                            file: filePath,
                            line: i + 1,
                            remediation: pattern.remediation,
                        });
                    }
                }
            }
        } catch {
            // File might not exist
        }
    }

    /**
     * Scan for postMessage security issues.
     */
    private async scanFileForPostMessage(filePath: string): Promise<void> {
        try {
            const content = await readFile(filePath, 'utf-8');

            for (const pattern of POSTMESSAGE_PATTERNS) {
                if (pattern.pattern.test(content)) {
                    let hasProperCheck = false;

                    if (pattern.hasOriginCheck) {
                        hasProperCheck = pattern.hasOriginCheck.test(content);
                    }

                    if (pattern.hasTargetOrigin) {
                        hasProperCheck = pattern.hasTargetOrigin.test(content);
                    }

                    if (!hasProperCheck) {
                        this.addFinding({
                            type: 'dangerous-api',
                            severity: pattern.severity,
                            description: pattern.description,
                            evidence: `postMessage usage without proper validation`,
                            file: filePath,
                            remediation: pattern.remediation,
                        });
                    }
                }
            }
        } catch {
            // File might not exist
        }
    }

    /**
     * Scan for localStorage usage (discouraged in extensions).
     */
    private async scanFileForStorage(filePath: string): Promise<void> {
        try {
            const content = await readFile(filePath, 'utf-8');
            const lines = content.split('\n');

            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];

                for (const pattern of LOCALSTORAGE_PATTERNS) {
                    if (pattern.pattern.test(line)) {
                        const isComment = /(^\s*\/\/|^\s*\/\*|^\s*\*)/.test(line);
                        if (isComment) continue;

                        this.addFinding({
                            type: 'dangerous-api',
                            severity: pattern.severity,
                            description: pattern.description,
                            evidence: line.trim().slice(0, 150),
                            file: filePath,
                            line: i + 1,
                            remediation: pattern.remediation,
                        });
                    }
                }
            }
        } catch {
            // File might not exist
        }
    }

    private addFinding(finding: ExtensionFinding): void {
        // Deduplicate based on type, file, and description
        const key = `${finding.type}:${finding.file}:${finding.description.slice(0, 50)}:${finding.line || ''}`;
        if (!this.findings.some(f => `${f.type}:${f.file}:${f.description.slice(0, 50)}:${f.line || ''}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): ExtensionFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
    }
}
