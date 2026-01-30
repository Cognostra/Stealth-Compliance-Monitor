/**
 * SBOM (Software Bill of Materials) Generator
 *
 * IScanner that detects npm packages loaded at runtime by analyzing
 * JavaScript response content for webpack/vite chunk patterns, package
 * version comments, and known global variables.
 *
 * Optionally queries the OSV API for known vulnerabilities.
 */

import type { Page, Request, Response } from 'playwright';
import type { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';
import { safeReadResponseBody, isJavaScriptResponse } from '../utils/response-reader.js';

export interface DetectedPackage {
    name: string;
    version: string;
    source: 'webpack-chunk' | 'vite-chunk' | 'script-comment' | 'global-variable' | 'source-map';
    evidence: string;
    url: string;
}

export interface OsvVulnerability {
    id: string;
    packageName: string;
    severity: string;
    summary: string;
    aliases: string[];
}

export interface SbomReport {
    format: 'cyclonedx' | 'spdx';
    bomFormat: string;
    specVersion: string;
    components: DetectedPackage[];
    vulnerabilities: OsvVulnerability[];
    generatedAt: string;
}

// Known package patterns in bundled JS
const PACKAGE_COMMENT_PATTERN = /\/\*[!*]\s*([a-z@][a-z0-9._\-/@]*)\s+v?([\d]+\.[\d]+\.[\d]+[a-z0-9.\-]*)\s*\*\//gi;
const WEBPACK_MODULE_PATTERN = /\/\*\*\*\/ ["']([a-z@][a-z0-9._\-/@]*)["']/gi;
const VITE_IMPORT_PATTERN = /from\s+["']\/node_modules\/\.vite\/deps\/([a-z@][a-z0-9._\-]*)\.js/gi;
const NPM_CDN_PATTERN = /(?:unpkg\.com|cdn\.jsdelivr\.net\/npm|cdnjs\.cloudflare\.com\/ajax\/libs)\/([a-z@][a-z0-9._\-/@]*)(?:@([\d]+\.[\d]+\.[\d]+[a-z0-9.\-]*))?/gi;

// Known globals to check for version detection
const GLOBAL_VERSION_CHECKS = [
    { name: 'react', global: 'React.version', pattern: /^[\d.]+/ },
    { name: 'react-dom', global: 'ReactDOM.version', pattern: /^[\d.]+/ },
    { name: 'vue', global: 'Vue.version', pattern: /^[\d.]+/ },
    { name: 'angular', global: 'angular.version.full', pattern: /^[\d.]+/ },
    { name: 'jquery', global: 'jQuery.fn.jquery', pattern: /^[\d.]+/ },
    { name: 'lodash', global: '_.VERSION', pattern: /^[\d.]+/ },
    { name: 'moment', global: 'moment.version', pattern: /^[\d.]+/ },
    { name: 'axios', global: 'axios.VERSION', pattern: /^[\d.]+/ },
    { name: 'three', global: 'THREE.REVISION', pattern: /^\d+/ },
    { name: 'd3', global: 'd3.version', pattern: /^[\d.]+/ },
];

export class SbomScanner implements IScanner {
    readonly name = 'SbomScanner';
    private packages: Map<string, DetectedPackage> = new Map();
    private analyzedUrls: Set<string> = new Set();
    private pages: WeakSet<Page> = new WeakSet();

    async onResponse(response: Response): Promise<void> {
        if (!isJavaScriptResponse(response)) return;
        const url = response.url();
        if (this.analyzedUrls.has(url)) return;
        this.analyzedUrls.add(url);

        const body = await safeReadResponseBody(response, 2 * 1024 * 1024);
        if (!body) return;

        this.analyzeScriptContent(body, url);
        this.analyzeScriptUrl(url);
    }

    onPageCreated(page: Page): void {
        if (this.pages.has(page)) return;
        this.pages.add(page);
    }

    /**
     * Run global variable checks on a page after navigation.
     */
    async runPageChecks(page: Page): Promise<DetectedPackage[]> {
        const newPackages: DetectedPackage[] = [];

        for (const check of GLOBAL_VERSION_CHECKS) {
            try {
                const version = await page.evaluate((globalPath: string) => {
                    try {
                        const parts = globalPath.split('.');
                        let obj: unknown = window;
                        for (const part of parts) {
                            obj = (obj as Record<string, unknown>)?.[part];
                        }
                        return typeof obj === 'string' || typeof obj === 'number' ? String(obj) : null;
                    } catch {
                        return null;
                    }
                }, check.global);

                if (version && check.pattern.test(version)) {
                    const pkg = this.addPackage({
                        name: check.name,
                        version,
                        source: 'global-variable',
                        evidence: `${check.global} = "${version}"`,
                        url: page.url(),
                    });
                    if (pkg) newPackages.push(pkg);
                }
            } catch {
                // Page might have navigated away
            }
        }

        return newPackages;
    }

    private analyzeScriptContent(body: string, url: string): void {
        // Package comment headers: /*! package@version */
        let match: RegExpExecArray | null;
        const commentPattern = new RegExp(PACKAGE_COMMENT_PATTERN.source, 'gi');
        while ((match = commentPattern.exec(body)) !== null) {
            this.addPackage({
                name: this.normalizePackageName(match[1]),
                version: match[2],
                source: 'script-comment',
                evidence: match[0].slice(0, 100),
                url,
            });
        }

        // Webpack module identifiers
        const webpackPattern = new RegExp(WEBPACK_MODULE_PATTERN.source, 'gi');
        while ((match = webpackPattern.exec(body)) !== null) {
            const name = this.normalizePackageName(match[1]);
            if (name && !name.startsWith('./') && !name.startsWith('../')) {
                this.addPackage({
                    name,
                    version: 'unknown',
                    source: 'webpack-chunk',
                    evidence: match[0].slice(0, 100),
                    url,
                });
            }
        }

        // Vite import patterns
        const vitePattern = new RegExp(VITE_IMPORT_PATTERN.source, 'gi');
        while ((match = vitePattern.exec(body)) !== null) {
            this.addPackage({
                name: this.normalizePackageName(match[1]),
                version: 'unknown',
                source: 'vite-chunk',
                evidence: match[0].slice(0, 100),
                url,
            });
        }
    }

    private analyzeScriptUrl(url: string): void {
        const cdnPattern = new RegExp(NPM_CDN_PATTERN.source, 'gi');
        let match: RegExpExecArray | null;
        while ((match = cdnPattern.exec(url)) !== null) {
            this.addPackage({
                name: this.normalizePackageName(match[1]),
                version: match[2] || 'unknown',
                source: 'script-comment',
                evidence: `CDN URL: ${url.slice(0, 200)}`,
                url,
            });
        }
    }

    private normalizePackageName(raw: string): string {
        return raw.replace(/\/$/, '').split('/').slice(0, raw.startsWith('@') ? 2 : 1).join('/');
    }

    private addPackage(pkg: DetectedPackage): DetectedPackage | null {
        const key = `${pkg.name}@${pkg.version}`;
        if (this.packages.has(key)) return null;
        this.packages.set(key, pkg);
        logger.debug(`[SbomScanner] Detected: ${key} via ${pkg.source}`);
        return pkg;
    }

    getResults(): DetectedPackage[] {
        return Array.from(this.packages.values());
    }

    clear(): void {
        this.packages.clear();
        this.analyzedUrls.clear();
    }

    onClose(): void {
        logger.info(`  [SBOM] Detected ${this.packages.size} packages`);
    }
}

/**
 * Generate a CycloneDX 1.5 SBOM report from detected packages.
 */
export function generateCycloneDxReport(packages: DetectedPackage[]): object {
    return {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: {
            timestamp: new Date().toISOString(),
            tools: [{ vendor: 'LSCM', name: 'SbomScanner', version: '3.2.0' }],
        },
        components: packages.map(pkg => ({
            type: 'library',
            name: pkg.name,
            version: pkg.version,
            purl: pkg.version !== 'unknown' ? `pkg:npm/${pkg.name}@${pkg.version}` : `pkg:npm/${pkg.name}`,
            properties: [
                { name: 'lscm:source', value: pkg.source },
                { name: 'lscm:evidence', value: pkg.evidence },
            ],
        })),
    };
}

/**
 * Query the OSV API for vulnerabilities in detected packages.
 */
export async function queryOsvVulnerabilities(packages: DetectedPackage[]): Promise<OsvVulnerability[]> {
    const vulnerabilities: OsvVulnerability[] = [];
    const versionedPackages = packages.filter(p => p.version !== 'unknown');

    for (const pkg of versionedPackages.slice(0, 50)) {
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 5000);
            const response = await fetch('https://api.osv.dev/v1/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    package: { name: pkg.name, ecosystem: 'npm' },
                    version: pkg.version,
                }),
                signal: controller.signal,
            });
            clearTimeout(timer);

            if (response.ok) {
                const data = await response.json() as { vulns?: Array<{ id: string; summary?: string; severity?: Array<{ type: string; score: string }>; aliases?: string[] }> };
                if (data.vulns) {
                    for (const vuln of data.vulns) {
                        vulnerabilities.push({
                            id: vuln.id,
                            packageName: pkg.name,
                            severity: vuln.severity?.[0]?.score || 'unknown',
                            summary: vuln.summary || vuln.id,
                            aliases: vuln.aliases || [],
                        });
                    }
                }
            }
        } catch {
            // Skip failed queries
        }
    }

    return vulnerabilities;
}
