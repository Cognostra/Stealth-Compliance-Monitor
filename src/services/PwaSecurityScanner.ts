/**
 * PWA Security Scanner
 *
 * IScanner implementation for Progressive Web App security analysis:
 * - Service Worker security analysis (scope, update cycle, cache poisoning risks)
 * - Web App Manifest validation (start_url, scope security, display mode)
 * - HTTPS enforcement checks (mixed content detection)
 * - Push notification permission abuse detection
 * - Background sync security concerns
 * - Cache storage inspection for sensitive data
 */

import type { Page, Response } from 'playwright';
import type { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

export interface PwaFinding {
    type: 'insecure-scope' | 'overbroad-sw' | 'missing-manifest' | 'http-start-url' | 'sensitive-cache' | 'push-abuse';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    url: string;
    evidence: string;
    remediation: string;
}

interface ManifestData {
    start_url?: string;
    scope?: string;
    display?: string;
    orientation?: string;
    theme_color?: string;
    background_color?: string;
    icons?: Array<{ src: string; sizes?: string; type?: string }>;
    serviceworker?: {
        src?: string;
        scope?: string;
        use_cache?: boolean;
    };
}

interface ServiceWorkerInfo {
    scriptURL: string;
    state: 'installing' | 'installed' | 'activating' | 'activated' | 'redundant';
    scope: string;
    hasFetchHandler: boolean;
    hasMessageHandler: boolean;
    updateViaCache: 'imports' | 'all' | 'none';
    cacheNames: string[];
}

export class PwaSecurityScanner implements IScanner {
    readonly name = 'PwaSecurityScanner';
    private findings: PwaFinding[] = [];
    private pages: WeakSet<Page> = new WeakSet();
    private analyzedUrls: Set<string> = new Set();
    private manifestData: Map<string, ManifestData> = new Map();
    private swInfo: Map<string, ServiceWorkerInfo[]> = new Map();

    onPageCreated(page: Page): void {
        if (this.pages.has(page)) return;
        this.pages.add(page);
        logger.debug('[PwaSecurityScanner] Attached to page');
    }

    onResponse(response: Response): void {
        const url = response.url();
        const headers = response.headers();

        // Detect manifest file
        if (url.endsWith('manifest.json') || url.endsWith('.webmanifest')) {
            logger.debug(`[PwaSecurityScanner] Detected manifest: ${url}`);
        }

        // Detect service worker file
        if (url.includes('service-worker') || url.includes('serviceworker') || url.includes('sw.js')) {
            logger.debug(`[PwaSecurityScanner] Detected service worker: ${url}`);
        }

        // Detect insecure content
        if (url.startsWith('http://') && !url.startsWith('http://localhost')) {
            const finding: PwaFinding = {
                type: 'http-start-url',
                severity: 'high',
                description: 'Insecure HTTP resource loaded - PWA requires all resources to be served over HTTPS',
                url,
                evidence: `Resource loaded over HTTP: ${url}`,
                remediation: 'Ensure all resources including service workers, manifests, and APIs are served over HTTPS with valid certificates',
            };
            this.addFinding(finding);
        }
    }

    /**
     * Perform comprehensive PWA security analysis on a page
     */
    async analyzePage(page: Page): Promise<PwaFinding[]> {
        const url = page.url();
        if (this.analyzedUrls.has(url)) {
            return this.findings.filter(f => f.url === url);
        }
        this.analyzedUrls.add(url);

        const newFindings: PwaFinding[] = [];

        try {
            // Check for manifest
            const manifestUrl = await this.findManifestUrl(page);
            if (manifestUrl) {
                const manifest = await this.fetchAndParseManifest(page, manifestUrl);
                this.manifestData.set(url, manifest);
                const manifestFindings = this.validateManifest(manifest, url, manifestUrl);
                newFindings.push(...manifestFindings);
            } else {
                const finding: PwaFinding = {
                    type: 'missing-manifest',
                    severity: 'medium',
                    description: 'No Web App Manifest found - PWA capabilities are limited without a manifest',
                    url,
                    evidence: 'No manifest link tag detected in document head',
                    remediation: 'Add a manifest.json file and reference it with <link rel="manifest" href="/manifest.json">',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // Check for service workers
            const swInfo = await this.getServiceWorkerInfo(page);
            if (swInfo.length > 0) {
                this.swInfo.set(url, swInfo);
                const swFindings = this.analyzeServiceWorkers(swInfo, url);
                newFindings.push(...swFindings);

                // Analyze cache storage
                const cacheFindings = await this.analyzeCacheStorage(page, url);
                newFindings.push(...cacheFindings);
            }

            // Check for push notification abuse
            const pushFindings = await this.analyzePushNotifications(page, url);
            newFindings.push(...pushFindings);

            // Check for background sync
            const syncFindings = await this.analyzeBackgroundSync(page, url);
            newFindings.push(...syncFindings);

            // Check for mixed content
            const mixedContentFindings = await this.detectMixedContent(page, url);
            newFindings.push(...mixedContentFindings);

        } catch (error) {
            logger.debug(`[PwaSecurityScanner] Error analyzing page: ${error}`);
        }

        return newFindings;
    }

    /**
     * Find manifest URL from page
     */
    private async findManifestUrl(page: Page): Promise<string | null> {
        return page.evaluate(() => {
            const manifestLink = document.querySelector('link[rel="manifest"]');
            return manifestLink?.getAttribute('href') || null;
        });
    }

    /**
     * Fetch and parse Web App Manifest
     */
    private async fetchAndParseManifest(page: Page, manifestUrl: string): Promise<ManifestData> {
        try {
            const absoluteUrl = new URL(manifestUrl, page.url()).href;
            const response = await page.evaluate(async (url) => {
                try {
                    const res = await fetch(url);
                    if (!res.ok) return null;
                    return await res.json();
                } catch {
                    return null;
                }
            }, absoluteUrl);

            return response || {};
        } catch {
            return {};
        }
    }

    /**
     * Validate manifest for security issues
     */
    private validateManifest(manifest: ManifestData, pageUrl: string, manifestUrl: string): PwaFinding[] {
        const findings: PwaFinding[] = [];

        // Check start_url uses HTTPS
        if (manifest.start_url) {
            if (manifest.start_url.startsWith('http://') && !manifest.start_url.startsWith('http://localhost')) {
                const finding: PwaFinding = {
                    type: 'http-start-url',
                    severity: 'critical',
                    description: 'Manifest start_url uses insecure HTTP protocol',
                    url: pageUrl,
                    evidence: `start_url: ${manifest.start_url}`,
                    remediation: 'Change start_url to use HTTPS protocol. PWAs must be served over HTTPS.',
                };
                this.addFinding(finding);
                findings.push(finding);
            }

            // Check if start_url is overly broad
            if (manifest.start_url === '/' || manifest.start_url === './' || manifest.start_url === '.') {
                const finding: PwaFinding = {
                    type: 'insecure-scope',
                    severity: 'medium',
                    description: 'Manifest start_url is overly broad, may allow navigation to unexpected origins',
                    url: pageUrl,
                    evidence: `start_url: ${manifest.start_url}`,
                    remediation: 'Specify a more specific start_url that points to the actual application entry point',
                };
                this.addFinding(finding);
                findings.push(finding);
            }
        }

        // Check scope security
        if (manifest.scope) {
            if (manifest.scope === '/' || manifest.scope === './' || manifest.scope === '.') {
                const finding: PwaFinding = {
                    type: 'insecure-scope',
                    severity: 'high',
                    description: 'Manifest scope is root-relative (/), service worker will intercept all navigations',
                    url: pageUrl,
                    evidence: `scope: ${manifest.scope}`,
                    remediation: 'Restrict scope to application-specific path (e.g., "/app/") to prevent service worker from intercepting unintended navigations',
                };
                this.addFinding(finding);
                findings.push(finding);
            }

            // Check if scope is too broad
            try {
                const scopeUrl = new URL(manifest.scope, pageUrl);
                const pageOrigin = new URL(pageUrl).origin;
                if (scopeUrl.origin !== pageOrigin) {
                    const finding: PwaFinding = {
                        type: 'insecure-scope',
                        severity: 'critical',
                        description: 'Manifest scope points to different origin than the PWA',
                        url: pageUrl,
                        evidence: `scope origin ${scopeUrl.origin} differs from page origin ${pageOrigin}`,
                        remediation: 'Ensure manifest scope is within the same origin as the application',
                    };
                    this.addFinding(finding);
                    findings.push(finding);
                }
            } catch {
                // Invalid URL in scope
            }
        }

        // Check display mode security
        if (manifest.display === 'fullscreen' || manifest.display === 'standalone') {
            const finding: PwaFinding = {
                type: 'insecure-scope',
                severity: 'low',
                description: `Display mode "${manifest.display}" removes browser UI including address bar, potentially hiding phishing attempts`,
                url: pageUrl,
                evidence: `display: ${manifest.display}`,
                remediation: 'Consider using "minimal-ui" display mode to retain some browser security indicators, or implement custom origin indicators in the app UI',
            };
            this.addFinding(finding);
            findings.push(finding);
        }

        return findings;
    }

    /**
     * Get service worker information from page
     */
    private async getServiceWorkerInfo(page: Page): Promise<ServiceWorkerInfo[]> {
        return page.evaluate(() => {
            if (!navigator.serviceWorker) return [];

            return navigator.serviceWorker.ready.then(() => {
                const controllers: ServiceWorkerInfo[] = [];

                // Get active controller
                if (navigator.serviceWorker.controller) {
                    const sw = navigator.serviceWorker.controller;
                    controllers.push({
                        scriptURL: sw.scriptURL,
                        state: sw.state as ServiceWorkerInfo['state'],
                        scope: (sw as unknown as { scope?: string }).scope || 'unknown',
                        hasFetchHandler: true, // Assume if active, it has fetch handler
                        hasMessageHandler: false, // Cannot detect without analyzing code
                        updateViaCache: 'none', // Default
                        cacheNames: [],
                    });
                }

                return controllers;
            });
        });
    }

    /**
     * Analyze service worker security issues
     */
    private analyzeServiceWorkers(swInfo: ServiceWorkerInfo[], pageUrl: string): PwaFinding[] {
        const findings: PwaFinding[] = [];

        for (const sw of swInfo) {
            // Check for overly broad scope
            if (sw.scope === '/' || sw.scope.endsWith('/') || sw.scope === '') {
                const finding: PwaFinding = {
                    type: 'overbroad-sw',
                    severity: 'high',
                    description: 'Service Worker scope is overly broad, potentially intercepting requests from other applications on the same origin',
                    url: pageUrl,
                    evidence: `Service Worker scope: ${sw.scope}, script: ${sw.scriptURL}`,
                    remediation: 'Register service worker with a restricted scope specific to your application path',
                };
                this.addFinding(finding);
                findings.push(finding);
            }

            // Check for insecure script URL
            if (sw.scriptURL.startsWith('http://') && !sw.scriptURL.startsWith('http://localhost')) {
                const finding: PwaFinding = {
                    type: 'http-start-url',
                    severity: 'critical',
                    description: 'Service Worker loaded over insecure HTTP connection',
                    url: pageUrl,
                    evidence: `Service Worker script URL: ${sw.scriptURL}`,
                    remediation: 'Serve service worker script over HTTPS only. Service workers require secure contexts.',
                };
                this.addFinding(finding);
                findings.push(finding);
            }

            // Check updateViaCache setting
            if (sw.updateViaCache === 'all') {
                const finding: PwaFinding = {
                    type: 'overbroad-sw',
                    severity: 'medium',
                    description: 'Service Worker uses "updateViaCache: all" which may cache compromised scripts',
                    url: pageUrl,
                    evidence: `updateViaCache: ${sw.updateViaCache}`,
                    remediation: 'Use "updateViaCache: imports" (default) to only cache imported scripts, not the main service worker',
                };
                this.addFinding(finding);
                findings.push(finding);
            }
        }

        return findings;
    }

    /**
     * Analyze cache storage for sensitive data
     */
    private async analyzeCacheStorage(page: Page, pageUrl: string): Promise<PwaFinding[]> {
        const findings: PwaFinding[] = [];

        try {
            const cacheInfo = await page.evaluate(async () => {
                if (!('caches' in window)) return null;

                const cacheNames = await caches.keys();
                const cacheContents: Array<{ name: string; urls: string[] }> = [];

                for (const name of cacheNames) {
                    const cache = await caches.open(name);
                    const requests = await cache.keys();
                    const urls = requests.map(r => r.url);
                    cacheContents.push({ name, urls });
                }

                return cacheContents;
            });

            if (!cacheInfo) return findings;

            // Check for sensitive data patterns in cache
            const sensitivePatterns = [
                /api\/(auth|login|token)/i,
                /password/i,
                /token/i,
                /session/i,
                /key/i,
                /secret/i,
                /credential/i,
                /ssn|social.*security/i,
                /credit.*card|cvv|ccnum/i,
            ];

            for (const cache of cacheInfo) {
                for (const url of cache.urls) {
                    for (const pattern of sensitivePatterns) {
                        if (pattern.test(url)) {
                            const finding: PwaFinding = {
                                type: 'sensitive-cache',
                                severity: 'high',
                                description: `Cache may contain sensitive data: ${url}`,
                                url: pageUrl,
                                evidence: `Cache "${cache.name}" contains potentially sensitive URL pattern: ${url}`,
                                remediation: 'Avoid caching API endpoints that return authentication tokens, personal information, or sensitive data. Implement cache exclusion rules for sensitive resources.',
                            };
                            this.addFinding(finding);
                            findings.push(finding);
                            break;
                        }
                    }
                }
            }

            // Check for overly broad caching
            if (cacheInfo.length > 0) {
                const totalUrls = cacheInfo.reduce((sum, c) => sum + c.urls.length, 0);
                if (totalUrls > 100) {
                    const finding: PwaFinding = {
                        type: 'sensitive-cache',
                        severity: 'medium',
                        description: `Excessive number of cached resources (${totalUrls}) may indicate over-caching`,
                        url: pageUrl,
                        evidence: `${totalUrls} resources cached across ${cacheInfo.length} cache(s)`,
                        remediation: 'Implement cache quotas and expiration policies. Regularly clean up old cache entries.',
                    };
                    this.addFinding(finding);
                    findings.push(finding);
                }
            }
        } catch (error) {
            logger.debug(`[PwaSecurityScanner] Error analyzing cache: ${error}`);
        }

        return findings;
    }

    /**
     * Analyze push notification usage for potential abuse
     */
    private async analyzePushNotifications(page: Page, pageUrl: string): Promise<PwaFinding[]> {
        const findings: PwaFinding[] = [];

        try {
            const pushState = await page.evaluate(() => {
                return {
                    permission: Notification.permission,
                    hasPushManager: 'PushManager' in window,
                    hasServiceWorker: 'serviceWorker' in navigator,
                };
            });

            // Check for immediate permission requests
            if (pushState.permission === 'granted') {
                // Check if there was an automatic permission request
                const hasPromptCode = await page.evaluate(() => {
                    // Check for common push notification library patterns
                    const html = document.documentElement.innerHTML;
                    const pushPatterns = [
                        /OneSignal/i,
                        /push.*notification/i,
                        /web.*push/i,
                        /firebase.*messaging/i,
                        /push.*prompt/i,
                    ];
                    return pushPatterns.some(p => p.test(html));
                });

                if (hasPromptCode) {
                    const finding: PwaFinding = {
                        type: 'push-abuse',
                        severity: 'medium',
                        description: 'Push notifications permission may have been requested automatically without user interaction',
                        url: pageUrl,
                        evidence: 'Push notification libraries detected and permission is already granted',
                        remediation: 'Request push notification permissions only after explicit user action (e.g., clicking "Enable Notifications" button). Never request on page load.',
                    };
                    this.addFinding(finding);
                    findings.push(finding);
                }
            }

            // Check for notification permission abuse patterns
            if (pushState.permission === 'default') {
                const hasAutoPrompt = await page.evaluate(() => {
                    // Look for automatic permission request patterns
                    const scripts = Array.from(document.querySelectorAll('script'));
                    return scripts.some(script => {
                        const content = script.textContent || '';
                        return content.includes('Notification.requestPermission') &&
                               !content.includes('click') &&
                               !content.includes('button');
                    });
                });

                if (hasAutoPrompt) {
                    const finding: PwaFinding = {
                        type: 'push-abuse',
                        severity: 'high',
                        description: 'Automatic push notification permission request detected on page load',
                        url: pageUrl,
                        evidence: 'Notification.requestPermission() called without user gesture',
                        remediation: 'Always wrap notification permission requests behind user-initiated actions. Automatic permission requests violate best practices and may annoy users.',
                    };
                    this.addFinding(finding);
                    findings.push(finding);
                }
            }
        } catch (error) {
            logger.debug(`[PwaSecurityScanner] Error analyzing push notifications: ${error}`);
        }

        return findings;
    }

    /**
     * Analyze background sync for security concerns
     */
    private async analyzeBackgroundSync(page: Page, pageUrl: string): Promise<PwaFinding[]> {
        const findings: PwaFinding[] = [];

        try {
            const syncState = await page.evaluate(() => {
                return {
                    hasSyncManager: 'SyncManager' in window,
                    hasPeriodicSync: 'PeriodicSyncManager' in window,
                    swRegistered: 'serviceWorker' in navigator && !!navigator.serviceWorker.controller,
                };
            });

            if (syncState.hasSyncManager && syncState.swRegistered) {
                // Check service worker code for sync event handlers
                const hasSyncHandler = await page.evaluate(async () => {
                    if (!navigator.serviceWorker?.controller) return false;

                    // Try to detect sync registration
                    try {
                        const registration = await navigator.serviceWorker.ready;
                        return 'sync' in registration;
                    } catch {
                        return false;
                    }
                });

                if (hasSyncHandler) {
                    // Check for sensitive operations in sync
                    const finding: PwaFinding = {
                        type: 'sensitive-cache',
                        severity: 'medium',
                        description: 'Background Sync API is available - ensure sync operations do not transmit sensitive data without user consent',
                        url: pageUrl,
                        evidence: 'Background Sync Manager detected with active service worker',
                        remediation: 'Audit background sync operations to ensure they do not automatically transmit sensitive user data. Implement user notification for sync operations involving personal information.',
                    };
                    this.addFinding(finding);
                    findings.push(finding);
                }
            }

            // Check for periodic background sync (more aggressive)
            if (syncState.hasPeriodicSync) {
                const finding: PwaFinding = {
                    type: 'push-abuse',
                    severity: 'medium',
                    description: 'Periodic Background Sync API detected - may drain battery and use data without user awareness',
                    url: pageUrl,
                    evidence: 'PeriodicSyncManager is available',
                    remediation: 'Use periodic background sync sparingly and provide user controls to disable it. Consider privacy implications of periodic data synchronization.',
                };
                this.addFinding(finding);
                findings.push(finding);
            }
        } catch (error) {
            logger.debug(`[PwaSecurityScanner] Error analyzing background sync: ${error}`);
        }

        return findings;
    }

    /**
     * Detect mixed content issues
     */
    private async detectMixedContent(page: Page, pageUrl: string): Promise<PwaFinding[]> {
        const findings: PwaFinding[] = [];

        try {
            const mixedContent = await page.evaluate(() => {
                const issues: Array<{ element: string; src: string }> = [];

                // Check for HTTP resources on HTTPS pages
                if (window.location.protocol === 'https:') {
                    // Check images
                    document.querySelectorAll('img[src^="http:"]').forEach(img => {
                        issues.push({ element: 'img', src: img.getAttribute('src') || '' });
                    });

                    // Check scripts
                    document.querySelectorAll('script[src^="http:"]').forEach(script => {
                        issues.push({ element: 'script', src: script.getAttribute('src') || '' });
                    });

                    // Check stylesheets
                    document.querySelectorAll('link[rel="stylesheet"][href^="http:"]').forEach(link => {
                        issues.push({ element: 'stylesheet', src: link.getAttribute('href') || '' });
                    });

                    // Check iframes
                    document.querySelectorAll('iframe[src^="http:"]').forEach(iframe => {
                        issues.push({ element: 'iframe', src: iframe.getAttribute('src') || '' });
                    });

                    // Check fetch/XHR targets (via performance API)
                    const entries = performance.getEntriesByType('resource');
                    entries.forEach((entry: PerformanceEntry) => {
                        const resource = entry as PerformanceResourceTiming;
                        if (resource.name.startsWith('http:')) {
                            issues.push({ element: 'xhr/fetch', src: resource.name });
                        }
                    });
                }

                return issues;
            });

            // Deduplicate and create findings
            const seen = new Set<string>();
            for (const item of mixedContent) {
                if (!seen.has(item.src)) {
                    seen.add(item.src);
                    const finding: PwaFinding = {
                        type: 'http-start-url',
                        severity: 'high',
                        description: `Mixed content: ${item.element} loaded over HTTP on HTTPS page`,
                        url: pageUrl,
                        evidence: `Insecure resource: ${item.src}`,
                        remediation: 'Load all resources over HTTPS. Use protocol-relative URLs (//example.com) or absolute HTTPS URLs.',
                    };
                    this.addFinding(finding);
                    findings.push(finding);
                }
            }
        } catch (error) {
            logger.debug(`[PwaSecurityScanner] Error detecting mixed content: ${error}`);
        }

        return findings;
    }

    private addFinding(finding: PwaFinding): void {
        const key = `${finding.type}:${finding.url}:${finding.evidence}`;
        if (!this.findings.some(f => `${f.type}:${f.url}:${f.evidence}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): PwaFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
        this.analyzedUrls.clear();
        this.manifestData.clear();
        this.swInfo.clear();
    }

    onClose(): void {
        logger.info(`  [PWA Security] ${this.findings.length} PWA security findings detected`);
    }
}
