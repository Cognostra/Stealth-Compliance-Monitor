/**
 * MobileSecurityScanner Service
 *
 * Detects mobile-specific security vulnerabilities and misconfigurations.
 * Focuses on mobile web security concerns including:
 * - Viewport configuration issues (zoom blocking, text scaling)
 * - Touch event security (tapjacking prevention)
 * - Motion sensor permission abuse (accelerometer/gyroscope)
 * - Vibration API abuse
 * - Insecure deep link handling
 * - Orientation/Fullscreen API abuse
 *
 * Implements IScanner for registry-based lifecycle management.
 */

import { Page, Response } from 'playwright';
import { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

/**
 * Mobile security finding types
 */
export type MobileFindingType =
    | 'viewport-blocking'
    | 'tapjacking-risk'
    | 'motion-abuse'
    | 'deep-link-insecure'
    | 'vibration-abuse';

/**
 * Severity levels for mobile security findings
 */
export type MobileFindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Individual mobile security finding
 */
export interface MobileFinding {
    type: MobileFindingType;
    severity: MobileFindingSeverity;
    title: string;
    description: string;
    evidence: string;
    recommendation: string;
    url?: string;
    selector?: string;
}

/**
 * Complete mobile security scan results
 */
export interface MobileScanResult {
    url: string;
    findings: MobileFinding[];
    passed: boolean;
    score: number;
}

/**
 * MobileSecurityScanner - IScanner implementation for mobile web security
 */
export class MobileSecurityScanner implements IScanner {
    readonly name = 'MobileSecurityScanner';

    private findings: MobileFinding[] = [];
    private scannedUrls: Set<string> = new Set();
    private page: Page | null = null;

    // ═══════════════════════════════════════════════════════════════════════════
    // IScanner Lifecycle Hooks
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Called when page is created
     */
    onPageCreated(page: Page): void {
        this.page = page;
        logger.info('  📱 Mobile Security Scanner attached');
    }

    /**
     * Called for each network response - scan for mobile-specific issues
     */
    async onResponse(response: Response): Promise<void> {
        try {
            const url = response.url();
            const contentType = response.headers()['content-type'] || '';

            // Only scan HTML pages once
            if (contentType.includes('text/html') && !this.scannedUrls.has(url)) {
                this.scannedUrls.add(url);

                try {
                    // Perform mobile security scan on this page
                    await this.scanPage(url);
                } catch (error) {
                    logger.debug(`MobileSecurityScanner: Could not scan ${url}: ${error}`);
                }
            }
        } catch (e) {
            logger.debug(`MobileSecurityScanner error: ${e instanceof Error ? e.message : String(e)}`);
        }
    }

    /**
     * Called during shutdown
     */
    onClose(): void {
        logger.debug(`MobileSecurityScanner: Found ${this.findings.length} mobile security issues`);
    }

    /**
     * Get collected results
     */
    getResults(): MobileFinding[] {
        return [...this.findings];
    }

    /**
     * Clear scanner state
     */
    clear(): void {
        this.findings = [];
        this.scannedUrls.clear();
        this.page = null;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Core Scanning Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Scan a page for mobile security issues
     */
    private async scanPage(url: string): Promise<void> {
        if (!this.page) {
            logger.warn('MobileSecurityScanner: No page attached');
            return;
        }

        const pageFindings: MobileFinding[] = [];

        try {
            // Run all mobile security checks
            const viewportFindings = await this.checkViewportConfiguration();
            const touchFindings = await this.checkTouchEventSecurity();
            const motionFindings = await this.checkMotionSensors();
            const deepLinkFindings = await this.checkDeepLinkSecurity();
            const fullscreenFindings = await this.checkFullscreenAndOrientation();
            const vibrationFindings = await this.checkVibrationAPI();

            // Collect all findings
            pageFindings.push(
                ...viewportFindings,
                ...touchFindings,
                ...motionFindings,
                ...deepLinkFindings,
                ...fullscreenFindings,
                ...vibrationFindings
            );

            // Log findings
            pageFindings.forEach(finding => {
                logger.warn(`  ⚠️ [${finding.severity.toUpperCase()}] ${finding.title} - ${finding.type}`);
            });

            // Add to findings collection
            this.findings.push(...pageFindings);

        } catch (error) {
            logger.error(`MobileSecurityScanner: Error scanning ${url}: ${error}`);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Security Check Methods
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Check viewport meta tag configuration
     * Detects: zoom blocking, text scaling issues, user-scalable=no
     */
    private async checkViewportConfiguration(): Promise<MobileFinding[]> {
        const findings: MobileFinding[] = [];

        try {
            const viewportIssues = await this.page!.evaluate(() => {
                const issues: Array<{ type: string; content: string; evidence: string }> = [];

                // Find viewport meta tag
                const viewportMeta = document.querySelector('meta[name="viewport"]');

                if (!viewportMeta) {
                    issues.push({
                        type: 'missing-viewport',
                        content: 'Missing viewport meta tag',
                        evidence: 'No viewport meta tag found in head'
                    });
                    return issues;
                }

                const content = viewportMeta.getAttribute('content') || '';
                const contentLower = content.toLowerCase();

                // Check for user-scalable=no (blocks accessibility)
                if (contentLower.includes('user-scalable=no') || contentLower.includes('user-scalable=0')) {
                    issues.push({
                        type: 'zoom-blocking',
                        content: 'Viewport blocks user zoom',
                        evidence: `user-scalable=no found in: ${content}`
                    });
                }

                // Check for maximum-scale restrictions
                const maxScaleMatch = content.match(/maximum-scale[=:]?(\d+(?:\.\d+)?)/i);
                if (maxScaleMatch) {
                    const maxScale = parseFloat(maxScaleMatch[1]);
                    if (maxScale < 3) {
                        issues.push({
                            type: 'zoom-blocking',
                            content: 'Maximum-scale too restrictive for accessibility',
                            evidence: `maximum-scale=${maxScale} in: ${content}`
                        });
                    }
                }

                // Check for initial-scale issues
                const initialScaleMatch = content.match(/initial-scale[=:]?(\d+(?:\.\d+)?)/i);
                if (!initialScaleMatch) {
                    issues.push({
                        type: 'viewport-blocking',
                        content: 'Missing initial-scale in viewport',
                        evidence: `No initial-scale defined in: ${content}`
                    });
                }

                // Check for width=device-width
                if (!contentLower.includes('width=device-width')) {
                    issues.push({
                        type: 'viewport-blocking',
                        content: 'Viewport not set to device width',
                        evidence: `Missing width=device-width in: ${content}`
                    });
                }

                return issues;
            });

            viewportIssues.forEach(issue => {
                findings.push({
                    type: issue.type === 'missing-viewport' ? 'viewport-blocking' : (issue.type as MobileFindingType),
                    severity: issue.type === 'zoom-blocking' ? 'medium' : 'low',
                    title: issue.content,
                    description: 'Viewport configuration may block users from zooming or scaling content, impacting accessibility and usability.',
                    evidence: issue.evidence,
                    recommendation: 'Ensure viewport includes "width=device-width, initial-scale=1" and avoids "user-scalable=no" or restrictive maximum-scale values.',
                    selector: 'meta[name="viewport"]'
                });
            });

        } catch (error) {
            logger.debug(`Viewport check failed: ${error}`);
        }

        return findings;
    }

    /**
     * Check for touch event security issues (tapjacking prevention)
     */
    private async checkTouchEventSecurity(): Promise<MobileFinding[]> {
        const findings: MobileFinding[] = [];

        try {
            const touchIssues = await this.page!.evaluate(() => {
                const issues: Array<{ type: string; description: string; selectors: string[] }> = [];

                // Check for elements with pointer-events: none that might be overlaying interactive elements
                const overlays = document.querySelectorAll('[style*="pointer-events: none" i], [style*="pointer-events:none" i]');
                const suspiciousOverlays: string[] = [];

                overlays.forEach((el, index) => {
                    const style = (el as HTMLElement).style;
                    if (style.pointerEvents === 'none') {
                        // Check if element is positioned absolutely or fixed (potential overlay)
                        const position = style.position;
                        if (position === 'absolute' || position === 'fixed') {
                            suspiciousOverlays.push(`${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}${el.className ? '.' + el.className.split(' ').join('.') : ''}`);
                        }
                    }
                });

                if (suspiciousOverlays.length > 0) {
                    issues.push({
                        type: 'tapjacking-risk',
                        description: `Found ${suspiciousOverlays.length} elements with pointer-events: none that may be overlaying interactive content`,
                        selectors: suspiciousOverlays.slice(0, 5)
                    });
                }

                // Check for touch-action CSS properties
                const allElements = document.querySelectorAll('*');
                const touchActionElements: string[] = [];

                allElements.forEach(el => {
                    const computedStyle = window.getComputedStyle(el);
                    const touchAction = computedStyle.touchAction;

                    if (touchAction && touchAction !== 'auto' && touchAction !== '') {
                        touchActionElements.push(`${el.tagName.toLowerCase()}: touch-action=${touchAction}`);
                    }
                });

                if (touchActionElements.length > 0) {
                    issues.push({
                        type: 'tapjacking-risk',
                        description: `Found ${touchActionElements.length} elements with non-default touch-action`,
                        selectors: touchActionElements.slice(0, 5)
                    });
                }

                // Check for fast-click libraries that might introduce clickjacking
                const scripts = document.querySelectorAll('script[src]');
                let hasFastClick = false;
                scripts.forEach(script => {
                    const src = script.getAttribute('src') || '';
                    if (src.toLowerCase().includes('fastclick') || src.toLowerCase().includes('fast-click')) {
                        hasFastClick = true;
                    }
                });

                if (hasFastClick) {
                    issues.push({
                        type: 'tapjacking-risk',
                        description: 'FastClick library detected - may introduce clickjacking vulnerabilities',
                        selectors: ['script[src*="fastclick"]']
                    });
                }

                return issues;
            });

            touchIssues.forEach(issue => {
                findings.push({
                    type: 'tapjacking-risk',
                    severity: 'medium',
                    title: issue.description,
                    description: 'Elements with pointer-events: none or non-default touch-action may enable tapjacking attacks where malicious overlays intercept user interactions.',
                    evidence: issue.selectors.join(', '),
                    recommendation: 'Review touch-action CSS properties and pointer-events usage. Ensure overlays cannot intercept unintended user interactions. Consider using touch-action: manipulation for buttons.',
                    selector: issue.selectors[0]
                });
            });

        } catch (error) {
            logger.debug(`Touch event security check failed: ${error}`);
        }

        return findings;
    }

    /**
     * Check for motion sensor permission abuse
     */
    private async checkMotionSensors(): Promise<MobileFinding[]> {
        const findings: MobileFinding[] = [];

        try {
            const motionIssues = await this.page!.evaluate(() => {
                const issues: Array<{ type: string; description: string; evidence: string }> = [];

                // Check for DeviceMotionEvent listeners
                const originalAddEventListener = window.addEventListener;
                let hasDeviceMotion = false;
                let hasDeviceOrientation = false;

                // Check inline script text for device motion/orientation references
                const scripts = document.querySelectorAll('script:not([src])');
                let inlineScriptContent = '';
                scripts.forEach(script => {
                    inlineScriptContent += script.textContent || '';
                });

                // Check for DeviceMotionEvent usage
                if (inlineScriptContent.includes('DeviceMotionEvent') ||
                    inlineScriptContent.includes('devicemotion') ||
                    inlineScriptContent.includes('acceleration') ||
                    inlineScriptContent.includes('rotationRate')) {
                    hasDeviceMotion = true;
                }

                // Check for DeviceOrientationEvent usage
                if (inlineScriptContent.includes('DeviceOrientationEvent') ||
                    inlineScriptContent.includes('deviceorientation') ||
                    inlineScriptContent.includes('alpha') ||
                    inlineScriptContent.includes('beta') ||
                    inlineScriptContent.includes('gamma')) {
                    hasDeviceOrientation = true;
                }

                // Check for permission API usage for motion sensors
                if (inlineScriptContent.includes('navigator.permissions') &&
                    (inlineScriptContent.includes('accelerometer') ||
                        inlineScriptContent.includes('gyroscope') ||
                        inlineScriptContent.includes('magnetometer'))) {
                    issues.push({
                        type: 'motion-abuse',
                        description: 'Permission API used for motion sensors detected',
                        evidence: 'Script references navigator.permissions with motion sensor types'
                    });
                }

                if (hasDeviceMotion) {
                    issues.push({
                        type: 'motion-abuse',
                        description: 'DeviceMotionEvent usage detected',
                        evidence: 'Script references DeviceMotionEvent or devicemotion'
                    });
                }

                if (hasDeviceOrientation) {
                    issues.push({
                        type: 'motion-abuse',
                        description: 'DeviceOrientationEvent usage detected',
                        evidence: 'Script references DeviceOrientationEvent or deviceorientation'
                    });
                }

                // Check for Sensor API (modern replacement)
                if (inlineScriptContent.includes('Accelerometer') ||
                    inlineScriptContent.includes('Gyroscope') ||
                    inlineScriptContent.includes('LinearAccelerationSensor') ||
                    inlineScriptContent.includes('AbsoluteOrientationSensor')) {
                    issues.push({
                        type: 'motion-abuse',
                        description: 'Generic Sensor API usage detected',
                        evidence: 'Script references Accelerometer, Gyroscope, or other sensor constructors'
                    });
                }

                return issues;
            });

            motionIssues.forEach(issue => {
                findings.push({
                    type: 'motion-abuse',
                    severity: 'low',
                    title: issue.description,
                    description: 'Motion sensor access can be used for device fingerprinting, keystroke inference attacks, or tracking user behavior without consent.',
                    evidence: issue.evidence,
                    recommendation: 'Request user consent before accessing motion sensors. Consider if motion data is actually necessary for the application functionality.',
                    selector: 'script'
                });
            });

        } catch (error) {
            logger.debug(`Motion sensor check failed: ${error}`);
        }

        return findings;
    }

    /**
     * Check for insecure deep link handling and custom protocol usage
     */
    private async checkDeepLinkSecurity(): Promise<MobileFinding[]> {
        const findings: MobileFinding[] = [];

        try {
            const deepLinkIssues = await this.page!.evaluate(() => {
                const issues: Array<{ type: string; description: string; evidence: string }> = [];

                // Check for custom protocol handlers (intent://, customscheme://)
                const links = document.querySelectorAll('a[href^="intent:"], a[href*="://"]');
                const customProtocols: string[] = [];

                links.forEach(link => {
                    const href = link.getAttribute('href') || '';
                    const protocolMatch = href.match(/^([a-z][a-z0-9+.-]*):/i);

                    if (protocolMatch) {
                        const protocol = protocolMatch[1].toLowerCase();
                        // Skip standard protocols
                        if (!['http', 'https', 'ftp', 'mailto', 'tel', 'sms', 'javascript', 'data'].includes(protocol)) {
                            customProtocols.push(`${protocol}: ${href.substring(0, 100)}`);
                        }
                    }
                });

                if (customProtocols.length > 0) {
                    issues.push({
                        type: 'deep-link-insecure',
                        description: `Found ${customProtocols.length} custom protocol handlers`,
                        evidence: customProtocols.slice(0, 3).join('; ')
                    });
                }

                // Check for iframe src with custom protocols
                const iframes = document.querySelectorAll('iframe[src]');
                const iframeProtocols: string[] = [];

                iframes.forEach(iframe => {
                    const src = iframe.getAttribute('src') || '';
                    const protocolMatch = src.match(/^([a-z][a-z0-9+.-]*):/i);

                    if (protocolMatch) {
                        const protocol = protocolMatch[1].toLowerCase();
                        if (!['http', 'https', 'about'].includes(protocol)) {
                            iframeProtocols.push(`${protocol}: ${src.substring(0, 100)}`);
                        }
                    }
                });

                if (iframeProtocols.length > 0) {
                    issues.push({
                        type: 'deep-link-insecure',
                        description: `Found iframes using custom protocols`,
                        evidence: iframeProtocols.join('; ')
                    });
                }

                // Check for window.location assignments to custom protocols in scripts
                const scripts = document.querySelectorAll('script:not([src])');
                let hasLocationAssignment = false;
                scripts.forEach(script => {
                    const content = script.textContent || '';
                    if (content.includes('window.location') || content.includes('location.href')) {
                        const customSchemeMatch = content.match(/location\.(?:href|assign|replace)\s*=\s*["']([a-z][a-z0-9+.-]*):/i);
                        if (customSchemeMatch) {
                            const scheme = customSchemeMatch[1].toLowerCase();
                            if (!['http', 'https', 'ftp', 'mailto', 'tel', 'javascript', 'data'].includes(scheme)) {
                                hasLocationAssignment = true;
                            }
                        }
                    }
                });

                if (hasLocationAssignment) {
                    issues.push({
                        type: 'deep-link-insecure',
                        description: 'Dynamic custom protocol navigation detected',
                        evidence: 'Script assigns window.location to custom protocol'
                    });
                }

                return issues;
            });

            deepLinkIssues.forEach(issue => {
                findings.push({
                    type: 'deep-link-insecure',
                    severity: 'medium',
                    title: issue.description,
                    description: 'Custom protocol handlers (deep links) can be exploited to launch arbitrary apps, bypass security controls, or perform phishing attacks if not properly validated.',
                    evidence: issue.evidence,
                    recommendation: 'Validate all custom protocol URLs before navigation. Use allowlists for permitted schemes. Avoid using custom protocols in iframes.',
                    selector: 'a[href], iframe[src], script'
                });
            });

        } catch (error) {
            logger.debug(`Deep link security check failed: ${error}`);
        }

        return findings;
    }

    /**
     * Check for fullscreen and orientation API abuse
     */
    private async checkFullscreenAndOrientation(): Promise<MobileFinding[]> {
        const findings: MobileFinding[] = [];

        try {
            const apiIssues = await this.page!.evaluate(() => {
                const issues: Array<{ type: string; description: string; evidence: string; severity: string }> = [];

                const scripts = document.querySelectorAll('script:not([src])');
                let inlineScriptContent = '';
                scripts.forEach(script => {
                    inlineScriptContent += script.textContent || '';
                });

                // Check for fullscreen API usage
                const fullscreenMethods = ['requestFullscreen', 'webkitRequestFullscreen', 'mozRequestFullScreen', 'msRequestFullscreen'];
                const hasFullscreen = fullscreenMethods.some(method => inlineScriptContent.includes(method));

                if (hasFullscreen) {
                    issues.push({
                        type: 'fullscreen-abuse',
                        description: 'Fullscreen API usage detected',
                        evidence: 'Script references requestFullscreen or vendor-prefixed variants',
                        severity: 'low'
                    });
                }

                // Check for screen orientation lock
                if (inlineScriptContent.includes('screen.orientation') ||
                    inlineScriptContent.includes('orientation.lock') ||
                    inlineScriptContent.includes('lockOrientation')) {
                    issues.push({
                        type: 'orientation-abuse',
                        description: 'Screen orientation lock detected',
                        evidence: 'Script references screen.orientation.lock or lockOrientation',
                        severity: 'low'
                    });
                }

                // Check for wake lock API (keep screen on)
                if (inlineScriptContent.includes('WakeLock') ||
                    inlineScriptContent.includes('navigator.wakeLock')) {
                    issues.push({
                        type: 'wakelock-abuse',
                        description: 'Wake Lock API usage detected',
                        evidence: 'Script references WakeLock or navigator.wakeLock',
                        severity: 'info'
                    });
                }

                // Check for presentation API (casting)
                if (inlineScriptContent.includes('PresentationRequest') ||
                    inlineScriptContent.includes('navigator.presentation')) {
                    issues.push({
                        type: 'presentation-abuse',
                        description: 'Presentation API usage detected',
                        evidence: 'Script references PresentationRequest or navigator.presentation',
                        severity: 'info'
                    });
                }

                return issues;
            });

            apiIssues.forEach(issue => {
                findings.push({
                    type: 'motion-abuse',
                    severity: issue.severity as MobileFindingSeverity,
                    title: issue.description,
                    description: 'Fullscreen, orientation lock, and related APIs can be used to trap users in phishing interfaces, bypass security UI, or persist malicious content visibility.',
                    evidence: issue.evidence,
                    recommendation: 'Only use fullscreen and orientation APIs in response to explicit user gestures. Provide clear exit mechanisms. Respect user device preferences.',
                    selector: 'script'
                });
            });

        } catch (error) {
            logger.debug(`Fullscreen/Orientation check failed: ${error}`);
        }

        return findings;
    }

    /**
     * Check for vibration API abuse patterns
     */
    private async checkVibrationAPI(): Promise<MobileFinding[]> {
        const findings: MobileFinding[] = [];

        try {
            const vibrationIssues = await this.page!.evaluate(() => {
                const issues: Array<{ type: string; description: string; evidence: string; severity: string }> = [];

                const scripts = document.querySelectorAll('script:not([src])');
                let inlineScriptContent = '';
                scripts.forEach(script => {
                    inlineScriptContent += script.textContent || '';
                });

                // Check for vibration API usage
                if (inlineScriptContent.includes('navigator.vibrate') ||
                    inlineScriptContent.includes('.vibrate(')) {

                    // Check for excessive vibration patterns
                    const vibrateMatches = inlineScriptContent.match(/navigator\.vibrate\(([^)]+)\)/g);

                    if (vibrateMatches) {
                        const totalVibrations = vibrateMatches.length;

                        // Check for long vibration patterns (could indicate abuse)
                        let totalDuration = 0;
                        vibrateMatches.forEach(match => {
                            const args = match.match(/\[?([^\]]+)\]?/) || match.match(/\(([^)]+)\)/);
                            if (args) {
                                const durations = args[1].split(',').map(s => parseInt(s.trim(), 10) || 0);
                                totalDuration += durations.reduce((a, b) => a + b, 0);
                            }
                        });

                        if (totalDuration > 5000) {
                            issues.push({
                                type: 'vibration-abuse',
                                description: 'Excessive vibration pattern detected',
                                evidence: `Found ${totalVibrations} vibrate calls with total duration ${totalDuration}ms`,
                                severity: 'low'
                            });
                        } else {
                            issues.push({
                                type: 'vibration-abuse',
                                description: 'Vibration API usage detected',
                                evidence: `Found ${totalVibrations} vibrate() calls`,
                                severity: 'info'
                            });
                        }
                    }
                }

                // Check for beacon API (background data transmission)
                if (inlineScriptContent.includes('navigator.sendBeacon')) {
                    const beaconMatches = inlineScriptContent.match(/navigator\.sendBeacon\(/g);
                    const beaconCount = beaconMatches ? beaconMatches.length : 0;

                    if (beaconCount > 5) {
                        issues.push({
                            type: 'beacon-abuse',
                            description: 'Excessive beacon API usage detected',
                            evidence: `Found ${beaconCount} sendBeacon() calls - may indicate tracking`,
                            severity: 'low'
                        });
                    }
                }

                return issues;
            });

            vibrationIssues.forEach(issue => {
                findings.push({
                    type: issue.type === 'beacon-abuse' ? 'motion-abuse' : 'vibration-abuse',
                    severity: issue.severity as MobileFindingSeverity,
                    title: issue.description,
                    description: issue.type === 'beacon-abuse'
                        ? 'Excessive use of sendBeacon API may indicate covert data transmission or user tracking without their knowledge.'
                        : 'Excessive vibration patterns can be used to annoy users, drain battery, or hide malicious activity through haptic feedback manipulation.',
                    evidence: issue.evidence,
                    recommendation: issue.type === 'beacon-abuse'
                        ? 'Limit beacon usage to essential data transmission. Inform users about background data collection. Respect privacy preferences.'
                        : 'Use vibration API sparingly and only for meaningful user feedback. Avoid long or excessive patterns that could drain battery or annoy users.',
                    selector: 'script'
                });
            });

        } catch (error) {
            logger.debug(`Vibration API check failed: ${error}`);
        }

        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Public API Methods
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Get all findings collected by the scanner
     */
    getAllFindings(): MobileFinding[] {
        return [...this.findings];
    }

    /**
     * Get findings by type
     */
    getFindingsByType(type: MobileFindingType): MobileFinding[] {
        return this.findings.filter(f => f.type === type);
    }

    /**
     * Get findings by severity
     */
    getFindingsBySeverity(severity: MobileFindingSeverity): MobileFinding[] {
        return this.findings.filter(f => f.severity === severity);
    }

    /**
     * Get a summary of the scan results
     */
    getSummary(): MobileScanResult {
        const criticalCount = this.findings.filter(f => f.severity === 'critical').length;
        const highCount = this.findings.filter(f => f.severity === 'high').length;
        const mediumCount = this.findings.filter(f => f.severity === 'medium').length;
        const lowCount = this.findings.filter(f => f.severity === 'low').length;
        const infoCount = this.findings.filter(f => f.severity === 'info').length;

        // Calculate score (start at 100, deduct based on severity)
        let score = 100;
        score -= criticalCount * 20;
        score -= highCount * 10;
        score -= mediumCount * 5;
        score -= lowCount * 2;
        score -= infoCount * 0;
        score = Math.max(0, score);

        const urls = Array.from(this.scannedUrls);

        return {
            url: urls[urls.length - 1] || '',
            findings: [...this.findings],
            passed: this.findings.filter(f => f.severity === 'critical' || f.severity === 'high').length === 0,
            score
        };
    }

    /**
     * Run a complete scan on the current page
     * Can be called manually for ad-hoc scanning
     */
    async scan(url: string): Promise<MobileScanResult> {
        if (!this.page) {
            throw new Error('MobileSecurityScanner: No page attached. Call onPageCreated() first.');
        }

        this.scannedUrls.clear();
        this.findings = [];

        logger.info(`  📱 Scanning mobile security on ${url}...`);

        await this.scanPage(url);

        const summary = this.getSummary();

        if (summary.findings.length > 0) {
            logger.warn(`  ⚠️ Found ${summary.findings.length} mobile security issues (Score: ${summary.score})`);
        } else {
            logger.info(`  ✅ Mobile security scan passed (Score: 100)`);
        }

        return summary;
    }
}

export default MobileSecurityScanner;
