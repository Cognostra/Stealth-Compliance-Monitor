/**
 * Behavioral Fingerprinting Detection
 *
 * IScanner that detects browser fingerprinting techniques used by websites:
 * - Canvas fingerprinting (toDataURL, getImageData)
 * - WebGL fingerprinting (getParameter, getExtension)
 * - AudioContext fingerprinting (createOscillator, createDynamicsCompressor)
 * - Battery API usage
 * - Font enumeration
 * - Screen/display fingerprinting
 * - MediaDevices enumeration
 *
 * Uses page.addInitScript() to shim fingerprinting APIs before page loads,
 * then reads detection flags via page.evaluate().
 */

import type { Page, Request, Response } from 'playwright';
import type { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

export interface FingerprintFinding {
    type: 'canvas' | 'webgl' | 'audio' | 'battery' | 'font-enum' | 'screen' | 'media-devices' | 'webrtc-fingerprint';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    url: string;
    gdprRelevant: boolean;
    ccpaRelevant: boolean;
    remediation?: string;
}

const FINGERPRINT_INIT_SCRIPT = `
(() => {
    const fp = {
        canvas: { calls: 0, contexts: [] },
        webgl: { calls: 0, params: [] },
        audio: { calls: 0 },
        battery: { calls: 0 },
        fonts: { calls: 0, tested: [] },
        screen: { calls: 0, props: [] },
        mediaDevices: { calls: 0 },
        webrtc: { calls: 0 },
    };

    window.__fingerprintDetections = fp;

    // Canvas fingerprinting detection
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
        const canvas = this;
        // Only flag if canvas has been drawn to (not empty canvases)
        if (canvas.width > 0 && canvas.height > 0) {
            fp.canvas.calls++;
            fp.canvas.contexts.push('toDataURL');
        }
        return origToDataURL.apply(this, args);
    };

    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(...args) {
        fp.canvas.calls++;
        fp.canvas.contexts.push('getImageData');
        return origGetImageData.apply(this, args);
    };

    // WebGL fingerprinting detection
    const shimWebGLParam = (proto) => {
        if (!proto) return;
        const origGetParam = proto.getParameter;
        if (origGetParam) {
            proto.getParameter = function(pname) {
                fp.webgl.calls++;
                fp.webgl.params.push(pname);
                return origGetParam.call(this, pname);
            };
        }
        const origGetExtension = proto.getExtension;
        if (origGetExtension) {
            proto.getExtension = function(name) {
                fp.webgl.calls++;
                return origGetExtension.call(this, name);
            };
        }
    };

    if (typeof WebGLRenderingContext !== 'undefined') {
        shimWebGLParam(WebGLRenderingContext.prototype);
    }
    if (typeof WebGL2RenderingContext !== 'undefined') {
        shimWebGLParam(WebGL2RenderingContext.prototype);
    }

    // AudioContext fingerprinting detection
    if (typeof AudioContext !== 'undefined' || typeof webkitAudioContext !== 'undefined') {
        const AC = typeof AudioContext !== 'undefined' ? AudioContext : webkitAudioContext;
        const origCreateOscillator = AC.prototype.createOscillator;
        if (origCreateOscillator) {
            AC.prototype.createOscillator = function() {
                fp.audio.calls++;
                return origCreateOscillator.call(this);
            };
        }
        const origCreateDynamicsCompressor = AC.prototype.createDynamicsCompressor;
        if (origCreateDynamicsCompressor) {
            AC.prototype.createDynamicsCompressor = function() {
                fp.audio.calls++;
                return origCreateDynamicsCompressor.call(this);
            };
        }
    }

    // Battery API detection
    if (navigator.getBattery) {
        const origGetBattery = navigator.getBattery.bind(navigator);
        navigator.getBattery = function() {
            fp.battery.calls++;
            return origGetBattery();
        };
    }

    // Font enumeration detection via measureText
    const origMeasureText = CanvasRenderingContext2D.prototype.measureText;
    let lastFontChange = '';
    const origSetFont = Object.getOwnPropertyDescriptor(CanvasRenderingContext2D.prototype, 'font');
    if (origSetFont?.set) {
        Object.defineProperty(CanvasRenderingContext2D.prototype, 'font', {
            ...origSetFont,
            set(value) {
                lastFontChange = value;
                return origSetFont.set.call(this, value);
            },
        });
    }
    CanvasRenderingContext2D.prototype.measureText = function(text) {
        if (lastFontChange && fp.fonts.tested.length < 50) {
            fp.fonts.calls++;
            fp.fonts.tested.push(lastFontChange);
            lastFontChange = '';
        }
        return origMeasureText.call(this, text);
    };

    // Screen property access detection
    const screenProps = ['width', 'height', 'colorDepth', 'pixelDepth', 'availWidth', 'availHeight'];
    for (const prop of screenProps) {
        const desc = Object.getOwnPropertyDescriptor(Screen.prototype, prop) ||
                     Object.getOwnPropertyDescriptor(screen, prop);
        if (desc?.get) {
            const origGet = desc.get;
            Object.defineProperty(screen, prop, {
                get() {
                    fp.screen.calls++;
                    fp.screen.props.push(prop);
                    return origGet.call(this);
                },
                configurable: true,
            });
        }
    }

    // MediaDevices enumeration detection
    if (navigator.mediaDevices?.enumerateDevices) {
        const origEnumerate = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
        navigator.mediaDevices.enumerateDevices = function() {
            fp.mediaDevices.calls++;
            return origEnumerate();
        };
    }

    // WebRTC fingerprinting detection (ICE candidates)
    if (typeof RTCPeerConnection !== 'undefined') {
        const OrigRTC = RTCPeerConnection;
        window.RTCPeerConnection = function(...args) {
            fp.webrtc.calls++;
            return new OrigRTC(...args);
        };
        window.RTCPeerConnection.prototype = OrigRTC.prototype;
    }
})();
`;

// Threshold for number of font probes that indicates enumeration
const FONT_ENUM_THRESHOLD = 10;
// Threshold for screen property accesses
const SCREEN_ACCESS_THRESHOLD = 4;

export class FingerprintDetector implements IScanner {
    readonly name = 'FingerprintDetector';
    private findings: FingerprintFinding[] = [];
    private pages: WeakSet<Page> = new WeakSet();
    private injectedPages: WeakSet<Page> = new WeakSet();

    onPageCreated(page: Page): void {
        if (this.pages.has(page)) return;
        this.pages.add(page);
        logger.debug('[FingerprintDetector] Attached to page');
    }

    /**
     * Inject fingerprint detection shims before page navigation.
     * Must be called before page.goto().
     */
    async injectDetectionShims(page: Page): Promise<void> {
        if (this.injectedPages.has(page)) return;
        try {
            await page.addInitScript(FINGERPRINT_INIT_SCRIPT);
            this.injectedPages.add(page);
            logger.debug('[FingerprintDetector] Injected detection shims');
        } catch {
            logger.debug('[FingerprintDetector] Failed to inject shims');
        }
    }

    /**
     * Collect fingerprint detections after page has loaded and executed scripts.
     */
    async collectDetections(page: Page): Promise<FingerprintFinding[]> {
        const newFindings: FingerprintFinding[] = [];
        const url = page.url();

        try {
            const detections = await page.evaluate(() =>
                (window as unknown as Record<string, unknown>).__fingerprintDetections as {
                    canvas: { calls: number; contexts: string[] };
                    webgl: { calls: number; params: number[] };
                    audio: { calls: number };
                    battery: { calls: number };
                    fonts: { calls: number; tested: string[] };
                    screen: { calls: number; props: string[] };
                    mediaDevices: { calls: number };
                    webrtc: { calls: number };
                } | undefined
            );

            if (!detections) return newFindings;

            // Canvas fingerprinting
            if (detections.canvas.calls > 0) {
                const finding: FingerprintFinding = {
                    type: 'canvas',
                    severity: 'high',
                    description: 'Canvas fingerprinting detected - page reads canvas pixel data for device identification',
                    evidence: `${detections.canvas.calls} canvas read calls: ${detections.canvas.contexts.slice(0, 5).join(', ')}`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'Canvas fingerprinting requires explicit user consent under GDPR. Provide opt-out mechanism.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // WebGL fingerprinting
            if (detections.webgl.calls > 3) {
                const finding: FingerprintFinding = {
                    type: 'webgl',
                    severity: 'medium',
                    description: 'WebGL fingerprinting detected - page queries GPU/renderer info for device identification',
                    evidence: `${detections.webgl.calls} WebGL parameter queries`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'WebGL fingerprinting is a tracking technique requiring consent. Use feature detection instead.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // AudioContext fingerprinting
            if (detections.audio.calls > 0) {
                const finding: FingerprintFinding = {
                    type: 'audio',
                    severity: 'high',
                    description: 'AudioContext fingerprinting detected - creates oscillator/compressor to generate audio fingerprint',
                    evidence: `${detections.audio.calls} AudioContext API calls used for fingerprinting`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'Audio fingerprinting is a sophisticated tracking technique. Requires explicit consent under GDPR.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // Battery API
            if (detections.battery.calls > 0) {
                const finding: FingerprintFinding = {
                    type: 'battery',
                    severity: 'medium',
                    description: 'Battery API usage detected - can be used for cross-site tracking via battery level/charging status',
                    evidence: `${detections.battery.calls} navigator.getBattery() calls`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'Battery API is deprecated in most browsers due to privacy concerns. Remove usage.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // Font enumeration
            if (detections.fonts.calls > FONT_ENUM_THRESHOLD) {
                const finding: FingerprintFinding = {
                    type: 'font-enum',
                    severity: 'medium',
                    description: `Font enumeration detected - page probed ${detections.fonts.calls} fonts for fingerprinting`,
                    evidence: `${detections.fonts.calls} font measurements, fonts tested: ${detections.fonts.tested.slice(0, 5).join(', ')}...`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'Font enumeration creates a unique fingerprint. Use standard web fonts and avoid probing installed fonts.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // Screen fingerprinting
            if (detections.screen.calls > SCREEN_ACCESS_THRESHOLD) {
                const uniqueProps = [...new Set(detections.screen.props)];
                if (uniqueProps.length >= 3) {
                    const finding: FingerprintFinding = {
                        type: 'screen',
                        severity: 'low',
                        description: 'Screen property enumeration detected - multiple screen properties accessed for fingerprinting',
                        evidence: `${detections.screen.calls} screen property reads: ${uniqueProps.join(', ')}`,
                        url,
                        gdprRelevant: true,
                        ccpaRelevant: false,
                        remediation: 'Accessing multiple screen properties can contribute to fingerprinting. Only access properties needed for layout.',
                    };
                    this.addFinding(finding);
                    newFindings.push(finding);
                }
            }

            // MediaDevices enumeration
            if (detections.mediaDevices.calls > 0) {
                const finding: FingerprintFinding = {
                    type: 'media-devices',
                    severity: 'medium',
                    description: 'MediaDevices enumeration detected - enumerating audio/video devices for fingerprinting',
                    evidence: `${detections.mediaDevices.calls} enumerateDevices() calls`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'MediaDevices.enumerateDevices() reveals connected hardware. Requires user consent for media access.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // WebRTC fingerprinting
            if (detections.webrtc.calls > 0) {
                const finding: FingerprintFinding = {
                    type: 'webrtc-fingerprint',
                    severity: 'high',
                    description: 'WebRTC used potentially for IP address fingerprinting via ICE candidates',
                    evidence: `${detections.webrtc.calls} RTCPeerConnection instantiations`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'WebRTC can leak local IP addresses. Implement RTCPeerConnection proxy or disable if not needed.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }
        } catch {
            // Page may have navigated
        }

        return newFindings;
    }

    private addFinding(finding: FingerprintFinding): void {
        const key = `${finding.type}:${finding.url}`;
        if (!this.findings.some(f => `${f.type}:${f.url}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): FingerprintFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
    }

    onClose(): void {
        logger.info(`  [Fingerprint] ${this.findings.length} fingerprinting techniques detected`);
    }
}
