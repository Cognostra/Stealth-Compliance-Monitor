/**
 * WebRTC Security Analyzer
 *
 * IScanner that detects WebRTC security issues:
 * - ICE candidate IP leakage (local IP exposure)
 * - Media stream permissions without proper constraints
 * - Insecure STUN/TURN server configurations
 * - Unencrypted RTP (missing DTLS-SRTP)
 * - Data channel security issues
 *
 * Uses page.addInitScript() to shim RTCPeerConnection before page loads,
 * intercepts getUserMedia calls, and monitors RTC configuration.
 */

import type { Page, Request, Response } from 'playwright';
import type { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

export type WebRTCFindingType =
    | 'ice-leak'
    | 'insecure-stun'
    | 'plaintext-rtp'
    | 'weak-dtls'
    | 'media-permission'
    | 'data-channel';

export interface WebRTCFinding {
    type: WebRTCFindingType;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    url: string;
    remediation?: string;
    gdprRelevant: boolean;
    ccpaRelevant: boolean;
}

interface RTCIceCandidate {
    candidate: string;
    sdpMid: string | null;
    sdpMLineIndex: number | null;
}

interface RTCConfiguration {
    iceServers?: Array<{
        urls: string | string[];
        username?: string;
        credential?: string;
    }>;
    iceTransportPolicy?: 'all' | 'relay';
    bundlePolicy?: 'balanced' | 'max-compat' | 'max-bundle';
    rtcpMuxPolicy?: 'require' | 'negotiate';
    iceCandidatePoolSize?: number;
}

// Init script that shims WebRTC APIs to detect security issues
const WEBRTC_INIT_SCRIPT = `
(() => {
    'use strict';

    // Detection storage
    const detections = {
        iceCandidates: [],
        localIps: [],
        insecureStun: [],
        plainTurn: [],
        dtlsDisabled: false,
        weakCipherSuites: [],
        mediaCalls: [],
        dataChannels: [],
        peerConnections: [],
        getUserMediaCalls: [],
    };

    window.__webrtcDetections = detections;

    // Private IP patterns
    const PRIVATE_IP_PATTERNS = [
        /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/,
        /^fc00:/i,
        /^fe80:/i,
        /^169\.254\./,
        /^127\./,
        /^0\./,
        /::1$/,
    ];

    function isPrivateIP(ip) {
        return PRIVATE_IP_PATTERNS.some(pattern => pattern.test(ip));
    }

    function extractIPFromCandidate(candidate) {
        const matches = candidate.match(/(?:typ host|typ srflx).*\s([0-9a-fA-F.:]+)\s/);
        return matches ? matches[1] : null;
    }

    function isInsecureStun(url) {
        if (typeof url !== 'string') return false;
        const lower = url.toLowerCase();
        // Check for public STUN without TURN relay
        return lower.includes('stun:') && !lower.includes('turn:');
    }

    function isPlaintextTurn(url) {
        if (typeof url !== 'string') return false;
        const lower = url.toLowerCase();
        // TURN without TLS
        return lower.includes('turn:') && !lower.includes('turns:');
    }

    // Shim RTCPeerConnection
    if (typeof RTCPeerConnection !== 'undefined') {
        const OriginalRTCPeerConnection = RTCPeerConnection;

        window.RTCPeerConnection = function(configuration) {
            const pcId = 'pc_' + Math.random().toString(36).substr(2, 9);
            const pcInfo = {
                id: pcId,
                createdAt: Date.now(),
                config: configuration || {},
                iceCandidates: [],
                hasStun: false,
                hasTurn: false,
                hasTurns: false,
                dtlsDisabled: false,
                weakDtls: false,
            };

            // Analyze configuration
            if (configuration && configuration.iceServers) {
                for (const server of configuration.iceServers) {
                    const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
                    for (const url of urls) {
                        if (isInsecureStun(url)) {
                            pcInfo.hasStun = true;
                            detections.insecureStun.push({
                                url,
                                pcId,
                                timestamp: Date.now(),
                            });
                        }
                        if (url.toLowerCase().includes('turn:')) {
                            pcInfo.hasTurn = true;
                            if (isPlaintextTurn(url)) {
                                detections.plainTurn.push({
                                    url,
                                    pcId,
                                    timestamp: Date.now(),
                                });
                            }
                        }
                        if (url.toLowerCase().includes('turns:')) {
                            pcInfo.hasTurns = true;
                        }
                    }
                }
            }

            // Check DTLS settings
            if (configuration) {
                // Chrome/Firefox specific: check for deprecated DtlsSrtpKeyAgreement
                if (configuration.optional) {
                    for (const option of configuration.optional) {
                        if (option.DtlsSrtpKeyAgreement === false) {
                            pcInfo.dtlsDisabled = true;
                            detections.dtlsDisabled = true;
                        }
                    }
                }
            }

            // Create the actual peer connection
            const pc = new OriginalRTCPeerConnection(configuration);

            // Monitor ICE candidates
            const originalAddIceCandidate = pc.addIceCandidate;
            pc.addIceCandidate = function(candidate) {
                if (candidate && candidate.candidate) {
                    const ip = extractIPFromCandidate(candidate.candidate);
                    pcInfo.iceCandidates.push(candidate.candidate);
                    
                    if (ip && isPrivateIP(ip)) {
                        detections.localIps.push({
                            ip,
                            candidate: candidate.candidate,
                            pcId,
                            timestamp: Date.now(),
                        });
                    }
                    
                    detections.iceCandidates.push({
                        candidate: candidate.candidate,
                        pcId,
                        timestamp: Date.now(),
                    });
                }
                return originalAddIceCandidate.apply(this, arguments);
            };

            // Monitor connection state for security issues
            pc.addEventListener('iceconnectionstatechange', function() {
                if (pc.iceConnectionState === 'completed' || pc.iceConnectionState === 'connected') {
                    // Connection established - check if using relay
                    const stats = pc.getStats ? pc.getStats() : Promise.resolve([]);
                    // Stats analysis would go here in a real implementation
                }
            });

            // Monitor data channels
            const originalCreateDataChannel = pc.createDataChannel.bind(pc);
            pc.createDataChannel = function(label, options) {
                const channel = originalCreateDataChannel(label, options);
                const channelInfo = {
                    label,
                    options: options || {},
                    pcId,
                    createdAt: Date.now(),
                    negotiated: options?.negotiated || false,
                    id: options?.id,
                };
                detections.dataChannels.push(channelInfo);
                return channel;
            };

            detections.peerConnections.push(pcInfo);
            return pc;
        };

        // Copy prototype and static properties
        window.RTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
        Object.setPrototypeOf(window.RTCPeerConnection, OriginalRTCPeerConnection);
    }

    // Shim getUserMedia to detect media permission requests
    const originalGetUserMedia = navigator.mediaDevices?.getUserMedia;
    if (originalGetUserMedia) {
        navigator.mediaDevices.getUserMedia = function(constraints) {
            const callInfo = {
                timestamp: Date.now(),
                constraints: JSON.parse(JSON.stringify(constraints || {})),
                hasVideo: !!(constraints && constraints.video),
                hasAudio: !!(constraints && constraints.audio),
                weakConstraints: false,
            };

            // Check for weak constraints
            if (constraints) {
                // Video without constraints is suspicious
                if (constraints.video === true) {
                    callInfo.weakConstraints = true;
                }
                // Audio without constraints is suspicious
                if (constraints.audio === true) {
                    callInfo.weakConstraints = true;
                }
                // Check for ideal facingMode which can leak device info
                if (constraints.video && typeof constraints.video === 'object') {
                    if (constraints.video.facingMode) {
                        callInfo.weakConstraints = true;
                    }
                }
            }

            detections.getUserMediaCalls.push(callInfo);
            return originalGetUserMedia.call(this, constraints);
        };
    }

    // Shim legacy getUserMedia
    if (navigator.getUserMedia) {
        const originalLegacyGUM = navigator.getUserMedia.bind(navigator);
        navigator.getUserMedia = function(constraints, success, error) {
            detections.getUserMediaCalls.push({
                timestamp: Date.now(),
                constraints: JSON.parse(JSON.stringify(constraints || {})),
                hasVideo: !!(constraints && constraints.video),
                hasAudio: !!(constraints && constraints.audio),
                weakConstraints: constraints && (constraints.video === true || constraints.audio === true),
                legacy: true,
            });
            return originalLegacyGUM(constraints, success, error);
        };
    }

    // Monitor enumerateDevices for device fingerprinting
    if (navigator.mediaDevices?.enumerateDevices) {
        const originalEnumerateDevices = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
        navigator.mediaDevices.enumerateDevices = function() {
            return originalEnumerateDevices().then(devices => {
                // Flag if devices are enumerated without user interaction
                detections.mediaCalls.push({
                    type: 'enumerateDevices',
                    deviceCount: devices.length,
                    timestamp: Date.now(),
                    devices: devices.map(d => ({ kind: d.kind, label: d.label ? 'labeled' : 'unlabeled' })),
                });
                return devices;
            });
        };
    }
})();
`;

export class WebRTCAnalyzer implements IScanner {
    readonly name = 'WebRTCAnalyzer';
    private findings: WebRTCFinding[] = [];
    private pages: WeakSet<Page> = new WeakSet();
    private injectedPages: WeakSet<Page> = new WeakSet();

    onPageCreated(page: Page): void {
        if (this.pages.has(page)) return;
        this.pages.add(page);
        logger.debug('[WebRTCAnalyzer] Attached to page');
    }

    /**
     * Inject WebRTC detection shims before page navigation.
     * Must be called before page.goto().
     */
    async injectDetectionShims(page: Page): Promise<void> {
        if (this.injectedPages.has(page)) return;
        try {
            await page.addInitScript(WEBRTC_INIT_SCRIPT);
            this.injectedPages.add(page);
            logger.debug('[WebRTCAnalyzer] Injected detection shims');
        } catch {
            logger.debug('[WebRTCAnalyzer] Failed to inject shims');
        }
    }

    /**
     * Collect WebRTC detections after page has loaded and executed scripts.
     */
    async collectDetections(page: Page): Promise<WebRTCFinding[]> {
        const newFindings: WebRTCFinding[] = [];
        const url = page.url();

        try {
            const detections = await page.evaluate(() => {
                const d = (window as unknown as Record<string, unknown>).__webrtcDetections as {
                    iceCandidates: Array<{ candidate: string; pcId: string; timestamp: number }>;
                    localIps: Array<{ ip: string; candidate: string; pcId: string; timestamp: number }>;
                    insecureStun: Array<{ url: string; pcId: string; timestamp: number }>;
                    plainTurn: Array<{ url: string; pcId: string; timestamp: number }>;
                    dtlsDisabled: boolean;
                    weakCipherSuites: string[];
                    mediaCalls: Array<{ type: string; deviceCount: number; timestamp: number; devices: Array<{ kind: string; label: string }> }>;
                    dataChannels: Array<{ label: string; options: Record<string, unknown>; pcId: string; createdAt: number; negotiated: boolean; id?: number }>;
                    peerConnections: Array<{
                        id: string;
                        createdAt: number;
                        config: RTCConfiguration;
                        iceCandidates: string[];
                        hasStun: boolean;
                        hasTurn: boolean;
                        hasTurns: boolean;
                        dtlsDisabled: boolean;
                        weakDtls: boolean;
                    }>;
                    getUserMediaCalls: Array<{
                        timestamp: number;
                        constraints: Record<string, unknown>;
                        hasVideo: boolean;
                        hasAudio: boolean;
                        weakConstraints: boolean;
                        legacy?: boolean;
                    }>;
                } | undefined;
                return d;
            });

            if (!detections) return newFindings;

            // 1. ICE Candidate IP Leakage (local IP exposure)
            if (detections.localIps.length > 0) {
                const uniqueIps = [...new Set(detections.localIps.map(item => item.ip))];
                const finding: WebRTCFinding = {
                    type: 'ice-leak',
                    severity: 'high',
                    description: `WebRTC ICE candidates leaking ${uniqueIps.length} local IP address(es) - can be used for device fingerprinting and tracking`,
                    evidence: `Local IPs exposed: ${uniqueIps.join(', ')}. Total ${detections.localIps.length} candidates with private IPs.`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'Configure RTCPeerConnection with iceTransportPolicy: "relay" to force TURN relay, or use a STUN/TURN server that filters local candidates. Consider using mDNS (.local) candidates instead of IP addresses.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // 2. Insecure STUN server configuration
            if (detections.insecureStun.length > 0) {
                const uniqueStun = [...new Set(detections.insecureStun.map(item => item.url))];
                const finding: WebRTCFinding = {
                    type: 'insecure-stun',
                    severity: 'medium',
                    description: `WebRTC using public STUN servers without TURN relay - exposes public IP address`,
                    evidence: `STUN servers used: ${uniqueStun.slice(0, 5).join(', ')}${uniqueStun.length > 5 ? ` and ${uniqueStun.length - 5} more` : ''}`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'Use TURN servers with relay transport to hide client IP addresses. If STUN is necessary, ensure it is combined with proper consent mechanisms.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // 3. Plaintext TURN servers
            if (detections.plainTurn.length > 0) {
                const uniquePlainTurn = [...new Set(detections.plainTurn.map(item => item.url))];
                const finding: WebRTCFinding = {
                    type: 'insecure-stun',
                    severity: 'high',
                    description: `TURN servers configured without TLS/DTLS encryption (turn: instead of turns:)`,
                    evidence: `Plaintext TURN servers: ${uniquePlainTurn.slice(0, 5).join(', ')}${uniquePlainTurn.length > 5 ? ` and ${uniquePlainTurn.length - 5} more` : ''}`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'Configure TURN servers with turns: (TLS) or turn: with DTLS. Plaintext TURN exposes relay traffic to network sniffing.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // 4. DTLS disabled or weak
            if (detections.dtlsDisabled) {
                const finding: WebRTCFinding = {
                    type: 'weak-dtls',
                    severity: 'critical',
                    description: 'WebRTC configured with DTLS-SRTP disabled - RTP media will be transmitted unencrypted',
                    evidence: 'RTCPeerConnection configuration explicitly disables DtlsSrtpKeyAgreement',
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'Remove DtlsSrtpKeyAgreement: false from RTCPeerConnection optional constraints. Modern browsers require DTLS-SRTP, this may cause connection failures.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // Check for missing DTLS-SRTP indication in peer connections
            const weakDtlsConfigs = detections.peerConnections.filter(
                pc => pc.config && !pc.hasTurns && !pc.hasTurn && pc.hasStun
            );
            if (weakDtlsConfigs.length > 0 && detections.localIps.length === 0) {
                const finding: WebRTCFinding = {
                    type: 'weak-dtls',
                    severity: 'medium',
                    description: 'WebRTC configuration relies solely on STUN without encrypted transport verification',
                    evidence: `${weakDtlsConfigs.length} peer connection(s) using STUN-only configuration`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: false,
                    remediation: 'Verify that DTLS-SRTP is enabled by checking getStats() for DTLS cipher suite. Ensure SDES (deprecated) is not being negotiated.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // 5. Media permission issues
            const weakMediaCalls = detections.getUserMediaCalls.filter(call => call.weakConstraints);
            if (weakMediaCalls.length > 0) {
                const finding: WebRTCFinding = {
                    type: 'media-permission',
                    severity: 'medium',
                    description: `getUserMedia called ${weakMediaCalls.length} time(s) with weak or missing constraints`,
                    evidence: `Media calls without proper constraints may request maximum resolution/audio quality without user control`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'Always specify explicit constraints in getUserMedia calls. Use { video: { width: { ideal: 1280 }, height: { ideal: 720 } } } instead of { video: true }. Avoid requesting facingMode unless necessary.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // Legacy getUserMedia usage
            const legacyCalls = detections.getUserMediaCalls.filter(call => call.legacy);
            if (legacyCalls.length > 0) {
                const finding: WebRTCFinding = {
                    type: 'media-permission',
                    severity: 'low',
                    description: 'Legacy navigator.getUserMedia API used instead of modern navigator.mediaDevices.getUserMedia',
                    evidence: `${legacyCalls.length} legacy getUserMedia call(s) detected`,
                    url,
                    gdprRelevant: false,
                    ccpaRelevant: false,
                    remediation: 'Migrate to navigator.mediaDevices.getUserMedia() for better security and Promise-based API.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // 6. Data channel security
            if (detections.dataChannels.length > 0) {
                const negotiatedChannels = detections.dataChannels.filter(ch => ch.negotiated);
                const unlabeledChannels = detections.dataChannels.filter(ch => !ch.label || ch.label === '');

                if (negotiatedChannels.length > 0) {
                    const finding: WebRTCFinding = {
                        type: 'data-channel',
                        severity: 'medium',
                        description: `WebRTC data channels created with negotiated=true (${negotiatedChannels.length}) - bypasses SDP signaling`,
                        evidence: `Negotiated data channels: ${negotiatedChannels.map(ch => ch.label || 'unnamed').join(', ')}`,
                        url,
                        gdprRelevant: false,
                        ccpaRelevant: false,
                        remediation: 'Negotiated data channels skip SDP exchange, which can be used to bypass security gateways. Ensure out-of-band negotiation is authenticated.',
                    };
                    this.addFinding(finding);
                    newFindings.push(finding);
                }

                // Check for ordered=false and maxRetransmits=0 (unreliable, unordered - DoS risk)
                const unreliableChannels = detections.dataChannels.filter(
                    ch => ch.options && (ch.options.ordered === false || ch.options.maxRetransmits === 0)
                );
                if (unreliableChannels.length > 0) {
                    const finding: WebRTCFinding = {
                        type: 'data-channel',
                        severity: 'low',
                        description: `Unreliable data channels detected (${unreliableChannels.length}) - potential for DoS via packet flooding`,
                        evidence: `Unreliable channels: ${unreliableChannels.map(ch => ch.label || 'unnamed').join(', ')}`,
                        url,
                        gdprRelevant: false,
                        ccpaRelevant: false,
                        remediation: 'Unreliable (unordered or maxRetransmits=0) data channels can be flooded. Implement application-level rate limiting.',
                    };
                    this.addFinding(finding);
                    newFindings.push(finding);
                }
            }

            // Additional: Check for plaintext RTP (no DTLS-SRTP) by analyzing peer connection state
            const plaintextCandidates = detections.iceCandidates.filter(
                cand => cand.candidate.includes('typ host') || cand.candidate.includes('typ srflx')
            );
            if (
                plaintextCandidates.length > 0 &&
                !detections.dtlsDisabled &&
                detections.peerConnections.some(pc => !pc.hasTurns && !pc.hasTurn)
            ) {
                // This is a warning that media might be flowing without encryption
                // We can't definitively know without checking getStats(), but we can flag the risk
                const finding: WebRTCFinding = {
                    type: 'plaintext-rtp',
                    severity: 'medium',
                    description: 'Potential unencrypted RTP traffic - peer connections established without TURN and using direct host/srflx candidates',
                    evidence: `${plaintextCandidates.length} direct ICE candidates. Verify DTLS-SRTP is negotiated by checking chrome://webrtc-internals or equivalent.`,
                    url,
                    gdprRelevant: true,
                    ccpaRelevant: true,
                    remediation: 'Ensure DTLS-SRTP is enabled (default in modern browsers). Check that SDES cipher suites are not being negotiated. Use wireshark or webrtc-internals to verify encryption.',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }
        } catch (error) {
            logger.debug(`[WebRTCAnalyzer] Error collecting detections: ${error}`);
        }

        return newFindings;
    }

    private addFinding(finding: WebRTCFinding): void {
        const key = `${finding.type}:${finding.url}:${finding.evidence.substring(0, 50)}`;
        if (!this.findings.some(f => `${f.type}:${f.url}:${f.evidence.substring(0, 50)}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): WebRTCFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
    }

    onClose(): void {
        logger.info(`  [WebRTC] ${this.findings.length} security issues detected`);
    }
}
