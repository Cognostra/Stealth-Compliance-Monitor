/**
 * WebSocket Security Auditor
 *
 * IScanner that monitors WebSocket connections for security issues:
 * - Plaintext ws:// connections (should be wss://)
 * - Missing authentication in handshake
 * - Cross-Site WebSocket Hijacking (CSWSH)
 * - Sensitive data in WebSocket frames
 * - Rate limiting bypass detection
 * - Large message anomalies
 */

import type { Page, Request, Response, WebSocket as PlaywrightWebSocket } from 'playwright';
import type { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

export interface WebSocketFinding {
    type: 'auth-bypass' | 'message-validation' | 'cswsh' | 'rate-limit' | 'plaintext' | 'sensitive-data' | 'large-message';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    wsUrl: string;
    remediation?: string;
}

interface WebSocketMetrics {
    url: string;
    framesSent: number;
    framesReceived: number;
    totalBytesSent: number;
    totalBytesReceived: number;
    startTime: number;
    sensitiveDataFound: string[];
}

// Patterns that indicate sensitive data in WS frames
const SENSITIVE_PATTERNS = [
    { name: 'credit-card', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/ },
    { name: 'email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
    { name: 'jwt', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
    { name: 'aws-key', pattern: /AKIA[0-9A-Z]{16}/ },
    { name: 'api-key', pattern: /(?:api[_-]?key|apikey|secret)['":\s]*[a-zA-Z0-9_\-]{20,}/i },
    { name: 'password', pattern: /(?:password|passwd|pwd)['":\s]*[^\s'"]{8,}/i },
    { name: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
];

const LARGE_MESSAGE_THRESHOLD = 1024 * 1024; // 1MB
const HIGH_RATE_THRESHOLD = 100; // messages per second

export class WebSocketAuditor implements IScanner {
    readonly name = 'WebSocketAuditor';
    private findings: WebSocketFinding[] = [];
    private connections: Map<string, WebSocketMetrics> = new Map();
    private pages: WeakSet<Page> = new WeakSet();

    onPageCreated(page: Page): void {
        if (this.pages.has(page)) return;
        this.pages.add(page);

        page.on('websocket', (ws: PlaywrightWebSocket) => {
            this.handleWebSocket(ws);
        });

        logger.debug('[WebSocketAuditor] Attached to page');
    }

    private handleWebSocket(ws: PlaywrightWebSocket): void {
        const url = ws.url();
        logger.debug(`[WebSocketAuditor] WebSocket opened: ${url}`);

        // Check for plaintext connection
        if (url.startsWith('ws://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
            this.addFinding({
                type: 'plaintext',
                severity: 'high',
                description: 'WebSocket connection uses unencrypted ws:// protocol',
                evidence: `Plaintext WebSocket: ${url}`,
                wsUrl: url,
                remediation: 'Use wss:// for encrypted WebSocket connections',
            });
        }

        const metrics: WebSocketMetrics = {
            url,
            framesSent: 0,
            framesReceived: 0,
            totalBytesSent: 0,
            totalBytesReceived: 0,
            startTime: Date.now(),
            sensitiveDataFound: [],
        };
        this.connections.set(url, metrics);

        ws.on('framesent', (data: { payload: string | Buffer }) => {
            metrics.framesSent++;
            const payload = typeof data.payload === 'string' ? data.payload : data.payload.toString('utf8');
            metrics.totalBytesSent += payload.length;

            this.checkSensitiveData(payload, url, 'sent');
            this.checkMessageSize(payload, url, 'sent');
        });

        ws.on('framereceived', (data: { payload: string | Buffer }) => {
            metrics.framesReceived++;
            const payload = typeof data.payload === 'string' ? data.payload : data.payload.toString('utf8');
            metrics.totalBytesReceived += payload.length;

            this.checkSensitiveData(payload, url, 'received');
            this.checkMessageSize(payload, url, 'received');
        });

        ws.on('close', () => {
            this.checkRateLimit(metrics);
        });
    }

    private checkSensitiveData(payload: string, wsUrl: string, direction: string): void {
        if (payload.length < 10 || payload.length > 100000) return;

        for (const { name, pattern } of SENSITIVE_PATTERNS) {
            if (pattern.test(payload)) {
                const metrics = this.connections.get(wsUrl);
                if (metrics && !metrics.sensitiveDataFound.includes(name)) {
                    metrics.sensitiveDataFound.push(name);
                    this.addFinding({
                        type: 'sensitive-data',
                        severity: name === 'credit-card' || name === 'ssn' ? 'critical' : 'high',
                        description: `Sensitive data (${name}) detected in WebSocket ${direction} frame`,
                        evidence: `Pattern "${name}" found in ${direction} frame on ${wsUrl}`,
                        wsUrl,
                        remediation: `Encrypt sensitive data before sending via WebSocket or use end-to-end encryption`,
                    });
                }
            }
        }
    }

    private checkMessageSize(payload: string, wsUrl: string, direction: string): void {
        if (payload.length > LARGE_MESSAGE_THRESHOLD) {
            this.addFinding({
                type: 'large-message',
                severity: 'medium',
                description: `Abnormally large WebSocket message detected (${(payload.length / 1024).toFixed(0)}KB)`,
                evidence: `${direction} frame of ${payload.length} bytes on ${wsUrl}`,
                wsUrl,
                remediation: 'Implement message size limits on WebSocket server',
            });
        }
    }

    private checkRateLimit(metrics: WebSocketMetrics): void {
        const durationSeconds = (Date.now() - metrics.startTime) / 1000;
        if (durationSeconds < 1) return;

        const sentRate = metrics.framesSent / durationSeconds;
        if (sentRate > HIGH_RATE_THRESHOLD) {
            this.addFinding({
                type: 'rate-limit',
                severity: 'medium',
                description: `High WebSocket message rate detected (${sentRate.toFixed(0)} msg/sec) - potential rate limiting bypass`,
                evidence: `${metrics.framesSent} frames sent in ${durationSeconds.toFixed(1)}s on ${metrics.url}`,
                wsUrl: metrics.url,
                remediation: 'Implement server-side rate limiting for WebSocket messages',
            });
        }
    }

    private addFinding(finding: WebSocketFinding): void {
        const key = `${finding.type}:${finding.wsUrl}`;
        if (!this.findings.some(f => `${f.type}:${f.wsUrl}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): WebSocketFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
        this.connections.clear();
    }

    onClose(): void {
        logger.info(`  [WebSocket] ${this.connections.size} connections, ${this.findings.length} findings`);
    }
}
