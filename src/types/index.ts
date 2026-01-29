/**
 * LSCM Type Definitions
 * Core interfaces and types for the Live-Site Compliance Monitor
 */

// Configuration Types
export interface LscmConfig {
    liveUrl: string;
    testUserEmail: string;
    testUserPass: string;
    zapApiKey?: string;
    zapProxyHost: string;
    zapProxyPort: number;
    minDelayMs: number;
    maxDelayMs: number;
    screenshotsDir: string;
    reportsDir: string;
    userAgent: string;
}

// Audit Result Types
export interface AuditReport {
    timestamp: string;
    targetUrl: string;
    duration: number;
    performance: PerformanceMetrics;
    accessibility: AccessibilityMetrics;
    security: SecurityMetrics;
    userFlows: UserFlowResult[];
    overallScore: number;
    passed: boolean;
}

export interface PerformanceMetrics {
    score: number;
    firstContentfulPaint: number;
    largestContentfulPaint: number;
    totalBlockingTime: number;
    cumulativeLayoutShift: number;
    speedIndex: number;
    timeToInteractive: number;
}

export interface AccessibilityMetrics {
    score: number;
    issues: AccessibilityIssue[];
}

export interface AccessibilityIssue {
    id: string;
    impact: 'critical' | 'serious' | 'moderate' | 'minor';
    description: string;
    helpUrl?: string;
}

export interface SecurityMetrics {
    score: number;
    headers: SecurityHeader[];
    alerts: SecurityAlert[];
    passiveOnly: boolean;
}

export interface PerformanceBudget {
    minScore: number;
    maxLCP?: number; // milliseconds
    maxCLS?: number;
    maxTBT?: number; // milliseconds
}

export interface SecurityHeader {
    name: string;
    present: boolean;
    value?: string;
    recommendation?: string;
}

export interface SecurityAlert {
    risk: 'High' | 'Medium' | 'Low' | 'Informational';
    name: string;
    description: string;
    url: string;
    solution?: string;
}

// User Flow Types
export interface UserFlowResult {
    name: string;
    steps: FlowStepResult[];
    passed: boolean;
    duration: number;
    screenshotPath?: string;
}

export interface FlowStepResult {
    name: string;
    action: string;
    selector?: string;
    passed: boolean;
    error?: string;
    duration: number;
}

export interface FlowStep {
    name: string;
    action: 'navigate' | 'click' | 'type' | 'wait' | 'verify' | 'screenshot';
    selector?: string;
    value?: string;
    timeout?: number;
}

export interface UserFlow {
    name: string;
    description: string;
    steps: FlowStep[];
}

// Service Types
export interface BrowserService {
    initialize(): Promise<void>;
    navigate(url: string): Promise<void>;
    click(selector: string): Promise<void>;
    type(selector: string, text: string): Promise<void>;
    waitForSelector(selector: string, timeout?: number): Promise<void>;
    screenshot(name: string): Promise<string>;
    getSecurityHeaders(): Promise<SecurityHeader[]>;
    close(): Promise<void>;
}

export interface LighthouseService {
    runAudit(url: string): Promise<{
        performance: PerformanceMetrics;
        accessibility: AccessibilityMetrics;
    }>;
}

export interface ZapService {
    initialize(): Promise<void>;
    getAlerts(url: string): Promise<SecurityAlert[]>;
    isPassiveMode(): boolean;
    close(): Promise<void>;
}

// Logger Types
// Electron Auditing Types
export interface ElectronSecurityFinding {
    type: 'node-integration' | 'context-isolation' | 'ipc-exposure' | 'remote-module' | 'missing-csp';
    severity: 'critical' | 'high' | 'medium';
    description: string;
    remediation: string;
}

// Flutter Semantics Types
export interface FlutterSemanticsIssue {
    type: 'missing-semantics' | 'incomplete-aria' | 'missing-focus' | 'missing-label' | 'missing-role' | 'missing-live-region';
    severity: 'high' | 'medium' | 'low';
    element: string;
    description: string;
    url?: string;
}

export type LogLevel = 'info' | 'warn' | 'error' | 'debug';

export interface Logger {
    info(message: string, meta?: Record<string, unknown>): void;
    warn(message: string, meta?: Record<string, unknown>): void;
    error(message: string, meta?: Record<string, unknown>): void;
    debug(message: string, meta?: Record<string, unknown>): void;
}
