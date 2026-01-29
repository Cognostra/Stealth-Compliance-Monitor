/**
 * ElectronBrowserService - Electron App Auditing
 *
 * Uses Playwright's electron.launch() to attach to a local Electron
 * executable and run the same scanning pipeline on its renderer pages.
 *
 * The Page returned is a standard Playwright Page object, so all
 * existing scanners and checks work without modification.
 *
 * Additionally performs Electron-specific security checks:
 * - nodeIntegration enabled in renderer (CRITICAL)
 * - contextIsolation disabled (HIGH)
 * - Remote module enabled (HIGH)
 * - Exposed IPC channels (MEDIUM)
 * - Missing CSP in Electron (MEDIUM)
 */

import { _electron as electron, ElectronApplication, Page } from 'playwright';
import { logger } from '../utils/logger.js';
import { ElectronSecurityFinding } from '../types/index.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface ElectronLaunchOptions {
    /** Path to the Electron app executable or directory */
    executablePath: string;
    /** Extra arguments to pass to the Electron app */
    args?: string[];
    /** Environment variables to pass to the app */
    env?: Record<string, string>;
    /** Timeout for app launch (ms) */
    timeout?: number;
}

export interface ElectronAuditResult {
    /** The main window Page object for scanning */
    page: Page;
    /** Electron-specific security findings */
    securityFindings: ElectronSecurityFinding[];
    /** App metadata */
    appInfo: {
        name?: string;
        version?: string;
        electronVersion?: string;
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class ElectronBrowserService {
    private app: ElectronApplication | null = null;
    private mainWindow: Page | null = null;
    private securityFindings: ElectronSecurityFinding[] = [];

    /**
     * Launch the Electron app and get the main window.
     */
    async launch(options: ElectronLaunchOptions): Promise<ElectronAuditResult> {
        const timeout = options.timeout || 30000;

        logger.info(`Launching Electron app: ${options.executablePath}`);

        this.app = await electron.launch({
            executablePath: options.executablePath,
            args: options.args || [],
            env: {
                ...process.env,
                ...options.env,
            },
            timeout,
        });

        // Wait for the first BrowserWindow to open
        this.mainWindow = await this.app.firstWindow();
        logger.info(`Electron app launched, main window URL: ${this.mainWindow.url()}`);

        // Wait for initial load
        await this.mainWindow.waitForLoadState('domcontentloaded');

        // Gather app info
        const appInfo = await this.getAppInfo();

        // Run Electron-specific security checks
        this.securityFindings = await this.runElectronSecurityChecks();

        return {
            page: this.mainWindow,
            securityFindings: this.securityFindings,
            appInfo,
        };
    }

    /**
     * Get all open windows/pages in the Electron app.
     */
    async getPages(): Promise<Page[]> {
        if (!this.app) throw new Error('Electron app not launched');
        return this.app.windows();
    }

    /**
     * Get the main window page.
     */
    getMainWindow(): Page | null {
        return this.mainWindow;
    }

    /**
     * Get collected Electron-specific security findings.
     */
    getSecurityFindings(): ElectronSecurityFinding[] {
        return [...this.securityFindings];
    }

    /**
     * Close the Electron app.
     */
    async close(): Promise<void> {
        if (this.app) {
            try {
                await this.app.close();
            } catch (error) {
                logger.warn(`Error closing Electron app: ${error instanceof Error ? error.message : String(error)}`);
            }
            this.app = null;
            this.mainWindow = null;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // APP INFO
    // ═══════════════════════════════════════════════════════════════════════════

    private async getAppInfo(): Promise<ElectronAuditResult['appInfo']> {
        if (!this.app) return {};

        try {
            const [name, version, electronVersion] = await Promise.all([
                this.app.evaluate(({ app }) => app.getName()).catch(() => undefined),
                this.app.evaluate(({ app }) => app.getVersion()).catch(() => undefined),
                this.app.evaluate(({ process: p }) => p.versions.electron).catch(() => undefined),
            ]);

            logger.info(`Electron App: ${name || 'unknown'} v${version || 'unknown'} (Electron ${electronVersion || 'unknown'})`);
            return { name, version, electronVersion };
        } catch {
            return {};
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ELECTRON-SPECIFIC SECURITY CHECKS
    // ═══════════════════════════════════════════════════════════════════════════

    private async runElectronSecurityChecks(): Promise<ElectronSecurityFinding[]> {
        const findings: ElectronSecurityFinding[] = [];

        if (!this.app || !this.mainWindow) return findings;

        // Check webPreferences security settings
        const webPrefsFindings = await this.checkWebPreferences();
        findings.push(...webPrefsFindings);

        // Check CSP
        const cspFindings = await this.checkCSP();
        findings.push(...cspFindings);

        // Check IPC exposure
        const ipcFindings = await this.checkIPCExposure();
        findings.push(...ipcFindings);

        if (findings.length > 0) {
            logger.warn(`Found ${findings.length} Electron security issues`);
        } else {
            logger.info('No Electron-specific security issues found');
        }

        return findings;
    }

    private async checkWebPreferences(): Promise<ElectronSecurityFinding[]> {
        const findings: ElectronSecurityFinding[] = [];
        if (!this.mainWindow) return findings;

        try {
            const prefs = await this.mainWindow.evaluate(() => {
                // Check if nodeIntegration is enabled (it shouldn't be)
                const hasNode = typeof (window as Record<string, unknown>).require === 'function' ||
                    typeof (window as Record<string, unknown>).__dirname === 'string';

                // Check if contextIsolation is disabled
                const hasContextBridge = typeof (window as Record<string, unknown>).contextBridge !== 'undefined';

                // Check for remote module
                const hasRemote = typeof (window as Record<string, unknown>).require === 'function' &&
                    (() => {
                        try {
                            const req = (window as Record<string, unknown>).require as (m: string) => unknown;
                            req('@electron/remote');
                            return true;
                        } catch { return false; }
                    })();

                return { hasNode, hasContextBridge, hasRemote };
            });

            if (prefs.hasNode) {
                findings.push({
                    type: 'node-integration',
                    severity: 'critical',
                    description: 'nodeIntegration is enabled in the renderer process. This allows any script (including XSS payloads) to execute arbitrary Node.js code.',
                    remediation: 'Set nodeIntegration: false in BrowserWindow webPreferences. Use contextBridge to expose only necessary APIs.',
                });
            }

            if (!prefs.hasContextBridge && !prefs.hasNode) {
                findings.push({
                    type: 'context-isolation',
                    severity: 'high',
                    description: 'contextIsolation appears to be disabled. The renderer has direct access to Electron APIs without the safety of context isolation.',
                    remediation: 'Set contextIsolation: true in BrowserWindow webPreferences and use contextBridge.exposeInMainWorld() for IPC.',
                });
            }

            if (prefs.hasRemote) {
                findings.push({
                    type: 'remote-module',
                    severity: 'high',
                    description: 'The @electron/remote module is enabled, allowing renderer processes to directly call main process APIs. This negates many security benefits of process isolation.',
                    remediation: 'Remove @electron/remote and use IPC (ipcRenderer/ipcMain) with explicit message handlers instead.',
                });
            }
        } catch (error) {
            logger.debug(`WebPreferences check failed: ${error instanceof Error ? error.message : String(error)}`);
        }

        return findings;
    }

    private async checkCSP(): Promise<ElectronSecurityFinding[]> {
        const findings: ElectronSecurityFinding[] = [];
        if (!this.mainWindow) return findings;

        try {
            const cspInfo = await this.mainWindow.evaluate(() => {
                const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                const cspContent = meta?.getAttribute('content');
                return {
                    hasCSP: !!cspContent,
                    csp: cspContent || null,
                    hasUnsafeInline: cspContent?.includes("'unsafe-inline'") || false,
                    hasUnsafeEval: cspContent?.includes("'unsafe-eval'") || false,
                };
            });

            if (!cspInfo.hasCSP) {
                findings.push({
                    type: 'missing-csp',
                    severity: 'medium',
                    description: 'No Content-Security-Policy found in the Electron app. CSP helps prevent XSS and code injection attacks.',
                    remediation: "Add a CSP meta tag to the HTML: <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">",
                });
            } else if (cspInfo.hasUnsafeEval) {
                findings.push({
                    type: 'missing-csp',
                    severity: 'medium',
                    description: "CSP includes 'unsafe-eval' which weakens protection against code injection.",
                    remediation: "Remove 'unsafe-eval' from CSP. Refactor code to avoid eval() and new Function().",
                });
            }
        } catch (error) {
            logger.debug(`CSP check failed: ${error instanceof Error ? error.message : String(error)}`);
        }

        return findings;
    }

    private async checkIPCExposure(): Promise<ElectronSecurityFinding[]> {
        const findings: ElectronSecurityFinding[] = [];
        if (!this.mainWindow) return findings;

        try {
            const ipcInfo = await this.mainWindow.evaluate(() => {
                const win = window as Record<string, unknown>;

                // Check for exposed ipcRenderer
                const hasIpcRenderer = typeof win.ipcRenderer !== 'undefined' ||
                    typeof (win.electron as Record<string, unknown>)?.ipcRenderer !== 'undefined';

                // Check for broadly exposed IPC in preload
                const exposedAPIs = Object.keys(win).filter(key => {
                    if (['location', 'navigator', 'document', 'window', 'self', 'top', 'parent', 'frames'].includes(key)) return false;
                    const val = win[key];
                    return typeof val === 'object' && val !== null && typeof (val as Record<string, unknown>).send === 'function';
                });

                return { hasIpcRenderer, exposedAPIs };
            });

            if (ipcInfo.hasIpcRenderer) {
                findings.push({
                    type: 'ipc-exposure',
                    severity: 'medium',
                    description: 'ipcRenderer is directly exposed to the renderer. This allows scripts to send arbitrary IPC messages to the main process.',
                    remediation: 'Do not expose ipcRenderer directly. Use contextBridge.exposeInMainWorld() with specific, validated IPC channels.',
                });
            }

            if (ipcInfo.exposedAPIs.length > 5) {
                findings.push({
                    type: 'ipc-exposure',
                    severity: 'medium',
                    description: `${ipcInfo.exposedAPIs.length} objects with send() methods exposed to renderer. Consider reducing the attack surface.`,
                    remediation: 'Minimize the APIs exposed via contextBridge. Only expose what the renderer needs.',
                });
            }
        } catch (error) {
            logger.debug(`IPC check failed: ${error instanceof Error ? error.message : String(error)}`);
        }

        return findings;
    }
}

export default ElectronBrowserService;
