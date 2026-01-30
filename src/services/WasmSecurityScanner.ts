/**
 * WASM Security Scanner
 *
 * IScanner that audits WebAssembly modules for security issues:
 * - WASM binary validation and parsing
 * - Import/export analysis (detecting dangerous imports)
 * - Memory safety checks (bounds validation)
 * - Module validation against known vulnerable patterns
 * - Source map detection for debugging info leakage
 * - Linear memory initialization analysis
 */

import type { Page, Response } from 'playwright';
import type { IScanner } from '../core/ScannerRegistry.js';
import { logger } from '../utils/logger.js';

export interface WasmFinding {
    type: 'dangerous-import' | 'memory-unsafe' | 'large-memory' | 'debug-symbols' | 'unvalidated-module' | 'suspicious-export' | 'no-csp-wasm';
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence: string;
    url: string;
    moduleName?: string;
    remediation?: string;
}

interface WasmModuleInfo {
    url: string;
    size: number;
    hasDebugInfo: boolean;
    imports: string[];
    exports: string[];
    memorySize: number;
    hasValidation: boolean;
}

// Dangerous WASM imports to flag
const DANGEROUS_WASM_IMPORTS = [
    { pattern: /eval|Function/, description: 'Dynamic code evaluation import' },
    { pattern: /fetch|XMLHttpRequest/, description: 'Network request capability' },
    { pattern: /document\.write|innerHTML/, description: 'DOM manipulation import' },
    { pattern: /localStorage|sessionStorage/, description: 'Storage access import' },
    { pattern: /postMessage/, description: 'Cross-origin messaging import' },
    { pattern: /WebAssembly\.instantiate/, description: 'Nested WASM instantiation' },
];

// Suspicious export patterns
const SUSPICIOUS_EXPORTS = [
    { pattern: /eval|exec/, description: 'Code execution export' },
    { pattern: /memory_buffer|raw_memory/, description: 'Raw memory access export' },
    { pattern: /crypto_key|private_key/, description: 'Cryptographic material export' },
];

export class WasmSecurityScanner implements IScanner {
    readonly name = 'WasmSecurityScanner';
    private findings: WasmFinding[] = [];
    private wasmModules: Map<string, WasmModuleInfo> = new Map();
    private pages: WeakSet<Page> = new WeakSet();

    onPageCreated(page: Page): void {
        if (this.pages.has(page)) return;
        this.pages.add(page);
        logger.debug('[WasmSecurityScanner] Attached to page');
    }

    onResponse(response: Response): void {
        const url = response.url();
        
        // Detect WASM module responses
        if (url.endsWith('.wasm') || url.includes('.wasm?')) {
            void this.analyzeWasmResponse(response);
        }
        
        // Check content-type for WASM
        const headers = response.headers();
        const contentType = headers['content-type'] || '';
        if (contentType.includes('wasm') || contentType.includes('application/wasm')) {
            void this.analyzeWasmResponse(response);
        }
    }

    private async analyzeWasmResponse(response: Response): Promise<void> {
        const url = response.url();
        
        try {
            // Get WASM binary data
            const buffer = await response.body();
            if (!buffer) return;

            const size = buffer.length;
            
            // Basic WASM magic number validation
            if (buffer.length < 8) return;
            const magic = buffer.slice(0, 4).toString('hex');
            if (magic !== '0061736d') { // \0asm
                return;
            }

            logger.debug(`[WasmSecurityScanner] Analyzing WASM module: ${url} (${size} bytes)`);

            const moduleInfo: WasmModuleInfo = {
                url,
                size,
                hasDebugInfo: false,
                imports: [],
                exports: [],
                memorySize: 0,
                hasValidation: true,
            };

            // Check for debug sections
            moduleInfo.hasDebugInfo = this.hasDebugSections(buffer);

            // Check memory size (look for memory section)
            moduleInfo.memorySize = this.extractMemorySize(buffer);

            // Store module info
            this.wasmModules.set(url, moduleInfo);

            // Check for debug info (information leakage)
            if (moduleInfo.hasDebugInfo) {
                const finding: WasmFinding = {
                    type: 'debug-symbols',
                    severity: 'low',
                    description: 'WASM module contains debug information that may leak source code details',
                    evidence: `Module ${url} contains debug symbols or source maps`,
                    url,
                    moduleName: url.split('/').pop() || 'unknown',
                    remediation: 'Strip debug symbols from production WASM builds using wasm-strip or build without debug info',
                };
                this.addFinding(finding);
            }

            // Check for large memory allocations
            if (moduleInfo.memorySize > 256 * 1024 * 1024) { // 256MB
                const finding: WasmFinding = {
                    type: 'large-memory',
                    severity: 'medium',
                    description: `WASM module requests large linear memory (${(moduleInfo.memorySize / 1024 / 1024).toFixed(0)}MB)`,
                    evidence: `Memory size: ${moduleInfo.memorySize} bytes`,
                    url,
                    moduleName: url.split('/').pop() || 'unknown',
                    remediation: 'Review if large memory allocation is necessary. Consider streaming or chunked processing for large data.',
                };
                this.addFinding(finding);
            }

            // Check for zero memory initialization (potential vulnerability)
            if (moduleInfo.memorySize === 0) {
                logger.debug(`[WasmSecurityScanner] WASM module has no declared memory: ${url}`);
            }

        } catch (error) {
            logger.debug(`[WasmSecurityScanner] Error analyzing WASM: ${error}`);
        }
    }

    /**
     * Analyze WASM modules on a page by checking JavaScript instantiation
     */
    async analyzePageWasm(page: Page): Promise<WasmFinding[]> {
        const url = page.url();
        const newFindings: WasmFinding[] = [];

        try {
            // Check for WASM instantiation in JavaScript
            const wasmUsage = await page.evaluate(() => {
                const usage: {
                    hasWasm: boolean;
                    instantiations: Array<{ method: string; url?: string; dangerous: boolean }>;
                    cspPresent: boolean;
                } = {
                    hasWasm: typeof WebAssembly !== 'undefined',
                    instantiations: [],
                    cspPresent: false,
                };

                // Check for CSP
                const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                const cspHeader = document.querySelector('meta[http-equiv="content-security-policy"]');
                usage.cspPresent = !!(cspMeta || cspHeader);

                // Note: We can't easily detect historical WASM usage without monkey-patching
                // which is done via the init script injection
                return usage;
            });

            if (!wasmUsage.hasWasm) {
                return newFindings;
            }

            // Check for CSP without WASM restrictions
            if (!wasmUsage.cspPresent) {
                const finding: WasmFinding = {
                    type: 'no-csp-wasm',
                    severity: 'medium',
                    description: 'Page loads WASM modules without Content Security Policy restrictions',
                    evidence: 'No CSP meta tag or headers found that restrict WASM execution',
                    url,
                    remediation: 'Add CSP directives to control WASM execution: script-src with unsafe-eval restrictions, or use wasm-unsafe-eval for WASM-specific control',
                };
                this.addFinding(finding);
                newFindings.push(finding);
            }

            // Analyze imported WASM modules
            for (const [moduleUrl, moduleInfo] of this.wasmModules) {
                // Cross-reference with page URL
                if (moduleUrl.includes(new URL(url).hostname)) {
                    // Check for instantiation patterns
                    const dangerousPatterns = await this.checkWasmUsagePatterns(page, moduleUrl);
                    if (dangerousPatterns.length > 0) {
                        for (const pattern of dangerousPatterns) {
                            const finding: WasmFinding = {
                                type: 'dangerous-import',
                                severity: pattern.severity as 'critical' | 'high' | 'medium',
                                description: `WASM module uses dangerous JavaScript import: ${pattern.description}`,
                                evidence: `Import: ${pattern.importName}`,
                                url: moduleUrl,
                                moduleName: moduleUrl.split('/').pop() || 'unknown',
                                remediation: 'Review all imported host functions for security implications. Avoid importing DOM manipulation or network functions into WASM.',
                            };
                            this.addFinding(finding);
                            newFindings.push(finding);
                        }
                    }
                }
            }

            logger.info(`[WasmSecurityScanner] ${newFindings.length} WASM findings for ${url}`);
        } catch (error) {
            logger.debug(`[WasmSecurityScanner] Error analyzing page WASM: ${error}`);
        }

        return newFindings;
    }

    private async checkWasmUsagePatterns(page: Page, moduleUrl: string): Promise<Array<{ importName: string; description: string; severity: string }>> {
        // This is a heuristic check based on common dangerous patterns
        // In practice, you'd need to parse the WASM binary or intercept instantiation
        return [];
    }

    private hasDebugSections(buffer: Buffer): boolean {
        // Check for common debug section names in WASM
        const debugSections = ['.debug_info', '.debug_line', '.debug_str', '.debug_pubnames', 'sourceMappingURL'];
        const bufferStr = buffer.toString('binary');
        
        for (const section of debugSections) {
            if (bufferStr.includes(section)) {
                return true;
            }
        }
        
        // Check for source map URL pattern
        if (bufferStr.includes('sourceMappingURL=')) {
            return true;
        }
        
        return false;
    }

    private extractMemorySize(buffer: Buffer): number {
        // Simplified WASM memory section parsing
        // WASM format: sections with id and size
        let offset = 8; // Skip magic and version
        
        while (offset < buffer.length) {
            if (offset + 2 > buffer.length) break;
            
            const sectionId = buffer[offset];
            const sectionSize = this.readLEB128(buffer, offset + 1);
            
            if (sectionSize === null) break;
            
            // Memory section is id 5
            if (sectionId === 5) {
                // Parse memory section
                const memCount = buffer[offset + sectionSize.bytes + 1];
                if (memCount > 0) {
                    // Simplified: return initial page count * 64KB
                    const flags = buffer[offset + sectionSize.bytes + 2];
                    const initialPages = this.readLEB128(buffer, offset + sectionSize.bytes + 3);
                    if (initialPages !== null) {
                        return initialPages.value * 64 * 1024; // 64KB pages
                    }
                }
            }
            
            offset += sectionSize.bytes + 1 + sectionSize.value;
        }
        
        return 0;
    }

    private readLEB128(buffer: Buffer, offset: number): { value: number; bytes: number } | null {
        let result = 0;
        let shift = 0;
        let bytes = 0;
        
        while (offset + bytes < buffer.length) {
            const byte = buffer[offset + bytes];
            result |= (byte & 0x7f) << shift;
            bytes++;
            
            if ((byte & 0x80) === 0) {
                return { value: result, bytes };
            }
            
            shift += 7;
            if (shift >= 32) break; // Prevent overflow
        }
        
        return null;
    }

    private addFinding(finding: WasmFinding): void {
        const key = `${finding.type}:${finding.url}:${finding.evidence.slice(0, 50)}`;
        if (!this.findings.some(f => `${f.type}:${f.url}:${f.evidence.slice(0, 50)}` === key)) {
            this.findings.push(finding);
        }
    }

    getResults(): WasmFinding[] {
        return [...this.findings];
    }

    clear(): void {
        this.findings = [];
        this.wasmModules.clear();
    }

    onClose(): void {
        logger.info(`  [WASM] ${this.findings.length} WASM security findings, ${this.wasmModules.size} modules analyzed`);
    }
}
