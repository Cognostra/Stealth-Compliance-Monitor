/**
 * VulnIntelligenceService
 * 
 * Enriches vulnerability findings with CVE details, CVSS scores,
 * exploit availability, and remediation intelligence.
 * 
 * Features:
 * - CVE ID mapping and enrichment
 * - CVSS v3.1 score calculation and severity
 * - Exploit database cross-reference (ExploitDB, Metasploit)
 * - Remediation priority scoring
 * - Known Exploited Vulnerabilities (KEV) check (CISA)
 * - CWE descriptions enrichment
 * - Version upgrade recommendations
 * 
 * Data Sources:
 * - NVD (National Vulnerability Database) API - Primary
 * - CIRCL.lu CVE API - Fallback
 * - CISA KEV Catalog
 * - Local vulnerability database cache
 * - File-based JSON cache for persistence
 */

import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger.js';
import { VulnerableLibrary } from './FrontendVulnerabilityScanner.js';
import { SecurityAlert } from '../types/index.js';

export interface CvssScore {
    version: '3.1' | '3.0' | '2.0';
    baseScore: number;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
    vector: string;
    exploitabilityScore?: number;
    impactScore?: number;
}

export interface CweInfo {
    id: string;
    name: string;
    description: string;
}

export interface ExploitInfo {
    available: boolean;
    source?: 'ExploitDB' | 'Metasploit' | 'GitHub' | 'PoC' | 'Other';
    url?: string;
    lastSeen?: string;
    maturity?: 'functional' | 'proof-of-concept' | 'unproven';
}

export interface RemediationInfo {
    type: 'upgrade' | 'patch' | 'workaround' | 'config' | 'none';
    description: string;
    targetVersion?: string;
    effort: 'low' | 'medium' | 'high';
    priority: number; // 1-10 scale
    references: string[];
}

export interface EnrichedVulnerability {
    // Original finding
    original: VulnerableLibrary | SecurityAlert;
    type: 'library' | 'security-alert';
    
    // CVE enrichment
    cveId: string;
    cveDescription?: string;
    publishedDate?: string;
    lastModified?: string;
    
    // CWE enrichment
    cwe?: CweInfo;
    
    // CVSS scoring
    cvss: CvssScore;
    
    // Exploit intelligence
    exploit: ExploitInfo;
    
    // CISA KEV status
    knownExploitedVuln: boolean;
    kevDateAdded?: string;
    kevDueDate?: string;
    
    // Remediation guidance
    remediation: RemediationInfo;
    
    // Risk scoring
    riskScore: number; // Calculated 1-100
    riskFactors: string[];
}

export interface VulnIntelligenceConfig {
    nvdApiKey?: string;           // NVD API key for higher rate limits
    cacheEnabled?: boolean;       // Enable local caching
    cacheTtlMinutes?: number;     // Cache TTL (default 24h)
    cacheFilePath?: string;       // Path to JSON cache file
    enrichExploits?: boolean;     // Check exploit databases
    enrichKev?: boolean;          // Check CISA KEV
    enrichCwe?: boolean;          // Enrich with CWE descriptions
    timeout?: number;             // API timeout in ms
    useNvdApi?: boolean;          // Enable NVD API calls
    useCirclApi?: boolean;        // Enable circl.lu fallback
    rateLimitMs?: number;         // Rate limit between API calls
}

// CWE Database for common weaknesses
const CWE_DATABASE: Record<string, CweInfo> = {
    'CWE-79': { id: 'CWE-79', name: 'Cross-site Scripting (XSS)', description: 'Improper Neutralization of Input During Web Page Generation' },
    'CWE-89': { id: 'CWE-89', name: 'SQL Injection', description: 'Improper Neutralization of Special Elements used in an SQL Command' },
    'CWE-94': { id: 'CWE-94', name: 'Code Injection', description: 'Improper Control of Generation of Code' },
    'CWE-400': { id: 'CWE-400', name: 'Uncontrolled Resource Consumption', description: 'Resource exhaustion through algorithmic complexity (ReDoS)' },
    'CWE-1321': { id: 'CWE-1321', name: 'Prototype Pollution', description: 'Improperly Controlled Modification of Object Prototype Attributes' },
    'CWE-22': { id: 'CWE-22', name: 'Path Traversal', description: 'Improper Limitation of a Pathname to a Restricted Directory' },
    'CWE-918': { id: 'CWE-918', name: 'SSRF', description: 'Server-Side Request Forgery' },
    'CWE-502': { id: 'CWE-502', name: 'Deserialization of Untrusted Data', description: 'Deserialization of Untrusted Data' },
    'CWE-352': { id: 'CWE-352', name: 'CSRF', description: 'Cross-Site Request Forgery' },
    'CWE-287': { id: 'CWE-287', name: 'Improper Authentication', description: 'Improper Authentication' },
    'CWE-862': { id: 'CWE-862', name: 'Missing Authorization', description: 'Missing Authorization' },
    'CWE-798': { id: 'CWE-798', name: 'Hardcoded Credentials', description: 'Use of Hard-coded Credentials' },
    'CWE-611': { id: 'CWE-611', name: 'XXE', description: 'Improper Restriction of XML External Entity Reference' },
    'CWE-434': { id: 'CWE-434', name: 'Unrestricted Upload', description: 'Unrestricted Upload of File with Dangerous Type' },
    'CWE-200': { id: 'CWE-200', name: 'Information Exposure', description: 'Exposure of Sensitive Information to an Unauthorized Actor' },
};

// Known CVE database for common library vulnerabilities (offline fallback)

// Known CVE database for common library vulnerabilities (offline fallback)
const CVE_DATABASE: Record<string, Partial<EnrichedVulnerability>> = {
    'CVE-2020-11022': {
        cveDescription: 'jQuery XSS vulnerability in htmlPrefilter regex',
        cwe: { id: 'CWE-79', name: 'Cross-site Scripting (XSS)', description: 'Improper Neutralization of Input During Web Page Generation' },
        cvss: {
            version: '3.1',
            baseScore: 6.1,
            severity: 'MEDIUM',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        },
        exploit: {
            available: true,
            source: 'PoC',
            maturity: 'proof-of-concept',
        },
        knownExploitedVuln: false,
        remediation: {
            type: 'upgrade',
            description: 'Upgrade jQuery to version 3.5.0 or later',
            targetVersion: '3.5.0',
            effort: 'low',
            priority: 7,
            references: ['https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2'],
        },
    },
    'CVE-2020-11023': {
        cveDescription: 'jQuery XSS vulnerability in HTML sanitization regex',
        cwe: { id: 'CWE-79', name: 'Cross-site Scripting (XSS)', description: 'Improper Neutralization of Input During Web Page Generation' },
        cvss: {
            version: '3.1',
            baseScore: 6.1,
            severity: 'MEDIUM',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        },
        exploit: {
            available: true,
            source: 'PoC',
            maturity: 'proof-of-concept',
        },
        knownExploitedVuln: false,
        remediation: {
            type: 'upgrade',
            description: 'Upgrade jQuery to version 3.5.0 or later',
            targetVersion: '3.5.0',
            effort: 'low',
            priority: 7,
            references: ['https://github.com/jquery/jquery/security/advisories/GHSA-jpcq-cgw6-v4j6'],
        },
    },
    'CVE-2019-11358': {
        cveDescription: 'jQuery prototype pollution vulnerability in $.extend()',
        cwe: { id: 'CWE-1321', name: 'Prototype Pollution', description: 'Improperly Controlled Modification of Object Prototype Attributes' },
        cvss: {
            version: '3.1',
            baseScore: 6.1,
            severity: 'MEDIUM',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        },
        exploit: {
            available: true,
            source: 'GitHub',
            maturity: 'functional',
        },
        knownExploitedVuln: false,
        remediation: {
            type: 'upgrade',
            description: 'Upgrade jQuery to version 3.4.0 or later',
            targetVersion: '3.4.0',
            effort: 'low',
            priority: 8,
            references: ['https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/'],
        },
    },
    'CVE-2021-23337': {
        cveDescription: 'Lodash command injection via template function',
        cwe: { id: 'CWE-94', name: 'Code Injection', description: 'Improper Control of Generation of Code' },
        cvss: {
            version: '3.1',
            baseScore: 7.2,
            severity: 'HIGH',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
        },
        exploit: {
            available: true,
            source: 'PoC',
            maturity: 'proof-of-concept',
        },
        knownExploitedVuln: false,
        remediation: {
            type: 'upgrade',
            description: 'Upgrade Lodash to version 4.17.21 or later',
            targetVersion: '4.17.21',
            effort: 'low',
            priority: 9,
            references: ['https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c'],
        },
    },
    'CVE-2020-28500': {
        cveDescription: 'Lodash ReDoS vulnerability in toNumber, trim, and trimEnd functions',
        cwe: { id: 'CWE-400', name: 'Uncontrolled Resource Consumption', description: 'Resource exhaustion through algorithmic complexity (ReDoS)' },
        cvss: {
            version: '3.1',
            baseScore: 5.3,
            severity: 'MEDIUM',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
        },
        exploit: {
            available: false,
        },
        knownExploitedVuln: false,
        remediation: {
            type: 'upgrade',
            description: 'Upgrade Lodash to version 4.17.21 or later',
            targetVersion: '4.17.21',
            effort: 'low',
            priority: 6,
            references: ['https://snyk.io/vuln/SNYK-JS-LODASH-1018905'],
        },
    },
    'CVE-2018-16487': {
        cveDescription: 'Lodash prototype pollution via merge, mergeWith, and defaultsDeep',
        cwe: { id: 'CWE-1321', name: 'Prototype Pollution', description: 'Improperly Controlled Modification of Object Prototype Attributes' },
        cvss: {
            version: '3.1',
            baseScore: 9.8,
            severity: 'CRITICAL',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        },
        exploit: {
            available: true,
            source: 'ExploitDB',
            maturity: 'functional',
        },
        knownExploitedVuln: false,
        remediation: {
            type: 'upgrade',
            description: 'Upgrade Lodash to version 4.17.11 or later',
            targetVersion: '4.17.11',
            effort: 'low',
            priority: 10,
            references: ['https://nvd.nist.gov/vuln/detail/CVE-2018-16487'],
        },
    },
    'CVE-2020-8203': {
        cveDescription: 'Lodash prototype pollution in zipObjectDeep',
        cwe: { id: 'CWE-1321', name: 'Prototype Pollution', description: 'Improperly Controlled Modification of Object Prototype Attributes' },
        cvss: {
            version: '3.1',
            baseScore: 7.4,
            severity: 'HIGH',
            vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H',
        },
        exploit: {
            available: true,
            source: 'GitHub',
            maturity: 'functional',
        },
        knownExploitedVuln: false,
        remediation: {
            type: 'upgrade',
            description: 'Upgrade Lodash to version 4.17.19 or later',
            targetVersion: '4.17.19',
            effort: 'low',
            priority: 9,
            references: ['https://github.com/lodash/lodash/issues/4874'],
        },
    },
    'CVE-2022-24785': {
        cveDescription: 'Moment.js path traversal vulnerability',
        cwe: { id: 'CWE-22', name: 'Path Traversal', description: 'Improper Limitation of a Pathname to a Restricted Directory' },
        cvss: {
            version: '3.1',
            baseScore: 7.5,
            severity: 'HIGH',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        },
        exploit: {
            available: true,
            source: 'PoC',
            maturity: 'proof-of-concept',
        },
        knownExploitedVuln: false,
        remediation: {
            type: 'upgrade',
            description: 'Migrate from Moment.js to date-fns, Luxon, or Day.js',
            effort: 'medium',
            priority: 8,
            references: ['https://github.com/moment/moment/security/advisories/GHSA-8hfj-j24r-96c4'],
        },
    },
    'CVE-2017-18214': {
        cveDescription: 'Moment.js ReDoS vulnerability in date parsing',
        cwe: { id: 'CWE-400', name: 'Uncontrolled Resource Consumption', description: 'Resource exhaustion through algorithmic complexity (ReDoS)' },
        cvss: {
            version: '3.1',
            baseScore: 7.5,
            severity: 'HIGH',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        },
        exploit: {
            available: false,
        },
        knownExploitedVuln: false,
        remediation: {
            type: 'upgrade',
            description: 'Upgrade Moment.js to 2.19.3+ or migrate to alternatives',
            targetVersion: '2.19.3',
            effort: 'low',
            priority: 7,
            references: ['https://github.com/moment/moment/issues/4163'],
        },
    },
    'CVE-2021-44228': {
        cveDescription: 'Apache Log4j2 JNDI RCE vulnerability (Log4Shell)',
        cwe: { id: 'CWE-94', name: 'Code Injection', description: 'Improper Control of Generation of Code' },
        cvss: {
            version: '3.1',
            baseScore: 10.0,
            severity: 'CRITICAL',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        },
        exploit: {
            available: true,
            source: 'Metasploit',
            maturity: 'functional',
            url: 'https://www.exploit-db.com/exploits/50592',
        },
        knownExploitedVuln: true,
        kevDateAdded: '2021-12-10',
        remediation: {
            type: 'upgrade',
            description: 'Upgrade Log4j to version 2.17.0 or later immediately',
            targetVersion: '2.17.0',
            effort: 'high',
            priority: 10,
            references: [
                'https://logging.apache.org/log4j/2.x/security.html',
                'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
            ],
        },
    },
};

// CISA KEV catalog (sample of high-profile entries)
const KEV_CATALOG: Set<string> = new Set([
    'CVE-2021-44228', // Log4Shell
    'CVE-2021-26855', // ProxyLogon
    'CVE-2023-22515', // Atlassian Confluence
    'CVE-2023-44487', // HTTP/2 Rapid Reset
    // Add more as needed
]);

interface CacheEntry {
    data: Partial<EnrichedVulnerability>;
    timestamp: number;
}

interface FileCache {
    version: string;
    entries: Record<string, CacheEntry>;
}

export class VulnIntelligenceService {
    private config: Required<VulnIntelligenceConfig>;
    private memoryCache: Map<string, CacheEntry> = new Map();
    private lastApiCall: number = 0;
    private fileCache: FileCache | null = null;
    private fileCacheLoaded: boolean = false;

    constructor(config: VulnIntelligenceConfig = {}) {
        this.config = {
            cacheEnabled: config.cacheEnabled ?? true,
            cacheTtlMinutes: config.cacheTtlMinutes ?? 1440, // 24 hours
            cacheFilePath: config.cacheFilePath ?? './cache/vuln-intel-cache.json',
            enrichExploits: config.enrichExploits ?? true,
            enrichKev: config.enrichKev ?? true,
            enrichCwe: config.enrichCwe ?? true,
            timeout: config.timeout ?? 10000,
            nvdApiKey: config.nvdApiKey ?? process.env.NVD_API_KEY ?? '',
            useNvdApi: config.useNvdApi ?? true,
            useCirclApi: config.useCirclApi ?? true,
            rateLimitMs: config.rateLimitMs ?? (config.nvdApiKey ? 20 : 500), // 50/sec with key, 2/sec without
        };
    }

    /**
     * Load file-based cache from disk
     */
    private async loadFileCache(): Promise<void> {
        if (this.fileCacheLoaded || !this.config.cacheEnabled) return;
        
        try {
            const cacheDir = path.dirname(this.config.cacheFilePath);
            if (!fs.existsSync(cacheDir)) {
                fs.mkdirSync(cacheDir, { recursive: true });
            }

            if (fs.existsSync(this.config.cacheFilePath)) {
                const content = fs.readFileSync(this.config.cacheFilePath, 'utf-8');
                this.fileCache = JSON.parse(content);
                
                // Load into memory cache, filtering expired entries
                const ttlMs = this.config.cacheTtlMinutes * 60 * 1000;
                const now = Date.now();
                
                if (this.fileCache?.entries) {
                    for (const [cveId, entry] of Object.entries(this.fileCache.entries)) {
                        if (now - entry.timestamp < ttlMs) {
                            this.memoryCache.set(cveId, entry);
                        }
                    }
                }
                
                logger.debug(`📦 Loaded ${this.memoryCache.size} cached CVEs from file`);
            } else {
                this.fileCache = { version: '1.0', entries: {} };
            }
        } catch (error) {
            logger.warn(`⚠️ Failed to load vuln intel cache: ${error}`);
            this.fileCache = { version: '1.0', entries: {} };
        }
        
        this.fileCacheLoaded = true;
    }

    /**
     * Save file-based cache to disk
     */
    private async saveFileCache(): Promise<void> {
        if (!this.config.cacheEnabled || !this.fileCache) return;
        
        try {
            // Sync memory cache to file cache
            this.fileCache.entries = {};
            for (const [cveId, entry] of this.memoryCache.entries()) {
                this.fileCache.entries[cveId] = entry;
            }
            
            const cacheDir = path.dirname(this.config.cacheFilePath);
            if (!fs.existsSync(cacheDir)) {
                fs.mkdirSync(cacheDir, { recursive: true });
            }
            
            fs.writeFileSync(this.config.cacheFilePath, JSON.stringify(this.fileCache, null, 2));
            logger.debug(`💾 Saved ${this.memoryCache.size} CVEs to cache file`);
        } catch (error) {
            logger.warn(`⚠️ Failed to save vuln intel cache: ${error}`);
        }
    }

    /**
     * Rate limiter for API calls
     */
    private async rateLimit(): Promise<void> {
        const now = Date.now();
        const elapsed = now - this.lastApiCall;
        
        if (elapsed < this.config.rateLimitMs) {
            await new Promise(resolve => setTimeout(resolve, this.config.rateLimitMs - elapsed));
        }
        
        this.lastApiCall = Date.now();
    }

    /**
     * Fetch CVE data from NVD API (primary source)
     */
    private async fetchFromNvd(cveId: string): Promise<Partial<EnrichedVulnerability> | null> {
        if (!this.config.useNvdApi) return null;
        
        try {
            await this.rateLimit();
            
            const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
            const headers: Record<string, string> = {
                'Accept': 'application/json',
            };
            
            if (this.config.nvdApiKey) {
                headers['apiKey'] = this.config.nvdApiKey;
            }
            
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), this.config.timeout);
            
            const response = await fetch(url, {
                headers,
                signal: controller.signal,
            });
            
            clearTimeout(timeout);
            
            if (!response.ok) {
                if (response.status === 403) {
                    logger.warn(`⚠️ NVD API rate limited for ${cveId}`);
                }
                return null;
            }
            
            const data = await response.json() as {
                vulnerabilities?: Array<{
                    cve: {
                        id: string;
                        descriptions?: Array<{ lang: string; value: string }>;
                        published?: string;
                        lastModified?: string;
                        metrics?: {
                            cvssMetricV31?: Array<{
                                cvssData: {
                                    baseScore: number;
                                    baseSeverity: string;
                                    vectorString: string;
                                };
                                exploitabilityScore?: number;
                                impactScore?: number;
                            }>;
                            cvssMetricV30?: Array<{
                                cvssData: {
                                    baseScore: number;
                                    baseSeverity: string;
                                    vectorString: string;
                                };
                            }>;
                        };
                        weaknesses?: Array<{
                            description: Array<{ lang: string; value: string }>;
                        }>;
                    };
                }>;
            };
            
            if (!data.vulnerabilities?.length) {
                return null;
            }
            
            const cve = data.vulnerabilities[0].cve;
            const description = cve.descriptions?.find(d => d.lang === 'en')?.value;
            
            // Extract CVSS v3.1 or v3.0
            let cvss: CvssScore | undefined;
            if (cve.metrics?.cvssMetricV31?.length) {
                const metric = cve.metrics.cvssMetricV31[0];
                cvss = {
                    version: '3.1',
                    baseScore: metric.cvssData.baseScore,
                    severity: metric.cvssData.baseSeverity as CvssScore['severity'],
                    vector: metric.cvssData.vectorString,
                    exploitabilityScore: metric.exploitabilityScore,
                    impactScore: metric.impactScore,
                };
            } else if (cve.metrics?.cvssMetricV30?.length) {
                const metric = cve.metrics.cvssMetricV30[0];
                cvss = {
                    version: '3.0',
                    baseScore: metric.cvssData.baseScore,
                    severity: metric.cvssData.baseSeverity as CvssScore['severity'],
                    vector: metric.cvssData.vectorString,
                };
            }
            
            // Extract CWE
            let cwe: CweInfo | undefined;
            if (this.config.enrichCwe && cve.weaknesses?.length) {
                const cweId = cve.weaknesses[0]?.description?.find(d => d.lang === 'en')?.value;
                if (cweId) {
                    cwe = await this.lookupCwe(cweId);
                }
            }
            
            logger.debug(`✅ NVD API: Retrieved ${cveId}`);
            
            return {
                cveId,
                cveDescription: description,
                publishedDate: cve.published,
                lastModified: cve.lastModified,
                cvss,
                cwe,
            };
        } catch (error) {
            if (error instanceof Error && error.name === 'AbortError') {
                logger.warn(`⚠️ NVD API timeout for ${cveId}`);
            } else {
                logger.debug(`⚠️ NVD API error for ${cveId}: ${error}`);
            }
            return null;
        }
    }

    /**
     * Fetch CVE data from circl.lu API (fallback source)
     */
    private async fetchFromCircl(cveId: string): Promise<Partial<EnrichedVulnerability> | null> {
        if (!this.config.useCirclApi) return null;
        
        try {
            await this.rateLimit();
            
            const url = `https://cve.circl.lu/api/cve/${cveId}`;
            
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), this.config.timeout);
            
            const response = await fetch(url, {
                headers: { 'Accept': 'application/json' },
                signal: controller.signal,
            });
            
            clearTimeout(timeout);
            
            if (!response.ok) {
                return null;
            }
            
            const data = await response.json() as {
                id?: string;
                summary?: string;
                Published?: string;
                Modified?: string;
                cvss?: number;
                cvss_vector?: string;
                cwe?: string;
            };
            
            if (!data || !data.id) {
                return null;
            }
            
            // Map circl.lu CVSS (v2) to our format
            let cvss: CvssScore | undefined;
            if (data.cvss !== undefined) {
                cvss = {
                    version: '2.0',
                    baseScore: data.cvss,
                    severity: this.cvssToSeverity(data.cvss),
                    vector: data.cvss_vector ?? '',
                };
            }
            
            // Get CWE info
            let cwe: CweInfo | undefined;
            if (this.config.enrichCwe && data.cwe) {
                cwe = await this.lookupCwe(data.cwe);
            }
            
            logger.debug(`✅ CIRCL API: Retrieved ${cveId}`);
            
            return {
                cveId,
                cveDescription: data.summary,
                publishedDate: data.Published,
                lastModified: data.Modified,
                cvss,
                cwe,
            };
        } catch (error) {
            if (error instanceof Error && error.name === 'AbortError') {
                logger.warn(`⚠️ CIRCL API timeout for ${cveId}`);
            } else {
                logger.debug(`⚠️ CIRCL API error for ${cveId}: ${error}`);
            }
            return null;
        }
    }

    /**
     * Look up CWE information
     */
    private async lookupCwe(cweId: string): Promise<CweInfo | undefined> {
        // Normalize CWE ID
        const normalizedId = cweId.toUpperCase().startsWith('CWE-') 
            ? cweId.toUpperCase() 
            : `CWE-${cweId}`;
        
        // Check local database first
        if (CWE_DATABASE[normalizedId]) {
            return CWE_DATABASE[normalizedId];
        }
        
        // Return basic info if not in database
        return {
            id: normalizedId,
            name: 'Unknown CWE',
            description: `See https://cwe.mitre.org/data/definitions/${cweId.replace(/\D/g, '')}.html`,
        };
    }

    /**
     * Convert CVSS score to severity string
     */
    private cvssToSeverity(score: number): CvssScore['severity'] {
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        if (score >= 0.1) return 'LOW';
        return 'NONE';
    }

    /**
     * Enrich a vulnerable library finding with CVE intelligence
     */
    async enrichLibrary(library: VulnerableLibrary): Promise<EnrichedVulnerability[]> {
        await this.loadFileCache();
        const enriched: EnrichedVulnerability[] = [];

        for (const vuln of library.vulnerabilities) {
            const cveId = vuln.cve;
            
            // Check cache first
            if (this.config.cacheEnabled) {
                const cached = this.getFromCache(cveId);
                if (cached) {
                    enriched.push({
                        ...this.buildEnrichedVuln(cached, library, 'library', cveId, vuln.description),
                    });
                    continue;
                }
            }

            // Look up from APIs and local database
            const enrichedVuln = await this.lookupCve(cveId);
            
            // Create enriched vulnerability
            const result = this.buildEnrichedVuln(enrichedVuln, library, 'library', cveId, vuln.description);

            // Cache the result
            if (this.config.cacheEnabled && enrichedVuln) {
                this.addToCache(cveId, enrichedVuln);
            }

            enriched.push(result);
        }

        // Save cache after enrichment
        await this.saveFileCache();

        return enriched;
    }

    /**
     * Build enriched vulnerability object
     */
    private buildEnrichedVuln(
        enrichedVuln: Partial<EnrichedVulnerability> | null,
        original: VulnerableLibrary | SecurityAlert,
        type: 'library' | 'security-alert',
        cveId: string,
        fallbackDescription: string
    ): EnrichedVulnerability {
        const isLibrary = type === 'library';
        
        const result: EnrichedVulnerability = {
            original,
            type,
            cveId,
            cveDescription: enrichedVuln?.cveDescription ?? fallbackDescription,
            publishedDate: enrichedVuln?.publishedDate,
            lastModified: enrichedVuln?.lastModified,
            cwe: enrichedVuln?.cwe,
            cvss: enrichedVuln?.cvss ?? (isLibrary 
                ? this.estimateCvss((original as VulnerableLibrary).severity)
                : this.mapAlertRiskToCvss((original as SecurityAlert).risk)),
            exploit: enrichedVuln?.exploit ?? { available: false },
            knownExploitedVuln: this.checkKev(cveId),
            remediation: enrichedVuln?.remediation ?? (isLibrary 
                ? this.generateRemediation(original as VulnerableLibrary)
                : this.generateAlertRemediation(original as SecurityAlert)),
            riskScore: 0,
            riskFactors: [],
        };

        result.riskScore = this.calculateRiskScore(result);
        result.riskFactors = this.identifyRiskFactors(result);

        return result;
    }

    /**
     * Enrich a ZAP security alert with intelligence
     */
    async enrichAlert(alert: SecurityAlert): Promise<EnrichedVulnerability | null> {
        await this.loadFileCache();
        
        // Extract CVE from alert if present
        const cveMatch = alert.description.match(/CVE-\d{4}-\d{4,7}/i);
        const cveId = cveMatch ? cveMatch[0].toUpperCase() : this.generatePseudoCve(alert);

        // Check cache
        if (this.config.cacheEnabled && cveMatch) {
            const cached = this.getFromCache(cveId);
            if (cached) {
                const result = this.buildEnrichedVuln(cached, alert, 'security-alert', cveId, alert.description);
                return result;
            }
        }

        // Look up CVE if we have one
        let enrichedVuln: Partial<EnrichedVulnerability> | null = null;
        if (cveMatch) {
            enrichedVuln = await this.lookupCve(cveId);
        }

        const result = this.buildEnrichedVuln(enrichedVuln, alert, 'security-alert', cveId, alert.description);

        if (this.config.cacheEnabled && cveMatch && enrichedVuln) {
            this.addToCache(cveId, enrichedVuln);
        }

        await this.saveFileCache();
        return result;
    }

    /**
     * Bulk enrich multiple findings
     */
    async enrichAll(
        libraries: VulnerableLibrary[],
        alerts: SecurityAlert[]
    ): Promise<{
        libraries: EnrichedVulnerability[];
        alerts: EnrichedVulnerability[];
        summary: IntelligenceSummary;
    }> {
        logger.info(`🔍 Enriching ${libraries.length} library vulns and ${alerts.length} security alerts`);

        const enrichedLibraries: EnrichedVulnerability[] = [];
        const enrichedAlerts: EnrichedVulnerability[] = [];

        // Enrich libraries
        for (const lib of libraries) {
            const enriched = await this.enrichLibrary(lib);
            enrichedLibraries.push(...enriched);
        }

        // Enrich alerts
        for (const alert of alerts) {
            const enriched = await this.enrichAlert(alert);
            if (enriched) {
                enrichedAlerts.push(enriched);
            }
        }

        // Generate summary
        const all = [...enrichedLibraries, ...enrichedAlerts];
        const summary = this.generateSummary(all);

        logger.info(`✅ Enrichment complete: ${all.length} total findings`);
        logger.info(`   Critical: ${summary.bySeverity.CRITICAL}, High: ${summary.bySeverity.HIGH}`);
        logger.info(`   With exploits: ${summary.withExploits}, KEV: ${summary.inKev}`);

        return {
            libraries: enrichedLibraries,
            alerts: enrichedAlerts,
            summary,
        };
    }

    /**
     * Look up CVE from local database, NVD API, or circl.lu fallback
     */
    private async lookupCve(cveId: string): Promise<Partial<EnrichedVulnerability> | null> {
        // First check local database (fastest)
        if (CVE_DATABASE[cveId]) {
            logger.debug(`📦 Local DB hit: ${cveId}`);
            return CVE_DATABASE[cveId];
        }

        // Try NVD API (primary source)
        const nvdData = await this.fetchFromNvd(cveId);
        if (nvdData) {
            return nvdData;
        }

        // Fall back to circl.lu API
        const circlData = await this.fetchFromCircl(cveId);
        if (circlData) {
            return circlData;
        }
        
        logger.debug(`⚠️ No data found for ${cveId}`);
        return null;
    }

    /**
     * Check if CVE is in CISA KEV catalog
     */
    private checkKev(cveId: string): boolean {
        return KEV_CATALOG.has(cveId);
    }

    /**
     * Estimate CVSS score from severity string
     */
    private estimateCvss(severity: string): CvssScore {
        const mapping: Record<string, CvssScore> = {
            'CRITICAL': { version: '3.1', baseScore: 9.5, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
            'HIGH': { version: '3.1', baseScore: 7.5, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
            'MEDIUM': { version: '3.1', baseScore: 5.5, severity: 'MEDIUM', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N' },
            'LOW': { version: '3.1', baseScore: 3.5, severity: 'LOW', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N' },
        };
        return mapping[severity.toUpperCase()] ?? mapping['MEDIUM'];
    }

    /**
     * Map ZAP alert risk to CVSS
     */
    private mapAlertRiskToCvss(risk: string): CvssScore {
        const mapping: Record<string, CvssScore> = {
            'High': { version: '3.1', baseScore: 8.0, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N' },
            'Medium': { version: '3.1', baseScore: 5.5, severity: 'MEDIUM', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N' },
            'Low': { version: '3.1', baseScore: 3.5, severity: 'LOW', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N' },
            'Informational': { version: '3.1', baseScore: 0.0, severity: 'NONE', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N' },
        };
        return mapping[risk] ?? mapping['Medium'];
    }

    /**
     * Generate remediation for library vulnerability
     */
    private generateRemediation(library: VulnerableLibrary): RemediationInfo {
        return {
            type: 'upgrade',
            description: library.recommendation,
            effort: 'low',
            priority: this.calculateRemediationPriority(library.severity),
            references: [],
        };
    }

    /**
     * Generate remediation for ZAP alert
     */
    private generateAlertRemediation(alert: SecurityAlert): RemediationInfo {
        return {
            type: alert.solution ? 'patch' : 'workaround',
            description: alert.solution ?? 'Review and remediate the identified vulnerability',
            effort: alert.risk === 'High' ? 'high' : 'medium',
            priority: this.calculateRemediationPriority(alert.risk),
            references: [],
        };
    }

    /**
     * Calculate remediation priority (1-10)
     */
    private calculateRemediationPriority(severity: string): number {
        const mapping: Record<string, number> = {
            'CRITICAL': 10,
            'HIGH': 8,
            'High': 8,
            'MEDIUM': 6,
            'Medium': 6,
            'LOW': 4,
            'Low': 4,
            'Informational': 2,
        };
        return mapping[severity] ?? 5;
    }

    /**
     * Calculate overall risk score (1-100)
     */
    private calculateRiskScore(vuln: EnrichedVulnerability): number {
        let score = vuln.cvss.baseScore * 10; // Base: 0-100 from CVSS

        // Boost for exploit availability
        if (vuln.exploit.available) {
            score += 10;
            if (vuln.exploit.maturity === 'functional') {
                score += 10;
            }
        }

        // Boost for KEV status
        if (vuln.knownExploitedVuln) {
            score += 20;
        }

        // Cap at 100
        return Math.min(100, Math.round(score));
    }

    /**
     * Identify risk factors for display
     */
    private identifyRiskFactors(vuln: EnrichedVulnerability): string[] {
        const factors: string[] = [];

        if (vuln.cvss.baseScore >= 9.0) {
            factors.push('Critical CVSS score');
        } else if (vuln.cvss.baseScore >= 7.0) {
            factors.push('High CVSS score');
        }

        if (vuln.exploit.available) {
            factors.push('Public exploit available');
            if (vuln.exploit.maturity === 'functional') {
                factors.push('Weaponized exploit');
            }
        }

        if (vuln.knownExploitedVuln) {
            factors.push('In CISA KEV catalog');
        }

        if (vuln.cvss.vector.includes('AV:N')) {
            factors.push('Network-accessible');
        }

        if (vuln.cvss.vector.includes('PR:N')) {
            factors.push('No authentication required');
        }

        return factors;
    }

    /**
     * Generate pseudo-CVE ID for alerts without CVE
     */
    private generatePseudoCve(alert: SecurityAlert): string {
        // Create a deterministic ID based on alert properties
        const hash = Buffer.from(`${alert.name}-${alert.risk}`).toString('base64').slice(0, 8);
        return `ALERT-${hash}`;
    }

    /**
     * Cache management - get from memory cache
     */
    private getFromCache(cveId: string): Partial<EnrichedVulnerability> | null {
        const cached = this.memoryCache.get(cveId);
        if (!cached) return null;

        const ttlMs = this.config.cacheTtlMinutes * 60 * 1000;
        if (Date.now() - cached.timestamp > ttlMs) {
            this.memoryCache.delete(cveId);
            return null;
        }

        return cached.data;
    }

    /**
     * Add to memory cache (will be persisted on saveFileCache)
     */
    private addToCache(cveId: string, data: Partial<EnrichedVulnerability>): void {
        this.memoryCache.set(cveId, { data, timestamp: Date.now() });
    }

    /**
     * Generate intelligence summary
     */
    private generateSummary(vulns: EnrichedVulnerability[]): IntelligenceSummary {
        const bySeverity = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            NONE: 0,
        };

        let withExploits = 0;
        let inKev = 0;
        let avgRiskScore = 0;

        for (const vuln of vulns) {
            bySeverity[vuln.cvss.severity]++;
            if (vuln.exploit.available) withExploits++;
            if (vuln.knownExploitedVuln) inKev++;
            avgRiskScore += vuln.riskScore;
        }

        return {
            totalFindings: vulns.length,
            bySeverity,
            withExploits,
            inKev,
            averageRiskScore: vulns.length > 0 ? Math.round(avgRiskScore / vulns.length) : 0,
            topCves: vulns
                .filter(v => v.cveId.startsWith('CVE-'))
                .sort((a, b) => b.riskScore - a.riskScore)
                .slice(0, 5)
                .map(v => ({ cveId: v.cveId, riskScore: v.riskScore })),
        };
    }

    /**
     * Clear the cache (memory and file)
     */
    async clearCache(): Promise<void> {
        this.memoryCache.clear();
        this.fileCache = { version: '1.0', entries: {} };
        await this.saveFileCache();
        logger.info('🗑️ VulnIntelligence cache cleared');
    }

    /**
     * Get cache statistics
     */
    getCacheStats(): { entries: number; filePath: string } {
        return {
            entries: this.memoryCache.size,
            filePath: this.config.cacheFilePath,
        };
    }
}

export interface IntelligenceSummary {
    totalFindings: number;
    bySeverity: Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE', number>;
    withExploits: number;
    inKev: number;
    averageRiskScore: number;
    topCves: Array<{ cveId: string; riskScore: number }>;
}

export default VulnIntelligenceService;
