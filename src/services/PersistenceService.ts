/**
 * PersistenceService - Write-Ahead Logging (WAL) for Crash Resilience
 * 
 * Prevents data loss during long scans by immediately writing each finding
 * to a JSON Lines (.jsonl) file. If the script crashes, data can be recovered
 * by reading the log file.
 * 
 * Architecture:
 * - Each log entry is a single line of JSON (JSON Lines format)
 * - Entries are appended immediately (sync for critical data, async for performance)
 * - The hydrate() method reconstructs the full state from the log
 * - Session files are timestamped for easy identification
 * 
 * Log Entry Types:
 * - 'session_start': Initial session metadata
 * - 'page_result': Completed page crawl result
 * - 'network_incident': Network security finding
 * - 'leaked_secret': Secret detection finding
 * - 'console_error': Console error captured
 * - 'supabase_issue': Supabase security issue
 * - 'vuln_library': Vulnerable library detection
 * - 'security_finding': ZAP or other security finding
 * - 'session_end': Session completion marker
 */

import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Log entry types for type safety
 */
export type LogEntryType =
    | 'session_start'
    | 'session_end'
    | 'page_result'
    | 'network_incident'
    | 'leaked_secret'
    | 'console_error'
    | 'supabase_issue'
    | 'vuln_library'
    | 'security_finding'
    | 'security_assessment'
    | 'a11y_issue'
    | 'seo_issue'
    | 'broken_link'
    | 'broken_asset'
    | 'visual_regression'
    | 'custom';

/**
 * Structure of each log entry
 */
export interface WALEntry<T = unknown> {
    timestamp: string;
    type: LogEntryType;
    sequence: number;
    payload: T;
}

/**
 * Session metadata stored at start
 */
export interface SessionMetadata {
    sessionId: string;
    startUrl: string;
    startTime: string;
    version: string;
}

/**
 * Hydrated session data reconstructed from the log
 */
export interface HydratedSession {
    metadata: SessionMetadata | null;
    pageResults: unknown[];
    networkIncidents: unknown[];
    leakedSecrets: unknown[];
    consoleErrors: unknown[];
    supabaseIssues: unknown[];
    vulnLibraries: unknown[];
    securityFindings: unknown[];
    securityAssessments: unknown[]; // New field
    a11yIssues: unknown[];
    seoIssues: unknown[];
    brokenLinks: unknown[];
    brokenAssets: unknown[];
    visualRegressions: unknown[];
    customEntries: unknown[];
    isComplete: boolean;
    entryCount: number;
}



// ═══════════════════════════════════════════════════════════════════════════════
// PERSISTENCE SERVICE CLASS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * PersistenceService Class
 * 
 * Provides write-ahead logging for crash resilience during compliance scans.
 */
export class PersistenceService {
    private logFilePath: string | null = null;
    private sessionId: string | null = null;
    private sequence: number = 0;
    private isInitialized: boolean = false;
    private writeStream: fs.WriteStream | null = null;

    // Directory for temporary session logs
    private static readonly TEMP_DIR = 'reports/temp';
    private static readonly VERSION = '1.0.0';

    /**
     * Initialize a new logging session
     * Creates the temp directory and log file
     * @param startUrl - The starting URL for this session
     * @returns Path to the created log file
     */
    async init(startUrl: string): Promise<string> {
        // Generate unique session ID
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        this.sessionId = `session-${timestamp}`;
        this.sequence = 0;

        // Ensure temp directory exists
        const tempDir = path.resolve(process.cwd(), PersistenceService.TEMP_DIR);
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
            logger.debug(`Created temp directory: ${tempDir}`);
        }

        // Create log file path
        this.logFilePath = path.join(tempDir, `${this.sessionId}.jsonl`);

        // Open write stream for appending
        this.writeStream = fs.createWriteStream(this.logFilePath, {
            flags: 'a',
            encoding: 'utf8'
        });

        this.isInitialized = true;

        // Log session start
        const metadata: SessionMetadata = {
            sessionId: this.sessionId,
            startUrl,
            startTime: new Date().toISOString(),
            version: PersistenceService.VERSION,
        };

        await this.log('session_start', metadata);

        logger.info(`📝 WAL initialized: ${this.logFilePath}`);
        return this.logFilePath;
    }

    /**
     * Append a log entry to the WAL file
     * Uses synchronous write for data safety
     * @param type - The type of entry
     * @param payload - The data to log
     */
    async log<T>(type: LogEntryType, payload: T): Promise<void> {
        if (!this.isInitialized || !this.logFilePath) {
            logger.warn('PersistenceService not initialized. Call init() first.');
            return;
        }

        const entry: WALEntry<T> = {
            timestamp: new Date().toISOString(),
            type,
            sequence: this.sequence++,
            payload,
        };

        const line = JSON.stringify(entry) + '\n';

        try {
            // Use synchronous write for critical data safety
            fs.appendFileSync(this.logFilePath, line, 'utf8');
        } catch (error) {
            logger.error(`Failed to write to WAL: ${error}`);
            // Don't throw - we don't want logging failures to crash the scan
        }
    }

    /**
     * Log a batch of entries efficiently
     * @param entries - Array of type/payload pairs
     */
    async logBatch(entries: Array<{ type: LogEntryType; payload: unknown }>): Promise<void> {
        for (const entry of entries) {
            await this.log(entry.type, entry.payload);
        }
    }

    /**
     * Mark the session as complete
     * @param summary - Optional summary data
     */
    async complete(summary?: unknown): Promise<void> {
        await this.log('session_end', {
            endTime: new Date().toISOString(),
            totalEntries: this.sequence,
            summary,
        });

        // Close write stream
        if (this.writeStream) {
            this.writeStream.end();
            this.writeStream = null;
        }

        logger.info(`📝 WAL session complete: ${this.sequence} entries written`);
    }

    /**
     * Hydrate session data from a log file
     * Reconstructs the full state by reading all entries
     * @param logFilePath - Path to the .jsonl file (optional, uses current session if not provided)
     * @returns Reconstructed session data
     */
    static hydrate(logFilePath: string): HydratedSession {
        const session: HydratedSession = {
            metadata: null,
            pageResults: [],
            networkIncidents: [],
            leakedSecrets: [],
            consoleErrors: [],
            supabaseIssues: [],
            vulnLibraries: [],
            securityFindings: [],
            securityAssessments: [],
            a11yIssues: [],
            seoIssues: [],
            brokenLinks: [],
            brokenAssets: [],
            visualRegressions: [],
            customEntries: [],
            isComplete: false,
            entryCount: 0,
        };

        if (!fs.existsSync(logFilePath)) {
            logger.warn(`WAL file not found: ${logFilePath}`);
            return session;
        }

        try {
            const content = fs.readFileSync(logFilePath, 'utf8');
            const lines = content.trim().split('\n').filter(line => line.trim());

            for (const line of lines) {
                try {
                    const entry: WALEntry = JSON.parse(line);
                    session.entryCount++;

                    switch (entry.type) {
                        case 'session_start':
                            session.metadata = entry.payload as SessionMetadata;
                            break;
                        case 'session_end':
                            session.isComplete = true;
                            break;
                        case 'page_result':
                            session.pageResults.push(entry.payload);
                            break;
                        case 'network_incident':
                            session.networkIncidents.push(entry.payload);
                            break;
                        case 'leaked_secret':
                            session.leakedSecrets.push(entry.payload);
                            break;
                        case 'console_error':
                            session.consoleErrors.push(entry.payload);
                            break;
                        case 'supabase_issue':
                            session.supabaseIssues.push(entry.payload);
                            break;
                        case 'vuln_library':
                            session.vulnLibraries.push(entry.payload);
                            break;
                        case 'security_finding':
                            session.securityFindings.push(entry.payload);
                            break;
                        case 'security_assessment':
                            session.securityAssessments.push(entry.payload);
                            break;
                        case 'a11y_issue':
                            session.a11yIssues.push(entry.payload);
                            break;
                        case 'seo_issue':
                            session.seoIssues.push(entry.payload);
                            break;
                        case 'broken_link':
                            session.brokenLinks.push(entry.payload);
                            break;
                        case 'broken_asset':
                            session.brokenAssets.push(entry.payload);
                            break;
                        case 'visual_regression':
                            session.visualRegressions.push(entry.payload);
                            break;
                        case 'custom':
                            session.customEntries.push(entry.payload);
                            break;
                    }
                } catch (parseError) {
                    logger.warn(`Failed to parse WAL line: ${line.substring(0, 50)}...`);
                }
            }

            logger.info(`📖 Hydrated ${session.entryCount} entries from WAL`);
        } catch (error) {
            logger.error(`Failed to hydrate WAL: ${error}`);
        }

        return session;
    }

    /**
     * Find incomplete sessions that can be resumed
     * @returns Array of log file paths for sessions that didn't complete
     */
    static findIncompleteSessions(): string[] {
        const tempDir = path.resolve(process.cwd(), PersistenceService.TEMP_DIR);

        if (!fs.existsSync(tempDir)) {
            return [];
        }

        const incomplete: string[] = [];
        const files = fs.readdirSync(tempDir).filter(f => f.endsWith('.jsonl'));

        for (const file of files) {
            const filePath = path.join(tempDir, file);
            const session = PersistenceService.hydrate(filePath);

            if (!session.isComplete && session.metadata) {
                incomplete.push(filePath);
            }
        }

        return incomplete;
    }

    /**
     * Clean up old completed session files
     * @param maxAgeDays - Delete files older than this (default: 7 days)
     */
    static cleanup(maxAgeDays: number = 7): void {
        const tempDir = path.resolve(process.cwd(), PersistenceService.TEMP_DIR);

        if (!fs.existsSync(tempDir)) {
            return;
        }

        const cutoff = Date.now() - (maxAgeDays * 24 * 60 * 60 * 1000);
        const files = fs.readdirSync(tempDir).filter(f => f.endsWith('.jsonl'));
        let deleted = 0;

        for (const file of files) {
            const filePath = path.join(tempDir, file);
            const stats = fs.statSync(filePath);

            if (stats.mtimeMs < cutoff) {
                fs.unlinkSync(filePath);
                deleted++;
            }
        }

        if (deleted > 0) {
            logger.info(`🧹 Cleaned up ${deleted} old WAL files`);
        }
    }

    /**
     * Get the current log file path
     */
    getLogFilePath(): string | null {
        return this.logFilePath;
    }

    /**
     * Get the current session ID
     */
    getSessionId(): string | null {
        return this.sessionId;
    }

    /**
     * Check if the service is initialized
     */
    isActive(): boolean {
        return this.isInitialized;
    }

    /**
     * Get current entry count
     */
    getEntryCount(): number {
        return this.sequence;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SINGLETON INSTANCE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Default persistence service instance
 * Can be imported and used across the application
 */
export const persistenceService = new PersistenceService();

export default PersistenceService;
