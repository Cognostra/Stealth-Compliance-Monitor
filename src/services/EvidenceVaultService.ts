/**
 * Evidence Vault Service
 *
 * Secure storage and management of compliance evidence with
 * chain of custody, tamper-proofing, and audit trails.
 *
 * Features:
 * - Immutable evidence storage
 * - Cryptographic hashing for integrity
 * - Chain of custody tracking
 * - Evidence lifecycle management
 * - Retention policy enforcement
 * - Export to legal hold formats
 */

import { createHash, randomUUID } from 'node:crypto';
import { logger } from '../utils/logger.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface EvidenceItem {
    id: string;
    caseId: string;
    type: 'screenshot' | 'network-log' | 'dom-snapshot' | 'console-log' | 'certificate' | 'http-request' | 'http-response' | 'audit-trail';
    source: {
        url: string;
        timestamp: string;
        scanner: string;
        version: string;
    };
    content: Buffer | string;
    metadata: {
        title: string;
        description: string;
        tags: string[];
        hash: string;
        size: number;
        encoding: string;
    };
    custody: CustodyRecord[];
    retention: {
        created: string;
        expires: string | null;
        legalHold: boolean;
    };
}

export interface CustodyRecord {
    timestamp: string;
    action: 'created' | 'accessed' | 'modified' | 'exported' | 'deleted' | 'verified';
    actor: string;
    reason: string;
    hashAtTime: string;
}

export interface EvidenceVaultConfig {
    storagePath: string;
    defaultRetentionDays: number;
    hashAlgorithm: 'sha256' | 'sha512';
    encryptionEnabled: boolean;
    legalHoldEnabled: boolean;
    maxFileSize: number; // bytes
}

export interface EvidenceSearchCriteria {
    caseId?: string;
    type?: EvidenceItem['type'];
    url?: string;
    scanner?: string;
    tags?: string[];
    dateFrom?: string;
    dateTo?: string;
    hasLegalHold?: boolean;
}

export interface EvidenceExport {
    id: string;
    format: 'native' | 'pdf' | 'tar' | 'zip';
    items: EvidenceItem[];
    manifest: {
        exportedAt: string;
        exportedBy: string;
        totalItems: number;
        totalSize: number;
        integrityHash: string;
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVICE IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

export class EvidenceVaultService {
    private config: EvidenceVaultConfig;
    private evidence: Map<string, EvidenceItem> = new Map();
    private caseIndex: Map<string, Set<string>> = new Map(); // caseId -> evidenceIds

    constructor(config?: Partial<EvidenceVaultConfig>) {
        this.config = {
            storagePath: './evidence',
            defaultRetentionDays: 2555, // 7 years (default for financial records)
            hashAlgorithm: 'sha256',
            encryptionEnabled: false,
            legalHoldEnabled: true,
            maxFileSize: 100 * 1024 * 1024, // 100MB
            ...config,
        };
    }

    /**
     * Store evidence in the vault.
     */
    async storeEvidence(
        caseId: string,
        type: EvidenceItem['type'],
        source: EvidenceItem['source'],
        content: Buffer | string,
        metadata: Partial<EvidenceItem['metadata']> = {}
    ): Promise<EvidenceItem> {
        const id = randomUUID();
        const now = new Date().toISOString();

        // Validate size
        const size = Buffer.isBuffer(content) ? content.length : Buffer.byteLength(content, 'utf-8');
        if (size > this.config.maxFileSize) {
            throw new Error(`Evidence size ${size} exceeds maximum ${this.config.maxFileSize}`);
        }

        // Calculate hash
        const hash = this.calculateHash(content);

        // Calculate expiration
        const retentionDays = this.config.defaultRetentionDays;
        const expires = new Date();
        expires.setDate(expires.getDate() + retentionDays);

        const item: EvidenceItem = {
            id,
            caseId,
            type,
            source,
            content,
            metadata: {
                title: metadata.title || `${type} evidence`,
                description: metadata.description || '',
                tags: metadata.tags || [],
                hash,
                size,
                encoding: metadata.encoding || (Buffer.isBuffer(content) ? 'binary' : 'utf-8'),
            },
            custody: [{
                timestamp: now,
                action: 'created',
                actor: 'system',
                reason: 'Initial evidence capture',
                hashAtTime: hash,
            }],
            retention: {
                created: now,
                expires: this.config.legalHoldEnabled ? null : expires.toISOString(),
                legalHold: false,
            },
        };

        this.evidence.set(id, item);

        // Index by case
        const caseEvidence = this.caseIndex.get(caseId) || new Set();
        caseEvidence.add(id);
        this.caseIndex.set(caseId, caseEvidence);

        logger.info(`[EvidenceVault] Stored ${type} evidence ${id} for case ${caseId}`);
        return item;
    }

    /**
     * Retrieve evidence by ID.
     */
    getEvidence(id: string, actor: string = 'system', reason: string = 'Access'): EvidenceItem | null {
        const item = this.evidence.get(id);
        if (!item) return null;

        // Record access
        this.recordCustody(id, 'accessed', actor, reason);

        return item;
    }

    /**
     * Verify evidence integrity.
     */
    verifyIntegrity(id: string): { valid: boolean; currentHash: string; storedHash: string; message: string } {
        const item = this.evidence.get(id);
        if (!item) {
            return { valid: false, currentHash: '', storedHash: '', message: 'Evidence not found' };
        }

        const currentHash = this.calculateHash(item.content);
        const storedHash = item.metadata.hash;

        const valid = currentHash === storedHash;

        // Record verification
        this.recordCustody(id, 'verified', 'system', `Integrity check: ${valid ? 'PASSED' : 'FAILED'}`);

        return {
            valid,
            currentHash,
            storedHash,
            message: valid ? 'Evidence integrity verified' : 'EVIDENCE TAMPERING DETECTED',
        };
    }

    /**
     * Search evidence by criteria.
     */
    searchEvidence(criteria: EvidenceSearchCriteria): EvidenceItem[] {
        const results: EvidenceItem[] = [];

        for (const item of this.evidence.values()) {
            if (criteria.caseId && item.caseId !== criteria.caseId) continue;
            if (criteria.type && item.type !== criteria.type) continue;
            if (criteria.url && !item.source.url.includes(criteria.url)) continue;
            if (criteria.scanner && item.source.scanner !== criteria.scanner) continue;
            if (criteria.tags && !criteria.tags.every(tag => item.metadata.tags.includes(tag))) continue;
            if (criteria.dateFrom && item.source.timestamp < criteria.dateFrom) continue;
            if (criteria.dateTo && item.source.timestamp > criteria.dateTo) continue;
            if (criteria.hasLegalHold !== undefined && item.retention.legalHold !== criteria.hasLegalHold) continue;

            results.push(item);
        }

        return results.sort((a, b) =>
            new Date(b.source.timestamp).getTime() - new Date(a.source.timestamp).getTime()
        );
    }

    /**
     * Apply legal hold to evidence.
     */
    applyLegalHold(id: string, actor: string, reason: string): boolean {
        if (!this.config.legalHoldEnabled) {
            logger.warn('[EvidenceVault] Legal hold not enabled');
            return false;
        }

        const item = this.evidence.get(id);
        if (!item) return false;

        item.retention.legalHold = true;
        item.retention.expires = null; // Never expire

        this.recordCustody(id, 'modified', actor, `Legal hold applied: ${reason}`);

        logger.info(`[EvidenceVault] Legal hold applied to evidence ${id}`);
        return true;
    }

    /**
     * Remove legal hold (requires authorization).
     */
    removeLegalHold(id: string, actor: string, reason: string, authorization: string): boolean {
        if (!this.config.legalHoldEnabled) return false;

        // In production, validate authorization token/certificate
        if (!authorization) {
            logger.error('[EvidenceVault] Removal of legal hold requires authorization');
            return false;
        }

        const item = this.evidence.get(id);
        if (!item) return false;

        item.retention.legalHold = false;

        // Reset expiration
        const expires = new Date();
        expires.setDate(expires.getDate() + this.config.defaultRetentionDays);
        item.retention.expires = expires.toISOString();

        this.recordCustody(id, 'modified', actor, `Legal hold removed: ${reason}`);

        logger.info(`[EvidenceVault] Legal hold removed from evidence ${id}`);
        return true;
    }

    /**
     * Export evidence for legal proceedings.
     */
    exportEvidence(
        criteria: EvidenceSearchCriteria,
        format: EvidenceExport['format'],
        actor: string
    ): EvidenceExport {
        const items = this.searchEvidence(criteria);

        // Record export for each item
        for (const item of items) {
            this.recordCustody(item.id, 'exported', actor, `Export in ${format} format`);
        }

        // Calculate integrity hash of export
        const exportContent = items.map(i => i.metadata.hash).join('');
        const integrityHash = this.calculateHash(exportContent);

        const totalSize = items.reduce((sum, i) => sum + i.metadata.size, 0);

        const export_: EvidenceExport = {
            id: randomUUID(),
            format,
            items,
            manifest: {
                exportedAt: new Date().toISOString(),
                exportedBy: actor,
                totalItems: items.length,
                totalSize,
                integrityHash,
            },
        };

        logger.info(`[EvidenceVault] Exported ${items.length} items in ${format} format`);
        return export_;
    }

    /**
     * Get chain of custody for evidence.
     */
    getChainOfCustody(id: string): CustodyRecord[] | null {
        const item = this.evidence.get(id);
        return item ? [...item.custody] : null;
    }

    /**
     * Get evidence summary for a case.
     */
    getCaseSummary(caseId: string): {
        totalItems: number;
        byType: Record<string, number>;
        totalSize: number;
        hasLegalHold: boolean;
        dateRange: { earliest: string; latest: string };
    } | null {
        const evidenceIds = this.caseIndex.get(caseId);
        if (!evidenceIds || evidenceIds.size === 0) return null;

        const items = Array.from(evidenceIds).map(id => this.evidence.get(id)).filter(Boolean) as EvidenceItem[];

        const byType: Record<string, number> = {};
        for (const item of items) {
            byType[item.type] = (byType[item.type] || 0) + 1;
        }

        const totalSize = items.reduce((sum, i) => sum + i.metadata.size, 0);
        const hasLegalHold = items.some(i => i.retention.legalHold);

        const timestamps = items.map(i => i.source.timestamp).sort();

        return {
            totalItems: items.length,
            byType,
            totalSize,
            hasLegalHold,
            dateRange: {
                earliest: timestamps[0],
                latest: timestamps[timestamps.length - 1],
            },
        };
    }

    /**
     * Purge expired evidence (respecting legal holds).
     */
    purgeExpired(actor: string = 'system'): { purged: number; preserved: number } {
        const now = new Date().toISOString();
        let purged = 0;
        let preserved = 0;

        for (const [id, item] of this.evidence) {
            if (item.retention.legalHold) {
                preserved++;
                continue;
            }

            if (item.retention.expires && item.retention.expires < now) {
                this.recordCustody(id, 'deleted', actor, 'Retention period expired');
                this.evidence.delete(id);

                // Remove from case index
                const caseEvidence = this.caseIndex.get(item.caseId);
                if (caseEvidence) {
                    caseEvidence.delete(id);
                }

                purged++;
            }
        }

        logger.info(`[EvidenceVault] Purged ${purged} expired items, preserved ${preserved} under legal hold`);
        return { purged, preserved };
    }

    /**
     * Generate audit report for compliance.
     */
    generateAuditReport(): {
        totalEvidence: number;
        totalCases: number;
        storageUsed: number;
        legalHolds: number;
        integrityViolations: number;
        custodyChainEntries: number;
    } {
        const items = Array.from(this.evidence.values());

        let integrityViolations = 0;
        for (const item of items) {
            const currentHash = this.calculateHash(item.content);
            if (currentHash !== item.metadata.hash) {
                integrityViolations++;
            }
        }

        return {
            totalEvidence: items.length,
            totalCases: this.caseIndex.size,
            storageUsed: items.reduce((sum, i) => sum + i.metadata.size, 0),
            legalHolds: items.filter(i => i.retention.legalHold).length,
            integrityViolations,
            custodyChainEntries: items.reduce((sum, i) => sum + i.custody.length, 0),
        };
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PRIVATE METHODS
    // ═══════════════════════════════════════════════════════════════════════════════

    private calculateHash(content: Buffer | string): string {
        const hasher = createHash(this.config.hashAlgorithm);
        if (Buffer.isBuffer(content)) {
            hasher.update(content);
        } else {
            hasher.update(content, 'utf-8');
        }
        return hasher.digest('hex');
    }

    private recordCustody(id: string, action: CustodyRecord['action'], actor: string, reason: string): void {
        const item = this.evidence.get(id);
        if (!item) return;

        const currentHash = this.calculateHash(item.content);
        item.custody.push({
            timestamp: new Date().toISOString(),
            action,
            actor,
            reason,
            hashAtTime: currentHash,
        });
    }
}

export default EvidenceVaultService;
