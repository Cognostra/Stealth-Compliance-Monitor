/**
 * Global Setup for Integration Tests
 *
 * Runs once before all tests to:
 * - Check environment configuration
 * - Verify Docker/ZAP availability (if needed)
 * - Create necessary directories
 */

import { FullConfig } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

async function globalSetup(config: FullConfig): Promise<void> {
    console.log('\n🚀 Running global setup for integration tests...\n');

    // Ensure required directories exist
    const dirs = [
        'test-results',
        'playwright-report',
        'screenshots',
        'reports',
        'logs',
    ];

    for (const dir of dirs) {
        const dirPath = path.resolve(process.cwd(), dir);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
            console.log(`📁 Created directory: ${dir}`);
        }
    }

    // Set default test environment variables if not set
    if (!process.env.LIVE_URL) {
        process.env.LIVE_URL = 'https://example.com';
    }
    if (!process.env.TEST_EMAIL) {
        process.env.TEST_EMAIL = 'test@example.com';
    }
    if (!process.env.TEST_PASSWORD) {
        process.env.TEST_PASSWORD = 'test_password';
    }
    if (!process.env.MIN_DELAY_MS) {
        process.env.MIN_DELAY_MS = '100'; // Fast for tests
    }
    if (!process.env.MAX_DELAY_MS) {
        process.env.MAX_DELAY_MS = '200';
    }

    // Check if ZAP is needed and available
    const zapUrl = process.env.ZAP_PROXY_URL || 'http://localhost:8080';
    const hasZapTests = config.projects.some(p => p.name === 'e2e-with-zap');

    if (hasZapTests) {
        console.log(`🔒 Checking ZAP availability at ${zapUrl}...`);
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);

            const response = await fetch(`${zapUrl}/JSON/core/view/version/`, {
                signal: controller.signal,
            });
            clearTimeout(timeout);

            if (response.ok) {
                const data = await response.json() as { version: string };
                console.log(`✅ ZAP is available (version: ${data.version})`);
            } else {
                console.warn(`⚠️ ZAP responded with status ${response.status}`);
            }
        } catch (error) {
            console.warn(`⚠️ ZAP is not available at ${zapUrl}. ZAP tests may be skipped.`);
            console.warn('   Run "docker-compose up -d zaproxy" to start ZAP.');
        }
    }

    console.log('\n✅ Global setup complete\n');
}

export default globalSetup;
