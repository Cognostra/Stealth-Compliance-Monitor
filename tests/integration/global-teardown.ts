/**
 * Global Teardown for Integration Tests
 *
 * Runs once after all tests to:
 * - Clean up resources
 * - Close any remaining browser sessions
 * - Generate summary
 */

import { FullConfig } from '@playwright/test';
import { BrowserService } from '../../src/services/BrowserService.js';

async function globalTeardown(config: FullConfig): Promise<void> {
    console.log('\n🧹 Running global teardown...\n');

    // Close all active browser sessions
    try {
        await BrowserService.closeAll();
        console.log('✅ Closed all browser sessions');
    } catch (error) {
        console.warn('⚠️ Error closing browser sessions:', error);
    }

    console.log('\n✅ Global teardown complete\n');
}

export default globalTeardown;
