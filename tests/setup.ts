/**
 * Jest Global Setup
 * Runs after environment setup, before each test file
 */

import { jest } from '@jest/globals';
import { resetConfig } from '../src/config/env.js';

// Increase timeout for integration tests
jest.setTimeout(30000);

// Reset config singleton before each test to prevent pollution
beforeEach(() => {
  resetConfig();
});

// Global teardown
afterAll(async () => {
  // Clean up any resources
});
