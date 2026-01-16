/**
 * Jest Environment Setup
 * Sets mock environment variables before tests run
 */

process.env.LIVE_URL = 'https://example.com';
process.env.TEST_EMAIL = 'test@example.com';
process.env.TEST_PASSWORD = 'test_password_123';
process.env.ZAP_PROXY_URL = 'http://localhost:8080';
process.env.MIN_DELAY_MS = '100'; // Fast for tests
process.env.MAX_DELAY_MS = '200';
process.env.SCREENSHOTS_DIR = './test-screenshots';
process.env.REPORTS_DIR = './test-reports';
process.env.ENABLE_AI = 'false';
