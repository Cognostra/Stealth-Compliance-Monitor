# Plugin Development Guide

Complete guide to creating custom compliance checks for Stealth Compliance Monitor.

## Table of Contents

- [Quick Start](#quick-start)
- [Plugin Anatomy](#plugin-anatomy)
- [API Reference](#api-reference)
- [Common Patterns](#common-patterns)
- [Testing Plugins](#testing-plugins)
- [Publishing Plugins](#publishing-plugins)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### 1. Create Your Plugin File

Create a new `.ts` file in `custom_checks/`:

```bash
touch custom_checks/my-custom-check.ts
```

### 2. Add the Basic Structure

```typescript
import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../src/core/CustomCheckLoader';

export async function check(
    page: Page,
    context: CustomCheckContext
): Promise<CustomCheckViolation[]> {
    const violations: CustomCheckViolation[] = [];
    
    // Your logic here
    
    return violations;
}
```

### 3. Enable Custom Checks

In your `.env`:

```bash
CUSTOM_CHECKS_ENABLED=true
CUSTOM_CHECKS_DIR=./custom_checks
```

### 4. Run and Test

```bash
npm run dev
```

Your check runs automatically on every page scanned!

---

## Plugin Anatomy

### File Header (Recommended)

```typescript
/**
 * Plugin Name
 * 
 * Brief description of what this plugin checks.
 * 
 * Configuration:
 *   MY_PLUGIN_OPTION - Description (default: value)
 * 
 * @author Your Name
 * @version 1.0.0
 * @tags tag1, tag2, tag3
 */
```

### Required Export

Your plugin **must** export a function named `check`:

```typescript
export async function check(
    page: Page,
    context: CustomCheckContext
): Promise<CustomCheckViolation[]>
```

### Return Type

Always return an array of `CustomCheckViolation` objects (can be empty).

---

## API Reference

### CustomCheckContext

```typescript
interface CustomCheckContext {
    /** Current page URL being scanned */
    currentUrl: string;
    
    /** Original target URL */
    targetUrl: string;
    
    /** Logger instance */
    logger: {
        debug(message: string): void;
        info(message: string): void;
        warn(message: string): void;
        error(message: string): void;
    };
    
    /** Full application configuration */
    config: ComplianceConfig;
}
```

### CustomCheckViolation

```typescript
interface CustomCheckViolation {
    /** Unique identifier (e.g., 'my-check-issue-name') */
    id: string;
    
    /** Short title for the issue */
    title: string;
    
    /** Severity level */
    severity: 'critical' | 'high' | 'medium' | 'low';
    
    /** Detailed description of the issue */
    description: string;
    
    /** How to fix the issue (optional but recommended) */
    remediation?: string;
    
    /** URL where the issue was found (optional) */
    url?: string;
    
    /** CSS selector of the problematic element (optional) */
    selector?: string;
    
    /** Evidence supporting the finding (optional) */
    evidence?: string;
}
```

### Playwright Page API

The `page` parameter is a Playwright Page object with full access to:

- `page.$()` - Query single element
- `page.$$()` - Query all elements
- `page.evaluate()` - Run JavaScript in browser
- `page.textContent()` - Get text content
- `page.getAttribute()` - Get element attribute
- `page.locator()` - Create locator for element

See [Playwright Documentation](https://playwright.dev/docs/api/class-page) for full API.

---

## Common Patterns

### Pattern 1: Check for Element Presence

```typescript
export async function check(page: Page, context: CustomCheckContext) {
    const violations: CustomCheckViolation[] = [];
    
    const element = await page.$('selector');
    if (!element) {
        violations.push({
            id: 'my-check-element-missing',
            title: 'Required Element Missing',
            severity: 'high',
            description: 'The required element was not found.',
            remediation: 'Add the required element to the page.',
        });
    }
    
    return violations;
}
```

### Pattern 2: Validate Element Content

```typescript
export async function check(page: Page, context: CustomCheckContext) {
    const violations: CustomCheckViolation[] = [];
    
    const content = await page.textContent('h1');
    
    if (!content || content.length < 10) {
        violations.push({
            id: 'my-check-h1-too-short',
            title: 'H1 Too Short',
            severity: 'medium',
            description: `H1 content "${content}" is too short.`,
            remediation: 'Provide a more descriptive page heading.',
            selector: 'h1',
        });
    }
    
    return violations;
}
```

### Pattern 3: Evaluate JavaScript in Browser

```typescript
export async function check(page: Page, context: CustomCheckContext) {
    const violations: CustomCheckViolation[] = [];
    
    const data = await page.evaluate(() => {
        // This runs in the browser context
        return {
            hasJQuery: typeof window.jQuery !== 'undefined',
            documentTitle: document.title,
            linkCount: document.querySelectorAll('a').length,
        };
    });
    
    if (data.hasJQuery) {
        violations.push({
            id: 'my-check-jquery-detected',
            title: 'jQuery Detected',
            severity: 'low',
            description: 'jQuery is loaded on this page.',
            evidence: 'window.jQuery is defined',
        });
    }
    
    return violations;
}
```

### Pattern 4: Check Multiple Elements

```typescript
export async function check(page: Page, context: CustomCheckContext) {
    const violations: CustomCheckViolation[] = [];
    
    const images = await page.$$('img');
    
    for (const img of images) {
        const alt = await img.getAttribute('alt');
        const src = await img.getAttribute('src');
        
        if (!alt) {
            violations.push({
                id: 'my-check-img-no-alt',
                title: 'Image Missing Alt Text',
                severity: 'high',
                description: 'Image is missing alt attribute.',
                selector: `img[src="${src}"]`,
                remediation: 'Add descriptive alt text to the image.',
            });
        }
    }
    
    return violations;
}
```

### Pattern 5: Network Request Analysis

```typescript
export async function check(page: Page, context: CustomCheckContext) {
    const violations: CustomCheckViolation[] = [];
    
    // Get performance entries
    const resources = await page.evaluate(() => {
        return performance.getEntriesByType('resource').map(r => ({
            name: r.name,
            size: (r as PerformanceResourceTiming).transferSize,
            type: (r as PerformanceResourceTiming).initiatorType,
        }));
    });
    
    const largeResources = resources.filter(r => r.size > 500000);
    
    for (const resource of largeResources) {
        violations.push({
            id: 'my-check-large-resource',
            title: 'Large Resource Detected',
            severity: 'medium',
            description: `Resource ${resource.name} is ${Math.round(resource.size / 1024)}KB.`,
            remediation: 'Optimize or compress this resource.',
        });
    }
    
    return violations;
}
```

### Pattern 6: Configuration from Environment

```typescript
const CONFIG = {
    maxImageSize: parseInt(process.env.MY_CHECK_MAX_IMAGE_KB || '200') * 1024,
    requiredMetaTags: (process.env.MY_CHECK_REQUIRED_META || 'description,viewport').split(','),
    strictMode: process.env.MY_CHECK_STRICT === 'true',
};

export async function check(page: Page, context: CustomCheckContext) {
    const violations: CustomCheckViolation[] = [];
    
    context.logger.debug(`[MyCheck] Config: ${JSON.stringify(CONFIG)}`);
    
    // Use CONFIG values in your checks
    
    return violations;
}
```

### Pattern 7: Async/Await with Error Handling

```typescript
export async function check(page: Page, context: CustomCheckContext) {
    const violations: CustomCheckViolation[] = [];
    
    try {
        const result = await page.evaluate(() => {
            // Complex browser logic
        });
        
        // Process result
        
    } catch (error) {
        context.logger.warn(`[MyCheck] Failed: ${error}`);
        // Optionally add a violation for the failure
    }
    
    return violations;
}
```

---

## Testing Plugins

### Manual Testing

1. Create a test HTML file:

```html
<!-- test-fixtures/my-test.html -->
<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
    <h1>Test Content</h1>
</body>
</html>
```

2. Run against local server:

```bash
npx serve test-fixtures &
LIVE_URL=http://localhost:3000/my-test.html npm run dev
```

### Unit Testing

```typescript
// tests/custom-checks/my-check.test.ts
import { chromium } from 'playwright';
import { check } from '../../custom_checks/my-check';

describe('My Custom Check', () => {
    let browser, page;
    
    beforeAll(async () => {
        browser = await chromium.launch();
    });
    
    afterAll(async () => {
        await browser.close();
    });
    
    beforeEach(async () => {
        page = await browser.newPage();
    });
    
    afterEach(async () => {
        await page.close();
    });
    
    it('should detect missing element', async () => {
        await page.setContent('<html><body></body></html>');
        
        const violations = await check(page, {
            currentUrl: 'http://test.com',
            targetUrl: 'http://test.com',
            logger: console,
            config: {},
        });
        
        expect(violations).toHaveLength(1);
        expect(violations[0].id).toBe('my-check-element-missing');
    });
});
```

---

## Publishing Plugins

### 1. Add Documentation

Include a JSDoc header:

```typescript
/**
 * My Awesome Check
 * 
 * Detailed description of what this checks.
 * 
 * @author Your Name <email@example.com>
 * @version 1.0.0
 * @tags security, compliance, custom
 */
```

### 2. Submit to Community

1. Fork the repository
2. Add your plugin to `plugins/community/`
3. Update `plugins/README.md` gallery
4. Submit a Pull Request

### 3. NPM Package (Advanced)

You can also publish as a standalone npm package:

```json
{
  "name": "scm-plugin-my-check",
  "version": "1.0.0",
  "main": "index.ts",
  "peerDependencies": {
    "playwright": "^1.40.0"
  }
}
```

Users install with:
```bash
npm install scm-plugin-my-check
cp node_modules/scm-plugin-my-check/index.ts custom_checks/
```

---

## Troubleshooting

### Plugin Not Loading

1. Check file extension is `.ts`
2. Verify `CUSTOM_CHECKS_ENABLED=true`
3. Check `CUSTOM_CHECKS_DIR` path is correct
4. Look for TypeScript errors in console

### Violations Not Appearing

1. Add `context.logger.debug()` statements
2. Check if your selectors match
3. Verify the check function returns violations
4. Test with simpler logic first

### Performance Issues

1. Avoid heavy DOM queries
2. Use `page.$()` instead of `page.$$()` when possible
3. Batch `page.evaluate()` calls
4. Add timeouts for network-dependent checks

### TypeScript Errors

Ensure you have the correct imports:

```typescript
import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../src/core/CustomCheckLoader';
```

### Browser Context Issues

Remember that `page.evaluate()` runs in an isolated browser context:

```typescript
// ❌ Won't work - can't access Node.js variables
const myVar = 'test';
await page.evaluate(() => {
    console.log(myVar); // undefined!
});

// ✅ Pass variables as arguments
await page.evaluate((variable) => {
    console.log(variable); // 'test'
}, myVar);
```

---

## Need Help?

- 💬 [GitHub Discussions](https://github.com/Cognostra/Stealth-Compliance-Monitor/discussions)
- 📖 [Playwright Docs](https://playwright.dev/docs/api/class-page)
- 🐛 [Report Issues](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues)
