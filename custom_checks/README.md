# Custom Compliance Checks

This directory is for user-defined compliance checks written in TypeScript or JavaScript.
These checks are automatically loaded and executed during the compliance scan.

## How it Works

1. **Create a file** in this directory (e.g., `cookie-banner.ts`).
2. **Export a function** named `check` (or default export).
3. **Use Playwright** to inspect the page.
4. **Return violations** if found.

## Example

```typescript
import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../src/core/CustomCheckLoader';

export async function check(page: Page, context: CustomCheckContext): Promise<CustomCheckViolation[]> {
    const violations: CustomCheckViolation[] = [];

    // Check for cookie banner
    const banner = await page.$('#cookie-banner');
    if (!banner) {
        violations.push({
            id: 'cookie-banner-missing',
            title: 'Cookie Banner Missing',
            severity: 'high',
            description: 'The site must have a cookie consent banner.',
            remediation: 'Implement a cookie consent banner visible on load.'
        });
    }

    return violations;
}
```

## Types

### CustomCheckViolation

```typescript
interface CustomCheckViolation {
    id: string;              // Unique ID
    title: string;           // Human readable title
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    description: string;     // Detailed description
    selector?: string;       // Optional CSS selector
    url?: string;            // Optional URL
    remediation?: string;    // Optional fix instructions
    evidence?: string;       // Optional evidence text
}
```

### CustomCheckContext

```typescript
interface CustomCheckContext {
    targetUrl: string;       // The target verification URL
    currentUrl: string;      // Current page URL
    visitedUrls: string[];   // List of all visited URLs
    logger: Logger;          // Logger instance
    profile: string;         // Current scan profile
}
```

## Configuration

Enable or disable custom checks in your `.env` file:

```bash
CUSTOM_CHECKS_ENABLED=true
CUSTOM_CHECKS_DIR=./custom_checks
```
