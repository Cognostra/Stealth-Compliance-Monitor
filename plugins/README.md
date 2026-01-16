# 🔌 Plugin Gallery

Community-contributed custom checks for Stealth Compliance Monitor.

## Official Example Plugins

These plugins are maintained as examples and starting points for your own custom checks.

| Plugin | Description | Tags |
|--------|-------------|------|
| [gdpr-cookie-consent](examples/gdpr-cookie-consent.ts) | GDPR cookie consent compliance | `gdpr`, `privacy`, `cookies` |
| [brand-consistency](examples/brand-consistency.ts) | Visual brand consistency checks | `branding`, `visual`, `ux` |
| [performance-budget](examples/performance-budget.ts) | Performance budget enforcement | `performance`, `budget`, `optimization` |
| [form-validation](examples/form-validation.ts) | Form accessibility & UX validation | `accessibility`, `forms`, `wcag` |
| [social-meta-tags](examples/social-meta-tags.ts) | Open Graph & Twitter Card validation | `seo`, `social`, `opengraph` |

## Installing Plugins

1. Copy plugin files to your `custom_checks/` directory:
   ```bash
   cp plugins/examples/gdpr-cookie-consent.ts custom_checks/
   ```

2. Ensure custom checks are enabled in `.env`:
   ```bash
   CUSTOM_CHECKS_ENABLED=true
   CUSTOM_CHECKS_DIR=./custom_checks
   ```

3. Run your scan - plugins are automatically loaded!

## Creating Your Own Plugin

### Basic Structure

```typescript
import { Page } from 'playwright';
import { CustomCheckContext, CustomCheckViolation } from '../src/core/CustomCheckLoader';

export async function check(
    page: Page, 
    context: CustomCheckContext
): Promise<CustomCheckViolation[]> {
    const violations: CustomCheckViolation[] = [];
    
    // Your check logic here
    
    return violations;
}
```

### CustomCheckContext Properties

| Property | Type | Description |
|----------|------|-------------|
| `currentUrl` | `string` | Current page URL being scanned |
| `targetUrl` | `string` | Initial target URL |
| `logger` | `Logger` | Logging utility |
| `config` | `object` | Full application config |

### CustomCheckViolation Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `id` | `string` | ✅ | Unique violation identifier |
| `title` | `string` | ✅ | Short violation title |
| `severity` | `'critical' \| 'high' \| 'medium' \| 'low'` | ✅ | Issue severity |
| `description` | `string` | ✅ | Detailed description |
| `remediation` | `string` | ❌ | How to fix the issue |
| `url` | `string` | ❌ | Page URL where found |
| `selector` | `string` | ❌ | CSS selector of element |
| `evidence` | `string` | ❌ | Supporting evidence |

### Best Practices

1. **Use meaningful IDs**: Prefix with your check name (e.g., `gdpr-no-consent`)
2. **Provide remediation**: Always tell users how to fix issues
3. **Handle errors gracefully**: Wrap checks in try/catch
4. **Log debug info**: Use `context.logger.debug()` for troubleshooting
5. **Be specific**: Target exact elements with selectors
6. **Document configuration**: If your plugin uses env vars, document them

### Example: Environment Configuration

```typescript
// Read config from environment
const CONFIG = {
    maxItems: parseInt(process.env.MY_CHECK_MAX_ITEMS || '10'),
    strictMode: process.env.MY_CHECK_STRICT === 'true',
};
```

## Community Plugins

Want to share your plugin? See our [Contributing Guide](../CONTRIBUTING.md#custom-compliance-checks-plugins).

### Submission Guidelines

1. Follow the plugin structure above
2. Include JSDoc header with `@author`, `@version`, `@tags`
3. Handle errors gracefully
4. Provide meaningful remediation guidance
5. Test on multiple sites before submitting
6. Submit via Pull Request to `plugins/community/`

## Plugin Ideas

Looking for inspiration? Here are some plugin ideas:

- **ADA Compliance**: Section 508 specific checks
- **HIPAA**: Healthcare data exposure detection
- **PCI-DSS**: Payment card data validation
- **i18n/l10n**: Internationalization completeness
- **Dark Mode**: Checks for dark mode support
- **Print Styles**: Validates print stylesheet presence
- **RSS/Atom Feed**: Checks for feed availability
- **Sitemap**: Validates sitemap.xml presence
- **robots.txt**: Validates robots.txt configuration
- **Security Headers**: CSP, HSTS, X-Frame-Options
- **Font Loading**: Validates font-display usage
- **Image Optimization**: WebP/AVIF format checks
- **Lazy Loading**: Native lazy loading validation

## Support

- 💬 [GitHub Discussions](https://github.com/Cognostra/Stealth-Compliance-Monitor/discussions)
- 🐛 [Report Issues](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues)
- 📖 [Full Documentation](../README.md)
