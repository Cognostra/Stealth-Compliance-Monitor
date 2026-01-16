# Testing Strategy for Stealth Compliance Monitor

## Executive Summary

This document outlines a comprehensive testing strategy to elevate the Stealth Compliance Monitor to "top-tier" software quality. Our goal is to achieve **80%+ code coverage** with meaningful tests that ensure reliability, security, and maintainability.

---

## Test Pyramid Architecture

```
                    ┌─────────────┐
                    │   E2E Tests │  ← Expensive, slow, high confidence
                    │    (~10%)   │
                    └─────────────┘
                   ┌───────────────┐
                   │  Integration  │  ← Medium cost, browser interactions
                   │    (~20%)     │
                   └───────────────┘
                  ┌─────────────────┐
                  │   Unit Tests    │  ← Fast, cheap, isolated
                  │    (~70%)       │
                  └─────────────────┘
```

---

## Implementation Tiers

### ✅ Tier 1: Core Scanner Services (COMPLETED)
**Priority: Critical | Coverage Target: 90%**

| Service | Test File | Status |
|---------|-----------|--------|
| SecretScanner | `SecretScanner.test.ts` | ✅ Complete |
| PiiScanner | `PiiScanner.test.ts` | ✅ Complete |
| ConsoleMonitor | `ConsoleMonitor.test.ts` | ✅ Complete |
| NetworkSpy | `NetworkSpy.test.ts` | ✅ Complete |
| AssetValidator | `AssetValidator.test.ts` | ✅ Complete |
| SEOValidator | `SEOValidator.test.ts` | ✅ Complete |
| LinkChecker | `LinkChecker.test.ts` | ✅ Complete |

---

### 🔄 Tier 2: Security & Vulnerability Services
**Priority: High | Coverage Target: 85%**

| Service | Test File | Key Tests |
|---------|-----------|-----------|
| FrontendVulnerabilityScanner | `FrontendVulnerabilityScanner.test.ts` | XSS detection, injection patterns, CSP validation |
| SecurityAssessment | `SecurityAssessment.test.ts` | Security header checks, HTTPS validation, cookie security |
| SupabaseSecurityScanner | `SupabaseSecurityScanner.test.ts` | RLS policy detection, exposed keys, auth config |
| ZapService | `ZapService.test.ts` | OWASP ZAP integration, vulnerability parsing |
| ZapActiveScanner | `ZapActiveScanner.test.ts` | Active scan management, alert processing |

**Test Focus Areas:**
- Pattern matching for vulnerability signatures
- False positive reduction
- Severity classification accuracy
- Security header parsing

---

### 📊 Tier 3: Reporting & Persistence
**Priority: Medium | Coverage Target: 80%**

| Service | Test File | Key Tests |
|---------|-----------|-----------|
| ReportGenerator | `ReportGenerator.test.ts` | JSON/HTML output, template rendering |
| HtmlReportGenerator | `HtmlReportGenerator.test.ts` | HTML formatting, chart generation |
| FleetReportGenerator | `FleetReportGenerator.test.ts` | Multi-site aggregation, dashboard generation |
| HistoryService | `HistoryService.test.ts` | Historical data tracking, trend analysis |
| PersistenceService | `PersistenceService.test.ts` | Data storage, retrieval, cleanup |

**Test Focus Areas:**
- Output format validation
- Data aggregation accuracy
- File system operations (use temp directories)
- Template rendering edge cases

---

### 🌐 Tier 4: Browser & Network Services
**Priority: Medium | Coverage Target: 75%**

| Service | Test File | Key Tests |
|---------|-----------|-----------|
| BrowserService | `BrowserService.test.ts` | Browser lifecycle, page creation |
| CrawlerService | `CrawlerService.test.ts` | URL discovery, depth limiting, robots.txt |
| AuthService | `AuthService.test.ts` | Authentication flows, session management |
| InteractionTester | `InteractionTester.test.ts` | Form interactions, click testing |

**Test Focus Areas:**
- Mock Playwright Page/Browser objects
- Network request/response mocking
- Error handling and recovery
- Timeout management

---

### 🔧 Tier 5: External Integrations
**Priority: Lower | Coverage Target: 70%**

| Service | Test File | Key Tests |
|---------|-----------|-----------|
| WebhookService | `WebhookService.test.ts` | HTTP delivery, retry logic, payload format |
| SiemLogger | `SiemLogger.test.ts` | Log formatting, transport handling |
| AiRemediationService | `AiRemediationService.test.ts` | AI API interaction, response parsing |
| LighthouseService | `LighthouseService.test.ts` | Lighthouse integration, score parsing |

**Test Focus Areas:**
- Mock external APIs
- Network failure handling
- Rate limiting
- Retry logic

---

### 🏗️ Tier 6: Core Infrastructure
**Priority: High | Coverage Target: 85%**

| Component | Test File | Key Tests |
|-----------|-----------|-----------|
| ComplianceRunner | `ComplianceRunner.test.ts` | Scanner orchestration, execution flow |
| ScannerRegistry | `ScannerRegistry.test.ts` | ✅ Complete |
| CustomCheckLoader | `CustomCheckLoader.test.ts` | Dynamic module loading |
| UserFlowRunner | `UserFlowRunner.test.ts` | Custom flow execution |

---

## Integration Test Strategy

### Browser Integration Tests (`tests/integration/browser/`)

```typescript
// Test real browser interactions without external dependencies
describe('Browser Integration', () => {
    it('should capture console errors from real page');
    it('should detect network failures');
    it('should scan accessibility issues');
});
```

### E2E Tests (`tests/integration/e2e/`)

```typescript
// Full compliance scan workflow
describe('E2E Compliance Scan', () => {
    it('should complete full scan of test site');
    it('should generate valid HTML report');
    it('should detect known vulnerabilities in test fixtures');
});
```

---

## Test Infrastructure Requirements

### 1. Mock Factories
Create reusable mock factories for common objects:

```typescript
// tests/factories/mockPage.ts
export const createMockPage = (options?: MockPageOptions): Page => ({
    evaluate: jest.fn(),
    goto: jest.fn(),
    url: () => options?.url ?? 'https://example.com',
    // ... more methods
});
```

### 2. Test Fixtures
Maintain test fixtures for consistent testing:

```
tests/fixtures/
├── html/
│   ├── vulnerable-page.html
│   ├── accessible-page.html
│   └── seo-compliant.html
├── responses/
│   ├── lighthouse-report.json
│   └── zap-alerts.json
└── secrets/
    └── test-patterns.txt
```

### 3. Test Utilities

```typescript
// tests/utils/testHelpers.ts
export const waitForCondition = async (condition: () => boolean, timeout = 5000) => {...};
export const createTempDirectory = () => {...};
export const loadFixture = (name: string) => {...};
```

---

## Coverage Targets & Milestones

### Milestone 1: Foundation (Current → Week 2)
- **Target: 30% coverage**
- Complete Tier 1 tests ✅
- Set up test infrastructure
- Establish mock patterns

### Milestone 2: Security Focus (Week 3-4)
- **Target: 50% coverage**
- Complete Tier 2 tests
- Add security-focused integration tests

### Milestone 3: Full Coverage (Week 5-8)
- **Target: 80% coverage**
- Complete Tiers 3-6
- Add E2E test suite

### Milestone 4: Excellence (Ongoing)
- **Target: 90% coverage**
- Mutation testing
- Performance benchmarks
- Chaos engineering tests

---

## Code Quality Standards

### Test Requirements
1. **Each test must have a clear purpose** - Name describes behavior
2. **Tests must be isolated** - No shared state between tests
3. **Tests must be deterministic** - Same input = same output
4. **Tests must be fast** - Unit tests < 100ms, Integration < 5s

### Naming Conventions
```typescript
describe('ServiceName', () => {
    describe('methodName', () => {
        it('should [expected behavior] when [condition]');
        it('should throw Error when [invalid input]');
        it('should return empty array when [edge case]');
    });
});
```

### Coverage Requirements by File Type
| File Type | Line Coverage | Branch Coverage |
|-----------|--------------|-----------------|
| Services | 80% | 75% |
| Utils | 90% | 85% |
| Core | 85% | 80% |
| Types | N/A | N/A |

---

## CI/CD Integration

### GitHub Actions Configuration
```yaml
# .github/workflows/test.yml additions
- name: Run Unit Tests
  run: npm run test:unit -- --coverage

- name: Run Integration Tests
  run: npm run test:integration

- name: Upload Coverage
  uses: codecov/codecov-action@v5

- name: Enforce Coverage Thresholds
  run: |
    if [ $(jq '.total.lines.pct' coverage/coverage-summary.json) -lt 80 ]; then
      exit 1
    fi
```

### Pre-commit Hooks
```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "npm run test:changed"
    }
  }
}
```

---

## Advanced Testing Strategies

### 1. Mutation Testing
Use Stryker to validate test quality:
```bash
npx stryker run
```

### 2. Property-Based Testing
For pattern matching services:
```typescript
import fc from 'fast-check';

it('should detect SSN in any format', () => {
    fc.assert(
        fc.property(fc.ssnArbitrary(), (ssn) => {
            expect(scanner.detectSSN(ssn)).toBe(true);
        })
    );
});
```

### 3. Snapshot Testing
For report generation:
```typescript
it('should generate consistent HTML report', () => {
    const report = generator.generate(findings);
    expect(report).toMatchSnapshot();
});
```

### 4. Contract Testing
For external API integrations:
```typescript
describe('Webhook Contract', () => {
    it('should send payload matching expected schema', async () => {
        const payload = await webhookService.buildPayload(findings);
        expect(payload).toMatchSchema(webhookSchema);
    });
});
```

---

## Monitoring & Maintenance

### Test Health Metrics
- **Flaky Test Rate**: < 1%
- **Test Execution Time**: < 2 minutes for unit tests
- **Coverage Trend**: Only increases, never decreases

### Regular Reviews
- Weekly: Review failing tests
- Monthly: Review coverage trends
- Quarterly: Review test architecture

---

## Next Steps

1. **Immediate**: Run the new Tier 1 tests to verify coverage increase
2. **This Week**: Begin Tier 2 security service tests
3. **Next Week**: Set up test fixtures and mock factories
4. **Ongoing**: Maintain coverage above 80%

---

## Appendix: Test Commands

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test file
npm test -- tests/services/PiiScanner.test.ts

# Run tests in watch mode
npm test -- --watch

# Run only changed tests
npm test -- --onlyChanged

# Update snapshots
npm test -- --updateSnapshot
```

---

*Document Version: 1.0.0*  
*Last Updated: January 2025*  
*Author: Compliance Monitor Team*
