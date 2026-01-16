# Contributing to Stealth Compliance Monitor

First off, thank you for considering contributing to Stealth Compliance Monitor! 🎉

This project thrives because of contributors like you. Whether you're fixing bugs, adding features, improving documentation, or creating plugins, your contributions are welcome.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Commit Message Convention](#commit-message-convention)
- [Pull Request Process](#pull-request-process)
- [Plugin Development](#plugin-development)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)
- [Community](#community)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [security@cognostra.com](mailto:security@cognostra.com).

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Stealth-Compliance-Monitor.git
   cd Stealth-Compliance-Monitor
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Cognostra/Stealth-Compliance-Monitor.git
   ```
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## How to Contribute

### Types of Contributions We Welcome

- 🐛 **Bug fixes** - Found a bug? Fix it and submit a PR!
- ✨ **New features** - Have an idea? Discuss it in an issue first, then implement
- 📝 **Documentation** - Improve guides, fix typos, add examples
- 🔌 **Plugins** - Create custom compliance checks for the community
- 🧪 **Tests** - Increase coverage or improve existing tests
- 🌐 **Translations** - Help make the tool accessible in more languages
- 🎨 **UI/UX improvements** - Enhance the dashboard and reports

## Development Setup

### Prerequisites

- Node.js v18 or higher
- Docker and Docker Compose
- Git

### Installation

```bash
# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Start ZAP proxy (required for security scanning)
docker compose up -d zap

# Run tests to verify setup
npm test

# Run the compliance scanner
npm start
```

### Project Structure

```
├── src/
│   ├── core/           # Core orchestration logic
│   ├── services/       # Individual scanner implementations
│   ├── config/         # Configuration management
│   ├── types/          # TypeScript type definitions
│   └── utils/          # Utility functions
├── tests/              # Test suites
├── custom_checks/      # Plugin directory
├── reports/            # Generated reports
└── docs/               # Documentation site
```

## Code Style Guidelines

We use ESLint and Prettier to maintain consistent code style.

### TypeScript Guidelines

- Use strict TypeScript mode
- Prefer `interface` over `type` for object shapes
- Use meaningful variable and function names
- Document public APIs with JSDoc comments
- Avoid `any` type - use `unknown` when necessary

### File Naming

- Use `PascalCase` for class files: `BrowserService.ts`
- Use `kebab-case` for utility files: `compliance-map.ts`
- Use `.test.ts` suffix for test files

### Running Linters

```bash
# Check for issues
npm run lint

# Auto-fix issues
npm run lint:fix
```

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, missing semicolons, etc. |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `chore` | Maintenance tasks |

### Examples

```
feat(scanner): add Nuclei integration for CVE detection
fix(reports): correct HTML encoding in vulnerability descriptions
docs(readme): add fleet mode configuration examples
test(services): add unit tests for WebhookService
```

## Pull Request Process

1. **Ensure your branch is up to date**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run the full test suite**:
   ```bash
   npm test
   npm run lint
   ```

3. **Create your PR** with:
   - Clear title following commit convention
   - Description of changes
   - Screenshots for UI changes
   - Link to related issue(s)

4. **PR Review Checklist**:
   - [ ] Tests pass
   - [ ] Linting passes
   - [ ] Documentation updated (if applicable)
   - [ ] No breaking changes (or clearly documented)
   - [ ] Types are properly defined

5. **After review**, maintainers will merge your PR

### PR Labels

| Label | Description |
|-------|-------------|
| `bug` | Bug fix |
| `enhancement` | New feature |
| `documentation` | Documentation changes |
| `good first issue` | Good for newcomers |
| `help wanted` | Extra attention needed |
| `plugin` | Plugin-related |

## Plugin Development

We encourage community plugins! See [custom_checks/README.md](custom_checks/README.md) for the full guide.

### Quick Plugin Template

```typescript
// custom_checks/my-check.ts
import { CustomCheckContext, CustomCheckResult } from '../src/types';

export const metadata = {
    name: 'my-custom-check',
    version: '1.0.0',
    description: 'Description of what this check does',
    author: 'Your Name',
    tags: ['security', 'compliance']
};

export async function run(context: CustomCheckContext): Promise<CustomCheckResult[]> {
    const results: CustomCheckResult[] = [];
    
    // Your check logic here
    
    return results;
}
```

### Plugin Submission

1. Create your plugin in `custom_checks/`
2. Add tests in `tests/custom_checks/`
3. Submit PR with `plugin` label
4. After review, it may be added to the Plugin Gallery

## Reporting Bugs

### Before Submitting

1. Check existing [issues](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues)
2. Verify you're on the latest version
3. Collect relevant information:
   - Node.js version (`node --version`)
   - OS and version
   - Docker version (if applicable)
   - Error messages and stack traces

### Bug Report Template

Use our [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) which includes:

- Steps to reproduce
- Expected vs actual behavior
- Environment details
- Screenshots/logs

## Feature Requests

We love new ideas! Before requesting:

1. Check if it already exists in [issues](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues)
2. Consider if it fits the project's scope
3. Use our [feature request template](.github/ISSUE_TEMPLATE/feature_request.md)

### Feature Scope

✅ **In scope:**
- New security scanners
- Performance optimizations
- Report enhancements
- CI/CD integrations
- Accessibility improvements

❌ **Out of scope:**
- Active exploitation tools
- Credential harvesting
- Malicious scanning features

## Community

- 💬 [GitHub Discussions](https://github.com/Cognostra/Stealth-Compliance-Monitor/discussions) - Questions, ideas, show & tell
- 🐛 [Issue Tracker](https://github.com/Cognostra/Stealth-Compliance-Monitor/issues) - Bug reports and feature requests
- 📖 [Documentation](https://cognostra.github.io/Stealth-Compliance-Monitor/) - Full docs and guides

## Recognition

Contributors are recognized in:
- README.md contributors section
- Release notes
- Our eternal gratitude! 🙏

---

Thank you for being part of making the web more secure and accessible! 🚀
