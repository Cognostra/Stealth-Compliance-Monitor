# Release Guide

This document describes the release process for Stealth Compliance Monitor.

## Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.x.x): Breaking changes
- **MINOR** (x.1.x): New features (backward compatible)
- **PATCH** (x.x.1): Bug fixes (backward compatible)

## Release Checklist

### Pre-Release

- [ ] All tests pass (`npm test`)
- [ ] Linting passes (`npm run lint`)
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated with all changes
- [ ] Version in package.json is updated
- [ ] No critical security vulnerabilities
- [ ] All PRs for the release are merged

### Creating a Release

#### Option 1: Tag-Based Release (Recommended)

1. **Update version in package.json:**
   ```bash
   npm version patch  # or minor, major
   ```

2. **Update CHANGELOG.md:**
   - Move items from `[Unreleased]` to new version section
   - Add release date
   - Update comparison links at bottom

3. **Commit and tag:**
   ```bash
   git add .
   git commit -m "chore: release v1.0.0"
   git tag v1.0.0
   git push origin main --tags
   ```

4. **GitHub Actions will automatically:**
   - Run tests
   - Build Docker images (amd64 + arm64)
   - Push to GHCR and Docker Hub
   - Create GitHub Release with notes

#### Option 2: Manual Workflow Dispatch

1. Go to **Actions** → **Release**
2. Click **Run workflow**
3. Enter version number (e.g., `1.0.0`)
4. Check **prerelease** if applicable
5. Click **Run workflow**

### Post-Release

- [ ] Verify Docker images are available
- [ ] Verify GitHub Release is created
- [ ] Test installation from npm/Docker
- [ ] Update documentation site if needed
- [ ] Announce on social media/community channels

## Release Notes Template

```markdown
## 🎉 Stealth Compliance Monitor vX.Y.Z

### Highlights
- Feature 1
- Feature 2

### Added
- New feature description

### Changed
- Changed behavior description

### Fixed
- Bug fix description

### Security
- Security fix description

### Breaking Changes
- Description of breaking change and migration path

### Upgrade Guide
Instructions for upgrading from previous version.

### Contributors
Thanks to @contributor1, @contributor2 for their contributions!
```

## Hotfix Process

For critical security fixes:

1. Create branch from latest release tag:
   ```bash
   git checkout -b hotfix/security-fix v1.0.0
   ```

2. Apply fix and test

3. Update CHANGELOG.md

4. Tag as patch release:
   ```bash
   git tag v1.0.1
   git push origin hotfix/security-fix --tags
   ```

5. Merge back to main:
   ```bash
   git checkout main
   git merge hotfix/security-fix
   git push origin main
   ```

## Docker Image Tags

Each release publishes the following Docker tags:

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `1.0.0` | Specific version |
| `1.0` | Latest patch of minor version |
| `1` | Latest minor of major version |

## Rollback

If a release has critical issues:

1. **Docker:**
   ```bash
   docker pull ghcr.io/cognostra/stealth-compliance-monitor:0.9.0
   ```

2. **npm:**
   ```bash
   npm install -g stealth-compliance-monitor@0.9.0
   ```

3. Mark GitHub Release as pre-release or delete
4. Investigate and fix in new patch release
