# ESM Migration Plan

> **Status:** ✅ COMPLETED in v2.0.0  
> **Completed:** January 16, 2026  
> **Blocked Packages:** Now unblocked - chalk 5+, p-limit 6+, eslint 9+

## Overview

This migration converted the project from CommonJS to ES Modules, enabling the use of modern ESM-only packages.

## Currently Blocked Upgrades

| Package | Current | Latest | Breaking Change |
|---------|---------|--------|-----------------|
| chalk | 4.1.2 | 5.x+ | ESM-only |
| p-limit | 5.0.0 | 7.x+ | ESM-only (v6+) |
| eslint | 8.x | 9.x | Flat config required |
| @typescript-eslint/* | 6.x | 8.x | Requires ESLint 9 |

## Migration Steps

### Phase 1: Project Configuration

1. **Update package.json**
   ```json
   {
     "type": "module"
   }
   ```

2. **Update tsconfig.json**
   ```json
   {
     "compilerOptions": {
       "module": "ESNext",
       "moduleResolution": "NodeNext",
       "target": "ES2022"
     }
   }
   ```

### Phase 2: Code Changes

1. **Convert all imports**
   ```typescript
   // Before (CommonJS)
   const chalk = require('chalk');
   
   // After (ESM)
   import chalk from 'chalk';
   ```

2. **Update dynamic imports**
   ```typescript
   // Before
   const module = require(path);
   
   // After
   const module = await import(path);
   ```

3. **Add file extensions to relative imports**
   ```typescript
   // Before
   import { logger } from './utils/logger';
   
   // After
   import { logger } from './utils/logger.js';
   ```

4. **Replace `__dirname` and `__filename`**
   ```typescript
   // Before
   const configPath = path.join(__dirname, 'config.json');
   
   // After
   import { fileURLToPath } from 'url';
   import { dirname } from 'path';
   
   const __filename = fileURLToPath(import.meta.url);
   const __dirname = dirname(__filename);
   ```

### Phase 3: ESLint Flat Config Migration

1. **Create `eslint.config.js`** (replaces `.eslintrc.json`)
   ```javascript
   import eslint from '@eslint/js';
   import tseslint from 'typescript-eslint';
   
   export default tseslint.config(
     eslint.configs.recommended,
     ...tseslint.configs.recommended,
     {
       files: ['src/**/*.ts'],
       rules: {
         // Your rules here
       }
     }
   );
   ```

2. **Remove old config files**
   - `.eslintrc.json`
   - `.eslintignore` (use `ignores` in flat config)

### Phase 4: Testing Updates

1. **Update Jest configuration for ESM**
   ```javascript
   // jest.config.js
   export default {
     preset: 'ts-jest/presets/default-esm',
     extensionsToTreatAsEsm: ['.ts'],
     moduleNameMapper: {
       '^(\\.{1,2}/.*)\\.js$': '$1',
     },
     transform: {
       '^.+\\.tsx?$': ['ts-jest', { useESM: true }],
     },
   };
   ```

2. **Update test imports**

### Phase 5: CI/CD Updates

1. Update GitHub Actions workflows if needed
2. Ensure Node.js version supports ESM (18+)

## Files Requiring Changes

Run this to find all files using CommonJS patterns:
```bash
grep -r "require\(" src/ --include="*.ts"
grep -r "__dirname\|__filename" src/ --include="*.ts"
```

## Estimated Effort

| Task | Effort |
|------|--------|
| package.json + tsconfig changes | 1 hour |
| Convert ~50 source files | 4-6 hours |
| ESLint flat config migration | 2 hours |
| Jest ESM configuration | 2 hours |
| Testing & debugging | 4 hours |
| **Total** | **~15 hours** |

## Rollback Plan

If issues arise:
1. Revert `package.json` type field
2. Revert `tsconfig.json` module settings
3. Keep pinned versions in dependabot.yml

## References

- [Node.js ESM Documentation](https://nodejs.org/api/esm.html)
- [TypeScript ESM Support](https://www.typescriptlang.org/docs/handbook/esm-node.html)
- [ESLint Flat Config Migration](https://eslint.org/docs/latest/use/configure/migration-guide)
- [Jest ESM Support](https://jestjs.io/docs/ecmascript-modules)
- [chalk ESM Migration](https://github.com/chalk/chalk/releases/tag/v5.0.0)
