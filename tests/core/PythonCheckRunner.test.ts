import { PythonCheckRunner, PythonCheckContext } from '../../src/core/PythonCheckRunner.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const mockLogger = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
};

const baseContext: PythonCheckContext = {
    targetUrl: 'https://example.com',
    currentUrl: 'https://example.com/page',
    visitedUrls: ['https://example.com', 'https://example.com/page'],
    profile: 'standard',
};

describe('PythonCheckRunner', () => {
    let tmpDir: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lscm-python-test-'));
        jest.clearAllMocks();
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    describe('discoverScripts', () => {
        it('should return empty array for non-existent directory', () => {
            const runner = new PythonCheckRunner(mockLogger, {
                pythonDir: '/nonexistent/path',
            });
            expect(runner.discoverScripts()).toEqual([]);
        });

        it('should discover .py files', () => {
            fs.writeFileSync(path.join(tmpDir, 'check1.py'), '');
            fs.writeFileSync(path.join(tmpDir, 'check2.py'), '');
            fs.writeFileSync(path.join(tmpDir, 'not_python.js'), '');

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const scripts = runner.discoverScripts();

            expect(scripts.length).toBe(2);
            expect(scripts.every(s => s.endsWith('.py'))).toBe(true);
        });

        it('should ignore hidden and underscore-prefixed files', () => {
            fs.writeFileSync(path.join(tmpDir, 'check.py'), '');
            fs.writeFileSync(path.join(tmpDir, '_helper.py'), '');
            fs.writeFileSync(path.join(tmpDir, '.hidden.py'), '');

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const scripts = runner.discoverScripts();

            expect(scripts.length).toBe(1);
            expect(scripts[0]).toContain('check.py');
        });
    });

    describe('runCheck', () => {
        it('should execute a script that returns valid JSON violations', async () => {
            const script = path.join(tmpDir, 'valid_check.py');
            fs.writeFileSync(script, `
import json, sys
violations = [{
    "id": "test-001",
    "title": "Test Finding",
    "severity": "medium",
    "description": "Test description",
    "url": "https://example.com"
}]
print(json.dumps(violations))
`);

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const result = await runner.runCheck(script, baseContext);

            expect(result.exitCode).toBe(0);
            expect(result.violations.length).toBe(1);
            expect(result.violations[0].id).toBe('test-001');
            expect(result.violations[0].severity).toBe('medium');
        });

        it('should handle scripts that return empty violations', async () => {
            const script = path.join(tmpDir, 'empty_check.py');
            fs.writeFileSync(script, `
import json
print(json.dumps([]))
`);

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const result = await runner.runCheck(script, baseContext);

            expect(result.exitCode).toBe(0);
            expect(result.violations.length).toBe(0);
        });

        it('should handle scripts that exit with non-zero code', async () => {
            const script = path.join(tmpDir, 'failing_check.py');
            fs.writeFileSync(script, `
import sys
print("error message", file=sys.stderr)
sys.exit(1)
`);

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const result = await runner.runCheck(script, baseContext);

            expect(result.exitCode).toBe(1);
            expect(result.violations.length).toBe(0);
            expect(result.stderr).toContain('error message');
        });

        it('should handle scripts that output invalid JSON', async () => {
            const script = path.join(tmpDir, 'invalid_json.py');
            fs.writeFileSync(script, `
print("this is not json")
`);

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const result = await runner.runCheck(script, baseContext);

            expect(result.exitCode).toBe(0);
            expect(result.violations.length).toBe(0);
            expect(result.stderr).toContain('Failed to parse');
        });

        it('should handle scripts that output invalid violation schema', async () => {
            const script = path.join(tmpDir, 'bad_schema.py');
            fs.writeFileSync(script, `
import json
print(json.dumps([{"wrong": "schema"}]))
`);

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const result = await runner.runCheck(script, baseContext);

            expect(result.violations.length).toBe(0);
            expect(result.stderr).toContain('Failed to parse');
        });

        it('should timeout long-running scripts', async () => {
            const script = path.join(tmpDir, 'slow_check.py');
            fs.writeFileSync(script, `
import time, json
time.sleep(60)
print(json.dumps([]))
`);

            const runner = new PythonCheckRunner(mockLogger, {
                pythonDir: tmpDir,
                timeout: 1000, // 1 second timeout
            });
            const result = await runner.runCheck(script, baseContext);

            expect(result.exitCode).toBe(-1);
            expect(result.stderr).toContain('timed out');
        }, 10000);

        it('should reject scripts outside allowed directory', async () => {
            const outsideScript = path.join(os.tmpdir(), 'evil_check.py');
            fs.writeFileSync(outsideScript, 'print("[]")');

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });

            await expect(runner.runCheck(outsideScript, baseContext))
                .rejects.toThrow('outside allowed directory');

            fs.unlinkSync(outsideScript);
        });

        it('should reject non-existent scripts', async () => {
            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });

            await expect(runner.runCheck(path.join(tmpDir, 'missing.py'), baseContext))
                .rejects.toThrow('not found');
        });

        it('should pass context to script via --context argument', async () => {
            const script = path.join(tmpDir, 'context_check.py');
            fs.writeFileSync(script, `
import json, sys
context = json.loads(sys.argv[2])
violations = []
if context.get("targetUrl") == "https://example.com":
    violations.append({
        "id": "context-test",
        "title": "Context received",
        "severity": "info",
        "description": f"Target: {context['targetUrl']}, Profile: {context['profile']}"
    })
print(json.dumps(violations))
`);

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const result = await runner.runCheck(script, baseContext);

            expect(result.violations.length).toBe(1);
            expect(result.violations[0].id).toBe('context-test');
            expect(result.violations[0].description).toContain('https://example.com');
        });

        it('should include duration in results', async () => {
            const script = path.join(tmpDir, 'timed_check.py');
            fs.writeFileSync(script, `
import json
print(json.dumps([]))
`);

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const result = await runner.runCheck(script, baseContext);

            expect(result.duration).toBeGreaterThanOrEqual(0);
        });
    });

    describe('runAll', () => {
        it('should run all discovered scripts', async () => {
            fs.writeFileSync(path.join(tmpDir, 'check_a.py'), `
import json
print(json.dumps([{"id": "a-001", "title": "A", "severity": "low", "description": "From A"}]))
`);
            fs.writeFileSync(path.join(tmpDir, 'check_b.py'), `
import json
print(json.dumps([{"id": "b-001", "title": "B", "severity": "high", "description": "From B"}]))
`);

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const results = await runner.runAll(baseContext);

            expect(results.length).toBe(2);
            const allViolations = results.flatMap(r => r.result.violations);
            expect(allViolations.length).toBe(2);
        });

        it('should return empty array for no scripts', async () => {
            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const results = await runner.runAll(baseContext);

            expect(results).toEqual([]);
        });

        it('should handle mixed success and failure', async () => {
            fs.writeFileSync(path.join(tmpDir, 'good.py'), `
import json
print(json.dumps([]))
`);
            fs.writeFileSync(path.join(tmpDir, 'bad.py'), `
import sys
sys.exit(1)
`);

            const runner = new PythonCheckRunner(mockLogger, { pythonDir: tmpDir });
            const results = await runner.runAll(baseContext);

            expect(results.length).toBe(2);
            const goodResult = results.find(r => r.name === 'good');
            const badResult = results.find(r => r.name === 'bad');
            expect(goodResult?.result.exitCode).toBe(0);
            expect(badResult?.result.exitCode).toBe(1);
        });
    });
});
