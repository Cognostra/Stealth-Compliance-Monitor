/**
 * PythonCheckRunner - Out-of-Process Python Check Executor
 *
 * Spawns Python scripts as child processes, captures their JSON stdout,
 * and parses results into CustomCheckViolation format.
 *
 * Python Script Contract:
 * - Input: JSON context passed via --context CLI argument
 * - Output: JSON array of violation objects to stdout
 * - Exit 0 = success (violations are findings, not errors)
 * - Non-zero exit = script error
 */

import { spawn } from 'node:child_process';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { z } from 'zod';
import { Logger } from '../types/index.js';
import { CustomCheckViolation } from './CustomCheckLoader.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface PythonCheckContext {
    targetUrl: string;
    currentUrl: string;
    visitedUrls: string[];
    profile: string;
}

interface PythonCheckExecutionResult {
    violations: CustomCheckViolation[];
    stdout: string;
    stderr: string;
    exitCode: number | null;
    duration: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// VALIDATION SCHEMA
// ═══════════════════════════════════════════════════════════════════════════════

const ViolationSchema = z.object({
    id: z.string(),
    title: z.string(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    description: z.string(),
    selector: z.string().optional(),
    url: z.string().optional(),
    remediation: z.string().optional(),
    evidence: z.string().optional(),
});

const ViolationArraySchema = z.array(ViolationSchema);

// ═══════════════════════════════════════════════════════════════════════════════
// PYTHON CHECK RUNNER
// ═══════════════════════════════════════════════════════════════════════════════

export class PythonCheckRunner {
    private readonly logger: Logger;
    private readonly pythonExecutable: string;
    private readonly timeout: number;
    private readonly pythonDir: string;

    constructor(
        logger: Logger,
        options: {
            pythonDir?: string;
            pythonExecutable?: string;
            timeout?: number;
        } = {}
    ) {
        this.logger = logger;
        this.pythonDir = path.resolve(options.pythonDir || './custom_checks/python');
        this.pythonExecutable = options.pythonExecutable || process.env.PYTHON_EXECUTABLE || 'python3';
        this.timeout = options.timeout || Number(process.env.PYTHON_CHECK_TIMEOUT) || 60000;
    }

    /**
     * Discover Python check scripts in the python checks directory.
     */
    discoverScripts(): string[] {
        if (!fs.existsSync(this.pythonDir)) {
            this.logger.debug(`Python checks directory not found: ${this.pythonDir}`);
            return [];
        }

        const files = fs.readdirSync(this.pythonDir).filter(file => {
            return file.endsWith('.py') && !file.startsWith('_') && !file.startsWith('.');
        });

        this.logger.info(`Found ${files.length} Python check scripts in ${this.pythonDir}`);
        return files.map(file => path.join(this.pythonDir, file));
    }

    /**
     * Run a single Python check script and return parsed violations.
     */
    async runCheck(scriptPath: string, context: PythonCheckContext): Promise<PythonCheckExecutionResult> {
        const startTime = Date.now();

        // Validate script path is within allowed directory
        const resolvedPath = path.resolve(scriptPath);
        const resolvedDir = path.resolve(this.pythonDir);
        if (!resolvedPath.startsWith(resolvedDir)) {
            throw new Error(`Script path "${scriptPath}" is outside allowed directory "${this.pythonDir}"`);
        }

        if (!fs.existsSync(resolvedPath)) {
            throw new Error(`Python script not found: ${resolvedPath}`);
        }

        const contextJson = JSON.stringify(context);

        return new Promise<PythonCheckExecutionResult>((resolve, reject) => {
            let stdout = '';
            let stderr = '';
            let killed = false;

            const child = spawn(this.pythonExecutable, [resolvedPath, '--context', contextJson], {
                timeout: this.timeout,
                env: {
                    ...process.env,
                    LSCM_TARGET_URL: context.targetUrl,
                    LSCM_CURRENT_URL: context.currentUrl,
                    LSCM_PROFILE: context.profile,
                },
                stdio: ['pipe', 'pipe', 'pipe'],
            });

            const timeoutHandle = setTimeout(() => {
                killed = true;
                child.kill('SIGTERM');
                setTimeout(() => {
                    if (!child.killed) {
                        child.kill('SIGKILL');
                    }
                }, 5000);
            }, this.timeout);

            child.stdout.on('data', (data: Buffer) => {
                stdout += data.toString();
            });

            child.stderr.on('data', (data: Buffer) => {
                stderr += data.toString();
            });

            child.on('close', (exitCode) => {
                clearTimeout(timeoutHandle);
                const duration = Date.now() - startTime;

                if (killed) {
                    resolve({
                        violations: [],
                        stdout,
                        stderr: `Script timed out after ${this.timeout}ms`,
                        exitCode: -1,
                        duration,
                    });
                    return;
                }

                if (exitCode !== 0) {
                    resolve({
                        violations: [],
                        stdout,
                        stderr: stderr || `Script exited with code ${exitCode}`,
                        exitCode,
                        duration,
                    });
                    return;
                }

                // Parse JSON output
                try {
                    const parsed = JSON.parse(stdout.trim());
                    const validated = ViolationArraySchema.parse(parsed);
                    resolve({
                        violations: validated,
                        stdout,
                        stderr,
                        exitCode: 0,
                        duration,
                    });
                } catch (parseError) {
                    const errorMsg = parseError instanceof Error ? parseError.message : String(parseError);
                    resolve({
                        violations: [],
                        stdout,
                        stderr: `Failed to parse script output as JSON: ${errorMsg}`,
                        exitCode: 0,
                        duration,
                    });
                }
            });

            child.on('error', (error) => {
                clearTimeout(timeoutHandle);
                const duration = Date.now() - startTime;

                if (error.message.includes('ENOENT')) {
                    reject(new Error(`Python executable not found: ${this.pythonExecutable}. Install Python 3 or set PYTHON_EXECUTABLE.`));
                } else {
                    reject(error);
                }
            });
        });
    }

    /**
     * Run all discovered Python check scripts.
     */
    async runAll(context: PythonCheckContext): Promise<{
        name: string;
        result: PythonCheckExecutionResult;
    }[]> {
        const scripts = this.discoverScripts();
        if (scripts.length === 0) return [];

        const results: { name: string; result: PythonCheckExecutionResult }[] = [];

        for (const scriptPath of scripts) {
            const name = path.basename(scriptPath, '.py');
            this.logger.debug(`Running Python check: ${name}`);

            try {
                const result = await this.runCheck(scriptPath, context);

                if (result.stderr && result.exitCode !== 0) {
                    this.logger.warn(`Python check '${name}' stderr: ${result.stderr}`);
                }
                if (result.violations.length > 0) {
                    this.logger.info(`Python check '${name}' found ${result.violations.length} violations`);
                }

                results.push({ name, result });
            } catch (error) {
                this.logger.error(`Python check '${name}' failed: ${error instanceof Error ? error.message : String(error)}`);
                results.push({
                    name,
                    result: {
                        violations: [],
                        stdout: '',
                        stderr: error instanceof Error ? error.message : String(error),
                        exitCode: -1,
                        duration: 0,
                    },
                });
            }
        }

        return results;
    }
}

export default PythonCheckRunner;
