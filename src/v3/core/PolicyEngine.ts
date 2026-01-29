/**
 * Policy-as-Code Engine
 * Evaluates custom compliance policies defined in YAML configuration
 * 
 * Security Note: Uses safe expression parsing without eval()
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import type {
    PolicyConfig,
    Policy,
    PolicyResult,
    PolicyEvaluationResult,
    PolicyEvaluationContext,
    PolicyMatchedFinding,
    ConditionNode,
    PolicyOperator,
} from '../types/policy.js';
import { validateRegexSafety, validateFilePath, validateYamlSafety, REGEX_TIMEOUT_MS } from '../utils/validation.js';
import { LIMITS } from '../utils/constants.js';

/**
 * Token types for the expression lexer
 */
type TokenType =
    | 'IDENTIFIER'
    | 'STRING'
    | 'NUMBER'
    | 'OPERATOR'
    | 'LOGICAL'
    | 'LPAREN'
    | 'RPAREN'
    | 'EOF';

interface Token {
    type: TokenType;
    value: string | number;
    position: number;
}

/**
 * Policy Engine for evaluating compliance policies
 */
export class PolicyEngine {
    private policies: Policy[] = [];
    private context: PolicyEvaluationContext | null = null;

    /**
     * Load policies from a YAML file with path validation
     *
     * @param filePath - Path to the policy YAML file
     * @param allowedDirs - Optional array of allowed directories (defaults to env config)
     * @throws Error if path validation fails or file cannot be read
     */
    loadFromFile(filePath: string, allowedDirs?: string[]): void {
        // Determine allowed directories
        let allowedDirectories = allowedDirs;
        if (!allowedDirectories) {
            // Try to get from environment config
            try {
                const envConfig = process.env.POLICY_ALLOWED_DIRS;
                if (envConfig) {
                    allowedDirectories = envConfig.split(',').map(d => d.trim()).filter(d => d.length > 0);
                } else {
                    // Default to current directory and ./policies
                    allowedDirectories = ['.', './policies'];
                }
            } catch {
                // If config not available, default to current directory only
                allowedDirectories = ['.', './policies'];
            }
        }

        // Validate file path to prevent path traversal attacks
        const validation = validateFilePath(filePath, {
            allowedDirs: allowedDirectories,
            requiredExtensions: ['.yml', '.yaml'],
            mustExist: true,
        });

        if (!validation.valid) {
            throw new Error(`Policy file path validation failed: ${validation.error}`);
        }

        // Use the validated normalized path
        const absolutePath = validation.normalizedPath!;

        // Check file size before reading to prevent memory exhaustion
        try {
            const stats = fs.statSync(absolutePath);
            if (stats.size > LIMITS.YAML_MAX_SIZE_BYTES) {
                throw new Error(
                    `Policy file too large: ${stats.size} bytes exceeds maximum of ${LIMITS.YAML_MAX_SIZE_BYTES} bytes (${LIMITS.YAML_MAX_SIZE_BYTES / 1024 / 1024}MB)`
                );
            }

            const content = fs.readFileSync(absolutePath, 'utf-8');
            this.loadFromString(content);
        } catch (error) {
            // Specific error handling for common filesystem issues
            if (error instanceof Error) {
                const nodeError = error as NodeJS.ErrnoException;
                if (nodeError.code === 'EACCES') {
                    throw new Error(`Permission denied reading policy file: ${absolutePath}`);
                } else if (nodeError.code === 'ENOENT') {
                    throw new Error(`Policy file not found: ${absolutePath}`);
                } else if (nodeError.code === 'EISDIR') {
                    throw new Error(`Path is a directory, not a file: ${absolutePath}`);
                } else {
                    // Re-throw the original error if it's not a filesystem error
                    throw error;
                }
            }
            throw error;
        }
    }

    /**
     * Load policies from a YAML string with safety validation
     *
     * @param yamlContent - YAML content as string
     * @throws Error if YAML is unsafe or invalid
     */
    loadFromString(yamlContent: string): void {
        // Validate YAML safety to prevent YAML bomb attacks
        const yamlValidation = validateYamlSafety(yamlContent);
        if (!yamlValidation.safe) {
            throw new Error(`YAML safety validation failed: ${yamlValidation.error}`);
        }

        // Parse YAML
        const config = yaml.load(yamlContent) as PolicyConfig;

        if (!config || !Array.isArray(config.policies)) {
            throw new Error('Invalid policy configuration: missing policies array');
        }

        // Limit number of policies to prevent resource exhaustion
        if (config.policies.length > LIMITS.MAX_POLICIES_PER_FILE) {
            throw new Error(
                `Too many policies defined (${config.policies.length} > ${LIMITS.MAX_POLICIES_PER_FILE}). ` +
                `This may indicate a malicious configuration.`
            );
        }

        this.policies = config.policies.filter((p) => p.enabled !== false);
    }

    /**
     * Load policies directly from Policy objects
     *
     * Useful for programmatic policy creation or testing.
     * Filters out disabled policies automatically.
     *
     * @param policies - Array of policy objects to load
     *
     * @example
     * ```typescript
     * const engine = new PolicyEngine();
     * engine.loadPolicies([
     *   {
     *     name: 'No Critical Vulnerabilities',
     *     condition: 'severity == "critical"',
     *     action: 'fail',
     *     enabled: true
     *   }
     * ]);
     * ```
     */
    loadPolicies(policies: Policy[]): void {
        this.policies = policies.filter((p) => p.enabled !== false);
    }

    /**
     * Get currently loaded policies
     *
     * Returns a copy of the policies array to prevent external modification.
     * Only includes enabled policies (disabled policies are filtered out during loading).
     *
     * @returns Array of loaded Policy objects (defensive copy)
     *
     * @example
     * ```typescript
     * const engine = new PolicyEngine();
     * engine.loadFromFile('policies.yml');
     * const policies = engine.getPolicies();
     * console.log(`Loaded ${policies.length} policies`);
     * ```
     */
    getPolicies(): Policy[] {
        return [...this.policies];
    }

    /**
     * Evaluate all loaded policies against the provided context
     *
     * Executes each enabled policy's condition expression against the scan results.
     * Policies are evaluated independently, and results are categorized by action (fail/warn/info).
     *
     * A policy "passes" if its condition does NOT match (i.e., no violations found).
     * A policy "fails" if its condition matches (violations detected).
     *
     * @param context - Evaluation context containing findings, metadata, and scores
     * @returns Evaluation result with pass/fail status and categorized policy results
     *
     * @example
     * ```typescript
     * const engine = new PolicyEngine();
     * engine.loadFromFile('policies.yml');
     *
     * const result = engine.evaluate({
     *   findings: [
     *     { id: '1', type: 'xss', severity: 'critical', title: 'XSS Found' }
     *   ],
     *   meta: {
     *     targetUrl: 'https://example.com',
     *     scanProfile: 'standard',
     *     duration: 5000,
     *     timestamp: new Date().toISOString()
     *   }
     * });
     *
     * if (!result.passed) {
     *   console.error(`Policy violations: ${result.failedPolicies.length}`);
     *   process.exit(result.exitCode);
     * }
     * ```
     */
    evaluate(context: PolicyEvaluationContext): PolicyEvaluationResult {
        this.context = context;

        const results: PolicyResult[] = [];
        const failedPolicies: PolicyResult[] = [];
        const warnedPolicies: PolicyResult[] = [];
        const passedPolicies: PolicyResult[] = [];

        for (const policy of this.policies) {
            const result = this.evaluatePolicy(policy, context);
            results.push(result);

            if (!result.passed && result.action === 'fail') {
                failedPolicies.push(result);
            } else if (!result.passed && result.action === 'warn') {
                warnedPolicies.push(result);
            } else {
                passedPolicies.push(result);
            }
        }

        const summary = {
            fail: failedPolicies.length,
            warn: warnedPolicies.length,
            info: results.filter((r) => r.action === 'info').length,
            pass: passedPolicies.length,
        };

        return {
            passed: failedPolicies.length === 0,
            totalPolicies: this.policies.length,
            failedPolicies,
            warnedPolicies,
            passedPolicies,
            summary,
            exitCode: failedPolicies.length > 0 ? 1 : 0,
        };
    }

    /**
     * Evaluate a single policy
     */
    private evaluatePolicy(policy: Policy, context: PolicyEvaluationContext): PolicyResult {
        try {
            const matchedFindings = this.findMatchingFindings(policy.condition, context);
            const conditionMatched = matchedFindings.length > 0;

            // Policy passes if the condition does NOT match (no violations found)
            const passed = !conditionMatched;

            return {
                policy,
                passed,
                action: policy.action,
                matchedFindings,
            };
        } catch (error) {
            return {
                policy,
                passed: false,
                action: policy.action,
                matchedFindings: [],
                error: error instanceof Error ? error.message : String(error),
            };
        }
    }

    /**
     * Find findings that match the policy condition
     */
    private findMatchingFindings(
        condition: string,
        context: PolicyEvaluationContext
    ): PolicyMatchedFinding[] {
        const matched: PolicyMatchedFinding[] = [];

        // Check if this is a finding-level condition (references severity, type, etc.)
        const isFindingCondition = this.isFindingCondition(condition);

        if (isFindingCondition) {
            // Evaluate condition for each finding
            for (const finding of context.findings) {
                if (this.evaluateCondition(condition, { finding, context })) {
                    matched.push(finding);
                }
            }
        } else {
            // Evaluate condition against context only (e.g., lighthouse_performance < 80)
            if (this.evaluateCondition(condition, { context })) {
                // Return a synthetic finding for context-level violations
                matched.push({
                    id: 'policy-violation',
                    type: 'policy',
                    severity: 'high',
                    title: 'Policy Condition Matched',
                });
            }
        }

        return matched;
    }

    /**
     * Check if condition references finding-level fields
     */
    private isFindingCondition(condition: string): boolean {
        const findingFields = ['severity', 'type', 'title', 'url', 'id'];
        const lowerCondition = condition.toLowerCase();
        return findingFields.some((field) => lowerCondition.includes(field));
    }

    /**
     * Evaluate a condition expression
     */
    private evaluateCondition(
        condition: string,
        evalContext: { finding?: PolicyMatchedFinding; context: PolicyEvaluationContext }
    ): boolean {
        const tokens = this.tokenize(condition);
        const ast = this.parse(tokens);
        return this.evaluateNode(ast, evalContext);
    }

    /**
     * Tokenize the condition string
     */
    private tokenize(expression: string): Token[] {
        const tokens: Token[] = [];
        let pos = 0;

        const operators = ['==', '!=', '<=', '>=', '<', '>', 'contains', 'startsWith', 'endsWith', 'matches'];
        const logicals = ['AND', 'OR', 'NOT', 'and', 'or', 'not', '&&', '||', '!'];

        while (pos < expression.length) {
            // Skip whitespace
            if (/\s/.test(expression[pos])) {
                pos++;
                continue;
            }

            // Parentheses
            if (expression[pos] === '(') {
                tokens.push({ type: 'LPAREN', value: '(', position: pos });
                pos++;
                continue;
            }
            if (expression[pos] === ')') {
                tokens.push({ type: 'RPAREN', value: ')', position: pos });
                pos++;
                continue;
            }

            // String literals
            if (expression[pos] === '"' || expression[pos] === "'") {
                const quote = expression[pos];
                const start = pos + 1;
                pos++;
                while (pos < expression.length && expression[pos] !== quote) {
                    pos++;
                }
                tokens.push({ type: 'STRING', value: expression.slice(start, pos), position: start });
                pos++; // Skip closing quote
                continue;
            }

            // Numbers
            if (/\d/.test(expression[pos]) || (expression[pos] === '-' && /\d/.test(expression[pos + 1]))) {
                const start = pos;
                if (expression[pos] === '-') pos++;
                while (pos < expression.length && /[\d.]/.test(expression[pos])) {
                    pos++;
                }
                tokens.push({ type: 'NUMBER', value: parseFloat(expression.slice(start, pos)), position: start });
                continue;
            }

            // Multi-character operators
            let foundOp = false;
            for (const op of operators) {
                if (expression.slice(pos, pos + op.length).toLowerCase() === op.toLowerCase()) {
                    tokens.push({ type: 'OPERATOR', value: op.toLowerCase(), position: pos });
                    pos += op.length;
                    foundOp = true;
                    break;
                }
            }
            if (foundOp) continue;

            // Logical operators
            let foundLogical = false;
            for (const logicalOperator of logicals) {
                if (expression.slice(pos, pos + logicalOperator.length).toUpperCase() === logicalOperator.toUpperCase()) {
                    // Make sure it's a complete word for text logicals
                    if (/^[a-zA-Z]+$/.test(logicalOperator)) {
                        const nextChar = expression[pos + logicalOperator.length];
                        if (nextChar && /[a-zA-Z_]/.test(nextChar)) continue;
                    }
                    const normalized = logicalOperator.replace('&&', 'AND').replace('||', 'OR').replace('!', 'NOT').toUpperCase();
                    tokens.push({ type: 'LOGICAL', value: normalized, position: pos });
                    pos += logicalOperator.length;
                    foundLogical = true;
                    break;
                }
            }
            if (foundLogical) continue;

            // Identifiers
            if (/[a-zA-Z_]/.test(expression[pos])) {
                const start = pos;
                while (pos < expression.length && /[a-zA-Z0-9_.]/.test(expression[pos])) {
                    pos++;
                }
                const value = expression.slice(start, pos);
                // Check if it's a boolean literal
                if (value.toLowerCase() === 'true' || value.toLowerCase() === 'false') {
                    tokens.push({ type: 'STRING', value: value.toLowerCase(), position: start });
                } else {
                    tokens.push({ type: 'IDENTIFIER', value, position: start });
                }
                continue;
            }

            // Unknown character - skip
            pos++;
        }

        tokens.push({ type: 'EOF', value: '', position: pos });
        return tokens;
    }

    /**
     * Parse tokens into an AST
     */
    private parse(tokens: Token[]): ConditionNode {
        let pos = 0;

        const parseOr = (): ConditionNode => {
            let left = parseAnd();

            while (pos < tokens.length && tokens[pos].type === 'LOGICAL' && tokens[pos].value === 'OR') {
                pos++; // consume OR
                const right = parseAnd();
                left = { type: 'logical', operator: 'OR', left, right };
            }

            return left;
        };

        const parseAnd = (): ConditionNode => {
            let left = parseNot();

            while (pos < tokens.length && tokens[pos].type === 'LOGICAL' && tokens[pos].value === 'AND') {
                pos++; // consume AND
                const right = parseNot();
                left = { type: 'logical', operator: 'AND', left, right };
            }

            return left;
        };

        const parseNot = (): ConditionNode => {
            if (tokens[pos].type === 'LOGICAL' && tokens[pos].value === 'NOT') {
                pos++; // consume NOT
                const operand = parseNot();
                return { type: 'logical', operator: 'NOT', left: operand };
            }
            return parseComparison();
        };

        const parseComparison = (): ConditionNode => {
            const left = parsePrimary();

            if (pos < tokens.length && tokens[pos].type === 'OPERATOR') {
                const operator = tokens[pos].value as PolicyOperator;
                pos++; // consume operator
                const right = parsePrimary();
                return {
                    type: 'comparison',
                    operator,
                    left: left.value as string,
                    right: right.value as string | number | boolean
                };
            }

            return left;
        };

        const parsePrimary = (): ConditionNode => {
            const token = tokens[pos];

            if (token.type === 'LPAREN') {
                pos++; // consume (
                const node = parseOr();
                if (tokens[pos].type === 'RPAREN') {
                    pos++; // consume )
                }
                return node;
            }

            if (token.type === 'IDENTIFIER' || token.type === 'STRING' || token.type === 'NUMBER') {
                pos++;
                return { type: 'value', value: token.value };
            }

            throw new Error(`Unexpected token at position ${token.position}: ${token.value}`);
        };

        return parseOr();
    }

    /**
     * Evaluate AST node
     */
    private evaluateNode(
        node: ConditionNode,
        evalContext: { finding?: PolicyMatchedFinding; context: PolicyEvaluationContext }
    ): boolean {
        if (node.type === 'value') {
            // Resolve identifier to actual value
            const resolved = this.resolveValue(node.value as string, evalContext);
            return Boolean(resolved);
        }

        if (node.type === 'logical') {
            if (node.operator === 'AND') {
                return (
                    this.evaluateNode(node.left as ConditionNode, evalContext) &&
                    this.evaluateNode(node.right as ConditionNode, evalContext)
                );
            }
            if (node.operator === 'OR') {
                return (
                    this.evaluateNode(node.left as ConditionNode, evalContext) ||
                    this.evaluateNode(node.right as ConditionNode, evalContext)
                );
            }
            if (node.operator === 'NOT') {
                return !this.evaluateNode(node.left as ConditionNode, evalContext);
            }
        }

        if (node.type === 'comparison') {
            const left = this.resolveValue(node.left as string, evalContext);
            const right = this.resolveValue(node.right as string | number | boolean, evalContext);
            return this.compare(left, node.operator as PolicyOperator, right);
        }

        return false;
    }

    /**
     * Resolve a value reference (e.g., "severity" → finding.severity)
     */
    private resolveValue(
        value: string | number | boolean,
        evalContext: { finding?: PolicyMatchedFinding; context: PolicyEvaluationContext }
    ): string | number | boolean {
        if (typeof value === 'number' || typeof value === 'boolean') {
            return value;
        }

        // Boolean string literals
        if (value === 'true') return true;
        if (value === 'false') return false;

        // Finding field references
        if (evalContext.finding) {
            const finding = evalContext.finding;
            switch (value.toLowerCase()) {
                case 'severity':
                    return finding.severity.toLowerCase();
                case 'type':
                    return finding.type.toLowerCase();
                case 'title':
                    return finding.title.toLowerCase();
                case 'url':
                    return finding.url?.toLowerCase() || '';
                case 'id':
                    return finding.id;
            }
        }

        // Context field references (with underscore or dot notation)
        const ctx = evalContext.context;
        const normalizedValue = value.toLowerCase().replace(/_/g, '.');

        if (normalizedValue.startsWith('lighthouse.') || normalizedValue.startsWith('lighthouse_')) {
            const field = normalizedValue.split(/[._]/)[1];
            if (ctx.lighthouse) {
                switch (field) {
                    case 'performance':
                        return ctx.lighthouse.performance;
                    case 'accessibility':
                        return ctx.lighthouse.accessibility;
                    case 'seo':
                        return ctx.lighthouse.seo;
                    case 'bestpractices':
                        return ctx.lighthouse.bestPractices;
                }
            }
            return 0;
        }

        if (normalizedValue.startsWith('security.') || normalizedValue.startsWith('security_')) {
            const field = normalizedValue.split(/[._]/)[1];
            if (ctx.security) {
                switch (field) {
                    case 'critical':
                        return ctx.security.critical;
                    case 'high':
                        return ctx.security.high;
                    case 'medium':
                        return ctx.security.medium;
                    case 'low':
                        return ctx.security.low;
                    case 'total':
                        return ctx.security.total;
                }
            }
            return 0;
        }

        // Return original value if not a reference
        return value;
    }

    /**
     * Test a string against a regex pattern with safety validation
     *
     * @param input - The string to test
     * @param pattern - The regex pattern
     * @returns True if the pattern matches, false otherwise
     * @throws Error if the regex is unsafe
     */
    private testRegexSafe(input: string, pattern: string): boolean {
        // Validate regex safety to prevent ReDoS attacks
        const safetyCheck = validateRegexSafety(pattern);
        if (!safetyCheck.safe) {
            throw new Error(`Unsafe regex pattern: ${safetyCheck.reason}`);
        }

        // Create and test regex
        try {
            const regex = new RegExp(pattern);
            return regex.test(input);
        } catch (error) {
            throw new Error(`Regex execution failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Compare two values with an operator
     */
    private compare(
        left: string | number | boolean,
        operator: PolicyOperator,
        right: string | number | boolean
    ): boolean {
        // Normalize strings for comparison
        const normalizeString = (v: string | number | boolean): string | number | boolean => {
            if (typeof v === 'string') return v.toLowerCase();
            return v;
        };

        const l = normalizeString(left);
        const r = normalizeString(right);

        switch (operator) {
            case '==':
                return l === r;
            case '!=':
                return l !== r;
            case '<':
                return Number(l) < Number(r);
            case '>':
                return Number(l) > Number(r);
            case '<=':
                return Number(l) <= Number(r);
            case '>=':
                return Number(l) >= Number(r);
            case 'contains':
                return String(l).includes(String(r));
            case 'startswith':
                return String(l).startsWith(String(r));
            case 'endswith':
                return String(l).endsWith(String(r));
            case 'matches':
                try {
                    return this.testRegexSafe(String(l), String(r));
                } catch (error) {
                    // Log error for debugging but don't throw (maintain backward compatibility)
                    // In production, this should be logged to monitoring system
                    if (error instanceof Error && error.message.includes('Unsafe regex')) {
                        throw error; // Throw for unsafe patterns (security)
                    }
                    return false; // Return false for other regex errors
                }
            default:
                return false;
        }
    }
}

export default PolicyEngine;
