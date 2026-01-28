/**
 * Policy-as-Code Type Definitions
 * Defines the schema for .compliance-policy.yml files
 */

/**
 * Root structure of a policy configuration file
 */
export interface PolicyConfig {
    version?: string;
    policies: Policy[];
    globals?: PolicyGlobals;
}

/**
 * Global settings that apply to all policies
 */
export interface PolicyGlobals {
    /** Default action when no policy matches */
    defaultAction?: PolicyAction;
    /** Whether to continue evaluating after first failure */
    continueOnFailure?: boolean;
    /** Tags to include/exclude from evaluation */
    includeTags?: string[];
    excludeTags?: string[];
}

/**
 * Individual policy rule
 */
export interface Policy {
    /** Human-readable name for the policy */
    name: string;
    /** Optional description for documentation */
    description?: string;
    /** Condition expression to evaluate */
    condition: string;
    /** Action to take when condition matches */
    action: PolicyAction;
    /** Optional custom message for violations */
    message?: string;
    /** Tags for filtering */
    tags?: string[];
    /** Whether this policy is enabled */
    enabled?: boolean;
}

/**
 * Actions that can be taken when a policy condition matches
 */
export type PolicyAction = 'fail' | 'warn' | 'info' | 'pass';

/**
 * Result of evaluating a single policy
 */
export interface PolicyResult {
    policy: Policy;
    /** Whether the policy passed (condition did not match or action is pass) */
    passed: boolean;
    /** The action that was triggered */
    action: PolicyAction;
    /** Findings that matched this policy's condition */
    matchedFindings: PolicyMatchedFinding[];
    /** Evaluation error, if any */
    error?: string;
}

/**
 * A finding that matched a policy condition
 */
export interface PolicyMatchedFinding {
    id: string;
    type: string;
    severity: string;
    title: string;
    url?: string;
    selector?: string;
}

/**
 * Overall result of policy evaluation
 */
export interface PolicyEvaluationResult {
    /** Whether all policies passed */
    passed: boolean;
    /** Total number of policies evaluated */
    totalPolicies: number;
    /** Policies that failed */
    failedPolicies: PolicyResult[];
    /** Policies that warned */
    warnedPolicies: PolicyResult[];
    /** Policies that passed */
    passedPolicies: PolicyResult[];
    /** Summary counts */
    summary: {
        fail: number;
        warn: number;
        info: number;
        pass: number;
    };
    /** Suggested exit code (0 = success, 1 = failure) */
    exitCode: number;
}

/**
 * Context available during policy evaluation
 */
export interface PolicyEvaluationContext {
    /** All findings from the scan */
    findings: PolicyMatchedFinding[];
    /** Scan metadata */
    meta: {
        targetUrl: string;
        scanProfile: string;
        duration: number;
        timestamp: string;
    };
    /** Lighthouse scores */
    lighthouse?: {
        performance: number;
        accessibility: number;
        seo: number;
        bestPractices: number;
    };
    /** Security summary */
    security?: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        total: number;
    };
}

/**
 * Supported operators in condition expressions
 */
export type PolicyOperator =
    | '=='
    | '!='
    | '<'
    | '>'
    | '<='
    | '>='
    | 'contains'
    | 'startswith'
    | 'endswith'
    | 'matches';

/**
 * Parsed condition AST node
 */
export interface ConditionNode {
    type: 'comparison' | 'logical' | 'value';
    operator?: PolicyOperator | 'AND' | 'OR' | 'NOT';
    left?: ConditionNode | string;
    right?: ConditionNode | string | number | boolean;
    value?: string | number | boolean;
}
