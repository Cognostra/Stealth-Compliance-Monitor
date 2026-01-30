
import { logger } from '../utils/logger.js';
import * as path from 'node:path';
import * as fs from 'node:fs';

export interface CliOptions {
    args: string[];
    profileName: string;
    activeFlag: boolean;
    headedFlag: boolean;
    debugFlag: boolean;
    slowMoValue: number;
    positionalTarget?: string;
    /** Electron auditing: target type override */
    targetType?: 'web' | 'electron';
    /** Path to Electron executable */
    electronPath?: string;
    /** Extra args to pass to Electron */
    electronArgs?: string;
    /** Enable local LLM remediation via Ollama */
    aiFixFlag: boolean;
    /** Optional model override for --ai-fix */
    aiFixModel?: string;
    /** Enable Flutter semantics scanning */
    flutterSemanticsFlag: boolean;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 1: Core Security
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable SBOM (Software Bill of Materials) scanning */
    sbomScannerFlag: boolean;
    /** Enable GraphQL deep security scanning */
    graphqlScannerFlag: boolean;
    /** Enable WebSocket security auditing */
    websocketAuditorFlag: boolean;
    /** Enable CSP violation collection */
    cspCollectorFlag: boolean;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 2: AI-Powered
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable Visual AI compliance checking */
    visualAiComplianceFlag: boolean;
    /** Path to brand color palette guide */
    brandGuidePath?: string;
    /** Enable browser fingerprinting detection */
    fingerprintDetectionFlag: boolean;
    /** Enable AI-generated test flow generation */
    aiTestFlowGeneratorFlag: boolean;
    /** Enable smart false positive filtering */
    falsePositiveFilterFlag: boolean;
    /** Enable privacy policy analyzer */
    privacyPolicyAnalyzerFlag: boolean;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 3: Web Platform
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable WebRTC security analysis */
    webrtcAnalyzerFlag: boolean;
    /** Enable PWA security scanning */
    pwaScannerFlag: boolean;
    /** Enable browser extension audit */
    extensionAuditFlag: boolean;
    /** Enable mobile security scanning */
    mobileSecurityScannerFlag: boolean;
    /** Enable Shadow DOM & Web Components scanning */
    shadowDomScannerFlag: boolean;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 4: Infrastructure/DevSecOps
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable WebAssembly security scanning */
    wasmScannerFlag: boolean;
    /** Enable container security scanning */
    containerScannerFlag: boolean;
    /** Enable Kubernetes security scanning */
    k8sScannerFlag: boolean;
    /** Enable API contract testing */
    apiContractTestingFlag: boolean;
    /** Enable chaos engineering tests */
    chaosTestingFlag: boolean;
    /** Enable multi-region compliance testing */
    multiRegionComplianceFlag: boolean;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 5: Integrations
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable VS Code extension integration */
    vscodeIntegrationFlag: boolean;
    /** Enable GitHub App integration */
    githubIntegrationFlag: boolean;
    /** Enable Postman/Newman integration */
    postmanIntegrationFlag: boolean;
    /** Enable JIRA/ServiceNow ticketing integration */
    ticketingIntegrationFlag: boolean;
    /** Enable Slack/Teams messaging integration */
    messagingIntegrationFlag: boolean;

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 6: Enterprise
    // ═══════════════════════════════════════════════════════════════════════════════
    /** Enable FAIR risk quantification */
    fairRiskQuantificationFlag: boolean;
    /** Enable compliance drift detection */
    driftDetectionFlag: boolean;
    /** Enable third-party risk aggregation */
    thirdPartyRiskFlag: boolean;
    /** Enable real-time dashboard */
    realtimeDashboardFlag: boolean;
    /** Enable evidence vault for legal hold */
    evidenceVaultFlag: boolean;
}

export function parseCliOptions(args: string[]): CliOptions {
    const profileArg = args.find(arg => arg.startsWith('--profile='));
    const activeFlag = args.includes('--active');
    let profileName = profileArg ? profileArg.split('=')[1] : 'standard';

    // If --active flag is set, force deep-active profile
    if (activeFlag && !profileArg) {
        profileName = 'deep-active';
        logger.warn('⚠️  --active flag detected, using deep-active profile');
    }

    const headedFlag = args.includes('--headed');
    const debugFlag = args.includes('--debug');
    const slowMoArg = args.find(arg => arg.startsWith('--slow-mo='));
    const slowMoValue = slowMoArg ? Number.parseInt(slowMoArg.split('=')[1], 10) : 0;
    const positionalTarget = args.find(arg => !arg.startsWith('-'));

    // Electron auditing flags
    const targetTypeArg = args.find(arg => arg.startsWith('--target-type='));
    const targetType = targetTypeArg ? targetTypeArg.split('=')[1] as 'web' | 'electron' : undefined;
    const electronPathArg = args.find(arg => arg.startsWith('--electron-path='));
    const electronPath = electronPathArg ? electronPathArg.split('=')[1] : undefined;
    const electronArgsArg = args.find(arg => arg.startsWith('--electron-args='));
    const electronArgs = electronArgsArg ? electronArgsArg.split('=')[1] : undefined;

    // AI fix flag (--ai-fix or --ai-fix=model-name)
    const aiFixArg = args.find(arg => arg.startsWith('--ai-fix'));
    const aiFixFlag = !!aiFixArg;
    const aiFixModel = aiFixArg && aiFixArg.includes('=') ? aiFixArg.split('=')[1] : undefined;

    // Flutter semantics flag
    const flutterSemanticsFlag = args.includes('--flutter-semantics');

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 1: Core Security
    // ═══════════════════════════════════════════════════════════════════════════════
    const sbomScannerFlag = args.includes('--sbom');
    const graphqlScannerFlag = args.includes('--graphql');
    const websocketAuditorFlag = args.includes('--websocket');
    const cspCollectorFlag = args.includes('--csp');

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 2: AI-Powered
    // ═══════════════════════════════════════════════════════════════════════════════
    const visualAiComplianceFlag = args.includes('--visual-ai');
    const brandGuidePathArg = args.find(arg => arg.startsWith('--brand-guide='));
    const brandGuidePath = brandGuidePathArg ? brandGuidePathArg.split('=')[1] : undefined;
    const fingerprintDetectionFlag = args.includes('--fingerprint');
    const aiTestFlowGeneratorFlag = args.includes('--ai-flows');
    const falsePositiveFilterFlag = args.includes('--fp-filter');
    const privacyPolicyAnalyzerFlag = args.includes('--privacy');

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 3: Web Platform
    // ═══════════════════════════════════════════════════════════════════════════════
    const webrtcAnalyzerFlag = args.includes('--webrtc');
    const pwaScannerFlag = args.includes('--pwa');
    const extensionAuditFlag = args.includes('--extension');
    const mobileSecurityScannerFlag = args.includes('--mobile');
    const shadowDomScannerFlag = args.includes('--shadow-dom');

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 4: Infrastructure/DevSecOps
    // ═══════════════════════════════════════════════════════════════════════════════
    const wasmScannerFlag = args.includes('--wasm');
    const containerScannerFlag = args.includes('--container');
    const k8sScannerFlag = args.includes('--k8s');
    const apiContractTestingFlag = args.includes('--api-contract');
    const chaosTestingFlag = args.includes('--chaos');
    const multiRegionComplianceFlag = args.includes('--multi-region');

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 5: Integrations
    // ═══════════════════════════════════════════════════════════════════════════════
    const vscodeIntegrationFlag = args.includes('--vscode');
    const githubIntegrationFlag = args.includes('--github');
    const postmanIntegrationFlag = args.includes('--postman');
    const ticketingIntegrationFlag = args.includes('--ticketing');
    const messagingIntegrationFlag = args.includes('--messaging');

    // ═══════════════════════════════════════════════════════════════════════════════
    // v3.2 FEATURE FLAGS - Phase 6: Enterprise
    // ═══════════════════════════════════════════════════════════════════════════════
    const fairRiskQuantificationFlag = args.includes('--fair-risk');
    const driftDetectionFlag = args.includes('--drift');
    const thirdPartyRiskFlag = args.includes('--third-party-risk');
    const realtimeDashboardFlag = args.includes('--dashboard');
    const evidenceVaultFlag = args.includes('--evidence');

    return {
        args,
        profileName,
        activeFlag,
        headedFlag,
        debugFlag,
        slowMoValue,
        positionalTarget,
        targetType,
        electronPath,
        electronArgs,
        aiFixFlag,
        aiFixModel,
        flutterSemanticsFlag,
        // v3.2 Phase 1
        sbomScannerFlag,
        graphqlScannerFlag,
        websocketAuditorFlag,
        cspCollectorFlag,
        // v3.2 Phase 2
        visualAiComplianceFlag,
        brandGuidePath,
        fingerprintDetectionFlag,
        aiTestFlowGeneratorFlag,
        falsePositiveFilterFlag,
        privacyPolicyAnalyzerFlag,
        // v3.2 Phase 3
        webrtcAnalyzerFlag,
        pwaScannerFlag,
        extensionAuditFlag,
        mobileSecurityScannerFlag,
        shadowDomScannerFlag,
        // v3.2 Phase 4
        wasmScannerFlag,
        containerScannerFlag,
        k8sScannerFlag,
        apiContractTestingFlag,
        chaosTestingFlag,
        multiRegionComplianceFlag,
        // v3.2 Phase 5
        vscodeIntegrationFlag,
        githubIntegrationFlag,
        postmanIntegrationFlag,
        ticketingIntegrationFlag,
        messagingIntegrationFlag,
        // v3.2 Phase 6
        fairRiskQuantificationFlag,
        driftDetectionFlag,
        thirdPartyRiskFlag,
        realtimeDashboardFlag,
        evidenceVaultFlag,
    };
}

export function loadTargets(targetUrl: string | string[]): string[] {
    if (Array.isArray(targetUrl)) {
        return targetUrl;
    } 
    
    if (targetUrl.endsWith('.json')) {
        try {
            const targetsPath = path.resolve(targetUrl);
            logger.info(`Loading targets from: ${targetsPath}`);

            if (fs.existsSync(targetsPath)) {
                const fileContent = fs.readFileSync(targetsPath, 'utf-8');
                const jsonData = JSON.parse(fileContent);

                if (Array.isArray(jsonData)) {
                    return jsonData;
                } 
                if (jsonData.targets && Array.isArray(jsonData.targets)) {
                    return jsonData.targets;
                } 
                
                throw new Error('Invalid JSON format. Expected array or object with "targets" array.');
            } else {
                throw new Error(`File not found: ${targetsPath}`);
            }
        } catch (error) {
            logger.error(`Failed to load targets file: ${error instanceof Error ? error.message : String(error)}`);
            process.exit(1);
        }
    } 
    
    return [targetUrl];
}
