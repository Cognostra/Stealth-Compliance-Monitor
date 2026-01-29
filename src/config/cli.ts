
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
