
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

    return {
        args,
        profileName,
        activeFlag,
        headedFlag,
        debugFlag,
        slowMoValue,
        positionalTarget
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
