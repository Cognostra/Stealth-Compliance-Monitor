
import prompts from 'prompts';
import * as fs from 'node:fs';
import { logger } from '../../utils/logger.js';

export async function runInitWizard(): Promise<void> {
    console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║           Stealth Compliance Monitor - Initialization              ║
╚═══════════════════════════════════════════════════════════════════╝
`);

    const response = await prompts([
        {
            type: 'text',
            name: 'targetUrl',
            message: 'What is the target URL to monitor?',
            initial: 'https://example.com'
        },
        {
            type: 'select',
            name: 'scanProfile',
            message: 'Select a scan profile',
            choices: [
                { title: 'Standard (Passive, 15 pages)', value: 'standard' },
                { title: 'Smoke (Health Check, 1 page)', value: 'smoke' },
                { title: 'Deep (Full Scan, 50 pages)', value: 'deep' }
            ],
            initial: 0
        },
        {
            type: 'confirm',
            name: 'enableV3',
            message: 'Enable v3 features (SARIF, Compliance Mapping)?',
            initial: true
        },
        {
            type: (prev: boolean) => prev === true ? 'multiselect' : null,
            name: 'frameworks',
            message: 'Select compliance frameworks',
            choices: [
                { title: 'SOC 2', value: 'soc2' },
                { title: 'GDPR', value: 'gdpr' },
                { title: 'HIPAA', value: 'hipaa' }
            ],
            min: 1
        },
        {
            type: 'confirm',
            name: 'saveConfig',
            message: 'Save configuration to .env?',
            initial: true
        }
    ]);

    if (response.saveConfig) {
        // For demo purposes, we'll just log what we would do or write a fresh file if missing
        if (fs.existsSync('.env')) {
            logger.info('Updating .env is skipped in this demo wizard to avoid overwriting secrets, but configuration is ready.');
        } else {
            fs.writeFileSync('.env', `LIVE_URL=${response.targetUrl}\nSCAN_PROFILE=${response.scanProfile}\n`, 'utf-8');
            logger.info('Created .env file.');
        }
    }

    console.log('\n✅ Initialization Complete!');
    console.log(`Run audit with: npm run dev -- --profile=${response.scanProfile} ${response.enableV3 ? '--compliance=' + response.frameworks.join(',') : ''}`);
}
