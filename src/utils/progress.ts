import { SingleBar, Presets } from 'cli-progress';
import { logger } from './logger.js';

export class ProgressReporter {
    private readonly bar: SingleBar;
    private isActive = false;
    private readonly prefix: string;
    private current = 0;

    constructor(prefix?: string) {
        this.prefix = prefix ? `${prefix}: ` : '';
        this.bar = new SingleBar({
            format: `${this.prefix}{bar} {percentage}% | {value}/{total} | {label} {detail}`,
            barCompleteChar: '\u2588',
            barIncompleteChar: '\u2591',
            hideCursor: true,
            clearOnComplete: false,
            stopOnComplete: true,
            forceRedraw: true
        }, Presets.shades_classic);
    }

    start(totalSteps: number, label: string): void {
        this.current = 0;
        if (!process.stdout.isTTY) {
            logger.info(`${this.prefix}${label}`);
            return;
        }

        this.isActive = true;
        this.bar.start(totalSteps, 0, {
            label: label,
            detail: ''
        });
    }

    advance(label: string, detail: string = ''): void {
        this.current++;
        if (!this.isActive) {
            return;
        }
        
        this.bar.increment(1, {
            label: label,
            detail: detail ? `- ${detail}` : ''
        });
    }

    update(label: string, detail: string = ''): void {
         if (!this.isActive) return;
         
         this.bar.update(this.current, {
             label: label,
             detail: detail ? `- ${detail}` : ''
         });
    }

    finish(label = 'Complete'): void {
        if (this.isActive) {
            this.bar.update(this.bar.getTotal(), {
                label: label,
                detail: ''
            });
            this.bar.stop();
            this.isActive = false;
        } else {
            logger.info(`${this.prefix}${label}`);
        }
    }
}
