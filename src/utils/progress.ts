import * as readline from 'readline';

const SPINNER_FRAMES = ['|', '/', '-', '\\'];

export class ProgressReporter {
    private total = 1;
    private current = 0;
    private label = '';
    private detail: string | undefined;
    private startTime = Date.now();
    private timer: NodeJS.Timeout | null = null;
    private spinnerIndex = 0;
    private readonly prefix: string;

    constructor(prefix?: string) {
        this.prefix = prefix ? `${prefix} ` : '';
    }

    start(totalSteps: number, label: string): void {
        this.total = Math.max(1, totalSteps);
        this.current = 0;
        this.label = label;
        this.detail = undefined;
        this.startTime = Date.now();

        if (!process.stdout.isTTY) {
            return;
        }

        this.stopTimer();
        this.timer = setInterval(() => this.render(false), 1000);
        this.render(true);
    }

    advance(label: string, detail?: string): void {
        this.current = Math.min(this.total, this.current + 1);
        this.label = label;
        this.detail = detail;
        this.render(true);
    }

    update(label: string, detail?: string): void {
        this.label = label;
        this.detail = detail;
        this.render(true);
    }

    finish(label = 'Complete'): void {
        this.label = label;
        this.detail = undefined;
        this.current = this.total;
        this.render(true);
        this.stopTimer();

        if (process.stdout.isTTY) {
            process.stdout.write('\n');
        }
    }

    private stopTimer(): void {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
    }

    private render(force: boolean): void {
        if (!process.stdout.isTTY) {
            return;
        }

        const percent = Math.round((this.current / this.total) * 100);
        const width = 20;
        const filled = Math.round((percent / 100) * width);
        const bar = `${'█'.repeat(filled)}${'░'.repeat(width - filled)}`;
        const spinner = SPINNER_FRAMES[this.spinnerIndex++ % SPINNER_FRAMES.length];
        const elapsed = Math.floor((Date.now() - this.startTime) / 1000);
        const detail = this.detail ? ` - ${this.detail}` : '';
        const line = `${this.prefix}${spinner} [${bar}] ${percent}% ${this.label}${detail} (${elapsed}s)`;

        readline.clearLine(process.stdout, 0);
        readline.cursorTo(process.stdout, 0);
        process.stdout.write(line);

        if (force) {
            return;
        }
    }
}
