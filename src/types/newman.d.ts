/**
 * Type declaration for newman package
 * Newman is an optional peer dependency for Postman collection execution
 */
declare module 'newman' {
    interface NewmanRunOptions {
        collection: string | object;
        environment?: string;
        reporters?: string[];
        reporter?: Record<string, unknown>;
        timeout?: number;
        bail?: boolean;
        suppressExitCode?: boolean;
        [key: string]: unknown;
    }

    interface NewmanRunSummary {
        run: {
            stats: {
                requests: { total: number; pending: number; failed: number };
                assertions: { total: number; pending: number; failed: number };
            };
            timings: {
                started: string;
                completed: string;
                responseAverage: number;
            };
            failures: Array<{
                source: string;
                error: { message: string; test?: string };
            }>;
        };
    }

    function run(
        options: NewmanRunOptions,
        callback: (err: Error | null, summary: NewmanRunSummary) => void
    ): void;

    export { run, NewmanRunOptions, NewmanRunSummary };
    export default { run };
}
