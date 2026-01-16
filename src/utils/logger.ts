/**
 * Winston Logger Configuration
 * Logs to both Console and file (logs/app.log)
 */

import winston from 'winston';
import * as fs from 'fs';
import * as path from 'path';
import { redactObject, redactString } from './redaction.js';

// Ensure logs directory exists
const logsDir = path.resolve(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

const { combine, timestamp, printf, colorize, errors } = winston.format;
const redactionEnabled = process.env.REDACTION_ENABLED?.toLowerCase() !== 'false';

const redactFormat = winston.format(info => {
    if (!redactionEnabled) return info;
    const redacted: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(info)) {
        if (key === 'message' && typeof val === 'string') {
            redacted[key] = redactString(val);
        } else if (key === 'stack' && typeof val === 'string') {
            redacted[key] = redactString(val);
        } else if (key === 'level' || key === 'timestamp') {
            redacted[key] = val;
        } else {
            redacted[key] = redactObject(val);
        }
    }
    return redacted as winston.Logform.TransformableInfo;
});

/**
 * Custom log format for console output
 */
const consoleFormat = printf(({ level, message, timestamp, stack, ...meta }) => {
    const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
    const stackStr = stack ? `\n${stack}` : '';
    return `${timestamp} [${level}] ${message}${metaStr}${stackStr}`;
});

/**
 * Custom log format for file output (no colors)
 */
const fileFormat = printf(({ level, message, timestamp, stack, ...meta }) => {
    const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
    const stackStr = stack ? `\n${stack}` : '';
    return `${timestamp} [${level.toUpperCase()}] ${message}${metaStr}${stackStr}`;
});

/**
 * Winston logger instance
 * - Console: Colorized output with timestamps
 * - File: Plain text output to logs/app.log
 */
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: combine(
        errors({ stack: true }),
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        redactFormat()
    ),
    transports: [
        // Console transport with colors
        new winston.transports.Console({
            format: combine(
                colorize({ all: true }),
                timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                consoleFormat
            ),
        }),
        // File transport - all logs
        new winston.transports.File({
            filename: path.join(logsDir, 'app.log'),
            format: combine(
                timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                fileFormat
            ),
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
        // Separate error log file
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
            format: combine(
                timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                fileFormat
            ),
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
    ],
    // Handle exceptions and rejections
    exceptionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'exceptions.log'),
        }),
    ],
    rejectionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'rejections.log'),
        }),
    ],
});

/**
 * Log a section header for visual separation
 */
export function logSection(title: string): void {
    const separator = '═'.repeat(60);
    logger.info('');
    logger.info(separator);
    logger.info(`  ${title.toUpperCase()}`);
    logger.info(separator);
}

/**
 * Log a numbered step in a process
 */
export function logStep(step: number, total: number, message: string): void {
    logger.info(`[${step}/${total}] ${message}`);
}

/**
 * Log a success message with checkmark
 */
export function logSuccess(message: string): void {
    logger.info(`✓ ${message}`);
}

/**
 * Log a failure message with X
 */
export function logFailure(message: string): void {
    logger.error(`✗ ${message}`);
}

/**
 * Log a warning message
 */
export function logWarning(message: string): void {
    logger.warn(`⚠ ${message}`);
}

/**
 * Create a child logger with additional metadata
 */
export function createChildLogger(meta: Record<string, unknown>): winston.Logger {
    return logger.child(meta);
}

export { logger };
export default logger;
