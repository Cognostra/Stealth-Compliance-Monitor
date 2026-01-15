# Stealth Compliance Monitor - Dockerfile
# Base image with Node.js and pre-installed Playwright browsers
FROM mcr.microsoft.com/playwright:v1.41.0-jammy

# Set working directory
WORKDIR /app

# Create non-root user for security (Playwright image already has pwuser)
# We'll use it later for running the application

# Copy package files first (for better layer caching)
COPY package.json package-lock.json* ./

# Install dependencies (use npm ci for reproducible builds)
# --ignore-scripts prevents postinstall scripts that might fail in container
RUN npm ci --ignore-scripts

# Install Playwright browsers (in case they're not fully installed)
# This ensures compatibility with the installed playwright version
RUN npx playwright install chromium --with-deps

# Copy TypeScript config
COPY tsconfig.json ./

# Copy source code
COPY src/ ./src/

# Build TypeScript to JavaScript
RUN npm run build

# Create directories for outputs with proper permissions
RUN mkdir -p /app/reports /app/logs /app/screenshots /app/snapshots/baseline /app/snapshots/current /app/snapshots/diff \
    && chown -R pwuser:pwuser /app

# Copy any existing baseline snapshots (if they exist)
COPY --chown=pwuser:pwuser snapshots/baseline/ ./snapshots/baseline/ 2>/dev/null || true

# Switch to non-root user for security
USER pwuser

# Health check - verify node is working
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "console.log('healthy')" || exit 1

# Default command - run the compiled bot
CMD ["node", "dist/index.js"]
