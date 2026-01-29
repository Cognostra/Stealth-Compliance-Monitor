# Stealth Compliance Monitor - Dockerfile
# Multi-architecture production container (amd64/arm64)
#
# Build: docker build -t stealth-compliance-monitor .
# Run:   docker run -v $(pwd)/reports:/app/reports stealth-compliance-monitor
#
# Multi-arch build:
#   docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/your-org/scm:latest --push .

# Base image with Node.js and pre-installed Playwright browsers
# This image supports both amd64 and arm64 architectures
FROM mcr.microsoft.com/playwright:v1.57.0-jammy

# Labels for container registry
LABEL org.opencontainers.image.source="https://github.com/your-org/stealth-compliance-monitor"
LABEL org.opencontainers.image.description="Automated compliance scanning for web applications"
LABEL org.opencontainers.image.licenses="MIT"

# Set working directory
WORKDIR /app

# Create non-root user for security (Playwright image already has pwuser)
# We'll use it later for running the application

# Copy package files first (for better layer caching)
COPY package.json package-lock.json* ./

# Copy TypeScript config and source code
COPY tsconfig.json ./
COPY src/ ./src/

# Install dependencies, build TypeScript, and prepare directories
# Combined into single RUN to reduce Docker layers
RUN npm ci --ignore-scripts && \
    npx playwright install chromium --with-deps && \
    npm run build && \
    mkdir -p /app/reports \
             /app/logs \
             /app/screenshots \
             /app/snapshots/baseline \
             /app/snapshots/current \
             /app/snapshots/diff \
             /app/cache && \
    chown -R pwuser:pwuser /app

# Note: To include baseline snapshots in the image, create snapshots/baseline/
# directory in your build context and add .png files there before building

# Switch to non-root user for security
USER pwuser

# Environment defaults (can be overridden at runtime)
ENV NODE_ENV=production
ENV REPORTS_DIR=/app/reports
ENV SCREENSHOTS_DIR=/app/screenshots
ENV VULN_INTEL_CACHE_PATH=/app/cache/vuln-intel-cache.json

# Health check - verify node is working
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "console.log('healthy')" || exit 1

# Default command - run the compiled bot
CMD ["node", "dist/index.js"]
