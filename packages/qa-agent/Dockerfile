# Stage 1: Build dashboard (React + Vite)
FROM node:22-alpine AS dashboard
WORKDIR /build
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm install
COPY dashboard/ .
RUN npm run build

# Stage 2: Build qa-agent binary (Bun compile)
FROM oven/bun:1.3-alpine AS agent
WORKDIR /build
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile || bun install
COPY src/ src/
COPY script/ script/
RUN bun run script/build.ts --single

# Stage 3: Runtime
FROM oven/bun:1.3-debian

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Claude CLI
RUN npm install -g @anthropic-ai/claude-code

WORKDIR /app

# Copy qa-agent binary
COPY --from=agent /build/dist/qa-agent /app/qa-agent
RUN chmod +x /app/qa-agent

# Copy dashboard static files
COPY --from=dashboard /build/dist /app/public

# Copy orchestrator source (runs via bun)
COPY orchestrator/ /app/orchestrator/

# Data volume for repos, reports, config, and Claude credentials
VOLUME /data

EXPOSE 3000

# HOME=/data ensures Claude stores credentials at /data/.claude/.credentials.json
# This persists OAuth tokens across container restarts via the volume mount
ENV HOME=/data
ENV NODE_ENV=production
ENV PORT=3000
ENV PUBLIC_DIR=/app/public
ENV QA_AGENT_PATH=/app/qa-agent
ENV DATA_DIR=/data

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

CMD ["bun", "run", "/app/orchestrator/index.ts"]
