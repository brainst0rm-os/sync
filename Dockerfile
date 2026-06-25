# brainstorm-sync relay node (SYNC-1, forward-only).
FROM oven/bun:1.3-slim

WORKDIR /app

# Install deps (dev deps are only needed for lint/typecheck; runtime needs none,
# but we keep the lockfile install for reproducibility).
COPY package.json bun.lock* ./
RUN bun install --production || bun install --production --no-save

COPY src ./src
COPY tsconfig.json ./

ENV PORT=7780
ENV LOG_LEVEL=info
EXPOSE 7780

# Liveness: GET /healthz returns "ok".
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD bun -e "fetch('http://127.0.0.1:'+(process.env.PORT||7780)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["bun", "run", "src/main.ts"]
