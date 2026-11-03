# syntax=docker/dockerfile:1.7

# Built from the zolana-tvc root: deploy/aws/deploy.sh passes it as the context.
FROM node:24-bookworm-slim AS builder
ENV NEXT_TELEMETRY_DISABLED=1
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ./
COPY patches ./patches
COPY packages/tvc-wallet/package.json ./packages/tvc-wallet/package.json
COPY packages/tvc-wallet-kit/package.json ./packages/tvc-wallet-kit/package.json
COPY examples/privacy-wallet-next-app/package.json ./examples/privacy-wallet-next-app/package.json
RUN pnpm install --frozen-lockfile

COPY packages/tvc-wallet ./packages/tvc-wallet
COPY packages/tvc-wallet-kit ./packages/tvc-wallet-kit
COPY examples/privacy-wallet-next-app ./examples/privacy-wallet-next-app
RUN pnpm --filter @zolana/tvc-wallet --filter @zolana/tvc-wallet-kit build
RUN --mount=type=secret,id=helius_api_key,required=true \
  NEXT_PUBLIC_HELIUS_API_KEY="$(cat /run/secrets/helius_api_key)" \
  pnpm --filter zolana-privacy-wallet-next-app build

FROM node:24-bookworm-slim AS runner
ENV NODE_ENV=production \
  NEXT_TELEMETRY_DISABLED=1 \
  HOSTNAME=0.0.0.0 \
  PORT=3001
WORKDIR /app/examples/privacy-wallet-next-app
COPY --from=builder /src/examples/privacy-wallet-next-app/.next/standalone /app
COPY --from=builder /src/examples/privacy-wallet-next-app/.next/static ./.next/static
COPY --from=builder /src/examples/privacy-wallet-next-app/public ./public
USER node
EXPOSE 3001
CMD ["sh", "-c", "HOSTNAME=0.0.0.0 exec node server.js"]
