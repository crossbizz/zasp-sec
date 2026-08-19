FROM node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY app ./app
COPY apps ./apps
COPY public ./public
COPY worker ./worker
COPY next.config.ts postcss.config.mjs tsconfig.json vite.config.ts cloudflare-env.d.ts next-env.d.ts ./
RUN npm run build

FROM node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS runtime
ENV HOST=0.0.0.0 NODE_ENV=production PORT=3000
WORKDIR /app
COPY --from=build --chown=65532:65532 /src/dist/standalone/ ./
USER 65532:65532
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=2s --start-period=20s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:3000/').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["node", "server.js"]
