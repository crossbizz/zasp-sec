FROM node:22.23.1-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY app ./app
COPY apps ./apps
COPY public ./public
COPY next.config.ts postcss.config.mjs tsconfig.json vite.config.ts cloudflare-env.d.ts next-env.d.ts ./
RUN npm run build

FROM node:22.23.1-bookworm-slim AS runtime
ENV HOSTNAME=0.0.0.0 NODE_ENV=production PORT=3000
WORKDIR /app
COPY --from=build --chown=65532:65532 /src/dist ./dist
COPY --from=build --chown=65532:65532 /src/public ./public
COPY --from=build --chown=65532:65532 /src/node_modules ./node_modules
COPY --from=build --chown=65532:65532 /src/package.json ./package.json
USER 65532:65532
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=2s --start-period=20s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:3000/').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["./node_modules/.bin/vinext", "start", "-p", "3000"]
