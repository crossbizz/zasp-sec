FROM golang:1.25.6-alpine3.22@sha256:fa3380ab0d73b706e6b07d2a306a4dc68f20bfc1437a6a6c47c8f88fe4af6f75 AS build
ARG VERSION
WORKDIR /src/platform
COPY services/health /src/health
COPY services/platform/go.mod services/platform/go.sum ./
RUN go mod download
COPY services/platform ./
RUN test -n "$VERSION" && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.buildVersion=$VERSION" -o /out/agentsec-worker ./agentsec-worker && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.buildVersion=$VERSION" -o /out/red-team-adapter ./red-team-adapter && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/zasp-healthcheck ./cmd/zasp-healthcheck

FROM ghcr.io/promptfoo/promptfoo:0.121.19@sha256:50d3a796710e4db7a5ede90bf27dc28146ef022a7ebb83914c5105608396fd96
ENV HOME=/tmp \
    PROMPTFOO_CACHE_ENABLED=false \
    PROMPTFOO_CONFIG_DIR=/tmp/promptfoo-state \
    PROMPTFOO_DISABLE_ERROR_LOG=1 \
    PROMPTFOO_DISABLE_REMOTE_GENERATION=1 \
    PROMPTFOO_DISABLE_TELEMETRY=1 \
    PROMPTFOO_DISABLE_UPDATE=1
WORKDIR /app
COPY --from=build --chown=1000:1000 /out/agentsec-worker /out/red-team-adapter /out/zasp-healthcheck ./
COPY --chown=promptfoo:promptfoo workers/redteam-node/runner.mjs ./redteam-runner.mjs
USER 1000:1000
EXPOSE 8081 8443
HEALTHCHECK --interval=10s --timeout=2s --start-period=10s --retries=3 CMD ["/app/zasp-healthcheck", "http://127.0.0.1:8081/healthz"]
ENTRYPOINT ["/app/agentsec-worker"]
