FROM golang:1.26.8-alpine3.23@sha256:a8fa79c5bd40d880b52bd3b6d7669ecdcfd00e85facdd427d279efb5ddd79cb1 AS build
ARG VERSION
WORKDIR /src/platform
COPY services/health /src/health
COPY services/platform/go.mod services/platform/go.sum ./
RUN go mod download
COPY services/platform ./
RUN test -n "$VERSION" && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.buildVersion=$VERSION" -o /out/agentsec-worker ./agentsec-worker && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.buildVersion=$VERSION" -o /out/agentsec-attack-lab-proxy ./attack-lab-proxy && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/zasp-authorization-reconcile ./cmd/zasp-authorization-reconcile && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/zasp-healthcheck ./cmd/zasp-healthcheck

FROM ghcr.io/promptfoo/promptfoo:0.121.19@sha256:50d3a796710e4db7a5ede90bf27dc28146ef022a7ebb83914c5105608396fd96 AS promptfoo-assets
FROM node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS node-assets
FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS runner-assets
ENV HOME=/tmp PROMPTFOO_CACHE_ENABLED=false PROMPTFOO_CONFIG_DIR=/tmp/promptfoo-state PROMPTFOO_DISABLE_ERROR_LOG=1 PROMPTFOO_DISABLE_REMOTE_GENERATION=1 PROMPTFOO_DISABLE_TELEMETRY=1 PROMPTFOO_DISABLE_UPDATE=1
WORKDIR /app
COPY --from=node-assets /usr/local/bin/node /usr/local/bin/node
COPY --from=promptfoo-assets /app/ /app/
COPY workers/redteam-node/runner.mjs /app/redteam-runner.mjs
USER 65532:65532
RUN test "$(node --version)" = "v22.23.1" && test "$(node /app/dist/src/entrypoint.js --version)" = "0.121.19" && \
    node --input-type=module -e "const m = await import('./redteam-runner.mjs'); if (typeof m.buildPromptfooConfiguration !== 'function') process.exit(1); const {createClient} = await import('@libsql/client'); const db = createClient({url:'file:/tmp/runner-abi.db'}); await db.execute('SELECT 1'); db.close()"

FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS security-python-build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
COPY workers/security-python /src/security-python
RUN python -m venv /opt/zasp/security/cartography && \
    /opt/zasp/security/cartography/bin/pip install --require-hashes --no-deps -r /src/security-python/build-requirements.lock && \
    /opt/zasp/security/cartography/bin/pip install --require-hashes --no-build-isolation --no-deps -r /src/security-python/cartography/requirements.lock && \
    /opt/zasp/security/cartography/bin/pip install --no-build-isolation --no-deps /src/security-python && \
    /opt/zasp/security/cartography/bin/python -c "import cartography; from security_worker import cartography_aws; assert cartography_aws.load_runtime_api().version == '0.139.1'" && \
    /opt/zasp/security/cartography/bin/security-worker health
# The pinned zstd dependency resolves to source on CPython 3.13 ARM64. Compile its
# bundled C sources here; no compiler or build headers enter the runtime stage.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev
RUN python -m venv /opt/zasp/security/prowler && \
    /opt/zasp/security/prowler/bin/pip install --require-hashes --no-deps -r /src/security-python/build-requirements.lock && \
    /opt/zasp/security/prowler/bin/pip install --require-hashes --no-build-isolation --no-deps -r /src/security-python/prowler/requirements.lock && \
    /opt/zasp/security/prowler/bin/pip install --no-build-isolation --no-deps /src/security-python && \
    /opt/zasp/security/prowler/bin/python -c "from security_worker import prowler_aws; api = prowler_aws.load_runtime_api(); assert api.version == '5.39.1'; assert all(name in prowler_aws._CHECK_MODULES for name in prowler_aws.CHECKS)" && \
    /opt/zasp/security/prowler/bin/security-worker health

FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV HOME=/tmp PROMPTFOO_CACHE_ENABLED=false PROMPTFOO_CONFIG_DIR=/tmp/promptfoo-state PROMPTFOO_DISABLE_ERROR_LOG=1 PROMPTFOO_DISABLE_REMOTE_GENERATION=1 PROMPTFOO_DISABLE_TELEMETRY=1 PROMPTFOO_DISABLE_UPDATE=1
WORKDIR /app
COPY --from=runner-assets /usr/local/bin/node /usr/local/bin/node
COPY --from=runner-assets --chown=65532:65532 /app/ /app/
COPY --from=build --chown=65532:65532 /out/agentsec-worker /out/agentsec-attack-lab-proxy /out/zasp-authorization-reconcile /out/zasp-healthcheck ./
COPY --from=security-python-build --chown=65532:65532 /opt/zasp/security /opt/zasp/security
USER 65532:65532
EXPOSE 8081
HEALTHCHECK --interval=10s --timeout=2s --start-period=10s --retries=3 CMD ["/app/zasp-healthcheck", "http://127.0.0.1:8081/healthz"]
ENTRYPOINT ["/app/agentsec-worker"]
