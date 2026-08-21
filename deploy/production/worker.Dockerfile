FROM golang:1.25.6-alpine3.22@sha256:fa3380ab0d73b706e6b07d2a306a4dc68f20bfc1437a6a6c47c8f88fe4af6f75 AS build
ARG VERSION
WORKDIR /src/platform
COPY services/health /src/health
COPY services/platform/go.mod services/platform/go.sum ./
RUN go mod download
COPY services/platform ./
RUN test -n "$VERSION" && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.buildVersion=$VERSION" -o /out/agentsec-worker ./agentsec-worker && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/zasp-healthcheck ./cmd/zasp-healthcheck

FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS security-python-build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
COPY workers/security-python /src/security-python
RUN python -m venv /opt/zasp/security/cartography && \
    /opt/zasp/security/cartography/bin/pip install --require-hashes --no-deps -r /src/security-python/build-requirements.lock && \
    /opt/zasp/security/cartography/bin/pip install --require-hashes --no-build-isolation --no-deps -r /src/security-python/cartography/requirements.lock && \
    /opt/zasp/security/cartography/bin/pip install --no-build-isolation --no-deps /src/security-python && \
    /opt/zasp/security/cartography/bin/python -c "import cartography; from security_worker import cartography_aws; assert cartography_aws.load_runtime_api().version == '0.139.1'" && \
    /opt/zasp/security/cartography/bin/security-worker health
RUN python -m venv /opt/zasp/security/prowler && \
    /opt/zasp/security/prowler/bin/pip install --require-hashes --no-deps -r /src/security-python/build-requirements.lock && \
    /opt/zasp/security/prowler/bin/pip install --require-hashes --no-build-isolation --no-deps -r /src/security-python/prowler/requirements.lock && \
    /opt/zasp/security/prowler/bin/pip install --no-build-isolation --no-deps /src/security-python && \
    /opt/zasp/security/prowler/bin/python -c "from security_worker import prowler_aws; api = prowler_aws.load_runtime_api(); assert api.version == '5.39.1'; assert all(name in prowler_aws._CHECK_MODULES for name in prowler_aws.CHECKS)" && \
    /opt/zasp/security/prowler/bin/security-worker health

FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=build --chown=65532:65532 /out/agentsec-worker /out/zasp-healthcheck ./
COPY --from=security-python-build --chown=65532:65532 /opt/zasp/security /opt/zasp/security
USER 65532:65532
EXPOSE 8081
HEALTHCHECK --interval=10s --timeout=2s --start-period=10s --retries=3 CMD ["/app/zasp-healthcheck", "http://127.0.0.1:8081/healthz"]
ENTRYPOINT ["/app/agentsec-worker"]
