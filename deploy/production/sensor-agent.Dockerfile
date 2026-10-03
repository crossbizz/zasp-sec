FROM golang:1.26.8-alpine3.23@sha256:a8fa79c5bd40d880b52bd3b6d7669ecdcfd00e85facdd427d279efb5ddd79cb1 AS build
ARG VERSION
WORKDIR /src
COPY services/health ./health
COPY services/platform ./platform
COPY services/sensor-agent ./sensor-agent
WORKDIR /src/sensor-agent
RUN go mod download && test -n "$VERSION" && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.buildVersion=$VERSION" -o /out/sensor-agent . && \
    cd /src/platform && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/zasp-healthcheck ./cmd/zasp-healthcheck

FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412 AS runtime
WORKDIR /app
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/sensor-agent /out/zasp-healthcheck ./
USER 65532:65532
EXPOSE 8081
HEALTHCHECK --interval=10s --timeout=2s --start-period=10s --retries=3 CMD ["/app/zasp-healthcheck", "http://127.0.0.1:8081/healthz"]
ENTRYPOINT ["/app/sensor-agent"]
