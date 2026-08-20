FROM golang:1.25.6-alpine3.22@sha256:fa3380ab0d73b706e6b07d2a306a4dc68f20bfc1437a6a6c47c8f88fe4af6f75 AS build
ARG VERSION
WORKDIR /src
COPY services/platform/go.mod services/platform/go.sum ./
RUN go mod download
COPY services/platform ./
RUN test -n "$VERSION" && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.buildVersion=$VERSION" -o /out/agentsec-worker ./agentsec-worker && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/zasp-healthcheck ./cmd/zasp-healthcheck

FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412 AS runtime
WORKDIR /app
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/agentsec-worker /out/zasp-healthcheck ./
USER 65532:65532
EXPOSE 8081
HEALTHCHECK --interval=10s --timeout=2s --start-period=10s --retries=3 CMD ["/app/zasp-healthcheck", "http://127.0.0.1:8081/healthz"]
ENTRYPOINT ["/app/agentsec-worker"]
