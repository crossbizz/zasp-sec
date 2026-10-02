FROM golang:1.25.13-alpine3.23@sha256:42fc3368d1c50170a452f2bf4a1dfd292a065870c3f258d799aad4316671cb69 AS build
ARG VERSION
WORKDIR /src
COPY services/health ./health
COPY services/platform ./platform
COPY services/runtime-gateway ./runtime-gateway
WORKDIR /src/runtime-gateway
RUN go mod download && test -n "$VERSION" && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.buildVersion=$VERSION" -o /out/runtime-gateway . && \
    cd /src/platform && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/zasp-healthcheck ./cmd/zasp-healthcheck

FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412 AS runtime
WORKDIR /app
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/runtime-gateway /out/zasp-healthcheck ./
USER 65532:65532
EXPOSE 8080 8081
HEALTHCHECK --interval=10s --timeout=2s --start-period=10s --retries=3 CMD ["/app/zasp-healthcheck", "http://127.0.0.1:8081/healthz"]
ENTRYPOINT ["/app/runtime-gateway"]
