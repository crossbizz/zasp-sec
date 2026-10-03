FROM golang:1.26.8-alpine3.23@sha256:a8fa79c5bd40d880b52bd3b6d7669ecdcfd00e85facdd427d279efb5ddd79cb1 AS build
ARG VERSION
WORKDIR /src/platform
COPY services/health /src/health
COPY services/platform/go.mod services/platform/go.sum ./
RUN go mod download
COPY services/platform ./
RUN test -n "$VERSION" && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/agentsec-attack-lab-runner ./attack-lab-runner

FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412 AS runtime
WORKDIR /app
COPY --from=build --chown=65532:65532 /out/agentsec-attack-lab-runner ./
USER 65532:65532
ENTRYPOINT ["/app/agentsec-attack-lab-runner"]
