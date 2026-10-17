FROM golang:1.26.8-alpine3.23@sha256:a8fa79c5bd40d880b52bd3b6d7669ecdcfd00e85facdd427d279efb5ddd79cb1 AS build
WORKDIR /src
COPY services/gatewaypodidentity/ ./
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
RUN test "$(go env GOVERSION)" = go1.26.8 && \
    go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/gateway-reviewer-publisher ./cmd/gateway-reviewer-publisher

FROM scratch AS runtime
COPY --from=build /out/gateway-reviewer-publisher /gateway-reviewer-publisher
USER 65532:65532
ENTRYPOINT ["/gateway-reviewer-publisher"]
