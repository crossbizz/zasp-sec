# M1-28 Service Health Endpoints Design

## Goal and boundary

M1-28 registers the common M1-28a health contract after platform,
event-ingest, and runtime-gateway wiring is complete. It documents the exact
root-level internal process endpoints in OpenAPI and one internal service
matrix, then makes a root gate prove that every Go command retains the same
semantics.

This task adds no handler, listener, product API route, gateway, proxy, MCP or
tool operation, OPA evaluation, authentication, provider access, public
ingress, deployment manifest, or aggregation model. M1-29 remains Pending.
M0-09, M0-18, and M0-19 remain Blocked.

## Selected architecture

Add a separate self-contained OpenAPI 3.1 document at
`openapi/internal-health.yaml`. The existing `openapi/openapi.yaml` remains the
public product API and generated-client input. Health probes are root-level
process endpoints rather than `/api/v1` product operations or `/internal/v1`
data-plane operations, so putting them in the product root would misclassify
the transport, change the generated client, and violate the existing UI/API
coverage namespace boundary.

The internal document has no server URL, global product bearer requirement,
example payload, customer data, provider name, callback, or webhook. It
defines exactly `/healthz`, `/readyz`, `/version`, and `/metrics`, each with GET
and HEAD operations. `security: []` records that the handler itself performs
no authentication; deployment network policy and probe reachability remain
with M1-30.

## Exact HTTP contract

All four paths reject query strings, raw escaped paths, trailing aliases, and
unknown paths with 404 and an empty body. Methods other than GET and HEAD
return 405, `Allow: GET, HEAD`, and an empty body. Every response has
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and an exact
decimal `Content-Length`. HEAD returns the GET status and representation
length without a body.

- `/healthz` is always 200 with exactly `{"status":"live"}` plus one newline.
- `/readyz` is 503/not-ready outside the serving lifetime and 200/ready only
  while serving; shutdown withdraws readiness before bounded cleanup.
- `/version` is 200 with the exact validated service and build version.
- `/metrics` is 200 Prometheus 0.0.4 text containing only the bounded
  `agentsec_up`, `agentsec_ready`, and `agentsec_build_info` gauges.

The version schema accepts only the reviewed handler grammar. The service
catalog is closed to `agentsec-api`, `agentsec-worker`, `event-ingest`, and
`runtime-gateway`.

## Internal service matrix

Add `docs/internal/service-health-endpoints.md` with exactly four command rows:
platform API, platform worker, event ingest, and runtime gateway. Every row
binds its module/command, service label, fixed internal `:8081` listener, the
four paths, and the same lifecycle semantics. The document states that equal
ports are safe because the commands run in separate process/container network
namespaces and that M1-30 owns deployment Services, probes, and network policy.

## Verification and integration

Add a strict duplicate-key-safe Node test for the complete internal OpenAPI
shape and service matrix. Hostile mutations cover path/method drift, product
auth, remote references, extra schema fields, readiness collapse, service
catalog drift, missing response headers, and matrix duplication or omission.

Add a root `health:contract:test` command that runs the strict OpenAPI/service
test and the reviewed race suites for `services/health`, both platform
commands, event-ingest, and runtime-gateway. Root verification invokes that
gate. The pinned Redocly command lints both OpenAPI documents, while generation
and UI/API coverage continue to consume only the public product root.

Completion requires focused RED/GREEN, six root health-contract passes,
Redocly and generated-client regressions, full pinned repository verification,
audits/scans, zero-finding independent review, push, and exact-SHA Runnable UI
success.

M1-28 starts at `663/1/61/3` overall and `68/30/1/37/0` for M1. Completion
changes those values to `663/0/62/3` and `68/30/0/38/0`. M1-29 remains Pending.
