# M1-28a Shared Health Handler Design

## Goal and boundary

M1-28a creates one dependency-free Go HTTP handler package shared by the
platform API, platform worker, event-ingest, and runtime-gateway commands. The
package defines exact process liveness, service readiness, build version, and
Prometheus-text metrics responses without opening a listener or contacting a
dependency.

The module lives at `services/health` with import path
`github.com/zasp-ai/zasp-sec/services/health`. M1-28b through M1-28d own wiring
the handler into commands; M1-28 owns the later documented common endpoint
contract. M1-28b remains Pending. M0-09, M0-18, and M0-19 remain Blocked.

## Considered approaches

1. **Standalone shared module (selected).** Each service module can consume the
   same small package through an explicit local module requirement when its
   wiring task begins. This keeps health semantics independent of the larger
   platform module and avoids duplicate implementations.
2. **Package under `services/platform`.** This is simpler for the two platform
   commands but makes event-ingest and runtime-gateway depend on the full
   platform module boundary.
3. **One package per service module.** This avoids cross-module requirements but
   is not shared and invites response, readiness, and metric drift.

The standalone module is the smallest boundary that satisfies all four later
wiring tasks without adding a workspace file, third-party dependency, or
listener.

## Public API

The package exports these exact paths:

```go
const (
    LivenessPath = "/healthz"
    ReadinessPath = "/readyz"
    VersionPath = "/version"
    MetricsPath = "/metrics"
)
```

Construction returns a concrete `*Handler` implementing `http.Handler`:

```go
type Config struct {
    Service string
    Version string
}

var ErrInvalidConfig = errors.New("invalid health handler configuration")

func New(config Config) (*Handler, error)
func (handler *Handler) SetReady(ready bool)
func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request)
```

`Service` is 1-64 lowercase ASCII characters in nonempty alphanumeric segments
separated by single hyphens. `Version` uses the existing service-build grammar:
1-64 ASCII alphanumeric characters plus internal `.`, `_`, `+`, and `-`, with
an alphanumeric first character. Invalid configuration returns only
`ErrInvalidConfig` and no handler.

Every new handler starts not ready. `SetReady` uses an atomic boolean, so
startup/shutdown code may change readiness while probes run without a mutex,
callback, goroutine, dependency call, or race. Liveness is independent and
always reports the in-process handler as live.

## Exact HTTP behavior

Only `GET` and `HEAD` with an empty query are accepted. `HEAD` returns the same
status and headers as `GET` with no response body. Other methods return 405 with
`Allow: GET, HEAD`; unknown paths and nonempty queries return 404. Rejections
have an empty body.

JSON endpoints use `application/json; charset=utf-8`; metrics uses
`text/plain; version=0.0.4; charset=utf-8`. Every response sets
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and an exact
`Content-Length`.

The exact GET responses are:

| Path | Ready state | Status | Body |
| --- | --- | ---: | --- |
| `/healthz` | either | 200 | `{"status":"live"}\n` |
| `/readyz` | true | 200 | `{"status":"ready"}\n` |
| `/readyz` | false | 503 | `{"status":"not_ready"}\n` |
| `/version` | either | 200 | `{"service":"<service>","version":"<version>"}\n` |
| `/metrics` | either | 200 | exact bounded Prometheus text below |

Metrics contain only three bounded gauges: `agentsec_up{service=...} 1`,
`agentsec_ready{service=...} 0|1`, and
`agentsec_build_info{service=...,version=...} 1`, each with one fixed HELP and
TYPE declaration. There are no timestamps, request paths, customer identifiers,
dependency errors, arbitrary labels, or runtime/provider values.

```text
# HELP agentsec_up Process liveness.
# TYPE agentsec_up gauge
agentsec_up{service="<service>"} 1
# HELP agentsec_ready Service readiness.
# TYPE agentsec_ready gauge
agentsec_ready{service="<service>"} <0-or-1>
# HELP agentsec_build_info Build information.
# TYPE agentsec_build_info gauge
agentsec_build_info{service="<service>",version="<version>"} 1
```

## Failure and security behavior

The package performs no file, environment, provider, credential, database,
Docker, subprocess, or network operation and does not register on the global
default mux. Construction validates every value before retaining it. Exact
ASCII grammars prevent JSON, header, or Prometheus-label injection. Readiness
is local state rather than a blocking callback, so probe handling cannot hang
on an uncooperative dependency and remains race-safe.

The package does not authorize exposure of these internal service endpoints.
Later wiring and deployment tasks own listener addresses, network policies,
timeouts, graceful shutdown, and dependency-specific readiness changes.

## Verification and completion

Tests use `httptest.ResponseRecorder` and prove:

- liveness remains 200 while readiness changes from 503 to 200 and back;
- version and metrics return exact bytes and bounded labels;
- concurrent `SetReady` and probe requests are race-free;
- GET/HEAD status, headers, lengths, and bodies are exact;
- invalid service/version values, unknown paths, query strings, and methods fail
  closed; and
- construction and request handling perform no external I/O.

The root command will be `npm run health:test`, executing the standalone module
with the race detector. Completion requires a witnessed missing-package RED,
six focused race passes, module tidy-diff/verify/vet, all service-module and
repository gates, zero production audit findings, redacted secret scans,
whole-range zero-finding review, exact-SHA Runnable UI success, and a clean
synchronized branch. Final source-plan arithmetic is `667/0/58/3` overall and
`68/34/0/34/0` for M1.
