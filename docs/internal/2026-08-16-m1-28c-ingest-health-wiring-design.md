# M1-28c Event-Ingest Health Wiring Design

## Goal and boundary

M1-28c wires the M1-28a shared health handler into the existing
`services/event-ingest` command. The command becomes a real long-running
internal HTTP process whose smoke test distinguishes liveness from readiness
and proves the exact `/healthz`, `/readyz`, `/version`, and `/metrics` contract.

This task does not add an ingest endpoint, queue consumer, SQS call, event
normalization, batching, persistence, provider or credential access, public
ingress, deployment manifest, or OpenAPI operation. M1-28d remains Pending.
M0-09, M0-18, and M0-19 remain Blocked.

## Selected architecture

Add an event-ingest-local bounded server lifecycle in the existing standalone
module. It consumes the exact shared handler from
`github.com/zasp-ai/zasp-sec/services/health` through the canonical local edge:

```go
require github.com/zasp-ai/zasp-sec/services/health v0.0.0

replace github.com/zasp-ai/zasp-sec/services/health => ../health
```

The dependency validator expands its repository-owned health-module allowlist
from the exact platform consumer to the exact platform and event-ingest
consumers. Both require the direct `v0.0.0` edge, exact canonical replacement,
and exact target module. Indirect, alternate-consumer, wrong-version, wrong-
target, remote, missing, duplicate, or extra replacements fail closed and the
internal edge remains outside the third-party license lock.

The lifecycle remains local because the reviewed M1-28b runtime lives inside
the platform module. Importing that module would invert the service boundary,
pull unrelated platform requirements into event-ingest, and require main-module
replacements for transitive local modules because dependency replacements do
not propagate. A later dedicated refactor may extract a standalone lifecycle
module; M1-28c does not broaden into that migration.

## Runtime contract

The event-ingest runtime uses the same exact reviewed bounds as the platform
commands: two-second read-header/read/write timeouts, thirty-second idle
timeout, 4 KiB maximum request headers, and independent five-second graceful
shutdown. It uses only its constructed handler, never `http.DefaultServeMux`,
and is single-use.

Before serving, liveness is 200 and readiness is 503 through the constructed
handler. Immediately before `http.Server.Serve`, readiness becomes true. On
cancellation it becomes false before an independently bounded shutdown starts;
shutdown is joined before return and its failure wins. Nil, typed-nil, canceled,
corrupted, repeated, and panicking runtime boundaries fail deterministically
without exposing internal data.

## Command wiring

The command preserves the exact `event-ingest build <version>` line and its
existing version grammar. Production binds one dedicated internal `:8081`
listener through an injectable function and uses a `SIGINT`/`SIGTERM` context.
Construction and cancellation checks occur before listen/output. Every
post-listen failure closes the retained listener; panics are contained behind
the fixed runtime category. Production prints no internal error.

The same port as the platform commands is intentional because these commands
run in separate process/container network namespaces. Deployment tasks own
Services, network policy, and probe declarations.

## Verification

Behavior-first tests use only injected or owned numeric-loopback listeners.
They prove the liveness/readiness distinction before serving, all four exact
routes while serving, readiness withdrawal before shutdown, the preserved
build line, exact server bounds, independent deadline, single-use and malformed
state fencing, default-mux isolation, listener cleanup and panic containment,
and bounded smoke-test handoff.

Completion requires six fresh race passes, 100% statement coverage for the new
lifecycle, the full event-ingest module, module gates, linked real-listener
smoke, dependency validation, full pinned repository gates, audit, scans,
zero-finding independent review, exact-SHA CI, and clean synchronization.

M1-28c starts at `665/1/59/3` overall and `68/32/1/35/0` for M1. Completion
changes those values to `665/0/60/3` and `68/32/0/36/0`. M1-28d remains Pending.
