# M1-28d Runtime-Gateway Health Wiring Design

## Goal and boundary

M1-28d wires the M1-28a shared health handler into the existing
`services/runtime-gateway` command. The command becomes a real long-running
internal HTTP process whose smoke test distinguishes liveness from readiness
and proves the exact `/healthz`, `/readyz`, `/version`, and `/metrics` contract.

This task does not add a gateway, proxy, MCP server, tool or API forwarding,
OPA evaluation, request authentication, configuration loading, credential or
provider access, public ingress, deployment manifest, or OpenAPI operation.
M1-28 remains Pending. M0-09, M0-18, and M0-19 remain Blocked.

## Selected architecture

Add a runtime-gateway-local bounded server lifecycle in the existing standalone
module. It consumes the exact shared handler from
`github.com/zasp-ai/zasp-sec/services/health` (`services/health`) through the
canonical local edge:

```go
require github.com/zasp-ai/zasp-sec/services/health v0.0.0

replace github.com/zasp-ai/zasp-sec/services/health => ../health
```

The dependency validator expands its repository-owned health-module allowlist
from the exact platform and event-ingest consumers to the exact platform,
event-ingest, and runtime-gateway consumers. All require the direct `v0.0.0`
edge, exact canonical replacement, and exact target module. Indirect,
alternate-consumer, wrong-version, wrong-target, remote, missing, duplicate, or
extra replacements fail closed and the internal edge remains outside the
third-party license lock.

The lifecycle remains local because the reviewed M1-28b runtime lives inside
the platform module. Importing that module would invert the service boundary,
pull unrelated platform requirements into runtime-gateway, and require
main-module replacements for transitive local modules because dependency
replacements do not propagate. M1-28 later registers the common endpoint
contract; it does not need a lifecycle extraction to prove consistent behavior.

## Runtime contract

The runtime-gateway uses the same exact reviewed bounds as the platform and
event-ingest commands: two-second read-header/read/write timeouts, thirty-second
idle timeout, 4 KiB maximum request headers, and independent five-second
graceful shutdown. It uses only its constructed handler, never
`http.DefaultServeMux`, and is single-use.

Before serving, liveness is 200 and readiness is 503 through the constructed
handler. Immediately before `http.Server.Serve`, readiness becomes true. On
cancellation it becomes false before independently bounded shutdown starts;
shutdown is joined before return and its failure wins. Nil, typed-nil,
canceled, corrupted, repeated, and panicking runtime boundaries fail
deterministically without exposing internal data. A recovered shutdown panic
force-releases the retained listener through a panic-contained close boundary
before the serving path is joined.

## Command wiring

The command preserves the exact `runtime-gateway build <version>` line and its
existing version grammar. Production binds one dedicated internal `:8081`
listener through an injectable function and uses a `SIGINT`/`SIGTERM` context.
Construction and cancellation checks occur before listen/output. Every
post-listen failure closes the retained listener; panics are contained behind
the fixed runtime category. Production prints no internal error.

The same port as the other commands is intentional because these processes run
in separate process/container network namespaces. Deployment tasks own
Services, network policy, and probe declarations.

## Verification

Behavior-first tests use only injected or owned numeric-loopback listeners.
They prove the liveness/readiness distinction before serving, all four exact
routes while serving, readiness withdrawal before shutdown, the preserved
build line, exact server bounds, independent deadline, single-use and malformed
state fencing, default-mux isolation, listener cleanup and panic containment,
and bounded smoke-test handoff.

Completion requires six fresh race passes, 100% statement coverage for the new
lifecycle, the full runtime-gateway module, module gates, linked real-listener
smoke, dependency validation, full pinned repository gates, audit, scans,
zero-finding independent review, exact-SHA CI, and clean synchronization.

M1-28d starts at `664/1/60/3` overall and `68/31/1/36/0` for M1. Completion
changes those values to `664/0/61/3` and `68/31/0/37/0`. M1-28 remains Pending.
