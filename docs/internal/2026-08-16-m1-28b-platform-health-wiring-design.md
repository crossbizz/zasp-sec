# M1-28b Platform Health Wiring Design

## Goal and boundary

M1-28b wires the M1-28a shared health handler into the existing
`agentsec-api` and `agentsec-worker` commands. Each command becomes a real,
long-running internal HTTP process that exposes the exact shared `/healthz`,
`/readyz`, `/version`, and `/metrics` contract on a dedicated health listener.

This task does not add product API routes, a worker queue loop, provider or
database calls, dependency-specific readiness checks, public ingress, OpenAPI
operations, or deployment manifests. M1-28c remains Pending. M0-09, M0-18,
and M0-19 remain Blocked.

## Selected architecture

Add one dependency-free platform-local package at
`services/platform/healthserver`. It owns the bounded `net/http.Server`
lifecycle while importing the shared handler from
`github.com/zasp-ai/zasp-sec/services/health`. Both commands depend on this
runtime instead of duplicating listener, timeout, readiness, and shutdown
behavior.

The platform module adds an explicit local-module requirement:

```go
require github.com/zasp-ai/zasp-sec/services/health v0.0.0

replace github.com/zasp-ai/zasp-sec/services/health => ../health
```

Dependency validation accepts this exact repository-owned `v0.0.0` requirement
only when the manifest contains the matching canonical `../health` replacement
and the target is already a required product manifest. It remains outside the
third-party license lock because the repository does not currently declare a
project license. Other local replacements, internal versions, or paths fail
closed. No third-party package or Go workspace is added.

Alternatives rejected:

1. Duplicating an `http.Server` in both `main` packages invites timeout,
   readiness, and shutdown drift.
2. Registering the handler on `http.DefaultServeMux` creates ambient global
   state and test interference.
3. Adding environment or flag configuration here broadens this microtask into
   deployment configuration. Later deployment tasks may make the address
   configurable without changing the server contract.
4. Testing handlers without a listener would repeat M1-28a and would not prove
   that both commands expose the endpoints.

## Runtime contract

`healthserver.New` validates the shared handler configuration before retaining
anything and returns a concrete runtime:

```go
type Config struct {
    Service string
    Version string
}

var (
    ErrInvalidConfig = errors.New("invalid health server configuration")
    ErrInvalidRuntime = errors.New("invalid health server runtime")
)

func New(config Config) (*Server, error)
func (server *Server) Serve(ctx context.Context, listener net.Listener) error
```

The HTTP server has exact finite settings: two-second read-header, read, and
write timeouts; a thirty-second idle timeout; 4 KiB maximum request headers;
and a five-second graceful-shutdown budget. It uses only the constructed
shared handler and never the global default mux.

`Serve` rejects nil contexts, nil listeners, and repeated/concurrent use before
serving. A canceled context before startup returns without advertising
readiness. Otherwise readiness becomes true only after the caller has acquired
the listener and immediately before `http.Server.Serve`; cancellation flips
readiness false before shutdown starts. The shutdown operation uses an
independent background timeout, is joined before return, and its failure takes
precedence over the normal `http.ErrServerClosed` result. Unexpected serve
errors are returned without internal or request data.

The runtime is single-use. It never opens a listener, reads process state,
logs, emits metrics beyond the shared handler, or contacts a dependency.

## Command wiring

Both production commands:

- retain the exact compile-time `buildVersion` grammar and exact existing
  `agentsec-<service> build <version>` output line;
- construct the health runtime before opening a listener;
- bind the dedicated internal address `:8081` through an injectable listen
  function;
- create a `signal.NotifyContext` for `SIGINT` and `SIGTERM`;
- close a listener on every post-listen failure;
- serve with the exact service name (`agentsec-api` or `agentsec-worker`); and
- exit nonzero without printing internal errors when construction, listening,
  output, serving, or shutdown fails.

Using the same port is intentional because the commands run in separate
process/container network namespaces. The later Kubernetes and Helm tasks own
Service exposure and probe declarations. No public route or host-network
authorization is implied.

## Verification

Tests are behavior-first and use only numeric loopback listeners or injected
fakes. They prove:

- both command runtimes expose all four exact endpoints over a real listener;
- readiness is 200 while running and becomes unavailable after cancellation;
- version and metrics contain the exact command service/version values;
- the exact build line is preserved;
- invalid configuration fails before listen/output;
- listen and output failures close or avoid the listener as appropriate;
- startup cancellation, serve failure, graceful shutdown, shutdown timeout,
  nil values, and repeated/concurrent use fail deterministically;
- readiness flips back before an in-flight request is drained;
- server settings are exact and no default-mux route is registered; and
- six fresh race runs, 100% platform healthserver statement coverage, both
  command builds, module gates, dependency validation, full repository gates,
  audit, scans, independent review, exact-SHA CI, and clean synchronization
  pass before completion.

M1-28b completion changes source-plan arithmetic to `666/0/59/3` overall and
`68/33/0/35/0` for M1. M1-28c remains Pending.
