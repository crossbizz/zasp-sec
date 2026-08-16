# Internal Service Health Endpoints

The four Go commands expose one process-local health contract on a dedicated
listener. The equal ports are intentional because each command runs in its own
process or container network namespace.

| Command | Module | Service label | Listener | Paths |
| --- | --- | --- | --- | --- |
| Platform API | `services/platform/agentsec-api` | `agentsec-api` | internal `:8081` | `/healthz`, `/readyz`, `/version`, `/metrics` |
| Platform worker | `services/platform/agentsec-worker` | `agentsec-worker` | internal `:8081` | `/healthz`, `/readyz`, `/version`, `/metrics` |
| Event ingest | `services/event-ingest` | `event-ingest` | internal `:8081` | `/healthz`, `/readyz`, `/version`, `/metrics` |
| Runtime gateway | `services/runtime-gateway` | `runtime-gateway` | internal `:8081` | `/healthz`, `/readyz`, `/version`, `/metrics` |

## Common semantics

GET returns the exact representation; HEAD returns the same status and
representation length with no body. Liveness remains 200 independently of
readiness. Readiness is 503 outside the serving lifetime and 200 only while
serving. Shutdown withdraws readiness before the independently bounded
five-second cleanup.

Unknown paths and any query string are 404 with an empty body. Methods other
than GET and HEAD are 405 with `Allow: GET, HEAD` and an empty body. Every
response disables caching and media-type sniffing and declares the exact GET
representation length.

No endpoint is part of the public product API or the `/internal/v1` data plane.
The handlers perform no authentication, provider access, configuration load,
or dependency I/O. M1-30 owns deployment Services, health probes, reachability,
and network policy. M1-29 remains Pending.
