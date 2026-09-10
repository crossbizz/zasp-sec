# Measure the API workload

`agentsecctl api-load` performs authenticated HTTPS reads against a deployment
you authorize. It has no mutation endpoints, discovery triggers, automatic
pagination or arbitrary queries. Use a read-only product token scoped to the
intended tenant, workspace and environment. Keep the token in an owned regular
file with mode 0600. The CA bundle must be an owned regular PEM file; symlinks
are rejected. The client verifies TLS hostnames, ignores HTTP proxy environment
variables and never follows redirects. There is no insecure-TLS flag.

Build with `go build -C cmd/agentsecctl .`; invoke the resulting
`cmd/agentsecctl/agentsecctl` binary or install it on PATH. Run `agentsecctl api-load help` for
the command forms. Lint reads only a scenario from stdin, with no network calls:

```sh
agentsecctl api-load lint < scenario.json
agentsecctl api-load run --endpoint https://product.example.com \
  --credential-file /secure/read-only-product-token \
  --ca-bundle-file /secure/product-ca.pem \
  < scenario.json > measurement.json
agentsecctl api-load evaluate < measurement.json > gate.json
```

Use an access-controlled output directory. The measurement contains timing,
status, fixed outcome codes and declared source/profile identifiers. It excludes
credentials, hostnames, response bodies, tenant identifiers and raw errors.
Invalid input emits no report. A completed measured run emits its measurement
even when its gate fails; evaluation emits the failed gate with a nonzero exit.
Preserve both files when diagnosing a failure. SIGINT/SIGTERM cancel active
requests, wait for their completion and record unsent requests as cancelled.

The closed scenario has these required fields:

| Field | Accepted value |
| --- | --- |
| `version` | `bounded-api-read-v1` |
| `profile` | Short release identifier, using the CLI's identifier validation |
| `profile_sha256` | Lowercase SHA-256 of the exact retained deployment-profile file |
| `deployment_kind` | `local` or `reference`, declared by the operator |
| `release_sha` | Lowercase 40-character source commit SHA |
| `duration_seconds` | Offered-load window, 1 through 300 seconds |
| `requests_per_second` | 1 through 100, with at least 20 total planned requests |
| `concurrency` | Maximum 1 through 16 active requests |
| `request_timeout_ms` | 100 through 30,000 milliseconds |

Keep the profile file with the measurement. It must describe the actual release
images/source state, topology, hardware, database settings, tenant/data sizes,
background workers and reference-concurrency choice. A local working-tree run
must record that source state; its commit SHA identifies the base, not a claim
that uncommitted code was released. Never use a local profile as reference proof.
The CLI validates digest syntax but does not attest the file, target or deployment.
Every report explicitly says `operator-declared-unattested`. A passed local
measurement is not production-readiness certification or release acceptance.

The versioned scenario rotates equally through four first-page reads:
`/api/v1/agents?limit=50`, `/api/v1/findings?limit=50`,
`/api/v1/integrations?limit=50` and `/api/v1/tools?limit=50`.
Requests have no application retries. Success requires HTTP 200, JSON,
`Cache-Control: no-store`, a bounded items array, canonical route-specific record
identity/type fields and valid pagination metadata. This is minimum record
validation, not a replacement for the complete OpenAPI response contract tests.
Each response body is limited to 1 MiB and discarded after validation.

Pacing is open-loop. There is no catch-up burst or pending-request queue.
Saturated concurrency and missed scheduling intervals remain explicit samples
and fail the gate. This prevents a slow client from reporting a deceptively fast
small subset of the workload. The offer window may be followed by bounded drain,
but the entire measured run must remain within 300 seconds. Choose a window
that leaves room for the request timeout. Late drain can fail the run.

Evaluation uses nearest-rank p50/p95/p99 over attempted requests, including HTTP,
transport and response-validation failures. Capacity, scheduling and unsent
cancellation samples have no fabricated latency; their counts remain visible.
The gate requires at least 20 attempts and five for each endpoint, p95 at most
750 ms, an error rate at most one percent, and no capacity/scheduling/cancellation
omissions or interruption. Every planned request must appear once, in order.

The existing composed browser harness runs 100 actual API reads through its
owned TLS ingress and evaluates the resulting artifact. That is local functional
integration evidence, with the harness's provider and dataset limitations.
Concurrent post-retirement loading, representative reference data/topology,
profile attestation and retained release evidence still need their own proof.
