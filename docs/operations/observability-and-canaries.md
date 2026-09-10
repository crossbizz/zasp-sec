# Observability, correlation and canaries

API requests emit one JSON line with timestamp, severity, normalized route class, method, status, duration, correlation ID, trace ID and span ID. Logs omit query strings, bodies, authorization, cookies and raw resource/tenant IDs. The API accepts only valid W3C `traceparent` input from the trusted edge and returns both `Traceparent` and `X-Correlation-ID`.

The edge rejects requests unless host, origin and TLS forwarding metadata are exact and the immediate peer is in the configured trusted-proxy CIDRs. Per-client limiting uses the verified forwarding chain, not a client-supplied leftmost address; direct unit-test operation falls back to the socket address. Every accepted request receives an explicit deadline of at most 30 seconds, and the same context is propagated through repository and provider calls.

Private `/metrics` exposes process readiness/build data, a bounded detailed API request histogram, request/rate-limit/authentication/dependency counters, and live PostgreSQL pool gauges. Detailed labels use a fixed method set plus `OTHER`, allowlisted routes, bounded status classes and an overflow cap. Independent fixed-cardinality `zasp_http_slo_requests_total` and `zasp_http_slo_request_duration_seconds` series preserve status plus read/mutation latency semantics even after detailed-series overflow. Separate ServiceMonitors scrape API, discovery, projections, gateway control, event ingest, and every runtime worker on port 8081. Prometheus pages when a required Deployment is absent or unavailable, and it tickets failed worker dependency readiness or an HPA held at its maximum. Queue age and projection-lag paging remains an external release gate until each source exports bounded durable lag metrics; capacity is not a substitute for lag.

## Reconciliation maintenance

The API samples PostgreSQL catalog statistics for two fixed tables:
`public.zasp_connector_effects` and `public.zasp_connector_effect_lane_scopes`.
It samples serially every 15 seconds with a two-second query deadline. Scrapes
read the cached result, not the database. After a failed sample, at startup, or
after 45 seconds without a fresh sample, `zasp_reconciliation_maintenance_sample_valid`
is zero and table gauges disappear. Unavailable data never becomes healthy zeros.
The sampler stops with the API lifecycle and doesn't control readiness or issue
VACUUM, terminate sessions, change table settings or add database grants.

Valid samples expose `dead_tuples`, `live_tuples`, `autovacuum_enabled` and
`last_autovacuum_seconds`, all prefixed with `zasp_reconciliation_maintenance_`.
The only table labels are the two fixed names above. Row counts are estimates.
Ordinary autovacuum must be enabled globally and for the table; this does not
guarantee worker capacity, scheduling or successful reclamation. A null vacuum
timestamp is rendered as zero, meaning no recorded vacuum, not completed cleanup.
Statistics reset or lag, a zero estimate and a recent vacuum timestamp never prove
the raw scan or reference-load gate passed. PostgreSQL documents these limits in
its [statistics guide](https://www.postgresql.org/docs/18/monitoring-stats.html).

Three operator tickets distinguish the cases:

- `ZaspReconciliationMaintenanceUnavailable`: invalid/stale samples, missing
  sampler series, failed scrape targets or all API targets absent for one minute.
- Dead-tuple estimates at or above 10,000 for two minutes trigger
  `ZaspReconciliationMaintenanceDebt`, even when the vacuum timestamp advances.
- `ZaspReconciliationAutovacuumDisabled` fires after one minute with ordinary
  autovacuum disabled. The thresholds are diagnostic warnings, not a cleanup SLA.

On a ticket, first check the private scrape target and sampler validity. If data
is unavailable, inspect the API's bounded repository failure counters, database
connectivity and `track_counts`; don't infer zero debt. If debt persists, an
authorized database operator should inspect `pg_stat_all_tables`, effective
autovacuum settings and `pg_stat_progress_vacuum` for these exact tables. Look for
long-running transactions, old snapshot horizons, replication-slot retention,
worker saturation and provider maintenance limits. Broader session statistics
may require operator privileges; never grant them to the product API to make a
dashboard green. Keep query text, customer rows, credentials and principal names
out of exported metrics and incident attachments.

If cleanup is held back by an application transaction, coordinate its safe
completion with its owner. Recheck estimates and actual query work afterward.
Don't automatically terminate a session, drop a slot or run `VACUUM FULL`.
Escalate unresolved debt or API latency/error-budget violations to the database
operator with timestamps, fixed table names and bounded aggregate evidence.
Any maintenance intervention needs the deployment's change procedure. Keep the
incident open until the measured operation recovers; advancing vacuum counters
alone aren't recovery evidence. The original concurrent API/reference-load gate
and immediate post-retirement raw-scan concern remain separate.

The customer-edge release adds a private `sensor-agent` ServiceMonitor. It
pages when adapter readiness disappears or reports zero and when either the
`sensor-agent` or `zasp-tetragon` DaemonSet has unavailable nodes. The SaaS
sensor detail remains the source for cluster heartbeat sequence, capabilities,
kernel/BTF state, event rate, and drops. A green Kubernetes DaemonSet alone
doesn't prove that heartbeat or event ingest reached the SaaS.

Request, PostgreSQL repository and provider boundaries emit API-local correlation records as JSON event `correlation_span`; workers emit structured lifecycle and mutation audit outcomes for scheduler, outbox, discovery, and projection processing. These records reuse validated identifiers for log correlation, but they are not OpenTelemetry spans and do not provide end-to-end distributed tracing. The log pipeline must collect them without raw credentials, provider payloads, lease tokens, or tenant identifiers. Real end-to-end OpenTelemetry SDK/export and distributed tracing remains an external release gate.

## Collector

The hosted chart always renders one private OpenTelemetry Collector. In `none` mode it accepts OTLP only from product pods, clears untrusted schema and scope metadata, drops link-bearing spans, allowlists metric names, blanks untrusted log bodies plus span/event names and status messages, removes unapproved attributes, applies the memory limiter and batch processor, then sends to `nop` with no remote credential or egress. Grafana and New Relic modes use one Secret-backed authorization header and an exact remote CIDR list. Each remote exporter has a 256-request in-memory queue, two consumers, nonblocking overflow, a five-second send timeout, and a 60-second retry ceiling. `ZaspOTelCollectorQueueLoss` pages as soon as an enqueue failure appears in the five-minute window. `ZaspOTelCollectorQueueMetricMissing` pages only after the exact remote queue-capacity metric has stayed absent for ten minutes. The Collector does not make API-local `correlation_span` records into OTLP spans; application SDK export remains a separate release gate.

To investigate a user-visible failure, collect the correlation ID from the response or error envelope, search structured logs for the exact `correlation_id`, pivot to the returned trace ID, then inspect the API-local request and repository/provider correlation records. Access is operator-only and searches must remain within the incident window and customer scope. Do not request credentials or response bodies from the user.

`production-readonly-canary` runs every five minutes, forbids overlap, and has a 60-second deadline. It checks the public sign-in page plus its six security-header families, then performs a read-only authenticated home-summary request and requires correlation and trace headers. Its PAT is a least-privilege secret-manager value; rotate it like any production credential. A canary never mutates product data.
