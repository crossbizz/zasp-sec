# Observability, correlation and canaries

API requests emit one JSON line with timestamp, severity, normalized route class, method, status, duration, correlation ID, trace ID and span ID. Logs omit query strings, bodies, authorization, cookies and raw resource/tenant IDs. The API accepts only valid W3C `traceparent` input from the trusted edge and returns both `Traceparent` and `X-Correlation-ID`.

Private `/metrics` exposes process readiness/build data and bounded request, duration, rate-limit, authentication and dependency counters. The Prometheus rules page on sustained readiness loss or a 5xx rate above 1%, and ticket API read p95 above 500 ms or mutation p95 above 1 second. The web user-flow budget is p95 below 2 seconds.

To investigate a user-visible failure, collect the correlation ID from the response or error envelope, search structured logs for the exact `correlation_id`, pivot to the returned trace ID, then inspect edge → web/API → repository/queue/provider spans. Access is operator-only and searches must remain within the incident window and customer scope. Do not request credentials or response bodies from the user.

`production-readonly-canary` runs every five minutes, forbids overlap, and has a 60-second deadline. It checks the public sign-in page plus its six security-header families, then performs a read-only authenticated home-summary request and requires correlation and trace headers. Its PAT is a least-privilege secret-manager value; rotate it like any production credential. A canary never mutates product data.
