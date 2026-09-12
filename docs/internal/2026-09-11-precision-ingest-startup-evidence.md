# Production intake composition

The production event-ingest dependency factory now consumes
`ZASP_RUNTIME_INGEST_SCHEMA`. Empty or `runtime-event-v1` keeps historical
construction; `runtime-event-v2` selects the explicit precise PostgreSQL
repository and precise HTTP handler together. Other values reject configuration.
Deployment manifests are unchanged. This selection needs registered51 readiness
and the existing cloud readiness checks before startup succeeds.

The cached repository previously hid acceptance lookup and precision readiness
behind its narrower embedded interface. It now forwards acceptance lookup to the
underlying authority and forwards precision readiness without using the cache.
Missing capabilities, nil values and cancelled contexts fail closed. The actual
PostgreSQL repository still owns credential and request validation.

Superpowers tests first failed on the two erased capabilities and acceptance of
unknown configuration. Selector regression tests verify compiled51 checksum and
fingerprint arguments and HTTP503 for precision drift despite a healthy cache.
Temporarily restoring historical selectors reproduced wrong readiness SQL and
HTTP400 without a precision check. Both precise selectors were restored.

Full event-ingest race suite passed in1.284s; UI build and diff check passed.
Independent review found a blocking recovery defect. The tests exercise both selectors directly, not
`buildProductionIngestDependencies`; factory call sites were inspected but are
not protected by a composed startup test yet. Database-backed intake was separately verified in
`2026-09-11-precision-http-evidence.md`; these composition tests use declared
database/cloud boundaries and do not prove deployed TLS, S3 or a live producer.
No publication or original microtask credit.

P1, open: the factory still builds the historical ProductionIngestReconciler.
`validIngestReconciliationLease` accepts only runtime-event-v1, while SQL recovery
claim leases persisted V2 batches too. Go then rejects the claimed result before
artifact inspection, release or completion. Repeated claims consume attempts,
and a mixed claim discards its historical leases too. Do not activate or publish
this composition until explicit version-aware recovery, old-consumer isolation
and interrupted-upload/replay tests pass. The current green service tests do not
cover that failure. This finding is the next critical-path implementation task.
