# Compliance connected-review preflight

Read-only source inspection by the controller. This is an open-finding record,
not verification of a fix or production availability. Task5 remains active.

## Provider failure versus integrity rejection

The deferred Task4 finding is confirmed in current source:

- `services/platform/apiserver/compliance_download.go` returns the same
  `ErrRepositoryUnavailable` for reader errors, cancelled contexts, incorrect
  immutable receipts, digest mismatches and invalid persisted envelopes.
- `services/platform/apiserver/compliance_http.go` calls the grant operation
  `integrity_failure` for every download-read error. SQL can consume the grant
  and record an integrity incident even when the cause is a provider outage.
- `services/platform/artifactstore/store.go`, `Store.Get`, also merges driver
  errors and returned-object validation failures into `ErrGet`.
- `services/platform/artifactstore/s3driver/driver.go`, `fetch`, merges provider
  Head/Get failures, body I/O errors, response pin mismatches and body validation
  failures into `ErrGet`. The distinction is already lost before HTTP handling.

The final fix must preserve safe internal categories through the actual reader
stack. A handler-only sentinel does not prove that storage-layer integrity
rejections still produce their required audit. Keep public errors generic and
never include raw provider diagnostics. No byte disclosure on either category.
Do not extend read leases, consume successfully, or permit retries that bypass
existing single-read authority.

Focused coverage needed: controlled provider failure, context cancellation,
successful provider response with wrong immutable version/metadata/checksum,
persisted-envelope rejection, and valid download. Assert the precise durable
audit/consume behavior as well as absence of attachment/private diagnostics.
The existing `TestComplianceHTTPDownloadNoDisclosureBeforeConsume` covers
denial but does not assert the distinction between provider and integrity audit
operations; its generic `error` case is insufficient evidence for this finding.

## Expected composition telemetry

Production composition writes both spans and operational telemetry to
`os.Stdout` in `services/platform/agentsec-api/production_runtime.go`.
Avoid global stdout replacement in potentially concurrent tests. If adding a
test writer seam, retain production defaults and keep it internal, with no
environment-selectable suppression. Capture routine fixture output and retain
it on failure. This remains lower priority than functional browser acceptance.

## Batched verification boundary

User explicitly requested feature-batched testing. Focused RED/GREEN remains
required for changed behavior. Group affected integration tests and independent
review at the connected feature boundary, then fresh UI tests/typecheck/lint/
build and release gates before any push. Reuse prior evidence only where its
source and dependency identities remain applicable. Keep each original task's
evidence mapping; batching does not change the 728-task scope or availability.

No source implementation, test execution, classification promotion, commit or
push is claimed by this preflight. Coordinate the final fix wave after Task5's
captured patch to preserve its before/after evidence chain.
