# Precise projection worker checkpoint

Explicit projection V3 execution consumes correlation V4 receipts, requires the
bound predecessor digest and selects index V2 for archive reads. It uses the
precise projector and receipt codec. Historical V1/V2 jobs retain their own
decoders, algorithms, receipt bytes and effect ordering through immutable
per-version configuration copies.

V3 execution is authorized-only. Worker identity, token, lease freshness,
stored receipt locator/version/checksum, scope, batch, generation and effect
digest are checked before downstream effects. Cancellation and renewed lease
windows retain the existing checks. V3 receipt serialization is validated before
graph writes; receipt storage follows graph success.

Superpowers evidence:

- New tests failed with unavailable V3 construction before implementation.
- The local chain runs the V4 correlation executor, reads its actual encoded
  receipt through the declared artifact adapter, executes V3 projection and
  decodes its precise receipt. Strong agent/session/source/sandbox bindings are
  asserted explicitly.
- Tests reject missing capabilities and old-worker execution before I/O, preserve
  historical receipt bytes and check cancellation at graph/receipt boundaries.
  A declared renewed window permits execution when the original window expired.
- A valid1000-result V4 receipt with an escaped archive version produces an
  oversized projection receipt. Moving validation after graph application made
  the regression fail with graphcalls1/receiptcalls0. Restoring preflight yields
  malformed rejection with zero writes. The fixture separately proves all1000
  projected items are valid before the write-boundary assertion.
- Final expanded worker race command `go test -C services/platform -race -count=1
  ./agentsec-worker -run '^TestPrecise|^TestSandboxProjectionWorker|^TestRuntimeProjection|^TestSandboxCorrelation|^TestFrozenCorrelation'`
  exited0 in6.656s. UI build and diff checks passed. Independent review closed
  the test gap with no remaining findings.

These checks use declared database, graph and storage providers. They do not
prove live projection persistence or deployed workers. Completion V3, actual
archive/index V2 workers, production configuration, claiming and migration
readiness remain open. No push or original microtask credit.
