# Precise projection checkpoint

`ProjectPrecise` consumes V2 archives with V4 correlations bound by its caller
to an authenticated predecessor receipt. It preserves displayed millisecond
timestamps, evidence references and source-qualified sandbox identity. The
archive digest retains exact source-time evidence. Kernel Exact confidence is
rejected, including a supplied result with otherwise valid identity fields.

Projection consumes display fields from the validated precise decoder. It does
not use lineage for attribution or run a precise archive through the legacy
decoder. New risk-v3 and projection-batch-v3 digest domains separate these
effects from prior projections. Legacy Project/ProjectSandbox behavior and
historical receipt vectors remain unchanged.

Superpowers verification:

- Rejecting stubs failed valid precise/unknown-sandbox/ambiguous scenarios before
  implementation. Invalid scenarios include Exact confidence, residual ambiguous
  identity, missing sandbox source, foreign event/scope, digest drift and duplicate
  correlations.
- Tests preserve content and replay, reject cross-version archives, and require
  a1ns source-time change to change risk identity/digest even when display time
  stays the same. Classification and identity expectations use explicit values.
- `go test -C services/platform -race -count=1 ./runtimeprojection ./runtimecorrelation
  ./runtimeevent` exited0 in1.510s/1.674s/5.147s, including historical vectors.
- With PostgreSQL18 on PATH, `go test -C services/platform -race -count=1 ./apiserver
  -run '^TestRuntimePrecisionFreeze|^TestRuntimeCandidateAuthorityFreezesReplayAfterLateAdmission$'`
  exited0 in13.972s. Actual frozen snapshots flow through the repository,
  correlator, receipt codec and projector. Identity/confidence remain bound;
  replay after late admission retains identical projection item and digest.
- UI build and diff checks passed. Independent review found no projector issues.

The PostgreSQL fixtures are owner-seeded and use a test-only execution grant.
This is not HTTP admission, live worker execution, projection persistence or UI
acceptance. Projection receipt V3 and worker/downstream integration remain open,
as do production startup, claiming and migration readiness. No push or original
microtask credit.
