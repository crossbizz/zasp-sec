# Precise correlation receipt checkpoint

The bounded change adds separate `EncodePreciseReceipt` and
`DecodePreciseReceipt` entry points for `runtime-correlation-v4` and
`runtime-correlation-receipt-v4`. Shared private codec helpers preserve
historical receipt bytes. The old entry points explicitly refuse V4, including
the old arbitrary-version V1 fallback.

V4 requires a nonzero snapshot digest, the V4 effect digest domain and valid
sandbox bindings. Exact confidence is rejected even with a recomputed digest.
Canonical decoding rejects aliases, duplicates, unknown fields and trailing
bytes. Both V4 encoding and decoding enforce a 1MiB serialized limit.

Superpowers TDD evidence from this session:

- Rejecting stubs failed the round-trip and valid historical-unknown/ambiguous
  result tests before implementation (exit1).
- Independent review found an encoder/decoder size mismatch. A valid1000-result
  fixture with HTML-escaped sandbox text reproduced an1810857-byte receipt that
  could not replay. The regression failed before the V4-only size guard.
- Direct-wire tests bypass the encoder to exercise rehashed Exact and conflicting
  identity rejection in the decoder. A rehashed V3 effect is rejected.
- `go test -C services/platform -race -count=1 ./runtimecorrelation ./runtimeevent
  ./runtimeprojection ./runtimelineage` exited0:1.745s,5.202s,2.021s,1.415s.
  This includes the pinned historical V2 receipt and existing V3 tests.
- With PostgreSQL18 on PATH, `go test -C services/platform -race -count=1
  ./apiserver -run '^TestRuntimePrecisionFreeze|^TestRuntimeCandidateAuthorityFreezesReplayAfterLateAdmission$'`
  exited0 in14.070s after the fixture correction. Actual PostgreSQL snapshots flow through the repository,
  correlator and receipt codec. Late admission leaves old receipt bytes intact;
  new snapshots retain the existing ambiguity assertions. Review also removed
  reliance on hardcoded predecessor references: the fixture reads the actual
  SQL reference, object version and lease expiry, then asserts receipt replay
  preserves its input bindings. Independent review closed this finding.
- `npm run build` exited0 and produced the standalone UI. `git diff --check`
  passed. Independent codec review closed both findings.

The database integration uses owner-seeded authority fixtures and a test-only
worker grant. It does not prove V2 HTTP admission or deployed workers. Worker
dispatch, complete migration readiness/activation and end-to-end acceptance
remain open. No main push or original microtask credit accompanies this local
checkpoint.
