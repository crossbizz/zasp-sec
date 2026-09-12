# Precision source normalization

> Use Superpowers test-driven-development and independent review.

**Goal:** Normalize owned V3 source records without losing their precise times.
**Spec:** `2026-09-11-process-precision-design.md`, integration step2.
This task implements normalization only. Versioned envelope/checkpoint transport
and actual daemon generation ownership remain required follow-on integration.

Create `sensoradapter/precise_source.go` and tests. Modify `adapter.go` to retain
the parsed provider timestamp internally and allow an internal observation
callback before process-cache state commits. Legacy Normalize calls that path
without a callback; its output is unchanged.

Export `NewPreciseLineageNormalizer(maximum int, source LineageSource)` returning
`*PreciseNormalizer`, which exposes `Normalize([]byte) (PreciseRuntimeEvent,error)`.
Only this constructor accepts `tetragon-local-stream-v3`. Its private existing
normalizer uses V2 file/cgroup semantics. The new type cannot be passed to the
old FileProcessor. `PreciseRuntimeEvent` serializes the existing event fields
with a V2 observed_lineage field. V1 decoders reject qualified V2 output.
Unqualified source records retain absent lineage, as before; no missing source
identifier is invented. Invalid/future process starts omit the process pair.

- [x] Test same-millisecond source/process retention, old constructor rejection,
  V1 wire decoder rejection, absent qualification and cache-backed file events.
  Confirm the positive precision case fails before implementation.
- [x] Preserve exact parsed source time and implement the separate constructor
  and callback. Keep source generation immutable and validate before cache commit.
- [x] Run sensoradapter/runtimelineage/runtimeevent races and existing source
  checkpoint compatibility tests. Review independently and update the ledger.

No live activation or original task credit. Do not send new records through the
legacy enrollment envelope, adopt old cursors or claim persisted precision.

Verified locally: initial constructor RED in `/tmp/zasp-precision-source-red.log`;
review-found epoch/pre-epoch omission RED in
`/tmp/zasp-precision-source-epoch-red.log`. Final sensoradapter, runtimelineage
and runtimeevent race suites passed in `/tmp/zasp-precision-source-final.log`
(11.959s, 1.449s and 3.648s). Fresh UI build exited0 in
`/tmp/zasp-precision-source-ui.log`. Independent Superpowers re-review found no
remaining scoped findings. Invalid process pairs retain valid container identity.
