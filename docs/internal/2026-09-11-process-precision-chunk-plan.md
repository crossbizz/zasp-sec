# Precise owned chunk implementation plan

> Use Superpowers test-driven-development and requesting-code-review.
> Execute this tightly coupled state-machine change inline.

**Goal:** Durable constructor-driven V3 normalization and V2 envelope replay.
**Architecture:** Generic private chunk state machine, generation-specific
private record contracts, unchanged V1 aliases and wire layouts.
**Tech Stack:** Go1.25 generics, os.Root, existing atomic checkpoint writer.
**Spec:** `2026-09-11-process-precision-chunk-design.md`.

## Files and interfaces

Modify `services/platform/sensoradapter/chunk_processor.go`: generic
`chunkProcessor[E any]`, `chunkCheckpointOf[E any]`, `pendingChunkOf[E any]`.
Preserve old aliases so existing tests and exported API keep their types.
Create `chunk_contract.go` for the private selected callbacks and V1/V2 factories.
Create `precise_chunk_test.go` for file-backed restart acceptance.

```go
type ChunkProcessor = chunkProcessor[RuntimeEvent]
type PreciseChunkProcessor = chunkProcessor[PreciseRuntimeEvent]
func NewPreciseChunkProcessor(config ChunkProcessorConfig) (*PreciseChunkProcessor, error)
```

The private contract carries checkpoint/envelope/schema constants, target,
normalization, prepare/ingest, body decode, digest, event-size and observation
extraction callbacks. The shared processor owns the normalizer's actual cache,
opened roots, lock, pending state and progress. Public constructors supply the
complete private contract after generation-specific normalization validation.

- [x] Add real-root tests for uncertain send then close/reopen with exact bytes,
  credential rotation, next partial file identity from restored cache, durable
  write-before-token, V1/V2 cursor refusal and changed-boot refusal.
- [x] Run tests with constructor/method stubs returning ErrStream; confirm RED.
- [x] Parameterize types and receivers without altering serialized fields or
  state transition order. Select normalization, envelope and event checks through
  the private contract; preserve old cache, chain and filesystem checks.
- [x] Add failure-before-upload tests and all-dropped/expired/preparation-failure
  checkpoint cases. Run full sensoradapter/runtimelineage/runtimeevent race suites
  and sensor-agent races, UI build, independent review and ledger checks.
- [x] Record verified scope and remaining daemon/server/activation gates.

No released migrations, archive decoders, daemon profile defaults or original
task status change in this step. Do not publish the larger incomplete draft.

Local evidence: constructor RED in `/tmp/zasp-precision-chunk-red.log` and
focused restart GREEN in `/tmp/zasp-precision-chunk-green.log`. Expanded
sensoradapter/runtimelineage/runtimeevent races passed12.535s/1.607s/3.754s in
`/tmp/zasp-precision-chunk-full.log`. Existing sensor-agent races passed104.542s
in `/tmp/zasp-precision-chunk-daemon.log`. Fresh UI build exited0 in
`/tmp/zasp-precision-chunk-ui.log`. Independent Superpowers review found no
findings; its remaining condition was the now-passed sensor-agent run.
Status ledger remains728/536/131/61 with no new original task credit.
