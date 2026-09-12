# Precise index store checkpoint

`runtimeindex.Store.ApplyPrecise` reads strict V2 archives, validates input
scope/digest/limits and constructs index documents from display fields. It does
not derive semantic agent/session/sandbox authority from observed lineage.
Archive digest remains part of document identity; V2 index effect hashing uses
`zasp.runtime-index.batch.v2`. Existing Apply retains legacy decoding/hashing.

Superpowers evidence:

- Rejecting stubs failed precise indexing and provider-drift tests before code.
- A typed sensor event with nanosecond observed lineage flows through the actual
  archive decoder and store into a declared driver. Tests check display time,
  source/class/archive bindings, absent semantic identities and deterministic
  replay. A1ns source-time change alters document ID and effect digest.
- Old Apply rejects V2 archives; precise Apply rejects missing version and digest
  drift before provider calls. Incorrect provider results fail closed.
- `go test -C services/platform -race -count=1 ./runtimeindex/... ./runtimeevent
  ./runtimeprojection ./runtimecorrelation` exited0: index1.602s, OpenSearch
  driver1.925s, runtimeevent5.306s, projection2.589s, correlation2.312s.
- Independent Superpowers review returned no findings. Diff checks passed.

These are local store/driver package tests, not a live OpenSearch write proof.
Index V2 worker capability and factory wiring, archive V2 execution, database
finalization, durable routing and production activation remain open. No push
or original microtask credit.
