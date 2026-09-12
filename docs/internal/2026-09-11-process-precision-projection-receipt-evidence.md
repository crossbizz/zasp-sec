# Precise projection receipt checkpoint

Separate `EncodePreciseReceipt`/`DecodePreciseReceipt` entry points accept only
`runtime-projection-v3` with `runtime-projection-receipt-v3`. They validate V3
risk IDs and effect digests, Tetragon source, non-Exact confidence, sandbox source
binding, canonical display time, evidence references and ordered unique events.
Historical receipt entry points remain limited to V1/V2.

The precise encoder enforces the decoder's4MiB serialized limit. Shared private
codec helpers retain the historical wire layout and validation rules. Canonical
round-trip checks reject duplicates, aliases, null sandbox values, schema/version
changes, changed bindings and trailing bytes.

Superpowers evidence:

- Rejecting stubs failed round-trip and valid unknown-sandbox tests before
  implementation.
- Direct-wire tests recompute risk IDs and effect digests before testing forged
  Exact confidence, OTLP source, missing sandbox source and noncanonical display
  time. These bypass encoder validation to exercise the decoder itself.
- Removing only the precise encoder size guard emitted6796913 bytes from an
  otherwise-valid1000-item receipt and failed the regression. The guard was
  restored before final verification.
- Final `go test -C services/platform -race -count=1 ./runtimeprojection
  ./runtimecorrelation ./runtimeevent` exited0 in1.787s/1.694s/5.127s, including
  historical projection receipt vectors.
- UI build, diff and authoritative ledger checks passed. Independent Superpowers
  review returned no findings and approved this local codec checkpoint.

This codec does not authenticate a receipt's storage provenance. Its worker
must bind the stored object, lease, predecessor and archive before consumption.
Projection worker V3, completion ingestion, migration/claim routing and deployed
acceptance remain open. No original task credit or push.
