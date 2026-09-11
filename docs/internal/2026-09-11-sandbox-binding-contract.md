# Versioned semantic sandbox binding

Local prerequisite only. M3-46 and M3-47 remain component-only. There is no
SQL50 installation, v3 worker activation or downstream sandbox projection yet.
The production producer still creates v2 correlation jobs.

The old frozen candidate contract loses `sandbox.id` even though the admitted
OTLP archive requires it. This change adds `runtime-candidate-snapshot-v2`,
paired only with `runtime-correlation-v3`, and a separate freeze SQL entrypoint.
The SQL function is not implemented in this increment. Missing authority fails
closed, with no fallback to a historical snapshot or rewritten receipt.

Each candidate retains its admitted source enrollment and semantic sandbox.
Null means a historical observation didn't retain the sandbox. Missing keys,
empty observed IDs, invalid types, aliases and unbound same-batch values fail.
Historical null observations remain candidates. They cannot be discarded to
manufacture a unique populated binding. A current OTLP batch must agree with
its exact archived sandbox and source; it cannot substitute historical null.

The v3 matcher still requires qualified cluster/node/boot/pod/full-container
identity and the five-minute occurrence window. When both observations have
process or cgroup qualifiers, contradictions reject the occurrence before
deduplication. Those optional checks aren't continuous lifetime proof. The
sub-millisecond process omission remains separate work.

Deduplication uses agent, session, enrolled source, sandbox-known flag and
sandbox text. Repeated identical bindings remain Strong. Different sandbox or
source bindings become Probable, including when agent/session are equal. This
is an intentional v3 confidence change. A unique historical unknown can still
assign Strong agent/session identity, but it has no sandbox/source assignment.
All Probable and Unattributed identity fields remain empty. Only that event's
explicit OTLP identity receives Exact, with its admitted source namespace.

The v3 result has a separate effect digest and receipt schema. Its sandbox and
semantic source survive encode/decode and participate in the digest. Old receipt
versions reject populated new fields, even if a caller recomputes a matching
old-version digest. Empty fields are omitted from historical wire bytes.
The v2 correlator rejects new snapshots; v3 refuses old snapshots.

## Evidence recorded

- `/tmp/zasp-sandbox-snapshot-red.log`: the old repository rejected the new
  versioned snapshot, before the decoder implementation.
- `/tmp/zasp-sandbox-version-red.log`: the historical correlator accepted a
  new snapshot before the explicit version fence.
- `/tmp/zasp-sandbox-matcher-red.log`: new matcher tests couldn't compile
  because the v3 entrypoint did not exist. This is missing-API evidence, not a
  runtime semantic failure.
- `/tmp/zasp-sandbox-receipt-red.log`: v3 receipts were rejected and historical
  versions accepted populated sandbox results with recomputed old digests.
- `/tmp/zasp-sandbox-final-contract-races.log`: complete runtimeevent,
  runtimecorrelation and runtimeprojection race suites pass, including
  same-batch provenance and frozen-version compatibility regressions.
- `/tmp/zasp-sandbox-old-v2-vector.log`: an isolated temporary test harness
  captured a literal receipt from unchanged production source at
  `49faf28d7b762aac0e3fc316962fe8905ae15802`. The harness was removed after
  capture; the pinned literal, effect digest and receipt digest are retained in
  the new regression. The new code reproduces its bytes exactly.
- `/tmp/zasp-sandbox-contract-verify.log`: full verification with 1,188 UI tests,
  build, compiled
  imports and all 728 ledger rows pass. This run preceded only the final two
  added Go regressions; those passed the fresh contract race run above.
- `/tmp/zasp-sandbox-source-gate.log`: source release gate passes. Built-image
  attestation, providers and public deployment remain separate external gates.

Independent read-only review found no contract bug and requested the two final
regressions, now passing. Final review approved this local checkpoint only,
with no SQL50, v3 consumer or M3 completion claim. Superpowers isn't installed; its official upstream
test-driven development, verification-before-completion and requesting-code-review
instructions are the disclosed fallback. The repository fixtures exercise the
real closed decoder using declared SQL responses. They aren't PostgreSQL or
live-provider proofs.

Next: append-only SQL observation admission, immutable v2 snapshots without
rewriting historical v1 rows, v3 claim routing with both old entrypoints fenced,
compatible49 pre-staging and pinned50 activation. Then preserve the new binding
through workers, projections, graph, search, APIs and browser acceptance.
