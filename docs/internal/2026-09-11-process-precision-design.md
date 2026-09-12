# Preserve source process-time precision

M3-46 remains open. This extends the original source attribution work; it does
not replace sandbox binding, auto discovery, multi-tenancy or deployment gates.

The adapter's `decodeProviderRoot` truncates source time to milliseconds before
`LineageSource.qualify` compares process start. A start at .123456789 and event
at .123999999 legitimately belong together, but the legacy event becomes .123
and omits the optional process pair. The cache retains the original process
start, so later events can recover that pair. The first event still loses it.

Keep the legacy profile, event timestamp, IDs, archives and frozen algorithms
unchanged. Moving the event forward or rounding the process start would invent
time and can change occurrence-window boundary results. Broadening the existing
decoder would also change what old frozen workers accept.

Add a separately decoded `kubernetes-container-v2` observation with a required
canonical UTC RFC3339Nano `source_event_time`. Preserve the same qualified host,
boot, pod, container, optional PID/start and cgroup fields. The precise source
time must truncate to the existing millisecond event timestamp; process start
must be at or before the precise source time. V1 still rejects V2 observations.
Consumers opt into V2 with a separate Go type, not a widened V1 validation path.

## Integration order

1. Implement the closed precision observation type and its exact-time accessor.
   Prove same-millisecond PID/start retention, wrong-bin/future-start rejection,
   strict decoding and unchanged V1 acceptance/bytes.
2. Preserve provider source time before truncation. Introduce a new owned source
   generation profile and versioned envelope/record field that carries the V2
   observation. Old source generations and checkpoints keep their exact bytes;
   old consumers refuse new generations. No live source activation yet.
3. Add versioned ingest/archive/candidate persistence, preserving source time as
   canonical text so PostgreSQL timestamp precision cannot collapse nanoseconds.
   New frozen matching uses the validated precise time for occurrence windows,
   not the millisecond display time. Preserve existing snapshot/receipt versions.
4. Compose actual source ingestion, PostgreSQL/provider projection, query and
   browser evidence. Activate only after compatible consumers and guarded
   deployment sequence are established. M3-46/M3-47 receive no credit until
   original acceptance passes.

Step1 and the normalization portion of step2 are implemented and locally
reviewed. The companion source plan records exact-time and omission regressions.
Step2's separate versioned envelope now freezes and retries precise records with
the original enrollment constraint. Owned chunk checkpoint integration now
uses the shared persistence state machine with constructor-selected V1/V2 record
contracts. Real-file restart tests preserve exact retries and cached process
precision. A separate daemon V3 startup now reuses owned identity-bracketed
subscription and manifest publication; admitted V3 readers select the precise
consumer. Local Unix-stream-to-spool-to-retry tests pass. Production's default
constructor stays V2. Precise source receipt verification and checkpoint
retirement now use explicit V3 entry points with unchanged shared authorization
and filesystem checks. Local daemon tests cover ACK, producer completion,
retirement and24-generation fixed-slot reuse. Steps3-4 and activation remain
open. These components are not an activated product capability.

The complete precise-record decoder now preserves canonical bytes and reconstructs
the embedded legacy rejection marker after JSON decoding. It validates content
and exact time-bin binding before replacing the receiver, including when an
unqualified record clears earlier identity. This closes the decoded-record
downgrade found while tracing transport. The companion envelope plan records
the separate V2 schema and retry-byte contract built on this decoder.

Transport integration must cover `sensoradapter/envelope.go`'s schema,
idempotency and enrollment constraints; `chunk_processor.go`'s owned-generation
pending envelope and cache; and `runtimeevent/production_ingest.go`'s separate
schema acceptance and archive decoding. The existing FileProcessor and old
chunk checkpoints cannot adopt V3 source records. New schema acceptance alone
is insufficient without downstream archive and durable stage version support.

Step3 now has a local, separately versioned server archive codec. Private
preparation consumes canonical precise Tetragon envelope bodies and applies
the authenticated collection mode; replay gets tenant scope only from its lease
argument. The mandatory `runtime-archive-v2` root fences old workers even when
lineage is absent. Real normalizer-to-envelope-to-archive tests preserve exact
times and content-free selectors. The existing HTTP handler still rejects V2
before reservation. SQL persistence, durable job routing and frozen precise
matching remain open. See `2026-09-11-process-precision-archive-plan.md`.

The next migration's exact SQL time fragment is now locally verified on
PostgreSQL18. Whole seconds use calendar validation; fractional digits become
exact numeric seconds, avoiding timestamptz nanosecond rounding. Separate V2
lineage validation compares optional process starts exactly and binds the source
instant to its display bin. An occurrence1ns outside the five-minute window is
excluded by this numeric expression. Production candidate queries do not yet use
it. The fragment still needs migration checksum/fingerprint inclusion, lifecycle
guards and job routing. See `2026-09-11-process-precision-sql-plan.md`.

The separate private freeze SQL fragment now uses exact source epochs against
admitted semantic observations before its candidate limit. It consumes V2
archive/index evidence under a V4 correlation lease and retains snapshot-v3,
including source-bound sandbox identity and immutable replay. Actual PostgreSQL
tests cover exact boundaries, late admissions,1001-row crowding/overflow and
old-version refusal. Historical functions remain unchanged. This fragment has
no worker grant; complete migration readiness and Go snapshot/correlation
integration are still required. See `2026-09-11-process-precision-freeze-plan.md`.

The Go repository now calls the private precise freeze function and returns a
distinct sealed V3 snapshot after validating its exact bytes and bindings.
Candidate selection checks use the precise source time, while historical
semantic observations retain their V1 timestamps/profile. Actual PostgreSQL
tests now consume this method, including immutable replay and crowding/overflow.
The V4 correlation algorithm, worker claim routing and complete migration
activation remain open. See `2026-09-11-process-precision-repository-plan.md`.

The separate V4 correlation algorithm now validates precise source-time windows
and process/cgroup conflicts against sealed snapshot-v3. Complete competing
bindings remain ambiguous with identity cleared; kernel observations never
become Exact. Its digest has a separate V4 domain. Actual PostgreSQL integration
proves immutable replay and new ambiguity after late admission. Historical
algorithms and receipt codecs are unchanged. Receipt V4, worker dispatch and
migration activation remain open. See
`2026-09-11-process-precision-correlation-plan.md`.

Separate V4 receipt entry points now consume these correlation results and
preserve the snapshot binding with a V4 schema/digest. Historical entry points
refuse V4; their pinned bytes still pass. Both V4 codec directions enforce the
1MiB wire limit. Rehashed Exact confidence is refused. Actual PostgreSQL-backed
correlation now round-trips through the receipt codec with immutable replay.
See `2026-09-11-process-precision-receipt-evidence.md`. Worker dispatch and
migration activation remain open.

The correlation executor now has a distinct precise candidate authority and
V4 dispatch. It requires index V2 and preflights V4 receipt serialization before
graph effects, preserving later receipt persistence and lease fences. Historical
jobs retain byte-identical receipts. See
`2026-09-11-process-precision-worker-evidence.md`. This does not yet wire V4 into
production startup, claiming, migration readiness or downstream consumers.

The database factory now binds both historical and precise candidate interfaces
to one correlation-authorized repository for V4 and rejects injected authority.
Local factory-to-executor-to-receipt tests pass. Startup configuration, durable
claim routing, migration readiness and downstream consumers still need wiring.

The separate precise projector now consumes V2 archives and V4 correlations,
preserves display/evidence/sandbox fields and uses risk-v3/projection-batch-v3
domains. A1ns archive change remains bound despite identical display time.
Actual PostgreSQL-through-receipt projection replay passes. Projection receipt
V3 and worker/downstream integration remain open. See
`2026-09-11-process-precision-projection-evidence.md`.

The separate projection receipt V3 codec is now implemented with V3 risk/effect
validation, canonical bytes and a4MiB serialization bound. It rejects Exact
kernel confidence and semantic-source items even after digests are recomputed.
Historical receipt formats are unchanged. Projection worker and completion
consumption still need integration. See
`2026-09-11-process-precision-projection-receipt-evidence.md`.

Projection V3 worker execution now binds V4 correlation receipts, selects
index V2 archive reads and uses precise projection/receipt codecs. V3 receipt
validation precedes graph effects; persistence follows graph success. Historical
job receipt bytes and lease/cancellation fences are preserved. Completion V3 and
production activation remain open. See
`2026-09-11-process-precision-projection-worker-evidence.md`.

Completion V3 now validates precise projection receipts within4MiB, emits a
versioned stage receipt and preserves original projection bytes for finalization.
The local worker chain and declared finisher handoff pass; historical behavior
remains unchanged. Database finalization, archive/index V2 workers and production
activation still need implementation. See
`2026-09-11-process-precision-completion-evidence.md`.

The index store now exposes ApplyPrecise for validated V2 archives. Display
documents retain archive-bound evidence without promoting observed lineage to
semantic identity; V2 hashing separates effects from legacy indexing. Worker
capability/factory wiring and activation remain open. See
`2026-09-11-process-precision-index-store-evidence.md`.

Index V2 worker dispatch now requires the precise store capability and authorized
lease, with cancellation/renewal checks around effects and receipts. Historical
V1 receipt bytes remain unchanged. Local races, review and UI build passed; see
`2026-09-11-process-precision-index-worker-evidence.md`. Archive V2 execution,
durable routing, database finalization and activation remain open.

Archive V2 execution now validates its private capability, precise body and
current lease. It retains V1 effects for historical jobs. Full worker races
and independent review passed; see
`2026-09-11-process-precision-archive-worker-evidence.md`. Startup selection,
server V2 ingestion, durable routing/finalization and activation remain open.
