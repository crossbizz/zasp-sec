# Precision upload recovery, in progress

Independent review found that V2 production intake used a V1-only recovery path.
SQL could lease an interrupted V2 upload before Go rejected its schema, leaving
that lease and any later leases in the claimed batch unprocessed.

The precision repository now uses a separate four-argument
`zasp_runtime_claim_reconciliation_v2` claim under fresh compiled51 readiness.
Only explicit precision construction accepts V1/V2 recovery leases; historical
validation remains V1-only. Release, finish and quarantine also check fresh51
before their existing SQL calls. Their persisted schema and exact artifact checks
remain database responsibilities.

The new explicit precise reconciler requires a precision-readiness capability
and checks it before claiming. It processes mixed supported versions. Production
service selection now includes this reconciler with the precise repository and
HTTP handler; the reconciliation cache forwards uncached precision readiness.

Superpowers RED reproduced V2 rejection in the repository claim and separately
in release, finish and quarantine. Those cases now pass. Restoring the historical
reconciler mode reproduced abandoning the V2 lease after processing the V1 lease;
the explicit precise mode was restored. Full runtimeevent races passed in5.072s,
and event-ingest races in1.533s. These tests use declared database/artifact results.

Independent Go review found no new blocking logic defect and repeated targeted
races in1.290s. It requires failed-readiness cases proving zero operation queries,
plus behavioral coverage of actual factory selection before integration acceptance.
Registered51 database changes/tests are in progress.
The failed-readiness gap now has20 cases: denied, missing, malformed, duplicate
and database-error responses for claim/release/finish/quarantine. All return
unavailable after exactly one readiness query, with no operation SQL. Targeted
races passed in1.692s. Follow-up review confirmed the20-case gap is closed.

An actual client/HTTP/Go-reconciler/PostgreSQL interruption case is added and
compiles. The local artifact fixture saves the object but loses its response;
recovery must inspect the exact binding, persist success and the five-stage
precision tuple, then permit token-rotation replay without a second upload.
The first actual PostgreSQL run reached the versioned claim but returned a valid
lease time with a -07:00 offset. Go's UTC-location requirement rejected that
decoded lease. A unit test reproduced the offset failure; the repository now
normalizes the decoded timestamp to UTC without changing its instant.

Review also found an acceptance-identity mismatch: the actual Go reconciler used
scope/generation/reconciliation-derived job and outbox IDs, while HTTP lookup
requires batch/runtime-job and batch/runtime-outbox IDs. The older incomplete
PostgreSQL fixture called SQL directly with HTTP IDs, so it didn't cover the Go
derivation. A new test reproduced the mismatch. Explicit precise recovery now
uses the HTTP identities for both supported schemas; historical construction
retains its existing derivation. Full runtimeevent races passed in5.260s and
event-ingest races in1.493s. The UI build passed before this Go-only correction.
Independent identity review found no new issues.

Both actual PostgreSQL HTTP tests passed in10.796s on migration fingerprint
7459fe4b9ac84a777e5bf351346be136c26eb401fb5d34a97dc345d00cb36b91. They exercise
normal accepted-response loss and stored-artifact response loss, the real Go
reconciler, registered ingest principal, persisted success and stage tuple,
then accepted replay after token rotation with one artifact upload. Full
runtimeevent races passed in5.279s and event-ingest in1.539s. Transport and
artifact storage remain local fixtures, not cloud/deployed proof. Timestamp
normalization review found no issues and repeated targeted races in1.229s.
The full migration regression/review remain pending.
Old claim isolation, cached-old mutation protection, release fingerprints and
full migration regression/review remain required. The P1 stays open. No push,
deployment activation or original task credit.

SQL review found an expired-recovery-lease guard also rejected legitimate
authenticated request finalization. The migration owner reproduced42501 and
narrowed that guard to expired retry/exhaustion cleanup, retaining separate
claim/observation protections. Both actual HTTP tests pass in11.083s on corrected
fingerprintccc188cf6ea8b9a0bab502159fb2566992f64c56926389531a812ac3c777b0d9.
Independent SQL re-review approved the bounded correction conditional on the
final-pin recovery suite. That suite passed in57.978s and migration races in1.585s.
The earlier full precision run passed in247.462s before this last correction;
a fresh full precision run on the final pin passed in268.186s. This closes the
bounded recovery correction's regression/review gate, not whole-release readiness.
Shared production composition now has reviewed behavioral coverage; see
`2026-09-11-precision-ingest-composition-evidence.md` for its resource-boundary limits.
