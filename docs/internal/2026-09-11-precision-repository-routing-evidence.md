# Precision completion now has an explicit repository route

Superpowers RED: `go test -C services/platform ./runtimeevent -run
TestPreciseCompletionPinsAuthorityBeforeMutation -count=1` failed all seven
cases because V3 called the historical finisher without precision readiness.

The repository now checks compiled release51 identity and principal before
every V3 completion outcome. Success selects only the precise18-argument
finisher and passes the original receipt bytes. Closed readiness decoding
rejects absent/denied functions, drift, null, duplicate and unknown fields.

Focused race command:
`go test -C services/platform -race ./runtimeevent -run
'TestPreciseCompletion|TestSandboxCompleteRepository|TestRuntimeCompleteRepository'
-count=1` passed in1.848s. It covers declared database responses, matching and
altered results, receipts larger than1MiB, failure-transition readiness and old
V1/V2 dispatch. Independent read-only review found no issues. UI build passed.

This doesn't prove the database release is ready. Its fingerprint was still
under construction during the routing tests. The real PostgreSQL test
`TestRuntimePrecisionRepositoryRegisteredCompletion` has been added and reached
the unfinished install gate, failing with `install precision migration database
failed` in5.053s. It must pass registered install, actual repository completion,
replay, source-qualified persistence, target queue, rollback refusal after new
evidence and readiness drift before this integration is complete.

Migration work is active in agent `/root/precision_migration`; its requirements
and recovery ledger are in this plan's `.superpowers/sdd` workspace. No push,
production activation or original task credit.

The explicit `NewPostgresPrecisePipelineRepository` now fixes supported
capability at construction for all five stage authorities. Each selects its
versioned SQL claim only after strict compiled51 readiness. Claimed versions
are limited to archive1/2, index1/2, correlation1-4, projection1-3 and complete1-3.
Historical constructors are unchanged. Precision heartbeat and finish also
require healthy51 while draining historical work, and reject unsupported stage
versions before querying the database.

Tests first failed against generic claim/readiness selection. A separate RED
showed an unsupported complete-v4 heartbeat reaching the database. After the
implementation, `go test -C services/platform -race ./runtimeevent -count=1`
passed in5.363s. Independent review found no repository issues, noting that
complete-v2 drain still needs schema50 compatibility readiness inside51.
These are declared-database routing results from that checkpoint. Registered51
SQL wrappers and mixed-version fences now have actualPG tests; current evidence
and remaining acceptance gaps are in
`2026-09-11-process-precision-finalization-plan.md`. This earlier result alone
does not establish those later database or provider checks.
