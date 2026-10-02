# Existing-test discovery and scheduler checkpoint

Component evidence only. M7A-21 remains component-only/disabled and unshipped.
The original 728-task scope and availability counts are unchanged.

## Implemented

The database exposes one eligible admitted tenant scope per guarded keyset
lookup. It excludes future pending work, live leases and settled links, accepts
expired leases, and checks registered worker authority and release pins before
and after selection. It grants no direct table access or target execution.
The compiled fingerprint was calibrated in owned PostgreSQL:
`7b717e852ad034b523ed49cac5908cd8f7203bb28cf4896adcaa92eb4f7adc22`.

The Go client strictly decodes scope receipts and binds release pins. A new
scheduler processes at most one scope per poll, advances before reconciliation
to prevent a failed tenant monopolizing polls, and wraps at most once. Discovery
errors preserve the last cursor. Calls are serialized with cancelable waits and
a 30-second operation budget. Close cancels and joins active work; a timeout
does not falsely report that borrowed dependencies can be closed.

## Verification and review

- SQL RED: missing six-argument function, SQLSTATE42883, before implementation.
- Final owned offline PostgreSQL group, session5051 exit0: reconciliation lease
  17.96s, compiled fingerprint3.30s, release8.70s, scope discovery19.40s.
  Includes read-only transaction, role/grant/input rejection, tuple ordering,
  eligibility, and controlled-lock post-selection principal/checksum drift.
  PostgreSQL children joined normally. Full commands are in the task report at
  `.superpowers/sdd/2026-09-17-existing-test-scheduling-plan/task-1-report.md`.
- Scheduler RED52be1f: missing rotation/dependency/shutdown behavior. Focused
  race GREEN5db014. Additional typed-nil/incomplete-client REDecb3ec was fixed.
- Grouped `go test -race ./migrations ./agentsec-worker -count=1`, offline local
  toolchain/cache, exit0 ca8433: migrations4.883s, worker38.709s.
- Independent source review found no Critical/Important findings. Its two minor
  coverage gaps prompted waiting-caller cancellation and fresh-instance
  rediscovery tests. Latest grouped `go test -race ./agentsec-worker -run
  '^TestExistingTest' -count=1` exit0 cc2332,7.070s, includes those tests.
- Ledger validator5acd0e:728 rows,534 production-available,133 component-only,
  61 blocked/external,0 missing. No status promotion.

## Still required

The scheduler now has production worker dispatch and read-only cloud artifact
composition as described below; these remain undeployed component code. Exact
workload/IAM/network configuration and deployment remain open. Database tests have one populated
scope; multi-scope/duplicate-link traversal and registered scheduler composition
with process restart/reclaim still need acceptance evidence. Fresh Go instances
are not proof of process restart or persistent database recovery.

Load characterization and live tenant/provider end-to-end evidence remain open.
No UI build, release clearance, commit or push is claimed for this partial batch.
Old registered worker binaries compiled with the previous release pin must be
rebuilt before subsequent composed database acceptance.

## Runtime wiring continuation

The `security-agent-test-reconciler` mode loads dedicated role/token settings,
uses the registered security-agent worker database authority, and accepts only
core worker/database/evidence settings. It requires batch1 and lease60s, matching
ReconcileOne. Planner, target, queue and other provider configuration is refused.
The dedicated factory uses explicit web identity with STS role/account checking
and the existing versioned S3/KMS reader validation. The reconciler sees only
Get/ObjectReference, not the writable store. This is not an IAM permission proof.

Readiness and execution are tracked as borrowers. Closing cancels both and waits
for them before cloud cleanup; an unjoined borrower keeps both cloud and database
clients alive and returns an error. Readiness caches successful checks for30s;
the actual SQL calls continue enforcing authority/release pins on every poll.

Test-first evidence: configuration RED963080 then GREEN45bb4a; composition and
readiness-borrower shutdown REDd076e5 then race GREEN698417; dispatch and actual
versioned artifact-store retrieval REDa3f039 then grouped race GREENc03de4,8.327s.
Full worker/migration race c63023 passed40.083s/4.938s. Independent review found
no Critical/Important defects and one Minor: several unused attack-lab inputs
were still accepted. Five added rejection cases failed a52c7a. Replacing the
partial deny-list with a closed config allowlist fixed them; final full worker
race23dbd4 passed39.721s. Independent follow-up found the Minor resolved and no
new findings. All tests ran with local Go, GOPROXY=off and the owned Go cache.

Dispatch testing constructs real cloud clients but performs no authenticated AWS
request. Artifact retrieval uses a controlled S3 transport boundary. Neither is
live cloud/deployment evidence. Dedicated chart/IAM/network configuration,
registered multi-scope runtime/restart-reclaim, and live cloud access remain open.
No commit, push or availability promotion in this continuation.
