# Existing-test settlement candidate checkpoint

The SQL settlement candidate is implemented. M7A-21 remains component-only and
disabled. This checkpoint does not claim full settlement composition, production
readiness, or completion of the original 728-task scope.

## Implemented contract

The registered worker settles using its scoped lease, original authoritative
snapshot and exact verifier JSON bytes. SQL checks compiled authority, locked
attempt/journal association, allowed outcomes and per-category remediation
proofs. It stores the exact-byte proof hash and immutable replay association,
updates link/step/effect/parent atomically, and emits one audit record. Final
authority and original lease deadline checks roll back work delayed by waits.

Expired leased execution with an existing invocation journal becomes durable
unknown outcome, without issuing another target invocation. Already cancelled
parents and steps remain cancelled. Exact lost-response replay returns the saved
receipt; altered ownership, snapshot or proof is refused.

Candidate migration55 fingerprint:
`02d8009f78b8e08e54d35e1bc5a681b93a67687d61f4f698d62a10916cacf059`.
Calibration used the owned offline database only.

## Evidence and its limits

- RED58abb9: registered acceptance reached missing settlement function42883.
- Owned grouped acceptance74defe/df9d2d: four completed execution modes passed
  in46.25s, expired uncertain recovery12.37s, stopped-parent preservation14.53s.
  These exercise changed lease/version/snapshot refusal, duplicate proof keys,
  remediation check-ID/digest/flag/status tampering, run-lock NOWAIT refusal,
  authority drift, deadline rollback, exact-byte hash, atomic state, replay and
  single audit. The remediation case explicitly requires remediated, preventing
  a baseline-unavailable fallback from passing that case.
- Earlier groupd224c0 failed before recovery settlement because the isolated
  recovery fixture lacked its discovery seed. The test-only seed was corrected;
  the grouped results above supersede that failed run.
- Late callback acceptance7c1c63: owned recovery passed12.31s. The registered
  adapter completed its started journal after settlement; test failure/unknown,
  parent inconclusive, link uncertainty and receipt outcome remained recorded.
  This asserts the receipt outcome, not equality of the entire receipt.
- Linked repository race6678f9 passed5.471s. Migration racef472da passed5.528s;
  owned compiled fingerprint4ef126 passed3.72s and release/rollback8.53s.
- Independent source review found no new Critical/Important findings in the
  reviewed candidate. It reported the version-exhaustion gap below and corrected
  the scope of the late-callback receipt claim.

These are controlled Node/database/component checks. They are not live target,
cloud artifact storage, IAM/KMS, deployed worker or browser end-to-end proof.

## Still required

1. Resolve reconciliation version exhaustion coherently: claim can issue
   version1000000 while settle/release refuse it. Do not merely move the point
   where pending work becomes stranded.
2. Integrate cancellation for stopped parents whose linked test is still queued
   or unstarted. Direct acceptance of confirmed cancellation and definitive
   failure remains missing.
3. Compose polling/heartbeat, unknown classification, exact-version artifact
   verification and settlement. Test restart/lost-response handling through
   that composition. Client source snapshots and saved requests are immutable;
   expired saved retries rely on SQL's exact replay fence, not a client bypass.
4. Check consistent handling of historical before.error_code=outcome_unknown
   between the SQL proof guard and Go decoder.
5. Complete original A-D acceptance and external/live gates. Run fresh UI and
   full release verification before any push. No commit or push in this batch.

Counts remain534 production-available,133 component-only,61 blocked/external,
0 missing. Batch verification reduces repeated setup, not required coverage.

## Worker client continuation

`agentsec-worker/security_agent_test_settlement_client.go` now prepares an
immutable request from a live matching claim, the saved validated source
envelope, and exact verifier bytes whose SHA256 matches the verifier digest.
Submission uses the guarded12-argument SQL entrypoint and compiled pins. The
receipt must match parent/step/version/outcome/reason/hash and permitted state
combinations. An expired saved request can reach the database for exact replay;
preparing a new expired request is refused. Errors stay sanitized.

REDdd2412 established the missing client API. Independent review found valid
but contradictory receipt enums; RED9dea8b reproduced false remediation,
false verified effect and stopped-parent success acceptance. REDf5c991 then
reproduced unknown-outcome/succeeded-effect acceptance. Both guards were added,
including positive tests for preserved terminal history and legitimate
evidence-unavailable succeeded effects. These tests use a controlled query
boundary, not a registered DB settlement or live artifact proof. Final grouped
worker/actual Node race7bb3a9 passed6.883s using:

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache \
ZASP_TEST_NODE=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node \
/opt/homebrew/bin/go test -race ./agentsec-worker \
  -run '^(TestExistingTest|TestRedTeam|TestProductionRedTeamRunner|TestComposeRedTeam)' -count=1
```

Run from `services/platform`. Final independent re-review confirmed both
receipt findings resolved with no new findings in this delta. This local run
alone did not prove registered DB integration; see the subsequent owned run.

## Registered client acceptance continuation

The owned actual Node completion fixture now optionally invokes the compiled
worker client with `ZASP_RECONCILE_CLIENT_SETTLE=true`. The child asserts its
registered session user, claims and reads the real snapshot, renews ownership,
and prepares/submits a settlement. Storage is deliberately unavailable: the
real verifier must yield inconclusive/evidence-unavailable, with persisted
unknown execution classified before submission. This is fail-closed integration
coverage, not successful artifact retrieval or remediation evidence.

Exact replay returns the same typed receipt. Subsequent evidence reads and
reclaims are refused. The owner independently asserts settled/cleared link
ownership, inconclusive parent/step and persisted effect digest equal to the
receipt proof hash. This owner assertion does not separately inspect effect
state; do not claim that additional coverage from it.

Registered completed-path group97f197 passed all four modes41.78s. Independent
test review found no Critical/Important findings and confirmed these evidence
limits. Pending-work groupc021d9 passed all four modes16.52s; the entire process
exited0 and both owned PostgreSQL servers joined normally. Eight registered
child checks passed across completed and queued execution modes.
Both Linux binaries were freshly compiled against the current candidate; the
container had no network, read-only mounts and its own temporary PostgreSQL.
The test does not establish process-restart persistence or a deployed worker.

## Reconciliation flow candidate

`security_agent_test_reconciler.go` adds one tenant-scoped reconciliation pass:
claim one link, renew60s, read the fenced snapshot, release queued/retryable work
with30s delay, classify unknown before any artifact read, compare completed
artifacts, and submit immutable settlement. Definitive failed/cancelled tests
retain their distinct outcomes. A30s operation context bounds work inside the
renewed lease. A lost acknowledgement gets one retry with identical saved
bytes and ownership. Leased executions attempt unknown settlement; SQL alone
checks expired execution plus durable journal. A still-live refusal releases
the reconciliation lease for later checking, without executing another target.

REDefb1b4/320d2d established the missing ReconcileOne method. Grouped worker and
actual Node race5937f4 passed7.640s. Controlled query-boundary tests cover known
failure, cancellation, unknown, pending, leased-live/expired, heartbeat failure,
lost acknowledgement and exact artifact comparison. The comparable fail/pass
case reads four versioned objects through the real artifactstore provider and
submits a remediated proof. Unknown/pending paths read none. These are local
composition checks, not a registered DB plus successful artifact-store proof.

The production scheduler/runtime mount and tenant enumeration are not wired by
this candidate. Full restart/lease-loss acceptance and registered successful
artifact retrieval remain open, along with the earlier SQL exhaustion and
queued-cancellation gaps. Independent review found no Critical/Important issue
in this bounded flow delta. It identified missing cancellation-during-artifact-
retrieval/settlement coverage; add a context-aware blocking dependency test
before claiming complete lifecycle verification. SQL admission is controlled
in these tests, including the live-versus-expired leased-execution cases.

## Registered artifact-to-settlement composition

The owned completion fixture now has an opt-in
`ZASP_RECONCILE_COMPOSE_ARTIFACTS=true` path. It hashes the actual input bytes
and stores their real size in the completion receipt. The actual Node producer
builds the output bundle. Both byte sequences are passed through a0600 temporary
file to the compiled registered worker child. A controlled versioned storage
driver backs the real artifactstore provider; `ReconcileOne` uses the real
registered database client and SQL settlement.

The parent checks persisted outcomes and step states, not only child success:
pass without a baseline becomes needs_human/test_baseline_unavailable with a
succeeded step; a failing current test becomes needs_human/test_condition_persists;
unknown execution becomes inconclusive without artifact reads. The final mode
has a saved baseline whose bytes are unavailable, so it must remain inconclusive
and must not claim remediation.

Review tightened the last case: exactly three reads are required, including
the saved baseline input reference at controlled-input-version, and the stored
proof must retain the current after-run at attempt3. The stronger initial run
27d93e/f003f5 failed because the assertion named a separate baseline-selection
fixture. This completion batch actually selects its earlier mode1 failed run
through production enqueue. An unrelated proposed fixture-bucket change was
reverted. Composition input references are now unique per run, avoiding reuse
of an immutable object/version for different input bytes. The expected third
read is the earlier mode1 input, whose bytes are absent from the current child's
controlled store. This remains a missing-baseline test, not remediation.

Initial owned composition862cc2/9b1c77 passed completed modes40.70s and pending
modes16.77s, before those stronger assertions. Final grouped worker/actual Node
race6a684c/5003c5 passed8.366s and exited0. Corrected strengthened owned run
3dc186/a16655 passed completed modes42.91s and pending modes16.84s, eight child
checks total, exit0 with both owned PostgreSQL servers joined normally. Final
independent re-review found no new Critical/Important findings. This is
controlled storage/database composition,
not live S3/IAM/KMS, real target execution, registered remediation, or deployed
worker scheduling. All previous external and production-mount gates remain.

## Available-baseline and cancellation acceptance

With `ZASP_RECONCILE_INCLUDE_BASELINE=true`, the parent retains the earlier
failed mode1 input and actual Node output bytes in a0600 file under the top-level
test's temporary directory. Mode3 receives those bytes alongside its own
passing artifacts. The registered worker runs the real ReconcileOne flow and
reads all four exact versions through the artifactstore provider. The parent
requires remediated/test_condition_changed, succeeded step, the saved baseline
run/attempt, three comparison checks, a verified effect with matching proof
hash, and exactly one test_reconciled audit. The separate missing-baseline
test path is preserved.

Owned completed-path530a5c passed all four modes42.57s, including registered
remediation with available controlled artifacts. Pending-path052846 passed all
four modes16.79s. The full process exited0, eight registered child checks passed,
and both owned PostgreSQL servers joined normally. This is actual Node producer plus
controlled storage plus registered SQL reconciliation, not live target/engine,
S3/IAM/KMS or deployed-worker proof.

Context-aware artifact and SQL dependencies now exercise cancellation during
retrieval and settlement. They require observing the supplied cancellation and
refuse any subsequent settlement/retry calls. Grouped worker/actual Node race
4b6ada passed8.484s. Independent review found no Critical/Important findings
and confirmed the previous cancellation coverage gap closed for this bounded
flow. Full process restart, shutdown and production scheduling remain separate
acceptance gates. No production activation, UI/full release gate or push.
