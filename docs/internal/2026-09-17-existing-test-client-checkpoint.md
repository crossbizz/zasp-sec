# Registered existing-test reconciliation client checkpoint

M7A-21 remains component-only and disabled. The Go worker now has a client for
the four guarded reconciliation entrypoints: bounded claim, evidence read,
heartbeat and delayed release. Each query includes compiled release55 checksum
and fingerprint. Claims retain a locally generated cryptographic32-byte token,
worker identity, full tenant scope, parent run/step, linked test run, ownership
version and deadline. No raw token is accepted from a receipt.

The client refuses malformed or mixed claim batches without returning partial
usable claims. Read/renew/release check original ownership expiry before and
after the query. Receipt identity, version transition, state and timestamp are
checked with strict duplicate/alias-aware decoding. Returned deadlines cannot
exceed the requested duration plus five seconds of clock-skew allowance from
response observation. Database errors return a fixed unavailable error; no
alternate API or legacy fallback runs. The constructor alone proves no database
readiness. Actual calls use the registered SQL authority checks.

## Evidence

- RED fcbf7b: client contract tests could not compile before the client existed.
- Query contract tests check the exact guarded function, positional scope,
  worker/token/version values and both compiled pins for all four operations.
- RED d136b1 reproduced oversized deadlines accepted by claim, heartbeat and
  release. The new duration bounds reject all three. Receipt negatives cover
  invalid run/version, duplicates, null, and expiry during the database call.
  Mixed-batch tests reject duplicate links, a foreign tenant after a valid row,
  and more rows than requested, with no partial claim output.
- Final grouped worker/actual Node race caf4b8 passed7.061s, including the added
  mixed-batch checks. Production SQL and the release55 fingerprint are unchanged.
- Initial owned registered-client acceptance b27fdf/72c755 passed18.64s across
  all four run/rerun supervised/autonomous modes.
- The final owned group enables the actual Node completion producer and launches
  a separate worker test binary against each owned database. The child asserts
  session_user equals security_agent_v33_worker_login, then uses the real
  Postgres driver/client for claim/read/renew/release, rejects reads after
  release and refuses premature reclaim. Completed snapshots require attempt3,
  three categories, exact scope/run and expected unknown status. Completion
  group49df1a passed46.00s, with all four child processes passing. Pending lease
  group05c11c passed17.94s with four further child passes. Final grouped process
  exited0 with PASS, and both owned database processes joined normally.
- Independent client and test-delta reviews found no Critical/Important issues.
  The review's deadline-bound and explicit-login suggestions were implemented.
  Reviewer ran no tests; command evidence comes from coordinator runs.

The owned integration proves real database-to-client decoding for pending and
complete attempts. It does not retrieve those completed artifacts from live
storage or execute settlement. The prior decoder fixture separately composes
artifact retrieval/comparison, but those two proofs are not a single production
workflow. Durable exact-lease settlement, worker polling/composition, composed
artifact acceptance, UI and A-D/live gates remain open. No finding is marked
remediated by this client.

No UI build, full release gate, commit or push is claimed. All728 original tasks
remain in scope; ledger classes stay534 production-available,133 component-only
and61 blocked/external. Status accounting is not live production proof.
