# Existing-test reconciliation lease checkpoint

M7A-21 remains component-only and disabled. Reconciliation now has scoped,
registered-worker claim, evidence-read, heartbeat and delayed-release database
entrypoints. This is ownership and evidence access, not permission to invoke a
target. Dispatch remains private.

Claims are bounded to 1-25 links, with 10-300 second leases. Busy organization
admission and parent rows are skipped. Ownership binds tenant, parent run, step,
worker, SHA256 of a 32-byte lease token, version and expiry. Reclaims increment
the version; release clears ownership, increments version and delays the next
poll. Raw tokens are not returned or stored. The private loader derives the
linked attempt and baseline; callers cannot choose replacement evidence.

All four public entrypoints recheck principal/release authority after their work
and before their final deadline check. A refusal rolls back writes. Heartbeat
must still finish before the original deadline, even when its proposed renewed
deadline is later. No finding status or remediation outcome is written here.

## Evidence

- RED c7db44: registered worker claim failed because the entrypoint was missing.
- Independent review found stale authorization across lock waits. RED 052f0c
  reproduced a claim succeeding after release metadata changed during a real,
  observed lock wait. Final authorization checks address that defect.
- Final owned calibration d8ae43 pins release55 to
  27fed36ec4c3dac6dc75eb2cdb4d311feed297e5aae89c3ee72ae71c03a4d5db.
- Grouped owned database acceptance uses the real registered roles and actual
  Node completion producer. Worker completion passed45.07s (e3b609), dispatch
  authorization15.97s (24af38), baseline6.56s (46b53d), reconciliation16.62s
  and compiled fingerprint4.02s (2ddcfb). Release/rollback passed11.08s;
  final grouped process exited0 with PASS (dab58d). All owned database
  processes joined and exited normally.
- Reconciliation checks cover duplicate claim refusal, stale token/version,
  tenant/run/step/worker substitutions, incorrect release pins, unregistered
  principal denial, expired ownership/reclaim, renewal, delayed release,
  bounded batches and skipping a busy organization. Metadata drift tests
  observe blocking for claim/read/heartbeat/release and assert unchanged link
  state after refusal. Representative heartbeat/release tests also expire the
  original lease during a blocked write and assert rollback.
- Migration race748093 passed6.249s; linked repository racecac1de passed5.467s.
- Independent re-review found the stale-authorization issue resolved, with no
  remaining Critical/Important findings in this component. The reviewer did
  not run tests; test evidence above comes from the coordinator's fresh runs.

These are controlled offline database/Node proofs. They are not live S3,
provider, IAM/KMS or deployed-user acceptance. Go receipt/snapshot decoding,
artifact retrieval wiring, exact-lease settlement, reconciler composition and
the full A-D/live gates remain open. The private lock helper alone is not a
complete authorization boundary: future settlement must repeat the final
authority and expiry checks after all work, as the guarded entrypoints do.

No fresh UI build, full release gate, commit or push is claimed. All original
728 tasks remain in scope; ledger classes stay534 production-available,
133 component-only and61 blocked/external. Ledger validation checks accounting,
not independent live production readiness.
