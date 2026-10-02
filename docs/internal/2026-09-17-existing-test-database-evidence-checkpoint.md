# Existing-test database evidence checkpoint

M7A-21 remains component-only and disabled. The private database loader is
implemented; guarded claim/lease settlement and worker composition remain open.

The loader accepts scoped Security Agent run/step IDs, then derives the linked
after-run and saved baseline from database authority. It cannot accept an
arbitrary replacement test-run or attempt from its caller. Complete runs must
match their exact current persisted attempt, input digest, verdict/error,
completion time and both artifact receipts. Baselines must still equal the
enqueue-time snapshot and precede link creation. Changed baselines are refused;
no older candidate is silently selected.

Invocation records must belong to the exact same scoped run/attempt/input digest
and bound test/version/target/category list. The snapshot includes successful
completed observations and a separate started-without-terminal flag. Pending
runs remain pending. The function is STABLE, reads one statement snapshot and
does not acquire historical run locks.

Links now retain the original category list from the locked definition at enqueue.
Later definition edits cannot change the evidence request. Baseline creation and
snapshot timestamps use explicit UTC formatting, independent of session timezone.

## Verification

- REDd4a90d: the real registered worker completed its attempt, then the new
  snapshot assertion failed because the private loader did not exist.
- REDa8b004: changing the read session to America/Los_Angeles caused an unchanged
  baseline to fail receipt equality. Explicit UTC formatting fixes this; the
  regression compares the entire snapshot across session timezones.
- Final owned calibration c7f837 established release55 fingerprint
  9f69f7ca431659b7e3a1b6ef500a614fe38d9f419e14f4098a73c2dfd31494e1.
- Grouped owned database b3ff7c/f52ce6/6f8e15/740098 passed actual Node producer
  and registered worker completion/snapshot checks38.20s, dispatch authorization
  including refusals14.79s, baseline5.00s, compiled fingerprint3.15s and
  release/rollback8.41s. All owned database processes exited cleanly.
- Snapshot checks prove exact receipts/journal values, registered-worker direct
  denial, foreign-scope refusal, and refusal of changed attempt digest, checksum
  or attempt number. Baseline checks include absent/retained baseline, pending
  after-run, immutable categories after definition edits, rejected baseline
  version changes and timezone-stable evidence.
- Linked repository race7b024f passed5.205s. Final migration raceb06cea passed4.627s.
- Independent source and UTC-delta reviews found no Critical/Important findings.

These are controlled database/Node proofs, not live S3/provider acceptance. The
loader has no worker EXECUTE grant. A guarded wrapper must verify the registered
principal, compiled release and exact link claim lease before returning the
snapshot, then settlement must recheck ownership using a final compare-and-swap.
Go decoding/worker wiring and composed artifact retrieval still need acceptance.
No finding status is changed by this loader.

No fresh UI build, full release gate, commit or push is claimed. Original728 task
counts remain534 production-available,133 component-only and61 blocked/external.
