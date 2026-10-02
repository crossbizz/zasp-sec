# Existing-test enqueue baseline checkpoint

M7A-21 remains component-only and disabled. No original task is promoted.

The private link enqueue now snapshots the latest committed, complete failed
attempt for the same tenant and test definition/version. The versioned definition
binds the selected target. It retains the exact attempt, input digest, completion
time, and both immutable artifact receipts. Missing input receipts, inconsistent
run/attempt metadata, zero output checksums, invalid scoped output references,
other versions, passing attempts and future completions are excluded. Link replay
returns the existing snapshot without selecting again.

This is a baseline candidate, not validated remediation evidence. Settlement must
retrieve both versioned objects, revalidate the retained association and compare
the complete target/credential/engine/check tuple. A selected legacy artifact
without comparison data must yield unavailable baseline, not silently fall back
to an older comparable failure.

## Verification and review

- Initial owned PostgreSQL RED 36e10c: baseline column absent.
- Initial candidate implementation passed b22f19 in 15.31s.
- Independent review found a transaction-time cutoff defect. The queued timestamp
  defaults to transaction start, which can predate prerequisite lock waits.
  RED 5d41ef reproduced selection of the older attempt after another connection
  committed the latest failure during an already-open dispatch transaction.
- Selection now snapshots before enqueue, using a wall-clock cutoff after
  prerequisite locks. It does not lock historical runs, avoiding the inverse
  run/definition lock order used by completion.
- The independent follow-up review confirmed the Important finding resolved with
  no new findings. The regression exercises transaction timing directly, not an
  actual held-lock wait.
- Owned calibration db827d established release55 fingerprint
  87578080526fe298b7746a292ff8b1c5bceb6e684805972da8d64916cf77f041.
- Grouped owned PostgreSQL cb37ee/e14b6e/ec93e1 passed worker completion 37.87s,
  prepared dispatch including authorization refusals 15.38s, baseline 5.03s,
  compiled fingerprint 3.26s and release/rollback 8.82s.
- Final fixture ordering correction makes invalid candidates newer than the
  selected valid failure. Fresh baseline 41727f passed all four supervised/
  autonomous run/rerun modes in 5.17s, including absent baseline, exact receipts,
  completion after transaction start and snapshot preservation on replay.
- Migration race 4233ed passed in 4.889s; linked repository race 16a24a passed
  in 5.032s. No host database was used.

The baseline fixture skips unrelated refusal cases already covered by the grouped
prepared-dispatch suite. This implements the user's feature-batched verification
cadence without removing the authorization tests.

## Still open

Settlement-time retrieval/comparison, reconciler ownership and worker composition,
before/after UI, full A-D acceptance and deployed-provider proof remain open.
No live provider or S3 proof, fresh UI build, full release gate, commit or push is
claimed by this checkpoint. All 728 original task statuses remain unchanged:
534 production-available, 133 component-only and 61 blocked/external.
