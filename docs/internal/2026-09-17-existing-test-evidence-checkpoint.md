# Existing-test artifact verification checkpoint

M7A-21 remains component-only and disabled. Original scope and task statuses are
unchanged. This implements the read-only evidence verifier, not durable settlement.

## Implemented

The worker verifier reads the exact scoped input/output object versions through
the existing artifact store. It validates reference/key scope, configured bucket,
version, size, checksum, media type, receipt association, run/input digest,
test/version/target and ordered categories. Strict JSON decoding rejects aliases,
duplicates and unexpected fields. Existing native/summary validators check the
engine, runner image, curated checks, prompts, assertions and redaction.

For linked evidence, observations must match the supplied persisted invocation
journal values, including response digest, protection flag, target comparison and
actual credential-version digest. The future DB loader, not these artifact
contents, must establish authority for those supplied values.

The comparison reads both attempts before reporting a change. A valid v2 failed
baseline and passing re-test must have identical evaluation identities and full
per-category target/credential tuples. All previously unsafe checks must become
protected and all other selected checks must be protected with HTTP200 results.
The versioned proof records before/after run, attempt, input digest and both
artifact receipts, plus per-check identity, prompt/assertion digests, protection
flags and HTTP status. Its digest is SHA256 of deterministic proof JSON.

A pass without a comparable baseline yields needs_human/test_baseline_unavailable.
A verified unsafe result yields needs_human/test_condition_persists. Missing or
substituted evidence and engine errors yield inconclusive. Valid legacy v1
artifacts remain readable but cannot establish remediation. The verifier performs
no finding or run-state writes.

## Evidence

- Reader API RED b4d510, followed by race2211f8 passing.
- Comparison API RED bf0229, followed by race6255bb passing.
- Legacy classification RED8a5902 reproduced an incorrect inconclusive outcome.
  Valid v1 reading now yields unavailable baseline; race1c2c87 passed.
- Independent reader and combined comparison reviews found no Critical/Important
  issues. Review correctly notes that the attempt value is only range-checked in
  this component: exact cross-attempt binding requires the future scoped DB loader.
- Added review-requested tests for a mixed two-category failed baseline becoming
  fully protected, engine_error classification and repeated proof-digest equality.
- Final grouped race35197f passed in5.906s:
  TestExistingTest*, TestRedTeam*, TestProductionRedTeamRunner*, TestComposeRedTeam*,
  with ZASP_TEST_NODE set to the local Node22 runtime. This includes the existing
  actual Node runner contract. New retrieval fixtures use the real artifact store
  with a controlled in-memory storage driver, not live S3.
- Substitution cases include changed receipt version/hash/size/bucket/path,
  run/test/target/category/input digest/verdict, missing or changed journal values,
  ambiguous input/bundle JSON and changed native identity. Comparison cases retain
  valid artifacts while changing endpoint, configuration, safety, credential
  binding/version, actual secret version or runner image; none claim remediation.

## Remaining gates

Wire the scoped persisted run/attempt/journal loader to this verifier, enforce
snapshot chronology and exact attempt association, implement DB-owned link
claim/lease/CAS settlement, join the reconciler in production worker shutdown,
expose before/after UI and verify composed A-D acceptance. Live provider/S3/IAM/KMS
proof and the full release gate remain separate. No production promotion, fresh
UI build, commit or push is claimed. SQL55 is unchanged at
87578080526fe298b7746a292ff8b1c5bceb6e684805972da8d64916cf77f041.
