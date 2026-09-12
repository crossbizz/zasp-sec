# Precise browser acceptance implementation plan

> For agentic workers: use superpowers:subagent-driven-development or executing-plans, test-driven-development and independent review for each task.

Goal: verify fresh precise worker-written evidence through the actual product
API and browser, including real pending/current search status.

Architecture: extend the owned combined harness with a dedicated precise-browser
branch. Pause its real provider proof after completion/queue acknowledgement and
before precise target2 indexing. Start the existing API/web/TLS/auth/browser
stack, observe pending state, release indexing and inspect current evidence.

Tech stack: Node22.23.1, Go, PostgreSQL18, existing owned S3/KMS/SQS/OpenSearch/
TLS-Neo4j dependencies, built vinext app and the existing Chrome/CDP harness.

Spec: `2026-09-11-precision-delivery-finalization-plan.md`, steps4-7, and
`2026-09-11-process-precision-finalization-plan.md` composed-browser requirement.

## Constraints

- Preserve all728 original tasks and all existing provider assertions/markers.
- New `ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER=true` requires runtime-only,
  sandbox-search and precision flags all exactlytrue. Reject before allocation.
- Never run the broad historical-count browser suite in this new branch.
- No migrations, public API contract changes, receipt rewriting or seeded runtime
  successes. Only existing declared authentication/session fixtures are allowed.
- Public `at` is canonical event_time. Compare its event_time/event_id order;
  source nanoseconds distinguish correlation inputs, not public timeline time.
- Do not pause a leased stage. Checkpoint only the precise batch after coordinator
  acknowledgement and before target2 index RunOnce.
- Preserve bounded child/signal cleanup. No live cloud or customer sensor claim.
- Commit/publication follows whole-change review, fresh verification and the
  remaining serialized rollout gate; these tasks alone don't authorize a push.

## Task1: Owned checkpoint and explicit mode

Files: create `scripts/runtime-precision-browser-proof.mjs` and
`scripts/runtime-precision-browser-proof.test.mjs`; modify
`scripts/production-combined-e2e.mjs`, its test file and
`services/platform/agentsec-worker/runtime_precision_combined_e2e_test.go`.

Interface: the new module exports `validatePrecisionBrowserMode(env)` and
`createPrecisionBrowserCheckpoint()`. The latter returns an owned loopback
endpoint, random token, `waitReady()`, single-use `release()` and idempotent
`close()`. Metadata comes from actual ingested batch/event/evidence IDs, scope,
session/agent and expected bound/unknown identities in the Go proof. Close the
metadata schema to these needs; never pass credentials or raw runtime artifacts.

- [x] Add explicit flag tests including browsertrue with each prerequisite
  missing or misspelled. Before implementation, the true browser mode must fail
  its missing capability test; preserve legacy combinations.

```js
assert.throws(() => validatePrecisionBrowserMode({
  ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER: "true",
}), /precision browser/);
```

- [x] Implement the one-shot checkpoint with a random bearer token on an
  ephemeral127.0.0.1 listener. Reject wrong token, unknown method/path, duplicate
  checkpoint, malformed/oversized metadata and release before readiness. Bound
  waiting for readiness to300seconds and release to90seconds; terminate cleanly
  on cancellation. Cap both by the remaining inherited Go deadline (currently
  420seconds within450/460second outer limits), never extending the provider
  deadline. Do not allow the endpoint to choose a database/tenant mutation.
- [x] Exercise wrong token, duplicate release, timeout, caller disconnect and
  close-before-ready against real loopback HTTP. Assert every waiter settles and
  the port closes. Before release, aborted browser acceptance must fail the
  paused provider. After release, the provider may already have passed: any
  later browser failure must fail the parent and suppress the new browser
  success marker without misrepresenting the completed provider result.
- [x] Add the Go checkpoint hook only when the new explicit mode is enabled,
  after the precise batch's catching_up assertion and before its index RunOnce.
  Use the inherited test context, bounded HTTP, exact token and closed metadata;
  validate the release response. Restrict the client to the owned loopback
  endpoint and disable redirects. Legacy provider mode doesn't contact the gate.
- [x] Start the provider command asynchronously in the parent, retaining the
  existing timeout/PASS/no-skip checks and a catch handler from creation. On any
  failure, settle/close every gate waiter before joining children, then run
  existing owned signal/child cleanup.
- [x] Run focused Node tests and Go fixture/flag races, then independent review.

Task1 review closed after a cleanup-order correction. A failed checkpoint close
or provider join previously prevented other cleanup. The actual cleanup function
now attempts every owned boundary, retains original errors and keeps its temporary
root on failure. Root repeated46 Node tests passing with2 existing opt-in container
cleanup skips in2.061s; focused Go checkpoint races passed2.301s. Independent
review accepted Task1 and repeated the7 failure-injection checks in53.7ms.
CI and the combined npm command now invoke the checkpoint tests. At this Task1
checkpoint Task2 remained open. The later Task2 proof2555 below supersedes that
status; Task1 alone does not prove product API/browser acceptance.

## Task2: Real API and browser acceptance

Files: the same new browser module and parent harness/tests. Reuse existing
`startBrowser`, `browserFetchJSON`, `waitForBrowserText`, `reloadBrowserPage`,
API child, web child, TLS proxy and authentication helpers. Extract the existing
API environment construction only as needed so the new branch selects
`ZASP_RUNTIME_SESSION_INDEX=zasp-runtime-sessions-v2` without changing old mode.

- [x] Test the runtime proxy's fixed additional allowlist against an owned
  HTTP engine: GET target2 `_mapping`, GET target2
  `_doc/_zasp_session_schema_v2`, POST target2 `_search`. Other target2 paths,
  methods and writes must not reach it. Preserve target1 and unrelated policy
  fixtures. Run RED before enabling these routes.
- [x] At checkpoint readiness, start the actual product stack and authenticate
  through the existing callback/cookie flow. Select Staging using the main
  principal's existing permitted scopes. Require a fresh session after the
  provider setup delay. Do not manufacture API runtime responses.
- [x] Through HTTP and visible UI, assert search catching_up and the actual
  'Indexing is catching up' badge. Release the checkpoint once. Await every
  existing provider success marker and no skips, then reload and assert current.
- [x] Open the bound event's timeline and evidence dialog using actual IDs from
  the checkpoint. Assert Strong, exact retained sandbox/source sensor and no
  Exact upgrade. Inspect the unknown collection across pagination until the fresh
  unknown event is found; require unattributed/unknown sandbox and absent source.
- [x] Compare displayed event IDs/order against canonical persisted event_time/
  event_id order, including historical rows. Check wrong-investigation and
  actual foreign-tenant denial. Reuse the isolated identity/session fixture
  pattern; delete only those owned identities in finally. Scope change must
  close the old evidence drawer. Runtime evidence snapshots must stay unchanged.
- [x] Require clean browser exceptions and the new marker
  `runtime precise browser proven:` in addition to all provider markers. Run the
  real missing-hook/assertion failure before declaring the completed integration
  green. If fixtures fail first, diagnose them without weakening product guards.
- [x] Run the final owned proof with all four flags, Node22 and PG18 on PATH:

```sh
ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER=true \
ZASP_COMBINED_E2E_RUNTIME_PRECISION=true \
ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY=true \
ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH=true \
node scripts/production-combined-e2e.mjs
```

- [x] Review the implementation and observed output independently, run fresh
  root verification, record exact cleanup/results and update the authoritative
  ledger without awarding live deployment or original task publication credit.

Self-review: covers pending/current, actual authentication/API/browser, bound and
unknown identity, pagination/order, tenant denial, unchanged evidence and cleanup.
It intentionally does not establish source-time display, customer sensor
activation, cloud IAM or serialized live rollout authorization.

Task2 actual run2555 exited0 on September12 against the completed root50910
build. Its exact terminal-output chunk0d3949 is preserved in
[precision-browser-2555-terminal.log](evidence/precision-browser-2555-terminal.log).
Every provider marker and the new browser marker passed; the parent required Go
PASS with no skips. Browser console/exception checks stayed clean and owned
cleanup reached file removal. This isolated mode did not run the historical-
count browser branch. No runtime success was seeded.

The missing browser implementation first failed actual run72521. Subsequent
runs99412,71249 and57484 exposed historical inventory readiness, offset-time
string comparison and omitted optional sandbox-field assumptions in the harness.
Each had a reproduced regression and independently reviewed correction. The
actual API/decoder contract stayed unchanged: precise unknown agent/session are
null, sandbox keys are absent, and visible times retain API bytes. Final Node
tests passed53 with2 pre-existing opt-in cleanup skips; lint passed. The final
review/root-verification/ledger checkpoint is now complete: root read the exact
terminal output, independently reviewed each runtime correction, and ran fresh
full verification11329 to exit0 (197 UI files/1243 tests, typecheck/lint,93 release
tests, production build and compiled imports). The authoritative ledger records
the local browser pass without changing any original task row. No live deployment
or publication credit.
