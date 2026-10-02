# Legacy compliance compatibility

DONE_WITH_CONCERNS, frozen for root's independent scoped review. Legacy
compatibility and the discovered legacy timestamp seam have focused RED/GREEN,
fresh grouped checks, and a passing assembled disabled-to-enabled browser run.
The only noted visual concern is the previously recorded Minor long-ID overflow.

Worktree `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`,
branch `codex/cached-runtime-ship-20260917`, HEAD
`8733b16f8d939d38a8157dd2519e57fc6f630542`.

## Scope and selected signal

The registered handler emits strictly decoded `control.freshness`; the retained
administration controls omit it. Existing bootstrap capabilities represent
permission to read compliance, not installation of its complete service. Adding
a capability would expand the public contract without improving this bounded
compatibility decision. The view now loads controls first, classifies the whole
validated set, and explicitly passes a read mode to the evidence adapter:

- All controls current: independent SOC2 and HIPAA chains, preserving the
  20-page/2,000-record bound per chain and dedicated long-cursor contract.
- All controls legacy, or empty controls: one unfiltered cursor/limit chain.
  Empty data cannot assert installed current-service support or enable exports.
- Mixed controls: fail before reading evidence, with the existing generic error.

No mode is cached, inferred from a read failure, or carried across principal,
scope, generation, or component lifetime. The effect checks abort/current
authority after controls; the shared pager checks abort before and after every
request, including before the next framework. Current authentication error
handling remains in the API client. Legacy cards retain the explicit unavailable
current-freshness label and do not expose export creation.

The assembled disabled-service browser found a second legacy compatibility seam:
retained SQL embeds PostgreSQL timestamps as RFC3339 `+00:00`, while the newer
record decoder accepted only `Z`. A real mounted trace showed successful200
controls/evidence with no framework query, followed by decoder failure. The exact
retained SQL was then executed in a fresh cached owned PostgreSQL container;
`legacy-compatibility-wire.json` captures the offset result. Its container joined
and was removed. Only untargeted legacy records now accept valid RFC3339 offsets.
Calendar and offset validity are checked separately; the original wire value is
preserved. Typed current records, detail, jobs, and grants remain Z-strict.

No SQL, schema, registration, storage, public API, migration pin, export cap, or
query allowlist changed. The three connected-wave findings remain closed.

## Focused RED and GREEN

All artifact names in this report are relative to this plan directory.

`legacy-compatibility-red.log`: real API client/adapter against retained strict
cursor/limit contract, exit1,7 failed/23 passed. Failures covered populated legacy
reads, empty/mixed mode selection, and evidence started after controls errors.
`legacy-compatibility-green.log`: exit0,4 files/60 tests passed, including expanded
controls/SOC2/HIPAA first/continuation-page scope/principal cancellation and late
401/409 authority protection.

The first actual legacy browser failed (`legacy-compatibility-browser.log`). A
diagnostic-only rerun retained the successful200 trace in
`legacy-compatibility-browser-diagnostic.log` and
`/tmp/zasp-compliance-browser-U6gmFZ/legacy-failure-trace.json`. Both runs joined
cleanup before further work. No production change was made from an assumed cause.

`legacy-compatibility-focused-timestamp-red.log`: exit1,2 failed/59 passed. The
adapter fixture and decoder regression now use the real PostgreSQL offset form.
`legacy-compatibility-focused-timestamp-green.log`: exit0,61 passed. Additional
final assertions reject invalid offset minutes, current list/detail offset
timestamps, and job/grant offset timestamps. Final full UI includes these.

Focused commands:

```sh
node node_modules/vitest/vitest.mjs run app/features/sessions/SessionsComplianceView.test.tsx --reporter=verbose
node node_modules/vitest/vitest.mjs run app/features/sessions/SessionsComplianceView.test.tsx apps/web/api/compliance-decoders.test.ts apps/web/api/pagination.test.ts app/features/sessions/compliance-api.test.ts --reporter=verbose
```

## Grouped verification

`legacy-compatibility-checks.mjs` stores the command/environment runner;
`legacy-compatibility-commands.jsonl` records exact commands and working
directories. Logs end with actual joined exit status. Node22.23.1 is
`/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node`.

- Go enumeration preceded race. Only `TestComplianceStorageFactoryBoundary`,
  `TestComplianceAPIProductionComposition`, and `TestComplianceAPIConfiguration`
  ran on the host. No SQL/process helper ran there. The first composition fixture
  matcher also matched the controls query's evidence subquery, causing two test
  failures. Narrowed that test-only matcher to its JOIN form; retained the failed
  log. `legacy-compatibility-go-race-corrected.log`:3 top-level tests passed,
  including installed/disabled/absent/unregistered modes. Disabled/absent read
  populated legacy records but reject framework queries400; installed controls
  have authoritative freshness and both framework requests succeed.
- Initial full UI224 files/2,135 tests passed; types/lint/harness lint/build and
  Node107 passed/2 opt-in skips before the browser discovered the timestamp seam.
- `legacy-compatibility-ui-final.log`:224 files,2,136 tests passed, exit0.
  This adds24 cases to the connected-wave2,112, including expanded cancellation.
  `legacy-compatibility-types-final.log`, `legacy-compatibility-lint-final.log`,
  `legacy-compatibility-harness-lint-final.log`, and
  `legacy-compatibility-build-final.log` all exit0.
- `legacy-compatibility-node-final.log`:107 passed,2 opt-in skips, exit0.
  The skips are existing opt-in real SIGTERM combined-runtime/Red-Team cleanup
  cases, not compliance tests. No SQL or Go suite was repeated for the TS-only
  timestamp correction. The final browser began after all grouped handles joined.

Go uses `/opt/homebrew/bin/go` with `GOTOOLCHAIN=local`, `GOPROXY=off`,
`GOSUMDB=off`, `GOCACHE=/private/tmp/zasp-budget-go-cache`.

## Final assembled browser and cleanup

`legacy-compatibility-browser-final.log` exits0. The real API initially runs with
all compliance export configuration absent, preserving retained composition.
The mounted legacy card displays membership evidence, its original offset
timestamp, and `Legacy evidence (current freshness unavailable)`. No export
action appears. The real unfiltered evidence response is200, and an explicit
framework probe remains400/invalid_request. Screenshot inspected:
`legacy-compatibility-browser-artifacts/compliance-legacy.png`.

The API then restarts with complete service configuration and the same signed-in
browser reloads. Current SOC2/HIPAA chains return populated evidence, including
actual576/566-character cursors for maximum128-character IDs. The HIPAA control
filter and exact version7 link work. All101 owned paging fixture records are
removed before the original export assertions; the100-record/control export caps
are untouched. Native JSON/CSV/readable bytes, worker interruption/restart,
API restart, source change, grant replay denial, sibling/foreign denial, and
signed-in continuity all pass. There are7 continuity checkpoints: the6 original
current-service checks plus the initial disabled-service check.

Job `pid_32190dad-400a-404f-a186-454101f95969`;
packageSHA256 `610b99247d95213f67fde8dea6f1cbdf642012fa61f986608ff2759c342de5d0`.
Native JSON760 bytes, readable770 bytes; CSV is compared exactly with the frozen
package by the unchanged assertion. This is controlled local SDK transport, not
live AWS. Artifacts remain at `/tmp/zasp-compliance-browser-vdFoCp` and are copied
to `legacy-compatibility-browser-artifacts/`.

Browser handle27460 joined exit0. All earlier handles (including both failed
browser runs and diagnostic SQL) also joined. The final log records browser,
API, web, proxy, identity/policy fixture, PostgreSQL, remaining process and
temporary file cleanup. `legacy-compatibility-cleanup.json` records no remaining
owned browser PostgreSQL containers or matching fixture processes. Existing
voxeval and unrelated stopped replay containers were not altered. Retained
evidence files are deliberate; owned ephemeral fixture records/databases were
removed by cleanup and are reproducible from the harness.

`legacy-compatibility-before-browser-final-identities.json` and
`legacy-compatibility-after-final-identities.json` match across4,720 source/build
files. All97 prior reviewed identities match their captured BEFORE or unchanged
current version;88 remain unchanged. The extra changed reviewed file is the
legacy record decoder. `legacy-compatibility-reused-identities.json` records each.
HEAD is unchanged. Reverse-apply validation and scoped whitespace checks pass.
PatchSHA256 `41c988dd92b8808a80b3a36835edf771bc309ece26069556fec99b4ecbed54b4`.

## Incremental files and self-review

Nine scoped source/test files changed:

- `app/features/sessions/compliance-api.ts`: explicit validated read-mode helper.
- `app/features/sessions/ComplianceEvidenceView.tsx`: controls-first mode decision.
- `app/features/sessions/SessionsComplianceView.tsx`: explicit adapter read mode.
- `app/features/sessions/SessionsComplianceView.test.tsx`: adapter/legacy/mixed/
  empty/auth and expanded chain cancellation coverage.
- `apps/web/api/compliance-decoders.ts`: legacy-only RFC3339 offset validation.
- `apps/web/api/compliance-decoders.test.ts`: wire regression and strict-current
  negative controls; existing long-cursor test passes explicit current mode.
- `services/platform/agentsec-api/compliance_composition_test.go`: real composed
  handler disabled/absent/current query contract and response authority checks.
- `services/platform/agentsec-api/compliance_browser_process_test.go`: explicit
  test-only legacy fixture guard; disabled service cannot call storage factory.
- `scripts/production-combined-e2e.mjs`: actual disabled-to-enabled acceptance.

Self-review traced the validated response signal, abort-before-request pager,
mode lifetime, generic errors, legacy freshness/export truthfulness, and strict
current timestamps. It also checked the retained handler's strict allowlist,
installed handler's both-framework control, and unchanged export/download/denial
assertions. No error-driven compatibility retry or capability cache exists.

## Reused evidence and constraints

Unchanged SQL/storage evidence is reused from `connected-fix-report.md`, including
25 SQL top-level passes and27 enumerated Go race tests. Source identity checking
includes earlier task manifests, CI, and connected-fix manifests. Release56
checksum remains `f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1`;
fingerprint `8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced`.
Release55 checksum remains
`01920b296d2ebbc4b84c6e714edaf50d6265d630e577bd26297755a15289fa00`;
fingerprint `2c324e78917f97feee14f915b397efbb92a183d47afd7473139dd0691cf0bb04`.

Fresh BEFORE snapshots and incremental AFTER blobs/patch are named
`legacy-compatibility-before/`, `legacy-compatibility-before.json`,
`legacy-compatibility-blobs.json`, and `legacy-compatibility-scoped.patch`.
The decoder's BEFORE was appended before its first edit. No broad HEAD patch.
Earlier connected-fix artifacts are untouched.

No staging/index mutation, commit, push, ledger change, subagent/reviewer
dispatch, dependency download, image pull/build, host PostgreSQL, live-provider,
or advisory call. Browser output uses the existing controlled local SDK transport,
not AWS. The user-requested browser export files are retained local artifacts.
Unrelated inherited work and voxeval containers remain untouched.

The narrow128-character-ID detail overflow is the already recorded Minor
follow-up. No visual redesign was performed. Hosted/Linux/advisory/live-provider/
deployment/scale/production gates remain outside this local compatibility proof.
