# Connected fix wave, frozen for review

DONE_WITH_CONCERNS. The three Important integration findings have focused
RED/GREEN and fresh grouped/browser evidence. One visual observation remains:
the 128-character policy ID causes horizontal overflow in the narrow HIPAA
detail screenshot. Root inspected it and requested reviewer triage, not another
UI change or build in this wave.

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.
Branch `codex/cached-runtime-ship-20260917`.
HEAD `8733b16f8d939d38a8157dd2519e57fc6f630542`, unchanged.

No staging, commit, push, ledger edit, new dependency download, image pull/build,
host PostgreSQL, live provider or advisory work. No subagents or review dispatch.
The existing dirty checkout and all earlier task/CI artifacts remain intact.
Only the owned browser's requested local export downloads were performed.

## What changed

Execute candidate discovery now breaks scope ties in claim-admission order:
last claim time, organization, workspace, environment. The per-scope oldest-job
ordinal stays first. Reconcile/cleanup keep their previous age ordering; claim
locks, lease admission and generation checks are unchanged. The new registered
SQL test creates C before B before A, puts two jobs in A, then discovers and
claims with batch1. It requires progress in A/B/C/A order with the oldest A job
first. Three waiting scopes exceed the batch size.

The mounted client now loads SOC2 and HIPAA through two explicitly filtered,
independent cursor chains. The chains run sequentially and share the effect's
AbortSignal. Each chain retains its 20-page/2,000-item bound. The all-framework
view combines their rows; framework/control filtering and exact source/version
links stay in the existing view. Cancellation is checked between pages and
before starting the second chain. Existing late401/409 and scope/principal
replacement tests still pass. The unfiltered server's compatibility default
remains SOC2; the UI no longer relies on it to populate HIPAA.

Compliance now has its own OpenAPI cursor, parameter and page-info contract.
Its maximum is5462 encoded characters, the unpadded base64url size of the
existing4096-byte decoded repository bound: `ceil(4096 * 4 / 3) = 5462`.
The eight JSON fields include three40-character scope IDs, operation, framework,
control and source kind/ID; valid source IDs can be128 characters. Those fields
already produce606-character filtered policy cursors with PostgreSQL JSONB
spacing.512 was insufficient. The Go query cap is now5462 (previously5500),
the dedicated OpenAPI maximum and strict TS page bounds agree, and the unrelated
shared Cursor/PageInfo/decoder maximum stays512. Existing SQL/repository binding
and malformed/foreign cursor rejection are untouched. Generated TypeScript was
regenerated and checked.

The full suite exposed a stale CI contract test: the approved workflow has32
steps, while its old expectation required30. With root approval, I aligned only
that test. Both new compliance steps now have exact command/name/timeout/env
expectations plus14 mutation cases for removal, skips, allowed failure, timeout,
command, environment and order changes. Existing audit/runtime assertions stay;
step lookup uses stable IDs or exact commands where the two added steps shifted
positions. `.github/workflows/runnable-ui.yml` and the approved preflight are
unchanged. The exact OpenAPI parameter expectation also gained the dedicated
compliance parameter.

## Focused evidence

All logs named below are in this directory. Commands used Node22.23.1 at
`/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node`.

| Check | RED | GREEN |
| --- | --- | --- |
| Populated HIPAA mounted client | `connected-fix-ui-red.log`: expected two policy links, got one | `connected-fix-ui-green.log`: both frameworks, independent continuation tokens, HIPAA framework/control filter and exact version link |
| Long compliance cursor | Same RED: schema mismatch at generic512 bound | Same GREEN: maximum policy ID crosses decoder and adapter;5463 refused; generic session decoder still refuses the long cursor |
| Candidate discovery/admission | `connected-fix-sql-red.log`: poll0 discovered unclaimable C, batch1 made no progress | `connected-fix-sql-green.log`: A/B/C/A progress and per-scope oldest order |

Focused UI command, unchanged from RED to GREEN:

```sh
node node_modules/vitest/vitest.mjs run app/features/sessions/SessionsComplianceView.test.tsx apps/web/api/compliance-decoders.test.ts --reporter=verbose
```

RED exit1,2 failures/28 passes. GREEN exit0,30 passes. Other fixtures were
adjusted to return empty HIPAA data when they deliberately model missing HIPAA;
the new populated case returns real typed policy evidence under both controls.

The SQL RED command matched
`^TestCompliance(CandidateAdmissionProgress|HTTPMaximumIDCursor)Postgres$`.
HTTP was an existing-capability characterization: it already emitted and
round-tripped606-character SOC2 and584-character HIPAA cursors for a128-character
policy ID with explicit control filters. The failure was in the public TS/schema
consumer, as the UI RED shows. SQL GREEN also matched
`TestComplianceCompiledFingerprintPostgres`,3/3 passed.

The fingerprint calibration's expected diagnostic failure is retained in
`connected-fix-calibration.log`. I used that owned database observation to update
the compiled release56 fingerprint, then ran the successful readiness test.

## Grouped checks

`connected-fix-checks.mjs` retains the exact grouped commands and environment.
`connected-fix-commands.jsonl` records each spawned command/cwd; each runner log
ends with the joined command's actual exit status. No output-only success claims.

- `connected-fix-go-enumeration.log` enumerates the exact nonSQL/nonprocess
  test names before host race. `connected-fix-go-race.log`: exit0,27 top-level
  tests across apiserver, worker, API composition/configuration and migration
  command/readiness. SQL and process helpers were excluded from host execution.
- `connected-fix-sql-group.log`: exit0,25 top-level tests passed. One parent-only
  helper reports an intentional standalone skip; its parent launches the fresh
  process during the test. The group includes registered source authority,
  release/readiness, all original source families, scope/filter/cursor rejection,
  capture overflow, quotas, post-wait authorization, grants, historical frozen
  bytes, response loss/restart, lease loss, reconciliation and exact-version
  cleanup. Database servers and worker subprocesses all join in the log.
- Node group initially had144 pass,1 fail,2 existing opt-in cleanup skips.
  The only failure was the new OpenAPI parameter absent from its exact expected
  object. `connected-fix-openapi-contract-green.log` reruns that amended scope:
  23/23 pass, exit0. Other group results are reused by unchanged identity; there
  was no second whole Node-group run. `connected-fix-node.log` retains the
  original diagnostic, including the144 successful tests.
- Initial full UI:180 failures in the stale CI contract,1918 passes.
  `connected-fix-ci-contract-green.log`:264/264 passed after its test-only fix.
  Final `connected-fix-ui-accepted.log`:224 files,2112 tests passed, exit0.
  That is the historical2096 plus2 defect regressions and14 CI mutation cases.
- `connected-fix-types.log`, `connected-fix-lint.log`,
  `connected-fix-harness-lint.log`, `connected-fix-build.log`,
  `connected-fix-openapi-check.log` and `connected-fix-openapi-lint.log` all exit0.
  The full UI joined before the production build completed. Browser started
  after every build/check handle joined. A pre-browser self-review corrected
  only the harness's new link-count selector from textContent to aria-label;
  final harness lint passed, and the actual run uses that corrected selector.
  Application/build inputs did not change after the build.

Go environment throughout:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache
```

Offline Go executable: `/opt/homebrew/bin/go`. SQL binaries were cross-compiled
with `GOOS=linux GOARCH=arm64 go test -C services/platform ./apiserver -c` into
`/private/tmp/zasp-compliance-connected-{red,calibrate,green}.test`; the worker
binary is `/private/tmp/zasp-compliance-connected-worker.test`.

The final SQL container command was:

```sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-connected-group --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-connected-green.test,dst=/compliance.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-connected-worker.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /compliance.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestCompliance' -test.v -test.timeout 240s
```

RED/calibration/GREEN used the same owned cached-container configuration,
matching named binaries and the focused patterns above (90s,60s,90s bounds).
Each container was removed by `--rm`; no other container was stopped or removed.

## One actual browser run

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache
ZASP_COMBINED_E2E_COMPLIANCE=true node scripts/production-combined-e2e.mjs
```

Exit0. `connected-fix-browser.log` is the complete combined output.
Original evidence is `/tmp/zasp-compliance-browser-cr1rud`; its retained copy is
`connected-fix-browser-artifacts/`, with byte sizes/SHA256 in
`connected-fix-browser-artifacts.json`.

The actual mounted adapter consumed102 policy records per framework, including
101 owned128-character paging IDs. Both framework cards contained the last ID.
Proxy traces show successful actual continuation requests with576-character
SOC2 and566-character HIPAA cursors. The fixture then selects HIPAA / Policy
definitions, opens the last policy, and checks exact source ID/version7 in the
URL plus the stale source timestamp/detail. The strict TS decoder and real
multi-page adapter are in this path; no invented short cursor or substituted
response is used.

Only those101 paging fixture rows are deleted in the owned database before
export, then the page reloads. The export's100-record/control cap is unchanged,
as are the assertions requiring exactly the original one policy record/version7
in exported bytes. This separates read-pagination coverage from bounded export
capture; it does not relax the export limit. The deleted fixture rows existed
only in the disposable database, and their recipe remains in the harness.

Job `pid_a0070dfe-d2af-432f-b205-e2f9522546e1`.
Frozen package SHA256
`44943bd056f9790b28be2f200724d92f6861800c3c4821988fd83915649b21ab`.
Native JSON760 bytes, CSV568, readable770. Each matches its exact persisted
member, with JSON extraction preserving native bytes. Worker interrupt/resume,
API restart/reload recovery, source-version change, grant replay refusal,
independent foreign404, sibling404 and successful authorized reads remain
asserted. All six session checkpoints have bootstrap200, the expected principal
and scope, no sign-in fallback and empty console-error kinds.

Both screenshots were visually inspected. The final1200x900 screenshot shows
Staging, current policy version8 and a visible export action. The narrow HIPAA
detail shows source version7, stale timestamp and definition_only metadata, but
its long unbroken ID overflows horizontally. That observation is unresolved.

## Pins, files and cleanup

`connected-fix-blobs.json` lists15 captured paths:13 changed plus the unchanged
release56 up/down templates. `connected-fix-scoped.patch` is an incremental
BEFORE-to-AFTER patch, never a broad HEAD diff. Reverse apply `--check` passed.
Fresh BEFORE bodies are in `connected-fix-before/`. The two test-only contract
files were captured before editing when the grouped checks exposed their stale
expectations.

Changed files: compliance job fragment and release fingerprint; the new
`compliance_connected_postgres_test.go`; compliance HTTP query bound;
SessionsComplianceView and its mounted-client test; administration decoder and
compliance decoder tests; OpenAPI schema/exact-root test/generated TypeScript;
browser harness; runnable-ui workflow contract test. No source edit follows the
frozen manifest.

Release56 uses the existing `ProductionCompliance()` fragment expansion and
checksum mechanism. Its emitted SQL is saved as
`connected-fix-compiled-release56.up.sql` / `.down.sql`; the template files need
no textual replacement. `connected-fix-pins.log` records:

```text
56 checksum f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1
56 fingerprint 8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced
55 checksum 01920b296d2ebbc4b84c6e714edaf50d6265d630e577bd26297755a15289fa00
55 fingerprint 2c324e78917f97feee14f915b397efbb92a183d47afd7473139dd0691cf0bb04
55 up blob 7b70f6493e3e5a0b4fe06d6d6c1e033a85e1a192
55 down blob c3514105cdc9fcc1353dadd577d1b1eea06721a4
```

`connected-fix-before-browser-identities.json` and
`connected-fix-after-identities.json` match4720 source/build files exactly.
`connected-fix-reused-identities.json` reconciles all95 previous reviewed file
identities,84 unchanged. Unchanged formatter/storage/provider and CI evidence
is reused only for those identities; the changed assembled path has fresh SQL,
race, UI/build and browser evidence above.

Every tool session joined:17283,95061,26223,88852,61670,89309,41893,54422,7566,
3237,42663,59529,31197,91536,54231,43698. The intentional RED/calibration/initial
contract failures are preserved. There is no active task process or container.
Final process inspection found no agentsec API/worker, vinext or combined harness;
the Docker inventory retains the same unrelated voxeval and old exited daemon
containers observed before the wave. Local compiled binaries/logs remain as
evidence; the browser's owned transient runtime directory was cleaned by its
existing cleanup path.

## Self-review and remaining gates

I checked the candidate ordering against claim scope ordering, the independent
framework cursor state and abort propagation, the unchanged generic cursor
bound, and the browser fixture's removal before bounded export. The original
denial/native-byte/continuity assertions remain. The approved CI workflow was
not modified to make its stale contract test pass.

The receiving-review, systematic-debugging, TDD and verification skills guided
the source checks, observed failures and evidence checks. Execution stayed in
the existing isolated worktree under the approved design/plan. Root owns the one
scoped independent re-review and any publication decision.

This is controlled local SDK transport, not live AWS. Hosted Linux execution,
approved advisory, deployed IAM/KMS/lifecycle/TLS, live-provider, scale and
production acceptance remain separate gates. No original728 obligation is
closed or reduced here. Review the frozen patch and triage the narrow-ID overflow.
