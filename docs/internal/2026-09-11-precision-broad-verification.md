# Broader verification, local gate passed; release incomplete

The first section records the earlier broad run. Later corrections and focused
verification are recorded below; they do not turn that failed run into a pass.

`npm run verify` ran with Node22.23.1 and PostgreSQL18 on PATH. Dependency checks,
service health, API contract/lint/generation, UI/API coverage, tenancy/RLS and
graph package checks passed. All197 UI test files and1238 tests passed, followed
by typecheck, lint and the44-file production source import check.

The run then failed at `deploy/staging/gate.test.mjs`: the embedded latest schema
is51, while the deliberate rollout contract expects50. This is a real missing
release deliverable. Do not merely change the expected number. Schema51 needs
explicit compatibility/worker/producer phases and their resource checks before
the staging gate can pass. Later root-verification steps were not reached.

The final-pin full precision PostgreSQL suite is running separately. A read-only
end-to-end audit also confirmed `decodeRuntimeDeliveryJob` in the queue coordinator
still rejects payload_schema other than runtime-event-v1. Explicit precision
coordinator routing is required before fresh V2 batches can traverse all workers.
These gates remain open; no publication or original task credit.

## Current follow-up

Explicit precise coordinator/outbox selection and both51 chart phases now exist
and have scoped reviews. Full actualPG precision races on semantic fingerprint
f22c0461b7ae0610e184e439c2c8b42fc2136ef5e293dc66b99faf01af7d9fdd passed384.915s;
the final cached-body/post-wait controls passed13.776s. The first complete local
provider run passed, but review requested fresh legacy-search queue isolation
and historical provider preservation assertions. Stronger provider acceptance
and release orchestration remain pending.

Fresh root Node22 verification after the intake observer change:

- `npm test`:197 files/1238 tests passed28.29s.
- `npm run build`:all five vinext build phases passed; standalone output exists.
- `npm run typecheck` and `npm run lint`:exit0.
- `git diff --check`:exit0.

These are current UI/build checks, not browser acceptance against the precise
backend, a complete root `verify` pass, or a production deployment. The staging
latest-schema gate and serialized rollout/provider evidence still need closure.

UI precision boundary follow-up: the historical projector can retain Exact
Tetragon records, while the precise projector/receipt rejects Exact. The public
event shape does not expose receipt version, so a blanket decoder rejection
would incorrectly reject historical evidence. No production decoder change.
A coverage-only test now decodes and renders two bound Strong events at
.123456788Z/.123456789Z with IDs ordered opposite to their timestamps. It checks
nanosecond ordering, reversed-page refusal and exact visible/datetime strings.
The two affected test files passed102 tests in1.30s. Independent review found no
issues and repeated the sandbox file's51 tests in1.14s;
this is component rendering evidence, not a browser connected to live providers.

The staging manifest gate has now been updated after the six actual rollout
phases were implemented and reviewed. It renders48/49 compatibility,50
backfill/query and51 consumers/intake; asserts51 intake, dual delivery and every
stage selector; retains default49 and rejects unknown/mixed selections. The
original51-vs50 failure was reproduced before this update. Staging/preflight
tests passed7/7 in2.340s. This is source-manifest compatibility, not serialized
live transition authorization. Independent review found no issues and
repeated7/7 in2.113s.

A new complete `npm run verify` with Node22/PG18 finished as session85568,
exit0. Dependency/health/API checks, tenant/RLS and graph checks,197 UI files with
1239 tests, typecheck/lint, source import checks,7 staging/preflight tests,
83 release tests, production build, compiled imports and the728-row ledger all
passed. UI tests took31.46s; release tests took13.779s. Compiled imports checked
7 client and8 server chunks. The earlier failed run remains historical evidence;
this is a distinct successful run after the manifest contract was implemented.

This gate does not run the entire precision PostgreSQL suite or actual provider
harness; their separate results remain necessary. Browser acceptance, serialized
live rollout enforcement and whole-change publication review are still open.

Post-verification executable audit found a launch blocker that the render gate
does not exercise: schema51 emits `agentsec-migrate up-to-51`, but main.go lacks
that dispatch and its runner-interface method. The library migration exists.
The CLI fix and actual executable PostgreSQL regression are now assigned.
The root verify pass above remains accurate for its scope, not proof of a
working schema51 migration job or a deployable release.

The CLI implementation now passes a focused built-executable PostgreSQL run;
see `2026-09-11-precision-cli-evidence.md`. A separate CI audit found that its
required apiserver selection omitted TestRuntimePrecision. A new workflow test
first failed on that exclusion; the filter now includes Precision and all24
workflow tests pass. Go test listing confirms49 precision test functions are
selected. The combined historical/precision actualPG scope is running as46102;
its result and timeout suitability are not yet known. Independent CI review
is pending. No remote CI run or push has occurred.

CI review accepted selector coverage but found the combined package's implicit
10minute timeout too short: retained separate Precision/Sandbox runs totaled
745.724seconds before other tests. A new assertion reproduced the absent timeout.
The complete selection now has an explicit30minute package bound. The original
combined run46102 retains its original10minute limit; it is not restarted merely
because output is quiet. Its terminal result and a final bounded-scope run remain
pending. This is timeout headroom, not removed test coverage or remote CI proof.

CLI51 closure: the full migration-command package passed77.613s after stale
unknown-command sentinels moved to52. Final owned-process/PG-environment fixture
coverage passed10.002s; root source review has no remaining scoped finding.
This resolves the missing-command implementation blocker, not the remaining
serialized live migration/cutover authorization or deployment attestation.

The original combined actualPG run46102 terminated at the implicit10minute
limit, exit1 after600.867s, during sandbox readiness setup. It is a timeout,
not a passing suite. A process check found no surviving apiserver/initdb/test
PostgreSQL process matching that run. The same complete selection is now running
with explicit30minute timeout as5115. No coverage was removed. Independent
review accepted the timeout correction and repeated24 workflow tests in1.03s.

The subsequent source audit rendered both51 phases and traced real executable
dispatch for ingest, workers, API target2 and customer-edge source v3. No further
unsupported selector or missing constructor wiring was found in that scope.
This does not test live manifest-fed startup, admission or rollout authorization.

The new precise-browser checkpoint test file is now explicitly invoked by CI
and the combined acceptance npm command. A new contract test first failed on
the missing invocation; all25 workflow checks then passed720ms. Root repeated
the combined/checkpoint Node tests:39 passed,2 existing opt-in container cleanup
tests skipped,2132.743ms. Independent checkpoint review found a cleanup ordering
bug on provider join failure, which must be fixed before Task1 approval. The real
browser branch remains fail-closed pending Task2; these tests are not browser
acceptance or remote CI evidence.

Task1 cleanup review is now closed after a reproduced failure and fix. Root
repeated46 passing Node tests with2 existing opt-in cleanup skips in2.061s,
plus Go checkpoint races in2.301s. Independent review repeated7 injected-cleanup
checks in53.7ms and approved the checkpoint slice. Actual API/browser acceptance
is the next implementation step; the full database run5115 remains separate.

The complete historical/precision actualPG selection5115 has now passed,
exit0 in914.702s, with the reviewed explicit30minute timeout. PostgreSQL18 tools
were on PATH. This is the exact expanded required-CI selection, including all
TestRuntimePrecision functions and the existing runtime/sensor/reconciliation
groups. It is a local pass, not a remote CI run or a whole-repository Go suite.
The earlier600.867s timeout remains a failed run; no tests were removed to obtain
this later pass. Browser acceptance and serialized rollout work are still open.

Fresh full root verification13229 on September12 exited1 at lint. Dependency,
health, API, tenancy/RLS and graph checks passed, followed by197 UI files with
1241 tests in25.36s and typecheck. ESLint rejected the new browser checkpoint's
intentional control-character regex (`no-control-regex`). The implementation
owner is correcting the expression without weakening sandbox-ID validation.
Later source-import, release and build steps were not reached in this run.
This is a failed full verification run despite its passing earlier checks.

The corrected full root run50910 completed with exit0. It passed dependencies,
health/API/tenant/RLS/graph checks,197 UI files with1241 tests in25.32s, typecheck,
lint, source import checks,7 staging/preflight tests,87 release tests in15.231s,
all five production build phases, compiled imports (7 client/8 server chunks)
and the728-row ledger. Browser proof99412 then started against the completed
build and reviewed harness; its result is pending. No remote CI or push occurred.

After that full run, a new workflow assertion reproduced omission of the
cutover package's own tests. Required CI now includes `./internal/sandboxcutover`
alongside the migration packages; both exact command-contract fixtures were
updated. Focused workflow tests passed26/26 in1.64s. This later CI-only change
was not part of the earlier full run. Main was re-read and remains
6f0a93cccc4e68119af5956a5e0ad4b4fcc3e719.

Actual browser run99412 exited1 after successful authentication because its
readiness check expected the historical "Support agent" inventory row. The
runtime-only fixture has no inventory rows. The correction waits for the real
authenticated Production scope, retaining callback-cookie and fresh-session
database checks; it does not seed inventory or change product authorization.
The new regression reproduced the old selector failure and root independently
passed it in62.203ms, including missing-cookie/stale-session refusal. Full Node
tests passed52 with2 existing opt-in cleanup skips; focused lint passed.
Actual run71249 exited1 after the pending API/UI checks and all unchanged provider
success markers passed. The browser identity helper compared equivalent RFC3339
timestamps with different timezone offsets as strings. The correction compares
nanosecond instants while retaining exact UI/API byte comparisons and UTC-only
checkpoint metadata. Root independently passed4 focused controls in61.467ms;
full Node tests passed53 with2 existing opt-in cleanup skips, and lint passed.
Run57484 also exited1 after provider success, because its helper expected null
sandbox fields for an unknown event. Actual API tests and the UI decoder require
both optional keys to be absent. The corrected helper retains null agent/session
requirements and explicitly rejects either present sandbox key, including null.
Root independently passed the focused positive/negative controls in54.663ms;
full Node tests passed53 with2 existing opt-in cleanup skips, and lint passed.
Run2555 then exited0 against the same completed build. Its exact terminal-output
chunk0d3949 is stored in
[precision-browser-2555-terminal.log](evidence/precision-browser-2555-terminal.log).
Actual fresh callback/API/UI pending-current checks, Strong sandbox and unknown
evidence, canonical ordering, tenant denial, clean browser errors and all
unchanged provider markers passed. Owned cleanup completed through file removal.
The file records that final tool-output chunk, not a reconstructed summary or
the complete buffered Go transcript. The harness's PASS/no-skip validator passed.
Earlier runs remain failures with cleanup completed. This is the isolated precise
browser mode, not a rerun of the broad historical-count browser suite or a new
full root verify pass. Live sensor/cloud attestation, serialized rollout and
publication remain separate.

After run2555, root independently read its exact terminal-output file and completed
fresh full verification11329, exit0. The log is
`/tmp/zasp-precision-final-root-verify.log`. All197 UI files/1243 tests passed in
25.17s; typecheck, lint, source imports44files, staging gates,93 release tests
(14.900s), all5 production build phases and compiled imports7client/8server chunks
passed. The ledger checker still reports728 rows,536 production-available,
131 component-only,61 blocked/external,0 missing. Nothing is staged or newly
pushed; read-only remote main remains6f0a93cccc4e68119af5956a5e0ad4b4fcc3e719.
