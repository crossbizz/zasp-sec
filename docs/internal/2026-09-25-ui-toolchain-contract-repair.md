# UI contract repair, September 25

The current full UI suite passes2472/2472 tests across242 files after five stale
version expectations were corrected. No application, dependency, workflow or
backend source was changed by this repair.

The initial run failed196 tests across three files, with2276 passing, in57.28s.
Two platform command contracts required module minimum1.25.0 even though the
approved Temporal SDK requires1.25.4. The runnable-UI workflow contract still
expected compiler1.25.6 in its prerequisite command, setup assertion and valid
fixture. The reviewed CI security repair already selects1.25.13.

Evidence for the intended values is in `services/platform/go.mod`, the actual
workflow and the September22 dependency-research, go-toolchain-release-gate and
go-toolchain-review records. The repair changes those five expectations only.
It preserves exact version matching and all workflow mutation/rejection checks.
Pre-existing changes in these files are not part of this five-line repair.

Verification under Node22.23.1:

| Check | Observed result |
| --- | --- |
| Initial `npm test -- --reporter=dot`, session65020 | Exit1;196 failed/2276 passed,57.28s |
| Three affected contract files, session14518 | Exit0;270 tests/3 files,24.11s |
| Full `npm test -- --reporter=dot`, session14749 | Exit0;2472 tests/242 files,47.78s |
| `npm run typecheck`, session15143 | Exit0 before the test-only repair |
| `npm run build`, session3323 | Exit0 before the test-only repair; standalone output generated |
| `npm run production:imports:source` | Exit0;74 source files checked |
| `npm run production:imports:compiled` | Exit0;7 client and8 server chunks checked |
| `npm run ui-api:check` | Exit0; planned2, API-available13, available147, public160, internal0 |

Independent review by `ordered_readiness_review`: SPEC PASS, QUALITY APPROVED,
no findings in the five substitutions. The reviewer checked module/CI values
against the recorded decisions and confirmed missing setup, relaxed pin,
disabled prerequisites, omitted/skipped lanes, allowed failure, timeouts,
caching and race-removal rejection controls remain intact. Review was read-only;
test results above were executed and inspected by the controller.

This proves local suite/build health only. It does not run the hosted CI job,
execute the backend under1.25.13, establish live provider or browser acceptance,
or verify the concurrently changing adapter candidate. No main push is claimed.

The import checks inspect the configured production entry graph and compiled
sentinels for forbidden demo/fixture imports. Their passing result is limited
to those guards; it is not evidence that every screen's API works end to end.
