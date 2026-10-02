# Connected manual admission verification

Root added `services/platform/apiserver/security_agent_manual_http_postgres_test.go`
against the database owner's shared `runManualAdmissionFixture`. It exercises
the real public HTTP handler, repository, PostgreSQL JSON driver and registered
API login. Identity is supplied at the middleware boundary. Definition/control
prerequisites are seeded; runs, trigger receipts, request receipts and run audit
must start empty and be created through the HTTP request.

Assertions cover source-free admission, original receipt/ETag, singular durable
side effects, retry with newly generated IDs, persisted run list/detail metadata,
changed-version conflict and revoked-membership refusal for replay/new intent.
This is not browser authentication, public definition activation, worker
execution, provider acceptance or production proof.

Verification so far:

- Formatted with `/opt/homebrew/bin/gofmt`.
- Native package compilation and existing controlled boundary regression:
  `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver -run '^TestSecurityAgentManualStart$' -count=1`
  from `services/platform`, session75512, exit0, package1.618s. This executes
  the existing27 controlled cases, not the new registered test.
- The new registered test has not run. SQL owner is still assembling manual
  admission and projections; no draft fingerprint is accepted as a checkpoint.

Next: run the new test with the connected manual SQL batch, resolve concrete
integration failures, then include its retained evidence in the feature review.
Keep all728 status rows unchanged until their own acceptance evidence exists.

## Registered HTTP checkpoint and reached authorization defect

The SQL owner held release58 fingerprint
`6aa9774be0596166801b9a2efd33876884d9e5607c5ff57ad894af3c1c16a08c`
for connected verification. Root changed list/detail checks to use the actual
public HTTP handler too, including no-store and the requested run-context view.

First registered attempt, session62337, stopped at missing required Clock in
the test's handler configuration,4.96s, owned PostgreSQL joined normally. This
was fixture calibration, not a product RED. Root supplied the required clock.

Registered behavioral RED, session52702,7.41s: fresh admission, original receipt
replay, HTTP list/detail and changed-version409 succeeded. Inactive requester
membership was refused by SQL but surfaced as retryable503, not403. The generic
Postgres classifier preserves42501 under repository-unavailable, and the run
handler had no authorization mapping. PostgreSQL joined normally; container1.

Four focused controlled cases were added: revoked membership, revoked effective
permissions, missing database function privilege and an incorrect SQLSTATE with
the same denial message. Native RED session75979 failed exactly the two user
denials as503, package1.959s. Infrastructure cases already remained503.

The fix recognizes only42501 with either `export membership rejected` or
`export source permission rejected` in the manual producer and returns existing
ErrRepositoryAuthorization. The run handler serializes that as non-retryable403
without mutation receipt. Other42501 infrastructure errors keep their503 path;
the generic database classifier and unrelated operations are unchanged.

Affected native race batch session75545 passed, package3.655s, command from
services/platform:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver -run '^TestSecurityAgentManual(Start|ReadPreservesNestedStrictness|ReadBinding|MutationProvenance|ClaimBoundary|PlannerContextBinding)$' -count=1
```

This is six top-level groups; ManualStart now has31 controlled variants. The
final registered rerun follows below; independent review is pending.

Registered GREEN session9448 passed in5.65s, container exit0, owned PostgreSQL
pg_ctl exit0 and server Wait exit0. All assertions described above were reached.
The fresh Linux/arm64 binary was compiled offline in session44519 (exit0):

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test -c ./apiserver -o /private/tmp/zasp-manual-http.test
```

Registered invocation:

```sh
/usr/local/bin/docker run --rm --name zasp-manual-http-check --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-manual-http.test,dst=/manual.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /manual.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentManualHTTPPostgres$' -test.v -test.timeout 120s
```

Reviewed-source candidate hashes (SHA256, paths under services/platform/apiserver):

| File | Hash |
| --- | --- |
| security_agent_manual_start.go | 62933d33fa14b40e773a4f749e37fe26730e8e5e774a8849adfa283ad73da67b |
| security_agent_handler.go | 4505639e2bb05692cc8d302ba0121bc984ed458355798eb4b652f2b468720622 |
| security_agent_manual_start_test.go | 689f2351077e738ae3d905ccd1da8c88b516b7fbe598dc53918d7bb0fe6dbf71 |
| security_agent_manual_http_postgres_test.go | d35de389c637931f7719acd71e387d9bd73be48db6544ca628be2982ef4d2c0e |

No publication or production classification follows from this component proof.

Independent review accepted the four hashed HTTP/Go files with no actionable
findings. The reviewer checked the narrow SQLSTATE/message mapping and the
integration assertions; it did not rerun tests. The SQL owner's later final
batch reran this unchanged HTTP test at fingerprint
`888a5f54afdd322a23ff22381d2abc33701c5274165270e0e4563e5a2e9694c6`,
PASS5.58s with normal owned PostgreSQL cleanup. Root verified the frozen SQL
source hashes, report/patch hashes, reverse-patch check and final log result.
See `database/manual-report.md` for its full batch and precise evidence limits.
Independent review of that SQL delta is separate and remains pending.

SQL review completed with one P2, so that delta is not accepted. The inserted
manual recheck runs inside the global budgeted claim loop after provisional
writes; an expected42501/40001 can roll back all claims and leave the oldest
invalid run eligible for another failed poll. Root confirmed the insertion and
the underlying unhandled loop in security_agent_budget_admission.sql. The SQL
owner is adding mixed invalid/healthy, cross-tenant registered evidence and
per-run refusal isolation. No other actionable findings were reported. Existing
passed checks do not cover this availability regression.

Disk capacity interrupted the parallel SQL compile. Only identified obsolete
test binaries were removed: database-owned binding/cancel/grants/origin outputs,
and the apiserver.test/worker.test pairs under `/private/tmp/zasp-export-settlement.8NVGKU`,
`/private/tmp/zasp-export-settlement.IiWkrW`, `/private/tmp/zasp-export-worker.5jI7bp`.
Source, retained logs/patches, current binaries and shared caches were preserved.
These removed outputs can be rebuilt; disk returned to1.5Gi free at that check.
