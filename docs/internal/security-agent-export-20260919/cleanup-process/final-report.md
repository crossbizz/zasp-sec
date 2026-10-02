# M7A-23 cleanup process and organization isolation packet

The final frozen-source run passed all seven registered groups, with no failures or skips. The new cleanup parent passed in 196.39s. Native race checks passed 17 top-level tests. No production fix was needed.

## Files and source binding

Only these two new test files and this evidence directory were written for this packet:

| New file | SHA-256 |
| --- | --- |
| `services/platform/apiserver/security_agent_export_cleanup_process_postgres_test.go` | `f6eed99c6c36d041d980d7903093a2fb820831c38f695b30ee550a4287110179` |
| `services/platform/agentsec-worker/security_agent_export_cleanup_process_test.go` | `3c109a19aebf30581f584e7873497a03453dde80429a7a68c11dced0c4a05268` |

The accepted run directory is `2026-09-20T01-43-46.293Z/`. All 1,635 source-file hashes recorded before building match the final files. Its API binary hash is `c696e6117f9a9b45a7ee638d357f7e8583d58efd8a2691725a36d71634628c66`; worker binary hash is `a9701ec13ceb7b544f17e108516b0a5de73e12a748b1233c6b6abd47996789e7`.

Installed and compiled release 58 agree: checksum `5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985`, fingerprint `8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f`.

## What passed

Three actual public-created artifacts were published and downloaded: the target, a same-organization sibling, and an artifact in a distinct organization/workspace/environment. Public definitions, manual runs, real planner acceptance, independent approval, dispatch, production export runtime and mounted download all execute in owned processes. Identity/scope/session and worker-registration prerequisites are seeded; export definitions, runs, plans, links, packages and stored objects are not.

| Artifact | Organization | Export |
| --- | --- | --- |
| Same-org sibling | `pid_6a000001-0000-4000-8000-000000000001` | `pid_baaf649b-c031-47db-8fbf-2d893007216b` |
| Second-org artifact | `pid_8ec00001-0000-4000-8000-000000000001` | `pid_bbe74002-c5da-4faf-89ed-53562a18b7fb` |
| Cleanup target | `pid_6a000001-0000-4000-8000-000000000001` | `pid_f985455b-4072-4aff-87ad-922fc911ece0` |

Cross-organization mounted API probes fail in both directions before any provider request. A mounted target grant is admitted through the real registered API SQL function with its durable session digest and CSRF, creating an actual 30-second read lease. This direct registered read-admission call is the controlled boundary used to hold the lease; it does not seed a lease row or bypass cleanup authority. Public cancellation expires retrieval while that lease still blocks cleanup.

The cleanup worker then crosses these boundaries using actual lease/retry deadlines, without timestamp updates:

| Fresh cleanup process | Provider result | Required SQL outcome |
| --- | --- | --- |
| `blocked` | No request during live read lease | 0 claims, 0 retries, 0 confirmations |
| `delete-loss` | Exact-version DELETE commits 204; process exits 86 before response | Package, retained bytes and cleanup duty remain |
| `held` | No request during the lost worker's 60-second lease | No claim and identical target job row |
| `denied` | DELETE and bounded GET both 403 `AccessDenied` | 1 claim, 1 retry, 0 confirmations; accounting unchanged |
| `generic404` | DELETE and bounded GET both 404 `NotFound` | 1 claim, 1 retry, 0 confirmations; accounting unchanged |
| `absent` | Exact DELETE and GET return typed 404 `NoSuchVersion` | 1 claim, 0 retries, 1 confirmation |
| `done` | No request or eligible claim | No second deletion or target-row mutation |

Both uncertain responses commit real 30-second retries. Only typed exact-version absence releases the target's accounting. Retained bytes change from **18,260 to 12,172**, exactly the target's **6,088** bytes. There is one physical deletion, one deletion audit and zero cleanup PUTs. The target remains as an exact-version tombstone with its stored bytes erased.

The sibling and second-org job/link/run/plan/provider-accounting rows stay identical, as do their object bytes, metadata and versions. Both are downloaded again through fresh mounted grant/download processes after target cleanup, with the exact original bytes. The source-bound summary includes each scoped key, immutable version, package/download hashes and protected-row hashes.

The cleanup flow joins all 48 child processes: 41 normal exits and seven intentional post-commit exits 86 (six setup planner/dispatch checkpoints and the lost DELETE). Its owned PostgreSQL process also joins normally. The grouped run joins all eight owned PostgreSQL clusters.

## Commands and results

From the shipping worktree root:

```sh
ZASP_CLEANUP_SELECTOR='^(TestSecurityAgentExport(CleanupProcess|PublicRestart|Authority|Lifecycle|StoppedSettlement)Postgres|TestCompliance(HTTPPostgresGrantLifecycle|RuntimePollingPostgres))$' node docs/internal/security-agent-export-20260919/cleanup-process/run.mjs
node docs/internal/security-agent-export-20260919/cleanup-process/native.mjs
```

The operator builds Linux arm64 binaries offline, then runs them in the pinned PostgreSQL image with network disabled, a read-only root/worktree, private temporary storage and bounded owned-child cleanup. Exact build and container commands are retained in `run.json`.

| Registered group | Result |
| --- | --- |
| Compliance HTTP grant lifecycle | PASS 5.60s |
| Compliance runtime polling | PASS 11.07s |
| New cleanup process flow | PASS 196.39s |
| Export lifecycle | PASS 10.41s |
| Stopped settlement | PASS 11.88s |
| Export authority | PASS 6.96s |
| Public A-H restart continuity | PASS 90.59s |

The retained native command is `go test -race ./agentsec-worker ./artifactstore/s3driver ./internal/exportfixture -run '^(TestSecurityAgentExportCleanupResponseTaxonomy|TestExport(Cleanup|ReadOnly).*|TestStore.*)$' -count=1 -v -timeout=120s`, using `/opt/homebrew/bin/go` with local/offline settings. All 17 top-level tests pass, without skips. Package times: worker 2.818s, S3 driver 1.434s, persistent store 3.875s. The native group does not run the PostgreSQL parent under the race detector.

`red-green.md` distinguishes the focused taxonomy negative control from setup wiring failures. The earlier 01:40:18 process PASS predates the stronger final assertions and is not the accepted source-bound result.

## Retained evidence

| Artifact | SHA-256 |
| --- | --- |
| `2026-09-20T01-43-46.293Z/run.json` | `b707a3ac0fcd034f151688c2ca088e312e3216a404fc0caa0e59e1ffb5ed3e73` |
| `2026-09-20T01-43-46.293Z/run.log` | `8264725c13a21925a37cb3a8331af42319767fc8c45d699cba8c865a62d9e518` |
| `2026-09-20T01-43-46.293Z/cleanup-summary.json` | `bc319f919dae4412998738643859c5c8ad0aef10b761694ff6c9f22968c07b10` |
| `2026-09-20T01-43-46.293Z/cleanup.json` | `bdd4e6e9e9c28acec26249e49cb0e770bb00ffcb517f30d26d971277ee52df70` |
| `native-race.log` | `f1ca4c60cd1514818d5b5e4efabab01a0c1b6fff064034a692026a1cf5caf776` |
| `native-race.json` | `066439d6832a3cc123486ab78d2c59e6cfc4422e11319a574dd0cab4acda6391` |

The operator removed its exact temporary binary directory. The exact owned container `zasp-cleanup-process-9gp1oq` is absent from Docker after the run. A separate compile-only executable was moved from `/tmp/zasp-cleanup-compile-api.test` to `/Users/manishmaheshwari/.Trash/zasp-cleanup-compile-api-20260919.test`; it remains recoverable. No unrelated process or file was removed.

This is controlled local process/SDK/PostgreSQL proof, not live AWS, deployed rollout or native-browser saving. Existing tests, product code, SQL, pins and ledger were not edited. No staging, commit or push. No known blocker remains for this local packet.
