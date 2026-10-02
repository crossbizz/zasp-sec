# Approval and routing handoff

DONE_WITH_CONCERNS. The connected approval SQL and run-kind batch is frozen for independent review. This is component evidence, not M7A-23 completion or production acceptance.

Current release58 pin: `e60b91c5d4ecd09bd20617e12eca85bc139865c9532f71e6613e578a6a5bd676`.
Accepted projection base pin: `46b69c98336c9a93c168e9b451ae8da69fb248ee1706d6d2c419f31707b6a998`.
Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.
HEAD: `8733b16f8d939d38a8157dd2519e57fc6f630542`.

Only three product files changed: the export links SQL fragment, release58 fingerprint, and new `apiserver/security_agent_export_approval_route_postgres_test.go`. Before bytes are under `approval-route-before/`. No Go implementation, TS, renderer, planner SQL or predecessor migration file was edited.

The private approval projection checks the scoped approval/run/step, original current plan hash, canonical plan and step digests, definition binding, closed typed selection, parent-run target, approval-required authorization and requester. An existing export link must retain the same plan/input/selection. The public context still uses the predecessor assembler and root's Go decoder. It reads the stored plan selection, never a newly collected selection.

Approval wording is `Create run-scoped evidence export`, TTL0 and reversible=true, preserving the builtin catalog's artifact-expiry meaning. Expiry does not recall downloaded bytes. The original trigger ProductID remains evidence_summary. The registered detail, page and run reads passed through root's public decoders.

The additive decision branch calls the existing base authorization/fresh-auth/requester/CAS/idempotency implementation, projects the export response, and persists that response in the same statement. A projection refusal rolls the whole decision back. Lost-reply replay returns its stored receipt even after the current approval version changes. This was tested, followed by actual registered claim and approved export dispatch.

`zasp_sa_export_run_kind(o,w,e,r,worker_value,lease_value) RETURNS jsonb` returns exactly `{export:boolean}`. It checks read-committed execution, exclusive worker role, exact release58 guard, canonical scope IDs and worker/token lengths. Fresh routing requires the current scoped planning lease. An unprepared run uses its immutable definition version and digest; a prepared run uses the canonical plan and matching step identities/digests. It does not reserve budget, mutate the lease, or authorize upload.

Export lost replies use the immutable original dispatch worker/token digest and original retrieve binding. Attack Lab false routing preserves that family's exact durable dispatch identity and approved plan/input/approval binding. Existing-test dispatch has no durable original dispatch-token receipt. Its cleared-lease refusal remains in place, tested against both its predecessor execute wrapper and the new route. That reliability gap remains required connected work; this batch does not invent replacement authority.

## What ran

Superpowers TDD drove the boundary tests before SQL implementation. `approval-route-red.log` records real registered RED: approval rejected unsupported export effect (22023), and run-kind was missing (42883). Both PostgreSQL lifetimes joined normally, container exit1. An initial Go field-name compile error was corrected before that run and is not behavioral RED.

The expanded RED reached missing routing after a real Attack Lab dispatch and on an unplanned existing-test parent. Its approval-refusal fixture stopped on an unused simple-protocol argument; that setup error was corrected and is not behavioral proof. `approval-route-expanded-red.log` retains the exact command and a summarized result, not a complete raw transcript.

The first affected batch at pin `cb0251e3b849eafb869446933141ff70b3c3d939faff853716eabef5398988fa` produced:

- Approval 6.05s, RunKind 5.56s, ApprovalRefusals 5.59s: PASS.
- The existing-test subcase passed in 5.98s. Attack Lab replay failed with 42702 because table alias p collided with a PL/pgSQL record named p.
- Supervised admission 5.36s and Release 6.79s passed. Seven owned PostgreSQL lifetimes joined normally; container exit1.

`approval-route-affected.log` is the full output. `approval-route-draft.patch` preserves that exact SQL/pin/test snapshot. The correction only renames the Attack Lab query alias to replay_plan, then recalibrates the fingerprint.

Final affected follow-up at the current pin passed: NonExportRoute16.39s (existing_test7.09s, attack_lab9.30s), Release6.47s. Three owned PostgreSQL lifetimes joined with pg_ctl and server Wait exit0; container exit0; no skips. `approval-route-final-green.log` is complete. The previously passing approval/export/supervised groups were not repeated after the alias-only correction.

Every PostgreSQL run used the existing Linux/arm64 postgres image by digest, `--pull=never --network none --read-only --user postgres`, owned tmpfs data and the mounted offline test binary. Exact Docker commands are the first line of each log. All calibration attempts and their observed pins are retained in the three calibration logs; calibration exit1 is expected before updating the compiled pin.

Compilation before each database run exited0:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-export-db-test-initial.test
```

The command ran from `services/platform`. `git apply --reverse --check docs/internal/security-agent-export-20260919/database/approval-route.patch` and `git diff --check` exited0. The reverse check is against inherited before bytes, not HEAD. Release tests checked actual registration, live drift refusal and exact predecessor restoration through up/down/up.

## Frozen hashes

```text
43c704245a849a4699167f72690317a43cd217bf231bc972e31b47ac36fed5fd  before links.sql
3ff1e314e35391de04af63a828213214ece386dcb0dd469c80fb52730f1c39aa  before release.go
9e222802fb51f612b9d25c89c641cbfb277544824d4471955198fdf7e78f19d7  after services/platform/migrations/sql/fragments/security_agent_export_links.sql
d211420809fa752b8edb9bc3491516066561a90573cb2ecb6745071a512c1135  after services/platform/migrations/security_agent_exports_release.go
40c05849105a1673f53ef4bd9e9b03b50038bf1e86c15c40d331b5cc173ab171  new services/platform/apiserver/security_agent_export_approval_route_postgres_test.go
9b9b573127b79ec54644e692f4aa93253accf34474473ca1699051f332af9475  approval-route.patch
64317aaf5d848674bd9ac7020e0009c6d6c99a7374fcff48af4c5fc52395ce07  approval-route-draft.patch
e5f4f2ecabdc7d0b24a3435fbaf5fafb38c471d1bae08b4e55ba604f30118a6b  approval-route-red.log
5d64f74cc8b6ebf77f72863ea3c4c4119002c71f7b3effe71ab12058711978c2  approval-route-affected.log
66070ffc15502b2e2ce568b7959629630347833fda581142e572e1a60d620059  approval-route-final-green.log
```

The earlier accepted projection/P2/P3 evidence is unchanged. No staging, commit, push, external provider/advisory call, secret access, dependency install, image pull, host PostgreSQL or subagent occurred.

## Still open

Independent review of this frozen delta is next, owned by root. Public planner SQL context/reservation/acceptance/failure, fully mounted unseeded workflow, multi-step authority, manual-parent typed provenance, existing-test dispatch replay, deployment and external production proof remain open. This fixture seeds prerequisite export plans, so approval/dispatch evidence is component-only.

Planner recommendation sent to root: keep predecessor signatures under export-specific wrappers, include original ordered typed export_selection in the canonical version-bound context, require exact tuple membership when accepting candidate evidence_ids, and recompute the same context digest at reservation and acceptance. No extra planner transport arguments are needed. Do not use this recommendation as implemented authority.
