# Public export SQL admission, frozen at 83416842

The SQL packet is frozen. Its lifecycle, current-authority waits, predecessor behavior, exact release restoration and manual HTTP regression passed on registered PostgreSQL at the final pin. The first combined final command exited 1 because the Go HTTP boundary mapped a valid current-user SQL denial to 503 instead of 403. SQL returned 42501 and refused the replay. After the Go owner's narrow correction, the HTTP-only rerun passed in 21.49s, container exit 0 and one clean owned PostgreSQL join. SQL stayed unchanged.

This is component evidence, not production or full M7A-23 acceptance. No commit, stage, push, deployment, external provider, image pull or host PostgreSQL was used.

## Bytes that define this packet

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.
HEAD: `8733b16f8d939d38a8157dd2519e57fc6f630542`. HEAD alone does not identify the inherited dirty source.

Release 58 checksum: `dba54cda63de25490d109447c05a7dc81e5fe32fade3f04673c5f1cf4cf43693`.
Fingerprint: `83416842dd0d4b0f70e9709045ae4534eb54efaabb5b77f1429edbfc1eb0cc7d`.

Paths below are relative to the worktree. Before bytes are retained in this report's sibling `public-activation-before/` directory.

| Owned source | Before SHA-256 | Frozen SHA-256 |
| --- | --- | --- |
| services/platform/migrations/sql/fragments/security_agent_export_definition.sql | absent | cd824d85d2b643f3f210d6446cba2d886badd9b01244ebb11db8cbad68814595 |
| services/platform/migrations/security_agent_exports_release.go | 813a6bf7f11ddd1e0d9246a2581690a60d0fe4a5c518dc8390ab4a3184c994fc | 2ab1e6c286e0f6dcc13d9b65adcce40913ceae4f3072605f64d84f22d4f2ca83 |
| services/platform/migrations/sql/0058_production_security_agent_exports.up.sql | 30df8924c0dc32cc861363bb39fe8dd722cf8c83ce0e33cbae0def1c9c43cee1 | ae0ead89664883bcc5407c0d083daab009825ef65e2182068b7fba50ffba54ba |
| services/platform/apiserver/security_agent_export_definition_postgres_test.go | absent | c6861b8f438000a3ce2aa410ea20b912ae366968937d0028e98e4a9ee9f0dcf3 |
| services/platform/apiserver/security_agent_export_release_postgres_test.go | e0cb3d18b28bc5c861a1595f0246ea80a950aa8d1533a41484dd664c9554583c | 560d67c6df84b09f31448402189b71abdf709cde8037685671608d43b2bb52bb |

Task-only patch: `public-activation-sql.patch`, SHA-256 `c21436b836251da8ad6472e5b97ba7d2bec4c1b6308658584ced8b0a71b9a884`. It compares the five owned files with their before bytes, not with HEAD. `git apply --reverse --check` passed against the frozen tree. `git diff --check` passed. The earlier pre-withdrawal patch is retained as `public-activation-prewithdrawal.patch`, SHA-256 `597a723c2b1c9bc6bf1ab11dcc6aaeaad58afcf6990b75b4d2d47b5dc7c080ca`.

Unchanged down SQL SHA-256: `2e68048c8b0ac75cf987871692a8b1789d1a2a2c89d5550859b9fa1791bc57d0`.
Accepted fragments were not edited:

| Fragment | SHA-256 |
| --- | --- |
| security_agent_manual.sql | cb4106ae08975d8b4ba38bfefc975a05d28aca8839ce5433745b8a75a4982bc4 |
| security_agent_export_accounting.sql | 52e75bf8a0a892cc7577f36cd43dafa0e6f53604389bf99ebd4fb75e2571c6bf |
| security_agent_export_planner.sql | d98e7b87c5a7530400de235a9c19c1a815a95fd0f90b4cfe645e584e9ac0ffc9 |
| security_agent_export_links.sql | 9e222802fb51f612b9d25c89c641cbfb277544824d4471955198fdf7e78f19d7 |

## The callable contract

All names below are in `public`, return jsonb unless stated, and require the exact checksum/fingerprint above. Argument order is frozen. `o,w,e` mean organization, workspace and environment; `d` is definition ID.

```sql
zasp_sa_export_workflow_readiness(
 expected_checksum text, expected_fingerprint text) RETURNS boolean

zasp_sa_export_mutate_definition(
 mutation_value text, definition_value text,
 organization_value text, workspace_value text, environment_value text,
 principal_value text, operation_value text, idempotency_value text,
 expected_version_value bigint, intent_value jsonb, body_value jsonb,
 audit_value text, correlation_value text, receipt_value text,
 expected_checksum text, expected_fingerprint text) RETURNS jsonb

zasp_sa_export_replay_definition(
 o text,w text,e text,actor text,operation_value text,key_value text,
 intent_value jsonb,expected_checksum text,expected_fingerprint text) RETURNS jsonb

zasp_sa_export_activate(
 o text,w text,e text,d text,actor text,key_value text,v bigint,
 target_value text,fresh_value timestamptz,audit_value text,
 correlation_value text,receipt_value text,
 expected_checksum text,expected_fingerprint text) RETURNS jsonb

zasp_sa_export_controls(
 o text,w text,e text,actor text,
 expected_checksum text,expected_fingerprint text) RETURNS jsonb

zasp_sa_export_set_control(
 o text,w text,e text,actor text,key_value text,target_value text,
 action_value text,enabled_value boolean,v bigint,fresh_value timestamptz,
 audit_value text,correlation_value text,receipt_value text,
 expected_checksum text,expected_fingerprint text) RETURNS jsonb

zasp_sa_export_definition_value(
 o text,w text,e text,d text,actor text,
 expected_checksum text,expected_fingerprint text) RETURNS SETOF jsonb

zasp_sa_export_definition_detail(
 o text,w text,e text,d text,actor text,
 expected_checksum text,expected_fingerprint text) RETURNS SETOF jsonb

zasp_sa_export_definition_page(
 o text,w text,e text,actor text,after_value text,limit_value integer,
 expected_checksum text,expected_fingerprint text) RETURNS jsonb
```

The mutation and activation writers are export-only. Incoming and retained action families both participate in classification; conversion in either direction is refused. Delete retains the original export resource's family.

Replay is an all-family receipt dispatcher with the predecessor `{found,result}` envelope. Export replay checks retained version history, body digest and original actor, including after delete. It does not expose deleted values. Value/detail/page readers are all-family, actor-aware readers.

The eight sorted control keys are `create_evidence_export`, `create_temporary_policy`, `isolate_session`, `rerun_test`, `revoke_integration_connection`, `run_test`, `start_attack_lab`, `update_finding_response`. Missing export control is disabled at version 0. The writer accepts environment and action targets, never global mutation.

Every actor-bound entrypoint checks the registered API principal, READ COMMITTED, canonical scope, active membership and current effective scopes. Reads require view; writes require view plus manage_workflows; controls require view plus manage_identity. Writes recheck authority after waits and after predecessor mutation. Tests use actual effective group grants, then revoke them during a controlled lock wait. Fresh-auth expiry during a control wait refuses without retained writes.

The body is closed: one export action, verification kind export, exact environment, max_steps 1, bounded name/trigger text and numeric budgets, no existing_test field. Cost is required and is in 1..1,000,000,000,000. Fresh drafts are disabled. This packet does not claim multi-step admission.

Activation preserves draft -> validated -> supervised -> autonomous. Root approved a narrow export-only withdrawal from supervised/autonomous to validated: disabled body, version/history/receipt and CAS remain atomic. It requires current authority, fresh authentication and installed exact release, but neither enabled execution controls nor connected worker health. Reverse-to-draft is refused. Existing-test and Attack Lab transitions are unchanged.

Installed readiness is not connected workflow readiness. SQL proves the registered admission surface and exact release; the Go capability combines that result with explicit configuration and private planner/action/compliance-writer/cleanup health checks. Retained reads, delete and safe withdrawal do not require healthy workers.

Private predecessor clones are owner-only in `zasp_sa_export_prior`. Legacy mutation, activation and replay paths fence incoming or retained export resources. Legacy value/detail/page readers hide export rows because those signatures cannot accept a current actor; new readers call private originals. Non-export response behavior remains unchanged. The migration saves original functions and ACLs before fences, then uses the existing down restore path. Empty rollback reaches exact 57; retained definitions/history/controls refuse rollback.

## What actually ran

The reusable `runExportDefinitionFixture` starts registered 56 -> 57 -> 58 and seeds actor authority, not an export definition/history/control/run/plan. The public lifecycle test creates its own draft and advances it. Root's HTTP fixture uses that helper and the real composition router/repository/API login.

Build, from `services/platform`:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-public-export-activation.test
```

Registered runner command, from the worktree root. Each row below supplies the literal NAME, SELECTOR, TIMEOUT and LOG; no other argument changed:

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name NAME --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-public-export-activation.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run 'SELECTOR' -test.v -test.timeout TIMEOUT 2>&1 | tee docs/internal/security-agent-export-20260919/database/LOG
```

| Command values | Result |
| --- | --- |
| NAME=zasp-public-export-definition-feature; TIMEOUT=900s; LOG=public-activation-feature-1.log; SELECTOR=`^TestSecurityAgent(ExportDefinition(PublicLifecycle\|AuthorityWait\|Predecessors\|HTTP)\|Export(Release\|Sources\|Authority\|PlannerAdmission\|PlannerRefusals\|PlannerAccounting)\|Manual(Admission\|HTTP\|ClaimIsolation))Postgres$` | At historical 2d6913 pin: 12 of 13 top-level groups passed, 27 clean owned PostgreSQL joins. Exit 1 solely for HTTP withdrawal before the new transition was approved/implemented. |
| NAME=zasp-public-export-definition-final; TIMEOUT=600s; LOG=public-activation-final.log; SELECTOR=`^TestSecurityAgent(ExportDefinition(PublicLifecycle\|AuthorityWait\|Predecessors\|HTTP)\|ExportRelease\|ManualHTTP)Postgres$` | Final 83416842 pin: lifecycle 9.30s, authority waits 7.02s, predecessors 9.05s, release 6.31s, manual HTTP 5.70s passed. Six clean owned PostgreSQL joins. Exit 1 solely for final HTTP 503/403 classification mismatch. |

The table escapes pipe characters for Markdown; the shell regex uses ordinary `|` characters. Final SQL-batch binary SHA-256 was `170cb857436e42572658f7397820db72ec31bdde2c8d3fc554debb8fe44a205b`.

Real behavioral RED came first:

- `public-activation-red.log`: registered baseline lacked workflow_readiness, SQLSTATE 42883, exit 1 in 5.14s. SHA-256 `031738759a615f12a0d81bb49e0a943c7dd35d9fb57df1b9d182d7efcc560a30`.
- Legacy replay bypass returned success before its fence in `public-activation-legacy-replay-red-1.log`, 5.71s, exit 1. SHA-256 `917f52d88e85456573df94f93295c62b84c4f647906c683c3f90adfa06c0866b`.
- `public-activation-read-red.log` reproduced legacy export reads and view-only reader rejection at pin 146d76. The concurrent wait case already passed; it is not evidence of a missing post-wait check. SHA-256 `a530e563360a510dfa0b3a3ef0c84ee49af9cef842c979c42039ece26355524b`.
- `public-activation-feature-1.log` reached unsupported safe withdrawal through the actual HTTP path. Root approved that transition; the final SQL groups then passed its CAS/replay/refusal cases.
- Final HTTP SQL denial is correct. Its mapping correction belongs to the Go packet.

Some earlier failures were fixture errors and are retained as such: invalid SCIM group IDs, editing scope.permissions when effective permissions come from the role, and reusing an HTTP correlation ID (23505). The apparent post-activation mirror/CAS problem was disproved by direct SQL; the HTTP correlation collision caused that failure. No mirror synchronization was introduced.

Calibration logs 1..5 deliberately ran an out-of-date fingerprint to obtain the exact registered catalog digest. Those are release calibration, not behavioral RED. Fingerprints progressed through 12e8986e, a7520c5a, 146d76fb, 2d6913cd, then final 83416842. Earlier logs remain unchanged.

The broad historical batch also passed autonomous/supervised/failure planner admission, missing/outstanding/unknown accounting refusals, source collection, twenty authority refusals, manual admission and eight claim-isolation cases. Their accepted source fragments are unchanged in this packet. I did not repeat those groups after the only later SQL change, export-only withdrawal in the private activation clone.

Log SHA-256:
- `public-activation-feature-1.log`: `f92c82ab73f5e6202582ffc7f8a7a73ea58b582ec56edf150b32079eec08c6ad`.
- `public-activation-final.log`: `9fb4c0044bf088e2b4c477f8024d3a5b057e9840389e28caf4a0dd16185c9189`.

All listed registered tests executed in the cached Linux/arm64, network-none container. There were no skips. Owned PostgreSQL lifetimes joined with pg_ctl exit 0 and server Wait exit 0.

## The remaining handoff

The final offline rebuild exited 0. The HTTP-only run used NAME=zasp-public-export-definition-http-final, SELECTOR=`^TestSecurityAgentExportDefinitionHTTPPostgres$`, TIMEOUT=300s and LOG=public-activation-http-final.log with the exact runner above. It passed in 21.49s, exit 0; pg_ctl and server Wait both exited 0. The actual public draft/update/control/activation path reached source-free manual admission, reservation and settled accounting, planner acceptance, approval, export dispatch and capture, then outage withdrawal/delete/replay and revoked-authority refusal. This is not storage-upload/download proof.

HTTP final log SHA-256: `8ce46aaab73e79b23b899b161e1c56a4cfa4d68d1309ea9118fbd76e17923b49`.
Final Linux/arm64 binary SHA-256: `9bf101ff5703fd214de15a9f2551f9d27f5c3b9b2c46dcc2f60f6e063674e88e`.
Exact retained commands are also in `public-activation-commands.md`.

I checked the Go owner's frozen input hashes before rebuilding. These are verification inputs, not files edited by this SQL packet:

| apiserver source | SHA-256 |
| --- | --- |
| workflow_handler.go | dce2fc3704f22ad4954e19d6fbf412e3654721e3df8e7776e523a049e9154f6c |
| workflow_repository.go | d06bf347e47d940345a9ea984805f32c360f54aa9be5239a79a1a08a9cd20108 |
| security_agent_repository.go | dd7a9e9ee691d87af58a8edb3d9b2b3f5b9c48a21403aa9a49f51e16014b695c |
| security_agent_handler.go | e9894bc1649652e26ea2cdf60a1e58705081af46735a2586ae0ebf0ffd3306a9 |
| security_agent_export_definition.go | add3d6493bc8e01d6e0639db358db48929d871d645935159c0ff2d6d40ce4660 |
| security_agent_export_definition_test.go | b9cb06175317281032c94e0d39cb95b6f00b0a8a6f92ccb0c68a2c36c3b4c973 |
| security_agent_export_definition_http_postgres_test.go | 99e763b3cb182f993b14196c8e92358850ef397660e06874a63f41652ea232f4 |

Independent review is coordinated by root with /root/evidence_export_worker_review after the SQL, Go and UI packets are frozen. The task patch reverse-check and diff whitespace check passed again after this HTTP run.

HTTP identity comes from the middleware boundary; it is not browser login proof. Worker health and model responses are controlled in the fixture. No external storage/provider or live deployment acceptance is claimed. The broader multi-step, deployment and original milestone obligations remain with the parent task.
