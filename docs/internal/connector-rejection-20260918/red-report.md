# M8-41 mounted connector-rejection RED

The missing durable audit is reproduced. This is RED-phase evidence, not a
completed fix or live SSRF/egress certification. No production source or
migration was changed, and nothing was staged, committed or published.

## Authoritative result

`TestConnectorRejectedAuthorityOverridesPostgres` was compiled offline,
enumerated by exact name, then run alone against fresh PostgreSQL in an owned,
cached, network-isolated Docker container. The final run exited **1** after
5.14 seconds. Its ten authorized cases fail at the intended assertion:

```text
missing durable safe scoped rejection audit: want one authorized-attempt event
with correlation pid_8b000000-0000-4000-8000-000000000001;
got delta=0 matching=0
```

The correlation suffix varies from 001 through 010. Full output is in
`red-run-final.log`. There are no setup failures in that final run.

Before those assertions, the test proves real browser-session authentication
through `NewProductMiddleware`, exact expected scope, Origin/CSRF and current
`manage_workflows` permission for a `security_engineer`. Product operations use
`NewComposition`, the real workflow handler/repository, and the registered
`security_agent_v33_discovery_api_login`, not owner SQL. The role is neither
superuser nor BYPASSRLS. Owner access is limited to migration/registration,
fixture seeding and outcome inspection; no compliance authorization helper is
used.

Safe GitHub setup returns 201 with `pending_authorization`. Safe generic-webhook
setup with supported `destination_url` returns 201 with `configured`. These
positive controls establish a working route, provider setup and write authority
before absence of auditing is interpreted.

POST create and PATCH of that same-scope GitHub integration each test
`nango_url`, `nango_base_url`, `proxy_url`, `provider_url`, and `provider_url`
combined with `client_secret`. Every authorized attempt returns 400
`invalid_request` with the expected safe correlation. The secret-field cases
exercise the current early `ReplayWorkflow` sensitive-field refusal, before
setup schema validation. Every case finds zero new scoped, actor-matched
`rejected` rows in `zasp_admin_audit`, including zero rows with its correlation.
The test does not prescribe a new action name.

For every rejected request, exact full-table snapshots remain unchanged for
workflow records, integrations, connections, credentials, effects, OAuth
attempts, workflow idempotency, workflow receipts, workflow audit and connector
audit. Responses do not disclose the hostile URL or credential marker. The
future expected rejection record is also checked for correlation and absence
of hostile URL, secret and submitted name; that check cannot prove safe record
contents until GREEN creates a record.

Separate controls all pass: unauthenticated 401, missing CSRF 403, foreign
expected-scope 409 `scope_stale`, and foreign update target 404. They do not
mutate state or borrow selected-scope rejection-audit authority.

## Provider observation boundary

The setup create/update route has no provider transport dependency. The test
observes zero dispatches to the composed connector HTTP route and zero calls to
a deny-only default HTTP RoundTripper. It does **not** observe a configured
Nango/GitHub custom transport, DNS, or live provider egress. Provider zero-egress
here is structurally limited to local setup validation, unchanged durable
connector effects and no connector-route dispatch. The default HTTP tripwire
does not prove that every possible custom transport is silent. Docker runs
with `--network none`; no external provider call was attempted.

## ACL discovery and setup-only failures

All exploratory outputs are retained; none is substituted for the final RED.
Each used the same `run-red.sh` command with the source/binary identities printed
at its start.

| Log | Result and correction |
| --- | --- |
| `red-run-1.log` | Setup assertion expected no audit INSERT privilege, but the registered API role has it. Removed the unsupported assumption; retained the observation. |
| `red-run-2.log` | Composition rejected reused dependency-handler identity. Corrected fixture to unique handlers, as composition requires. |
| `red-run-3.log` | Both safe creates returned 201; a compact-JSON substring expectation misread the webhook response. Replaced with semantic decoding. |
| `red-run-4.log` | All ten intended missing-audit failures observed, but foreign expected-scope control incorrectly expected 403. Router contract is 409; corrected it and decoded error responses semantically. |
| `red-run-final.log` | Both positive controls and all four negative controls pass; only the ten missing-audit assertions fail. |

The API audit INSERT privilege is released behavior, not a fixture-only grant.
`0010_production_discovery.up.sql:756-765` grants legacy table CRUD to
`zasp_discovery_api`; `zasp_admin_audit` is not excluded. Registration at
lines 699-701 grants that API role to the login. Release52 saves the existing
admin-audit ACL; its lines 79-81 require no table RLS and constrain the separate
`zasp_discovery_authority` privileges, not the legacy API CRUD grant. No grant
was changed or raw API audit INSERT attempted by this test.

## Reproduction and identities

Run from `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`:

```sh
set -o pipefail
bash docs/internal/connector-rejection-20260918/run-red.sh 2>&1 | tee docs/internal/connector-rejection-20260918/red-run-final.log
```

The script contains the exact compile, enumeration and Docker commands. It uses
`/opt/homebrew/bin/go`, `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`,
`GOCACHE=/private/tmp/zasp-budget-go-cache`, Linux arm64, cached image
`postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba`,
`--pull=never --network none --read-only --user postgres`, and a 180-second test
timeout. No dependencies or images were downloaded, and no host PostgreSQL or
full SQL suite was run.

HEAD before and after: `8733b16f8d939d38a8157dd2519e57fc6f630542`.

Final SHA-256 identities:

```text
cdeed423c112bf4652414ed2a07b8c3064697c1b8d9a29c7d08b43235f4efc70  /private/tmp/zasp-connector-rejection-red.test
3a60078282104d84a6d8d7c3f6583f3013c4f4344e98056968845f42b7c214a6  services/platform/apiserver/connector_rejection_postgres_test.go
60e41f9739312e54f8d6fd30b769a544564b2ba7c50f9477627f2578577fcbf4  services/platform/apiserver/workflow_handler.go
7a08cb2ed3ac09392fd8489529903f6190ec4a2ecb13e50af9edabc842cd866c  services/platform/apiserver/workflow_repository.go
ccde0eca8c60b15292808b2aeb4a332e8c4f7bb49687279686061226e39c8240  services/platform/integration/manifest.go
```

Current compiled release56 checksum:
`f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1`;
fingerprint:
`8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced`.
The real compiled forward migration chain reached release56.

`before-identity.log` and `after-identity.log` contain the full affected-source
inventory and inherited tracked diff summary. Their only difference is the new
test file. All inherited apiserver, migrations and integration source identities
are preserved. `red-scoped.patch` contains only this phase's new test, helper
scripts and report; evidence logs are retained beside it. `gofmt -l` and the
narrow `git diff --check` produced no output.

Every compile, enumeration, test, capture and Docker client process was joined.
Every PostgreSQL server logged `pg_ctl exit=0 server Wait exit=0 normal-exit`.
`--rm` removed all owned containers; a final `docker ps -a --filter
name=zasp-connector-rejection` returned no rows. The ten pre-existing voxeval
container names and IDs remained unchanged. The compiled test binary is retained
in `/private/tmp` for evidence. The RED test remains uncommitted for the root
agent's subsequent guarded-audit GREEN work.
