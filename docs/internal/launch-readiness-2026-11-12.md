# Launch readiness update, 2026-11-12

Launch is not accepted. Two of the blockers in [the 2026-11-11 report](launch-readiness-2026-11-11.md) are fixed: the schema now installs without a superuser, and the worker startup gate is open. One new blocker was found: the API can never report ready, on any database, until approval-notification delivery is activated. Nothing here was run in a deployment.

## Ledger

728 rows: **518 production-available, 149 component-only, 61 blocked/external**. One row moved from production-available to component-only (M1-10, Neon schema baseline). No row was promoted. The [remaining list](launch-remaining-tasks-2026-11-12.tsv) holds all 210 rows outside production-available.

## What changed

### 1. The schema installs without a superuser (was blocker 1)

`agentsec-migrate install-baseline` installs one generated baseline in a single transaction, as an operator that has `CREATEROLE` and `BYPASSRLS` but no `SUPERUSER`. That is what Neon, RDS and Cloud SQL give a database owner. Operator guide: [baseline-schema-install.md](../operations/baseline-schema-install.md).

| Check | Result |
| --- | --- |
| Install on PostgreSQL 18.3 as a non-superuser operator | Passed, about 2 s, one transaction |
| Second database in the same cluster (roles already exist) | Passed |
| Readiness predicates, baseline against superuser installation | 143 of 143 agree, apart from the two listed below |
| Catalog structure, baseline against superuser installation | About 13,700 facts identical: every schema, table, column, constraint, index, trigger, policy, function signature, owner, privilege, role and membership |
| Operator memberships left after install | One, in `zasp_discovery_authority`, as designed |
| Change to a product function after install | `intact()` false, worker gate closed, re-seal refused |
| Verifier registration and `zasp-bootstrap` as the non-superuser operator | Passed against the real Stytch TEST project |
| Unmodified API on the baseline | Starts; serves; readiness reaches the same check as on the superuser installation |

The baseline is generated from the historical chain by `services/platform/migrations/baseline/generate.sh`, which fails if any comparison above fails. The chain's layered self-verification (function-body hashes and fingerprint constants) is replaced by one catalog seal. The seal covers more than the old checks did: every definition, owner, privilege, role attribute and membership in the product schemas.

Two predicates differ from the superuser installation on purpose: the worker gate (below), and `zasp_temporal67.base_ready`, a layer-67 check that layer 68 superseded and nothing reads.

**Not done:** the install has not been run on the Neon project. This environment has no TCP path to Neon. The installer was verified with the same privilege shape Neon grants.

**Also changed:** service login names are fixed (`zasp_svc_*`) and the operator role must be named `zasp_operator`, because the baseline stores principal bindings and grantors.

### 2. The worker startup gate is open (was blocker 2)

`zasp_authorization80_worker.runtime_ready()` shipped as `... AND false`. In the baseline it follows catalog integrity. Run as each worker login on the baseline:

| Startup check | Logins | Result |
| --- | --- | --- |
| `zasp_authorization80_worker.runtime_ready()` | temporal executor, temporal compensation, discovery, scheduler | true |
| `zasp_authorization80_runtime.ready(checksum, authority)` | coordinator, archive, index, correlation, runtime projection, outbox | true |

**Not done:** no worker process has been started against the baseline. Each mode also needs queues, keys and endpoints that the local stack does not create yet. The gate was the database-side refusal; whether each worker then runs correctly is unproven.

### 3. Development mode against LocalStack

The production binaries use LocalStack and a local OpenSearch node when `ZASP_LOCAL_CLOUD_ENDPOINT` is set and `ZASP_ENVIRONMENT` is `development` or `test`. With any other environment a process that finds the setting refuses to start. Without the setting nothing changes. The production search-schema job runs against the local node, and the API's repository, policy-history, identity-provider and export readiness checks pass.

`deploy/local/real-stack/stack.sh up` now takes about 15 seconds (it was 95) and exercises the production install path.

### 4. Readiness failures are named

When `/readyz` returns 503 the API logs the first check that refused, from a fixed list. That is how the blocker below was found.

## New blocker: the API cannot become ready

`/readyz` stops at `approval-notifications` on both the superuser installation and the baseline. A deployment whose readiness never passes receives no traffic.

Cause: with the current authorization model the API refuses every product statement that does not carry a request authorization. The legacy approval-notification loop runs in the background with no request, so its claim statement is denied and it never reports ready. This is deliberate. The intended replacement, the approval-maintenance profile (`migrations/sql/approval_maintenance_profile.sql`), is marked "inactive integration candidate": no command installs it, its registration can never become active, and new notification origins are always recorded as `captured_inactive`. So approval-notification webhooks are not delivered at all today, and readiness fails because of it.

The earlier report said the cause was a false SQL readiness function. That was wrong; the SQL readiness check passes.

Fix, next batch: install and activate the profile in the baseline (dedicated maintenance login, verifier registration, per-Organization activation at bootstrap), configure the API, worker and projector for it, and prove a notification is delivered.

## Verification for this batch

- `go test ./migrations/baseline` with a non-superuser operator database: passed.
- Go packages touched (`agentsec-migrate`, `migrations`, `localcloud`, `bootstrap`, `cmd/...`, and for the LocalStack change `agentsec-api`, `agentsec-worker`, `apiserver`): no failure that is not also present on unmodified main in this environment.
- UI unit suite, typecheck, lint and production build: passed, except one quality test (Nango pinning) that also fails on unmodified main.
- Ledger validator and its tests: passed.

## Exact external prerequisites (unchanged)

| Prerequisite | Needed for |
| --- | --- |
| TCP path to the Neon project, and a `zasp_operator` role created there | First install on Neon |
| Stytch: redirect URLs registered, billing verified, an OAuth provider enabled | Invitation delivery and browser sign-in |
| A real AWS account with the deployment roles, KMS keys, queues and buckets | Anything beyond LocalStack emulation |
| Helm and a cluster | Release render and deployment gates |

## Next batch, in dependency order

1. **Activate approval-notification delivery** so readiness can pass, and prove a delivery end to end on the local stack.
2. **Run the workers on the local stack.** Create their queues, keys and endpoints in LocalStack, start the Security Agent, discovery, scheduler and runtime workers, and drive one discovery and one Security Agent run.
3. **Member onboarding and sign-in beyond the first administrator**: membership creation for invited members, Organization selection at sign-in in SaaS mode, SSO token exchange.
4. **Install on Neon** as soon as a TCP path exists.
