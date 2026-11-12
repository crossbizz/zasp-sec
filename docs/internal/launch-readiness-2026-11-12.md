# Launch readiness update, 2026-11-12

Launch is not accepted. Three blockers are fixed since [the 2026-11-11 report](launch-readiness-2026-11-11.md): the schema installs without a superuser, the worker startup gate is open, and the API reports ready. `/readyz` returns 200 for the first time, on a non-superuser baseline install with LocalStack and the real Stytch TEST project. One worker mode (the scheduler) has run; the others have not. Nothing here was run in a deployment.

## Ledger

728 rows: **518 production-available, 149 component-only, 61 blocked/external**. One row moved from production-available to component-only (M1-10, Neon schema baseline). No row was promoted. The [remaining list](launch-remaining-tasks-2026-11-12.tsv) holds all 210 rows outside production-available.

## What changed

### 1. The schema installs without a superuser (was blocker 1)

`agentsec-migrate install-baseline` installs one generated baseline in a single transaction, as an operator that has `CREATEROLE` and `BYPASSRLS` but no `SUPERUSER`. That is what Neon, RDS and Cloud SQL give a database owner. Operator guide: [baseline-schema-install.md](../operations/baseline-schema-install.md).

| Check | Result |
| --- | --- |
| Install on PostgreSQL 18.3 as a non-superuser operator | Passed, about 2 s, one transaction |
| Second database in the same cluster (roles already exist) | Passed |
| Readiness predicates, baseline against superuser installation | 147 of 147 agree, apart from the two listed below |
| Catalog structure, baseline against superuser installation | About 13,900 facts identical: every schema, table, column, constraint, index, trigger, policy, function signature, owner, privilege, role and membership |
| Operator memberships left after install | One, in `zasp_discovery_authority`, as designed |
| Owner-level changes after install (16 kinds: function body, strictness, cost, security, settings, grants, row security, rewrite rule, trigger, view, new objects, role membership, argument defaults) | Each turns `intact()` false; the worker gate closes; re-seal is refused |
| Verifier registration and `zasp-bootstrap` as the non-superuser operator | Passed against the real Stytch TEST project |
| API on the baseline | Starts, serves, and `/readyz` returns `200 {"status":"ready"}` |

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

The discovery scheduler worker was then started on the baseline (`stack.sh worker scheduler`). It runs, polls its schedules through `zasp_temporal72.pending_schedules`, and its `/readyz` returns 200. Before, it refused at startup on every database.

**Not done:** no other worker mode has been started. Each needs queues, keys and endpoints that the local stack does not create yet, and the Security Agent worker needs an OpenRouter API token. No discovery run or Security Agent run has been driven.

### 3. Development mode against LocalStack

The production binaries use LocalStack and a local OpenSearch node when `ZASP_LOCAL_CLOUD_ENDPOINT` is set and `ZASP_ENVIRONMENT` is `development` or `test`. With any other environment a process that finds the setting refuses to start. Without the setting nothing changes. The production search-schema job runs against the local node, and the API's repository, policy-history, identity-provider and export readiness checks pass.

`deploy/local/real-stack/stack.sh up` now takes about 15 seconds (it was 95) and exercises the production install path.

### 4. Readiness failures are named

When `/readyz` returns 503 the API logs the first check that refused, from a fixed list. That is how the two readiness blockers below were found.

### 5. The API reports ready (was a blocker found in this batch)

`/readyz` failed on every database, for two reasons. Both came from the same rule: with the current authorization model the API refuses any product statement that carries no request authorization, and background loops have no request.

**Approval notifications.** The legacy delivery loop was refused, by design. Its replacement, the approval-maintenance profile, shipped as an "inactive integration candidate": no command installed it, its registration could never become active, every notification origin was recorded as `captured_inactive`, and no function could activate an Organization. So no approval notification was ever delivered. The baseline now installs the profile, binds a dedicated login (`zasp_svc_approval_maintenance`), marks it active, and adds one operator-only function that activates delivery for an Organization against its exact authorization store and model. `zasp-bootstrap` calls it. The profile's own code (signed origin capture, delegation, reservation, settlement, the per-delivery permission check) is unchanged.

**Connector reconciliation.** The API's background connector reconciler, which finishes or cleans up connector work that authorized requests created, was refused the same way and nothing replaced it. Its eight lease-bound statements are now classified explicitly as system maintenance (`apiserver/connector_maintenance_authorization.go`). Only the reconciler can mark a context; statements that start connector work, write credentials or remediate a quarantine still need a request authorization.

**This is a security-model decision, recorded for review.** The alternative for connector reconciliation is the approval-maintenance pattern: capture a delegation when the request creates the work and re-check the requester's permission before each background step. That would stop a connection from completing if its requester lost permission in the seconds between request and reconciliation. It is a larger change and is not done.

**Not done:** no approval notification has been delivered end to end. That needs a Security Agent run that raises an approval, which needs the workers (next batch). The earlier report said readiness failed on a false SQL function. That was wrong; the SQL check passes.

## Verification for this batch

- `go test ./migrations/baseline` with a non-superuser operator database: passed.
- Go packages touched (`agentsec-migrate`, `migrations`, `localcloud`, `bootstrap`, `cmd/...`, `agentsec-api`, `agentsec-worker`, `apiserver`, `approvalmaintenance`, `authorization`): no failure that is not also present on unmodified main in this environment.
- UI unit suite, typecheck, lint and production build: passed, except one quality test (Nango pinning) that also fails on unmodified main.
- Ledger validator and its tests: passed.

## Independent review

A separate reviewer read the integrity schema, the installer, the temporary-grant scripts, the rewrite rules, the approval-delivery activation and the connector classification, and tested the integrity model on a live database.

- **Found and fixed:** the catalog digest did not cover table rewrite rules, function strictness, argument defaults or cost, or sequence parameters. An owner-level actor could have changed those without breaking the seal. The digest now covers them, and the installer test applies 16 kinds of owner-level change and requires each to break the seal.
- **Confirmed:** a role other than the operator cannot seal, re-seal or accept; no temporary installation privilege survives; activation is operator-only and fails closed with the delivery grants; the connector classification is exact-match and reachable only from the reconciler; the installer cannot commit a partial install.
- **Left as is (low):** `zasp-bootstrap` binds authorization and activates approval delivery in two statements. A crash between them leaves the binding without activation; a second run completes it.

## Exact external prerequisites

| Prerequisite | Needed for |
| --- | --- |
| TCP path to the Neon project, and a `zasp_operator` role created there | First install on Neon |
| Stytch: redirect URLs registered, billing verified, an OAuth provider enabled | Invitation delivery and browser sign-in |
| A real AWS account with the deployment roles, KMS keys, queues and buckets | Anything beyond LocalStack emulation |
| An OpenRouter API token | Starting the Security Agent worker, in development or production: its planner endpoint and model are fixed |
| Helm and a cluster | Release render and deployment gates |

## Next batch, in dependency order

1. **Run the workers on the local stack.** Create their queues, keys and endpoints in LocalStack, start the Security Agent, discovery, scheduler and runtime workers, and drive one discovery run and one Security Agent run that raises an approval, so an approval notification is delivered end to end.
2. **Decide the connector-reconciliation authority model** (classification as shipped, or delegation with a permission re-check).
3. **Member onboarding and sign-in beyond the first administrator**: membership creation for invited members, Organization selection at sign-in in SaaS mode, SSO token exchange.
4. **Install on Neon** as soon as a TCP path exists.
