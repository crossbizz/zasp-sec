# Installing the product schema (baseline)

`agentsec-migrate install-baseline` installs the complete product schema into an empty PostgreSQL database in one transaction. It needs no PostgreSQL superuser, so it works on managed PostgreSQL (Neon, RDS, Cloud SQL) as well as on a server you run yourself.

It replaces the historical migration chain for new installations. The chain needs a superuser and cannot run on managed PostgreSQL: PostgreSQL 16 and later give the role that creates another role an administrative membership the creator cannot remove, and the chain's own checks reject that membership.

## Requirements

| Requirement | Why |
| --- | --- |
| PostgreSQL 16 or later (18 is the reference) | The installer uses PostgreSQL 16 role-membership options. |
| Database collation `C` or `C.UTF-8` | Stored orderings in the schema assume it. |
| A role named `zasp_operator` with `LOGIN`, `CREATEROLE` and `BYPASSRLS`, that owns the database | The schema records this role as the grantor of its privileges, so the name is fixed. It does not need `SUPERUSER` or `CREATEDB`. |
| An empty database | The installer refuses a database that already holds a product schema. |
| The `pgcrypto` extension available | It is a trusted extension, so the database owner can create it. |

Create the operator and database once, as the provider's administrative role:

```sql
CREATE ROLE zasp_operator LOGIN CREATEROLE BYPASSRLS PASSWORD '...';
CREATE DATABASE zasp OWNER zasp_operator TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C';
```

On Neon, create the role and database with SQL as shown, not through the Neon console or API: roles created by the Neon API cannot be altered afterwards. Use a direct (non-pooled) connection for installation.

## Install

```bash
ZASP_POSTGRES_DSN='postgres://zasp_operator:...@host/zasp?sslmode=require' /app/agentsec-migrate install-baseline
```

On success it prints `{"artifact":"<sha256>","installed":true}`. It takes a few seconds. If any step fails, nothing is left behind.

The installer:

1. Creates the product roles: the non-login authority roles and the 31 service logins (`zasp_svc_api`, `zasp_svc_outbox`, and so on). Service logins are created without passwords and with no privilege beyond membership in their own authority role.
2. Creates every schema, table, function, policy and reference row as the operator.
3. Hands each object to its owning role. For this step only, the operator becomes a member of each owning role and each owning role may create in each schema. Both are removed again before the transaction ends.
4. Seals the catalog (see below) and checks that authorization readiness passes.

Afterwards the operator holds one membership, in `zasp_discovery_authority`, which the registration commands require.

### After installing

1. Set a password on each service login, as the operator: `ALTER ROLE zasp_svc_api PASSWORD '...';`. `SELECT rolname FROM pg_roles WHERE rolname LIKE 'zasp_svc_%'` lists them.
2. Register the deployment's verification keys, as the operator with `ZASP_MIGRATION_DB_PRINCIPAL=zasp_operator`: `register-authorization-verifier`, `register-worker-authorization-verifier`, `register-compensation-authorization-verifier` and `register-approval-maintenance-verifier`, then, once the first Organization exists, `register-identity-session-verifier` and `register-identity-webhook-verifier`.
3. Configure approval-notification delivery on the API, the workers and the permission projector: see the approval-maintenance bundle in [Cloud launch configuration](cloud-launch-configuration.md). The API does not report ready without it.
4. Create the first Organization: see [First Organization bootstrap](first-organization-bootstrap.md).

The service logins already hold their database bindings. `register-temporal-executor-principals` is not needed on a baseline installation.

### With the Helm chart

The hosted chart's schema job runs `verify-baseline`, `install-baseline` when that fails, and the four registrations of step 2, as `zasp_operator`. With `schema.registerIdentityVerifiers: true` it also runs the two identity registrations. It does not set passwords or create the first Organization. [Production deployment](production-deployment.md#schema-installation) lists the values, the Secrets to create first, and what has and has not been checked.

## Connecting where only HTTPS egress is allowed

Set `ZASP_POSTGRES_TRANSPORT=websocket` on `agentsec-migrate`, `zasp-bootstrap`, the API and the workers to carry the PostgreSQL protocol inside a TLS WebSocket on port 443 of the DSN's host (path `/v2`) instead of TCP port 5432. Neon serves this endpoint. Sessions, transactions and authentication are unchanged; the server certificate is always verified against the DSN's host, and the standard `HTTPS_PROXY` setting is honoured. The DSN must name a DNS host and use `sslmode=require` or stricter. Unset, or `tcp`, is the default and is what a normal deployment uses.

With this setting `install-baseline` and `verify-baseline` work from an HTTPS-only network, so the script form below is needed only where WebSockets are blocked too.

## Installing over an HTTPS SQL endpoint

Where port 5432 is not reachable but the provider offers an HTTPS SQL endpoint (Neon does), print the installation as single statements and send them as one transaction:

```bash
ZASP_BASELINE_EXISTING_ROLES=zasp_operator /app/agentsec-migrate baseline-script > script.json
```

`script.json` is a JSON array of about 12,000 statements. Send them in order, in one transaction on one session, as `zasp_operator` (for Neon: one `POST https://<endpoint host>/sql` with `{"queries":[{"query":...,"params":[]},...]}`). The last statement seals the catalog and raises an error unless it is intact and ready, which rolls everything back. `ZASP_BASELINE_EXISTING_ROLES` lists product roles the cluster already has, so they are not created twice. Check the preconditions yourself first: this form cannot.

The production Neon project was installed this way on 2026-11-12 in 7 seconds.

## Refusals

A refusal prints one line and exits with status 1:

```text
baseline refused: stage=<stage> [reason=<reason>] [sqlstate=<code> message=<message>]
```

| Stage | Cause |
| --- | --- |
| `configuration` | `ZASP_POSTGRES_DSN` is not set. |
| `database` | The database is unreachable. |
| `preconditions` | A requirement above is not met. The reason says which. |
| `roles` | A product role could not be created or altered. Usually a role of the same name already exists and belongs to another role. |
| `objects`, `ownership` | A statement failed. The SQLSTATE and message name the object. |
| `seal`, `verification` | The installed catalog did not seal or did not pass readiness. |

The message can contain object names. It never contains a credential: installation runs definitions only.

## Integrity

The historical releases verified one another by hashing each other's function bodies and comparing fingerprints with constants. The baseline replaces all of that with one check, `zasp_baseline.intact()`: is the catalog still the one that was installed?

At installation the catalog is sealed. The seal records a digest of every definition, owner and privilege in the product schemas and of the product roles and their memberships. Every readiness predicate, and the worker startup gate, depends on `intact()`. If any product function, table, policy, privilege, role attribute or membership changes, readiness turns false and the workers refuse to start. A changed catalog cannot be re-sealed.

```bash
ZASP_POSTGRES_DSN=... /app/agentsec-migrate verify-baseline
```

prints `{"sealed":true,"intact":true,"artifact":"<sha256>","current":true}` and exits 0 when the database holds this release's catalog unchanged. `current` is false when the database was installed from a different artifact.

Maintenance that rewrites catalog rows without changing their meaning (`VACUUM FULL`, `REINDEX`, a restore) does not break the seal. The check falls back from a fast comparison of row versions to the full digest, which costs about 150 ms per readiness evaluation until `verify-baseline` is run once to refresh the fast path. Run `verify-baseline` after a restore or a major-version upgrade.

Extension functions (`pgcrypto`) are outside the seal: on managed PostgreSQL they belong to the provider and change with extension upgrades.

A later, reviewed schema change must end by calling `zasp_baseline.accept('<artifact sha256>')` as the operator. Nothing else can re-seal a changed catalog.

## What changed relative to the historical chain

The baseline is generated from the chain, so it is the same schema. `services/platform/migrations/baseline/generate.sh` checks that on every regeneration: 147 readiness predicates return the same value on both, and about 13,900 structural facts (every schema, table, column, constraint, index, trigger, policy, function signature, owner, privilege, role and membership) are identical.

Five things differ on purpose:

- **Integrity checks.** Function bodies that hashed other functions or compared fingerprint constants call `zasp_baseline.intact()` instead (`rules.sql`).
- **Role memberships** are read through `zasp_baseline.role_memberships`, which hides the administrative membership PostgreSQL gives a non-superuser that creates a role.
- **The worker startup gate is open.** The chain shipped `zasp_authorization80_worker.runtime_ready()` as `... AND false`. In the baseline it follows catalog integrity. The Security Agent, discovery and scheduler worker modes pass their database startup check; before, they could not start on any database.

- **Approval-notification delivery is installed and active.** The chain shipped the approval-maintenance profile as an inactive candidate with no installer, so no approval notification was ever delivered and the API never reported ready. The baseline installs it, binds its dedicated login (`zasp_svc_approval_maintenance`), marks it active and adds `zasp_approval_maintenance.activate_projection`, which `zasp-bootstrap` calls for each Organization (`activation.sql`). The profile's own origin, delegation, reservation and settlement code is unchanged.

- **The product completion is applied** (`completion.sql`). The chain moved about half of the product onto the current authorization model. The baseline adds the authorized reads the rest needs (Security Agent definitions, execution controls, runs and approvals; tests, test runs and Attack Lab runs; the Organization, members, group mappings and the identity-provider organization lookup), capability readiness that is valid on the 61-release catalog, the inventory cutover of every new Environment, and one readiness check per candidate resolution instead of one per nested kind. It also adds the authorized Security Agent writes (create, update, delete, activate, run, execution controls) and the two single-object reads they need, the authorized single sign-on and SCIM connection writes, the per-Environment planner pricing binding the Security Agent worker reads instead of a mounted file, an approval page that filters before it pages, an audit page that checks resolver readiness once per page, and it revokes the direct grants on historical readers that the authorized functions replace wherever no historical role-shape check requires the grant. These objects change catalogs the historical layers hash, so `generate.sh` records the superuser installation's readiness predicates before applying the file and compares the finished baseline with that record. The structural comparison includes the new objects.

Service login names are fixed (`zasp_svc_*`). Set the `ZASP_*_DB_PRINCIPAL` settings to those names.

## Regenerating the artifact

`baseline.sql.gz`, `roles.sql` and `baseline.sha256` in `services/platform/migrations/baseline/` are generated. After changing the chain, `prelude.sql`, `rules.sql`, `activation.sql` or `completion.sql`, run:

```bash
services/platform/migrations/baseline/generate.sh
```

It needs Docker, Go and `psql`, and takes about five minutes. It stops if a rewrite rule no longer matches anything, or if the baseline's predicates or structure differ from the superuser installation.

## Not covered

- **Installing with `install-baseline` on production.** The production Neon project was installed over Neon's HTTPS SQL endpoint (above), not with `install-baseline`. Both run the same statements, and `verify-baseline` has since confirmed that installation over the WebSocket transport.
- **Upgrading an existing chain-installed database.** The baseline installs into an empty database only. No production database exists yet, so there is nothing to upgrade.
- **Removing the historical chain.** It stays in the repository as the generator's input.
