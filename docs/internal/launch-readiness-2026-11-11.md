# Launch readiness, 2026-11-11

Launch is not accepted. This batch ran the production binaries against real dependencies for the first time, found that the first step of the golden path did not exist in production code, built it, and found two further blockers that stop any production install. Nothing here was run in a deployment.

Starting main: `8cbd813493947d8e26289b381d90d1a5bf2bffe3`.

## Ledger

728 rows: **519 production-available, 148 component-only, 61 blocked/external**. Four rows moved from production-available to component-only (M2-07a, M2-07b, M2-07c, M2-07d). No row was promoted. The [remaining list](launch-remaining-tasks-2026-11-11.tsv) holds all 209 rows outside production-available.

The production-available class is still historical: it records what earlier audits accepted, not fresh deployed coverage. This batch shows why that matters. The four first-admin rows were recorded as "audited shipped composition" while no production code could create an Organization or a membership.

## What ran against real dependencies

All on one machine: PostgreSQL 18.3, the pinned Temporal 1.32.0 and OpenFGA 1.21.0 images (digests match `docs/operations/temporal-openfga.md`), and the Stytch TEST project through its API.

| Step | Result |
| --- | --- |
| Fresh schema install, `agentsec-migrate up-authorization-runtime-profile`, superuser operator, C collation | Passed in 55 s: schema 61, temporal 65–78, authorization 79/80 profiles |
| Six registration commands | Passed |
| Product authorization model published to OpenFGA; projector applies tuples | Passed: desired revision equals applied |
| `agentsec-api` (unmodified production binary) startup | Passed through PostgreSQL, Temporal, OpenFGA, current-authorization readiness and Stytch identity registration; `runtime_started` |
| Unauthenticated product request | `401 authentication_required` |
| Sign-in start | `302` to the real Stytch OAuth start with the issued state |
| Stytch accepts that redirect | **Refused**: `query_params_do_not_match`, the redirect URL is not registered in the Stytch dashboard |
| `zasp-bootstrap` creates the Stytch Organization | Passed against the real project |
| `zasp-bootstrap` invites the administrator | **Refused by Stytch**: `billing_not_verified_for_email` |
| `zasp-bootstrap` product records, repeated run | Passed: one Organization, default Workspace, three Environments, admin membership and scopes; the repeat changes nothing |
| Invitation callback with a token the provider rejects | `401`, after a real provider exchange |
| `/readyz` | **503**. The first failing check was not isolated. This machine has no OpenSearch policy-history index and no AWS connector secrets, and readiness checks both |
| Browser sign-in to completion | **Not run**: needs the two Stytch settings above and a person |

`deploy/local/real-stack/stack.sh` reproduces all of this from a clean machine in about two minutes.

One Organization was left in the Stytch TEST project for the next acceptance run: slug `zasp-bootstrap-acceptance.example`, stamped by the bootstrap, with one active member, `first-admin@zasp-bootstrap-acceptance.example`. Bootstrapping that name, domain and address resolves both without sending email. Every other Organization created during the bring-up was deleted.

## Launch blockers found in this batch

These are code or configuration facts, each reproduced. They are ordered by how early they stop a launch.

### 1. The schema cannot be installed on Neon

Neon is the required database, and a Neon role is not a superuser. As a non-superuser owner with `CREATEROLE` and `BYPASSRLS` on PostgreSQL 18.3, the install stops at release 10:

```text
ERROR:  ADMIN option cannot be granted back to your own grantor
```

One statement causes it, `services/platform/migrations/sql/0010_production_discovery.up.sql:751`:

```sql
GRANT zasp_discovery_authority TO CURRENT_USER WITH ADMIN OPTION;
```

A non-superuser who creates a role already holds its ADMIN option, granted by the bootstrap superuser, and PostgreSQL 16 and later refuse the self-grant. Every existing migration test runs as a superuser, so none caught it. In the same session `GRANT zasp_discovery_authority TO CURRENT_USER WITH INHERIT TRUE, SET TRUE` succeeds and leaves the operator with the same effective rights.

There is no operator-side workaround. Having a separate role create `zasp_discovery_authority` and grant it to the operator was tried; the operator's self-grant is refused the same way.

Confirmed on Neon itself, on a disposable branch that was deleted afterwards: `CREATE ROLE` as `neondb_owner` leaves an ADMIN-only membership granted by `cloud_admin`, and the same self-grant is refused with the same error.

**A guarded grant in release 10 is not enough.** Follow-up work on 2026-11-11 found that the schema's security model assumes a superuser installer throughout:

- PostgreSQL 16 and later give a non-superuser creator a membership in every role it creates. The creator cannot revoke it (`permission denied to revoke privileges granted by role`).
- The schema's own readiness predicates reject any membership outside a short list of exact shapes. `zasp_discovery_security_ready` in release 10 is the first; 70 predicate sites in 23 migration files inspect `pg_auth_members`. The automatic creator memberships fail them, at install time and at every runtime readiness check.
- Transferring ownership to the authority roles needs the operator to hold a `SET` membership in them, which is another membership the predicates reject. 144 migration files transfer ownership.

One operator-side arrangement was found that gets past release 10 with no migration change: create `zasp_discovery_authority` through a delegate role, so the release-10 grant has a different grantor, and grant the authority role `CREATE` on `public`. The install then runs releases 10 to 12 and stops at release 13, where the security predicate is false because of the delegate's membership. Every variant tried leaves at least one membership the predicates reject, and none can be removed without superuser.

So the fix is one of two things, and it is a decision:

1. **Rework the existing chain.** Change the membership predicates to accept the creator's automatic membership and the operator's `SET` membership, and guard the grants. That touches about 23 checksummed releases; their checksums are embedded in later releases and in the generated ordered-current artifacts, so the whole pinned chain is regenerated.
2. **Replace the chain with one baseline.** No database has ever had this schema installed (Neon `zasp` is empty), so the 80-release history protects nothing. Generate one reviewed baseline from a superuser install, write its role provisioning and predicates for a non-superuser owner, and retire the historical releases and their pins. The Temporal/OpenFGA plan's retirement packet already anticipates retiring them.

The worker gate (blocker 2) lives in the same pinned chain, so the choice decides how that is fixed as well.

### 2. Background workers refuse to start on the current schema profile

`zasp_authorization80_worker.runtime_ready()` is defined as `SELECT zasp_temporal78.current_ready() AND false` (`0080_authorization_worker_profile.sql:115`). Every worker mode other than the seven runtime-pipeline stages checks it at startup, so the Security Agent, discovery and scheduler workers cannot run on a database installed with the supported command. The API runs; nothing executes behind it. This is the open P7 worker-authority packet of the Temporal/OpenFGA plan, and it gates every execution, discovery and recovery flow.

### 3. Sign-in reaches only bootstrapped administrators of one Organization

- Sign-in admits only a member who already has a product membership, and before this batch nothing created one. `zasp-bootstrap` now creates it for designated administrators. Any other Stytch member (invited by an administrator, provisioned by SCIM, or joining through SSO) still has no path to a membership. M2-03 describes that reconciliation.
- Product-started sign-in always targets the one Stytch Organization in `ZASP_STYTCH_ORGANIZATION_ID`, in SaaS mode too. A second customer's members can enter through an invitation but cannot start sign-in. SaaS needs Organization selection at sign-in start.
- The callback exchanges OAuth and invitation tokens only. Corporate SSO, which the golden path names, is not accepted.

### 4. Two operator failures had no message

- The migration compares catalog fingerprints sorted with the database's default collation. On any collation other than `C` or `C.UTF-8` it stops at release 13 with `release migration failed` and no SQL error. Neon's default is `C.UTF-8`, so production is unaffected, but a mis-created database is undiagnosable. Documented; the migration tool still prints nothing more.
- A refused API start exited with status 1 and no output. Fixed: it now prints `agentsec-api startup refused: stage=<stage>` from a closed list of stages.

### 5. Readiness cost

The API readiness probe runs `zasp_authorization80.ready` and `zasp_authorization80_audit.production_ready` on both database pools on every tick. At startup those took about 0.85 s each on this machine. One failing check cancels the others, so any unavailable dependency shows up as cancelled database statements. Not yet measured against Neon latency.

## Exact external prerequisites

Nothing below can be done from the project API credentials or from this session.

| Prerequisite | Needed for | Detail |
| --- | --- | --- |
| Stytch dashboard: redirect URLs | Any sign-in | `<origin>/auth/callback?state={}` for Login and Signup, `<origin>/auth/callback` for Invite |
| Stytch billing verification, or an administrator address on the Stytch account's own domain | First-admin invitation | Otherwise `billing_not_verified_for_email` |
| Stytch dashboard: an OAuth provider enabled | Returning-member sign-in | Google, Microsoft, GitHub, Slack or HubSpot |
| A person with that mailbox | M2-07d, every browser flow | To follow the invitation and complete sign-in |
| A live Stytch project | Production | Only TEST credentials are configured |
| Real AWS credentials and account | M1A, M3-14, M8 deployment rows, connector/discovery/export readiness | The configured AWS credentials are LocalStack placeholders pointing at loopback |
| Network path to Neon on TCP 5432 | Running anything against the production database | This environment reaches Neon only over its HTTPS SQL endpoint; the product binaries need TCP |
| Helm | `deploy/production/release-contract.test.mjs` | Not installed here: 31 of 46 tests fail on unmodified main for that reason |

## Verification for this batch

- `services/platform/bootstrap`: 14 tests, 8 of them against the real installed schema on PostgreSQL 18.3.
- `services/platform/apiserver`: 14 new tests for the provider directory, token exchange and session callback. Removing the token-type check makes the suite fail.
- `services/platform/cmd/zasp-bootstrap`: 4 tests. `services/platform/agentsec-api`: package passes, with one new startup-refusal test.
- UI: 6 callback tests; typecheck passes.
- `npm run implementation:status:check` and its 40 tests pass.

The full Go suite (`go test ./...` in `services/platform`) was run on this change and on unmodified main in the same environment. Main has 132 failing test entries here and this change has 130; no test fails only on this change. The two that differ are a timing test in `internal/testprocess` that failed on main in that run.

Main is therefore not green in this environment. The failures were not all analyzed. The ones that were:

- `agentsec-migrate`: `TestPrecisionExplicitReleaseCommand`, `TestSandboxExplicitCommands` and `TestSandboxPrestageStopsAt49AndRegistersPrincipals` all fail on `up-to-56`. These are not environment failures; the tests and the command disagree on main.
- Tests that start their own PostgreSQL fail because this environment has PostgreSQL 16 binaries only and runs as root (`required owned PostgreSQL executable missing`, `initdb: exit status 1`).
- `apiserver`: `TestNative379V2ReplayCancelBudgetUnknownAndIdentity`, where a retained fixture refuses.
- `deploy/production/release-contract.test.mjs` (31 of 46) and the Nango quality contract that shells out to it, because Helm is not installed here.

The UI suite: 2,628 of 2,630 tests pass, one is skipped, and the one failure is that Nango contract. Typecheck, lint, the production build and both production import checks pass.

## Independent review

A separate reviewer read the identity change and found no authentication bypass, no cross-tenant path and no stateless OAuth completion. It judged the invitation path equal to the existing OAuth path on login CSRF, because the existing state was never bound to the browser. That is a weakness of both paths and is not fixed here.

Fixed from the review, each with a test: the bootstrap now stamps the Stytch Organizations it creates and refuses any it did not create; a single-tenant deployment bound to a Stytch Organization never creates or resolves another, and a mismatch is refused before an invitation is sent; default Workspaces and Environments are created only with the Organization, so a rerun after a rename creates nothing; the slug is the domain itself, so `foo-bar.com` and `foo.bar.com` no longer collide; `-organization-id` is refused in SaaS mode; an Organization already bound to another authorization store is not silently rebound; the provisioning transaction fixes its isolation level; and the invitation page exchanges the token only after a click.

Left open from the review:

- The stateless exchange accepts any Stytch email link for a member, not only an invitation, because Stytch redeems both the same way. Limiting it to a recorded pending invitation needs a schema change. Until then the control is a Stytch setting: frontend SDK disabled, or allowed authentication methods restricted per Organization.
- The bootstrap cannot re-send an expired invitation. Stytch's resend behaviour could not be checked while Stytch refuses to send email for this account.

## Next batch, in dependency order

1. **Make the schema install on Neon.** Guard the release-10 self-grant, regenerate the three pinned artifacts, and run the full install as a non-superuser owner until it passes end to end. Add that run as a permanent test; the superuser-only tests hid this.
2. **Open the worker gate.** Finish the P7 worker-authority packet so `runtime_ready()` can be true on a registered deployment, then run Security Agent, discovery and scheduler workers against real Temporal.
3. **Member onboarding and SaaS sign-in.** Membership reconciliation for non-bootstrap members, Organization selection at sign-in start, and SSO token exchange.
4. **Complete readiness locally.** OpenSearch and LocalStack in the real stack so `/readyz` turns green and connector, discovery and export flows can be driven.
5. **First browser acceptance.** With the Stytch prerequisites in place: invitation, first sign-in, onboarding, cross-tenant denial, permission revocation.

Items 1 and 2 need no external input.
