# MVP launch plan, 2026-11-12

This replaces "finish all 728 microtasks" as the working plan. The 728-row ledger stays as the record of what was built; this plan orders the remaining work by the product's golden path, because a row marked complete has repeatedly turned out not to run against real dependencies.

## What the MVP must prove

From the PRD (executive summary, §21 gate 1, §25): one loop on a production-grade system. An enterprise onboards, discovers an agent, sees its impact, validates it safely, lets a bounded Security Agent plan and act, verifies containment, and can audit all of it. The PRD's own cut line is §1 ("Keep in MVP", "Move after MVP", "Explicitly not MVP") and §4.1 (P0 capabilities). This plan does not cut any P0 capability. It orders them, and it defers proof of the second deployment mode (single-tenant) until the SaaS path runs end to end.

## Rule for "done"

A step is done when it has run through the product's own binaries against real dependencies (PostgreSQL without superuser, Temporal, OpenFGA, Stytch, and AWS or LocalStack in development), driven the way a user or operator drives it. A passing component test is not "done".

## Golden path: state of each step

| # | Step (PRD) | State on 2026-11-12 | Next action |
| --- | --- | --- | --- |
| 0 | Install and operate | Schema installed on production Neon and on the local stack without superuser. The API reports ready and the scheduler worker starts against a Neon development branch (`zasp-dev`), reached over the WebSocket transport on port 443. Discovery worker starts on the local database. | Deploy manifests still use the old login names and lack the install job and approval-delivery settings. Update them. |
| 1 | First-Admin bootstrap (§6.1) | `zasp-bootstrap` creates the Organization, Workspace, Environments, admin membership and scopes against real Stytch, on the local database and on the Neon development branch. The Stytch invitation call was refused for a made-up address; the member was created directly instead. Whether Stytch delivers an invitation to a real address is unproven. | Invite one real address and confirm delivery. |
| 2 | Sign-in and corporate SSO (§6.1, §14.2) | **First sign-in completed on 2026-11-13** against the Neon development branch: Stytch invitation email, token exchanged at `/api/v1/session/callback`, product session issued, session bootstrap returns the Organization admin's scope and permissions. Not exercised: the Google OAuth redirect, the UI in a browser, SSO token exchange, invited members beyond bootstrapped admins, SaaS Organization selection. Stytch refuses invitations outside the account's own email domain until billing is verified. The stack's single projector pass (`-limit 1`) left the second admin's permissions pending until another pass ran; production needs the projector running continuously. | Verify Stytch billing. Then browser sign-in through the UI, member onboarding, Organization selection, SSO, SCIM. |
| 3 | Connect launch systems (§6.2–6.3) | With a real admin session, 21 of 42 parameterless read routes answer. See "Read routes under the current authorization model" below. The integration catalog (AWS, Kubernetes, generic webhook) and integration list answer. No connector connected yet. | Schema work for the refused routes, starting with inventory; then connect AWS (LocalStack) through the API. |
| 4 | Discover (§7) | Discovery worker runs and consumes its queue. No discovery run has been driven. | Drive one discovery run end to end; confirm inventory appears. |
| 5 | Inventory, capability, findings, attack path (§8) | Built and component-tested. Projection workers (risk, graph, search) not started here; graph needs Neo4j. | Start projection workers; decide the local graph store. |
| 6 | Red team and Attack Lab (§9) | Built and component-tested. Workers not started here. Attack Lab needs EKS Fargate, which LocalStack does not emulate. | Red team on the local stack; Attack Lab needs real AWS. |
| 7 | Runtime policy: Monitor and Block (§10) | Built and component-tested. Runtime pipeline workers pass their database readiness; not started here. | Start the runtime pipeline; ingest one event; enforce one policy. |
| 8 | Security Agent plan, authorization, action or approval (§11) | The Security Agent writes (create, update, activate, run, execution controls) are authorized functions; create, update and run are verified live with an API token, activation and execution controls at SQL level (browser-session routes). The worker starts (`stack.sh worker security-agent`) and reads each Environment's pricing binding from the administrator-approved policy in the database; a mounted file is only an override. An activated finding-response agent starts runs automatically for matching open findings. A run reaches the planner request: pricing lookup passes, the provider reservation is made, the request is sent to OpenRouter, and OpenRouter answers 402 (the account has no credits); the run ends `needs_human`. No approval has been raised, so approval-notification delivery is still unexercised. | Fund the OpenRouter account, then drive a run through plan, approval and notification. Add a product route for the pricing approval (`pricing_admin` has none) and for the test-selector configuration the worker needs at startup. A run admitted while no pricing approval exists fails its workflow and stays `queued`, holding the agent's concurrency slot. Run detail, cancel and approval detail are still historical statements. |
| 9 | Containment, temporary-control expiry, re-test (§11.8–11.9) | Built and component-tested. | Covered by the run in step 8. |
| 10 | Session investigation and audit export (§12) | Built and component-tested; export readiness passes against LocalStack. | Verify after steps 4–8 produce real data. |

## Read routes under the current authorization model

Measured on 2026-11-13 with a real Organization admin session against the Neon development branch. The current authorization model admits only database statements on an explicit allowlist, each backed by an authorized SQL function. Much of the product was never moved onto it.

| Routes | State | What is needed |
| --- | --- | --- |
| Profile, home summary, integrations, catalog, policies, sensors, findings, attack paths, sessions and 12 others | Answer (200), in 5 to 8 seconds | Authorization target resolution takes about 5 seconds per request. It must get faster. |
| Compliance evidence | Fixed: answers | — |
| Compliance controls | Answers for a small page; the default page takes about 13 seconds and the server drops it at 10 | Faster resolution; batch the per-control reads. |
| Agents, tools, identities, runtimes | Allowlist bug fixed; PostgreSQL now refuses with `authorization inventory page rejected` | Inferred, not verified: the Environment has no inventory cutover state, and nothing in the product sets one for a new Environment. Needs a schema or bootstrap change. |
| Organization, members, group mappings, SSO and SCIM connections | Refused: no authorized SQL function exists | New functions in the schema plus allowlist rules. |
| Security Agent runs and approvals, tests, test runs, Attack Lab runs | Refused: no authorized SQL function exists | Same. |
| Security Agent definitions, templates, actions, execution controls | Refused earlier: a readiness check requires exactly 60 schema versions and the baseline has 61, so it can never pass | A current readiness function, then authorized reads. |
| Audit events | Times out | Resolution takes about 12 seconds; the authorized page is wired only with export storage; the API role lacks a grant its readiness check needs. |

Every schema item means a new baseline artifact and a reviewed `zasp_baseline.accept` on installed databases.

## Order of work

1. **One completed sign-in** on the local stack. Everything after it needs a session.
2. **Deployment manifests** for the baseline: operator and `zasp_svc_*` logins, install job, verifier registration, approval-delivery settings.
3. **Steps 3–4**: connect and discover against LocalStack.
4. **Steps 8–9**: Security Agent run with approval and delivered notification.
5. **Steps 5 and 7**: projections and runtime pipeline.
6. **Step 2 completion**: member onboarding, SaaS Organization selection, SSO, SCIM.
7. **Real AWS**: Attack Lab (step 6), IAM and KMS policy, and the staging deployment.
8. **Enterprise gates** (PRD §21): tenant-isolation release test on the deployed system, DR rehearsal, single-tenant install, performance targets, SBOM and signing.

## What needs a person or an external system

| Need | For |
| --- | --- |
| A Google account sign-in in a browser, on a machine that resolves the stack's origin | Step 2. An automated run cannot complete Google OAuth. |
| A deployment target (a server or cluster) | Running the API and workers against the production database. From HTTPS-only networks `ZASP_POSTGRES_TRANSPORT=websocket` reaches Neon; development runs use the `zasp-dev` branch, never production. |
| A real AWS account | Attack Lab on Fargate; real IAM, KMS and network behaviour. |
| A decision on the connector-reconciliation authority model | See the 2026-11-12 readiness update. |

## Not in the MVP

Unchanged from PRD §1: synchronous inline Require Approval, built-in case management, least-privilege recommendations, deep Azure and GCP, broad provider remediation, more Attack Lab providers, coding-agent endpoint hooks, Garak and Akto, deep drift UI, expanded compliance UX, custom roles, and everything under "Explicitly not MVP".
