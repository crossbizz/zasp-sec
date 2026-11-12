# MVP launch plan, 2026-11-12

This replaces "finish all 728 microtasks" as the working plan. The 728-row ledger stays as the record of what was built; this plan orders the remaining work by the product's golden path, because a row marked complete has repeatedly turned out not to run against real dependencies.

## What the MVP must prove

From the PRD (executive summary, §21 gate 1, §25): one loop on a production-grade system. An enterprise onboards, discovers an agent, sees its impact, validates it safely, lets a bounded Security Agent plan and act, verifies containment, and can audit all of it. The PRD's own cut line is §1 ("Keep in MVP", "Move after MVP", "Explicitly not MVP") and §4.1 (P0 capabilities). This plan does not cut any P0 capability. It orders them, and it defers proof of the second deployment mode (single-tenant) until the SaaS path runs end to end.

## Rule for "done"

A step is done when it has run through the product's own binaries against real dependencies (PostgreSQL without superuser, Temporal, OpenFGA, Stytch, and AWS or LocalStack in development), driven the way a user or operator drives it. A passing component test is not "done".

## Golden path: state of each step

| # | Step (PRD) | State on 2026-11-12 | Next action |
| --- | --- | --- | --- |
| 0 | Install and operate | Schema installed on production Neon and on the local stack without superuser. API reports ready. Scheduler and discovery workers start. | Deploy manifests still use the old login names and lack the install job and approval-delivery settings. Update them. |
| 1 | First-Admin bootstrap (§6.1) | `zasp-bootstrap` creates the Organization, Workspace, Environments, admin membership and scopes against real Stytch. | Done for the operator side. |
| 2 | Sign-in and corporate SSO (§6.1, §14.2) | Sign-in start redirects to Stytch. Stytch redirect URLs and Google OAuth are now configured. No sign-in has been completed. Only bootstrapped admins of one Organization can sign in; SSO tokens are not exchanged; invited members get no membership. | Complete one browser sign-in. Then member onboarding, Organization selection in SaaS mode, SSO token exchange, SCIM. |
| 3 | Connect launch systems (§6.2–6.3) | API connector readiness passes against LocalStack. No connector has been connected through the product. | After sign-in: connect AWS (LocalStack) through the UI and API. |
| 4 | Discover (§7) | Discovery worker runs and consumes its queue. No discovery run has been driven. | Drive one discovery run end to end; confirm inventory appears. |
| 5 | Inventory, capability, findings, attack path (§8) | Built and component-tested. Projection workers (risk, graph, search) not started here; graph needs Neo4j. | Start projection workers; decide the local graph store. |
| 6 | Red team and Attack Lab (§9) | Built and component-tested. Workers not started here. Attack Lab needs EKS Fargate, which LocalStack does not emulate. | Red team on the local stack; Attack Lab needs real AWS. |
| 7 | Runtime policy: Monitor and Block (§10) | Built and component-tested. Runtime pipeline workers pass their database readiness; not started here. | Start the runtime pipeline; ingest one event; enforce one policy. |
| 8 | Security Agent plan, authorization, action or approval (§11) | Worker gate open. An OpenRouter key is now available. Worker not started. Approval-notification delivery is activated but no notification has been delivered. | Start the Security Agent worker; drive one run that raises an approval; deliver the notification. |
| 9 | Containment, temporary-control expiry, re-test (§11.8–11.9) | Built and component-tested. | Covered by the run in step 8. |
| 10 | Session investigation and audit export (§12) | Built and component-tested; export readiness passes against LocalStack. | Verify after steps 4–8 produce real data. |

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
| A deployment target that reaches Neon over TCP (a server or cluster) | Running the API and workers against the production database. |
| A real AWS account | Attack Lab on Fargate; real IAM, KMS and network behaviour. |
| A decision on the connector-reconciliation authority model | See the 2026-11-12 readiness update. |

## Not in the MVP

Unchanged from PRD §1: synchronous inline Require Approval, built-in case management, least-privilege recommendations, deep Azure and GCP, broad provider remediation, more Attack Lab providers, coding-agent endpoint hooks, Garak and Akto, deep drift UI, expanded compliance UX, custom roles, and everything under "Explicitly not MVP".
