# MVP launch plan, 2026-11-12

This replaces "finish all 728 microtasks" as the working plan. The 728-row ledger stays as the record of what was built; this plan orders the remaining work by the product's golden path, because a row marked complete has repeatedly turned out not to run against real dependencies.

## What the MVP must prove

From the PRD (executive summary, §21 gate 1, §25): one loop on a production-grade system. An enterprise onboards, discovers an agent, sees its impact, validates it safely, lets a bounded Security Agent plan and act, verifies containment, and can audit all of it. The PRD's own cut line is §1 ("Keep in MVP", "Move after MVP", "Explicitly not MVP") and §4.1 (P0 capabilities). This plan does not cut any P0 capability. It orders them, and it defers proof of the second deployment mode (single-tenant) until the SaaS path runs end to end.

## Rule for "done"

A step is done when it has run through the product's own binaries against real dependencies (PostgreSQL without superuser, Temporal, OpenFGA, Stytch, and AWS or LocalStack in development), driven the way a user or operator drives it. A passing component test is not "done".

## Golden path: state of each step

| # | Step (PRD) | State on 2026-11-12 | Next action |
| --- | --- | --- | --- |
| 0 | Install and operate | The baseline artifact installs without superuser (local stack; installer test on a fresh database). The Helm chart installs the baseline with an install job and the `zasp_svc_*` logins; Terraform and a runbook for production AWS exist (`docs/operations/production-aws-runbook.md`). Both Neon databases still hold an older artifact. Nothing has been deployed to a cluster. | Reinstall the Neon databases with the current artifact. Deploy to real AWS with the values the runbook lists. |
| 1 | First-Admin bootstrap (§6.1) | `zasp-bootstrap` creates the Organization, Workspace, Environments, admin membership and scopes against real Stytch, on the local database and on the Neon development branch. The Stytch invitation call was refused for a made-up address; the member was created directly instead. Whether Stytch delivers an invitation to a real address is unproven. | Invite one real address and confirm delivery. |
| 2 | Sign-in and corporate SSO (§6.1, §14.2) | **First sign-in completed on 2026-11-13** against the Neon development branch: Stytch invitation email, token exchanged at `/api/v1/session/callback`, product session issued, session bootstrap returns the Organization admin's scope and permissions. Not exercised: the Google OAuth redirect, the UI in a browser, SSO token exchange, invited members beyond bootstrapped admins, SaaS Organization selection. Stytch refuses invitations outside the account's own email domain until billing is verified. The stack's single projector pass (`-limit 1`) left the second admin's permissions pending until another pass ran; production needs the projector running continuously. | Verify Stytch billing. Then browser sign-in through the UI, member onboarding, Organization selection, SSO, SCIM. |
| 3 | Connect launch systems (§6.2–6.3) | **Done on the local stack (2026-11-13):** an AWS integration is created and activated through the API against LocalStack, with the customer role under `/zasp-reference/` and an external-id reference. Setup status answers. Kubernetes and the generic webhook are not connected. | Connect real AWS. Kubernetes and webhook connections. |
| 4 | Discover (§7) | **Done on the local stack (2026-11-13):** a requested sync runs through Temporal and the discovery worker and succeeds in about 100 seconds; 4 identities and 2 posture findings appear through the API. A run that dies mid-page is released by the next sync on that integration after 10 quiet minutes (tested by killing the worker). An abandoned run with no later sync stays `running`. | Real AWS account. A periodic release so an abandoned run does not wait for the next sync. |
| 5 | Inventory, capability, findings, attack path (§8) | **Projections run on the local stack (2026-11-13):** the risk, graph and search workers are ready; after a sync Neo4j holds 13 nodes and 21 edges, the search index 15 documents, and all three report `current`. Provider kinds are mapped to neutral kinds. Home and search answer. Attack paths on real data and the pages in a browser are unverified. | Verify attack paths and the UI pages on discovered data. |
| 6 | Red team and Attack Lab (§9) | Built and component-tested. Workers not started here. Attack Lab needs EKS Fargate, which LocalStack does not emulate. | Red team on the local stack; Attack Lab needs real AWS. |
| 7 | Runtime policy: Monitor and Block (§10) | Built and component-tested. Runtime pipeline workers pass their database readiness; not started here. | Start the runtime pipeline; ingest one event; enforce one policy. |
| 8 | Security Agent plan, authorization, action or approval (§11) | The Security Agent writes (create, update, activate, run, execution controls) are authorized functions; create, update and run are verified live with an API token, activation and execution controls at SQL level (browser-session routes). The worker starts (`stack.sh worker security-agent`) and reads each Environment's pricing binding from the administrator-approved policy in the database; a mounted file is only an override. An activated finding-response agent starts runs automatically for matching open findings. A run reaches the planner request: pricing lookup passes, the provider reservation is made, the request is sent to OpenRouter, and OpenRouter answers 402 (the account has no credits); the run ends `needs_human`. No approval has been raised, so approval-notification delivery is still unexercised. | Fund the OpenRouter account, then drive a run through plan, approval and notification. Add a product route for the pricing approval (`pricing_admin` has none) and for the test-selector configuration the worker needs at startup. A run admitted while no pricing approval exists fails its workflow and stays `queued`, holding the agent's concurrency slot. Run detail, cancel and approval detail are still historical statements (in progress). A manual run is admitted only on a finding or attack path its requester may read. |
| 9 | Containment, temporary-control expiry, re-test (§11.8–11.9) | Built and component-tested. | Covered by the run in step 8. |
| 10 | Session investigation and audit export (§12) | Built and component-tested; export readiness passes against LocalStack. | Verify after steps 4–8 produce real data. |

## Authorization state of the API

State on 2026-11-13, local stack, artifact `3e35f8d0…`.

- **Reads.** Home summary, search, profile, integrations and setup status, inventory (agents, tools, identities, runtimes), findings, attack paths, compliance, Organization, members, group mappings, SSO and SCIM connections, Security Agent definitions, runs and approvals lists, tests and audit events answer through authorized functions. Home takes 4 to 7 seconds and search 2 to 4; both grow with the number of objects.
- **Direct database paths closed.** The API logins lost their unused grants on historical functions and tables. The functions a readiness check pins refuse an API session without a proof for the same scope and actor. Both reviews' attack scripts now end in `permission denied` or `checked request required`.
- **Still open.** A guarded historical function accepts any proof for its scope, not one for a specific operation. `zasp_authorization80.resolve` and `zasp_identity_admin_effective_scopes` answer an API login without a proof (object ids, versions and a principal's scopes). Pricing approval has an authorized function but no product route yet. Security Agent run detail, cancel and approval detail are being moved.
- **Tests.** Older API tests that call historical functions directly as an API principal are now refused; the API suite also stops at a panic in `TestSecurityAgentOrderedHTTP` that predates this work, so tests after it do not run.

Every schema change means a new baseline artifact and a reviewed `zasp_baseline.accept` on installed databases.

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
