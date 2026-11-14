# MVP launch plan, 2026-11-12

This replaces "finish all 728 microtasks" as the working plan. The 728-row ledger stays as the record of what was built; this plan orders the remaining work by the product's golden path, because a row marked complete has repeatedly turned out not to run against real dependencies.

## What the MVP must prove

From the PRD (executive summary, §21 gate 1, §25): one loop on a production-grade system. An enterprise onboards, discovers an agent, sees its impact, validates it safely, lets a bounded Security Agent plan and act, verifies containment, and can audit all of it. The PRD's own cut line is §1 ("Keep in MVP", "Move after MVP", "Explicitly not MVP") and §4.1 (P0 capabilities). This plan does not cut any P0 capability. It orders them, and it defers proof of the second deployment mode (single-tenant) until the SaaS path runs end to end.

## Rule for "done"

A step is done when it has run through the product's own binaries against real dependencies (PostgreSQL without superuser, Temporal, OpenFGA, Stytch, and AWS or LocalStack in development), driven the way a user or operator drives it. A passing component test is not "done".

## Golden path: state of each step

| # | Step (PRD) | State (see the 2026-11-14 section for the latest) | Next action |
| --- | --- | --- | --- |
| 0 | Install and operate | The baseline artifact installs without superuser (local stack; installer test on a fresh database). The Helm chart installs the baseline with an install job and the `zasp_svc_*` logins; Terraform and a runbook for production AWS exist (`docs/operations/production-aws-runbook.md`). Both Neon databases still hold an older artifact. Nothing has been deployed to a cluster. | Reinstall the Neon databases with the current artifact. Deploy to real AWS with the values the runbook lists. |
| 1 | First-Admin bootstrap (§6.1) | `zasp-bootstrap` creates the Organization, Workspace, Environments, admin membership and scopes against real Stytch, on the local database and on the Neon development branch. The Stytch invitation call was refused for a made-up address; the member was created directly instead. Whether Stytch delivers an invitation to a real address is unproven. | Invite one real address and confirm delivery. |
| 2 | Sign-in and corporate SSO (§6.1, §14.2) | **First sign-in completed on 2026-11-13** against the Neon development branch: Stytch invitation email, token exchanged at `/api/v1/session/callback`, product session issued, session bootstrap returns the Organization admin's scope and permissions. Not exercised: the Google OAuth redirect, the UI in a browser, SSO token exchange, invited members beyond bootstrapped admins, SaaS Organization selection. Stytch refuses invitations outside the account's own email domain until billing is verified. The stack's single projector pass (`-limit 1`) left the second admin's permissions pending until another pass ran; production needs the projector running continuously. | Verify Stytch billing. Then browser sign-in through the UI, member onboarding, Organization selection, SSO, SCIM. |
| 3 | Connect launch systems (§6.2–6.3) | **Done on the local stack (2026-11-13):** an AWS integration is created and activated through the API against LocalStack, with the customer role under `/zasp-reference/` and an external-id reference. Setup status answers. Kubernetes and the generic webhook are not connected. | Connect real AWS. Kubernetes and webhook connections. |
| 4 | Discover (§7) | **Done on the local stack (2026-11-13):** a requested sync runs through Temporal and the discovery worker and succeeds in about 100 seconds; 4 identities and 2 posture findings appear through the API. A run that dies mid-page is released by the next sync on that integration after 10 quiet minutes (tested by killing the worker). An abandoned run with no later sync stays `running`. **Agent discovery added in source (2026-11-14), not yet run on a stack:** the collectors now report agents nobody labelled (Bedrock agents, AgentCore runtimes, Lambda functions that call a model, unlabelled Kubernetes workloads, GitHub repositories with an agent, AI applications in Okta), and every inventory object says how it was found and whether an agent is unmanaged. Before this the only agent was a Kubernetes Deployment labelled `zasp.ai/entity-kind: agent`. See `docs/superpowers/plans/2026-11-14-automatic-agent-discovery.md`. | Real AWS account with at least one Bedrock or AgentCore agent, and the new optional read actions on the customer role. A sync on the local stack with the new artifact (LocalStack does not emulate the AI services; they should show `unavailable`). A periodic release so an abandoned run does not wait for the next sync. |
| 5 | Inventory, capability, findings, attack path (§8) | **Projections run on the local stack (2026-11-13):** the risk, graph and search workers are ready; after a sync Neo4j holds 13 nodes and 21 edges, the search index 15 documents, and all three report `current`. Provider kinds are mapped to neutral kinds. Home and search answer. Attack paths on real data and the pages in a browser are unverified. | Verify attack paths and the UI pages on discovered data. |
| 6 | Red team and Attack Lab (§9) | Built and component-tested. Workers not started here. Attack Lab needs EKS Fargate, which LocalStack does not emulate. | Red team on the local stack; Attack Lab needs real AWS. |
| 7 | Runtime policy: Monitor and Block (§10) | Built and component-tested. Runtime pipeline workers pass their database readiness; not started here. | Start the runtime pipeline; ingest one event; enforce one policy. |
| 8 | Security Agent plan, authorization, action or approval (§11) | The Security Agent writes (create, update, activate, run, execution controls) are authorized functions; create, update and run are verified live with an API token, activation and execution controls at SQL level (browser-session routes). The worker starts (`stack.sh worker security-agent`) and reads each Environment's pricing binding from the administrator-approved policy in the database; a mounted file is only an override. An activated finding-response agent starts runs automatically for matching open findings. A run reaches the planner request: pricing lookup passes, the provider reservation is made, the request is sent to OpenRouter, and OpenRouter answers 402 (the account has no credits); the run ends `needs_human`. No approval has been raised, so approval-notification delivery is still unexercised. | Fund the OpenRouter account, then drive a run through plan, approval and notification. Add a product route for the pricing approval (`pricing_admin` has none) and for the test-selector configuration the worker needs at startup. A run admitted while no pricing approval exists fails its workflow and stays `queued`, holding the agent's concurrency slot. Run detail, cancel and approval detail are still historical statements (in progress). A manual run is admitted only on a finding or attack path its requester may read. |
| 9 | Containment, temporary-control expiry, re-test (§11.8–11.9) | Built and component-tested. | Covered by the run in step 8. |
| 10 | Session investigation and audit export (§12) | Built and component-tested; export readiness passes against LocalStack. | Verify after steps 4–8 produce real data. |

## State on 2026-11-14

Local stack, artifact `a12f048b…`; the Neon development branch holds a fresh install of the same artifact (bootstrap, AWS integration, one sync in 2 min 51 s, 2 findings). The production Neon branch is untouched and still holds an older artifact; it is reinstalled at deployment.

**Verified in a browser on the local stack** (fixture session, not a real sign-in): connect and authorize AWS, sync (about 78 s) with projections current, identity detail, search, findings status changes, policy create through enforce, simulate, disable and delete, API token create, reveal, acknowledge and revoke, Workspace rename, Security Agent create, validate, enable and simulate, a supervised run that stops at `planner_provider_rejected`, and closing that run. The UI waits through the seconds in which permissions are applied after a change. Tester guide: `docs/operations/local-self-test.md`.

**Authorization.** Reads and writes on the golden path go through authorized functions, including Security Agent run detail, cancel, close, approval detail and decision, simulate, manual run, planner pricing, policy functions, integration delete, Workspace and Environment rename and finding status. Direct database paths for the API logins are closed. Still open: a guarded historical function accepts any proof for its scope, not one for a specific operation; `zasp_authorization80.resolve` and `zasp_identity_admin_effective_scopes` answer an API login without a proof.

**Open faults (being fixed).**

- Deleting an `active` integration leaves it `revoking`; nothing completes the revocation.
- Starting a run with the contract's short request form answers 400; only the versioned form works.
- A deleted sync schedule cannot be recreated (409).
- An abandoned sync with no later sync stays `running`.
- Webhook delivery status and test delivery answer 503.
- A missing object answers 403, not 404.
- On a fresh stack the LocalStack fixture yields no finding a Security Agent can run on.
- After a change, reads can answer 503 or 409 for 5 to 15 seconds; the compliance controls page takes 20 to 26 seconds in a browser.

**Not exercised.** Everything after the planner request (plan, approval, notification, action, containment, re-test): OpenRouter answers 402 until the account has credits. Real browser sign-in through the UI, SSO, SCIM. Red team, Attack Lab and the runtime pipeline on a running stack. Real AWS.

**Tests.** The API suite stops at a panic in `TestSecurityAgentOrderedHTTP` that predates this work and is run with that test skipped. Two UI quality tests that pin Go and deployment files fail (`m3-connectors-sensors-batch-contract`, `platform-worker-command-contract`).

Every schema change means a new baseline artifact and a reviewed `zasp_baseline.accept` on installed databases. The agent discovery work of 2026-11-14 changed the artifact (seven inventory rule rows, the rule catalog digest, four members on the inventory summary), so both Neon databases and the local stack need it.

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
