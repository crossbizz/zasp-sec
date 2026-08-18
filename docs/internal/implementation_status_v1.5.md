# Agent Security Platform Implementation Status

**Source plan:** `docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md`  
**Source PRD:** `docs/internal/agent_security_platform_PRD_v1.5.md`  
**Last updated:** August 18, 2026
**Execution branch:** `codex/zasp-implementation`

This file is the authoritative execution status for the 728 microtasks in the
v1.5 technical implementation plan. The plan remains authoritative for scope,
dependencies, deliverables, and verification. A plan task not listed under
In progress, Complete, or Blocked is Pending.

## Status summary

| Status | Count |
| --- | ---: |
| Pending | 0 |
| In progress | 516 |
| Complete | 209 |
| Blocked | 3 |

## Milestone summary

| Milestone | Total | Pending | In progress | Complete | Blocked |
| --- | ---: | ---: | ---: | ---: | ---: |
| M0 | 27 | 0 | 0 | 24 | 3 |
| M1 | 68 | 0 | 0 | 68 | 0 |
| M1A | 10 | 0 | 4 | 6 | 0 |
| M2 | 72 | 0 | 0 | 72 | 0 |
| M3 | 75 | 0 | 36 | 39 | 0 |
| M4 | 82 | 0 | 82 | 0 | 0 |
| M5 | 42 | 0 | 42 | 0 | 0 |
| M6 | 36 | 0 | 36 | 0 | 0 |
| M7 | 62 | 0 | 62 | 0 | 0 |
| M7A | 113 | 0 | 113 | 0 | 0 |
| M8 | 141 | 0 | 141 | 0 | 0 |

## Execution invariants

- Update this file at the status boundary for an individual task or a cohesive
  reviewed batch.
- Related microtasks may move from Pending to Complete together when their
  implementation commits and verification evidence identify every task.
- A task moves to Complete only after its required verification and task review pass.
- A task moves to Blocked only with the exact missing external dependency and evidence.
- Tests, type-check, lint, and production build must pass before a branch push.
- The UI must remain runnable and use product APIs as those contracts become available.
- Existing demo UI is reusable design input, not evidence that a plan task is complete.
- Security-sensitive behavior follows test-first implementation and fails closed.

## Prerequisite work

| ID | Status | Purpose | Verification |
| --- | --- | --- | --- |
| PRE-01 | Complete | Restored a clean, reproducible UI quality baseline before M0 work. | Node 22.23.1/npm 10.9.8 install, tests, type-check, lint, and production build pass without errors. |
| PRE-02 | Complete | Added a push and pull-request quality gate that enforces the runnable-UI invariant. | CI uses Node 22.23.1/npm 10.9.8, performs the locked install, and runs the root verification command. |

## Temporary waiver work

Temporary items are tracked execution work but are not part of the 728
source-plan microtasks and cannot satisfy their deferred provider gates.

| ID | Status | Purpose | Completion gate |
| --- | --- | --- | --- |
| PROV-01 | Blocked | Exercise IAM/STS assume, allowed-read, explicit-deny, and exact cleanup behavior in an isolated disposable LocalStack target without weakening the real-AWS harness. | Exact-pinned LocalStack 4.7.0 does not forward SourceIdentity into the assumed session and does not enforce the required SourceIdentity trust condition. Resume with an isolated provider version or build that proves both behaviors, then repeat cleanup, audit, gates, scans, and review. |

Repository commands, contract coverage, cleanup, audit, and zero-finding review
are in place. PROV-01 is Blocked on the exact LocalStack 4.7.0
SourceIdentity/trust-condition capability dependency. Official LocalStack
v4.14.0 source retains the same unsupported forwarding path; this was source
review only, not live testing. Its tagged STS provider accepts `source_identity`
but delegates the response without adding it to the returned session or stored
session configuration. The 728 source-plan counts are `0/516/209/3` because
PROV-01 is excluded from those counts.
For the active M8 resilience batch, live parity, outage injection, and reference load execution remain unresolved.

## In progress

| Task | Started | Current work |
| --- | --- | --- |
| M1A-10 | August 18, 2026 | Typed gate requires private Ready product stubs, exact IRSA dependency smoke, OTLP health, and credential-free evidence; real AWS staging execution remains unresolved. |
| M1A-09 | August 18, 2026 | Deterministic evidence binds Terraform revision, cluster/version, immutable image hashes, and deploy/smoke runs without credential fields. |
| M1A-08 | August 18, 2026 | Injected smoke boundary requires exact scoped S3, SQS, and OpenSearch operations through IRSA plus OTLP health evidence. |
| M1A-07 | August 18, 2026 | Injected staging deployment boundary requires four immutable product workloads Ready on private endpoints with no vendor dashboards. |
| M8-54 | August 18, 2026 | Release decision requires all seven aggregate gates and exposes every exception or unresolved blocker; live evidence remains unresolved. |
| M8-63 | August 18, 2026 | SaaS DR gate requires objective, isolation, product-surface, and cleanup evidence; live recovery remains unresolved. |
| M8-63e | August 18, 2026 | Recovery objectives require measured RPO <=1 hour and RTO <=4 hours plus usable representative queries. |
| M8-63d | August 18, 2026 | Derived rebuild requires exactly tracked OpenSearch replay and graph rebuild jobs. |
| M8-63c | August 18, 2026 | Core recovery inspection requires exact Organization sets, scoped records, archives, and no cross-Organization mixing. |
| M8-63b | August 18, 2026 | Recovery start retains one run ID and the exact selected source timestamp without waiting for completion. |
| M8-63a | August 18, 2026 | Recovery fixture requires at least two Organizations, test-only credentials, retained archives, and a versioned release reference. |
| M8-62 | August 18, 2026 | Onboarding gate requires five bounded product-guided stages with product-owned remediation or an explicit release blocker. |
| M8-62e | August 18, 2026 | Launch-IdP observation must distinguish directory integration from AgentSec SSO without vendor-dashboard knowledge. |
| M8-62d | August 18, 2026 | GitHub observation requires visible selected scope and actionable permission remediation. |
| M8-62c | August 18, 2026 | Kubernetes observation requires enrollment through healthy coverage with inventory/sensor/gateway distinctions clear. |
| M8-62b | August 18, 2026 | AWS observation requires product-guided configuration and actionable missing-permission remediation. |
| M8-62a | August 18, 2026 | First-Admin observation rejects bypass login or manual database edits and is capped at 15 minutes. |
| M8-61 | August 18, 2026 | Single-tenant result requires the same exact golden stages and API contract with only deployment metadata differing. |
| M8-61a | August 18, 2026 | Single-tenant golden start requires the pinned Organization and the same validated client/API contract. |
| M8-60 | August 18, 2026 | SaaS golden result requires all fourteen ordered product workflow stages plus linked session and audit evidence; live execution remains unresolved. |
| M8-60b | August 18, 2026 | The injected SaaS golden runtime starts one owned Organization/environment fixture and must reach the first connection stage; live execution remains unresolved. |
| M8-60a | August 18, 2026 | SaaS golden fixtures reject production-write identity and require exact Organization/environment scope plus cleanup ownership. |
| M8-59 | August 18, 2026 | Isolation result requires the recorded run completed with all reads/writes denied and no fixture data leaks. |
| M8-59b | August 18, 2026 | The injected isolation runtime starts the validated suite once and retains its run ID before inspection. |
| M8-59a | August 18, 2026 | One bounded suite validates all six two-Organization boundaries and exact denial/no-data outcomes. |
| M8-59a3 | August 18, 2026 | Isolation suite includes S3 evidence/export and scoped queue-envelope boundaries. |
| M8-59a2 | August 18, 2026 | Isolation suite includes graph and OpenSearch boundaries. |
| M8-59a1 | August 18, 2026 | Isolation suite includes API and direct Neon boundaries. |
| M8-58 | August 18, 2026 | Quota result requires the noisy Organization bounded and the normal neighbor at p95 <=750 ms. |
| M8-58b | August 18, 2026 | The injected quota runtime starts the bounded job, retains its run ID, and inspects only that run. |
| M8-58a | August 18, 2026 | Quota fixture requires two distinct Organizations, bounded rates/duration, and one intentional noisy neighbor. |
| M8-57 | August 18, 2026 | Customer-edge values now render only the Tetragon sensor and runtime gateway with local cache and scoped enrollment; no control-plane workload. |
| M8-57c | August 18, 2026 | Edge enrollment uses a Kubernetes secret reference and required Organization, Workspace, and Environment values without plaintext token material. |
| M8-57b | August 18, 2026 | Edge runtime-gateway values bind SaaS API destination and a bounded local policy cache with no Neon/graph dependency. |
| M8-57a | August 18, 2026 | Edge sensor values bind the exact-pinned Tetragon image and product event-ingest destination. |
| M8-56 | August 18, 2026 | Single-tenant values preserve the same chart/images/API and add only topology flags plus one required Organization value. |
| M8-55 | August 18, 2026 | SaaS values enable multi-tenant mode, disable customer recovery assumptions, and contain no pinned customer Organization. |
| M8-53 | August 18, 2026 | Design-partner value gate requires two distinct partners to change prioritization or remediation from linked verified evidence. |
| M8-52 | August 18, 2026 | Usability gate records bounded install blockers and requires every blocker product-owned or explicitly release-blocking. |
| M8-52d | August 18, 2026 | Usability evidence requires a redacted diagnostics bundle and an understandable next action. |
| M8-52c | August 18, 2026 | Usability evidence requires dependency failure diagnosis without opening a vendor dashboard. |
| M8-52b | August 18, 2026 | Usability evidence caps documented install observation at 15 minutes and retains exact product messages/blockers. |
| M8-52a | August 18, 2026 | Usability evidence requires a clean documented target with zero undocumented bootstrap steps. |
| M8-51 | August 18, 2026 | Golden E2E aggregate links all completed stage and investigate/audit artifacts without rerunning a stage; live E2E remains unresolved. |
| M8-51e | August 18, 2026 | Golden evidence adds exact session timeline, audit, and compliance references. |
| M8-51d | August 18, 2026 | Golden-stage evidence requires one simulated/enforced Block policy and an observed blocked retest; live stage execution remains unresolved. |
| M8-51c | August 18, 2026 | Golden-stage evidence requires a Verified canary-only Attack Lab result. |
| M8-51b | August 18, 2026 | Golden-stage evidence binds one credible exposure to one high-impact curated Red Team attempt. |
| M8-51a | August 18, 2026 | Golden-stage evidence requires successful inventory discovery and fresh source state after deployment. |
| M8-50 | August 18, 2026 | SOC 2 readiness checklist requires release, access, change, backup, incident, and vendor owners, locations, and cadence without claiming Type II completion. |
| M8-49 | August 18, 2026 | HIPAA profile gate keeps PostHog, OpenRouter, remote OTLP, and raw content disabled and requires the applicable BAA checklist. |
| M8-48 | August 18, 2026 | Supply-chain inventory requires reviewed owner/status records for Nango, Neo4j, Stytch, Neon, PostHog, OpenRouter, and OTLP. |
| M8-47 | August 18, 2026 | Vulnerability gate rejects every unaccepted critical result and requires an approved owner/expiry for exceptions. |
| M8-46 | August 18, 2026 | Image-signature evidence binds immutable image references and requires signed/verified state plus rejection of tampered and unsigned fixtures. |
| M8-45 | August 18, 2026 | Deterministic SPDX 2.3 inventory generation requires every shipped image by digest and pinned component version/license records; release artifact generation remains unresolved. |
| M8-44 | August 18, 2026 | Attack Lab safety gate requires rejection of production-write identity, host mounts, and undeclared egress without producing Verified. |
| M8-43 | August 18, 2026 | Runtime bypass gate requires malformed HTTP/MCP and replay attempts to fail while the signed Block decision remains active. |
| M8-42 | August 18, 2026 | Secret-leakage gate passes only when all six egress/storage sinks prove seeded and sensitive values absent. |
| M8-42f | August 18, 2026 | Metadata-only evidence storage must omit seeded raw content. |
| M8-42e | August 18, 2026 | Redacted diagnostics/support bundle evidence must omit seeded values. |
| M8-42d | August 18, 2026 | OTLP leakage evidence requires prohibited attributes removed before export. |
| M8-42c | August 18, 2026 | AI leakage evidence requires seeded secret, PII, and PHI fixture values absent at the provider boundary. |
| M8-42b | August 18, 2026 | PostHog leakage evidence additionally requires rejection before egress. |
| M8-42a | August 18, 2026 | Structured-log leakage evidence requires seeded and sensitive values absent. |
| M8-41 | August 18, 2026 | Connector SSRF gate requires arbitrary destination override rejection before any request and a retained audit record. |
| M8-40 | August 18, 2026 | One tenant-isolation gate requires API, graph, OpenSearch, and S3 boundaries all passing. |
| M8-40d | August 18, 2026 | S3 isolation evidence requires cross-Organization denial with no presigned URL or object body. |
| M8-40c | August 18, 2026 | OpenSearch isolation evidence requires zero foreign hits and a retained Organization filter. |
| M8-40b | August 18, 2026 | Graph isolation evidence requires zero foreign nodes/edges and a recorded guard result. |
| M8-40a | August 18, 2026 | API isolation evidence requires cross-Organization/Workspace reads and mutations denied with no foreign data. |
| M8-39 | August 18, 2026 | Sensor evidence records reference profile, workload, duration, CPU core-seconds, and peak memory without asserting a universal overhead percentage. |
| M8-38 | August 18, 2026 | The deterministic event-floor result records rate, recovery, indexing, drops, and retries; reference deployment execution remains unresolved. |
| M8-38c | August 18, 2026 | Event-load evaluation requires at least 5k events/sec, exact indexing, recovered backlog, zero drops, and bounded retries. |
| M8-38b | August 18, 2026 | A bounded event-load plan caps the requested rate, duration, batch size, batch count, and total generated event count. |
| M8-38a | August 18, 2026 | The generator model produces Organization-scoped batch metadata without allocating every event in memory. |
| M8-37 | August 18, 2026 | Graph-load evaluation caps depth at 3, results at 1000, artifact samples, and p95 at 3 seconds. |
| M8-36 | August 18, 2026 | The API reference result retains exact profile, p50/p95/p99, error rate, and deterministic pass/fail. |
| M8-36c | August 18, 2026 | API-load evaluation computes deterministic percentiles and rejects p95 over 750 ms or errors over one percent. |
| M8-36b | August 18, 2026 | API artifacts are bounded to five minutes, 100k samples, 16 endpoints, and exact request/error counts. |
| M8-36a | August 18, 2026 | API scenario validation accepts only fixed `/api/v1/` paths without queries, wildcards, or unbounded endpoint sets. |
| M8-35 | August 18, 2026 | Runtime policy latency evaluation deterministically rejects p95 over the 25 ms release threshold. |
| M8-34 | August 18, 2026 | SQS saturation evidence requires visible queue age/backlog, bounded memory, and active cached runtime policy. |
| M8-33 | August 18, 2026 | Neo4j outage evidence requires explicit degradation while basic inventory and runtime policy remain active. |
| M8-32 | August 18, 2026 | OpenSearch outage evidence requires visible backlog and retained runtime enforcement. |
| M8-31 | August 18, 2026 | Concurrent optional-vendor outage evidence requires core deterministic features and runtime enforcement to remain active. |
| M8-30 | August 18, 2026 | Nango outage evidence requires core launch connectors, inventory, graph, and policy behavior to continue. |
| M8-29 | August 18, 2026 | Neon outage evidence requires control-plane mutation to fail fast while cached runtime policy remains active. |
| M8-28 | August 18, 2026 | Stytch outage evidence requires degraded new authentication, unchanged token validity, and retained runtime enforcement. |
| M8-27 | August 18, 2026 | Real Fargate parity model requires scheduling, direct-egress denial, approved proxy success, and exact cleanup; isolated-AWS execution remains unresolved. |
| M8-26 | August 18, 2026 | Real storage parity model requires S3/KMS, Secrets, SQS, and OpenSearch success; isolated-AWS execution remains unresolved. |
| M8-25 | August 18, 2026 | Real IAM parity model requires allow, explicit deny, SourceIdentity, and IRSA behavior; the same isolated-account blocker as M0-09 remains. |
| M8-24 | August 18, 2026 | `agentsecctl diagnostics` emits only bounded health, version, configuration, and log fields and rejects seeded authorization/token/secret/session markers. |
| M8-23 | August 18, 2026 | Rollback evidence binds upgrade evidence, exact release ID, rollback ID, and state validation; live rehearsal remains unresolved. |
| M8-23d | August 18, 2026 | Rollback validation requires exact prior version, schema compatibility, resource counts, and sampled evidence state. |
| M8-23c | August 18, 2026 | The injected rollback runtime targets only the recorded fixture, release, and prior version. |
| M8-23b | August 18, 2026 | The injected upgrade boundary starts the current version against the exact tracked fixture and retains release and migration IDs; live disposable upgrade evidence remains unresolved. |
| M8-23a | August 18, 2026 | The injected upgrade boundary starts a previous-supported-version disposable fixture and requires a stable tracked identity. |
| M8-22 | August 18, 2026 | One read-only upgrade report aggregates version, migration, bundle, rollback artifact, and recovery-reference checks before mutation. |
| M8-22d | August 18, 2026 | Upgrade validation requires bounded immutable rollback and recovery references. |
| M8-22c | August 18, 2026 | Upgrade validation blocks unsupported policy/content bundle formats. |
| M8-22b | August 18, 2026 | Upgrade validation blocks incompatible Neon migration state before mutation. |
| M8-22a | August 18, 2026 | Upgrade validation accepts only a forward compatible same-major version step. |
| M8-21 | August 18, 2026 | The restore result retains rehearsal ID, terminal state, validation, and cleanup evidence; live provider evidence remains unresolved. |
| M8-21e | August 18, 2026 | Independent cleanup runs after every started restore rehearsal and cleanup failure wins. |
| M8-21d | August 18, 2026 | Restore validation requires exact scoped asset, finding, and policy count equality. |
| M8-21c | August 18, 2026 | Restore polling is bounded, uses one tracked rehearsal ID, and rejects dependency or failed terminal states without restart. |
| M8-21b | August 18, 2026 | An injected restore runtime starts only a validated manifest in an explicitly disposable non-source target. |
| M8-21a | August 18, 2026 | The bounded manifest reader rejects unknown/trailing fields, invalid references, production targets, and source-target reuse. |
| M8-20 | August 18, 2026 | The standalone agentsecctl backup command emits the validated, versioned, scoped recovery manifest as structured JSON. |
| M8-20c | August 18, 2026 | Backup manifests retain graph export and evidence archive references only, scoped under the authenticated Organization. |
| M8-20b | August 18, 2026 | Backup construction clones and sorts configuration/recovery metadata so callers cannot mutate the returned manifest. |
| M8-20a | August 18, 2026 | Recovery manifest schema v1 contains deployment, Neon recovery, configuration, graph, evidence, and expected-count references with no credential fields. |
| M8-19 | August 18, 2026 | Sensor preflight distinguishes disabled, optional warning, and required blocking kernel/BTF/Tetragon prerequisites. |
| M8-18 | August 18, 2026 | Core preflight requires compatible Neon migration/pool and reachable Stytch project/session boundaries. |
| M8-17 | August 18, 2026 | One typed readiness report separates blocking core checks from feature-specific Fargate and optional sensor checks. |
| M8-17e | August 18, 2026 | Attack Lab preflight checks EKS compatibility, exact Fargate/namespace setup, and private networking without blocking unrelated core readiness. |
| M8-17d | August 18, 2026 | OpenSearch preflight requires private reachability and required index operations with an actionable hint. |
| M8-17c | August 18, 2026 | Queue preflight requires the queue, DLQ, and producer/consumer permission set before install. |
| M8-17b | August 18, 2026 | Storage preflight requires scoped S3 evidence, KMS, and Secrets Manager capabilities. |
| M8-17a | August 18, 2026 | IAM preflight requires both the product role and IRSA binding and returns the exact trust/service-account remediation boundary. |
| M8-16 | August 18, 2026 | A fixed-output preflight validates production/private settings, five immutable product images, Attack Lab security group identity, and bounded Terraform/Helm/kubectl/AWS tool availability. |
| M8-15 | August 18, 2026 | Replicated product workloads define zone topology spread and one-item PodDisruptionBudgets. |
| M8-14 | August 18, 2026 | The product chart retains the exact-pinned Tetragon sensor image and bounded health/resources. |
| M8-13 | August 18, 2026 | The product chart deploys the exact-pinned OTel Collector with internal OTLP and health ports. |
| M8-12 | August 18, 2026 | The product chart deploys two exact-pinned free Nango server replicas behind an internal service. |
| M8-11 | August 18, 2026 | The product chart deploys exact-pinned Neo4j with internal Bolt service, readiness, and resource bounds. |
| M8-10 | August 18, 2026 | Runtime gateway uses the same required immutable product-image, private-service, probe, shutdown, security, and resource contract. |
| M8-09 | August 18, 2026 | Worker and event-ingest workloads share the bounded release chart and no duplicate deployment root. |
| M8-09c | August 18, 2026 | Worker and ingest pods receive termination grace, preStop drain, probes, and explicit resources. |
| M8-09b | August 18, 2026 | Event ingest has a replicated private Deployment with immutable-image input and health probes. |
| M8-09a | August 18, 2026 | Worker has a replicated private Deployment with immutable-image input and health probes. |
| M8-08 | August 18, 2026 | Web/API workloads and services are grouped in one reusable product chart. |
| M8-08c | August 18, 2026 | Web and API are exposed only by chart-local ClusterIP services. |
| M8-08b | August 18, 2026 | API has production replicas, health probes, shutdown grace, security context, and resources. |
| M8-08a | August 18, 2026 | Web has production replicas, health probes, shutdown grace, security context, and resources. |
| M8-07 | August 18, 2026 | The reusable AWS root creates bounded Attack Lab egress security-group authority and the chart emits its label-scoped SecurityGroupPolicy. |
| M8-06 | August 18, 2026 | The reusable AWS root adds an exact namespace/label Attack Lab Fargate profile and dedicated pod execution role. |
| M8-05 | August 18, 2026 | Existing product IRSA remains resource-scoped to product bucket prefixes, exact queues, OpenSearch, and the shared KMS key. |
| M8-04 | August 18, 2026 | OpenSearch production capacity is configurable while VPC-only access, encryption, HTTPS, and bounded access policy remain mandatory. |
| M8-03 | August 18, 2026 | Existing queues retain stable identities, KMS encryption, long polling, bounded visibility, retention, and redrive settings. |
| M8-02 | August 18, 2026 | Existing S3/KMS/Secrets resources add version retention, incomplete-upload cleanup, key rotation, encryption, public-access block, and recovery windows. |
| M8-01 | August 18, 2026 | Release values use the same Terraform addresses and private foundation; live AWS plan/drift evidence remains unresolved. |
| M8-01c | August 18, 2026 | One production tfvars file drives the existing staging/release Terraform root without a second module. |
| M8-01b | August 18, 2026 | Existing EKS resources accept production node and private-endpoint settings while preserving resource addresses. |
| M8-01a | August 18, 2026 | Existing VPC/subnet resources accept production CIDRs/AZs and add private AWS service endpoints without a second VPC module. |
| M7A-101 | August 18, 2026 | The fail-closed MVP gate aggregates trigger, simulation, planning, authorization, execution, approval, cleanup, verification, Home attention, audit, degraded safety, and topology-isolation checks. |
| M7A-100 | August 18, 2026 | The same bounded action, approval, verification, and audit contracts run without topology-specific behavior in the single-tenant fixture. |
| M7A-99 | August 18, 2026 | Organization-scoped repositories, planner references, approvals, action idempotency, and results reject concurrent same-looking cross-tenant records. |
| M7A-98 | August 18, 2026 | Completed-run detail and audit events retain trigger, plan hash, evidence IDs, authorization, approvals, execution, verification, and terminal state without protected arguments. |
| M7A-97 | August 18, 2026 | Mandatory approval prevents connection-revoke execution until one fresh-auth decision and idempotent resume. |
| M7A-96 | August 18, 2026 | Automatic containment requires a registered reversible action plus verified policy and re-test evidence before a Contained or Remediated state. |
| M7A-95 | August 18, 2026 | The run budget stops later steps after step, time, token, cost, or concurrency limits are exceeded. |
| M7A-94 | August 18, 2026 | Planner validation rejects valid-looking references outside the run's Organization/environment evidence snapshot before authorization. |
| M7A-93 | August 18, 2026 | Unknown external outcomes become Inconclusive and are never blindly retried. |
| M7A-92 | August 18, 2026 | Expired mandatory approvals move waiting work to Needs human and never enqueue automatic resume. |
| M7A-91 | August 18, 2026 | Planner failure records one bounded unavailable error, executes no action, and does not change existing runtime enforcement. |
| M7A-90d | August 18, 2026 | The Home fixture exposes critical paths, approvals, Needs-human runs, stale coverage, and recent containment through explicit canonical actions. |
| M7A-90c | August 18, 2026 | Approval-required notification emits one signed idempotent event with approval/run context only and no evidence body or secret. |
| M7A-90b | August 18, 2026 | Home renders ordered Needs-attention cards for exposure, approvals, responder failures, stale coverage, and containment without masking degraded state. |
| M7A-90a | August 18, 2026 | Home summary adds Organization-scoped approval age, responder state counts, and recent contained/remediated outcomes while preserving stale/degraded attention. |
| M7A-90 | August 18, 2026 | Evidence, finding, path, session, run, and approval surfaces use scoped canonical links with retained entity IDs. |
| M7A-89 | August 18, 2026 | Approval detail shows evidence, expected side effect, reversibility, TTL, run context, and fresh-auth guarded Approve/Deny/Cancel controls. |
| M7A-88 | August 18, 2026 | Protect -> Approvals lists only scoped action, agent, target, expiry, requester, and run context from the generated client. |
| M7A-87 | August 18, 2026 | Run action detail renders state, redacted arguments, result, rollback/TTL, and verification without protected values. |
| M7A-86 | August 18, 2026 | Run detail separates trigger/evidence and AI rationale from deterministic authorization and ordered registered plan steps. |
| M7A-85 | August 18, 2026 | Definition detail shows bounded configuration, allowed actions, limits, verification, and recent runs without provider/model internals. |
| M7A-84 | August 18, 2026 | The generated-client builder shows matched evidence, proposed steps, approval points, and per-step authorization with zero side effects. |
| M7A-83 | August 18, 2026 | Definitions require one terminal verification choice compatible with the selected registered actions. |
| M7A-82 | August 18, 2026 | Client and service contracts bound steps, runtime, temporary-policy TTL, AI budget, and concurrency to product maxima. |
| M7A-81 | August 18, 2026 | The autonomy step exposes automatic or supervised execution while product approval floors remain immutable. |
| M7A-80 | August 18, 2026 | The builder action catalog displays risk, target support, and reversibility and offers no arbitrary URL, code, or shell input. |
| M7A-79 | August 18, 2026 | Goal and Workspace/environment/agent/tag scope controls are separate from the explicitly selected action list. |
| M7A-78 | August 18, 2026 | The builder starts from one of five bounded templates or blank and exposes only canonical trigger choices. |
| M7A-77 | August 18, 2026 | Protect -> Security Agents renders the generated-client list with status, trigger, scope, autonomy, outcome, approvals, and owner columns. |
| M7A-76 | August 18, 2026 | Approval decisions accept approve, reject, or cancel only after fresh authorization and reject run identity self-approval. |
| M7A-75 | August 18, 2026 | Approval detail returns the expected registered effect, reversibility, remaining TTL, and evidence references. |
| M7A-74 | August 18, 2026 | Approval listing rebinds every item through its run and agent to the caller's Organization and environment. |
| M7A-73 | August 18, 2026 | The cancel endpoint uses the run CAS transition and returns a stable conflict for terminal state. |
| M7A-72 | August 18, 2026 | Run detail combines scoped evidence, redacted plan parameters, authorization, approvals, execution, and verification state. |
| M7A-71 | August 18, 2026 | Run listing supports bounded agent/status/environment filters and cursor pagination within one Organization. |
| M7A-70 | August 18, 2026 | Manual run creation accepts only authorized finding, attack-path, or session references in an allowed environment. |
| M7A-69 | August 18, 2026 | The simulation endpoint invokes scoped planning and authorization while never dispatching an action adapter. |
| M7A-68 | August 18, 2026 | Dry-run simulation returns matched evidence, proposed registered steps, approval points, authorization, and zero side effects. |
| M7A-67 | August 18, 2026 | Deletion disables and soft-deletes the definition while historical runs remain in the scoped repository. |
| M7A-66 | August 18, 2026 | Definition updates use versioned CAS and enabling requires current creator permission for every allowed registered action. |
| M7A-65 | August 18, 2026 | Definition reads require the request Organization and return the same bounded not-found envelope for foreign IDs. |
| M7A-64 | August 18, 2026 | Creation validates actions, approval floors, scope, verification, and limits and returns one stable invalid-definition error. |
| M7A-63 | August 18, 2026 | Definition listing applies Organization scope plus bounded cursor, status, trigger, and environment filtering. |
| M7A-62 | August 18, 2026 | The action API returns only registered target-compatible actions whose injected capability is supported. |
| M7A-61 | August 18, 2026 | The template API returns only the five bounded product templates and no prompt or provider internals. |
| M7A-60 | August 18, 2026 | Audit events cover trigger through terminal outcome, hash plans, and reject raw arguments, tokens, credentials, and secrets. |
| M7A-59 | August 18, 2026 | Run cancellation atomically stops future transitions and approval resume while preserving completed steps and temporary-control cleanup state. |
| M7A-58 | August 18, 2026 | Final Contained/Remediated outcomes require every configured verification to pass; execution acknowledgement alone remains Inconclusive. |
| M7A-57 | August 18, 2026 | The verification dispatcher routes exact metadata kinds, contains verifier panics, and returns Inconclusive for missing or failed verification. |
| M7A-56 | August 18, 2026 | Execution receipts classify as success, known failure, or unknown outcome; unknown side effects are never automatically retried. |
| M7A-55 | August 18, 2026 | Approved decisions enqueue one idempotent `security_agent.run` resume job, while denied/cancelled runs cannot resume. |
| M7A-54 | August 18, 2026 | Approval coordination requires a fresh-auth decision before mutating approval state or enqueueing resume work. |
| M7A-53 | August 18, 2026 | Approval-required steps atomically create one expiring approval and move the run to waiting_approval before later execution. |
| M7A-52 | August 18, 2026 | Auto execution dispatches only deterministic allow decisions through the registry's run/step idempotency boundary. |
| M7A-51 | August 18, 2026 | Queued runs transition to planning and persist only validated plans; planner failure records a fixed bounded error and moves to Failed. |
| M7A-50 | August 18, 2026 | The local `security_agent.run` dequeue handler is Organization-scoped and executes a replayed idempotency key once; production SQS wiring remains unresolved. |
| M7A-49 | August 18, 2026 | A synchronized run budget enforces steps, wall-clock duration, AI tokens/cost, and Organization concurrency before further action. |
| M7A-48 | August 18, 2026 | Enabling a definition requires the editor's permission for every registered allowed action; missing revoke permission fails closed. |
| M7A-47 | August 18, 2026 | Product action metadata imposes operator/admin approval floors that autonomous definitions cannot lower. |
| M7A-46 | August 18, 2026 | The deterministic authorizer returns allow, approval_required, or deny from definition, action metadata, and scope only. |
| M7A-45 | August 18, 2026 | Planner security fixtures keep malicious instructions inside untrusted evidence and reject invented revoke/URL steps. |
| M7A-44 | August 18, 2026 | Every planned step must use a registered, definition-allowed action and its exact parameter schema. |
| M7A-43 | August 18, 2026 | Planner validation binds scope, run, target, and evidence references to the current Organization/workspace/environment allowlist. |
| M7A-42 | August 18, 2026 | Plan acceptance enforces the lower definition/product step limit before any action; six steps fail when the limit is five. |
| M7A-41 | August 18, 2026 | AIGateway recognizes `security_response_plan` as structured-only and rejects it from the free-form governed explanation path. |
| M7A-40 | August 18, 2026 | Planner input keeps fixed product policy, bounded operator goal, canonical snapshot, and untrusted evidence in separate fields. |
| M7A-39 | August 18, 2026 | The snapshot builder emits bounded canonical finding/path/agent/session/policy summaries and scoped evidence IDs while dropping raw fields and foreign records. |
| M7A-38d | August 18, 2026 | Local finding/path/runtime trigger fixtures each create one queued run and one job; exact replay creates no duplicate. |
| M7A-38c | August 18, 2026 | The trigger source calls durable state persistence before dispatcher delivery for finding, attack-path, and runtime-decision events. |
| M7A-38b | August 18, 2026 | The automatic dispatcher matches enabled scoped definitions, applies per-definition cooldown, creates immutable queued runs, and emits `security_agent.run`; production queue wiring remains unresolved. |
| M7A-38a | August 18, 2026 | The internal trigger contract requires canonical source ID, Organization, environment, UTC time, and kind-specific finding/path/runtime fields. |
| M7A-38 | August 18, 2026 | A canonical Organization/environment/source fingerprint suppresses replayed trigger events for a bounded cooldown without cross-scope collision. |
| M7A-37 | August 18, 2026 | The runtime-decision matcher requires exact Organization, environment, action, risk, agent, session, count, and bounded UTC window. |
| M7A-36 | August 18, 2026 | The attack-path matcher binds Organization/environment and exact potential/verified evidence state. |
| M7A-35 | August 18, 2026 | The finding matcher binds enabled definitions to Organization, environment, family, and minimum severity and rejects cross-environment input. |
| M7A-34 | August 18, 2026 | The versioned Shadow Agent Triage template defaults only to non-destructive test, evidence, and configured handoff actions. |
| M7A-33 | August 18, 2026 | The versioned Repeated Policy Violation template binds its trigger to agent, session, count, and a five-minute window. |
| M7A-32 | August 18, 2026 | The versioned Prompt/Tool Injection template combines temporary policy plus existing-test actions and requires the linked risk to become blocked or not reproduced. |
| M7A-31 | August 18, 2026 | The versioned Credential Exposure template makes supported connection revocation explicitly approval-required. |
| M7A-30 | August 18, 2026 | The versioned Suspicious Egress template contains only temporary policy, evidence export, signed handoff, and verification defaults. |
| M7A-29 | August 18, 2026 | A fail-closed versioned template registry exposes five stable built-in IDs and rejects duplicate or malformed definitions. |
| M7A-28 | August 18, 2026 | Connection-revoke verification classifies provider/backend uncertainty as Inconclusive rather than success. |
| M7A-27 | August 18, 2026 | Supported connection revocation executes only with an explicit approval token and a stable run/step idempotency key; production broker wiring remains unresolved. |
| M7A-26 | August 18, 2026 | Connection-revoke metadata requires admin approval and is hidden when the injected connector capability reports unsupported. |
| M7A-25 | August 18, 2026 | The finding-response action permits assignment, notes, and open/investigating state only; Resolved/Safe inputs fail before execution. |
| M7A-24 | August 18, 2026 | The response-webhook action accepts only a configured destination ID plus run-scoped evidence, never an arbitrary URL; production signer/delivery wiring remains unresolved. |
| M7A-23 | August 18, 2026 | The evidence-export action requires every evidence ID to be scoped to the current run before invoking the bounded backend. |
| M7A-22 | August 18, 2026 | Attack Lab execution accepts only existing test definitions, approved preflight, and non-production/test targets. |
| M7A-21 | August 18, 2026 | `run_test` and `rerun_test` accept only an existing TestDefinition ID and reject arbitrary prompt/target content. |
| M7A-20 | August 18, 2026 | Session isolation executes idempotently through the bounded backend and requires verified gateway-decision evidence; production gateway wiring remains unresolved. |
| M7A-19 | August 18, 2026 | `isolate_session` metadata requires one supported scoped session, Monitor/Block-compatible temporary enforcement, approval, reversibility, and TTL. |
| M7A-18d | August 18, 2026 | `agentsec-worker` contains a bounded periodic hook for the exact claim/cleanup/verify worker path; production repository/service construction remains unresolved. |
| M7A-18c | August 18, 2026 | Expiry verification records cleaned or cleanup_failed audit evidence, and uncertainty becomes cleanup_failed rather than silent success. |
| M7A-18b | August 18, 2026 | Expired product-native controls disable through a scoped idempotency key, with repeat scans leaving the terminal state unchanged. |
| M7A-18a | August 18, 2026 | The Organization-scoped local temporary-control repository atomically claims expired controls so concurrent workers have one winner. |
| M7A-18 | August 18, 2026 | Temporary-policy verification returns Verified only for the expected scoped state; missing/stale bundle evidence becomes Inconclusive. |
| M7A-17 | August 18, 2026 | The registered temporary-policy action executes through a bounded policy-service contract and returns the same policy ID for a repeated run/step key; production adapter wiring remains unresolved. |
| M7A-16 | August 18, 2026 | `create_temporary_policy` metadata restricts requests to Monitor/Block, a bounded scope, a positive TTL, operator approval, reversibility, idempotency, and policy-state verification. |
| M7A-15 | August 18, 2026 | A fail-closed action registry exposes metadata, validation, execution, and verification contracts and rejects duplicate action keys. |
| M7A-14 | August 18, 2026 | The Organization-scoped local approval repository supports create/list/get/decide and rejects expired or terminal approvals. |
| M7A-13 | August 18, 2026 | The Organization-scoped local step repository enforces stable ordering and unique `(run_id, step_index)` values. |
| M7A-12 | August 18, 2026 | The Organization-scoped local run repository supports create/get/list and versioned compare-and-set transitions with one winner. |
| M7A-11 | August 18, 2026 | The local definition repository supports cursor listing, versioned updates, soft deletion, and trigger exclusion for disabled/deleted agents. |
| M7A-10 | August 18, 2026 | The local create/get repository binds every Security Agent definition to its Organization and rejects cross-Organization reads. |
| M7A-09 | August 18, 2026 | The local idempotency repository binds Organization, run, step, and action key and returns the exact prior outcome on a duplicate claim. |
| M7A-08 | August 18, 2026 | The immutable migration contract includes Organization-scoped approvals, expiry, approver, fresh-auth, decision, version, RLS, and primary-key boundaries; live Neon application remains unresolved. |
| M7A-07 | August 18, 2026 | The immutable migration contract includes Organization-scoped run steps and unique `(organization_id, run_id, step_index)` state; live Neon application remains unresolved. |
| M7A-06 | August 18, 2026 | The immutable migration contract includes Organization-scoped runs, trigger evidence snapshots, definition versions, CAS versions, and RLS; live Neon application remains unresolved. |
| M7A-05 | August 18, 2026 | One repeatably validated SQL contract defines Organization-scoped Security Agents, indexes, and tenant policies; live Neon apply/rollback evidence remains unresolved. |
| M7A-04 | August 18, 2026 | Security action metadata validates input schemas, risk class, target types, approval floor, reversibility, idempotency, and verification kind. |
| M7A-03 | August 18, 2026 | Version-one plans require ordered typed action steps, bounded summaries, exact action schemas, and no unknown fields. |
| M7A-02 | August 18, 2026 | Security Agent runs expose the eleven planned states and a fail-closed transition graph that rejects terminal-to-running transitions. |
| M7A-01 | August 18, 2026 | Security Agent definitions validate trigger, Organization/environment scope, autonomy, positive limits, allowed actions, verification, and definition version. |
| M7-40 | August 18, 2026 | The local M7 gate reports PASS only when all six independent flows and all five degraded-state fixtures pass; provider-backed milestone E2E remains unresolved. |
| M7-40f | August 18, 2026 | The strict UI/API coverage gate maps all 104 public MVP operations to a screen/action and handler task. |
| M7-40e | August 18, 2026 | The local AI-degrade flow reports explanation unavailability while deterministic evidence and actions remain usable. |
| M7-40d | August 18, 2026 | The local system-health flow distinguishes required security-plane failure from optional dependency degradation. |
| M7-40c | August 18, 2026 | The local data-control flow applies and audits environment retention/collection changes before subsequent reads. |
| M7-40b | August 18, 2026 | The local compliance flow binds filtered control evidence, source references, freshness, and deterministic export artifacts. |
| M7-40a | August 18, 2026 | The local session flow retains semantic/runtime evidence in stable timestamp/ID order with explicit confidence. |
| M7-39 | August 18, 2026 | The M7 gate registers exactly connector, graph, event-index, AI, and optional-OTLP degraded-state fixtures as independent evidence. |
| M7-39e | August 18, 2026 | The local System Health fixture reports optional remote-telemetry degradation without marking the security plane unhealthy. |
| M7-39d | August 18, 2026 | The local AI surface keeps deterministic evidence usable when explanation generation is unavailable. |
| M7-39c | August 18, 2026 | The local Sessions fixture retains known metadata while event-index activity is degraded. |
| M7-39b | August 18, 2026 | Existing graph-backed surfaces retain explicit degraded states; live graph outage E2E remains unresolved. |
| M7-39a | August 18, 2026 | Existing inventory/findings surfaces retain stale coverage warnings instead of false zero-risk output. |
| M7-38 | August 18, 2026 | The strict UI/API map covers all 104 current public operations with zero planned or unmapped operations. |
| M7-37 | August 18, 2026 | Existing Home and global-search surfaces prove deterministic local navigation; final live API binding remains unresolved. |
| M7-36 | August 18, 2026 | The local Audit Log surface renders product mutation evidence and an export-ready boundary. |
| M7-35 | August 18, 2026 | The External Data Flows surface renders destination, category, enablement, and health policy. |
| M7-34 | August 18, 2026 | The Data and Retention surface exposes metadata-only production defaults and regulated-setting guidance. |
| M7-33 | August 18, 2026 | The System Health surface distinguishes required health from optional degradation and displays version/freshness guidance. |
| M7-32 | August 18, 2026 | `getSystemVersion` is published and handled by the bounded local service. |
| M7-31 | August 18, 2026 | `listSystemComponents` is published and handled by the bounded local service. |
| M7-30 | August 18, 2026 | `getSystemStatus` is published and handled by the bounded local service. |
| M7-29 | August 18, 2026 | Local component probes aggregate required and optional dependency state; provider probes remain unresolved. |
| M7-28 | August 18, 2026 | The local evidence-aware AI panel renders sent-field and deterministic unavailable states. |
| M7-27 | August 18, 2026 | `createAIExplanation` is published and handled by a bounded governed local service. |
| M7-26 | August 18, 2026 | Local AI governance composes purpose/model/provider, request limits, redaction, and no-storage metadata. |
| M7-26c | August 18, 2026 | Provider selection requires explicit no-storage data-policy metadata. |
| M7-26b | August 18, 2026 | AI requests enforce bounded tokens, cost, deadline, and concurrency before provider invocation. |
| M7-26a | August 18, 2026 | AI requests reject purposes, models, and providers outside fixed allowlists before egress. |
| M7-25 | August 18, 2026 | An allowlist-only local redactor retains approved finding summary fields and drops secret/PII inputs. |
| M7-24 | August 18, 2026 | A server-side flag cache applies explicit defaults after bounded cached values expire. |
| M7-23 | August 18, 2026 | An allowlist-only product-event serializer rejects prompts, tool arguments, secrets, IPs, and raw evidence. |
| M7-22a | August 18, 2026 | Required external dependencies cannot be disabled while optional flows can be changed within category policy. |
| M7-22 | August 18, 2026 | `updateExternalDataFlows` is published and handled by the bounded local service. |
| M7-21 | August 18, 2026 | `getExternalDataFlows` is published and handled by the bounded local service. |
| M7-20 | August 18, 2026 | External-flow models bind required/optional destinations, allowed categories, enablement, and health. |
| M7-19 | August 18, 2026 | A bounded local retention worker expires product event/evidence references and records the admin policy change; provider scheduling remains unresolved. |
| M7-18 | August 18, 2026 | `updateDataControls` is published and handled by a bounded environment-scoped local store; provider persistence remains unresolved. |
| M7-17 | August 18, 2026 | `getDataControls` is published and handled by the bounded local service. |
| M7-16 | August 18, 2026 | Environment collection mode, retention, and deletion settings validate production as metadata-only. |
| M7-15 | August 18, 2026 | The local Compliance Evidence surface composes controls, freshness, gaps, and export interaction. |
| M7-15d | August 18, 2026 | The evidence export action renders a completed local job state. |
| M7-15c | August 18, 2026 | Compliance evidence renders distinct fresh, stale, and missing states. |
| M7-15b | August 18, 2026 | Evidence rows retain asset, source, and product evidence references. |
| M7-15a | August 18, 2026 | The local control list renders SOC 2 Security and HIPAA safeguards without certification claims. |
| M7-14 | August 18, 2026 | A bounded local artifact builder emits deterministic JSON, CSV, and human-readable evidence; S3 writing remains unresolved. |
| M7-13 | August 18, 2026 | `getComplianceExport` is published and handled by the bounded local service. |
| M7-12 | August 18, 2026 | `createComplianceExport` is published and handled by the bounded local service. |
| M7-11 | August 18, 2026 | `listComplianceEvidence` is published and handled by the bounded local service. |
| M7-10 | August 18, 2026 | `listComplianceControls` is published and handled by the bounded local service. |
| M7-09 | August 18, 2026 | The local evidence assembler binds product evidence IDs and marks stale or missing evidence explicitly. |
| M7-08 | August 18, 2026 | Bounded SOC 2 Security and HIPAA safeguard mappings retain explicit freshness cutoffs. |
| M7-07 | August 18, 2026 | The local session detail composes an ordered mixed-confidence evidence timeline. |
| M7-07c | August 18, 2026 | Session events display source and Exact, Strong, Probable, or Unattributed confidence. |
| M7-07b | August 18, 2026 | Session rows support tool, runtime, network, file, credential, and policy event classes. |
| M7-07a | August 18, 2026 | The local session timeline sorts replayed events by canonical UTC event time. |
| M7-06 | August 18, 2026 | The Sessions surface renders structured filters and evidence confidence. |
| M7-05 | August 18, 2026 | A structured local session-filter builder rejects arbitrary query strings and DSL; OpenSearch integration remains unresolved. |
| M7-04 | August 18, 2026 | `listSessionEvents` is published and handled by the bounded local service. |
| M7-03 | August 18, 2026 | `getSession` is published and handled by the bounded local service. |
| M7-02 | August 18, 2026 | `listSessions` is published and handled by the bounded local service. |
| M7-01 | August 18, 2026 | An idempotent local session projector correlates ordered semantic/runtime events without changing confidence. |
| M6-31 | August 18, 2026 | A six-stage local M6 composition gate requires create, simulate, monitor, enforce, retest, and cached-outage enforcement; staging remains unresolved. |
| M6-31e | August 18, 2026 | A local signed-bundle fallback keeps known Block decisions until expiry and applies explicit fail-open/fail-closed behavior afterward. |
| M6-31d | August 18, 2026 | Re-test state becomes Blocked only with an observed policy Block decision and retained correlation evidence. |
| M6-31c | August 18, 2026 | The local gate fixture enforces a matching action with a stable product block response and correlation ID. |
| M6-31b | August 18, 2026 | The local gate fixture records one idempotent Monitor decision without blocking the action. |
| M6-31a | August 18, 2026 | The local gate fixture creates and simulates one Monitor policy against bounded action-context fixtures. |
| M6-30 | August 18, 2026 | Decision evidence can update a verified local path to Blocked without deleting reachability state. |
| M6-29 | August 18, 2026 | The local policy detail surface renders simulation, decisions, rollout, enforcement, and disable actions. |
| M6-28 | August 18, 2026 | The local Policy wizard renders Scope, Trigger, Conditions, Action, Coverage, Simulate, and Rollout while omitting unsupported controls. |
| M6-27 | August 18, 2026 | The local Policies surface renders Monitor, Enforce, Disabled, coverage, and stale-bundle states. |
| M6-26 | August 18, 2026 | A focused local metadata-only evaluator p95 measurement boundary is implemented; cluster benchmark evidence remains unresolved. |
| M6-25 | August 18, 2026 | A local cached-bundle fallback preserves known policy decisions across simulated control-plane outage and explicit expiry behavior. |
| M6-24 | August 18, 2026 | An idempotent local runtime-decision store accepts a scoped decision exactly once without sensitive payload fields. |
| M6-23 | August 18, 2026 | Monitor decisions allow the upstream request and emit a metadata-only decision through an injected boundary. |
| M6-22 | August 18, 2026 | Block decisions return a stable product error and correlation ID without calling the upstream boundary. |
| M6-21 | August 18, 2026 | Runtime ActionContext normalization requires principal, agent, session, action, resource, and environment scope. |
| M6-20 | August 18, 2026 | A strict bounded MCP JSON-RPC parser retains method, tool, and resource metadata in canonical ActionContext. |
| M6-19 | August 18, 2026 | The local runtime HTTP proxy preserves allowed requests through an injected upstream boundary. |
| M6-18 | August 18, 2026 | The local rollout state machine rejects invalid transitions across draft, monitor, enforce, and disabled states. |
| M6-17 | August 18, 2026 | Policy simulation evaluates at most 100 injected historical action contexts and returns bounded counts/examples; OpenSearch integration remains unresolved. |
| M6-16 | August 18, 2026 | `listPolicyDecisions` is published in OpenAPI/generated types and handled by the bounded local service. |
| M6-15 | August 18, 2026 | `disablePolicy` is published in OpenAPI/generated types and handled by the bounded local service. |
| M6-14 | August 18, 2026 | `rolloutPolicy` is published in OpenAPI/generated types and handled by the bounded local service. |
| M6-13 | August 18, 2026 | `simulatePolicy` is published in OpenAPI/generated types and handled by the bounded local service. |
| M6-12 | August 18, 2026 | `deletePolicy` is published in OpenAPI/generated types and handled by the bounded local service. |
| M6-11 | August 18, 2026 | `updatePolicy` is published in OpenAPI/generated types and handled by the bounded local service. |
| M6-10 | August 18, 2026 | `getPolicy` is published in OpenAPI/generated types and handled by the bounded local service. |
| M6-09 | August 18, 2026 | `createPolicy` is published in OpenAPI/generated types and handled by the bounded local service. |
| M6-08 | August 18, 2026 | `listPolicies` is published in OpenAPI/generated types and handled by the bounded local service. |
| M6-07 | August 18, 2026 | A local environment-bound bundle getter rejects cross-environment reads; runtime-token and internal-route integration remain unresolved. |
| M6-06 | August 18, 2026 | A bounded in-memory last-valid signed-bundle cache is implemented; runtime-gateway restart integration remains unresolved. |
| M6-05 | August 18, 2026 | A deterministic HMAC-signed local bundle manifest rejects modification; S3 artifact writing remains unresolved. |
| M6-04 | August 18, 2026 | A deterministic local condition evaluator implements Monitor/Block outcomes; OPA SDK and runtime-gateway integration remain unresolved. |
| M6-03 | August 18, 2026 | Product Policy compiles to a deterministic internal representation and digest; production OPA/Rego compatibility remains unresolved. |
| M6-02 | August 18, 2026 | Policy validation rejects triggers, fields, operators, and enforcement actions outside injected runtime capabilities. |
| M6-01 | August 18, 2026 | The local Policy domain binds environment scope, trigger, conditions, Monitor/Block, rollout, and failure mode. |
| M5-35 | August 18, 2026 | A local M5 composition gate requires safety, worker replay, verdict, cleanup, and UI readiness; staging Fargate evidence remains unresolved. |
| M5-34 | August 18, 2026 | The Attack Lab result UI renders verdict, timeline, canary, network, evidence, and rerun concepts with distinct inconclusive outcomes. |
| M5-33 | August 18, 2026 | Attack Lab preflight composes safety sections and disables Run until explicit approval. |
| M5-33c | August 18, 2026 | Attack Lab preflight renders bounded runtime/resource limits plus cleanup behavior. |
| M5-33b | August 18, 2026 | Attack Lab preflight renders allowed destinations and expected side effects. |
| M5-33a | August 18, 2026 | Attack Lab preflight renders the selected non-production target and test credential class. |
| M5-32 | August 18, 2026 | The local Attack Lab worker runs preflight, provider, evidence, verdict, and cleanup idempotently with an injected provider. |
| M5-31 | August 18, 2026 | `rerunAttackLabRun` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-30 | August 18, 2026 | `cancelAttackLabRun` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-29 | August 18, 2026 | `getAttackLabRun` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-28 | August 18, 2026 | `createAttackLabRun` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-27 | August 18, 2026 | `listAttackLabRuns` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-26 | August 18, 2026 | Attack Lab verdicts distinguish verified canary touches, not reproduced outcomes, and infrastructure-inconclusive results locally. |
| M5-25 | August 18, 2026 | The local Attack Lab evidence collector binds semantic, gateway, egress, Kubernetes, and cloud side-effect sources without an in-sandbox eBPF dependency. |
| M5-24 | August 18, 2026 | A bounded canary descriptor requires a test resource, test-write credential class, and observable expected touch. |
| M5-23 | August 18, 2026 | One local SafetyDecision composes target, credential, destination, and measurable-success checks before sandbox creation. |
| M5-23d | August 18, 2026 | Attack Lab preflight rejects runs without an explicit observable success criterion. |
| M5-23c | August 18, 2026 | Attack Lab preflight rejects destinations outside the per-run allowlist. |
| M5-23b | August 18, 2026 | Attack Lab preflight hard-rejects production-write credentials. |
| M5-23a | August 18, 2026 | Attack Lab preflight rejects production targets before sandbox creation. |
| M5-22 | August 18, 2026 | HMAC-bound per-run egress tokens enforce exact host, method, and expiry values locally. |
| M5-21 | August 18, 2026 | The Fargate sandbox spec names a dedicated egress-proxy SecurityGroupPolicy; live EKS enforcement remains unresolved. |
| M5-20 | August 18, 2026 | The Fargate sandbox spec uses a dedicated Attack Lab service account and test-role annotation, never the product worker role. |
| M5-19 | August 18, 2026 | CPU, memory, ephemeral-storage, and timeout limits are mandatory and bounded in the local sandbox spec. |
| M5-18 | August 18, 2026 | A run-scoped local Fargate Job specification binds the dedicated profile, namespace, labels, and cleanup ownership fields. |
| M5-17 | August 18, 2026 | SandboxProvider defines Create, Run, Cancel, Destroy, and Capabilities boundaries locally. |
| M5-16 | August 18, 2026 | Existing Red Team results group deterministic outcomes and link successful attempts to the bounded Attack Lab route locally. |
| M5-15 | August 18, 2026 | Existing Red Team list/new-test UX renders curated packs and execution limits locally. |
| M5-14 | August 18, 2026 | The local worker persists an artifact reference plus normalized verdict and rejects a secret-bearing raw fixture. |
| M5-13 | August 18, 2026 | The local test worker consumes queued runs idempotently; duplicate delivery retains one attempt. |
| M5-12 | August 18, 2026 | `cancelTestRun` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-11 | August 18, 2026 | `getTestRun` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-10 | August 18, 2026 | `listTestRuns` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-09 | August 18, 2026 | `runTest` is published in OpenAPI/generated types and queues a bounded local run. |
| M5-08 | August 18, 2026 | `updateTest` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-07 | August 18, 2026 | `getTest` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-06 | August 18, 2026 | `createTest` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-05 | August 18, 2026 | `listTests` is published in OpenAPI/generated types and handled by the bounded local service. |
| M5-04 | August 18, 2026 | Test safety preflight rejects production targets, production-write credentials, and undeclared side effects locally. |
| M5-03 | August 18, 2026 | Curated pack selection recommends only capability-relevant tool, data-leakage, and prompt-injection categories with explanations. |
| M5-02 | August 18, 2026 | Promptfoo output normalizes objective, input artifact, behavior, verdict, evidence, and engine_error separately. |
| M5-01 | August 18, 2026 | Local TestDefinition, TestRun, TestAttempt, verdict, and safety metadata boundaries are implemented. |
| M4-59 | August 18, 2026 | A five-check local M4 gate passes only when inventory, capability, posture, attack path, and exposure UX agree; provider release evidence remains unresolved. |
| M4-59e | August 18, 2026 | The golden exposure fixture renders product-only Why, Evidence, Path, Fix, and Verify concepts locally. |
| M4-59d | August 18, 2026 | The golden fixture retains a bounded evidence-state attack path and ranked break option locally. |
| M4-59c | August 18, 2026 | The golden fixture raises one Agent-specific posture finding with exact evidence locally. |
| M4-59b | August 18, 2026 | The golden fixture renders production-write and shell capabilities with evidence state locally. |
| M4-59a | August 18, 2026 | The golden canonical Agent renders owner, identity, runtime, tools, and coverage locally. |
| M4-58 | August 18, 2026 | Home retains an explicit stale-source warning and cannot render a zero-risk healthy state locally. |
| M4-57 | August 18, 2026 | The Attack Paths surface renders a bounded path, evidence, and ranked Break Path option locally. |
| M4-56 | August 18, 2026 | Finding detail renders Why, Evidence, Path, Fix, Verify, assignment, acceptance, and ticket actions locally. |
| M4-55 | August 18, 2026 | The Findings list hides an unrelated Prowler record by default and retains Agent relevance locally. |
| M4-54 | August 18, 2026 | Runtimes list/detail fields expose isolation, sandbox, sensor, and policy coverage locally. |
| M4-53 | August 18, 2026 | Identities list/detail fields expose Agent linkage, privilege, reference, and evidence locally. |
| M4-52 | August 18, 2026 | Tools and MCP list/detail fields expose using Agents and control state locally. |
| M4-51 | August 18, 2026 | The Agent detail reading order composes identity through sessions and policy coverage locally. |
| M4-51e | August 18, 2026 | Agent Sessions and runtime-policy coverage sections link to canonical routes locally. |
| M4-51d | August 18, 2026 | Agent Findings and Attack Paths sections link to canonical exposure routes locally. |
| M4-51c | August 18, 2026 | Effective Capability cards render Observed and Blocked evidence states locally. |
| M4-51b3 | August 18, 2026 | Agent runtime and sandbox references link to canonical runtime detail locally. |
| M4-51b2 | August 18, 2026 | Agent Tool and MCP relationships link to canonical tool detail locally. |
| M4-51b1 | August 18, 2026 | Agent principal and credential references link to canonical identity detail locally. |
| M4-51a | August 18, 2026 | Agent header renders owner, status, environment, risk, and last-seen state; owner edit uses the generated client. |
| M4-50 | August 18, 2026 | Agent table, filters, and stale coverage indicators compose into one local route. |
| M4-50c | August 18, 2026 | Agent last-seen, stale-source, policy, and sensor coverage indicators fail visibly degraded locally. |
| M4-50b3 | August 18, 2026 | Runtime-sensor and policy-coverage filter state generates a bounded product query locally. |
| M4-50b2 | August 18, 2026 | Shell/code-execution and high-impact-reach filter state generates a bounded product query locally. |
| M4-50b1 | August 18, 2026 | Owner, environment, and risk filter state generates a bounded product query locally. |
| M4-50a | August 18, 2026 | The Agent table renders core columns plus deterministic local empty/loading/error test boundaries. |
| M4-49 | August 18, 2026 | The authorized safe global-search API and generated client contract are implemented locally. |
| M4-48 | August 18, 2026 | Bounded scoped product-name/type/ID search rejects raw graph-query syntax locally. |
| M4-47 | August 18, 2026 | The authorized stale-aware Home summary API and generated client contract are implemented locally. |
| M4-46 | August 18, 2026 | Home summary counts, risk-path changes, and coverage freshness fail unhealthy locally. |
| M4-45 | August 18, 2026 | The authorized deterministic attack-path break-options API is implemented locally. |
| M4-44 | August 18, 2026 | The authorized bounded attack-path lookup API is implemented locally. |
| M4-43 | August 18, 2026 | The authorized bounded attack-path list API is implemented locally. |
| M4-42 | August 18, 2026 | Deterministic evidence-linked node and policy break options are ranked locally. |
| M4-41 | August 18, 2026 | Potential, Observed, Verified, and Blocked attack-path state is retained locally. |
| M4-40 | August 18, 2026 | Attack paths are bounded to exact entry, sink, node, edge, and evidence sets locally. |
| M4-39 | August 18, 2026 | Ticket creation sends an HMAC-signed redacted payload through an injected webhook boundary. |
| M4-38 | August 18, 2026 | The authorized signed finding-ticket API and generated client contract are implemented locally. |
| M4-37 | August 18, 2026 | The authorized finding risk-acceptance API records a bounded reason locally. |
| M4-36 | August 18, 2026 | The authorized finding-status mutation API and generated client contract are implemented locally. |
| M4-35 | August 18, 2026 | The authorized scoped finding lookup API and generated client contract are implemented locally. |
| M4-34 | August 18, 2026 | The authorized relevance-filtered finding list API and generated client contract are implemented locally. |
| M4-33 | August 18, 2026 | Findings retain explainable evidence-linked risk factors without an opaque score. |
| M4-32 | August 18, 2026 | Unrelated Prowler cloud findings stay out of the default list unless bound to Agent, path, or compliance context. |
| M4-31 | August 18, 2026 | The inactive-Agent plus active-credential posture rule emits exact evidence locally. |
| M4-30 | August 18, 2026 | The CI/CD-write plus production-secret posture rule emits exact evidence locally. |
| M4-29 | August 18, 2026 | Host-filesystem or privileged runtime isolation emits exact posture evidence locally. |
| M4-28 | August 18, 2026 | Missing supported production runtime-policy coverage emits exact posture evidence locally. |
| M4-27 | August 18, 2026 | Destructive-tool reach without runtime control emits exact posture evidence locally. |
| M4-26 | August 18, 2026 | Unapproved remote tool or MCP reach emits exact posture evidence locally. |
| M4-25 | August 18, 2026 | Unrestricted egress plus sensitive-data reach emits exact posture evidence locally. |
| M4-24 | August 18, 2026 | Shell/code execution plus a production credential emits exact posture evidence locally. |
| M4-23 | August 18, 2026 | The untrusted/public-input plus production-write posture rule emits exact supporting evidence locally. |
| M4-22 | August 18, 2026 | The shared-credential posture rule emits exact supporting evidence locally. |
| M4-21 | August 18, 2026 | The human-credential posture rule emits exact supporting evidence locally. |
| M4-20 | August 18, 2026 | The ownerless-agent posture rule emits exact supporting evidence locally. |
| M4-19 | August 18, 2026 | Attack Lab verification and runtime-policy blocking preserve underlying reachability locally. |
| M4-18 | August 18, 2026 | Matching runtime/provider evidence upgrades reachable capabilities to observed locally. |
| M4-17 | August 18, 2026 | Bounded scoped graph queries derive Agent-to-target outcomes locally. |
| M4-16 | August 18, 2026 | Six MVP capability categories and fail-closed evidence-state transitions are implemented locally. |
| M4-15 | August 18, 2026 | The authorized scoped generic-asset lookup API and generated client contract are implemented locally. |
| M4-14 | August 18, 2026 | The authorized scoped runtime lookup API and generated client contract are implemented locally. |
| M4-13 | August 18, 2026 | The authorized scoped runtime list API and generated client contract are implemented locally. |
| M4-12 | August 18, 2026 | The authorized scoped identity lookup API exposes references and fingerprints but no raw credentials. |
| M4-11 | August 18, 2026 | The authorized scoped identity list API exposes references and fingerprints but no raw credentials. |
| M4-10 | August 18, 2026 | The authorized scoped tool lookup API and generated client contract are implemented locally. |
| M4-09 | August 18, 2026 | The authorized scoped tool list API and generated client contract are implemented locally. |
| M4-08 | August 18, 2026 | The authorized bounded Agent-session list API and generated client contract are implemented locally. |
| M4-07 | August 18, 2026 | The authorized bounded Agent-relationship API and generated client contract are implemented locally. |
| M4-06 | August 18, 2026 | The authorized bounded Agent-capability API and generated client contract are implemented locally. |
| M4-05 | August 18, 2026 | The authorized Agent ownership/tag mutation emits a scoped audit record locally. |
| M4-04 | August 18, 2026 | The authorized scoped Agent lookup API and generated client contract are implemented locally. |
| M4-03 | August 18, 2026 | The authorized scoped Agent list API and generated client contract are implemented locally. |
| M4-02 | August 18, 2026 | Scoped owner, team, and canonical tag mutation changes only the selected Agent and emits an audit locally. |
| M4-01 | August 18, 2026 | The bounded local asset/agent/tool/identity/runtime/relationship reconciliation gate is implemented; Neon/provider verification remains gated by M1A-10 and M3-52. |
| M4-01f | August 18, 2026 | Scoped canonical relationship projection is deterministic and replay-safe in the local product boundary. |
| M4-01e | August 18, 2026 | Runtime/workload/sandbox/isolation reconciliation preserves stable scoped identity locally. |
| M4-01d | August 18, 2026 | Identity reconciliation retains only credential references and fingerprints locally. |
| M4-01c | August 18, 2026 | Tool reconciliation prevents duplicate scoped source tools locally. |
| M4-01b | August 18, 2026 | Agent reconciliation preserves product identity while updating source metadata locally. |
| M4-01a | August 18, 2026 | Canonical asset reconciliation preserves stable full-scope IDs and evidence locally. |
| M3-52 | August 18, 2026 | A strict five-check local M3 gate is implemented; real staging remains unavailable and the task is not Complete. |
| M3-52e | August 18, 2026 | The composed failure fixture retains last-known inventory with an exact stale state. |
| M3-52d | August 18, 2026 | The local queue/archive/index replay fixture proves linked deterministic references and an empty synthetic DLQ. |
| M3-52c | August 18, 2026 | One semantic OTLP event and three runtime events traverse the bounded local ingest fixture. |
| M3-52b | August 18, 2026 | The scoped enrollment/heartbeat fixture produces supported sensor coverage locally. |
| M3-52a | August 18, 2026 | AWS, Kubernetes, GitHub, and directory fixtures compose into canonical scoped assets locally. |
| M3-51 | August 18, 2026 | Sensor enrollment, one-time rotation, and confirmed deletion controls are exposed locally. |
| M3-50 | August 18, 2026 | The Sensors route renders list, detail, enrollment, coverage, and freshness surfaces from generated schema types. |
| M3-49 | August 18, 2026 | Connection authorize, sync, and delete controls remain capability-gated and product-branded locally. |
| M3-48 | August 18, 2026 | Catalog, connected list, detail, and provider setup navigation are composed in the Connections route. |
| M3-48h | August 18, 2026 | The Generic Webhook UI exposes one fixed destination and signature-status flow without per-action URLs. |
| M3-48g | August 18, 2026 | The directory-security setup flow is visibly separate from product sign-in and Stytch SSO. |
| M3-48f | August 18, 2026 | GitHub access review displays returned Repository/Organization scope before initial sync. |
| M3-48e | August 18, 2026 | Kubernetes setup exposes coverage, scoped enrollment, Helm, heartbeat, and degraded-state steps locally. |
| M3-48d | August 18, 2026 | AWS setup exposes access review, role/external-ID, test, initial-sync, coverage, and permission remediation locally. |
| M3-48c3 | August 18, 2026 | Capability-gated integration detail actions are implemented locally; generated-client wiring remains in progress. |
| M3-48c2 | August 18, 2026 | Bounded integration data capabilities and sync-history detail are implemented locally. |
| M3-48c1 | August 18, 2026 | Integration detail health, scope, freshness, and last-sync summary are implemented locally. |
| M3-48b | August 18, 2026 | Connected-integration freshness list is implemented locally. |
| M3-48a | August 18, 2026 | Filterable product connector catalog cards remain free of internal adapter names. |
| M3-47 | August 18, 2026 | Ambiguous runtime lineage remains Probable or Unattributed and cannot upgrade to Exact. |
| M3-46 | August 18, 2026 | Unique sandbox/container/cgroup/process lineage correlation is implemented as Strong. |
| M3-45 | August 18, 2026 | Exact session and agent identity correlation is implemented as Exact. |
| M3-44 | August 18, 2026 | Deterministic scoped runtime-event index documents include archive references. |
| M3-43 | August 18, 2026 | Runtime worker orders archive, index, correlation, then acknowledgement and is replay-safe locally. |
| M3-43d | August 18, 2026 | Deterministic correlation writes occur only after archive and indexing succeed. |
| M3-43c | August 18, 2026 | Deterministic event indexing reuses event IDs and archive references on replay. |
| M3-43b | August 18, 2026 | Organization/date-scoped deterministic archive keys are implemented locally. |
| M3-43a | August 18, 2026 | Deterministic batch consumption and replay identity are implemented locally. |
| M3-42 | August 18, 2026 | Scoped internal event ingest acknowledges only after bounded publisher acceptance. |
| M3-41 | August 18, 2026 | Runtime events are batched by bounded count and bytes before queue publication. |
| M3-40 | August 18, 2026 | Metadata-only collection removes content while preserving action metadata. |
| M3-39 | August 18, 2026 | Sensor/runtime authentication and exact scope checks run before payload parsing. |
| M3-38 | August 18, 2026 | OTLP semantic attributes map agent, session, task, tool, sandbox, trace, and span identity. |
| M3-37 | August 18, 2026 | Sensor health derives kernel/BTF/resource/event/drop coverage state locally. |
| M3-14 | August 18, 2026 | Strict AWS assume-role identity adapter and local denial fixture are implemented; required real-AWS denial remains unavailable behind M1A-10. |

## Complete

| Task | Completed | Evidence |
| --- | --- | --- |
| M3-36 | August 18, 2026 | Process, file, and network Tetragon fixtures normalize with workload identity; the exact-pinned proof suite passes. |
| M3-35 | August 18, 2026 | Exact-pinned Tetragon wrapper and three bounded tracing policies pass manifest and lifecycle verification. |
| M3-34 | August 18, 2026 | Scoped token-authenticated heartbeat updates exact capabilities and rejects invalid tokens. |
| M3-33 | August 18, 2026 | Sensor coverage API passes authorized success and stable product-error tests. |
| M3-32 | August 18, 2026 | One-time sensor-token rotation passes scope, secrecy, and invalidation tests. |
| M3-31 | August 18, 2026 | Scoped sensor deletion passes authorized success and stable product-error tests. |
| M3-30 | August 18, 2026 | Scoped sensor update passes authorized success and stable product-error tests. |
| M3-29 | August 18, 2026 | Scoped sensor lookup passes authorized success and stable product-error tests. |
| M3-28 | August 18, 2026 | Sensor enrollment returns a raw token once and retains only its hash. |
| M3-27 | August 18, 2026 | Scoped sensor listing passes authorized success and stable product-error tests. |
| M3-26 | August 18, 2026 | Sensor model binds ID, token hash, configuration, capabilities, and heartbeat state. |
| M3-25 | August 18, 2026 | Authenticated GET-only Nango Proxy wrapper rejects unconfigured hosts and passes the exact proof suite. |
| M3-24 | August 18, 2026 | Nango OAuth callback validates state and PKCE and rejects mismatch fixtures. |
| M3-23 | August 18, 2026 | Product persistence retains only scoped Nango connection references, never raw provider credentials. |
| M3-22 | August 18, 2026 | Private Nango Auth/Proxy readiness and unreachable admin-ingress boundaries pass the reviewed proof suite. |
| M3-22c | August 18, 2026 | Nango database and encryption configuration renders Kubernetes Secret references only. |
| M3-22b | August 18, 2026 | Free Nango usage is constrained to Auth and Proxy with no Functions, Webhooks, or MCP dependency. |
| M3-22a | August 18, 2026 | Exact-pinned Nango deployment remains private and product-network scoped. |
| M3-21 | August 18, 2026 | Integration freshness retains last success/error/rate limit and stale last-known inventory. |
| M3-20 | August 18, 2026 | IdP normalization produces stable scoped user/group/application/service-principal identities and privilege edges. |
| M3-19 | August 18, 2026 | GitHub normalization produces stable scoped Organization/repository/app/workflow relationships. |
| M3-18 | August 18, 2026 | Kubernetes normalization links cluster, namespace, service account, workload identity, and runtime resource. |
| M3-17 | August 18, 2026 | AWS normalization produces stable scoped account, role, policy, and resource relationships. |
| M3-16 | August 18, 2026 | Exact-pinned Prowler runner emits canonical scoped resource and evidence through the reviewed proof. |
| M3-15 | August 18, 2026 | Exact-pinned Cartography runner preserves two-Organization source isolation through the reviewed proof. |
| M3-13 | August 18, 2026 | Added the exact scoped integration-sync job payload, idempotent job-key reuse, and forward-only queued/running/succeeded/failed transitions. |
| M3-12 | August 18, 2026 | Added the authorized exact integration-sync lookup API and generated client operation. |
| M3-11 | August 18, 2026 | Added the authorized integration-sync list API and generated client operation. |
| M3-10 | August 18, 2026 | Added the authorized idempotent integration-sync API with queued status. |
| M3-09 | August 18, 2026 | Added the authorized integration authorization-confirmation API. |
| M3-08 | August 18, 2026 | Added integration deletion with exact scope checks and active-sync conflict protection. |
| M3-07 | August 18, 2026 | Added strict scoped integration configuration update with connector-schema revalidation. |
| M3-06 | August 18, 2026 | Added exact scoped integration lookup with cross-Organization denial. |
| M3-05 | August 18, 2026 | Added strict scoped integration creation using only registered connector setup schemas. |
| M3-04 | August 18, 2026 | Added the authorized scoped integration-list API and generated client operation. |
| M3-03 | August 18, 2026 | Added the product-only connector-catalog search API and generated client operation. |
| M3-02a | August 18, 2026 | Added the signed Generic Webhook catalog entry with one HTTPS destination, a secret reference, and response/approval notification capabilities. |
| M3-02 | August 18, 2026 | Added the immutable connector catalog registry with bounded search and exact capability filters. |
| M3-01 | August 18, 2026 | Added the product ConnectorManifest boundary; public serialization excludes internal adapter and upstream implementation identity. |
| M1A-06 | August 18, 2026 | Added exact product IRSA trust and least-privilege scoped S3, SQS, OpenSearch, and KMS permissions without unrelated write actions. |
| M1A-05 | August 18, 2026 | Added a two-zone VPC-only OpenSearch domain with HTTPS, node encryption, KMS encryption, and product-role access. |
| M1A-04 | August 18, 2026 | Added the exact three product Standard queues and paired DLQs with encryption, redrive policies, schemas, and queue outputs. |
| M1A-03 | August 18, 2026 | Added the encrypted versioned evidence/archive bucket, public-access block, rotating KMS key, and three product secret slots. |
| M1A-02 | August 18, 2026 | Added the private-endpoint EKS control plane, encrypted Kubernetes secrets, and a minimal managed node group consuming both private subnets. |
| M1A-01 | August 18, 2026 | Added the shared non-production staging VPC and two private, non-public-IP subnets with exact outputs. |
| M2-47 | August 18, 2026 | Recorded the M2 gate PASS after the complete identity, administration, onboarding, session, deprovision, token, audit, cross-Organization, and single-tenant fixture suite passed without direct Stytch dashboard access. |
| M2-50 | August 18, 2026 | Proved two SaaS Organizations can use the same product routes independently while cross-Organization reads and mutations remain forbidden. |
| M2-49 | August 18, 2026 | Added the single-tenant configured-Organization guard before route dispatch and repository mutation. |
| M2-48 | August 18, 2026 | Added the two-Organization API authorization fixture with identical Workspace names and stable cross-Organization denial. |
| M2-47e | August 18, 2026 | Proved representative SSO, SCIM, group-mapping, and API-token mutations appear in the product audit history. |
| M2-47d | August 18, 2026 | Proved one scoped API token can be created, used, audited, revoked, and then rejected. |
| M2-47c | August 18, 2026 | Proved unauthorized Workspace reads and mutations are denied server-side. |
| M2-47b | August 18, 2026 | Retained the replay-safe SCIM deprovision fixture proving member disablement and complete Workspace-grant removal. |
| M2-47a | August 18, 2026 | Retained the fake-Stytch sign-in, session validation, revalidation, and revoked-session product-error fixture. |
| M2-46 | August 18, 2026 | Composed generated-client-backed Workspace and Environment onboarding with authorized scope selection. |
| M2-46c | August 18, 2026 | Added the authorized Workspace/Environment selector and omitted inaccessible scopes. |
| M2-46b | August 18, 2026 | Added generated-client-backed Environment create and update onboarding actions. |
| M2-46a | August 18, 2026 | Added generated-client-backed Workspace create and update onboarding actions. |
| M2-45 | August 18, 2026 | Added the API Access list/create/revoke UI with a one-time raw-token display and confirmation. |
| M2-44 | August 18, 2026 | Completed the fake-Stytch SSO, SCIM, and group-mapping administration action flow with confirmations and stable errors. |
| M2-43 | August 18, 2026 | Shipped the generated-client-backed Identity & Access administration route with five real product panels and stable loading, error, confirmation, and validation states. |
| M2-43e | August 18, 2026 | Added the group-mapping panel with exact role and Workspace/Environment scope editing. |
| M2-43d | August 18, 2026 | Added SCIM connection list, create, one-time bearer confirmation, and confirmed delete interactions. |
| M2-43c | August 18, 2026 | Added SSO connection list, create, test, and confirmed delete interactions. |
| M2-43b | August 18, 2026 | Added API-backed Organization member and immutable built-in-role panels. |
| M2-43a | August 18, 2026 | Wired the Administration Identity & Access route to the generated product API client. |
| M2-42 | August 18, 2026 | Added the scoped audit-export status lookup operation. |
| M2-41 | August 18, 2026 | Added ready bounded audit-export creation with exact event counts and correlation. |
| M2-40 | August 18, 2026 | Added the scoped paginated audit-event query operation. |
| M2-39 | August 18, 2026 | Added the product audit service for append, query, and export orchestration. |
| M2-39b | August 18, 2026 | Added structured metadata redaction before audit persistence and serialization. |
| M2-39a | August 18, 2026 | Added immutable append-only audit event persistence with no update or delete surface. |
| M2-38 | August 18, 2026 | Added hashed scoped API-token authentication that returns the shared authorization context and records last use. |
| M2-37 | August 18, 2026 | Added fresh-authorized API-token revocation without exposing stored credential material. |
| M2-36 | August 18, 2026 | Added one-time API-token creation with bounded entropy, SHA-256 digest storage, scope, permissions, and expiry. |
| M2-35 | August 18, 2026 | Added the paginated Organization-scoped API-token metadata list operation. |
| M2-34 | August 18, 2026 | Added the strict product API-token model with immutable credential and lifecycle boundaries. |
| M2-33 | August 18, 2026 | Added optimistic-versioned group-mapping create and update with exact parent-scope validation. |
| M2-32 | August 18, 2026 | Added the authorized paginated group-mapping list operation. |
| M2-31 | August 18, 2026 | Added the Organization IdP-group to built-in-role mapping store with optional exact Workspace and Environment scope. |
| M2-30 | August 18, 2026 | Added replay-safe SCIM member deprovision reconciliation that disables the product principal, removes every scoped Workspace grant, records one bounded audit summary, and retries safely after failure. |
| M2-29 | August 18, 2026 | Added a bounded Svix-compatible Stytch webhook signature, timestamp, project, event-identity, duplicate-key, and replay verifier plus the exact internal HTTP endpoint. |
| M2-28 | August 18, 2026 | Added the fresh-authenticated SCIM connection delete operation with exact provider acknowledgement and audit correlation. |
| M2-27 | August 18, 2026 | Added the fresh-authenticated SCIM connection create operation with a one-time bearer credential response that is excluded from list models. |
| M2-26 | August 18, 2026 | Added the paginated Organization-scoped SCIM connection list operation without retained bearer credentials. |
| M2-25 | August 18, 2026 | Added the product-owned SCIM connection service with strict provider config, response, HTTPS endpoint, credential, panic, and error boundaries. |
| M2-24 | August 18, 2026 | Added the fresh-authenticated SSO connection test operation with one fixed product result and audit correlation. |
| M2-23 | August 18, 2026 | Added the fresh-authenticated SSO connection delete operation with exact provider acknowledgement and audit correlation. |
| M2-22 | August 18, 2026 | Added the fresh-authenticated SSO connection create operation with strict SAML/OIDC and identity-provider configuration. |
| M2-21 | August 18, 2026 | Added the paginated Organization-scoped SSO connection list operation. |
| M2-20 | August 18, 2026 | Added the product-owned SSO service over the Stytch adapter with strict create, list, delete, test, panic, and provider-error semantics. |
| M2-19 | August 18, 2026 | Added the paginated built-in role and permission-list operation. |
| M2-18 | August 18, 2026 | Added the paginated Organization member-list operation with administrative permission enforcement. |
| M2-17 | August 18, 2026 | Added the authenticated current-principal operation over the product store. |
| M2-16 | August 18, 2026 | Added the scoped Environment update operation with strict JSON, authorization, and audit correlation. |
| M2-15 | August 18, 2026 | Added the scoped Environment lookup operation. |
| M2-14 | August 18, 2026 | Added the scoped Environment create operation with strict parent Workspace validation and audit correlation. |
| M2-13 | August 18, 2026 | Added the cursor-paginated authorized Environment-list operation. |
| M2-12 | August 18, 2026 | Added the scoped Workspace update operation with strict JSON, authorization, and audit correlation. |
| M2-11 | August 18, 2026 | Added the scoped Workspace lookup operation. |
| M2-10 | August 18, 2026 | Added the Organization Workspace create operation with strict JSON, permission enforcement, and audit correlation. |
| M2-09 | August 18, 2026 | Added the cursor-paginated authorized Workspace-list operation. |
| M2-08 | August 18, 2026 | Added the authenticated Organization lookup operation and the shared stable product-error boundary. |
| M2-07d | August 18, 2026 | Proved the product provision, invitation, first sign-in, Organization Admin reconciliation, and default-scope bootstrap path end to end with no bypass login or stored authentication secret. |
| M2-07c | August 18, 2026 | Added idempotent first-sign-in creation of one default Workspace and exact production, staging, and development Environments. |
| M2-07b | August 18, 2026 | Added the product-owned first-Admin invitation boundary using the Stytch-backed member and Organization references without persisting a raw authentication secret. |
| M2-07a | August 18, 2026 | Added idempotent operator bootstrap orchestration for one external and product Organization plus its designated first Admin. |
| M2-07 | August 18, 2026 | Added strict idempotent Organization reconciliation that keeps distinct external Organizations in distinct product records. |
| M2-06 | August 18, 2026 | Added server-side authorization resolution and handler enforcement for exact Organization, Workspace, Environment, and permission scope. |
| M2-05 | August 18, 2026 | Wired the scoped grant store and resolver behind one fail-closed authorization service. |
| M2-05b | August 18, 2026 | Added effective permission resolution across built-in principal roles and exact Workspace/Environment grants with cross-scope denial. |
| M2-05a | August 18, 2026 | Added idempotent Organization-scoped Workspace grant create/list/delete persistence methods. |
| M2-04 | August 18, 2026 | Defined the exact six built-in PRD roles and immutable product-permission snapshots. |
| M2-03 | August 18, 2026 | Added idempotent external member and Organization reference reconciliation into product principals. |
| M2-02a | August 18, 2026 | Added bounded fresh-session revalidation for sensitive operations; revoked, stale, foreign, malformed, and provider-outage paths fail closed. |
| M2-02 | August 18, 2026 | Added strict bearer-session authentication that returns only the product ExternalPrincipal and one stable authentication failure. |
| M2-01 | August 18, 2026 | Added a product-owned Stytch B2B adapter boundary for JWT, Organization, invitation, SSO, and SCIM operations without exposing provider SDK types. |
| M1-45 | August 18, 2026 | Ran the isolated real-Neon tenant lifecycle against eight protected tables; proved same-Organization access, foreign read/write denial, exact reverse migration, and schema/role absence. |
| M1-45d | August 18, 2026 | Added strict reversible RLS policy down assets in reverse order with exact policy and table-state verification. |
| M1-45c | August 18, 2026 | Added exact product policy predicates for findings, tests, audit metadata, and export jobs. |
| M1-45b | August 18, 2026 | Added exact Organization policy predicates for Organizations, grants, integrations, and policies with ENABLE and FORCE RLS. |
| M1-45a | August 18, 2026 | Added transaction-local Organization context with commit, independent rollback, fixed errors, and panic containment. |
| M1-44 | August 18, 2026 | Added the bounded cross-Organization SaaS tenancy suite across query, event, artifact, queue, graph, and quota boundaries while preserving explicit single-tenant scope. |
| M1-43 | August 18, 2026 | Added deterministic in-process Organization-scoped concurrency admission for connectors, graph queries, tests, and AI requests with independent counters and fixed over-limit rejection. |
| M1-36 | August 18, 2026 | Recorded the exact M1 foundation gate as PASS after M1-36a through M1-36e and the M1-44/M1-45 tenancy prerequisites passed. |
| M1-42 | August 18, 2026 | Hardened the existing GraphStore with explicit scope-mandatory write/query builders, proved an Organization-A bounded path cannot traverse otherwise identical Organization-B fixture state, retained hostile-result denial and concurrent per-call separation, and passed mutation, race, platform, inherited Neo4j, repository, audit, scan, and zero-finding review gates without a live provider call. |
| M1-41 | August 18, 2026 | Added one Organization-bound product consumer for exact background, runtime-event, and test envelopes; missing or foreign Organization scope fails before handler entry, and strict schema, fixed failure, panic, copy, concurrency, mutation, race, inherited SQS, repository, audit, scan, and zero-finding review gates passed. |
| M1-40 | August 18, 2026 | Routed all ArtifactStore operations through one scope-mandatory driver locator, proved a same-session Organization-A read cannot return the otherwise identical Organization-B fixture, retained concurrent per-call separation, and passed mutation, race, platform, inherited provider, repository, audit, scan, and zero-finding review gates. |
| M1-39 | August 18, 2026 | Made both EventStore driver builders explicitly scope-mandatory, fixed canonical Organization/Workspace/Environment values before driver I/O, rejected the same-session Organization-B fixture from an Organization-A query, and passed mutation, concurrency, race, platform, inherited adapter, repository, audit, scan, and zero-finding review gates. |
| M1-38 | August 18, 2026 | Added a stateless dependency-free repository guard that rejects missing or invalid product Organization scope before SQL execution, prepends the canonical Organization argument without caller-slice mutation or retained tenant state, and passed hostile tests, six race runs, full platform/repository gates, scans, and zero-finding review. |
| M1-37 | August 18, 2026 | Added strict typed `saas` and `single_tenant` deployment configuration; SaaS requires the Organization pin absent, single-tenant requires one canonical product Organization ID, and the complete truth table, six race passes, full platform/repository gates, scans, and zero-finding review passed. |
| M1-36e | August 18, 2026 | Re-ran the reviewed disposable assembled Kubernetes and LocalStack target in 261 seconds with the sole fixed success line; proved exact zero owned residue and unchanged ambient/shared fingerprints; passed six focused runs, 210 inherited tests, all Go/repository/license/audit/scan gates, and zero-finding whole-range review. |
| M1-36d | August 18, 2026 | Ran the reviewed strict UI/API traceability suite and fixed-output validator six times without changing the action map or API inventory; passed predecessor schema/OpenAPI, four Go, full repository, audit, scan, and zero-finding whole-range review gates. |
| M1-36c | August 18, 2026 | Re-ran the exact-pinned OpenAPI writer with byte-for-byte stable generated client output; passed strict tests, offline lint, six non-writing drift checks, all Go and repository matrices, audit, scans, and zero-finding whole-range review. |
| M1-36b | August 18, 2026 | Added one fixed-output offline gate across the exact database migration, canonical domain, SecurityEvent, event-index, and queue-message schema authorities; passed six focused runs, the real five-target gate, all four Go and full repository matrices, audit, scans, and zero-finding whole-range review. |
| M1-36a | August 18, 2026 | Re-proved the exact eight-target service, worker, web, and CLI build from an isolated clean checkout; disabled ambient npm user configuration in the offline web child; preserved clean tracked source; passed six orchestrator runs, the full four-module Go and repository matrices, audit, scans, and zero-finding whole-range review. |
| M1-35 | August 18, 2026 | Added the exact nine-group, 22-label PRD MVP product navigation; immutable typed route registry and unknown-route fallback; one fail-closed inert unauthenticated-route guard scaffold; corrected every reachable legacy navigation target; six focused stability passes; full repository gates, audits, scans, and zero-finding whole-range review. |
| M1-34 | August 18, 2026 | Added one immutable provider-neutral S3 bucket layout with exact Organization/Workspace/Environment evidence, export, and policy prefixes; strict non-escapable product-ID keys; exact bucket and same-account/same-Region customer-managed SSE-KMS configuration; fixed S3 Bucket Key behavior; six race passes; full platform and repository gates; pinned secret scans; and zero-finding whole-range review. |
| M1-33 | August 18, 2026 | Added three immutable product-owned Standard SQS queue definitions with paired DLQs, closed schema metadata, exact retention, visibility, polling, message-size, delay, redrive, redrive-allow, and proof-tag contracts; the final disposable LocalStack lifecycle proved all six queues and three schemas, exact cleanup and prefix-wide audit, unchanged shared infrastructure, six stability passes, full repository gates and scans, and zero-finding whole-range review. |
| M1-32 | August 18, 2026 | Added one immutable product-owned OpenSearch session/runtime event index-template contract with the exact 12-field M1-14 projection, deterministic JSON, strict dynamic-field rejection, bounded keyword mappings, a 1,024-field mapping-explosion fixture, six race passes, full repository gates and scans, and zero-finding whole-range review. |
| M1-31 | August 17, 2026 | Added one strict product AWS client factory for SQS, S3, KMS, Secrets Manager, and OpenSearch Service with explicit production authority, exact local and numeric-loopback CI endpoint overrides, synthetic credentials, bounded proxy-free transport, no retries or ambient AWS resolution, real SDK loopback request proofs, six race passes, full repository gates and scans, and zero-finding whole-range review. |
| M1-30 | August 17, 2026 | Added one strict canonical local start target over the reviewed M1-30d lifecycle, preserved all four completed profile contracts, retained disposable ownership and fixed output, passed exact live verification with zero owned residue and unchanged shared fingerprints, six focused stability runs, full repository gates and scans, and zero-finding whole-range review. |
| M1-30d | August 17, 2026 | Added the exact opt-in internal LocalStack S3 overlay with immutable Community image and license evidence, fixed synthetic endpoint variables, staged one-shot S3 Job, exact product/graph/observability preservation, complete Docker/containerd/Kubernetes ownership, reverse cleanup including provider TTL collection, fixed output, repeated exact live success, six hermetic stability runs, full repository gates/scans, and zero-finding whole-range review. |
| M1-30c | August 17, 2026 | Added the exact opt-in local OpenTelemetry Collector overlay with immutable Apache/GPL-scoped images, configuration-only no-egress proof, staged one-span Job, exact M1-21 span and file-backed sink evidence, complete Docker/containerd/Kubernetes ownership, prior-profile preservation, exact shared-image non-mutation, reverse cleanup, fixed output, final exact live passes, six hermetic stability runs, full repository gates/scans, and zero-finding whole-range review. |
| M1-30b | August 16, 2026 | Added the exact opt-in local Neo4j graph overlay with immutable GPL-scoped images, internal-only health, bounded kubelet PID authority, persistent marker proof across pod replacement, complete Docker/containerd/Kubernetes ownership, exact shared-image non-mutation, reverse cleanup, fixed output, two final exact live passes, six hermetic stability runs, full repository gates/scans, and zero-finding whole-range review. |
| M1-30a | August 16, 2026 | Added exact local Kubernetes manifests and a disposable kind lifecycle that builds the four real Go service stubs, proves all four pods Ready behind internal-only services, binds complete Docker/containerd/Kubernetes and retained filesystem identity, performs exact-owned cleanup without targeting the ambient cluster, and passed live verification, six hermetic stability runs, full repository gates/scans, and zero-finding independent review. |
| M1-29 | August 16, 2026 | Added the dependency-free strict Healthy, Degraded, and Unavailable component value with exact required/optional classification, bounded product reason codes, canonical UTC-millisecond last-success state, deterministic required-versus-optional aggregation, exact-zero regression coverage, six race and cross-command passes, 100% health-module statement coverage, full repository gates/scans, and zero-finding independent re-review. |
| M1-28 | August 16, 2026 | Registered the exact self-contained internal OpenAPI and four-command health matrix with exact GET/HEAD/status/header/media/schema semantics, a root cross-command race gate, six stability passes, unchanged public generated client and UI/API map, full repository gates/audits/scans, and zero-finding independent re-review. |
| M1-28d | August 16, 2026 | Wired the reviewed shared health handler into the standalone runtime-gateway command through one bounded internal listener with exact liveness/readiness transitions, panic-contained independent shutdown and listener cleanup, strict repository-owned dependency validation, a linked real-listener smoke, six race passes, 100% lifecycle statement coverage, full repository gates/audits/scans, and zero-finding independent review. |
| M1-28c | August 16, 2026 | Wired the reviewed shared health handler into the standalone event-ingest command through one bounded internal listener with exact liveness/readiness transitions, panic-contained independent shutdown and listener cleanup, strict repository-owned dependency validation, a linked real-listener smoke, six race passes, 100% lifecycle statement coverage, full repository gates/audits/scans, and zero-finding independent review. |
| M1-28b | August 16, 2026 | Wired the reviewed shared health handler into the platform API and worker commands through one bounded internal listener runtime with exact readiness and graceful shutdown, strict repository-owned dependency validation, real-listener smoke tests, six final race passes, 100% shared-runtime statement coverage, full repository gates/audits/scans, and zero-finding whole-range review. |
| M1-28a | August 16, 2026 | Added the dependency-free shared Go liveness, readiness, version, and bounded metrics handler with strict configuration and HTTP behavior, atomic readiness, exact root and dependency-inventory integration, six final race passes, 100% statement coverage, full repository gates/audits/scans, and zero-finding whole-range review. |
| M1-27 | August 16, 2026 | Added a scope-aware frontend ESLint rule that forbids ambient raw Fetch access under `app/**` and `apps/web/**` outside the exact generated-client boundary, rejects direct/member/computed/optional/alias/destructuring/sequence/higher-order forms without false local-name matches, and passed seeded hostile RED/GREEN, six stability passes, full repository gates/audits/scans, and zero-finding whole-range review. |
| M1-26 | August 16, 2026 | Added strict bounded UI/API coverage CI with planned/available lifecycle enforcement, complete public/internal OpenAPI operation classification, deliberate missing/unmapped-operation failures, fixed output, six stability passes, full repository gates/audits/scans, and zero-finding whole-range review. |
| M1-25 | August 16, 2026 | Added the strict checked-in two-screen UI-to-API map seed with five unique planned Home/System Health action mappings, duplicate-safe YAML and exact semantic mutation coverage, synthetic future operation resolution, six stability passes, full repository gates/audits/scans, and zero-finding whole-range review after removing unsupported route metadata. |
| M1-24 | August 16, 2026 | Generated and committed the exact immutable TypeScript API surface from M1-23 with exact-pinned OpenAPI TypeScript, exposed a zero-construction-I/O typed Fetch factory, approved the exact runtime dependency, enforced byte-reproducible drift checks in root CI, passed six stability cycles, full repository gates/audits/scans, and zero-finding whole-range review. |
| M1-23 | August 16, 2026 | Added the self-contained OpenAPI 3.1 root with exact alternative bearer authentication, canonical cursor pagination and four-field product error components, exact-pinned Redocly parser/linter CI gates, six stability passes, full repository gates/audits/scans, and zero-finding whole-range review. |
| M1-22 | August 16, 2026 | Added the dependency-free canonical six-field SecurityEvent envelope with exact version/source catalogs, full product scope, canonical UTC-millisecond time, typed evidence and product/trace/span correlation, strict direct-state rejection, six race passes, 100% statement coverage, full repository gates/scans, and zero-finding whole-range re-review. |
| M1-21 | August 16, 2026 | Added a dependency-free closed observability contract with exactly seven bounded common resource attributes, fixed service/deployment catalogs, typed product scope, strict product/trace/span correlation context fencing, raw-customer-content rejection, fresh-copy output, six race passes, 100% statement coverage, full repository gates/scans, and zero-finding whole-range review. |
| M1-20 | August 16, 2026 | Added a dependency-free scoped AIGateway with an exact `finding_explanation` purpose catalog, complete safe data-policy metadata, bounded redacted product content, one no-retry driver call, exact version-1 result validation, fixed errors, a hermetic fake-driver contract, six race passes, 100% coverage, full repository gates/scans, and zero-finding whole-range review. |
| M1-19 | August 16, 2026 | Added a dependency-free scoped ProductTelemetry with an exact `proof_completed` catalog, opaque typed fields, strict unknown/prohibited-field rejection before I/O, typed privacy-safe driver records, one bounded capture, explicit boolean acknowledgement presence, fixed errors, and a hermetic fake-driver contract; compiler RED, six race passes, 100% coverage, full repository gates/scans, and zero-finding re-review passed. |
| M1-18 | August 16, 2026 | Added a dependency-free scoped FeatureFlags boundary with required explicit enabled/disabled code defaults, exact cache hit/age metadata, one bounded driver attempt, safe outage/malformed-state fallback, fixed errors, and a hermetic fake-driver contract; compiler RED, six race passes, 100% coverage, full repository gates/scans, and zero-finding re-review passed. |
| M1-17 | August 16, 2026 | Added a dependency-free scoped AuditEmitter with required canonical actor/action/target/outcome fields, strict product grammar, one bounded append, exact acknowledgement, fixed errors, and a hermetic fake-driver contract; compiler RED, six race passes, full repository gates/scans, and zero-finding whole-range review passed. |
| M1-16 | August 16, 2026 | Added the exact-scoped official Neo4j driver adapter and an exact-owned disposable Community proof; the final live lifecycle proved three nodes, two edges, replay, structured scoped reads, Organization-B zero state, exact cleanup, prefix-wide absence, and shared-target non-mutation, followed by six hermetic passes, full repository gates, license and secret scans, and zero-finding whole-range review. |
| M1-15 | August 15, 2026 | Added a dependency-free provider-neutral GraphStore with exact Organization, Workspace, and Environment scope; canonical product-only node and edge identities; bounded structured upsert/read operations; strict defensive driver validation; a hermetic fake-driver contract; six final race passes; full repository gates and scans; and zero-finding review. Neo4j persistence remains with M1-16. |
| M1-14 | August 15, 2026 | Added a dependency-free scoped EventStore plus strict create-only OpenSearch adapter; the exact disposable lifecycle proved Organization-A index/search and Organization-B zero results, exact index/container/temp cleanup, shared-target non-mutation, six final hermetic passes, full repository gates and scans, and zero-finding independent review. |
| M1-13 | August 15, 2026 | Added a dependency-free Organization-scoped JobQueue with canonical bounded batches, opaque queue-bound receipts, exact SQS body-plus-attribute quotas, and a strict dynamic-port SDK adapter; the exact disposable LocalStack queue/DLQ lifecycle proved two scoped publish/consume/acknowledge operations, redrive state, Standard-queue partial/order handling, reverse cleanup, prefix-wide absence, shared-container non-mutation, six final hermetic passes, full repository gates/scans, and zero-finding independent review. |
| M1-12 | August 15, 2026 | Added a dependency-free Organization-scoped ArtifactStore with canonical keys, bounded fixed-error operations, defensive bytes, and SHA-256 integrity plus a strict S3/SSE-KMS adapter; the exact disposable LocalStack Put/Get/Delete lifecycle, reverse cleanup, prefix-wide audit, shared-container non-mutation, six final hermetic passes, full repository gates/scans, and zero-finding pre-landing review passed. |
| M1-11 | August 15, 2026 | Added a dependency-free driver-neutral application pool wrapper with bounded query and health contexts, validated wait/in-use statistics, exact close semantics, and a narrow pgx adapter; the exact live Neon proof observed proof-owned contention, released every acquired connection, closed cleanly, and passed all gates, scans, and zero-finding pre-landing review. |
| M1-10 | August 15, 2026 | Added an embedded dependency-free version-1 schema ledger and strict transaction runner; three fresh disposable Neon branches passed exact up/version/down/baseline restoration/deletion, all Go/product/root gates and scans passed, and independent review closed two Important and one Minor finding with zero remaining issues. |
| M1-09 | August 15, 2026 | Added one dependency-free scoped atomic idempotency claim/completion interface and request helper that executes only the unique acquired claim, returns completed duplicates' prior canonical product result, retains unknown outcomes for reconciliation, and passed ten focused groups, adversarial review, all Go/service/worker/root gates, audit, and scans. |
| M1-08 | August 15, 2026 | Added one dependency-free platform HTTP executor with an opaque validated policy, a single total deadline, complete-sequence concurrency bounds, transient-only safe retries, capped jittered backoff, one-attempt non-idempotent mutations, strict response ownership, fixed errors, twelve focused groups, adversarial review, all Go/service/worker/root gates, audit, and scans. |
| M1-07 | August 15, 2026 | A dependency-free typed loader now fails closed for missing required Stytch, Neon, AWS, or in-cluster OTLP configuration; keeps PostHog, OpenRouter, and remote OTLP explicitly optional; retains strict Secrets Manager references only; and passed ten focused groups, adversarial review, all Go/service/worker/root gates, audit, and scans. |
| M0-01 | August 13, 2026 | Fourteen external/OSS proof gates have objective PASS/FAIL criteria and initial `Not run` status; task review approved after two fix rounds. |
| M0-02 | August 13, 2026 | A disposable password-only Stytch Test Organization produced a real authenticated 60-minute Member session/JWT and was confirmed deleted; 33 black-box lifecycle/security tests, full verification, a pinned full-history Gitleaks scan, and independent review passed. |
| M0-03 | August 13, 2026 | The exact-pinned official Stytch Node SDK validated a fresh B2B JWT locally and the same JWT through forced remote authentication; 49 focused tests, a live disposable proof, full verification, dependency audit, full-history secret scan, and independent review passed. |
| M0-04 | August 13, 2026 | An exact-pinned Go/pgxpool proof derived and validated the effective Neon pooler destination, completed ten overlapping reads with zero acquired connections, closed cleanly, passed live hostname-verifying TLS, full gates, secret scan, and independent security re-review. |
| M0-05 | August 13, 2026 | A disposable Neon branch accepted one versioned up/down migration through a direct hostname-verifying pgx connection, returned exactly to its baseline fingerprint, and was absent from the active branch list after cleanup; 34 Go race tests, all repository gates, a full-history secret scan, and two independent security-review fix rounds passed. |
| M0-06 | August 13, 2026 | LocalStack created a uniquely owned Standard queue and DLQ, round-tripped exact redrive attributes and one two-event Organization-scoped batch, deleted the message, proved the source empty, and removed both queues; 22 Go behavior groups, live SDK proof, full gates, secret scan, and independent security re-review passed. |
| M0-07 | August 13, 2026 | An exact-digest disposable LocalStack target proved direct KMS encryption/decryption, an Organization-scoped SSE-KMS S3 object, and a KMS-backed secret; exact cleanup, prefix-wide current-SDK audit, container absence, full gates, secret scan, and final independent security re-review passed. |
| M0-08 | August 13, 2026 | A disposable exact-image OpenSearch target indexed one metadata-only Organization A session event; the scoped session/environment query returned exactly that event for A and zero hits for B, followed by exact index/container cleanup, full gates, secret scan, and final independent security re-review. |
| M0-10 | August 14, 2026 | Two exact-pinned disposable Cartography/Neo4j fixture runs loaded two synthetic Organizations and proved eight normalized nodes, four relationships, collision isolation, customer-label safety, exact cleanup, pinned gates/scans, two consecutive live passes, and zero-finding independent review under the fixture-only waiver; no AWS/GitHub authorization-parity claim. |
| M0-11 | August 14, 2026 | The exact-pinned Prowler fixture-only evidence proof produced one reviewed open/high finding and one linked normalized evidence record for the canonical M0-10 Organization-scoped role, proved exact cleanup and shared-target non-mutation, passed pinned gates and license/secret audits, and received a zero-finding independent re-review without claiming real-AWS parity. |
| M0-12 | August 14, 2026 | Two consecutive final-code exact-pinned disposable Tetragon/Kubernetes runs produced process, file, and outbound TCP signals with one shared Kubernetes workload identity, explicit sensor health/capability and zero drop/loss counters, exact full-ID cleanup and zero-resource audits, pinned gates/license/secret scans, and zero-finding independent review. |
| M0-13 | August 14, 2026 | The exact-pinned local OTLP ingest proof delivered one bounded trace and span with all six Organization/agent/session/task/tool/sandbox identity attributes through a real Collector into the product-owned ingest adapter, disabled remote export, proved exact cleanup in two final-code live runs, and passed pinned gates/scans plus zero-finding independent review; combined with M0-22, R-12 is PASS. |
| M0-14a | August 14, 2026 | The two consecutive final-code exact-pinned Nango/PostgreSQL runs proved minimum free self-hosted boot and exact database-backed readiness from a one-shot client on a private internal product network, with no host ports, exact cleanup, zero-resource audits, pinned gates/scans, and a zero-finding independent review; R-08 was deferred to M0-15. |
| M0-14b | August 15, 2026 | Two consecutive final-code exact-pinned Nango OAuth runs completed one private synthetic provider authorization-code and PKCE flow, retained only the Organization-scoped durable connection reference, proved exact wrapper/fixture/Nango/PostgreSQL/network/workspace ownership and zero cleanup, and passed pinned gates, license/secret scans, and a zero-finding pre-landing review; R-08 was deferred to M0-15. |
| M0-14c | August 15, 2026 | Two consecutive final-code exact-pinned Nango runs created one private `1password-events` API-key connection, verified the generated JWT-shaped provider key exactly once against the private TLS fixture, retained only the Organization-scoped durable connection reference, proved product-state secrecy and exact zero-resource cleanup, and passed pinned gates, license/secret scans, and a zero-finding whole-range review; R-08 was deferred to M0-15. |
| M0-14 | August 15, 2026 | Recorded the evidence-backed free self-hosted Nango MVP boundary as long-tail Auth plus Proxy, explicitly excluded Functions, Webhooks, MCP, RBAC, full observability, and Enterprise features without claiming their routes absent, and left the authenticated Proxy GET and R-08 decision to M0-15. |
| M0-15 | August 15, 2026 | Two consecutive final-code exact-pinned Nango Proxy runs returned one deterministic provider event through the authenticated private Proxy route, retained only scoped references plus allowlisted event ID/action, proved raw provider-token exclusion and exact zero-resource cleanup, passed pinned gates/license/secret scans, and received a zero-finding whole-range review; R-08 is PASS. |
| M0-16 | August 15, 2026 | Two consecutive final-code exact-pinned Promptfoo runs executed one synthetic direct prompt-injection case against a local fake agent, retained only the objective, vulnerable verdict, and SHA-256 evidence reference, proved exact zero-resource cleanup and shared-resource non-mutation, passed pinned gates/license/secret scans, and received a zero-finding whole-range review; R-09 is PASS. |
| M0-17 | August 15, 2026 | The exact-pinned official OPA Go SDK prepared one embedded policy query in-process, returned deterministic Allow and Block decisions across 100 warm-ups and 1,000 measured evaluations per decision, kept both decision-specific p95 values below 10 ms, and passed strict malformed-result, cancellation, panic, license, full-gate, secret-scan, and whole-range review checks; R-10 is PASS. |
| M0-20 | August 15, 2026 | One exact allowlisted analytics event reached a synthetic numeric-loopback PostHog endpoint; seeded prompt, secret, IP, and raw-evidence inputs each failed before network I/O, exact cleanup and fixed output passed, six focused runs plus full pinned repository gates/audit/scans were green, and adversarial review findings were fixed tests-first; R-13 is PASS without a hosted-PostHog delivery claim. |
| M0-21 | August 15, 2026 | One redacted synthetic finding explanation reached a numeric-loopback OpenRouter-compatible endpoint with every seeded secret/PII value absent; the exact structured result, cleanup, fixed output, six focused runs, full pinned repository gates/audit/scans, and adversarial fixes passed. M0-21a is Complete and R-14 is PASS from combined evidence. |
| M0-21a | August 15, 2026 | One bounded planning request carried untrusted instruction-injection text as data plus exactly two typed catalog actions and exact in-scope identifiers; validation accepted only the exact two-step plan, rejected action/argument/target/order/URL/shell/tool/prose drift, proved fixed output and independent cleanup, and passed six focused runs, full pinned gates/audit/scans, and adversarial review. R-14 is PASS with the retained M0-21 explanation evidence; M0-22 is Complete. |
| M0-22 | August 15, 2026 | Two consecutive exact-pinned source/sink Collector runs delivered the exact first trace, stopped and re-proved the only sink, completed the next application operation within its independent telemetry bound, proved exact zero-resource cleanup, and passed six focused runs, the retained M0-13 regression, full pinned repository gates/audit/scans, and adversarial review; combined M0-13/M0-22 evidence makes R-12 PASS. |
| M0-23 | August 15, 2026 | Recorded exactly fourteen evidence-backed M0 architecture decisions as 12 PASS / 2 BLOCKED / 0 FAIL / 0 unclassified, preserved R-03 and R-11 without provider substitution, verified every retained report and proof head, and passed hostile contract mutations, six focused runs, full pinned repository gates, audit, scans, and zero-finding evidence review. |
| M1-01d | August 15, 2026 | Created the service-local `services/platform` Go module and minimal `agentsec-api` command; exact default and link-time build versions, bounded validation, writer failures, race/build/module/vet gates, full repository verification, audit, scans, and zero-finding review passed without adding runtime I/O. |
| M1-01e | August 15, 2026 | Added the sibling service-local `agentsec-worker` command; exact default and link-time build versions, bounded validation, writer failures, both-command race/build/module/vet gates, full repository verification, audit, scans, and zero-finding review passed without adding a worker loop or runtime I/O. |
| M1-01f | August 15, 2026 | Created the standalone service-local `services/event-ingest` Go module and minimal command; exact default and link-time build versions, bounded validation, writer failures, ingest/platform race/build/module/vet gates, full repository verification, audit, scans, and zero-finding review passed without adding a listener or ingest behavior. |
| M1-01a | August 15, 2026 | Created the standalone service-local `services/runtime-gateway` Go module and minimal command; exact default and link-time build versions, bounded validation, writer failures, gateway/ingest/platform race/build/module/vet gates, full repository verification, audit, scans, and zero-finding review passed without adding proxy, listener, MCP, tool/API, OPA, configuration, provider, or network behavior. |
| M1-01b | August 15, 2026 | Created independent dependency-free Python security-worker and Node redteam-worker packages with exact no-op health commands; success/rejection/writer-error tests, six focused runs, retained Go regressions, full repository verification, audit, scans, generated-artifact hardening, and zero-finding review passed without adding worker loops, adapters, providers, queues, graphs, prompts, findings, configuration, credentials, listeners, or network behavior. |
| M1-01c | August 15, 2026 | Added the dependency-free `apps/web` build boundary around the existing locked runnable UI and the standalone `agentsecctl version` command; exact arguments/version/output, writer failures including short writes, six focused runs, web/CLI/service/worker regressions, full repository verification, audit, scans, and zero-finding review passed without adding preflight, recovery, diagnostics, provider, credential, listener, or network behavior. |
| M1-01 | August 15, 2026 | Added one dependency-free root build orchestrator for the exact eight completed service, worker, web, and CLI targets; offline/local Go compilation, isolated Python, exact worker results, bounded/fixed output, six focused runs, real artifact-free builds, all target regressions, full repository verification, audit, scans, and zero-finding review passed without dependency downloads or runtime product behavior. |
| M1-02 | August 15, 2026 | Added one exact reviewed dependency lock for all eight deployable product manifests and five current direct runtime packages; bounded fail-closed validation rejects syntax, manifest, version, license, owner, review, and copyleft drift at the start of the existing CI path, with tests-first adversarial fixes, six focused passes, all product regressions, full repository verification, audit, scans, and zero-finding review. |
| M1-03 | August 15, 2026 | Added opaque dependency-free `pid_`-prefixed UUIDv4 product IDs plus distinct bounded exact external-source references; raw and UUID-shaped vendor IDs cannot parse as product primary keys, entropy/grammar/text/reference tests and adversarial all-zero entropy fix pass, and all Go/product/full repository gates, audit, scans, and zero-finding review are green. |
| M1-04 | August 15, 2026 | Added an opaque dependency-free Organization/Workspace/Environment scope value; all three canonical product IDs are required, pairwise distinct, and revalidated against malformed same-package state, with missing/duplicate/vendor-boundary tests, six focused passes, all Go/product/full repository gates, audit, scans, and zero-finding review green. |
| M1-05 | August 15, 2026 | Added an opaque canonical product-ID evidence reference plus exact evidence-confidence and capability/path-state values; aliases, severity words, malformed references, receiver misuse, and invalid direct casts fail closed, with six focused passes, all Go/product/full repository gates, audit, scans, and zero-finding review green. |
| M1-06 | August 15, 2026 | Added an opaque stable product error code, distinct canonical correlation ID, bounded product-language message, explicit retryability, and exact four-field JSON response; malformed/direct-state and escaping snapshots, six focused passes, all Go/product/full repository gates, audit, scans, and zero-finding review are green. |

`PRE-01`, `PRE-02`, and `PROV-01` do not count as source-plan microtasks.

## Blocked

| Task | Blocked since | Exact dependency | Resume condition |
| --- | --- | --- | --- |
| M0-09 | August 13, 2026 | The reviewed real-AWS harness has none of the nine task-specific inputs and no isolated authenticated two-account fixture. Existing generic AWS values target loopback LocalStack. | Provide the documented isolated commercial-AWS source and target-admin credentials, expected distinct accounts/source principal, region, and exact isolation attestation. |
| M0-18 | August 15, 2026 | The reviewed harness is locally green, but the capability audit found 0/11 required inputs: no authenticated real EKS kubeconfig, disposable Fargate profile, product proxy endpoint, or canary credential. LocalStack k3s cannot prove AWS-managed Fargate scheduling. | Provide all eleven documented inputs for an isolated disposable real EKS Fargate profile, run the exact live proof, prove cleanup, repeat gates/scans/review, and only then decide R-11. |
| M0-19 | August 15, 2026 | The reviewed harness is locally green, but the capability audit found 0/19 required inputs: no authenticated real EKS/EC2 fixture, disposable Fargate profile, restricted Pod security group, product proxy endpoint, or canary credential. LocalStack cannot prove AWS-managed Fargate, branch-ENI attachment, or real EKS Security Groups for Pods enforcement. | Provide all nineteen documented inputs for an isolated disposable real EKS Security Groups for Pods fixture, run the exact live proof, prove reverse cleanup and global absence, repeat gates/scans/review, and only then decide R-11. |

The user approved a temporary delivery waiver for a fixture-only Cartography
normalization proof. M0-10 is Complete without claiming AWS or GitHub
authorization parity. M0-09 and PROV-01 remain Blocked, and R-03 remains
incomplete. M0-18 and M0-19 are also Blocked on their exact real-provider fixtures. A
zero-finding implementation review does not override the failed
provider capability gate.

## Review findings

| Source | Finding | Ruling |
| --- | --- | --- |
| Prerequisite final review | Runnable UI workflow pinned immutable but older v4 GitHub Action SHAs; GitHub later warned that their Node 20 runtimes were deprecated. | Resolved August 13, 2026: updated to the immutable official `actions/checkout` v7.0.1 and `actions/setup-node` v7.0.0 SHAs, both using the Node 24 action runtime. |
| M0-02 task review | Password migration/authentication responses did not validate every required identity-bearing Organization field. | Resolved in `da13230`: require a newly created Member and matching expanded Organizations at both boundaries, with fail-closed cleanup tests. |
| M0-02 task review | Mixed credential, cleanup-failure precedence, and stalled-response deadline paths lacked direct regression tests. | Resolved in `da13230`: added black-box zero-I/O, dual-failure, and bounded stalled-body cleanup coverage; review rerun approved with no remaining findings. |
| M0-04 task review | A validated Neon-looking URL could still use pgx query, environment, or file fallbacks to dial a different effective destination. | Resolved in `e8a8f5f`: explicit URL identity, minimal query allowlist, PG environment refusal, effective-config/TLS validation, and per-connection revalidation now fail closed; hostile regressions and live `verify-full` proof pass. |
| M0-04 task review | Worker panics bypassed fixed errors/cleanup, and the documented live command changed directories before loading the root `.env`. | Resolved in `e8a8f5f`: each worker converts panics to one fixed result and cleanup is proven; the exact runnable root sequence is contract-tested. |
| M0-05 task review | Successful and partial create responses could authorize cleanup without re-fetching the provider-stored run marker; DELETE 204 responses were not reconciled. | Resolved in `ba0d2b3`: exact provider annotation value/type/ID now gates database access and deletion, branch-only emergency cleanup retains that proof, and both 200/204 delete outcomes require exact active-list absence. |
| M0-05 re-review | Valid but stale branch or endpoint identifiers in malformed create responses could override stronger provider-listed ownership and strand the proof branch. | Resolved in `37d638f`: incomplete responses provide no identifier authority, provider branch/annotation proof is established independently, and endpoint/hint mismatches block database access while preserving exact cleanup. |
| M0-06 task review | The committed README contract was red, and strict redrive-policy parsing accepted duplicate known JSON keys. | Resolved in `4b8ae34`: the documented boundary and focused/full gates pass with corrected evidence, and recursive duplicate-key validation rejects duplicate policy and nested-envelope members. |
| M0-06 re-review | Go's case-insensitive struct-field matching allowed case-variant JSON aliases to bypass exact-key policy and envelope validation. | Resolved in `ba02323`: recursive exact JSON-tag schema validation rejects 42 alias forms across every policy, envelope, and nested-event member while preserving duplicate, unknown, trailing, malformed, null-container, and type checks. |
| M0-07 task review | Non-idempotent KMS key creation inherited SDK retries, prefix-wide audits could miss extra proof resources, and several definite post-create results were not retained early enough for cleanup. | Resolved in `8617ca7`: key creation is single-attempt, preflight/final audit reject prefix extras and duplicate proof keys, and staged key/alias/object targets plus exact ambiguous-write reconciliation preserve fail-closed cleanup. |
| M0-07 task review | Readiness did not enforce hard body/time limits, pre-orchestrator construction could escape the fixed-output boundary, and the endpoint validator accepted a slash path. | Resolved in `8617ca7`: readiness has byte and absolute-time caps, all construction/orchestration failures emit one fixed line, and only an exactly empty endpoint path is accepted; final re-review found no remaining issues. |
| M0-08 task review | Index ownership did not validate the proof discriminator, and definitive HTTP failures could reconcile overwrite-capable document writes or adopt pre-existing exact-looking resources. | Resolved in `cb54031`: exact proof metadata now gates inspection/reconciliation/cleanup, non-2xx mutations are definitive, document writes are create-only, and only ambiguous applied-success outcomes may reconcile exact provider state. |
| M0-08 re-review | Unexpected successful 2xx mutation statuses were classified as definitive, so an applied index or document could bypass reconciliation and strand owned state. | Resolved in `959f033`: unexpected 2xx outcomes are ambiguous while non-2xx remains definitive; applied-exact, unapplied, and mismatched index/document regressions pass and final re-review found no remaining issues. |
| PROV-01 final review | The implementation reached zero remaining Critical, Important, and Minor findings, but exact-pinned LocalStack 4.7.0 returned no SourceIdentity and accepted the deliberately wrong SourceIdentity despite the trust condition. | PROV-01 is Blocked, not Complete. M0-10 is Complete only under the fixture-only Cartography delivery waiver; M0-09 stays Blocked and R-03 remains incomplete. Resume PROV-01 only with provider evidence for both required SourceIdentity behaviors. |
| M0-10 final review | The final scoped implementation review found zero remaining Critical, Important, or Minor findings after the lifecycle, ownership, parsing, portability, and waiver-contract fixes. | Complete August 14, 2026 under the fixture-only Cartography delivery waiver after two consecutive live passes, exact zero-resource cleanup audits, pinned local gates, and redacted secret scans; no AWS/GitHub authorization-parity claim. |
| M0-11 final review | The final scoped implementation re-review found zero remaining Critical, Important, or Minor findings after definitive mutation classification, global absence audit, full runtime ownership, late-mutation settlement, and adapter-license evidence fixes. | Complete August 14, 2026 after the exact fixture-only live proof, linked normalized evidence capture, exact zero-resource cleanup, shared-target non-mutation, pinned local gates, license/secret audits, and zero-finding review; R-06 is PASS without a real-AWS parity claim. |
| M0-12 final review | The final scoped implementation re-review found zero remaining Critical, Important, or Minor findings after cleanup authorization, deadline, image-digest, concrete lifecycle, workload-identity, mutation-result, ownership, and evidence-boundary fixes. | Complete August 14, 2026 after two consecutive final-code live passes, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding independent review; R-07 is PASS under the approved observation-only boundary. |
| M0-13 final review | The final scoped implementation review found zero remaining Critical, Important, or Minor findings after bounded child supervision, mutation settlement, retained pre-verification cleanup authority, concrete runtime coverage, and fixed-output taxonomy alignment. | Complete August 14, 2026 after two consecutive final-code exact Collector passes, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding independent review; combined M0-13/M0-22 evidence now makes R-12 PASS. |
| M0-14a final review | The final scoped implementation review found zero remaining Critical, Important, or Minor findings after bounded mutation settlement, initialization candidate retention, raw HTTP-byte validation, schema/start/remove reconciliation, coherent cleanup snapshots, and immutable cross-correlated private-network ownership. | Complete August 14, 2026 after two consecutive final-code exact Nango/PostgreSQL passes, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding independent review; R-08 was deferred to M0-15. |
| M0-14b final review | The final scoped pre-landing review found zero remaining Critical, Important, or Minor findings after live API-shape, exact Docker attachment, complete TLS-workspace identity, ambiguous lifecycle, coherent cleanup, and synthetic-secret scan fixes. | Complete August 15, 2026 after two consecutive final-code exact OAuth passes, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding review; R-08 was deferred to M0-15. |
| M0-14c final review | The whole-range review found zero remaining Critical, Important, or Minor findings after exact live provider-schema/header corrections and strict bounded synthetic-key validation. | Complete August 15, 2026 after two consecutive final-code exact API-key passes, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding review; R-08 was deferred to M0-15. |
| M0-14 final review | The evidence and status review found zero remaining Critical, Important, or Minor findings after binding the source task, PRD, accepted proof chain, exact exclusions, aggregate counts, and hostile status/risk mutations. | Complete August 15, 2026 as an evidence-only Auth-plus-Proxy boundary record with pinned local gates, audit, license and secret scans; R-08 was deferred to M0-15. |
| M0-15 final review | The whole-range review found zero remaining Critical, Important, or Minor findings after exact live Proxy response validation and duplicate wire-header rejection. | Complete August 15, 2026 after two consecutive final-code private Proxy passes, product-only secrecy capture, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding review; R-08 is PASS. |
| M0-16 final review | The whole-range review found zero remaining Critical, Important, or Minor findings after exact workspace, network, container, mutation-settlement, readiness, global-absence, normalization, and retained-resource ownership fixes. | Complete August 15, 2026 after two consecutive final-code exact Promptfoo passes, product-only objective/verdict/evidence capture, exact zero-resource cleanup audits, shared-resource non-mutation, pinned local gates, license/secret scans, and zero-finding review; R-09 is PASS. |

## Execution notes

- The pre-existing UI is a browser-local prototype. It currently persists demo
  actions in local storage and does not call the product API.
- The repository passed 20 tests, type-check, and production build under Node
  22.23.1 at preflight. Lint reported 37 errors and is part of `PRE-01`.
- Node 26 exposes an experimental global `localStorage` that conflicts with the
  current Vitest DOM setup. The project uses Node 22 types and is pinned to
  verified Node 22.23.1 as part of completed `PRE-01`.
- On hosts with Homebrew libvips, dependency installation must set
  `SHARP_IGNORE_GLOBAL_LIBVIPS=1` so the locked Sharp binary is used.
- `PRE-01` completed with pinned Node 22.23.1/npm 10.9.8, a root verification
  command, and a clean lint baseline. No source-plan task status changed.
- `PRE-02` completed with a GitHub Actions gate for pushes and pull requests.
  It pins Node 22.23.1/npm 10.9.8, uses the documented locked install, and
  runs `npm run verify`; a parsed-workflow test protects that contract.
- The first remote gate passed but warned that the original v4 action pins used
  deprecated Node 20 runtimes. The gate now pins the current official v7 action
  releases by immutable SHA; both declare the Node 24 action runtime.
- `M0-01` completed after independent review confirmed all 14 proof gates and
  the supported EKS Fargate scheduling signal.
- `M0-02` resumed after Test-prefixed Stytch credentials became available in a
  separate ignored environment file. The values are not copied into this
  repository or emitted by proof output.
- `M0-02` completed after its stricter disposable flow passed live against
  Stytch Test, a pinned Gitleaks v8.30.1 full-history scan found no leaks, all
  61 repository tests and quality gates passed, and independent re-review
  approved the two security fix areas with no remaining findings.
- `M0-03` completed with the exact-pinned official Stytch Node SDK after its
  fresh-local and forced-remote paths passed the disposable live proof, all 77
  repository tests and quality gates passed, production dependency audit and
  pinned full-history secret scan were clean, and independent review found no
  Critical, Important, or Minor issues.
- `M0-04` completed after its hardened effective pgx configuration, panic
  cleanup, and runnable documentation passed independent re-review with no
  remaining findings. The live proof completed ten concurrent pooled reads,
  reported zero acquired connections, and closed under hostname-verifying TLS.
- `M0-05` completed after a current-code live run applied and reverted the
  embedded migration, restored the exact namespace fingerprint, deleted the
  disposable branch, and found zero active proof branches. The final
  independent re-review found no remaining issues after two cleanup-ownership
  fix rounds; Neon soft deletion means the evidence does not claim immediate
  physical erasure.
- `M0-06` completed after the exact-pinned AWS SDK created and freshly proved
  a tagged Standard queue/DLQ, round-tripped strict redrive policies and one
  two-event Organization-scoped message, proved the source empty, and found
  zero proof queues after cleanup. LocalStack evidence does not claim IAM
  enforcement or real-AWS parity. Final independent re-review found no issues.
- `M0-07` completed after direct KMS encryption/decryption, one default-plus-
  explicit SSE-KMS Organization-scoped object, and one KMS-backed current
  secret all round-tripped in an exact-digest disposable LocalStack target.
  Prefix-wide audit proved zero active proof resources and exactly the tracked
  pending-deletion key; the container was absent and shared development
  infrastructure was unchanged. Local evidence does not claim real-AWS
  encryption, IAM, durability, or release parity. Final re-review found no
  remaining issues.
- `M0-08` completed after an exact-image disposable OpenSearch target indexed
  one strict metadata-only Organization A session event. The scoped EventStore
  returned exactly one matching session/environment hit for A and zero for B,
  then prefix-wide audit found zero active proof indices and the disposable
  container was absent. This local proof does not claim AWS OpenSearch Service,
  IAM, durability, or release parity. Final independent re-review found no
  remaining issues.
- `M0-09` has a fully reviewed real-AWS harness but is Blocked because no
  isolated two-account fixture or task-specific credentials are available.
  LocalStack cannot satisfy its release-parity gate.
- The user approved PROV-01 as a temporary, non-source-plan compatibility proof.
  It uses a separate disposable LocalStack IAM/STS target and cannot modify or
  complete M0-09/R-03. PROV-01 is Blocked on the exact LocalStack
  SourceIdentity/trust-condition capability dependency. M0-10 is Complete
  only under the fixture-only Cartography delivery waiver and makes no AWS or
  GitHub authorization-parity claim.
- M0-10 is Complete after its root commands exposed only the hermetic
  two-Organization Cartography fixture proof. It accepts no dotenv,
  credential, or proxy input, makes no AWS or GitHub calls, and cleans up only
  proof-owned disposable resources. This does not prove AWS/GitHub authorization
  parity: M0-09 and PROV-01 remain Blocked, and R-03 remains incomplete.
- M0-11 is Complete as a fixture-only Prowler evidence proof after one exact
  live run, cleanup audit, repository gates, license/secret scans, and a
  zero-finding independent re-review passed. R-06 is PASS with that retained
  evidence. M0-09 and PROV-01 remain Blocked, and R-03 remains incomplete.
- M0-12 is Complete after two consecutive final-code exact-pinned disposable
  Tetragon/Kubernetes runs produced process, file, and outbound TCP signals with
  one shared Kubernetes workload identity, explicit capability/drop state, exact
  cleanup, pinned gates and scans, and a zero-finding independent review. R-07
  is PASS under the approved observation-only boundary.
- M0-13 is Complete after two consecutive final-code exact-pinned Collector
  runs retained one trace/span with all six semantic identity attributes,
  disabled remote export, proved exact cleanup, passed pinned gates/scans, and
  received zero-finding independent review. Combined with M0-22's bounded
  export and nonblocking failure proof, R-12 is PASS.
- M0-14a is Complete after two consecutive final-code runs of the exact free
  self-hosted Nango server with PostgreSQL as its only long-running dependency
  proved database-backed readiness from a one-shot client on a private product
  network, exact cleanup, zero-resource audits, pinned gates/scans, and a zero-
  finding independent review. R-08 was deferred to M0-15 and is now PASS.
- M0-14b is Complete after two consecutive final-code exact-pinned private
  fixture-provider OAuth runs through a product-owned wrapper retained only a
  durable Nango connection reference, proved exact zero-resource cleanup, and
  passed pinned gates and scans. It introduces no real provider credential or
  host publication and did not independently advance R-08; M0-15 later did.
- M0-14c is Complete after two consecutive final-code exact-pinned private fixture-provider
  API-key runs retained only the durable Organization-scoped connection reference,
  proved the raw key absent from product state, cleaned every exact-owned resource,
  and passed pinned gates and scans.
- M0-14 is Complete as an evidence-only boundary record: free self-hosted
  Nango is accepted for long-tail Auth plus Proxy, while Functions, Webhooks,
  MCP, RBAC, full observability, and Enterprise features remain out of scope.
  M0-15 is Complete after two consecutive authenticated private Proxy GETs,
  exact product-state secrecy and cleanup evidence, pinned gates/scans, and a
  zero-finding whole-range review. R-08 is PASS.
- M0-16 is Complete after two consecutive final-code exact-pinned Promptfoo
  runs executed one synthetic direct prompt-injection case against a local fake
  agent, retained only the objective, vulnerable verdict, and SHA-256 evidence
  reference, proved exact zero-resource cleanup and shared-resource
  non-mutation, and passed pinned gates, scans, and zero-finding review. R-09
  is PASS.
- M0-17 is Complete after two consecutive direct final-code OPA Go SDK proofs
  returned deterministic Allow/Block decisions with decision-specific p95 well
  below 10 ms, plus exact dependency/license audits, full gates, scans, and
  zero-finding whole-range review. R-10 is PASS. M0-18 is Blocked.
- M0-18 is Blocked with a reviewed real-provider-only Fargate proof boundary. The
  current capability audit has no real AWS credentials, authenticated EKS
  kubeconfig, disposable Fargate profile, product proxy endpoint, or test
  canary credential, so no cluster request has been made. LocalStack's embedded
  k3s/k3d EKS compatibility cannot advance M0-18 or R-11.
- M0-19 is Blocked with a reviewed real-provider-only Security Groups for Pods
  and branch-ENI evidence boundary. The capability audit found 0/19 required
  inputs and the fixed gate rejected before any AWS or cluster request. M0-18
  remains Blocked; R-11 remains Not run and M0-21 is In progress.
- M0-20 is Complete after its local fake PostHog endpoint received one exact
  allowlisted event while prompt, secret, IP, and raw-evidence inputs failed
  before I/O; cleanup, gates, scans, and review passed. R-13 is PASS.
- M0-21 is Complete with the reviewed local explanation/privacy proof. It does
  not advance R-14, which also requires the separate M0-21a planner proof.
- M0-21a is Complete with the fixed two-action catalog and in-scope planner
  validation boundary. M0-22 is Complete and R-14 is PASS from the combined
  M0-21 explanation/privacy and M0-21a planning evidence.
- M0-22 is Complete after two consecutive exact-pinned Collector runs proved
  bounded delivery, exporter failure, nonblocking application progress, and
  exact cleanup. Combined M0-13/M0-22 evidence makes R-12 PASS; M0-23 is
  Complete with the retained fourteen-decision gate.
