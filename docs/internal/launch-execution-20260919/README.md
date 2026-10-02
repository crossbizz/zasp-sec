# Launch execution plan

> For implementation in the main task: use Superpowers executing-plans, focused TDD and feature-batched independent review. This side-conversation change is documentation only; it starts no agents, tests, deployments or publication.

**Goal:** Finish the complete original 728-task scope and its production acceptance, including multi-tenancy, automatic discovery/sync and security, with less serial verification overhead.

**Architecture:** Preserve the original task dependency graph and authoritative availability ledger. Split preparation, completion of missing work, verification and release handoff so independent work can proceed while prerequisite acceptance remains explicit.

**Tech stack:** Existing Go services, PostgreSQL authority, React/TypeScript UI, worker adapters, Terraform/Helm and provider-backed release checks.

**Spec:** [Original v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md). [Authoritative availability TSV](../implementation_production_availability_v1.5.tsv). [Status and current evidence](../implementation_status_v1.5.md).

## Coverage and status boundary

Snapshot date: 2026-09-19. Exactly **202 pending ledger rows: 141 component-only + 61 blocked/external**. All have four named checklist subtasks, original deliverable/verification, original direct dependencies, nearest pending upstream prerequisites, a functional owner and a feature batch in [tasks.md](tasks.md). [tasks.json](tasks.json) is the same plan in machine-readable form, including all728 dependency nodes.

The four checklist entries per row are coordination stages, not808 new product requirements or a mandate for808 separate test/review runs. They are not complete file-level coding recipes: DISPATCH-GATE below resolves exact files, interfaces and focused checks just in time for each selected packet. No original task is removed, reclassified or declared complete. The historical526 production-available rows do not establish current end-to-end readiness. Five connected launch gaps below explicitly cover known incomplete paths across those historical rows too.

The ledger remains authoritative for status. This document is an execution companion, not a replacement ledger. Reconcile newer main-thread work before starting a card; evidence strings can lag newer component reports. Do not rebuild accepted components just because their availability class is still component-only.

## Active acceleration boundary

Current main-task priority is the automatic-discovery restart/replay correction,
then its connected proof. Do not restart this packet or divert its migration,
scheduler, generated-contract or publication ownership to another lane.

| State | Current boundary |
| --- | --- |
| Implemented | Additive release60 migration candidate: exact occurrence fencing, rebind generations, durable completion storage/replay, release59 compatibility inventory and safe down. |
| Locally verified | Tasks1–4 are independently accepted. Controlled attempt14 proves exact60 startup,300.268-second cadence, restart/rebind/durable completion, one sync/job/outbox, browser inventory change, last-good retention and disabled withdrawal with clean joins/cleanup. The exact candidate also passes the grouped repository verification, runnable UI build and285-test release contract suite. This is not live-provider proof. |
| Under review | None. Independent final review accepted the executable schema59-drain/schema60-activation guard and the inner-admission lease-expiry rollback regression. |
| Next critical path | Supply approved fresh exact-lock dependency audit evidence, rerun the fail-closed publication gate on unchanged bytes, then execute the remaining authorized external deployment, attestation and live-provider packages. |
| Published | None from this release60 packet. No commit, push or availability promotion is claimed. |
| Externally blocked | `npm run production:release:gate` rejects publication because approved fresh exact-lock advisory evidence is unavailable. Live provider/customer-cluster, hosted deployment, signing/scanning and human-observation evidence also still require the named external packages below. Controlled PostgreSQL or connector fixtures do not close them. |

Acceleration rules for this boundary:

- Use focused RED/GREEN only while behavior changes, one affected grouped gate
  per coherent task and one full UI/build/security/release matrix at publication.
- Reuse evidence only when source, dependency and environment pins still match.
  Rerun only the checks invalidated by a review fix or shared contract change.
- Inspect an existing long-running cadence/provider job by its recorded identity;
  never restart it merely to obtain status.
- Parallelize only work with available inputs and an exact file-disjoint write
  set. Keep one owner for migration SQL, registry/CLI pins and publication.
- Ship a bounded reviewed candidate when its actual SHIP-GATE passes. Do not
  wait for unrelated product work, and do not call that full-product completion.

## Why the queue must not run as one serial chain

The full original graph has728 nodes, no missing task references and no cycles. If every original dependency is interpreted as a prerequisite to **begin any work**, the pending frontier contains only **M0-02**. Many dependencies pass through historically completed nodes to earlier pending gates.

Keep every edge for original acceptance. Do not silently delete dependencies to claim parallel completion. Preparation, isolated implementation and local verification can overlap once the consumed contract is present and verified on a pinned revision. Original and nearest-pending task dependencies are attached to the release/acceptance stage, not the local-test stage. A failed or missing contract blocks its consumers, but an unrelated upstream publication gate must not prevent testing already available code. Live checks still require their own authorized environment and provider prerequisites. The single-node frontier describes strict original acceptance, not the number of implementation packets that can run now.

## Parallel lanes

| Lane | Ownership | Startable preparation now | Integration handoff |
| --- | --- | --- | --- |
| L1 | Agent execution: T07, T08 | Close manual SQL review; plan ordered-step contract; prepare export activation/runtime composition | Frozen SQL/API/action contracts and durable receipts to L3/L5 |
| L2 | Connect/discover/sync and test adapter: T03, T04, T12 | Two-tenant connector fixtures, queue/source freshness checks, pinned runner cases | Real scoped inventory/test evidence to L1/L5/L6 |
| L3 | Product UI, identity/audit, compliance/privacy: T10, T11, T14 | Reuse accepted components; prepare native download and API-backed browser journeys | Authenticated observable user journeys against L1/L2 contracts |
| L4 | Deployment and supply chain: T15, image attestation | Render/validate shared modules, exact image inventory, account/scan input checklist | Candidate-bound deploy/scan/attestation package |
| L5 | Verification/recovery/scale: T09, T16 | Tenant/budget/outage matrices, bounded load and upgrade/recovery fixtures | Grouped acceptance results on a frozen integrated candidate |
| L6 | External execution and human evidence | Prepare account/provider/participant prerequisites and bounded run manifests | Actual AWS/Fargate/cloud/human observations, not local substitutes |

These are logical lanes, not a claim that six workers have been launched. With four execution slots, use at most three non-overlapping implementers plus one integration/review seat. Rotate the active lane by unblocked work and dependency impact. The side conversation has not assigned or contacted any agent.

File ownership:

- One writer for `services/platform/migrations`, catalog checksums and release fingerprints.
- One integrator for `openapi/openapi.yaml` and generated `apps/web/api/generated.ts`.
- Split `services/platform/apiserver` and `agentsec-worker` by named files before assigning work; directory labels alone do not establish independence.
- L3 separates compliance/privacy from agent UI files. L4 owns Terraform/Helm changes; L5 consumes frozen deployment contracts.
- One publication owner reconciles current main, gates and exact commits. Do not stage, overwrite or publish unrelated dirty-tree changes.
- Dedicated disposable environments for outage/load tests. Never run disruption and acceptance on the same shared environment concurrently.

## Next executable packets

These are selection priorities, subject to DISPATCH-GATE; do not launch them from broad directory ownership alone. Skip or shorten already completed packets after checking newer main-thread evidence.

1. L1: reconcile and independently review the frozen manual SQL report; resolve only findings. In parallel, L3 prepares the authenticated public configuration-to-download journey against agreed contracts.
2. L1: complete public export activation/readiness and ordered multi-step execution as separate bounded packets with one shared SQL integrator. L2 can prepare existing-test retry/recovery coverage and discovery/sync fixtures without changing held SQL.
3. L4: resolve candidate-bound scanner/provider prerequisites early; validate deployment locally while external authorization is pending. No alternate advisory endpoint or fixture may bypass the recorded disclosure/production gates.
4. L5: prepare tenant/isolation, budget and recovery cases now; run them once against the integrated candidate when L1/L2 contracts are ready.
5. L6: execute only authorized reference-environment checks, then SaaS and single-tenant golden journeys and human observations. Close M8-54 only with all original required results.

Packets can be independently published when all their required gates pass; do not hold safe verified changes for unrelated unfinished features. Publication still does not mean the full launch scope is complete.

## DISPATCH-GATE: turn a selected packet into safe parallel work

Complete this once per coherent packet, shared by all its task cards. Do not repeat it202 times before coding. Preparation has no execution dependency and may begin immediately.

1. Name original task IDs and the single observable output of the packet. Read the newest evidence and identify the actual remaining gap; remove already accepted work from this packet, not from original scope.
2. Record the exact files to edit and any shared files to leave to the integrator. Broad source directories in task cards are discovery hints, not exclusive ownership assignments.
3. Record the actual consumed API/schema/action contract and its current revision. Specify produced fields/signatures or artifact identities before another packet consumes them. If the input does not exist, name the producer packet as a hard implementation dependency. Do not fabricate an interface to keep a lane busy.
4. Name the focused failing behavior, exact existing test command or new test location, and the feature-batch command. For implementation, write the test before the behavior change. A source audit alone is not runtime proof.
5. Record one implementer and one independent review handoff, required external authorization, and cleanup ownership. Select only packets with non-overlapping write sets and available runtime inputs.

The global DISPATCH-GATE marker is evaluated per packet, not a one-time flag that enables every task. A blocked packet yields its execution slot to another ready packet. The shared migration/pin writer remains single-owner.

Dependency types are distinct:

- **Implementation input:** actual code/schema/config consumed; missing input blocks coding that depends on it.
- **Local verification input:** built behavior plus the appropriate fixture/runtime; requires neither unrelated task publication nor the entire launch.
- **External execution input:** approved account, identity, environment or observer; cannot be replaced by local fixtures for a live criterion.
- **Original acceptance prerequisite:** every original dependency and unresolved upstream gate; preserved at task acceptance.
- **SHIP-GATE:** exact candidate's mandatory publication checks. It is not shorthand for M8-54 or completion of all202 pending rows. Publishing a safe packet does not itself promote its task's production availability.

## Verification cadence and stop rules

- For a changed behavior: focused failing regression, implementation, targeted passing check. Skip redundant setup/test cycles for unchanged code.
- At a coherent feature boundary: one affected API/database/worker/UI/race batch, with a task-to-assertion evidence map and one independent review.
- After review fixes: rerun affected cases plus checks invalidated by shared schema/contract/dependency changes. Reuse other evidence only while its exact source, dependencies and environment requirements remain valid.
- Before each push (**SHIP-GATE**): reviewed exact diff, required release/security checks, generated contract consistency and runnable UI build/smoke. Never waive a required scan or tenant/safety check for speed.
- External jobs: start once, record run ID, inspect that same job. Do not rerun long tests just to recover status.
- Preserve the original <=15-minute active-work timebox as a splitting signal, not a completion estimate. If a step exceeds it, split at a concrete output and record the next prerequisite. Infrastructure waiting is separate.
- A recurring failure gets a root-cause owner and a reproducer. Do not add adjacent features until that boundary is understood.
- Use a brief batch handoff: completed task IDs, exact evidence, remaining blockers, next unblocked packet. No invented completion percentage or launch date.

## External prerequisite packages

| Gate | Required input | Output |
| --- | --- | --- |
| EXT-live-aws | Authorized isolated AWS account, exact role trust and bounded resource scope | Actual STS/IRSA allowed/denied observations and resource cleanup record |
| EXT-live-fargate | Authorized disposable EKS/Fargate profile, canary target, SG/proxy and cleanup owner | Actual scheduling/canary and denied-direct/allowed-proxy egress with cleanup |
| EXT-cloud-deploy | Authorized reference deployment, current exact candidate, provider identities and bounded run budget | Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts |
| EXT-human-observation | Named consenting engineer/admin/design partners and a working reference environment | Actual observed task outcomes, product errors and explicit release-blocking findings |
| EXT-image-attestation | Exact candidate image digests, approved registry/signing identity and scanner tooling | Candidate-bound SBOMs, signatures and unsigned/tampered denial results |

M8-47 separately requires approved dependency/advisory disclosure and actual dependency/image scanner results for the exact candidate. Provider credentials, approved pricing and deployment access must be resolved explicitly where consumed. This plan grants no new cloud, messaging, signing or disclosure authority.

Current repository-evidence audit: none of the six packages above is available
as a current exact-candidate input. Existing offline Terraform, mock release runs,
base-image pins and local fixtures are preparation evidence only. They do not
authorize or prove live AWS/Fargate, reference deployment, product-image
attestation, scanner/advisory acceptance or human observation. Request each
named package once, attach its run/artifact identity, and inspect that same run;
do not restart local acceptance work while waiting for it.

## Connected gaps beyond pending-row counts

### R1: Close the manual admission integration review

Original coverage: M7A-70, M7A-71, M7A-72. Lane: L1. Depends on: verified existing contracts; no other supplemental packet.

- [x] R1.1: Review the frozen manual-report.md/manual.patch against current bytes; reconcile any subsequent main-thread work before editing.
- [x] R1.2: Resolve findings with focused reproductions; retain the actual public-handler/registered-SQL admission, replay, cancellation and foreign-authority evidence.
- [x] R1.3: Record review disposition and current pin in the authoritative status ledger; do not treat seeded activation as a public setup proof.

Reconciled September 20: the frozen patch is superseded by the accepted candidate-local rollback correction and current release-58 pin recorded in the authoritative ledger. Six current-byte manual native groups plus the public list/read/cancel handler test passed uncached. This is controlled component evidence, not live deployment proof.

### R2: Make evidence export publicly configurable and runnable

Original coverage: M7A-23. Lane: L1. Depends on: R1.

- [x] R2.1: Connect definition validation/activation, action controls and catalog availability to exact installed authority plus configured runtime readiness.
- [x] R2.2: Wire the existing planner, action and export/storage workers through production composition; refuse missing/degraded runtime without fabricated success.
- [x] R2.3: Create/activate/run the definition via product APIs and retain original run/approval/export/download receipts; no owner-seeded run or plan.

Reconciled September 20: newer release-58 public-created definition, activation, planner, approval, export, native download, restart, storage, and cleanup evidence supersedes this checklist. External provider and deployment gates remain open and are not implied by these checks.

### R3: Complete ordered multi-step execution

Original coverage: M7A-03, M7A-49. Lane: L1. Depends on: verified existing contracts; no other supplemental packet.

- [x] R3.1: Define the ordered typed step/persisted dependency contract against the existing plan schema; audit the single-step guard at services/platform/agentsec-worker/security_agent_runtime.go and SQL maximum_steps restrictions. See `docs/internal/2026-09-20-security-agent-ordered-multistep-design.md`; independent review corrections are incorporated.
- [ ] R3.2: Implement sequential dependent-step dispatch with per-step deterministic authorization, approval floors, budget accounting and idempotent restart/cancel behavior; do not simply remove length guards.
- [ ] R3.3: Prove a real multi-action plan: dependent step waits for predecessor evidence, a failed/stopped predecessor blocks downstream execution, and restart does not duplicate either action.

### R4: Prove the full authenticated Security Agent user journey

Original coverage: M7A-96, M7A-100, M8-60, M8-61. Lane: L5. Candidate integration depends on: R2, R3, M7A-21.verify, M7A-22.verify, M7A-24.verify. Preparation can start now. Live acceptance additionally requires the authorized deployment/provider inputs from EXT-cloud-deploy, EXT-live-aws and EXT-live-fargate. Original task acceptance dependencies remain unchanged.

- [ ] R4.1: Prepare browser identities and two isolated Organizations on the exact candidate; create definitions and approvals through actual APIs.
- [ ] R4.2: Run automatic trigger and manual invocation through planner/approval/actions/verification/TTL cleanup/retest and native evidence download, with restart and lost responses.
- [ ] R4.3: Record no-foreign-data/current-membership denials and the same SaaS/single-tenant API behavior; retain separate controlled and live-provider evidence.

### R5: Prove automatic discovery/sync and tenant isolation together

Original coverage: M3-52, M8-51a, M8-59, M8-60. Lane: L2. Depends on: verified existing contracts; no other supplemental packet.

R5 preparation and controlled fixture checks can start independently. R5.2 and live R5.3 require EXT-cloud-deploy and EXT-live-aws plus the specifically authorized connector credentials. This is a runtime-input gate, not a requirement to finish every task assigned to those external owners first.

- [ ] R5.1: Prepare two-Organization connector inventories and scoped enrollment; distinguish initial scan, incremental updates, disconnect and stale-source state.
- [ ] R5.2: Connect real authorized release providers and observe automatic discovery followed by a source change and resync; confirm canonical IDs, freshness and no tenant collision.
- [ ] R5.3: Run the browser inventory/path flow and cross-tenant API/Neon/graph/search/S3/queue negatives on the same candidate, with bounded cleanup.

## Owner queues

- T11-identity-admin: 7 tasks, lane L3. [M0-02](tasks.md#m0-02), [M0-03](tasks.md#m0-03), [M2-33](tasks.md#m2-33), [M2-41](tasks.md#m2-41), [M2-42](tasks.md#m2-42), [M2-47](tasks.md#m2-47), [M7-36](tasks.md#m7-36).
- T04-discovery-worker: 14 tasks, lane L2. [M0-06](tasks.md#m0-06), [M0-07](tasks.md#m0-07), [M0-08](tasks.md#m0-08), [M0-10](tasks.md#m0-10), [M1-01b](tasks.md#m1-01b), [M1-30a](tasks.md#m1-30a), [M1-30b](tasks.md#m1-30b), [M1-30c](tasks.md#m1-30c), [M1-30d](tasks.md#m1-30d), [M1-30](tasks.md#m1-30), [M1-31](tasks.md#m1-31), [M1-33](tasks.md#m1-33), [M1-34](tasks.md#m1-34), [M1-36e](tasks.md#m1-36e).
- EXT-live-aws: 2 tasks, lane L6. [M0-09](tasks.md#m0-09), [M3-14](tasks.md#m3-14).
- T03-launch-connectors: 7 tasks, lane L2. [M0-11](tasks.md#m0-11), [M0-14a](tasks.md#m0-14a), [M0-14b](tasks.md#m0-14b), [M0-14c](tasks.md#m0-14c), [M0-14](tasks.md#m0-14), [M0-15](tasks.md#m0-15), [M8-41](tasks.md#m8-41).
- T12-red-team: 1 tasks, lane L2. [M0-16](tasks.md#m0-16).
- EXT-live-fargate: 2 tasks, lane L6. [M0-18](tasks.md#m0-18), [M0-19](tasks.md#m0-19).
- T14-data-workflows: 41 tasks, lane L3. [M0-20](tasks.md#m0-20), [M0-21](tasks.md#m0-21), [M0-22](tasks.md#m0-22), [M7-08](tasks.md#m7-08), [M7-09](tasks.md#m7-09), [M7-10](tasks.md#m7-10), [M7-11](tasks.md#m7-11), [M7-12](tasks.md#m7-12), [M7-13](tasks.md#m7-13), [M7-14](tasks.md#m7-14), [M7-15a](tasks.md#m7-15a), [M7-15b](tasks.md#m7-15b), [M7-15d](tasks.md#m7-15d), [M7-15](tasks.md#m7-15), [M7-19](tasks.md#m7-19), [M7-22](tasks.md#m7-22), [M7-22a](tasks.md#m7-22a), [M7-23](tasks.md#m7-23), [M7-24](tasks.md#m7-24), [M7-25](tasks.md#m7-25), [M7-26a](tasks.md#m7-26a), [M7-26b](tasks.md#m7-26b), [M7-26c](tasks.md#m7-26c), [M7-26](tasks.md#m7-26), [M7-27](tasks.md#m7-27), [M7-28](tasks.md#m7-28), [M7-39a](tasks.md#m7-39a), [M7-39b](tasks.md#m7-39b), [M7-39c](tasks.md#m7-39c), [M7-39d](tasks.md#m7-39d), [M7-39e](tasks.md#m7-39e), [M7-39](tasks.md#m7-39), [M7-40e](tasks.md#m7-40e), [M7-40](tasks.md#m7-40), [M8-42a](tasks.md#m8-42a), [M8-42b](tasks.md#m8-42b), [M8-42c](tasks.md#m8-42c), [M8-42d](tasks.md#m8-42d), [M8-42e](tasks.md#m8-42e), [M8-42f](tasks.md#m8-42f), [M8-42](tasks.md#m8-42).
- T07-security-agent-authority: 2 tasks, lane L1. [M0-21a](tasks.md#m0-21a), [M7A-49](tasks.md#m7a-49).
- T10-product-ui: 7 tasks, lane L3. [M1-01c](tasks.md#m1-01c), [M7A-84](tasks.md#m7a-84), [M7A-86](tasks.md#m7a-86), [M7A-87](tasks.md#m7a-87), [M7A-88](tasks.md#m7a-88), [M7A-89](tasks.md#m7a-89), [M7A-90](tasks.md#m7a-90).
- T15-deployment: 18 tasks, lane L4. [M1A-01](tasks.md#m1a-01), [M1A-02](tasks.md#m1a-02), [M1A-03](tasks.md#m1a-03), [M1A-04](tasks.md#m1a-04), [M1A-05](tasks.md#m1a-05), [M1A-06](tasks.md#m1a-06), [M8-01a](tasks.md#m8-01a), [M8-01b](tasks.md#m8-01b), [M8-01c](tasks.md#m8-01c), [M8-01](tasks.md#m8-01), [M8-02](tasks.md#m8-02), [M8-03](tasks.md#m8-03), [M8-04](tasks.md#m8-04), [M8-05](tasks.md#m8-05), [M8-06](tasks.md#m8-06), [M8-07](tasks.md#m8-07), [M8-47](tasks.md#m8-47), [M8-56](tasks.md#m8-56).
- EXT-cloud-deploy: 42 tasks, lane L6. [M1A-07](tasks.md#m1a-07), [M1A-08](tasks.md#m1a-08), [M1A-09](tasks.md#m1a-09), [M1A-10](tasks.md#m1a-10), [M8-25](tasks.md#m8-25), [M8-26](tasks.md#m8-26), [M8-27](tasks.md#m8-27), [M8-28](tasks.md#m8-28), [M8-29](tasks.md#m8-29), [M8-30](tasks.md#m8-30), [M8-31](tasks.md#m8-31), [M8-32](tasks.md#m8-32), [M8-33](tasks.md#m8-33), [M8-34](tasks.md#m8-34), [M8-35](tasks.md#m8-35), [M8-36b](tasks.md#m8-36b), [M8-36](tasks.md#m8-36), [M8-37](tasks.md#m8-37), [M8-38b](tasks.md#m8-38b), [M8-38](tasks.md#m8-38), [M8-39](tasks.md#m8-39), [M8-51a](tasks.md#m8-51a), [M8-51b](tasks.md#m8-51b), [M8-51c](tasks.md#m8-51c), [M8-51d](tasks.md#m8-51d), [M8-51e](tasks.md#m8-51e), [M8-51](tasks.md#m8-51), [M8-58b](tasks.md#m8-58b), [M8-58](tasks.md#m8-58), [M8-59b](tasks.md#m8-59b), [M8-59](tasks.md#m8-59), [M8-60b](tasks.md#m8-60b), [M8-60](tasks.md#m8-60), [M8-61a](tasks.md#m8-61a), [M8-61](tasks.md#m8-61), [M8-63a](tasks.md#m8-63a), [M8-63b](tasks.md#m8-63b), [M8-63c](tasks.md#m8-63c), [M8-63d](tasks.md#m8-63d), [M8-63e](tasks.md#m8-63e), [M8-63](tasks.md#m8-63), [M8-54](tasks.md#m8-54).
- EXT-human-observation: 13 tasks, lane L6. [M3-52](tasks.md#m3-52), [M8-52a](tasks.md#m8-52a), [M8-52b](tasks.md#m8-52b), [M8-52c](tasks.md#m8-52c), [M8-52d](tasks.md#m8-52d), [M8-52](tasks.md#m8-52), [M8-53](tasks.md#m8-53), [M8-62a](tasks.md#m8-62a), [M8-62b](tasks.md#m8-62b), [M8-62c](tasks.md#m8-62c), [M8-62d](tasks.md#m8-62d), [M8-62e](tasks.md#m8-62e), [M8-62](tasks.md#m8-62).
- T08-supervised-agent: 4 tasks, lane L1. [M7A-21](tasks.md#m7a-21), [M7A-22](tasks.md#m7a-22), [M7A-23](tasks.md#m7a-23), [M7A-24](tasks.md#m7a-24).
- T09-agent-actions: 5 tasks, lane L5. [M7A-94](tasks.md#m7a-94), [M7A-95](tasks.md#m7a-95), [M7A-96](tasks.md#m7a-96), [M7A-100](tasks.md#m7a-100), [M7A-101](tasks.md#m7a-101).
- T16-recovery-ops: 35 tasks, lane L5. [M8-16](tasks.md#m8-16), [M8-17a](tasks.md#m8-17a), [M8-17b](tasks.md#m8-17b), [M8-17c](tasks.md#m8-17c), [M8-17d](tasks.md#m8-17d), [M8-17e](tasks.md#m8-17e), [M8-17](tasks.md#m8-17), [M8-18](tasks.md#m8-18), [M8-19](tasks.md#m8-19), [M8-22a](tasks.md#m8-22a), [M8-22b](tasks.md#m8-22b), [M8-22c](tasks.md#m8-22c), [M8-22d](tasks.md#m8-22d), [M8-22](tasks.md#m8-22), [M8-23a](tasks.md#m8-23a), [M8-23b](tasks.md#m8-23b), [M8-23c](tasks.md#m8-23c), [M8-23d](tasks.md#m8-23d), [M8-23](tasks.md#m8-23), [M8-24](tasks.md#m8-24), [M8-36a](tasks.md#m8-36a), [M8-36c](tasks.md#m8-36c), [M8-38a](tasks.md#m8-38a), [M8-38c](tasks.md#m8-38c), [M8-40a](tasks.md#m8-40a), [M8-40b](tasks.md#m8-40b), [M8-40c](tasks.md#m8-40c), [M8-40d](tasks.md#m8-40d), [M8-40](tasks.md#m8-40), [M8-58a](tasks.md#m8-58a), [M8-59a1](tasks.md#m8-59a1), [M8-59a2](tasks.md#m8-59a2), [M8-59a3](tasks.md#m8-59a3), [M8-59a](tasks.md#m8-59a), [M8-60a](tasks.md#m8-60a).
- EXT-image-attestation: 2 tasks, lane L4. [M8-45](tasks.md#m8-45), [M8-46](tasks.md#m8-46).

## Snapshot validation

Post-audit disposition: approved as a coordination/dependency plan, with per-packet DISPATCH-GATE required before implementation. See [audit and corrections](audit.md). This is a self-review; no side-conversation subagents were used.

The plan was checked against the original plan and current availability TSV for exact202-row coverage, original dependency/deliverable/verification equality, known references, unique subtask IDs and acyclic original dependencies. The nearest-pending prerequisites traverse historical rows; they are not just immediate neighbors.

Source hashes:
- `docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md`: `2eea10a4f38be2bd76f4c1e734a2dae3d47e340fc36be42946d0762786afb102`.
- `docs/internal/implementation_production_availability_v1.5.tsv`: `f57b0924e11880abcd60ff016f1e90ae54511254fbb978320f801122f45e3209`.

If either source changes, reconcile the affected cards before dispatch. Source/pin changes invalidate only evidence that depends on them; they do not justify repeating all728 tasks. No status ledger, product source, branch, index or git commit was changed by this planning task.
