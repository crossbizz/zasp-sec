# Temporal OSS and OpenFGA adoption decision

Date: 2026-09-22. User-authorized architectural change, prepared in the side conversation for execution by the main thread. Status: design and execution handoff only; no product implementation or deployment is claimed.

## Scope and precedence

Adopt self-hosted Temporal OSS for durable orchestration, OpenFGA for product permissions, and retain Stytch for identity. Preserve all 728 original tasks and their product acceptance requirements in `agent_security_platform_Technical_Implementation_Plan_v1.5.md`. This decision supersedes implementation choices that require completing the custom scheduler64/worker63 orchestration before activating the product. It does not supersede multi-tenancy, discovery, sync, security, audit, UI, or deployment requirements.

Execution plan: `2026-09-22-temporal-openfga-execution-plan.md` in this directory. The executor integrates this amendment into the authoritative status ledger without deleting historical evidence or creating a second completion count.

Explicit testing instruction: trust Temporal and OpenFGA implementations. Do not write vendor conformance tests, reproduce their test suites, or prove their scheduler, persistence engine, retry algorithms, graph evaluator, or SDK implementation. TDD applies only to Zasp business logic, adapters, authorization model, and integration. Batch tests and review per deliverable. A few application acceptance flows using real dependencies validate our wiring, not vendor internals.

## Evidence and corrected assumptions

Read-only inspection used worktree `.worktrees/cached-runtime-ship-20260917` at HEAD `8e8358dc`; about 1,020 modified/untracked paths existed. Preserve that work. Source state can advance before execution; refresh the inventory at the start.

1. The user reports development-only use and no in-flight runs. This removes the need to build a live-run migration system. It does not authorize dropping retained evidence or resetting a shared database. Confirm active work and outstanding cleanup before disabling old workers; use fresh disposable databases for development acceptance.
2. `identity/authorization.go` is not the demonstrated production authorization seam. Search found its constructor referenced only in that package's tests. Production authentication and permissions are calculated in `apiserver/repository.go`, enforced in `middleware.go`/`router.go` and SQL mutations, and exposed as capabilities by `production.go`. Wire those paths.
3. Role/permission maps differ between `identity/roles.go` and `apiserver/production.go`. For example the identity package's security-admin role excludes identity management, while the API's displayed role map shares the admin set. Resolve against the original PRD, operation requirements and actual SQL rules. Never copy one map blindly or union permissions.
4. `ReconcileStytchWebhook` currently accepts a specific `scim.member.delete` event. It is not a complete membership synchronization service. Establish which provider events exist and reconcile from authoritative provider reads where required.
5. Removing scheduler files alone leaves Release61 stored procedures and action executors requiring legacy claims. The cutover needs new thin transactional activity operations that preserve domain invariants without the old scheduler token protocol.
6. Line counts are not a deletion estimate. Release61 files contain approvals, budgets, receipts and action safety rules that remain necessary. The previous two-week estimate was unvalidated; use actual packet completion and dependency access to forecast.

## Ownership after cutover

| Responsibility | Owner | Application work retained |
| --- | --- | --- |
| Sign-in, sessions, SSO/SCIM identity | Stytch and existing verified adapter | Principal reconciliation, CSRF, fresh authentication, deprovisioning |
| Resource/role permission evaluation | OpenFGA | Permission model, trusted identity mapping, enforcement, tuple synchronization |
| Row isolation and transactional changes | Product PostgreSQL | RLS, tenant keys, constraints, revisions, narrow mutation privileges |
| Durable execution and schedules | Temporal OSS | Workflow definitions, Activities, timeouts, cancellation and cleanup decisions |
| Runtime security decisions | Existing policy engine/OPA | Risk policy, signed policies, gateway enforcement, approval rules |
| Provider effects and evidence | Existing product executors | Idempotency, reconciliation of ambiguous effects, receipts, signatures, budgets |

OpenFGA does not replace OPA runtime policy, SQL transactions, RLS or quotas. Temporal namespaces/task queues and OpenFGA stores are infrastructure partitions, not proof that a caller owns a product resource.

## Temporal design

Use Go SDK and the official server/chart. Pin compatible stable SDK, API, server, chart and image versions during implementation, with dependency locks and image digests. No speculative version numbers in this design. PostgreSQL stores Temporal persistence and SQL visibility in dedicated databases/roles; the application's PostgreSQL state remains separately owned. Do not deploy the development server as production.

Temporal owns control flow. PostgreSQL owns admission, approvals, durable product receipts, budget reservations, and the API read model. Retain one small transactional outbox for the SQL-to-Temporal boundary: commit admission plus a start command together, deliver with a deterministic workflow ID, and acknowledge after accepted start. Duplicate delivery must identify the same product run and input digest. Never hold a product transaction open across a Temporal RPC. Use the same outbox pattern for approval/cancellation notifications, with durable decision IDs and application-level duplicate handling.

Workflow identity contains canonical organization/workspace/environment/run IDs. Effect identity uses product run + step + action generation, never a Temporal attempt number. Keep that key stable across retries, resets and Continue-As-New when the intended effect is the same. A genuinely new business execution gets a new product identity. Temporal workflow reuse/conflict options must match this contract explicitly.

The initial workflow executes the existing ordered temporary-policy then existing-test flow, including approval, evidence, cancellation, cleanup and terminal product status. Move DB, OpenFGA, providers, signing, filesystem access and model calls into Activities. Workflow code uses SDK deterministic primitives. Workflow arguments and results contain IDs, digests and redacted summaries; secrets and large artifacts stay outside history.

Reuse executors as Activities after extracting them from `package main` where necessary. Thin activity SQL must atomically verify scope, plan/approval version, current admission/revocation fence and budget, then record the stable effect reservation or receipt. Do not retain scheduler64 lease choreography as a hidden second orchestration system. Keep resource-specific serialization or fencing only where concurrent external effects require it. A timed-out Activity can overlap a retry: an idempotency key alone is insufficient when the external provider cannot enforce it. Reconcile ambiguous effects before retry; surface unresolved outcomes honestly.

Cancellation is cooperative. Recheck product authorization before consequential effects; heartbeat long Activities. Cleanup runs under an explicitly retained, narrowly scoped compensation authority even if the initiating user's permission has since been revoked. Use a disconnected workflow context for required cleanup. Product cancellation does not mean an already issued provider effect was undone. Keep cleanup pending until evidence confirms completion. Termination is not the product cancel API.

Discovery uses a stable per-integration Temporal Schedule and a DiscoverySync workflow. Choose overlap, catch-up and manual-trigger behavior to preserve current product requirements. Reuse collectors, cursor checkpoints, reconciliation, and inventory writes. Plan subsequent moves of red-team/test, export and recovery job orchestration; do not replace streaming runtime ingestion or unrelated queues just because Temporal is installed. Maintain a complete consumer inventory so later deletion cannot strand a workflow family.

Tenant budget and concurrency limits remain application invariants. Do not assume a worker concurrency setting supplies a tenant quota or starvation bound. Check the selected OSS release's supported fairness options against the original requirements; add only the minimum admission control needed. Version workflow code for future live histories before launch.

## OpenFGA design

Use an internal service with a pinned store/model ID and authenticated access. Product APIs alone may submit application decisions and tuple updates; browsers and agents never receive store credentials. Retain the current stable product principal IDs as FGA user IDs, with their verified Stytch organization/member mapping. Agents and service principals use distinct FGA types and never get invented Stytch member identities.

Represent organization, workspace, environment and product resource ancestry. Map the six original roles and exact operation permissions, then resource-specific grants and bounded agent delegation. Each object has one product-validated parent in its organization. Organization context comes from the authenticated session and a server-loaded resource, never a request body claiming an organization. Agent decisions combine delegated permission with task/target binding and current product policy.

Stytch owns provider identity and membership facts. Product SQL owns resource hierarchy, workspace/environment grants and desired permission changes. OpenFGA stores their permission projection and evaluates the model. Tuple writes go through OpenFGA APIs, never through direct writes to its database.

Permission synchronization uses durable versioned desired state and an outbox. Serialize application of changes per organization initially. Track a monotonically increasing organization authorization revision and the last fully applied revision for the active model. Pending synchronization fails closed for that organization; grant activation waits for confirmed application. Membership deactivation and token/session revocation take effect in product SQL immediately, independently of FGA availability. Reconciliation must read current desired state instead of blindly replaying stale add/remove events. Provider webhook reordering must never reactivate a deleted membership.

For the first release, perform authorization checks with HIGHER_CONSISTENCY and avoid application positive-result caching. This does not make an unprocessed outbox visible and does not make SQL and OpenFGA one transaction. Before a sensitive SQL mutation commits, verify the organization authorization revision/model generation has not changed since the check, using the same row/lock protocol as permission changes. If changed or pending, reject or retry from the authorization boundary. Do not call OpenFGA inside a DB transaction. Preserve current fresh-auth, PAT permission intersection, tenant scope and target/version checks.

Keep audit evidence of the model and decision used for an approval. A pinned historical model is evidence, not permission to ignore later revocation. Actions must satisfy the current active authorization and product approval policy. Start with a bounded fixture/staging comparison against intended permissions, not an indefinite shadow service or an old/new union of allow results. After cutover, OpenFGA failure never falls back to old allow logic.

Lists, searches, exports, direct object reads, worker effects, PAT paths and UI capability calculation all need enforcement. Filtering a page after SQL pagination can leak counts or break pagination; preserve authorized query semantics and validate returned resources. Keep tenant RLS and narrowly scoped SQL mutation checks as the database backstop.

## Deletion boundary

Retire active scheduler64 and worker63 selectors, lease renewal/recovery loops, Release61 control-flow polling and their obsolete implementation-specific tests only after every caller is moved. Preserve historical migrations already applied to a database and add a retirement migration. Do not rewrite old checksummed migrations or drop audit/effect records to make tests pass. Remove obsolete runtime privileges through the migration, with an explicit dependency inventory.

Replace custom role evaluation in active production paths after permission parity and revision fencing pass. Retain role metadata, source grants, sessions, PAT restrictions, tenant scope, fresh-auth and provider identity code. Keep security and domain assertions from old tests when their old harness is removed.

## Official references checked

These links ground dependency behavior; the architecture above is our application design.

- [Temporal Activities](https://docs.temporal.io/activity-definition): retryable Activities can execute more than once; external-effect idempotency remains application/provider work; arguments and results enter history.
- [Go workflow basics](https://docs.temporal.io/develop/go/workflows/basics): deterministic workflow APIs and Activity boundaries for external I/O.
- [Go cancellation](https://docs.temporal.io/develop/go/workflows/cancellation): heartbeat-based Activity cancellation and cleanup with a disconnected context.
- [Go testing](https://docs.temporal.io/develop/go/best-practices/testing-suite): SDK facilities for testing our workflow code and skipping workflow time.
- [Go Schedules](https://docs.temporal.io/develop/go/workflows/schedules): schedule lifecycle and explicit overlap policy.
- [Go versioning](https://docs.temporal.io/develop/go/workflows/versioning): compatibility of workflow changes with existing histories.
- [Official Temporal Helm chart](https://github.com/temporalio/helm-charts): external persistence configuration and PostgreSQL visibility support.
- [OpenFGA source of truth](https://openfga.dev/docs/best-practices/source-of-truth): identity, hierarchy, filtering and search data can remain in their owning systems.
- [OpenFGA consistency](https://openfga.dev/docs/interacting/consistency): HIGHER_CONSISTENCY bypasses query caches; it is not an application synchronization barrier.
- [Immutable FGA models](https://openfga.dev/docs/getting-started/immutable-models): pin the authorization model ID in requests and deployment configuration.
- [OpenFGA production](https://openfga.dev/docs/best-practices/running-in-production): authenticated TLS access, disabled playground, migrations, dedicated datastore and pool/metrics configuration.

## Acceptance

The change is complete only when the product uses Temporal and OpenFGA through actual API/worker paths, discovery and sync work, the UI is usable with Stytch, tenant boundaries hold, and obsolete active orchestration/permission evaluators have been removed. Local acceptance is component evidence. Production availability still requires the actual deployment and external provider gates required by each original task. No original task becomes complete merely because an OSS service starts.
