# Typed Discovery Inventory Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut every production inventory and home read from generic `zasp_core_payloads` JSON to deterministic, source-owned typed inventory built from exact complete discovery snapshots.

**Architecture:** Immutable migration v14 evolves the v10 PostgreSQL inventory tables into the deterministic current projection while retaining exact source observations and evidence. The existing complete-snapshot transaction remains the sole inventory writer, but v14 replaces its body with provider-aware identity rules, multi-source rebuilding, typed compatibility responses, equivalence validation, and a targeted generic-payload write fence. Typed repository, OpenAPI, and frontend slices switch the public routes only after the v14 compatibility boundary is green.

**Tech Stack:** Go 1.25, PostgreSQL 16 migration SQL and `pgcrypto`, OpenAPI 3.1, TypeScript/React, Vitest, Node 22, Playwright/installed Chrome.

**Spec:** `.superpowers/sdd/2026-08-19-production-auto-discovery-and-response/task-5-brief.md`

## Global Constraints

- Migration identity is immutable version `14`, name `typed_inventory_cutover`, files `0014_typed_inventory_cutover.up.sql` and `.down.sql`; do not edit v10-v13.
- PostgreSQL typed inventory remains product read authority; OpenSearch, Neo4j, and risk are derived views.
- Only exact complete snapshots can advance inventory. Partial, failed, cancelled, malformed, or stale candidates have zero current-inventory mutation.
- Identity authority is keyed by exact scope, provider, source, namespace, and source-native ID; integration remains observation provenance, not canonical identity uniqueness.
- Discovered identity, evidence, confidence, observation time, and freshness must originate from a complete typed snapshot plus a versioned provider rule. Legacy JSON may supply only validated owner, team, and tags.
- Complete empty removes only the selected source. A canonical entity remains current while any other exact source observation is present.
- Cutover requires 100% per-scope/per-operation equivalence and zero targeted generic rows. There is no generic fallback after cutover.
- Session bootstrap and unrelated compatibility payloads remain outside the targeted write fence.
- Public cursors bind exact scope, operation, kind or parent ID, limit, and final key. Page size is `1..100`.
- Public output contains no object-store locator, credential/reference value, token, raw attributes, or provider error body.
- Every task ends with focused RED/GREEN evidence, an independent review gate, and an atomic commit before the next task edits its files.

---

### Task 1: Freeze typed observation and provider identity rules

**Files:**
- Create: `services/platform/inventoryprojection/rules.go`
- Create: `services/platform/inventoryprojection/rules_test.go`
- Modify: `services/platform/connectors/internal/providercollection/client.go`
- Modify: `services/platform/connectors/internal/providercollection/client_test.go`
- Modify: `services/platform/connectors/kubernetesdiscovery/collection_api.go`
- Modify: `services/platform/connectors/kubernetesdiscovery/collection_api_test.go`
- Modify: `services/platform/connectors/collection/contract.go`
- Modify: `services/platform/connectors/collection/contract_test.go`

**Interfaces:**
- Consumes: v13 complete `collection.SnapshotCandidate` entities/evidence and `inventoryprojection.ProjectWithAnnotations`.
- Produces: `inventoryprojection.RuleCatalog() []Rule` and canonical normalized entity observation fields consumed by v14 migration conformance tests.

- [ ] **Step 1: Write failing closed-catalog tests**

  Add tests for this exact rule catalog:

  ```go
  type Rule struct {
      Provider, SourceKind, Namespace string
      ProductKind Kind
      Version, Priority, ConfidenceBasisPoints int
      Freshness time.Duration
  }
  ```

  Exact initial mappings are: AWS account/role/resource/service to `asset`; Kubernetes cluster/namespace/resource to `asset`; Kubernetes workload to `runtime`; Kubernetes agent to `agent`; GitHub installation/organization to `asset` and repository to `tool`; Okta tenant to `asset`, application to `tool`, and group/user to `identity`. Versions are `1`; priorities are AWS `100`, Kubernetes `80`, GitHub `120`, Okta `110`; confidence is AWS `9000`, Kubernetes `9500`, GitHub `9000`, Okta `9500`; freshness is AWS/GitHub/Okta `24h` and Kubernetes `15m`. Prove unique `(provider,source_kind)`, bounded values, cloned results, stable order, and catalog SHA-256.

- [ ] **Step 2: Run the rule tests and witness RED**

  Run: `go test ./inventoryprojection -run 'TestRuleCatalog' -count=1`

  Expected: compile failure because `Rule` and `RuleCatalog` do not exist.

- [ ] **Step 3: Implement the immutable catalog and strict observation envelope**

  Add this canonical normalized entity shape after provider page validation and before `SnapshotCandidate` hashing:

  ```go
  type normalizedEntity struct {
      ID, Kind, SourceNativeID, DisplayName string
      StableFields, Attributes json.RawMessage
      IdentityNamespace string
      IdentityRuleVersion, IdentityPriority int
      ProductKind string
      ConfidenceBasisPoints int
      ObservedAt, FreshUntil string
      EvidenceID string
      SourceProjectionVersion int
  }
  ```

  `providercollection.Client` obtains one canonical UTC `observedAt` from its injected clock, looks up the exact catalog rule, derives `freshUntil`, and binds the deterministic evidence ID already generated for the entity. Provider page JSON remains raw provider evidence and does not contain these projection fields. Add `kubernetes_agent` only when an allowlisted deployment label `zasp.ai/entity-kind=agent` is present; ordinary deployments remain `kubernetes_workload`. Reject unknown rules, noncanonical UTC-Z timestamps, evidence mismatch, or a provider-supplied projection field.

- [ ] **Step 4: Run focused race and static gates**

  Run: `go test -race ./inventoryprojection ./connectors/collection ./connectors/internal/providercollection ./connectors/kubernetesdiscovery -count=1`

  Run: `go vet ./inventoryprojection ./connectors/collection ./connectors/internal/providercollection ./connectors/kubernetesdiscovery`

  Expected: all green; existing AWS/GitHub/Kubernetes/Okta provider fixtures are updated to the canonical envelope.

- [ ] **Step 5: Commit the observation contract**

  ```bash
  git add services/platform/inventoryprojection services/platform/connectors/collection services/platform/connectors/internal/providercollection services/platform/connectors/kubernetesdiscovery
  git commit -m "feat(inventory): bind typed source observations"
  ```

### Task 2: Register immutable v14 and exact readiness

**Files:**
- Create: `services/platform/migrations/sql/0014_typed_inventory_cutover.up.sql`
- Create: `services/platform/migrations/sql/0014_typed_inventory_cutover.down.sql`
- Create: `services/platform/migrations/typed_inventory_cutover_test.go`
- Modify: `services/platform/migrations/migrations.go`
- Modify: `services/platform/agentsec-migrate/main_test.go`

**Interfaces:**
- Consumes: exact v13 checksum/fingerprint/readiness and Task 1 rule-catalog digest.
- Produces: `ProductionTypedInventoryCutover() Metadata`, `ProductionTypedInventoryCutoverSemanticFingerprint() string`, `Runner.UpProductionTypedInventoryCutover`, and `Runner.DownProductionTypedInventoryCutover`.

- [ ] **Step 1: Write migration-chain REDs**

  Add unit tests asserting version `14`, name `typed_inventory_cutover`, embedded nonempty up/down SQL, exact checksum/fingerprint extraction, v13 release guard, registry order, empty/v1/v13-to-v14 reachability, pre-cutover v14-to-v13-to-v14, and refusal to install against a drifted v13 fingerprint.

- [ ] **Step 2: Run the migration REDs**

  Run: `go test ./migrations ./agentsec-migrate -run 'TestProductionTypedInventoryCutover|TestAgentsecMigrateCLIReachesV14' -count=1`

  Expected: compile failure for the missing metadata and runner methods.

- [ ] **Step 3: Add v14 metadata and a fail-closed schema skeleton**

  The up migration must first require exact v13 readiness, take the existing discovery/execution/workflow migration locks, create a single authority role `zasp_inventory_authority` with no login/inherit/admin attributes, and create `zasp_inventory_cutover_state` keyed by exact scope with phases `expanded`, `backfilled`, `equivalent`, `cutover`. The initial readiness function signature is:

  ```sql
  zasp_inventory_readiness(expected_checksum text, expected_fingerprint text)
  RETURNS boolean
  ```

  It must verify the v14 release row, live fingerprint, rule-catalog digest, authority ownership/RLS/policies/ACLs, legal phase order, and exact v13 readiness. Do not report ready merely because objects exist.

- [ ] **Step 4: Implement guarded down behavior**

  Down is legal only before any scope reaches `cutover` and only with the exact live v14 fingerprint/security shape. It removes v14 objects and release metadata atomically and restores exact v13 readiness. A cutover scope returns `ErrInvalidState` with zero mutation.

- [ ] **Step 5: Run migration unit/race gates**

  Run: `go test -race ./migrations ./agentsec-migrate -run 'TestProductionTypedInventoryCutover|TestAgentsecMigrateCLIReachesV14' -count=1`

  Run: `go vet ./migrations ./agentsec-migrate`

- [ ] **Step 6: Commit the immutable registry boundary**

  ```bash
  git add services/platform/migrations services/platform/agentsec-migrate/main_test.go
  git commit -m "feat(migrations): register typed inventory v14"
  ```

### Task 3: Build deterministic typed inventory and atomic cutover

**Files:**
- Modify: `services/platform/migrations/sql/0014_typed_inventory_cutover.up.sql`
- Modify: `services/platform/migrations/sql/0014_typed_inventory_cutover.down.sql`
- Modify: `services/platform/migrations/typed_inventory_cutover_test.go`
- Create: `services/platform/apiserver/inventory_cutover_postgres_test.go`
- Modify: `services/platform/inventoryprojection/projector_test.go`

**Interfaces:**
- Consumes: Task 1 catalog and the unchanged v10 `zasp_discovery_apply_snapshot(...)` signature used by production discovery workers.
- Produces: evolved typed inventory tables, deterministic rebuild functions, typed compatibility reads, targeted write fence, and exact v14 cutover readiness.

- [ ] **Step 1: Write hostile real-PostgreSQL REDs**

  Cover: source-native collision across providers; same provider identity across two integrations; deterministic precedence independent of arrival order; exact replay; stale/same-generation drift; complete empty; A+B then remove A/B; partial/failed no-op; evidence/version/checksum drift; missing rule/evidence/confidence/freshness; annotation-only legacy backfill; malformed/conflicting annotation; legacy inventory without typed snapshot; targeted writer racing cutover; snapshot apply racing equivalence; compatibility read after targeted-row deletion; and cutover down refusal.

- [ ] **Step 2: Run the PostgreSQL RED**

  Run: `go test ./apiserver -run TestProductionTypedInventoryCutoverPostgres -count=1 -v`

  Expected: SQLSTATE `42P01` for the first missing v14 identity table.

- [ ] **Step 3: Evolve the v10 typed tables without creating JSON authority**

  Add normalized tables `zasp_inventory_identity_rules`, `zasp_inventory_identity_bindings`, and `zasp_inventory_annotations`. Add typed projection columns to `zasp_inventory_entities` and exact provider/namespace/generation/digest/evidence/confidence/observed/fresh/rule columns to `zasp_inventory_source_observations`. Add artifact reference/key/version/size/tool/source/generation columns to `zasp_inventory_evidence`. Constraints must preserve exact scope and source/snapshot foreign keys; all authority tables are forced-RLS and owned only by `zasp_inventory_authority`.

- [ ] **Step 4: Replace snapshot apply with deterministic rebuild**

  `CREATE OR REPLACE FUNCTION zasp_discovery_apply_snapshot(...)` keeps the v10 signature. Under the existing `(scope,integration,source)` advisory lock it strictly decodes the Task 1 envelope, validates the exact catalog rule and one evidence row per entity, persists identity bindings, updates only that source, and rebuilds each affected canonical entity using `(priority,integration_id,provider,source,source_native_id)` ordering. It sets aggregate first/last across current observations but copies display/confidence/evidence/observed/fresh/projection version entirely from the winner. Existing risk/graph/search work creation remains exact and unchanged.

- [ ] **Step 5: Backfill only from complete v13 snapshot authority**

  During `expanded -> backfilled`, read each exact v13 last-good `zasp_discovery_snapshot_inputs` plus its normalized projection items. Reconstruct provider rules/evidence and current source observations; preserve existing first-seen values when bound; import only bounded owner/team/tags from targeted legacy payloads into annotations. If any targeted nonempty legacy operation cannot be reproduced from typed last-good inputs, abort the whole migration.

- [ ] **Step 6: Add equivalence, compatibility, deletion, and write fence**

  Canonicalize all targeted old/new operations and store per-scope count/digest in cutover state. Only `equivalent -> cutover` may delete targeted rows. Add a trigger on `zasp_core_payloads` rejecting insert/update/delete of `home`, inventory collection keys, detail keys, and agent subresource keys for a cutover scope while allowing `session_bootstrap:*` and unrelated operations. Replace `zasp_core_read` so targeted operations are generated from typed tables and never consult generic rows; non-targeted reads retain v13 behavior.

- [ ] **Step 7: Run real migration and concurrency gates**

  Run: `go test -race ./migrations ./agentsec-migrate ./apiserver -run 'TestProductionTypedInventoryCutover|TestAgentsecMigrateCLIReachesV14|TestProductionTypedInventoryCutoverPostgres' -count=1`

  Required evidence: fresh v1-to-v14, v13-to-v14, pre-cutover down/re-up, post-cutover down refusal, two-connection apply/equivalence serialization, exact fingerprint drift rejection, and zero targeted generic rows.

- [ ] **Step 8: Commit the database authority**

  ```bash
  git add services/platform/migrations services/platform/apiserver/inventory_cutover_postgres_test.go services/platform/inventoryprojection/projector_test.go
  git commit -m "feat(inventory): cut over typed snapshot authority"
  ```

### Task 4: Replace generic inventory repository and handlers

**Files:**
- Create: `services/platform/apiserver/inventory_repository.go`
- Create: `services/platform/apiserver/inventory_repository_test.go`
- Create: `services/platform/apiserver/inventory_handler.go`
- Create: `services/platform/apiserver/inventory_handler_test.go`
- Modify: `services/platform/apiserver/production.go`
- Modify: `services/platform/apiserver/production_test.go`
- Modify: `services/platform/apiserver/composition.go`
- Modify: `services/platform/apiserver/composition_test.go`
- Modify: `services/platform/apiserver/postgres_database.go`

**Interfaces:**
- Consumes: cutover-ready v14 typed SQL functions.
- Produces: typed `InventoryRepository`, exact cursor-paged handlers for 12 inventory operations, and typed home composition.

- [ ] **Step 1: Write strict repository and handler REDs**

  Cover the interface from the Task 5 brief, 1,002 items over more than ten pages, terminal `has_more=false`, no page-11 query, scope/kind/parent/limit cursor binding, cross-scope IDs, stale source/snapshot bindings, missing evidence/confidence/freshness, UTC-Z enforcement, cancellation, malicious reference/error fields, all public status/error schemas, and exact authorization/capability checks.

- [ ] **Step 2: Run focused REDs**

  Run: `go test ./apiserver -run 'TestInventoryRepository|TestInventoryHandler|TestProductionHandlersUseTypedInventory' -count=1`

  Expected: compile failure because `InventoryRepository` and `inventoryHTTPHandler` do not exist.

- [ ] **Step 3: Implement the typed repository**

  Implement exactly:

  ```go
  type InventoryRepository interface {
      ListInventoryPage(context.Context, domain.Scope, InventoryKind, string, int) (InventoryPage, error)
      GetInventory(context.Context, domain.Scope, domain.ProductID, InventoryKind) (InventoryDetail, error)
      ListAgentCapabilitiesPage(context.Context, domain.Scope, domain.ProductID, string, int) (CapabilityPage, error)
      ListAgentRelationshipsPage(context.Context, domain.Scope, domain.ProductID, string, int) (RelationshipPage, error)
      ListAgentSessionsPage(context.Context, domain.Scope, domain.ProductID, string, int) (SessionPage, error)
      GetHomeSummary(context.Context, domain.Scope) (HomeSummary, error)
  }
  ```

  Each PostgreSQL function is scope-first, keyset ordered, limited to `1..100`, and returns strict typed JSON. Home contains typed current counts and typed risk/path counts; response/search metrics remain explicitly unavailable rather than inferred.

- [ ] **Step 4: Wire only typed production dispatch**

  Replace `coreHTTPHandler` for list/detail agents, tools, identities, runtimes, assets, and agent subresources. Route `getHomeSummary` through the typed repository. Keep bootstrap on its existing repository. Construction requires exact v14 readiness and fails closed on v13 or later unknown versions.

- [ ] **Step 5: Run focused and package gates**

  Run: `go test -race ./apiserver -run 'TestInventory|TestProductionHandlersUseTypedInventory|TestPostgres' -count=1`

  Run: `go vet ./apiserver`

- [ ] **Step 6: Commit backend cutover**

  ```bash
  git add services/platform/apiserver
  git commit -m "feat(api): serve typed discovery inventory"
  ```

### Task 5: Freeze OpenAPI, generated transport, and production UI

**Files:**
- Modify: `openapi/openapi.yaml`
- Modify: `openapi/openapi.test.mjs`
- Modify: `apps/web/api/generated.ts`
- Modify: `apps/web/api/decoders.ts`
- Create: `apps/web/api/inventory-decoders.test.ts`
- Modify: `apps/web/api/client.ts`
- Modify: `apps/web/api/client.test.ts`
- Modify: `apps/web/api/pagination.ts`
- Modify: `apps/web/api/pagination.test.ts`
- Modify: `app/features/agents/AgentSecurityView.tsx`
- Modify: `app/features/agents/ProductionAgentSecurityView.tsx`
- Create: `app/features/agents/ProductionAgentSecurityView.test.tsx`
- Modify: `app/quality/ui-api-map-contract.test.ts`

**Interfaces:**
- Consumes: Task 4 typed backend response shapes.
- Produces: strict public `InventorySummary`, `InventoryDetail`, `InventorySourceObservation`, `InventoryEvidenceReference`, paged subresources, and one production API/view implementation.

- [ ] **Step 1: Write OpenAPI and decoder REDs**

  Add page cursor/limit to every collection and agent subresource route. Tests require maximum 100 items, exact `page_info`, closed kinds/freshness states, integer confidence `0..10000`, canonical timestamps, source/snapshot/evidence binding, no object locator or credential fields, and detail reload by stable ID.

- [ ] **Step 2: Run contract REDs**

  Run: `node --test openapi/openapi.test.mjs openapi/generated-client.test.mjs`

  Run: `npm exec vitest run apps/web/api/inventory-decoders.test.ts`

  Expected: failures for missing typed schemas and cursor parameters.

- [ ] **Step 3: Update OpenAPI and regenerate**

  Split list/detail types exactly as the Task 5 brief specifies. Evidence exposes only opaque evidence ID, checksum, media type, schema/parser/tool versions, collected time, and size. Generate `apps/web/api/generated.ts` with the repository generator and require zero drift.

- [ ] **Step 4: Unify frontend pagination and views**

  Use `loadAllCursorPages` with caps of 100 pages and 10,000 items, repeated-cursor rejection, and abort propagation. Both agent views consume the same typed API factory and strict decoder. Scope changes abort the prior request and evict/ignore the prior scope cache. Preserve existing route/drawer UX and make stable detail URLs reload correctly.

- [ ] **Step 5: Run frontend gates**

  Run: `node --test openapi/openapi.test.mjs openapi/generated-client.test.mjs`

  Run: `npm exec vitest run apps/web/api/inventory-decoders.test.ts apps/web/api/pagination.test.ts app/features/agents/ProductionAgentSecurityView.test.tsx`

  Run: `npm run typecheck && npm run lint && npm run build`

- [ ] **Step 6: Commit the public product surface**

  ```bash
  git add openapi apps/web app/features/agents app/quality/ui-api-map-contract.test.ts
  git commit -m "feat(web): consume typed discovery inventory"
  ```

### Task 6: Prove no-seed sync-to-inventory and promote the ledger

**Files:**
- Modify: `scripts/production-combined-e2e.mjs`
- Modify: `scripts/production-combined-e2e.test.mjs`
- Modify: `docs/internal/implementation_production_availability_v1.5.tsv`
- Modify: `docs/internal/implementation_status_v1.5.md`

**Interfaces:**
- Consumes: complete Task 1-5 production path.
- Produces: installed-browser proof and exact evidence-backed promotion for rows owned by `T05-inventory-cutover`.

- [ ] **Step 1: Write static harness REDs**

  Prohibit inserts of `home`, inventory collection/detail keys, findings, and paths. Require only authentication/bootstrap/admin prerequisites, public connector authorization, public sync request, durable execution/projection wait, typed inventory API assertions, browser reload/deep link, second-source retention, complete-empty removal, failed/partial retention, scope-switch abort, and database forensics.

- [ ] **Step 2: Run the static RED**

  Run: `node --test scripts/production-combined-e2e.test.mjs`

  Expected: failure because the current harness still inserts generic inventory payloads.

- [ ] **Step 3: Replace inventory seeds with deterministic local discovery**

  Start the real worker composition with an injected local deterministic provider and artifact authority. Authorize through the public API, request sync with retained idempotency key, wait for exact job/snapshot/projection receipts, then assert home, agents, tools, identities, runtimes, findings, and paths only through public routes and the installed browser. Database forensics require zero targeted generic rows and exact current source/snapshot/evidence bindings.

- [ ] **Step 4: Run full verification**

  Run: `go test -race ./... -count=1 -timeout=20m` from `services/platform`.

  Run: `npm run verify` with the pinned Node 22 runtime.

  Run: `npm run production:combined-e2e:test`.

  Run: `npm run implementation:status:check`.

  Expected: all green; Chrome, workers, PostgreSQL, and temporary state are fully cleaned.

- [ ] **Step 5: Promote only proven T05 rows**

  Change each `T05-inventory-cutover` row from `component-only` to `production-available` only when the exact public/database/browser assertion proves that row. Keep unsupported capabilities component-only with the missing evidence stated. Update totals mechanically through the ledger checker.

- [ ] **Step 6: Commit and push the completed Task 5 slice**

  ```bash
  git add scripts/production-combined-e2e.mjs scripts/production-combined-e2e.test.mjs docs/internal/implementation_production_availability_v1.5.tsv docs/internal/implementation_status_v1.5.md
  git commit -m "test(inventory): prove typed production cutover"
  git push origin HEAD:main
  ```
