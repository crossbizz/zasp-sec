# Task 6 Runtime Data Plane Closure Plan

**Goal:** Close every remaining `T06-runtime-data-plane` component-only row without changing the original product scope.

## 1. Prove the shipped private ingest boundary

Add a real-PostgreSQL test that sends an authenticated HTTP runtime batch through `runtimeevent.ProductionIngestHandler`, stores the canonical artifact through an injected versioned artifact authority, and proves the `202` response is emitted only after one durable batch, five stage rows, and one transactional runtime outbox row exist. Replay the identical request and prove the same batch/outbox authority is reused. Promote only `M1-01f` and `M3-42` after focused race, migration, release, and ledger gates pass.

## 2. Persist runtime correlation and projected risk state

Add a forward migration with tenant-scoped, generation-fenced correlation and runtime-risk projection tables. Extend the correlation and projection stage executors so a stage succeeds only after exact durable apply/replay. Preserve source isolation, complete-empty replacement, stale-generation rejection, immutable evidence locators, and rollback authority. Prove crash/replay and cross-tenant behavior with real PostgreSQL before promoting `M3-43d` and `M3-43`.

## 3. Mount policy simulation and decision history

Compose `simulatePolicy` and `listPolicyDecisions` in the public API using the existing strict policy engine and a bounded production OpenSearch reader. Add scope, permission, pagination, timeout, malformed-response, and replay tests. Connect the generated-client UI and promote `M6-13`, `M6-16`, and `M6-17` only after installed-browser proof.

## 4. Complete runtime gateway HTTP/MCP enforcement

Mount bounded HTTP and MCP evaluation routes in the production gateway. Normalize exact action context, return stable block responses, publish metadata-only monitor evidence, and retain signed offline policy behavior. Add malformed transport, replay, expiry, restart, and cross-tenant tests before promoting `M6-19` through `M6-23` and `M8-43`.

## 5. Run the complete Task 6 gate

Run the production-composed ingest-to-archive/index/correlation/projection/ACK-last journey, policy create/simulate/monitor/enforce/retest chain, cached-outage proof, release rendering, OpenAPI drift, browser journey, race/vet, security scan, and the 728-row ledger validator. Promote `M3-52c`, `M6-30`, `M6-31a` through `M6-31d`, and `M6-31` only when their exact assertions pass. Keep managed AWS/OpenSearch/Kubernetes calls explicitly external until credentials and a deployment target are available.
