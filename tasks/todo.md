# Automatic agent discovery (2026-11-14)

## Request
The PRD's jobs 1 and 2 (discover agents without instrumenting every application; find shadow or unmanaged agents) were not implemented: only a Kubernetes Deployment labelled `zasp.ai/entity-kind: agent` became an agent. Build discovery the way Akto and Noma do it for homegrown and SaaS agents. Employee endpoints are a separate effort.

Plan and detail: `docs/superpowers/plans/2026-11-14-automatic-agent-discovery.md`.

## Done
- [x] Signal catalog and matchers (`services/platform/agentsignals`)
- [x] Seven inventory kinds in the provider schema, rule catalog, search allow-list and SQL
- [x] AWS: Bedrock agents, AgentCore runtimes and gateways, Lambda functions that call a model; missing permissions and absent services do not fail a sync
- [x] Kubernetes: unlabelled agent workloads inferred from images, environment variable names, commands and ports; opt-out label
- [x] SaaS agents through Okta: AI applications connected to the tenant
- [x] GitHub: repositories that hold an agent manifest or an agent framework
- [x] Inventory summary says provider, source kind, how the object was found and whether an agent is unmanaged (SQL, API, OpenAPI, web client)
- [x] Agents page: Source, Found by and Status columns, Unmanaged filter, "How it was found" in the detail
- [x] Baseline artifact rebuilt; `generate.sh` runs without Docker
- [x] Customer AWS read policy and runbook

## In progress (second pass, 2026-11-14)
- [x] Provider groundwork: `microsoft` and `salesforce` in the collection contract, kinds, rule catalog, search allow-list
- [x] Provider plumbing: credentials, connector catalog, worker registration, SQL constraints, OpenAPI and web enums, deployment egress (both providers off by default; Helm and Terraform not rendered here)
- [x] Microsoft collector: Entra agent identities, AI enterprise applications, Copilot Studio agents (tested with fake Graph and Dataverse; API shapes unverified)
- [x] Salesforce collector: Agentforce agents (tested with a fake org; object names unverified)
- [x] Show AI service permission gaps on the integration detail
- [x] Dismiss a false positive ("Not an agent" in the ownership form; dismissed agents raise no posture findings)
- [x] Unknown `agent_id` on telemetry: closed without building. The pipeline only accepts ids the product issued, so telemetry cannot name an agent the product does not already know
- [x] Every collector runs a whole collection to a stored snapshot in a test. This found that Okta, GitHub, Salesforce and the AWS agents page failed at that step (Okta and GitHub since before this work); fixed
- [x] Baseline artifact rebuilt (43 rule rows; installs on a fresh PostgreSQL 18.3 as a non-superuser)
- [x] All suites compared against the code before this work: the same 77 Go tests and 2 web tests fail as before, none new; release and staging gates fail the same tests as before

## Third pass (2026-11-14): runtime discovery from network traffic
- [x] Egress catalog: model APIs, Bedrock and AgentCore data planes, remote MCP servers, agent tooling (`agentsignals/egress.go`)
- [x] Sensor role `egress-discovery`: DNS answers captured on the node, joined to Tetragon `tcp_connect` events by pod address and answer address
- [x] Per-node ConfigMap with catalog tokens per workload; names outside the catalog never leave the node
- [x] Kubernetes collector reads the observations; `egress:<token>` counts in agent inference; a missing permission or a bad document never fails a sync
- [x] Opt-in DaemonSet and RBAC in the customer-edge chart (`sensorAgent.egressDiscovery.enabled`)
- [x] Agents page explains a runtime signal in "How it was found"
- [x] Runbook step 15, plan updated
- [x] Checks: the Go packages this pass touches pass (sensor agent has one failure that predates it, `TestLineageSocketLinuxPeerUIDMismatch`); web suite fails the same 2 tests as before; the four deploy gate files fail the same 32 tests as before. The full platform Go suite was not rerun: nothing outside `agentsignals`, the Kubernetes collector and one worker test changed
- [x] Integration detail says when the collector may not read the observations (cluster entity records it; coverage gap `runtime-observations`; real-PostgreSQL test)
- [x] Measurement kit for the first cluster: `deploy/local/egress-discovery/smoke.yaml` and `report.sh --check-smoke` (run against a stand-in `kubectl` only)
- [x] Baseline artifact rebuilt for the coverage gap change (147 readiness predicates and 13,998 structural facts agree; the baseline package tests pass on PostgreSQL 18.3)
- [ ] Run it on one real cluster with the kit and measure what the egress signal adds and what it gets wrong (needs a cluster)

Decided not to build now: ClickHouse, Hubble, Pixie. Deferred until a cluster is available: a narrow TLS probe for tool-level visibility. Deferred until a customer asks: Okta grants (needs re-authorization), other platforms.

## Not buildable here
- [ ] Run each collector against a real AWS account, cluster, GitHub organization, Okta tenant, Entra tenant and Salesforce org; measure false positives and misses per signal class (needs those systems)
- [ ] Reinstall the Neon databases with the new baseline artifact (needs database access)

## Review
No provider was added: a fifth provider touches about forty switches and SQL constraints, a new kind under an existing provider about twelve. SaaS agents therefore arrive through the identity provider first, and Copilot Studio and Agentforce are separate provider tasks. Nothing ran against a real provider. The confidence numbers (60 to 70% for inferred agents) are judgement until the first item above is done.

---

# ZaspOps — plan review and revision (v2.2 as of 2026-08-12)

## Request
Review `docs/internal` PRD + Technical Implementation Plan. Criteria: MVP without over-engineering; reliable / enterprise-ready / compliance-ready (SOC 2, HIPAA); every task ≤ 10–15 min or rescoped; milestones dependency-correct; all APIs exist for all UI flows.

## Done
- [x] Read PRD and Technical Implementation Plan in full; assess against the six criteria
- [x] Archive v1 plan → `docs/internal/archive/ZaspOps Technical Implementation Plan (v1, archived 2026-08-10).md`
- [x] **v2.0:** descope table with reintroduction triggers (§2), simplified stack, vertical-slice milestones with Gate A read-only alpha, 10–15 min tasks with deps + verify commands (§21), UI ↔ API coverage map (§14), HIPAA as a gated track (§19); fixed v1 dependency bugs (§2.3)
- [x] **v2.1 (Manish):** Nango restored as self-hosted **OSS** scoped to connections/credentials (ZaspOps keeps syncs, provider webhooks, normalization; v1 caveats carried over — direct DB connection, non-rotatable encryption key exception, never evidence-of-record)
- [x] **v2.2 (Manish):** semantic retrieval is **evidence-gated** — MVP-1 ships graph + lexical; labeled eval baseline (M5.21–M5.22) → offline embedding spike, script-only (M5.23) → adoption ADR with thresholds (M5.24: recall@10 +10 pts or ≥30% cut in retrieval-miss failures); conditional R1 package (EmbeddingProvider, pgvector HNSW, hybrid RRF) builds only on adopt, re-check at N1 entry on defer
- [x] **Artifacts (2026-08-12):** architecture + per-flow diagrams → `docs/internal/ZaspOps MVP Diagrams.md`; coding-agent kickoff prompt → `docs/internal/Agent Kickoff Prompt.md`

## Decisions
- [x] ~~Nango~~ — **Manish:** self-hosted Nango OSS (applied in v2.1)
- [x] ~~Embeddings~~ — **Manish:** only if adding significant value → evidence gate + conditional R1 (applied in v2.2)
- [ ] TypeScript policy package instead of OPA/Rego (same determinism/hash contract; OPA when customers author policy)
- [ ] 3 AWS accounts (prod / staging / log-archive) instead of 4
- [ ] Partner launch framing: read-only production ≈ wk 6–8 (Gate A), write-enabled ≈ wk 10–12 (Gate B)

## Review
PRD untouched (flags in plan §2.4). Plan v2.2 keeps the governance core (RLS tenancy, provenance, deterministic policy, Proof Records, verification, fail-closed writes). Cuts still standing: Step Functions, custom EventBridge bus, OPA/Rego, separate model-gateway service, app-level Redis, edge mTLS CA in MVP-1, Merkle signing, 4th AWS account, PrivateLink, dual test rigs, premature partitioning. Open verification noted in §2.5: confirm the exact Nango OSS feature set against current self-hosting docs at bootstrap (fallback per provider = direct connector).
