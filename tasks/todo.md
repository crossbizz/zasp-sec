# Parity with Akto and Noma, agentless (2026-11-14)

## Request
Make Zasp better than, or at minimum equivalent to, Akto and Noma. Everything agentless. Connectors on Nango. Employee endpoints out of scope.

Plan and detail: `docs/superpowers/plans/2026-11-14-parity-with-akto-and-noma.md`. Task IDs below are the plan's.

## Decisions
- [x] Agentless throughout; node sensor and inline gateway are optional add-ons, not on the parity path
- [x] Build the cloud-log runtime signal (VPC Flow Logs with Route 53 Resolver query logs)
- [x] Nango for SaaS connectors (Elastic License 2.0; auth and proxy only; already deployed). First-party connectors stay first-party
- [ ] Counsel confirms the Nango license for customer-hosted installs
- [ ] Confirm Nango's free self-hosted feature set against its documentation

## State on 2026-11-14 after the first implementation pass
Built and pushed: A1, A4, C1, C2 (a, b, d and the join), G1, and parts of A5, A7 and C2c. Everything else below is not started. What was built ran against fakes only: no AWS account, no CloudTrail, no real log group. The three agent checks reach the Findings page through the existing discovery finding channel, so no schema change or baseline rebuild was needed.

Why the rest is not done in this pass, from reading the code:
- B1 (generic `saas` provider) touches about forty switches and SQL constraints and needs a baseline rebuild; B2 to B5 and D1 to D4 depend on it or on new tables.
- E1 (a Security Agent action per provider control) is 12 to 20 files per action: metadata, validation, readiness file, SQL key arrays, API and worker executors.
- F1 and F2: red team has exactly one prompt per category, pinned in Go, SQL and OpenAPI; a probe library is a redesign of that shape, not an import.
- A2 (a page per framework) means changing the compliance SQL function, validators, OpenAPI pattern and UI together; the per-finding references of A1 do not need it.
- A6 needs a last-activity field on the inventory summary (SQL).
- I1, H1, I2, I3 need real systems or accounts.

## Step 1: proof
- [ ] I1 Golden path in production (launch plan steps 0 to 10)
- [ ] H1 One Security Agent run end to end: plan, approval, action, containment, re-test

## Step 2: agentless parity floor
- [x] A1 AI compliance mapping (`services/platform/compliancemap`): every posture rule and agent check maps to OWASP LLM and Agentic Top 10, MITRE ATLAS, NIST AI RMF, ISO 42001 and EU AI Act controls; shown on each finding. The control identifiers are from memory and need a compliance review before they are quoted to a customer
- [ ] A2 Compliance page and export per framework (API, then UI)
- [ ] A3 Agent credential inventory
- [x] A4 Dormant credential finding: an agent whose execution role was not used for 90 days (`agent_role_unused_90_days`, AWS)
- [ ] A5 Over-privileged agent findings. Built: execution role with administrator access (`agent_role_administrator_access`). Not built: granted actions against actions actually used
- [ ] A6 Inactive agent state and filter
- [ ] A7 Guardrail posture findings. Built: Bedrock agent with no guardrail (`agent_guardrail_missing`). Not built: Copilot Studio and Agentforce
- [x] C1 CloudTrail reader: roles that invoked a model in the last seven days become inferred agents (`invoke:bedrock_model`); a function gains the signal of its role. Agent invocations are data events and are not read
- [x] C2a Flow log and resolver log source discovery, with a coverage line on the integration when a log or a permission is missing. CloudWatch Logs destinations only; S3 and Firehose are reported as not delivered
- [x] C2b Bounded log reader (two Logs Insights queries per region, last 24 hours, 1,000 rows) that keeps catalog tokens only
- [ ] C2c Attribution. Built: EC2 instances (the resolver log names the instance). Not built: ECS tasks, Lambda functions, and pods on EKS, which are attributed to their node
- [x] C2d Read policy additions (local stack fixture and runbook)
- [x] C2 Inferred agents from the cloud-log join, end to end against fakes: worker read, agents page, typed snapshot. Not run against AWS; LocalStack does not serve Logs Insights for these logs

## Step 3: connectors and MCP governance
- [ ] B1 Generic `saas` provider and kinds (one baseline rebuild)
- [ ] B2 Collector over the Nango proxy
- [ ] B3 Platform definition format, documented
- [ ] B4 Catalog and setup flow read platform definitions
- [ ] Gate: the second platform took under two days
- [ ] B5 Databricks
- [ ] B5 ServiceNow
- [ ] B5 Google Workspace
- [ ] B5 Slack
- [ ] B5 OpenAI organization
- [ ] B5 Anthropic organization
- [ ] B5 GitLab
- [ ] B5 Atlassian
- [ ] D1 MCP servers as inventory objects
- [ ] D2 MCP tool inventory with risk flags
- [ ] D3 MCP registry: approved, unapproved, blocked
- [ ] D4 MCP posture checks

## Step 4: enforcement, red team, supply chain, lead
- [ ] E1 Agentless enforcement through Security Agent actions on provider-native controls
- [ ] E2 Guardrail decision API for the customer's own gateway
- [ ] F1 Probe packs from Garak and Promptfoo
- [ ] F2 Agentic probe categories
- [ ] F3 Continuous re-test
- [x] G1 AI bill of materials: CycloneDX 1.6 download on an agent's detail, built in the browser from its discovery signals. No versions (discovery does not record them)
- [ ] G2 Skills and plugins inventory
- [ ] H2 Attack paths through agents
- [ ] H3 Remediation action on each new finding type
- [ ] H4 Evidence pack export

## Step 5
- [ ] C3 Azure AI Foundry and Azure OpenAI through the Microsoft connection
- [ ] F4 Attack Lab as a supported workflow
- [ ] I3 AWS Marketplace listing
- [ ] I4 Public documentation

## On request only
- [ ] C4 Google Cloud provider
- [ ] D5 MCP gateway (inline add-on)
- [ ] E3 Inline guardrails on the runtime gateway (add-on)

---

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
