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

## State on 2026-11-14 after the second implementation pass
Every build task below is implemented, merged and covered by tests. What "tested" means here: Go and web unit tests, end-to-end collector tests to a typed snapshot against fakes, and PostgreSQL 18 tests of every SQL section, several of them on a really installed baseline. Nothing has run against a real AWS account, a real SaaS provider, a real Nango, real S3, OpenFGA, Helm or Terraform. Provider API shapes written from memory are marked `UNVERIFIED` in the code. The open items are the ones that need real systems, accounts or people, and three sub-items for which no provider API is known.

## Step 1: proof (needs real systems)
- [ ] I1 Golden path in production (launch plan steps 0 to 10). Needs the production environment; also the Neon database must be reinstalled from the new baseline
- [ ] H1 One Security Agent run end to end: plan, approval, action, containment, re-test. Needs planner credits. The remediation path (request from a finding, approval, worker dispatch and finish) is proven on an installed baseline with the real handlers, without a planner call

## Step 2: agentless parity floor
- [x] A1 AI compliance mapping on every finding (`services/platform/compliancemap`). Control identifiers are from memory and need a check against the published frameworks
- [x] A2 Compliance page and export per framework: six AI frameworks beside SOC 2 and HIPAA; controls list their findings; export jobs run on the installed baseline (object store faked in the test)
- [x] A3 Agent credential inventory: the identities and credentials an agent uses, named and linked on the agent detail
- [x] A4 Dormant credential finding (`agent_role_unused_90_days`, AWS)
- [x] A5 Over-privileged agent findings: administrator access, and granted AI actions against the actions CloudTrail shows used (`agent_role_unused_ai_permissions`), with an access panel on the agent (`GET /agents/{id}/access`). "Unused" is asserted only for actions CloudTrail lookup can show
- [x] A6 Inactive agent state and filter; AWS agents carry the time CloudTrail last showed their role invoking a model
- [x] A7 Guardrail posture findings: Bedrock agent with no guardrail; Copilot Studio agent at the lowest content moderation level. Agentforce: open, no per-agent API field is known
- [x] C1 CloudTrail reader
- [x] C2a to C2d Cloud-log runtime signal (flow logs with resolver query logs)
- [x] C2c Attribution to EC2 instances, ECS services, VPC Lambda functions (when exactly one function matches) and EKS clusters. Pods are named by cluster only: AWS logs carry no pod name

## Step 3: connectors and MCP governance
- [x] B1 Generic `saas` provider and kinds
- [x] B2 Collector over the Nango proxy (`connectors/saasdiscovery`), with per-tenant hosts validated against the platform's pattern and public addresses only
- [x] B3 Platform definition format (`docs/operations/saas-connectors.md`)
- [x] B4 Catalog and setup flow read platform definitions; sign-in from the Integrations page for Slack, ServiceNow, Google Workspace and GitLab (the others use a key held in Nango or the reference form)
- [x] Gate: the second platform took minutes, not days
- [x] B5 Databricks, ServiceNow, Google Workspace, Slack, OpenAI organization, Anthropic organization, GitLab, Atlassian. Not listed because no list API is known: OpenAI assistants, Rovo agents, GitLab Duo agents
- [x] D1 MCP servers as inventory objects: AgentCore gateways and targets, repository MCP config files and desktop-extension manifests, Kubernetes workloads, remote hosts in AWS egress logs (`GET /mcp-servers`). Kubernetes MCP servers are not linked to agents: the collector lists no Services and reads no env values
- [x] D2 MCP tool inventory with risk class (read, write, execute, network)
- [x] D3 MCP registry: approved, unapproved, blocked (`/mcp-registry`, web panel)
- [x] D4 MCP posture checks: five findings, each linked to its attack path

## Step 4: enforcement, red team, supply chain, lead
- [x] E1 Agentless enforcement: Security Agent actions `attach_bedrock_guardrail` and `detach_role_administrator_policy` through a separate remediation role per integration; role setting on the AWS integration page; chart and Terraform off by default
- [x] E2 Guardrail decision API (`POST /api/v1/guardrails/decisions`) with its own token permission, a Guardrails page for the policy, and a gateway guide (LiteLLM example not run)
- [x] F1 Probe library: 1,080 probes in nine categories, written for this product (nothing copied from Garak or Promptfoo); a run executes a deterministic sample per category
- [x] F2 Agentic probe categories: indirect injection, poisoned resource, cross-agent delegation
- [x] F3 Continuous re-test: schedule per test, by cadence or on target change, non-production rule unchanged
- [x] G1 AI bill of materials
- [x] G2 Skills inventory (path and kind only) and two findings that read no contents: a skill that ships scripts in a project with production access, and a skill with no code owner
- [x] H2 Attack paths through agents: agent to MCP server to tool, agent to role to data store
- [x] H3 Remediation offered on the finding, starting a supervised Security Agent run
- [x] H4 Evidence pack per agent: download on demand, and a retained pack as an export job. The retained pack omits Security Agent runs owned by the Temporal executor and says so

## Step 5
- [x] C3 Azure OpenAI and AI Foundry accounts and deployments through the Microsoft connection, off by default (needs Reader on the subscriptions). Foundry agents: open, the data-plane API shape is not known with confidence
- [ ] F4 Attack Lab as a supported workflow on real AWS (needs an AWS account)
- [ ] I2 Runs against real providers for every collector and platform definition
- [ ] I3 AWS Marketplace listing
- [ ] I4 Public documentation

## On request only (not agentless)
- [ ] C4 Google Cloud provider
- [ ] D5 MCP gateway (inline add-on)
- [ ] E3 Inline guardrails on the runtime gateway (add-on)

## Found while building, not fixed
- [ ] The browser OAuth flow for GitHub, Okta and Slack appears to be refused under current authorization (read from code, not confirmed by running)
- [ ] Deleting a saas integration does not delete the Nango connection its sign-in created
- [ ] API Access creates tokens that expire after 24 hours; a gateway token for the decision API needs a longer expiry through the API

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
