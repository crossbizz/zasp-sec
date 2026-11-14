# Parity with Akto and Noma, agentless first (2026-11-14)

## Goal

Make Zasp at least equivalent to Akto and Noma on every capability a buyer compares, and clearly ahead on three: the closed remediation loop, attack paths, and evidence. Employee endpoints stay out of scope.

Two constraints from the owner:

- **Agentless throughout.** Nothing is installed in the customer's environment for discovery, runtime signal, posture, identity, compliance or enforcement. Decided 2026-11-14: the runtime signal comes from the customer's cloud logs (C1, C2), and enforcement comes from provider-native controls applied through the Security Agent (E1). The node sensor and an inline gateway remain in the product as optional add-ons and are not on the path to parity.
- **Nango for connectors.**

The comparison this plan closes is in the 2026-11-14 gap review. Competitor facts in it come from search summaries of vendor pages and reviews; their sites were not reachable from the session that wrote it. Recheck each row before it is used in sales material.

## Connectors: Nango, and where it fits

Nango is already in the stack. The chart deploys it, `services/platform/connectors/nango` holds a connection client and an allow-listed proxy, and one sample provider (Slack) is wired. It is used for sign-in to a provider and for proxying calls with the stored token. It does not run discovery: no collector reads through it today.

| Question | Answer |
| --- | --- |
| License | Elastic License 2.0. Not an OSI open-source license. It allows using, modifying and redistributing Nango, including inside a single-tenant or customer-edge install. It forbids offering Nango itself to third parties as a hosted service. Zasp's use (its own product's connections) is inside the license. Have counsel confirm before the first customer-hosted install. |
| Free self-hosted features | The README says "a limited feature set". The repo already assumes only auth and proxy are available and keeps syncs, webhooks and normalization in Zasp. Keep that assumption; confirm it against Nango's self-hosting documentation at the first new provider. |
| Fit | Good for SaaS platforms that authorize with OAuth or an API key (1,000+ APIs claimed). Not a fit for AWS role assumption, Kubernetes, Azure or Google Cloud workload identity: those stay first-party. |
| Something easier | No. Pipedream Connect, Paragon and Merge are hosted services that would put customer tokens with a third party, which a security product should not do. Airbyte is built for bulk data sync and is heavier to run. Steampipe (Apache 2.0 plugins) is worth a look only if cloud inventory breadth beyond AI services becomes a goal. |

**The real cost of a connector today is not sign-in, it is the closed provider list.** A new provider touches about forty switches and SQL constraints and needs a baseline rebuild. Nango alone does not change that. Workstream B fixes it once: one generic provider, `saas`, whose platform is an attribute. After that a new SaaS platform is a Nango entry, proxy rules and a mapping function, with no SQL change.

## Workstreams

Each task is sized S (under a day), M (one to three days) or L (about a week). "Agentless" says whether anything runs in the customer's environment.

### A. Parity floor from data already collected (agentless, no new connectors)

Cheapest rows to flip. Mostly mapping and queries over existing inventory and findings.

| ID | Task | Size | Done when |
| --- | --- | --- | --- |
| A1 | AI compliance mapping: tag every posture finding and red team category with OWASP LLM Top 10, OWASP Agentic Top 10, NIST AI RMF, ISO 42001, EU AI Act and MITRE ATLAS identifiers; one reviewed mapping file | M | A finding shows its framework references; the compliance page lists controls per framework with their evidence |
| A2 | Compliance page and export per framework (API first, then UI) | M | A framework report downloads with only evidence the caller may read |
| A3 | Agent credential inventory: per agent, every identity and credential it uses, from existing `uses_identity` relationships | S | Agent detail lists its credentials |
| A4 | Dormant credentials: IAM last-used and role last-activity read through the existing AWS role | M | A finding "credential unused for N days" on a discovered agent |
| A5 | Over-privileged agents: granted actions against actions seen in CloudTrail (see C1), plus admin-policy and wildcard checks | M | A finding names the unused permissions |
| A6 | Inactive ("zombie") agent state: no invocation or runtime signal for N days | S | Agents page filter "Inactive" |
| A7 | Guardrail posture: Bedrock agents and AgentCore runtimes with no guardrail attached; Copilot Studio and Agentforce agents with no content moderation setting | M | A finding per agent with no guardrail |

### B. Connector framework on Nango (agentless)

| ID | Task | Size | Done when |
| --- | --- | --- | --- |
| B1 | Generic provider `saas` in the collection contract with kinds `saas_tenant`, `saas_agent`, `saas_ai_application`, `saas_mcp_server`; `platform` is an attribute. One baseline rebuild. | L | A fake platform runs a full collection to a typed snapshot through the generic provider |
| B2 | Collector over the Nango proxy: paging styles (cursor, offset, link header), rate-limit handling, canonical output | M | The fake platform is collected through a stand-in Nango |
| B3 | Platform definition format: Nango entry, proxy rules, endpoints, mapping function, required scopes; documented in one page | S | Adding a platform changes one Go file and one test |
| B4 | Connector catalog and setup flow read platform definitions (API first, then UI) | M | A new platform appears in the catalog without web code |
| B5 | Platforms, in this order: Databricks (serving endpoints, agents), ServiceNow (AI agents), Google Workspace (OAuth grants to AI applications), Slack (installed AI apps), OpenAI organization (projects, assistants, keys), Anthropic organization (workspaces, keys), GitLab (agent repositories), Atlassian (Rovo agents) | M each | Each has a full-collection test against a fake; each is marked unverified until run against a real tenant |
| B6 | Move nothing: AWS, Kubernetes, GitHub, Okta, Microsoft and Salesforce stay first-party | - | - |

Evidence gate before B5: B1 to B3 must show that the second platform took under two days. If not, stop and fix the framework.

### C. Cloud breadth and an agentless runtime signal

| ID | Task | Size | Done when |
| --- | --- | --- | --- |
| C1 | CloudTrail reader through the existing AWS role: who called `InvokeModel`, `Converse`, `InvokeAgent`, `InvokeAgentRuntime`, and when | M | A role that calls a model becomes an inferred agent with signal `invoke:bedrock`, with last-invoked time |
| C2 | **The agentless runtime signal (decided: build).** Read VPC Flow Logs and Route 53 Resolver query logs through the existing AWS read role. Join a resolver answer for a catalog name to a flow from the same source address to the answered address, the same rule the node sensor uses. Covers EC2, ECS, EKS and Lambda in a VPC. | L | A workload with nothing AI-related in its definition becomes an inferred agent with signal `egress:<token>` after a sync |
| C2a | Log source discovery: find the account's flow log and resolver query log destinations (S3 or CloudWatch Logs), and report a coverage gap with the exact setup steps when either is missing | M | The integration detail says "Runtime signal: VPC Flow Logs not enabled" with what to enable |
| C2b | Bounded reader: a time window per sync, resolver logs filtered to catalog names first, then only flows to the answered addresses; byte and row limits; never stores names or addresses outside the catalog | M | A sync reads a bounded slice and a test asserts no uncatalogued name is kept |
| C2c | Attribution: source address to network interface to instance, task, pod (EKS with the VPC CNI gives pod addresses) or function; then to the workload or role already in inventory | M | The inferred agent is the Deployment, service or function, not an address |
| C2d | Read policy additions for the customer role (`logs:StartQuery`, `logs:GetQueryResults`, `s3:GetObject` on the log bucket, `ec2:DescribeFlowLogs`, `route53resolver:ListResolverQueryLogConfigs`, `ec2:DescribeNetworkInterfaces`) and runbook step | S | Policy file and runbook updated; a role without them still completes a sync |
| C3 | Azure through the existing Microsoft connection: Azure AI Foundry agents, Azure OpenAI deployments, managed identities (Azure Resource Manager reads) | L | Foundry agents listed; unverified until run on a real subscription |
| C4 | Google Cloud as a first-party provider (workload identity federation): Vertex AI Agent Engine, Gemini Enterprise agents, service accounts | L | Build when the first customer asks; costs one more provider in the closed list |
| C5 | The node sensor role stays as it is: optional, off by default. It is the choice for clusters outside AWS or without those logs. | - | - |

### D. MCP security

| ID | Task | Size | Agentless | Done when |
| --- | --- | --- | --- | --- |
| D1 | MCP servers as first-class inventory objects: from repository configs (`.mcp.json` and similar, parsed for server names and hosts, never secrets), SaaS agent connectors, AgentCore gateways, runtime egress | M | Yes | A "Tools & MCP" page lists servers with who uses them |
| D2 | MCP tool inventory: connect to a server with a customer-supplied read credential and call `tools/list`; record tool names and schemas, flag risky tools (shell, file write, database write) | M | Yes | A server shows its tools and risk flags |
| D3 | MCP registry: approved, unapproved and blocked servers; a finding when an agent uses an unapproved server | M | Yes | An unapproved server raises a finding on each agent that uses it |
| D4 | MCP posture: no authentication, plain HTTP, over-broad OAuth scopes, tool description changed since approval (rug pull) | M | Yes | Findings per check, mapped by A1 |
| D5 | MCP gateway on the existing runtime gateway: tool-level allow and deny, argument size limits, audit of every call | L | No, optional add-on | Not on the parity path; D3 with E1 (remove the connector) is the agentless control |

### E. Guardrails

| ID | Task | Size | Agentless | Done when |
| --- | --- | --- | --- | --- |
| E1 | **Agentless enforcement (primary).** The Security Agent applies provider-native controls with approval: attach or tighten a Bedrock guardrail, set content moderation on a Copilot Studio or Agentforce agent, remove an unapproved MCP connector, detach an over-broad policy | L | Yes | An approved action attaches a guardrail and A7's finding closes; each action has a rollback |
| E2 | Guardrail decision API for gateways the customer already runs (LiteLLM, Kong, Apigee): send the interaction, get allow, redact or block. Nothing of Zasp's is installed. | M | Yes (customer's own gateway) | A LiteLLM guardrail hook calls it; documented |
| E3 | Inline guardrails on Zasp's runtime gateway (prompt injection, redaction) as a supported workflow | L | No, optional add-on | Not on the parity path; build when a customer asks for inline blocking without their own gateway |

### F. Red team

| ID | Task | Size | Done when |
| --- | --- | --- | --- |
| F1 | Probe packs: import Garak and Promptfoo probe sets (Apache 2.0 and MIT) behind the existing curated-category gate; tag each with A1's frameworks | L | Over 1,000 probes selectable by category; non-production rule unchanged |
| F2 | Agentic probes: tool misuse, poisoned resource, indirect injection through MCP, cross-agent delegation | M | Each category has at least 20 probes and a passing run against the fixture agent |
| F3 | Continuous schedule: re-test on a cadence and on change of a discovered agent | M | A changed agent is re-tested without a person starting it |
| F4 | Attack Lab as a supported workflow | L | The route is no longer hidden; one run completes on real AWS |

### G. AI supply chain

| ID | Task | Size | Done when |
| --- | --- | --- | --- |
| G1 | AI bill of materials per repository agent: frameworks, model SDKs, models named in config, MCP servers, from the existing GitHub collector | M | CycloneDX ML-BOM export per agent |
| G2 | Agent skills and plugins inventory in repositories; a finding for skills that run shell or fetch remote code | M | Skills listed per repository; risky ones flagged |
| G3 | Model file scanning | - | Not planned. Noma is reported weak here too; revisit if a customer asks. |

### H. Lead, do not just match

| ID | Task | Size | Done when |
| --- | --- | --- | --- |
| H1 | Run the Security Agent loop end to end on a stack: plan, approval, action, containment, re-test | M | One run completes after the planner step (needs a funded planner account) |
| H2 | Attack paths through agents: agent to identity to data store, with the break options the Security Agent can take | M | A path from a discovered agent to a sensitive resource is shown with a ranked fix |
| H3 | One-click remediation from A4, A5, A7, D3: each finding offers the matching Security Agent action | M | The finding's Fix section runs the action through approval |
| H4 | Evidence pack: one export with discovery evidence, findings, actions taken, approvals and re-test results for an auditor | S | A signed export per agent |

### I. Proof and ecosystem

| ID | Task | Size | Done when |
| --- | --- | --- | --- |
| I1 | Golden path in production (launch plan steps 0 to 10) | - | Tracked in the launch plan; nothing here counts until it has run |
| I2 | Real-system runs of every collector, with false positives and misses recorded | - | Needs the systems |
| I3 | AWS Marketplace listing | M | Listing live |
| I4 | Public documentation: connector list with required permissions, guardrail API, MCP gateway | M | Docs site section |

## Order

1. **I1 and H1** first. Both competitors run in production; this is the largest gap and no feature closes it.
2. **A (all)**, **C1** and **C2 (with C2a to C2d)**. Agentless, no new connectors. Flips compliance, identity, inactive agents, guardrail posture and the runtime signal.
3. **B1 to B4**, then **B5** platform by platform, and **D1 to D4**.
4. **E1, E2**, **F1 to F3**, **G1, G2**, **H2 to H4**.
5. **C3**, **F4**.
6. **C4** when a customer asks. **D5 and E3** only as add-ons on request.

## What the comparison looks like after each step

| Capability | Today | After step 2 | After step 3 | After step 5 |
| --- | --- | --- | --- | --- |
| Discovery breadth | Behind | Behind | Level | Level |
| Runtime signal, agentless | None | Ahead on AWS (CloudTrail and flow logs, nothing installed) | Ahead | Ahead |
| Agent identity and access | Behind | Level | Level | Ahead (with H3) |
| MCP discovery and governance | Behind | Behind | Level | Level |
| MCP and content enforcement | Gap | Posture only | Posture only | Level without an inline component (after step 4); inline blocking of a single call remains an add-on |
| Red teaming | Behind | Behind | Behind | Level (after step 4) |
| AI compliance mapping | Behind | Level | Level | Level |
| AI supply chain | Gap | Gap | Gap | Level (after step 4) |
| Remediation loop | Ahead on paper | Ahead, proven (H1) | Ahead | Ahead |
| Attack paths | Level with Noma | Level | Level | Ahead (H2) |
| Production proof | None | Depends on I1 | Depends on I1 | Depends on I1 |

## First implementation pass (2026-11-14)

Built, tested against fakes, pushed:

| ID | What exists now | Limits |
| --- | --- | --- |
| A1 | `services/platform/compliancemap`: rule to framework controls; each finding carries `frameworks`; the finding detail lists them | Control identifiers are from memory, unreviewed. No per-framework page (A2). |
| A4 | Finding `agent_role_unused_90_days` | AWS only. Reads `iam:GetRole` for at most 200 agent roles per sync. |
| A5 (part) | Finding `agent_role_administrator_access` | Only "allow everything on everything" in a managed policy. Not used-against-granted. |
| A7 (part) | Finding `agent_guardrail_missing` | Bedrock agents only. |
| C1 | CloudTrail `LookupEvents` for the four Bedrock runtime calls, seven days, at most 200 events per call name and region; roles become `aws_inferred_agent` with resource type `iam_role` | Whether these calls appear as management events in every account is unverified. Identity Center and service-linked roles are skipped. A busy account is sampled. |
| C2 | Resolver query logs joined to flow logs through Logs Insights; an instance that resolved a catalog name and connected to the answered address becomes `aws_inferred_agent` with resource type `ec2_instance` | CloudWatch Logs destinations only. Instances only: a pod on EKS shows as its node, Lambda and Fargate are not attributed. First 100 sources and 300 destinations per region. The Insights field names (`srcids.instance`, `answers.N.Rdata`, `srcAddr`) are from memory. |
| G1 | CycloneDX 1.6 download per agent | Built from signals; no versions. |

How the checks reach the Findings page: the AWS collector emits them on the posture page as discovery findings on the agent entity (the channel Prowler findings use), so there was no schema change. Their stored title is generic ("Discovered AWS control ..."); the web application shows the proper title and guidance by rule.

## Second implementation pass (2026-11-14)

Six workstreams were built in parallel, merged, and the baseline rebuilt once. `tasks/todo.md` has the per-task state. In short:

| Workstream | What exists now | Limits |
| --- | --- | --- |
| Connectors (B1 to B5) | Provider `saas`; one collector over the Nango proxy; eight platform definitions; per-tenant hosts; sign-in from the Integrations page for four platforms | Every provider API shape is from memory. Nothing ran against a real provider or a real Nango. Whether Nango honours the base URL override header is unverified. |
| Red team (F1 to F3) | 1,080 probes in nine categories, three of them agentic; a run executes a sample; schedules by cadence or on target change; standalone runs execute on the installed baseline | No real Promptfoo process ran with the new configuration. The probes are written for this product, not imported. |
| Compliance and inventory (A2, A3, A6, H4) | Six AI frameworks on the compliance page and in exports; agent identities; activity state; evidence pack on demand and retained | Object store faked in tests. The retained pack omits Temporal-owned Security Agent runs. |
| Enforcement (E1, E2, H3) | Two provider remediation actions through a separate remediation role; remediation offered on the finding; guardrail decision API with its own token permission; Guardrails page | Nothing ran against real AWS. The LiteLLM example was not run. Helm and Terraform were edited as text. |
| MCP and cloud (D1 to D4, G2, A5, A7, C2c, C3, H2) | MCP servers, tools, registry and posture; skills; used against granted; attack paths through agents; attribution to ECS, Lambda and EKS clusters; Azure OpenAI and AI Foundry accounts | Agentforce moderation, Foundry agents and Kubernetes MCP links are open: no usable API or source is known. |

What remains is proof, not construction: I1, H1, I2 and F4 need real accounts; I3 and I4 are not engineering tasks; C4, D5 and E3 are on request and D5 and E3 are not agentless.

## Risks

- **Breadth claims are easy to make and hard to verify.** Every connector in B5 and C3 is written against documentation and a fake. Mark each unverified until it has run against a real tenant, and say so in the catalog.
- **The generic provider (B1) is a schema change in a pinned pipeline.** It is one baseline rebuild if done once; do not add kinds piecemeal.
- **Agentless enforcement cannot stop a single request in flight.** E1 changes the configuration so the next request is governed; E2 covers customers who already run a gateway. A buyer who needs Zasp itself to block one call inline needs the add-on (D5, E3). Say this plainly in sales material.
- **The flow-log signal depends on the customer's logging.** Without VPC Flow Logs and Resolver query logs there is no signal; C2a reports that as a coverage gap. Detection is delayed by log delivery (minutes) and the sync interval. Resolver logs do not exist for workloads using their own DNS. Query costs fall on the customer's account.
- **Nango's free self-hosted feature set can change.** Zasp depends only on auth and proxy; keep it that way.
- **CloudTrail volume.** C1 must read with a time window and event-name filter, not scan a trail.

## Not in this plan

Employee endpoints and coding assistants; ClickHouse, Hubble and Pixie; a TLS probe for tool-level visibility on unmanaged workloads; model file scanning.
