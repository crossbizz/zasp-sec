# Automatic agent discovery, 2026-11-14

**Goal (PRD jobs 1 and 2):** a customer connects AWS, Kubernetes, GitHub or Okta and sees their agents without labelling anything, and can tell which ones nobody has taken ownership of.

**Before this plan:** the only thing that produced an agent was a Kubernetes Deployment labelled `zasp.ai/entity-kind: agent`. The AWS collector read IAM and EC2 only. Nothing recorded how an object was found, and the product had no notion of an unmanaged agent.

**Reference products:** Akto (Argus for homegrown AI, SaaS AI agents) and Noma (homegrown and SaaS agents). Both list agents from cloud control planes, code and SaaS platforms, and call an agent that is found but not in the customer's registry a shadow agent. Employee endpoints (Akto Atlas, Noma endpoint agents) are out of scope here by decision.

## What an agent record now says

Every inventory summary (lists, detail and the agent update response) carries four more members:

| Member | Values |
| --- | --- |
| `provider` | `aws`, `kubernetes`, `github`, `okta` |
| `source_kind` | the kind the collector reported, for example `aws_bedrock_agent` |
| `discovery` | `method` (`declared`, `provider_api`, `inferred`), `platform`, and the catalog `signals` an inference rests on |
| `management_state` | for an agent: `unmanaged` while it was found without a declaration and has no owner, otherwise `managed`; `not_applicable` for other kinds |

Three ways an agent is found, with the confidence the rule catalog gives each:

| Method | Meaning | Confidence |
| --- | --- | --- |
| Declared | The owner labelled the workload `zasp.ai/entity-kind: agent`. | 95% |
| Provider record | The provider's own control plane lists it as an agent. | 95% |
| Inferred | The product concluded it from signals in the reviewed catalog (`services/platform/agentsignals`). | 60 to 70% |

A signal is a `class:value` token from the catalog (`env:openai`, `package:langgraph`, `manifest:mcp_config`, `iam:bedrock_invoke_model`, `app:chatgpt`). A collector may read an environment variable name, an image reference, a file path or a package name to match it. It records only the token. It never reads an environment variable value, a Secret, or file content beyond package names.

Inference rule: one strong signal (an agent framework, an agent protocol, an agent platform image, a model-provider credential name, an IAM permission to invoke a model or agent), or weak signals of two different classes. A default port alone, or a bare model SDK alone, is not an agent. A model server is not an agent.

An unowned agent already raises the `ownerless_agent` finding, so a shadow agent also appears on the Findings page.

## New inventory kinds

| Kind | Product kind | Provider | Found by |
| --- | --- | --- | --- |
| `aws_bedrock_agent` | agent | AWS | `bedrock:ListAgents`, `bedrock:GetAgent` |
| `aws_agentcore_runtime` | agent | AWS | `bedrock-agentcore:ListAgentRuntimes`, `GetAgentRuntime` |
| `aws_agentcore_gateway` | tool | AWS | `bedrock-agentcore:ListGateways` |
| `aws_inferred_agent` | agent | AWS | A Lambda function whose environment variable names or execution-role policies show it calls a model (`lambda:ListFunctions`) |
| `kubernetes_inferred_agent` | agent | Kubernetes | An unlabelled Deployment, StatefulSet, DaemonSet, Job or CronJob whose images, environment variable names, command, arguments or ports match the catalog |
| `github_agent_project` | agent | GitHub | A repository with an agent manifest (`.mcp.json`, `langgraph.json`, `.bedrock_agentcore.yaml`, an A2A agent card) or an agent framework in `requirements.txt`, `pyproject.toml`, `package.json` or `go.mod` |
| `okta_ai_application` | agent | Okta | An application in the tenant whose name is a known AI assistant, coding agent, agent builder, customer agent or meeting agent. This is the SaaS agent path in this release. |

No new provider was added. A fifth provider is about forty hard-coded switches, exact-count pins and SQL CHECK constraints (see "Next" below); a new kind under an existing provider is about twelve.

To keep a workload out of inference, label it `zasp.ai/entity-kind` with any value other than `agent`, for example `workload`.

## Tasks

State on 2026-11-14. "Tested" means unit and component tests in this repository. Nothing here has run against a real AWS account, cluster, GitHub organization or Okta tenant.

| # | Task | State |
| --- | --- | --- |
| 1 | Signal catalog and matchers (`agentsignals`) | Done, tested |
| 2 | Seven kinds in the provider schema, relationship matrix, rule catalog, search allow-list and SQL rule table; `discovery` attribute validation | Done, tested |
| 3 | Kubernetes: infer unlabelled agent workloads; opt-out label | Done, tested |
| 4 | Okta: classify AI applications as agents; assignments follow the new kind across pages and resume | Done, tested |
| 5 | GitHub: agent projects from repository trees and dependency manifests | Done, tested |
| 6 | AWS: Bedrock agents, AgentCore runtimes and gateways, model-calling Lambda functions; denied or absent services do not fail the sync | Done, tested |
| 7 | Inventory summary: `provider`, `source_kind`, `discovery`, `management_state` in SQL, the API, OpenAPI and the web client | Done, tested |
| 8 | Agents page: Source, Found by and Status columns, an Unmanaged filter, "How it was found" in the detail drawer | Done, tested |
| 9 | Baseline schema artifact rebuilt with the rule rows, the catalog digest and the summary members | Done; installs on a fresh PostgreSQL 18.3 as a non-superuser |
| 10 | Customer AWS read policy and runbook updated with the optional actions | Done |

## AWS

The collector has a fifth page, `agents`, between `resources` and `posture`. It reads every enabled region.

- **Permissions are optional.** The customer role needs `bedrock:ListAgents`, `bedrock:GetAgent`, `bedrock-agentcore:ListAgentRuntimes`, `bedrock-agentcore:GetAgentRuntime`, `bedrock-agentcore:ListGateways` and `lambda:ListFunctions` for full results. A role without them still completes the sync.
- **Coverage is recorded.** Each of the three services is an `aws_service` entity whose `status` is `collected`, `access_denied` (a region refused the call) or `unavailable` (no region offers the service). AgentCore is not in every region, so one region serving it is enough for `collected`. These are assets; no page lists assets yet, so the status is reachable through search only.
- **Lambda inference.** A function is listed when its environment variable names or the managed policies on its execution role match the catalog. Inline role policies are not read. A bare `*` action (for example `AdministratorAccess`) is not evidence; `bedrock:*` is.
- **Not verified:** how LocalStack answers for services it does not emulate. The collector treats HTTP 501, HTTP 404 and its "not implemented" messages as `unavailable`. If LocalStack answers differently, a local sync fails as retryable instead.
- **Known limits:** ARNs for Bedrock agents and AgentCore gateways are built with the `aws` partition, as instance ARNs already are, so GovCloud and China are wrong. One sync is bounded at 1,000 items per page (`apiserver/discovery_collection_input.go`), which an account with thousands of functions that call a model would hit.

## Schema

- `completion.sql` section X4 adds the seven rule rows and pins the new catalog digest. Section X5 adds the four summary members to `zasp_inventory_detail` and `zasp_inventory_page`.
- The baseline artifact changed, so installed databases need a reviewed `zasp_baseline.accept`, and the two Neon databases need the reinstall the launch plan already lists.
- `generate.sh` can now run without Docker: set `ZASP_BASELINE_PG_BIN` to a PostgreSQL 18 `bin` directory. This artifact was built that way with PostgreSQL 18.3 from conda-forge, not the Debian image. An unchanged rebuild differed from the committed artifact only in the version comment and in timestamps.

## What was checked, and how

- Unit and component tests for every collector, the schema, the API and the web client.
- Against a real PostgreSQL 18.3: the baseline builds from the historical chain (147 readiness predicates and 13,998 structural facts agree with the superuser installation); it installs on an empty database as a non-superuser and verifies sealed, intact and current; and the inventory tests read a provider record, a declared agent and an inferred agent through the patched functions, then take ownership of the inferred agent and see it become managed.
- Not run: any real provider, LocalStack, the local stack (`stack.sh`, which needs Docker), a browser, the Temporal workflow end to end.

## Second pass (same day): SaaS providers, dismissal, permission gaps

| # | Task | State |
| --- | --- | --- |
| 11 | `microsoft` and `salesforce` as optional providers: contract, catalog, credentials, connector catalog, worker registration, SQL constraints, OpenAPI and web enums, deployment values | Done, tested. Off by default. Chart and Terraform changes were not rendered or planned (neither tool is installed here) |
| 12 | Microsoft collector: Entra agent identities, enterprise applications that are known AI products, Copilot Studio agents through Dataverse | Done, tested against fake Graph and Dataverse servers |
| 13 | Salesforce collector: Agentforce agents (`BotDefinition`) with whether a version is active | Done, tested against a fake org |
| 14 | Dismiss a false positive | Done, tested on a real PostgreSQL |
| 15 | AI service permission gaps on the integration detail | Done; the SQL was tested on a stand-in for the freshness function, then applied by the baseline build |
| 16 | Every collector runs a whole collection to a stored snapshot in a test | Done. See "A defect this found" |

**New kinds:** `microsoft_tenant` and `salesforce_org` (assets), `microsoft_agent_identity`, `microsoft_copilot_agent` and `salesforce_agent` (agents, provider records, 95%), `microsoft_ai_application` (agent, inferred, 70%).

**Connecting them.** Both use reference authorization, like AWS: the customer creates an app registration (Microsoft) or a connected app with the client-credentials flow (Salesforce), and the client secret is stored under a reference in the connector secret store. A deployment enables a provider by setting `ZASP_DISCOVERY_MICROSOFT_COLLECTOR_VERSION` or `ZASP_DISCOVERY_SALESFORCE_COLLECTOR_VERSION` to `collector_v1`. The steps and permissions are in `docs/operations/production-aws-runbook.md`, steps 13 and 14.

- Microsoft needs `Application.Read.All` and, for Entra Agent ID, `AgentIdentity.Read.All`. A tenant without the agent identity feature or permission skips that phase. Copilot Studio needs the Dataverse environment URL and an application user in it; one integration covers one environment.
- Salesforce needs scope `api` and a run-as user with API Enabled and View Setup and Configuration.
- Egress is by CIDR lists, which cannot name a host. The two providers take their own lists, empty by default, and the chart refuses an enabled provider with an empty list. The ranges are shared with the providers' other services, so the policy admits more than the hosts the worker calls.

**Dismissal.** "Not an agent" in the agent's ownership form stores the reserved tag `not-an-agent` through the existing ownership update, so the decision is audited and needs an owner and a team. The agent's `management_state` becomes `dismissed`, the Agents list leaves it out unless the Dismissed filter is chosen, and no posture finding is raised for it. A declared agent cannot be dismissed.

**Permission gaps.** `GET /api/v1/integrations/{id}/freshness` gains `coverage_gaps`: the AWS AI services whose calls were refused or that no region offers. The integration detail lists them with the read actions to add.

**Unknown `agent_id` on telemetry: closed without building.** The ingest path accepts an agent id only when it is a product id, so telemetry can carry only ids the product issued. It cannot name an agent the product does not know. A stale or mistyped id is a configuration problem, not a discovered agent.

### A defect this found

A whole collection through the collection client failed as malformed for Okta, GitHub, Salesforce and the AWS agents page. Those collectors wrote JSON keys out of order and the snapshot contract requires canonical JSON. Their tests called the page API directly and never built a snapshot. For Okta and GitHub this predates the agent work: no Okta tenant, and no GitHub installation with a repository, could have completed a sync. Each collector now writes sorted keys and has a test that runs a typed collection to a complete snapshot. The first pass of this plan called the AWS, Okta and GitHub detectors "tested" while that gap was open.

### Not verified in the second pass

- Any real Entra tenant, Dataverse environment or Salesforce org. The Graph agent identity path, the Dataverse `bots` columns, and the Salesforce object, field and error names are from documentation and memory. The Salesforce collector tries four query variants because the agent objects changed across API versions 60 to 68.
- A Salesforce rate limit usually arrives as HTTP 403, which the collector reports as denied, not as rate limited.
- A wrong client secret at discovery time is reported as retryable.
- The web form cannot add a Dataverse URL to an existing Microsoft integration; it has to be recreated.

## Third pass (same day): runtime discovery from the node sensor

Request: build discovery from network traffic end to end, on the existing stack, following a reference design (passive discovery, protocol-aware discovery, identity enrichment).

### What was built

A sensor role, `egress-discovery`, and its join into Kubernetes agent inference. The evidence gate in item 4 below was set aside on the owner's instruction; the measurement it asked for is now the first thing to do on a real cluster.

| Layer of the reference design | What does it here |
| --- | --- |
| Passive discovery | The new role. Tetragon `tcp_connect` events give the pod's workload and the addresses; DNS answers captured on the node give the name. A workload that was given an address for a catalog name and then connected to it is recorded under the catalog token. |
| Protocol-aware discovery | By name only: model APIs, Bedrock and AgentCore data planes, and remote MCP servers (`mcp.<vendor>`). MCP method and tool names need plain-text HTTP; the existing runtime gateway and OTLP ingest carry those for managed agents. |
| Identity enrichment | Unchanged: provider control planes (AWS, Microsoft, Salesforce, Okta), the declared label, and OTLP or gateway telemetry for agents the product issued an ID to. |

Flow: sensor pod (per node) → ConfigMap `zasp-egress-<digest>` with label `zasp.ai/egress-observations=v1` → Kubernetes collector lists those ConfigMaps on each workload page → `egress:<token>` joins the workload's evidence → the existing rule (one strong signal, or weak signals of two classes) decides → `kubernetes_inferred_agent`.

Decisions:

- **Name source: DNS answers captured on the node** (AF_PACKET, cooked, kernel filter for UDP source port 53). It needs no customer infrastructure, unlike CoreDNS logs, Route 53 Resolver logs or Hubble. The join key is (pod address, answer address), so a shared CDN address alone never matches: the same pod must have asked for the name.
- **Transport: a ConfigMap, not a new ingest endpoint.** The collector already holds a cluster credential and the snapshot model wants one complete snapshot per integration. No new table, endpoint, schema migration or baseline rebuild. The customer can read exactly what is kept.
- **No ClickHouse, Hubble or Pixie.** What is stored is one small document per node (workload, token, last seen), not an event history; PostgreSQL through the existing snapshot is enough. Raw connection events already go to the existing runtime pipeline as digests.
- **A model API seen at run time is a strong signal**, the same bar as holding a model provider credential. Agent tooling hosts (search, sandboxes) are weak.
- **Off by default.** The role needs the host network and `NET_RAW`; a customer opts in (`sensorAgent.egressDiscovery.enabled`).
- **Privacy.** Names outside the catalog are dropped on the node before they are stored. The published document holds tokens only; a test asserts no name or address is in it.

Files: `services/platform/agentsignals/egress.go` (catalog, document, validation), `services/sensor-agent/egress_*.go` (DNS parser, capture, tracker, Tetragon stream, publisher, daemon), `services/platform/connectors/kubernetesdiscovery/egress_observations.go`, `deploy/staging/product/templates/edge.yaml`, runbook step 15.

### What was checked

- The whole sensor role in one test: a real packet capture on loopback with the kernel filter attached, a real gRPC stream from a stand-in Tetragon server, a fake API server. A DNS answer followed by a connection ends as a ConfigMap naming the workload and the token; the plain site in the same test does not.
- The DNS parser refuses queries, failures, fragments and pointer loops, and every truncation of a valid packet without a panic.
- A full Kubernetes collection with observations ends as a typed snapshot; a workload with no AI in its pod template becomes an inferred agent; an observation older than seven days, an opted-out workload and a forged document do not.
- A forbidden, malformed or failing ConfigMap list never fails a workload page.

### Not verified

- No cluster. No veth, CNI, real Tetragon, real DNS server or NodeLocal DNSCache has been in the path. Whether Tetragon's workload name matches the Deployment or CronJob name for every owner chain is unmeasured.
- The catalog's host names are from memory, not checked against provider documentation today.
- The chart block was rendered with a stand-in for Helm.
- False positive and miss rates. Measure on one cluster first: how many agents the egress signal adds over the pod-template signals, and what it gets wrong.

### Known limits

- Proxies and egress gateways hide the workload (the proxy resolves the name). DNS over HTTPS or TCP is not seen.
- Kubernetes only. EC2, ECS and Lambda have no sensor; VPC flow logs with Route 53 Resolver query logs would be the equivalent source.
- Inbound third-party agents calling the customer's APIs are not covered; that is an API gateway integration.
- A SaaS agent's internal sub-agents cannot be seen from the network, as the reference design says.
- Detection waits for the next Kubernetes sync.
- A missing ConfigMap permission is silent: the integration detail does not yet say the runtime signal is unavailable.

## Next, in order

These are not built. Each has an evidence gate or an external dependency.

1. **Run discovery against real systems.** One AWS account with a Bedrock agent, an AgentCore runtime and a Lambda function that calls a model; one cluster with an unlabelled LangGraph workload; one GitHub organization; one Okta tenant with ChatGPT or Claude connected. Record false positives and misses per signal class. This gates the confidence numbers above, which are judgement, not measurement.
2. **Microsoft as a provider (Copilot Studio and Entra agents). Built in the second pass; what remains is the real-tenant run in item 1.** Entra client credentials. `GET /v1.0/servicePrincipals/microsoft.graph.agentIdentity` (`AgentIdentity.Read.All`) for Entra Agent ID; `GET /v1.0/servicePrincipals` with `oauth2PermissionGrants` (`Application.Read.All`, `Directory.Read.All`) for AI applications consented in the tenant; Dataverse `GET {org}/api/data/v9.2/bots` and `botcomponents` per environment for Copilot Studio agents, their knowledge sources and tools. The Power Platform tenant inventory API is delegated-user only, so app-only discovery goes through Dataverse with an application user in each environment. This is a fifth provider: connector registry, credential class, subject binding, SQL CHECK constraints and the OpenAPI and web enums all change.
3. **Salesforce Agentforce as a provider. Built in the second pass; what remains is the real-org run in item 1.** Connected App with client credentials or JWT bearer, scope `api`. `SELECT ... FROM BotDefinition` and `BotVersion` over the REST query endpoint; planner, topic and action definitions over the Tooling API. The object names changed across API versions 60 to 68, so the first step is a query against a real org.
4. **Runtime discovery from the sensor. Built in the third pass; what remains is the measurement on one cluster.** Open-source Tetragon reports destination IP and port, not a name; the third pass takes the name from DNS answers captured on the node.
5. **Unknown `agent_id` on gateway and OTLP telemetry. Closed, see the second pass.** Today an unknown id is stored on the session and correlation reports `unattributed`. Turning it into a candidate agent needs a telemetry-sourced observation, which the snapshot model (one complete snapshot per integration) does not have. Design together with item 4.
6. **Other platforms, as customers ask:** Google Vertex AI Agent Engine (`reasoningEngines.list`), Dialogflow CX and Gemini Enterprise agents; ServiceNow (`sn_aia_agent`); OpenAI and Anthropic organization APIs (projects, service accounts and keys, not agents); Entra and Google Workspace OAuth grants as a second IdP path; SageMaker endpoints and ECS task definitions as further AWS signals; MCP servers found by image as tools.
7. **Okta grants.** `GET /api/v1/apps/{id}/grants` (`okta.appGrants.read`) would show which scopes an AI application holds. It needs one more OAuth scope on the Okta connection, so existing connections must re-authorize.
8. **Show AI service coverage on the integration. Built in the second pass.** The `access_denied` and `unavailable` statuses are recorded but only search finds them. The integration detail should say "Bedrock AgentCore: permission missing" with the actions to add.
9. **A dismiss action. Built in the second pass.** A false positive can be owned (which makes it managed) or opted out by label on Kubernetes. Other providers have no way to say "this is not an agent" yet.

Employee endpoints stay a separate plan.
