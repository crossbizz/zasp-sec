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

## Next, in order

These are not built. Each has an evidence gate or an external dependency.

1. **Run discovery against real systems.** One AWS account with a Bedrock agent, an AgentCore runtime and a Lambda function that calls a model; one cluster with an unlabelled LangGraph workload; one GitHub organization; one Okta tenant with ChatGPT or Claude connected. Record false positives and misses per signal class. This gates the confidence numbers above, which are judgement, not measurement.
2. **Microsoft as a provider (Copilot Studio and Entra agents).** Entra client credentials. `GET /v1.0/servicePrincipals/microsoft.graph.agentIdentity` (`AgentIdentity.Read.All`) for Entra Agent ID; `GET /v1.0/servicePrincipals` with `oauth2PermissionGrants` (`Application.Read.All`, `Directory.Read.All`) for AI applications consented in the tenant; Dataverse `GET {org}/api/data/v9.2/bots` and `botcomponents` per environment for Copilot Studio agents, their knowledge sources and tools. The Power Platform tenant inventory API is delegated-user only, so app-only discovery goes through Dataverse with an application user in each environment. This is a fifth provider: connector registry, credential class, subject binding, SQL CHECK constraints and the OpenAPI and web enums all change.
3. **Salesforce Agentforce as a provider.** Connected App with client credentials or JWT bearer, scope `api`. `SELECT ... FROM BotDefinition` and `BotVersion` over the REST query endpoint; planner, topic and action definitions over the Tooling API. The object names changed across API versions 60 to 68, so the first step is a query against a real org.
4. **Runtime discovery from the sensor.** Open-source Tetragon reports destination IP and port for a connection, not a DNS name or TLS SNI, and the sensor forwards digests only. Classifying egress to model providers needs a name source: CoreDNS or Route 53 Resolver query logs joined to pod and time, or an egress gateway that logs SNI. Matching provider IP ranges alone is low confidence because the large providers sit behind shared ranges and CDNs. Gate: on one cluster, measure how many inferred agents the name-joined egress signal adds over task 3, and its false positives, before building the pipeline.
5. **Unknown `agent_id` on gateway and OTLP telemetry.** Today an unknown id is stored on the session and correlation reports `unattributed`. Turning it into a candidate agent needs a telemetry-sourced observation, which the snapshot model (one complete snapshot per integration) does not have. Design together with item 4.
6. **Other platforms, as customers ask:** Google Vertex AI Agent Engine (`reasoningEngines.list`), Dialogflow CX and Gemini Enterprise agents; ServiceNow (`sn_aia_agent`); OpenAI and Anthropic organization APIs (projects, service accounts and keys, not agents); Entra and Google Workspace OAuth grants as a second IdP path; SageMaker endpoints and ECS task definitions as further AWS signals; MCP servers found by image as tools.
7. **Okta grants.** `GET /api/v1/apps/{id}/grants` (`okta.appGrants.read`) would show which scopes an AI application holds. It needs one more OAuth scope on the Okta connection, so existing connections must re-authorize.
8. **Show AI service coverage on the integration.** The `access_denied` and `unavailable` statuses are recorded but only search finds them. The integration detail should say "Bedrock AgentCore: permission missing" with the actions to add.
9. **A dismiss action.** A false positive can be owned (which makes it managed) or opted out by label on Kubernetes. Other providers have no way to say "this is not an agent" yet.

Employee endpoints stay a separate plan.
