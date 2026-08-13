# Product Requirements Document: Enterprise Agent Security Platform

**Version:** 1.5, release-candidate MVP  
**Date:** August 12, 2026  
**Audience:** Product, Design, Engineering, Security Research, Compliance, GTM, Customer Success  
**Status:** MVP specification

## Executive Summary

Build a SaaS-first Agent Security Platform for enterprises deploying autonomous agents that can execute code, call tools and APIs, access sensitive data, or change production systems. The default v1 experience is a multi-tenant AgentSec-managed SaaS control plane. The same product can also run as a dedicated single-tenant deployment for customers that require stronger isolation, customer-hosted operation, or dedicated infrastructure.

The product is not a sandbox-only security tool, MCP scanner, generic CSPM, or general SIEM. It connects agent intent and identity to tools, runtimes, cloud/SaaS resources, runtime behavior, and real side effects.

The core customer loop is:

**Deploy -> Discover -> Understand capability -> Prioritize path -> Test -> Verify safely -> Plan response -> Authorize -> Act -> Verify -> Protect continuously -> Investigate -> Prove**

Every MVP feature must strengthen that loop or be required for an enterprise to deploy it safely.

### MVP customer promise

A security engineer can sign in to the SaaS product, connect core systems, deploy the lightweight customer-side runtime components where needed, and answer:

1. What agents exist and who owns them?
2. What can each agent actually reach and do?
3. Which combinations can lead to material impact?
4. Can a risky behavior be reproduced safely?
5. Can the platform evaluate the evidence and propose or take an appropriate response within boundaries we configured?
6. Which response actions require human approval, and which can run autonomously?
7. Did the response actually contain the risk when the platform verified or re-tested it?
8. What happened in a real session, including every automated decision and action, with evidence suitable for audit and incident handoff?

### Product thesis

The differentiator is not any single checkbox. Current vendors already offer combinations of agent discovery, posture, graphs, red teaming, runtime controls, exploitability validation, self-hosting, and eBPF.

The product should win through the combined workflow:

**low-instrumentation discovery + effective capability + evidence state + semantic/runtime correlation + safe path reproduction + bounded Security Agents + deterministic action authorization + narrow runtime control + post-action verification**

## 1. Audit Decisions

The following decisions replace broader v1.1 scope.

### Keep in MVP

- SaaS-first multi-tenant deployment on AWS, plus a supported single-tenant deployment mode using the same product artifacts
- Stytch B2B for enterprise authentication and identity lifecycle
- Neon Postgres for relational control-plane state
- AWS managed SQS, OpenSearch Service, S3, KMS, Secrets Manager and IAM/STS
- LocalStack for local AWS development, with real AWS release-parity tests
- PostHog for allowlisted usage analytics and non-critical feature flags
- OpenTelemetry to an in-cluster Collector, optionally exporting to Grafana Cloud or New Relic
- OpenRouter for bounded Security Agent planning plus optional AI explanations, never for deterministic runtime allow/block
- eBPF as a first-class low-instrumentation sensor through Tetragon
- Cartography and Prowler behind product-owned adapters
- Nango free self-hosted only for long-tail Auth + Proxy
- Promptfoo for MVP red-team orchestration
- OPA Go SDK embedded in the runtime gateway
- one canonical agent security graph
- Effective Capability
- high-signal agent posture findings
- evidence-backed attack paths
- EKS Fargate Attack Lab reference path
- Monitor and Block runtime policy
- bounded Security Agents for agentic Act & Enforce, with built-in templates plus a user-configurable builder
- asynchronous approval workflow for Security Agent actions that exceed configured autonomy or platform safety floors
- session timeline and activity evidence
- audit/evidence export
- enterprise API/webhooks

### Move after MVP

- synchronous inline Require Approval for application/runtime actions beyond Security Agent response approvals
- built-in incident case management
- automated least-privilege recommendations
- deep Azure/GCP semantics
- broad provider-specific remediation actions
- additional Attack Lab providers
- coding-agent desktop/endpoint hooks beyond required runtime/OTel adapters
- Garak and Akto OSS test-content enrichment
- deep drift/change UI
- expanded compliance-framework UX

### Explicitly not MVP

- a standalone API-security product with full BOLA/BFLA/business-logic parity
- a full software supply-chain or vulnerability-management product
- byte-level taint tracking or universal DLP
- automatic destructive IAM remediation
- arbitrary custom code, arbitrary shell, arbitrary HTTP tools, or user-supplied executable plugins inside Security Agents
- custom user-authored Rego
- customer-written graph query language
- a full SIEM query language
- a full GRC authoring system
- a full case-management replacement for SIEM/SOAR
- every cloud as a first-party hosting target
- air-gapped deployment while Stytch and Neon are required managed dependencies

## 2. Target Customer and Jobs

### Initial ICP

Mid-market and enterprise organizations actively deploying agents that can execute code, use enterprise credentials, call SaaS/cloud APIs, or touch sensitive data.

Strong first use cases:

- coding and software-engineering agents
- cloud/infrastructure automation agents
- security automation agents
- IT/support agents with SaaS write permissions
- data/analytics agents with sensitive data access
- internal agents using MCP/tools and Kubernetes/remote execution

### Buyers

**CISO / VP Security** needs a defensible view of autonomous authority and governance.

**Cloud Security / CNAPP owner** needs blast-radius and identity/cloud context without adding an agent-specific product per framework.

**AppSec / Product Security** needs safe testing, developer remediation, and runtime control.

### Daily users

- AI Security Engineer
- Cloud Security Engineer
- AppSec/Product Security Engineer
- SOC analyst for handoff/investigation
- IAM engineer
- AI platform engineer
- agent owner/developer
- GRC/compliance reviewer
- enterprise/platform administrator

### Jobs to be done

1. Discover agents without instrumenting every application first.
2. Assign owners and identify shadow/unmanaged agents.
3. Understand what an agent can ultimately cause, not just its declared tool list.
4. Prioritize findings by credible paths to sensitive or destructive outcomes.
5. Test agent behavior safely in staging.
6. Prove or disprove a critical path using isolated test/canary resources.
7. Let a bounded Security Agent evaluate a finding/path/session and select an appropriate response from actions I explicitly allowed.
8. Require approval for higher-risk actions while allowing safe, reversible actions to execute automatically.
9. Verify that the response achieved the intended containment or remediation outcome, then re-test when applicable.
10. Reconstruct a session from agent/tool activity to OS/network/resource evidence, including automated response decisions and actions.
11. Produce audit and compliance-supporting evidence without screenshots/manual spreadsheets.
12. Operate the platform without opening or understanding internal OSS dashboards.

## 3. Product Principles

1. **Evidence before severity.** Show why risk exists.
2. **Observed reality and configuration are distinct.** Both matter.
3. **Safe by default.** Read-only onboarding and metadata-first collection.
4. **One security model.** Inventory, findings, paths, tests, policies, sessions, and evidence reference the same assets.
5. **One product experience.** OSS and managed vendors are implementation details.
6. **Low instrumentation first.** Add semantic depth where supported.
7. **Do not overclaim eBPF.** It provides runtime signals, not universal plaintext application context.
8. **Policy coverage must be honest.** If an action is monitor-only, say so.
9. **AI may plan, but it cannot authorize itself.** Security Agents can reason over evidence and propose an action plan, but deterministic product code decides whether each action is allowed, requires approval, or is prohibited.
10. **Bounded autonomy over open-ended autonomy.** MVP Security Agents use a fixed product action catalog, explicit scope, action budgets, approval floors, and verification criteria. They cannot run arbitrary shell or arbitrary external tools.
11. **Degraded is not empty.** Missing data must be visible as stale/degraded, never interpreted as safe.
12. **Enterprise readiness is operational.** Install, backup, restore, upgrade, diagnose, and audit must actually work.
13. **MVP means smallest credible enterprise outcome, not smallest demo.**

## 4. MVP Scope

### 4.1 P0 capabilities

Each capability below is required for the MVP. The scope is intentionally bounded to the smallest enterprise-credible implementation.

- **SaaS-first deployment with single-tenant option.** Fast onboarding by default, dedicated isolation when required. MVP: multi-tenant SaaS plus a dedicated single-tenant topology from the same release artifacts.
- **Enterprise identity.** Corporate identity lifecycle works. MVP: Stytch first-admin bootstrap, SAML/OIDC, SCIM, built-in roles, Workspace grants, and recovery procedure.
- **Core integrations.** Identity, cloud, code, and runtime context. MVP: AWS, Kubernetes, GitHub, Okta or Entra, plus the long-tail catalog foundation.
- **eBPF runtime sensor.** Low-instrumentation runtime visibility. MVP: Tetragon packaging, health, and filtered process/file/network events.
- **Semantic agent telemetry.** Better attribution when available. MVP: OTLP/gateway attributes for agent, session, task, tool, and sandbox IDs.
- **Agent inventory.** Know what exists and who owns it. MVP: agents, tools/MCP, identities, runtimes, owner, last seen, and coverage.
- **Effective Capability.** Understand blast radius. MVP: direct and indirect read, write, execute, admin, credential, and egress capability.
- **Posture findings.** Actionable weaknesses. MVP: a small product rule set plus agent-relevant cloud context from Prowler.
- **Attack paths.** Understand combined exposure. MVP: evidence-backed paths to sensitive or high-impact sinks with ranked break options.
- **Red Team.** Test agent behavior. MVP: Promptfoo-backed curated packs selected by capability.
- **Attack Lab.** Prove or disprove critical paths. MVP: EKS Fargate reference verification path using canary or test resources only.
- **Runtime policy.** Constrain dangerous actions. MVP: Monitor and Block, simulation, staged rollout, and cached signed bundles.
- **Security Agents.** Evaluate and respond automatically within customer-defined authority. MVP: built-in responder templates plus a custom bounded builder, fixed action catalog, plan preview, approval floors, action budgets, execution, audit, and verification.
- **Response approvals.** Keep higher-risk automated response safe. MVP: asynchronous approval queue for Security Agent actions, fresh authentication for sensitive approvals, expiration, and full audit.
- **Session investigation.** Understand what happened. MVP: semantic/runtime timeline with source and correlation confidence.
- **Audit and evidence.** Prove operation and access. MVP: append-only application audit, export, retention, and evidence freshness.
- **External data controls.** Understand egress. MVP: collection modes, retention, and PostHog/OpenRouter/OTLP controls.
- **API and webhook.** Enterprise automation. MVP: documented API for every UI action plus a generic outgoing webhook.

### 4.2 Initial high-signal findings

Do not flood customers with every cloud or LLM check. MVP focuses on findings likely to change action:

- agent has no owner
- agent uses human credential
- shared or long-lived credential across agents
- public/untrusted input plus production write capability
- shell/code execution plus production credential access
- unrestricted egress plus sensitive-data reach
- unapproved remote MCP/tool
- destructive tool without runtime control
- production agent lacks runtime policy coverage at an enforceable point
- sandbox/runtime exposes host filesystem or privileged mode
- agent can modify CI/CD and reach production secrets
- inactive/zombie agent retains active credential/permission

Prowler findings are surfaced by default only when they attach to an agent, identity, resource, attack path, or compliance evidence relevant to the Agent Security workflow.

## 5. Information Architecture

The MVP navigation is intentionally small.

**Home**
- Overview

Home is the daily operating queue, not a vanity dashboard. The Overview prioritizes:

- new or worsening critical exposures and Verified paths
- Security Agent runs in Needs human, Failed, or Inconclusive state
- pending Security Agent approvals, ordered by expiry and risk
- stale/degraded core integrations and sensors
- recently Contained/Remediated risks and re-test status

Each card links directly to the underlying Finding, Attack Path, Security Agent run, Approval, Integration, or Sensor. The same `getHomeSummary` API backs the page; drill-down uses the canonical list/detail APIs.

**Inventory**
- Agents
- Tools & MCP
- Identities
- Runtimes

**Exposure**
- Findings
- Attack Paths

**Test**
- Red Team
- Attack Lab

**Protect**
- Policies
- Security Agents
- Approvals

**Investigate**
- Sessions

**Compliance**
- Evidence

**Integrations**
- Connections
- Sensors

**Administration**
- Identity & Access
- Audit Log
- Data & Retention
- External Data Flows
- System Health
- API Access

Models, data assets, cloud resources and repositories are graph/detail entities, not separate top-level pages in MVP.

Effective Capability is part of Agent detail, not a separate top-level page.

## 6. Onboarding and First Value

### 6.1 First Organization and first Admin bootstrap

The first customer administrator must be able to enter the product before corporate SSO is configured. MVP uses Stytch for this bootstrap, not a second authentication system.

1. AgentSec provisioning creates the customer Stytch B2B Organization and matching product Organization, then invites the named first Organization Admin through the Stytch-backed product sign-in flow.
2. The first Admin signs in using the allowed bootstrap method, for example the Stytch B2B email invite/passwordless flow configured for the Organization.
3. Product resolves the Organization and creates the default Workspace plus `production`, `staging`, and `development` Environments if they do not exist.
4. The first Admin is guided to **Administration -> Identity & Access** to configure and test corporate SAML/OIDC.
5. After SSO succeeds, the Admin configures SCIM and group mappings, then can require the enterprise sign-in policy for normal users.
6. The bootstrap identity remains a normal audited Organization member. There is no customer-facing bypass login or separate local password database.

**Success condition:** a newly provisioned customer can reach the product, configure corporate identity, and continue onboarding without AgentSec support editing product state manually.

### 6.2 SaaS onboarding, default v1 path

1. Security Admin signs in through the Stytch-backed product experience.
2. Product shows the active Organization, Workspace and Environment and explains the default metadata-only collection mode.
3. Admin connects AWS, Kubernetes, GitHub and the selected launch IdP through the product-owned setup wizard described below.
4. Admin optionally deploys the lightweight customer-side Helm package containing the runtime sensor/gateway components required for selected runtime coverage. The SaaS control plane itself is not installed in the customer cluster.
5. Each connection and sensor shows Setup, Testing, Syncing, Healthy, Degraded or Stale state with a product-owned next action.
6. Home and Agents populate with evidence-backed inventory, coverage state and the first exposure paths.
7. Admin assigns an owner, creates a ticket/webhook, runs a safe test, creates a policy, or enables a Security Agent responder.

### 6.3 Launch connector setup flows

All launch connectors share one product flow: **Choose provider -> Review access -> Configure -> Test connection -> Initial sync -> Review coverage**. The user never opens Cartography, Prowler, Nango or another OSS dashboard.

#### AWS

1. Select **AWS** and choose the target Workspace/Environment.
2. Product explains that MVP discovery is read-only and shows the exact AWS permissions/data categories required.
3. Product generates the customer-specific external ID plus the supported IAM role setup instructions or Terraform/CloudFormation snippet.
4. Admin enters the role ARN and clicks **Test connection**.
5. Product verifies identity/assume-role access and required read permissions before allowing initial sync.
6. Initial sync shows account scope, discovered resource/identity counts, last success and any permission gaps with exact remediation guidance.

#### Kubernetes

1. Select **Kubernetes** and choose the target Workspace/Environment.
2. Product explains whether the customer needs inventory only, runtime sensor coverage, runtime enforcement, or the combined edge package.
3. Product creates a scoped sensor enrollment and displays the Helm command/values for the selected cluster.
4. Admin deploys the edge package. The Sensors page shows heartbeat, kernel/Tetragon capability, runtime gateway status and coverage.
5. Product tests Kubernetes inventory access plus sensor/gateway connectivity and reports unsupported nodes or missing permissions without marking the whole connection healthy.

#### GitHub

1. Select **GitHub** and choose Organization/repository scope.
2. Product explains the requested read permissions and optional actions before authorization.
3. Admin installs/authorizes the supported GitHub integration for the intended Organization/repositories.
4. Product validates installation scope and performs a bounded initial sync.
5. Connection detail shows repositories, apps/workflows/identities discovered, permission coverage, freshness and any missing scope.

#### Launch IdP, Okta or Microsoft Entra ID

1. Select the supported launch IdP and target Organization scope.
2. Product shows the exact read-only directory/application permissions required for security inventory, separate from Stytch SSO/SCIM configuration used to access AgentSec itself.
3. Admin authorizes/configures the provider credentials through the product flow.
4. Product validates directory/app visibility and syncs identities, groups, applications/service principals and privilege relationships required by the Agent Security graph.
5. Connection detail shows what was collected, stale/degraded state and permission gaps.

A built-in **Generic Webhook** integration uses the same Connections surface for outbound ticket/approval/response notifications. It is optional and does not require a new notification platform in MVP.

### 6.4 Single-tenant onboarding

For customers that require a dedicated control plane, deploy the same signed product release into a dedicated AgentSec-managed or customer-managed AWS environment using the single-tenant Helm/Terraform profile. `agentsecctl preflight` validates AWS, Kubernetes, Stytch, Neon and product dependencies. After installation, AgentSec provisions the pinned Organization and first Admin using the same Stytch bootstrap model, then the customer follows the same product onboarding wizard and UI as SaaS customers.

### 6.5 First-value success condition

Within the first day, a design partner can complete first-admin bootstrap, connect the launch systems, see meaningful agent inventory and open at least one evidence-backed risk path without modifying every agent application. SaaS customers should reach the first connection flow without infrastructure deployment. Single-tenant customers should install the dedicated topology without opening any underlying OSS dashboard.

## 7. Inventory and Agent Detail

### 7.1 Agents list

Default columns:

- Agent
- Owner
- Environment
- Runtime/platform
- Identity
- Effective capability risk
- Sensitive/high-impact reach
- Public/untrusted input
- Open findings
- Runtime policy coverage
- Last seen

Filters:

- owner/team
- environment
- risk
- identity type
- public exposure
- shell/code execution
- sensitive/high-impact reach
- runtime/sandbox type
- sensor/policy coverage
- active/inactive

Bulk actions are intentionally limited to assign owner, tag, export and create test/policy/ticket.

### 7.2 Agent detail

Header:

- name
- risk
- owner
- environment
- status
- first/last seen
- runtime policy coverage

Sections:

- Invoked by
- Identity
- Tools/MCP
- Runtime/sandbox
- Models/providers observed
- Sensitive/high-impact resources reachable
- Effective Capability
- Findings
- Attack Paths
- Sessions
- Policies

### 7.3 Effective Capability

MVP capability categories:

- read sensitive data
- write production resource
- execute code/shell
- access/use credential
- administer privileged system
- communicate to external destination

State:

- **Configured:** declared permission/tool configuration
- **Reachable:** graph/reachability supports the outcome
- **Observed:** runtime/provider evidence shows it occurred
- **Verified:** controlled test reproduced the security-relevant outcome
- **Blocked:** an enforced policy currently breaks the action at a supported enforcement point

Every capability shows the path and evidence source. Inferred relationships are labeled.

### 7.4 Tools & MCP

Show:

- server/tool identity
- owner
- local/remote
- agents using it
- authentication/credential method
- destructive/privileged capability
- observed usage
- approval/catalog status
- findings/tests
- runtime policy coverage

### 7.5 Identities

Show human/service/agent identities, credential type, agents using them, privilege, last use, resource reach and findings. Do not store raw credential values in graph/events.

### 7.6 Runtimes

Show provider/type, agents/sessions, isolation class, mounts, network/egress configuration, credential delivery method, privileged mode, sensor coverage and last execution.

## 8. Findings and Attack Paths

### 8.1 Finding detail UX

A finding page must answer in this order:

1. What is wrong?
2. Why does it matter here?
3. What evidence supports it?
4. Is there a path to material impact?
5. What is the smallest safe fix?
6. How can the customer verify the fix?

Primary actions:

- View path
- Verify safely when eligible
- Create Monitor/Block policy
- Assign owner
- Create generic ticket/webhook
- Accept risk with reason and expiry

### 8.2 Risk model

Risk is explainable and uses a small number of factors:

- weakness severity
- autonomy
- public/untrusted input
- identity privilege
- sensitive/high-impact reach
- observed behavior
- verified evidence
- current policy coverage
- environment criticality

Show top contributing factors, not an opaque score alone.

### 8.3 Attack path

Entry conditions include:

- public/untrusted input
- vulnerable/misconfigured agent or tool
- compromised/exposed credential
- unapproved remote MCP/tool

High-impact sinks include:

- production write/admin
- sensitive-data access
- credential store
- CI/CD control
- destructive SaaS/cloud action
- external exfiltration channel

Path states:

- Potential
- Observed
- Verified
- Blocked

The graph page has a small filter set, a center path view, and a right evidence panel. `Break Path` shows ranked small changes that remove or block the path.

## 9. Red Team and Attack Lab

### 9.1 Red Team

MVP target types:

- agent endpoint/test adapter
- MCP server/tool
- sandboxed coding-agent test target

Curated categories:

- direct prompt injection
- indirect prompt injection
- goal hijack/tool misuse
- sensitive-data extraction
- unsafe code/shell/tool chaining
- MCP/tool poisoning where applicable

The product recommends a small pack based on observed capabilities. Customers do not browse thousands of raw probes in MVP.

### 9.2 Red Team flow

1. Select target.
2. Product recommends pack and explains why.
3. Select Environment and safety mode.
4. Select test identity/credentials.
5. Product displays expected side effects and blocks unsafe production writes.
6. Run now or export CI configuration.
7. Results group by vulnerability/outcome, not raw prompts.

Each result shows attack objective, sequence, observed behavior, success criteria, evidence, affected capability, suggested fix and Attack Lab eligibility.

### 9.3 Attack Lab

Attack Lab answers: **Can the suspected high-impact path be reproduced safely?**

MVP reference provider is **EKS Fargate**.

- Installer creates a dedicated Attack Lab Fargate profile/namespace.
- Each verification run uses a fresh Fargate Pod/Job. AWS documents that each Fargate Pod has its own compute boundary and VM isolation.
- A local Docker/Kubernetes provider exists for non-hostile developer testing, but cannot produce a `Verified` verdict for hostile-code scenarios.
- Runs use dedicated test service accounts and canary/test credentials/resources.
- Production write credentials and production write targets are hard rejected.
- Egress is limited to the product egress proxy plus required cluster/AWS endpoints. Security groups provide L3/L4 containment; the product egress proxy provides per-run domain/HTTP allowlisting.
- Runs have timeout, CPU/memory and ephemeral-storage limits.
- Success criteria are explicit before execution.
- Evidence comes from semantic instrumentation, tool/runtime gateway, egress proxy, Kubernetes logs and controlled cloud/API side effects. MVP verification does not depend on eBPF inside Fargate Pods.

Verdicts:

- Verified
- Not Reproduced
- Inconclusive

Infrastructure or engine failure is Inconclusive, never Not Reproduced.

Result page:

- verdict and success criteria
- path/timeline
- tool/action sequence
- process evidence where available
- network destinations
- credential requests
- canary/test resource touched
- recommended policy/fix
- Re-run after fix

## 10. Runtime Protection

### 10.1 MVP outcomes

- Allow
- Monitor
- Block

Synchronous Require Approval for an application/runtime action, Redact and advanced rate-limits are P1. Security Agent response approvals are MVP because they are asynchronous control-plane actions and are required to bound autonomous response.

### 10.2 Enforcement points

MVP enforcement is product runtime gateway/proxy based for supported MCP/tool/API actions. Tetragon is observation-first in MVP.

The UI must distinguish:

- Enforced
- Monitor-only
- No supported enforcement point

### 10.3 Policy creation UX

1. Scope: Workspace, Environment, agent or tag.
2. Trigger: tool/API/MCP action or network destination supported by the gateway.
3. Conditions: agent, action risk, resource/destination, identity, environment.
4. Action: Monitor or Block.
5. Enforcement coverage: product shows where the policy can act.
6. Simulate against historical supported sessions.
7. Roll out in dry-run, selected Environment/agent set, then enforce.

Security teams do not write Rego. Product policy objects compile to internal OPA policy.

### 10.4 Reliability rule

Runtime gateways consume locally cached, signed policy bundles. New Stytch/Neon/PostHog/OpenRouter/remote-OTLP outages do not disable an already-deployed policy bundle.

## 11. Security Agents: Agentic Act & Enforce

### 11.1 Product purpose

Security Agents turn findings and runtime evidence into bounded response. They are not customer workload agents and are not a general agent-development platform. Their job is to evaluate a security situation, produce a transparent response plan, take only actions the customer has explicitly authorized, request approval when required, and verify the outcome.

The MVP loop is:

**Trigger -> Gather evidence -> Plan -> Deterministic authorization -> Auto-act or request approval -> Execute -> Verify -> Re-test or escalate -> Audit**

A Security Agent never receives raw cloud credentials or a general shell. The planner can select only typed product actions from the action catalog. The backend independently validates Organization, Workspace, Environment, target, action parameters, approval state and action budget before every side effect.

The MVP has two enforcement lanes:

- **Deterministic fast path:** runtime gateway + embedded OPA handles synchronous Allow/Monitor/Block decisions without an LLM.
- **Agentic response path:** Security Agents react asynchronously to findings, paths and runtime signals, reason about the evidence, and perform authorized response actions.

Security Agents must never be inserted into the synchronous request path for an application action in MVP.

### 11.2 MVP responder templates

Ship opinionated templates so customers get value without designing agents from scratch:

1. **Suspicious Egress Responder**: reacts to an agent reaching an unapproved destination, gathers session/path evidence, proposes a temporary destination or agent block, optionally starts verification, and notifies through the configured webhook.
2. **Credential Exposure Responder**: reacts to credential-access findings or suspicious credential use, contains the supported agent/session with a temporary Block policy, creates a ticket/webhook, and requests approval for any supported credential revocation action.
3. **Prompt/Tool Injection Responder**: reacts to a successful high-impact red-team result or Verified path, creates a scoped runtime Block policy, re-runs the test after enforcement, and escalates if the path remains exploitable.
4. **Repeated Policy Violation Responder**: reacts to repeated blocked high-risk actions from one session/agent, proposes temporary session/agent isolation and creates an evidence handoff.
5. **Shadow Agent Triage Responder**: reacts to an unmanaged or unowned agent, gathers identity/runtime/tool context, assigns a triage state, and opens a ticket/webhook without making destructive changes.

Templates are editable copies. Customers can also create a Security Agent with the same bounded builder.

### 11.3 Security Agent builder UX

**Protect -> Security Agents -> Create Security Agent**

Wizard:

1. **Start**: choose a built-in template or Blank bounded responder.
2. **Trigger**: finding family/severity, Attack Path state, runtime policy decision pattern, or Manual only.
3. **Goal**: short natural-language objective and optional operator guidance. This influences planning but never expands permissions.
4. **Scope**: Workspace, Environment, agents/tags, owners and allowed target classes.
5. **Allowed actions**: choose only from the product action catalog. The UI shows risk class, reversibility and whether an action is supported for the selected scope.
6. **Autonomy & approvals**: choose which allowed actions may auto-execute and which always require approval. Product safety floors can require approval even when the user asks for more autonomy.
7. **Limits**: maximum actions per run, maximum run duration, temporary-control TTL, AI token/cost budget and maximum concurrent runs.
8. **Verification**: select success conditions such as policy decision observed, test now blocked, destination unreachable through the gateway, integration disabled, or evidence handoff created.
9. **Simulate**: run against recent matching evidence without side effects and preview the proposed plan plus approval points.
10. **Enable**: save as disabled or enable for matching future triggers.

MVP custom Security Agents cannot add executable code, arbitrary HTTP endpoints, arbitrary shell commands, custom tool schemas or custom model providers. Expansion is a later product decision.

### 11.4 MVP action catalog

Keep the catalog small and high-value:

- create a temporary scoped Monitor or Block policy
- isolate a supported agent or session by applying a temporary deny policy through the runtime gateway
- run or re-run an existing Red Team test
- start safe Attack Lab verification when a configured non-production/test target is available
- create an evidence export or response bundle
- create a generic signed webhook/ticket handoff
- assign finding owner/response status or add a structured response note
- disable or revoke a product-managed long-tail integration connection only where the connector declares that action supported

Every action declares:

- input schema
- supported targets
- risk class
- minimum approval requirement
- reversible/irreversible
- idempotency behavior
- expected verification signal
- required product permission

The planner cannot invent actions or action parameters outside these schemas.

Temporary containment actions always require a TTL within product-defined bounds. Expiry is part of the action lifecycle, not best-effort cleanup. The platform must disable the temporary control idempotently, verify that cleanup occurred, and audit the result. If expiry cleanup cannot be verified, the Security Agent run and Home queue show Needs human until an operator resolves it.

### 11.5 Authorization and approval model

There are three independent boundaries:

**Definition boundary:** the Security Agent definition lists allowed scopes and actions.

**Product safety floor:** the platform can force approval or prohibit an action regardless of the definition. In MVP, destructive external-provider changes and supported credential/integration revocation require human approval. Product-native temporary policies, tests and evidence handoffs may be eligible for auto-execution when the customer explicitly enables them.

**Actor authorization:** the human who creates/enables the Security Agent must have permission for every enabled action class. An approver must be authorized for the target Workspace/Environment and pass fresh authentication for sensitive approvals.

Approval options:

- Approve this action once
- Deny
- Cancel the whole run

MVP does not implement standing approval grants or autonomous relaxation of policy.

### 11.6 Run and plan UX

Security Agent list shows:

- name/template
- enabled/disabled
- trigger
- scope
- autonomy level
- allowed actions
- last run/outcome
- pending approvals
- owner

Security Agent run detail shows:

- trigger and evidence snapshot
- planner rationale summary
- proposed ordered plan
- each step as Planned, Waiting approval, Running, Succeeded, Failed, Skipped or Verified
- deterministic authorization result for every step
- approver and decision where applicable
- action result and rollback/TTL state
- verification evidence
- final outcome: Contained, Remediated, Needs human, Failed, Inconclusive or Cancelled
- model/provider, template version, redaction policy, token/cost metadata and plan hash

The UI must clearly distinguish **AI plan/rationale** from **deterministic authorization and observed execution evidence**.

### 11.7 Planner safety and prompt-injection resistance

The planner runs through the product OpenRouter gateway with structured output. Evidence is treated as untrusted data, not instructions.

MVP requirements:

- build planner input from bounded product-generated summaries and evidence references, metadata-first by default
- redact prohibited secrets/PII/PHI according to Organization data policy before AI egress
- separate system policy, operator goal and untrusted evidence fields
- require structured plan output against a versioned schema
- reject unknown action names, unknown targets, malformed arguments and references outside authorized scope
- never expose provider credentials, Nango secrets, Stytch secrets, raw policy-signing keys or arbitrary network access to the planner
- cap steps, duration, concurrency and token/cost budget
- stop the run on unexpected execution results instead of letting the planner improvise an unbounded recovery path
- record the exact evidence IDs used to plan so the run is reproducible and auditable

If OpenRouter is unavailable, disabled or disallowed by Organization data policy, new Security Agent planning does not execute. The run becomes Planner unavailable/Paused and deterministic runtime policies continue unchanged.

### 11.8 Temporary containment lifecycle

Temporary Monitor/Block policies and session isolation created by Security Agents have a bounded TTL and explicit owner/run reference. The product worker claims expired controls, disables them idempotently, verifies the effective policy bundle no longer contains the control, and records cleanup evidence. Cleanup failures never silently disappear; they surface on the Security Agent run, Home and System Health until reconciled.

### 11.9 Verification is mandatory

A Security Agent run is not successful merely because an API call returned 200.

Each action has an expected verification signal. Examples:

- temporary Block policy -> observe matching policy decision or successful bundle publication
- isolation -> confirm the scoped agent/session is denied at the supported gateway
- re-test -> test result changes from vulnerable/verified to blocked or not reproduced for the expected reason
- integration disable/revoke -> provider/connection status confirms disabled/revoked
- webhook/ticket -> signed delivery acknowledgement exists

The run ends **Contained/Remediated** only when the configured verification condition passes. Otherwise it is Needs human, Failed or Inconclusive.

### 11.10 User stories and acceptance criteria

**SA-1, Build a responder:** As a Security Engineer, I can create a responder from a template or bounded blank builder so repetitive agent-risk response does not require a new playbook or code deployment.  
**Acceptance:** I can configure trigger, goal, scope, allowed actions, approval rules, limits and verification, simulate it, and enable it without entering executable code.

**SA-2, Safe autonomy:** As a Security Admin, I can allow reversible containment to run automatically while forcing riskier actions through approval.  
**Acceptance:** product approval floors cannot be disabled, and an approval-required step never executes without an authorized fresh-auth decision.

**SA-3, Understand the plan:** As a SOC/AppSec analyst, I can see why the Security Agent proposed each action and separately see the deterministic authorization result.  
**Acceptance:** AI rationale, authorization, action result and verification evidence are visually distinct.

**SA-4, Verify outcome:** As a security owner, I can trust that a run marked Contained or Remediated actually changed the security condition.  
**Acceptance:** terminal success requires an observed verification signal or linked re-test result, not only an API success response.

**SA-5, Audit automated response:** As GRC/auditor, I can reconstruct who configured the automation, what evidence triggered it, what the model proposed, what the platform authorized, who approved, what executed and what verification proved.  
**Acceptance:** the complete chain is exportable without exposing secrets or raw model credentials.

### 11.11 MVP user flow: agentic response

**Actor:** Security Engineer / Policy Manager

1. A high-risk finding or Verified path matches an enabled Security Agent trigger.
2. Product snapshots the canonical finding, path, agent, session and current policy evidence.
3. Planner creates a bounded response plan using only the agent's allowed actions.
4. Backend validates every proposed action against scope, action schema, product safety floor and current authorization.
5. Auto-approved low-risk steps execute.
6. Any step requiring approval appears in **Protect -> Approvals** with reason, target, expected side effect and rollback/TTL information.
7. Authorized approver approves or denies with fresh auth when required.
8. Executor performs the action idempotently and records result.
9. Verifier checks the expected security outcome and optionally re-runs the linked test.
10. Run detail shows final containment/remediation status and every audit event.

**Customer value:** reduce time-to-containment and repetitive analyst work without giving another AI system unrestricted authority.

## 12. Sessions and Investigation

A session timeline combines available evidence:

- initiating principal
- task/objective if instrumented
- model/provider metadata if collection permits
- tool/MCP calls
- runtime/sandbox execution
- process/file/network evidence where available
- credential-use evidence
- provider/API actions
- policy decisions
- controlled side effects

Correlation confidence:

- Exact
- Strong
- Probable
- Unattributed

The UI never presents inferred attribution as fact.

MVP search uses structured filters, not a custom query language. Filters include agent, principal, tool, process, file, domain, credential fingerprint, resource, policy decision and time.

## 13. Integrations

### 13.1 Core launch integrations

Deep support:

- AWS
- Kubernetes
- GitHub
- Okta **or** Microsoft Entra ID, with the second IdP added immediately after design-partner demand proves priority

Agent/model/tool context comes from runtime/OTel/gateway observation and provider APIs where useful.

### 13.2 Connector strategy

Use three mechanisms behind one catalog:

1. Cartography/native collection for inventory and relationships.
2. Prowler for cloud posture/compliance evidence.
3. Nango free self-hosted for long-tail Auth + Proxy only.

The free self-hosted Nango edition is intentionally narrow. MVP does not depend on Nango Functions, Webhooks, MCP server, RBAC, full observability or Enterprise-only runtime features. Core launch connectors bypass Nango and continue working if Nango is unhealthy.

A long-tail connector built with Nango Proxy still requires product code to call provider APIs and normalize security semantics. OAuth availability is not marketed as full connector depth.

### 13.3 Connection UX

The launch provider setup wizard is defined in Section 6.3. Every provider uses the same customer mental model even when the underlying authentication mechanism differs. Provider-specific configuration is rendered from product-owned setup metadata and validated server-side.


Each card shows:

- Connected / Degraded / Disconnected
- scope
- last successful sync
- freshness
- credential health
- data collected
- resources/identities discovered
- relevant findings
- available response/actions

Internal connector implementation is never shown.

## 14. Enterprise Identity and Administration

### 14.1 Tenant model

SaaS v1 is multi-tenant. One authenticated customer maps to one product Organization, and a SaaS control plane serves many Organizations.

`Organization -> Workspace -> Environment`

- Organization: tenant and commercial/security boundary
- Workspace: product/business/security boundary inside an Organization
- Environment: production/staging/development/custom

Every transactional row, event document, graph node/edge, artifact reference, queue job and API authorization context carries Organization scope. Customer APIs derive Organization from authenticated identity rather than accepting an arbitrary tenant ID from the browser.

Single-tenant mode uses the same data model and APIs, but the deployment is pinned to one Organization and receives dedicated infrastructure. This is a deployment topology choice, not a separate product or authorization model.

Tenant isolation is a release blocker for SaaS. Cross-Organization API, search, graph, artifact and background-job access must fail server-side. Per-Organization quotas and bounded workloads protect against noisy neighbors.

### 14.2 Stytch

Use Stytch B2B for:

- SAML/OIDC SSO
- SCIM provisioning/deprovisioning
- sessions/MFA policies where supported
- coarse organization roles

Normal read/navigation requests may use recent locally validated Stytch session JWTs. Sensitive administration and protection mutations, such as SSO changes, API-token creation and policy enforcement, require fresh Stytch session revalidation and fail closed if that revalidation is unavailable. This limits the short JWT revocation window without putting Stytch on the autonomous runtime enforcement path.

Product-owned Neon state stores Workspace/Environment grants.

Built-in roles:

- Organization Admin
- Security Admin
- Security Engineer
- Developer/Owner
- Compliance Viewer
- Read-only Viewer

Custom roles are P1 unless a design partner proves they are a deployment blocker.

### 14.3 Recovery

In SaaS, emergency administrative recovery is an AgentSec operator procedure with tightly restricted, audited production access and does not create a customer-facing bypass login. In single-tenant deployments, `agentsecctl` provides a deployment-scoped recovery path. Neither mode introduces a second everyday authentication system.

### 14.4 API access

Product-owned scoped API tokens support service automation, expiry, rotation/revocation and audit history. They are authorized through the same Workspace/Environment permission model.

## 15. Data Security and Compliance Readiness

### 15.1 Collection modes

**Metadata only, default for production:** no raw prompts/responses. Store model/tool/action metadata, hashes/lengths where helpful, policy outcome and provider classifications.

**Redacted evidence:** store bounded security-relevant snippets after redaction.

**Full approved content:** explicit Environment opt-in, limited roles and retention.

Collection policy is applied before durable storage.

### 15.2 External data flows

Administration -> External Data Flows lists:

- Stytch
- Neon
- PostHog
- OpenRouter
- Grafana Cloud or New Relic OTLP destination

For each show purpose, required/optional status, data categories, enablement, connection health and last success.

Raw prompts, security telemetry, secrets, graph evidence, sandbox artifacts and runtime policy payloads never go to PostHog.

OpenRouter receives only explicitly requested, redacted AI-assistance payloads. It is disabled by default in regulated profiles unless approved.

### 15.3 HIPAA-ready deployment profile

The product does not claim that installation makes a customer HIPAA compliant.

For workloads that may process ePHI:

- SaaS HIPAA mode is offered only after AgentSec's AWS environment and every subprocessor that can receive ePHI are covered by appropriate BAAs and configured for eligible services; single-tenant customer-hosted deployments additionally require the customer's AWS BAA and eligible-service configuration
- Stytch requires the applicable HIPAA/BAA contractual coverage if customer/legal review determines ePHI could reach the identity service; otherwise limit Stytch payloads to non-ePHI authentication/workforce metadata
- Neon must use its HIPAA/BAA configuration if ePHI could reach Neon
- production collection defaults to metadata-only
- encryption in transit and at rest
- least-privilege access and Workspace scoping
- audit logs
- backup/recovery procedures
- retention/deletion controls
- PostHog off unless specifically approved and no PHI is sent
- OpenRouter off unless contractual/data-policy review approves it; ZDR is not treated as a BAA
- remote OTLP off unless the customer approves the backend and exported fields

The current HHS Security Rule is the baseline. The 2025 Security Rule update remains proposed as of this audit date, so forward-looking safeguards may be adopted as hardening but are not represented as current law.

### 15.4 SOC 2 readiness

The product and company program need:

- access control and deprovisioning
- audit logging
- change/release controls
- vulnerability/dependency management
- incident-response process
- backup and recovery testing
- encryption/secrets management
- vendor/subprocessor inventory
- monitoring/alerting
- secure development/code review
- documented retention/deletion

A SOC 2 Type II report requires an audit observation period. MVP readiness means controls, owners and evidence collection exist, not that a Type II report can be produced immediately.

The customer-facing Compliance page is an evidence view, not a GRC authoring system. MVP maps product evidence to SOC 2 Security Trust Services Criteria and HIPAA Security Rule safeguard areas. More frameworks are P1.

## 16. Technology Constraints

### Required

- **Stytch B2B:** authentication, SSO, SCIM, sessions, coarse organization roles
- **Neon Postgres:** relational control-plane state
- **AWS:** EKS, S3, KMS, Secrets Manager, SQS, OpenSearch Service, IAM/STS, ECR and load balancing as required
- **LocalStack:** AWS emulation for local/CI where supported; real AWS remains release-parity authority
- **OpenTelemetry:** in-cluster Collector and service instrumentation

### Optional/non-critical

- **PostHog:** allowlisted usage analytics and non-security-critical feature flags
- **OpenRouter:** Security Agent planning plus optional AI explanations. It is required only when those AI features are enabled and is never on deterministic runtime allow/block paths.
- **Grafana Cloud or New Relic:** remote OTLP destination

### OSS reuse

- Cartography for relationship inventory
- Prowler for cloud posture/compliance evidence
- Tetragon for eBPF runtime observation
- Nango free self-hosted for Auth + Proxy only
- Promptfoo for MVP red-team orchestration
- OPA Go SDK for runtime policy evaluation
- OCSF as the event-normalization reference

Garak and selected Akto OSS content are P1 enrichment, not architectural dependencies.

## 17. Reference Deployment and Operations

### 17.1 SaaS reference, primary v1 mode

AgentSec-managed AWS:

- multi-AZ EKS for product web/API/workers and SaaS event ingestion
- shared managed AWS services with strict Organization scoping: SQS/DLQ, OpenSearch Service, S3/KMS, Secrets Manager and IAM/STS
- Neon for transactional product state
- Stytch B2B for authentication and Organization identity lifecycle
- internal Nango free self-hosted service for long-tail Auth + Proxy only
- rebuildable graph store behind the product GraphStore interface
- OpenTelemetry Collector
- PostHog, OpenRouter and remote OTLP only under the product data-egress rules

Customer environment, when runtime visibility or enforcement is needed:

- lightweight sensor/runtime Helm package
- Tetragon on supported Linux/Kubernetes nodes
- runtime gateway with locally cached signed policy bundles
- optional semantic OTLP/gateway adapters
- Attack Lab runner/profile in a customer test AWS environment when verification requires private assets, or an AgentSec-managed isolated test environment when the test can be safely reproduced without customer-private dependencies

Customer-side runtime enforcement must continue from cached signed policy when the SaaS control plane or internet connection is temporarily unavailable.

### 17.2 Single-tenant reference

The same application images, APIs, schemas and UI can be deployed into a dedicated AWS topology, either AgentSec-managed dedicated infrastructure or customer-hosted/BYOC where contracted. The deployment uses a single-tenant values profile and is pinned to one Organization. No enterprise-only fork or separate feature implementation is allowed.

Single-tenant reference components include EKS, SQS/DLQ, OpenSearch Service, S3/KMS, Secrets Manager, IAM/STS, graph store, Nango free internal service, OTel Collector and the same optional runtime/sensor components. Stytch and Neon remain the selected connected v1 dependencies unless a later no-egress edition replaces them behind existing interfaces.

### 17.3 Storage responsibilities

**Neon:** transactional control-plane state, policies, findings, tests, audit index/events, settings and identity links. In SaaS every row is Organization-scoped; selected critical tables add database-level tenant isolation controls in addition to application authorization.

**OpenSearch:** searchable runtime/semantic events and session timelines. All documents carry Organization scope and queries are constructed only through the scoped EventStore abstraction.

**Graph store:** rebuildable relationship graph and derived path/capability projections. Every node/edge is Organization-scoped and direct customer graph queries are not exposed.

**S3:** evidence artifacts, exports, signed policy/content bundles, compressed normalized runtime-event batch archives within configured retention, and backup/recovery artifacts where applicable. SaaS objects use Organization-scoped prefixes and product authorization; dedicated deployments use dedicated storage. OpenSearch is a query projection and can be rebuilt from retained S3 event batches.

**SQS:** durable background jobs and batched normalized runtime events. Every message carries Organization scope. Do not enqueue one message per syscall.

### 17.4 Nango operational boundary

The free self-hosted Nango edition is used only for Auth + Proxy. Product-owned code handles security semantics and provider API reads. Nango is not on the core discovery or runtime enforcement path. SaaS runs it as a private internal service; single-tenant deployments package the same internal service. Use a separate Nango database/schema and encryption key and do not expose its dashboard/log stack as product operation.

### 17.5 SaaS disaster recovery

MVP uses a simple recoverable single-region architecture, not active-active multi-region infrastructure. The initial customer-facing recovery objectives are **RPO <= 1 hour** and **RTO <= 4 hours** for the SaaS control plane, validated by rehearsal before GA. If measured recovery cannot meet those objectives, the published objective must be corrected before GA rather than hidden.

Recovery sources:

- Neon managed recovery/PITR capabilities for transactional product state
- S3 versioned/durable evidence, export, policy and normalized runtime-event archives
- infrastructure recreated from Terraform/Helm and signed release artifacts
- OpenSearch rebuilt from retained S3 normalized event archives
- graph projection rebuilt from canonical inventory/connector sources plus retained evidence

Runtime gateways in customer environments continue enforcing the last valid signed policy bundle during SaaS recovery according to the documented bundle failure policy. No MVP requirement for active-active regions, global database replication, or a second message bus is introduced.

## 18. Reliability and Scalability

### 18.1 Critical-path rules

- runtime gateway uses cached signed policy bundles
- no PostHog, OpenRouter or remote OTLP call on runtime allow/block path
- every external call has a deadline
- retry only transient failures
- bounded concurrency and queues
- idempotency keys for mutating/background workflows
- no destructive action retry unless idempotent or prior outcome is verified
- stale/degraded states are visible
- security event drops are measurable

### 18.2 Degraded behavior

**Stytch unavailable:** new login/identity administration degrades. Runtime enforcement, sensors and background security processing continue. Locally verifiable sessions remain subject to normal expiry and are never silently extended.

**Neon unavailable:** control-plane reads/writes that need Neon fail fast. Runtime enforcement continues from local policy bundle. Background workers pause/retry idempotently where state mutation is required.

**Nango unavailable:** only long-tail connection authorization/proxy actions degrade. Core AWS/Kubernetes/GitHub/IdP connectors remain functional.

**PostHog unavailable:** analytics may be dropped after a small bounded buffer; flags use cached/default values.

**OpenRouter unavailable:** new Security Agent planning and AI explanations are unavailable. Pending Security Agent runs stop before any new unplanned side effect; deterministic findings, tests and runtime policy remain functional.

**Remote OTLP unavailable:** Collector uses bounded retry; product security readiness is unaffected.

**OpenSearch unavailable:** event search/timeline is Degraded; runtime enforcement continues and event batches remain in bounded durable queues until retry/retention limits.

**Neo4j unavailable:** path/capability views are Degraded; basic inventory/finding workflow remains from product state.

**SQS unavailable:** new background/event jobs fail fast after a small bounded local buffer; runtime enforcement does not depend on SQS.

### 18.3 MVP performance floors

Do not set venture-scale targets without customer evidence.

Initial reference gates:

- metadata-only runtime policy p95 <= 25 ms in-cluster
- normal control-plane API p95 <= 750 ms for non-graph reads under reference load
- bounded graph neighborhood/path query <= 3 seconds for supported query limits
- event pipeline demonstrates at least 5,000 relevant normalized events/sec on published reference hardware, then must pass >= 2x the highest measured design-partner peak before GA
- sensor overhead is measured on representative workloads; do not claim a universal fixed percentage until validated
- no unbounded queue, request concurrency or query depth

## 19. End-to-End User Flows

### Flow A: SaaS onboarding and discover

**Actor:** Security Admin

1. Sign in to AgentSec SaaS through Stytch-backed SSO.
2. Confirm Organization, Workspace and Environment.
3. Connect AWS, Kubernetes, GitHub and IdP.
4. Deploy the customer-side runtime sensor/gateway Helm package only where runtime coverage is required.
5. Watch integration/sensor progress and freshness.
6. Open Agents inventory.
7. Open first high-risk agent/path.
8. Assign owner or create ticket/webhook.

**Value:** useful agent risk quickly without deploying the control plane or requiring agent SDK changes.

### Flow B: Understand blast radius

**Actor:** Cloud Security Engineer

1. Search for agent.
2. Open Agent detail.
3. Review Effective Capability.
4. Select `write production` or `use credential` capability.
5. See identity/tool/runtime/resource chain and evidence state.
6. Open linked attack path.
7. Review smallest `Break Path` options.
8. Create Monitor policy or ticket.

**Value:** prioritization by real reachable outcomes rather than isolated misconfiguration.

### Flow C: Red team and safely verify

**Actor:** AppSec Engineer

1. Select staging agent.
2. Product recommends curated test pack.
3. Run red team.
4. Open successful high-impact attempt.
5. Click Verify safely.
6. Review Fargate Attack Lab safety plan and test credentials.
7. Run verification.
8. Observe canary/test side effect.
9. Finding/path becomes Verified only if exact success criteria are met.
10. Create Block policy.
11. Simulate/dry-run and enable.
12. Re-run test.
13. Path becomes Blocked when policy evidence proves it.

**Value:** convert plausible risk into proof, then prove the fix.

### Flow D: Agentic Act & Enforce

**Actor:** Security Engineer / Policy Manager

1. Enable a built-in Security Agent template or create a bounded responder.
2. Select trigger, goal, scope, allowed actions, approval rules, limits and verification criteria.
3. Simulate against recent matching evidence and inspect the proposed plan.
4. Enable the Security Agent.
5. A high-risk finding, Verified path or matching runtime signal triggers a run.
6. Product snapshots evidence and the planner proposes a typed response plan.
7. Deterministic authorization validates each step.
8. Safe auto-approved actions run; higher-risk action waits in Protect -> Approvals.
9. Approver approves or denies with fresh auth when required.
10. Product verifies each executed action and re-tests the linked risk where applicable.
11. Run ends Contained/Remediated only when verification passes.
12. Session, finding/path and audit evidence link to the Security Agent run.

**Value:** faster response with transparent, customer-bounded autonomy rather than an unrestricted remediation bot.

### Flow E: Investigate a session

**Actor:** Security/SOC Analyst

1. Open a high-risk session from Agent or Finding.
2. Timeline shows principal, task/tool activity, runtime evidence, credential/network/resource actions and policy decisions.
3. Each row shows source and correlation confidence.
4. Analyst filters to file/network/credential events.
5. Analyst exports evidence or hands off through webhook/ticket.
6. Create temporary Block policy if needed.

**Value:** agent-aware evidence without replacing the customer's SIEM.

### Flow F: Identity lifecycle

**Actor:** Enterprise Admin

1. Configure SAML/OIDC in product UI.
2. Test sign-in.
3. Configure SCIM in product UI.
4. Map IdP groups to built-in role and Workspace grants.
5. Test user signs in.
6. Admin deprovisions user in IdP.
7. Stytch event removes product grants within documented window.
8. Audit log shows external identity event and internal authorization result.

**Value:** enterprise access follows existing identity governance.

### Flow G: Compliance evidence

**Actor:** GRC/Compliance

1. Open Compliance -> Evidence.
2. Choose SOC 2 Security or HIPAA safeguard view.
3. Filter production Workspace/Environment.
4. Review evidence freshness and gaps.
5. Export evidence package.
6. Evidence links back to current assets, findings, policies, tests and audit events.

**Value:** reduce manual evidence collection without claiming automated compliance.

### Flow H: Day-to-day security operations

**Actor:** AI Security / Cloud Security Engineer

1. Open Home and work the **Needs attention** queue.
2. Review new/worsening critical exposures and Verified paths first.
3. Resolve pending Security Agent approvals before expiry.
4. Open Security Agent runs in Needs human, Failed or Inconclusive and inspect the exact failed plan/action/verification step.
5. Resolve stale/degraded launch integrations or sensor coverage before trusting a clean finding count.
6. For each material risk, choose the smallest appropriate next step: assign, test, verify, create policy, run/enable responder, approve/deny, or hand off through the configured signed webhook.
7. Confirm Contained/Remediated outcomes and re-test status.
8. Leave Home with no hidden critical item: remaining risk is explicitly assigned, accepted with expiry, waiting for approval, or marked degraded with a next action.

**Value:** one understandable daily operating queue instead of requiring analysts to patrol every product module.

## 20. Product Metrics

### Customer value

- time from successful core connection to first useful inventory
- percent of active agents with owner
- percent with identity/runtime attribution
- percent of critical findings linked to evidence-backed path
- percent of critical paths with Observed or Verified evidence
- median time from finding to policy/ticket
- re-test closure rate after fix/policy
- median high-risk finding/path to first Security Agent plan
- median trigger to verified containment for Security Agent runs
- percent of Security Agent actions auto-executed vs approval-required
- Security Agent verification success, failure and Inconclusive rates
- approval deny/cancel rate and rollback/TTL expiry correctness
- percent of supported production agents with runtime policy coverage

### Product quality

- connector freshness/sync success
- sensor coverage and drop rate
- correlation confidence distribution
- false-positive feedback by rule family
- Attack Lab inconclusive rate and reason
- policy simulation-to-rollout rollback rate
- Security Agent plan validation rejection rate and reason
- Security Agent action execution/verification error rate
- oldest pending Security Agent approval age
- first-admin bootstrap-to-SSO success rate
- launch connector Test Connection and initial-sync success rate by provider
- SaaS onboarding/connection success rate and single-tenant install/preflight success rate
- Home Needs-attention queue age by critical exposure, approval and failed responder category
- temporary-control expiry cleanup success and oldest unresolved cleanup failure

Do not optimize for raw probes, connectors, findings or graph-node counts.

## 21. MVP Release Gates

MVP is enterprise-ready only when all gates pass:

1. SaaS golden flow passes: first-Admin bootstrap -> corporate SSO setup -> connect launch systems -> discover -> path -> red team -> Attack Lab -> Security Agent plan -> deterministic authorization -> auto-action/approval -> verified containment -> temporary-control expiry where applicable -> re-test -> session/audit. The same product flow also passes in the single-tenant deployment profile.
2. SSO, SCIM deprovisioning, built-in RBAC, Workspace scoping and recovery procedure pass.
3. Collection mode, retention, deletion, export, external-data-flow and secret-redaction tests pass.
4. Required/optional dependency failure tests show no silent security downgrade.
5. SaaS disaster recovery and single-tenant backup/restore are rehearsed. SaaS measured recovery meets the published MVP RPO/RTO objectives, and upgrade rollback is rehearsed.
6. Authorization isolation, SSRF, secret leakage, policy bypass, sandbox guardrails and image/dependency scans pass.
7. SOC 2 control owner/evidence plan exists; HIPAA profile and BAA/dependency checklist are documented and tested where applicable.
8. Every interactive UI flow has a documented OpenAPI operation and automated UI-to-API coverage check.
9. SaaS operators can deploy/upgrade/diagnose/recover the hosted service, and a platform engineer can install/diagnose the single-tenant profile, without opening OSS dashboards for normal operation.
10. Security Agent security tests prove untrusted evidence cannot expand the action catalog, cross tenant boundaries, bypass approval floors, access credentials, or execute out-of-scope actions. Planner/provider outage must fail safe without changing deterministic runtime policy.
11. First-admin bootstrap plus AWS, Kubernetes, GitHub and launch-IdP setup flows pass usability tests with actionable permission and failure guidance.
12. Temporary Security Agent controls expire, clean up, verify and audit correctly; cleanup failure becomes visible work rather than silent drift.
13. Home provides a complete daily Needs-attention queue for critical exposure, approvals, failed/Needs-human responder runs and stale coverage.
14. At least two design partners say verified-path/runtime evidence plus bounded automated response reduced time or effort to contain a real agent-risk scenario. If not, do not add more surface area to compensate.

## 22. Roadmap After MVP

Prioritize by observed customer friction:

1. Synchronous inline runtime approvals for application actions beyond the asynchronous Security Agent response approval queue.
2. Least-privilege recommendations after sufficient observation history.
3. Built-in incident response only if customers prefer it to SIEM/SOAR handoff.
4. Deeper Azure/GCP and more SaaS/data connectors.
5. More Attack Lab providers and coding-agent endpoint hooks.
6. Extensible Security Agent action SDK/custom tools only after the fixed MVP action catalog is proven safe and valuable.
7. Expanded compliance frameworks.
8. Select API-security/supply-chain features when they materially improve an agent path.
9. Deep data provenance only for validated exfiltration/DLP use cases.

## 23. Current Source Audit

Verified against primary/current sources carried forward from the August 11, 2026 audit; no new external dependency assumptions are introduced by the Security Agent design.

- Stytch B2B Organizations, SSO, SCIM, sessions and RBAC: https://stytch.com/docs/
- Stytch currently lists HIPAA/BAA under Enterprise: https://stytch.com/pricing
- Neon Postgres pooling, security and HIPAA/BAA support: https://neon.com/docs/ and https://neon.com/security
- AWS HIPAA Eligible Services: https://aws.amazon.com/compliance/hipaa-eligible-services-reference/
- EKS Fargate isolation: https://docs.aws.amazon.com/eks/latest/userguide/fargate.html
- EKS security groups for Pods: https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html
- EKS native NetworkPolicy limitation for Fargate: https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html
- HHS HIPAA Security Rule: https://www.hhs.gov/hipaa/for-professionals/security/
- AICPA Trust Services Criteria: https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
- OpenTelemetry Collector: https://opentelemetry.io/docs/collector/
- OpenRouter privacy/ZDR/routing: https://openrouter.ai/docs/
- PostHog analytics/feature flags and Trust Center: https://posthog.com/ and https://trust.posthog.com/
- LocalStack AWS service emulation: https://docs.localstack.cloud/aws/services/
- Cartography: https://github.com/cartography-cncf/cartography
- Prowler: https://github.com/prowler-cloud/prowler
- Tetragon: https://github.com/cilium/tetragon
- Nango: https://github.com/NangoHQ/nango and https://nango.dev/docs/guides/platform/self-hosting
- Promptfoo: https://github.com/promptfoo/promptfoo
- Open Policy Agent: https://www.openpolicyagent.org/docs

## 24. Assumptions and Residual Risks

- SaaS multi-tenancy materially raises the bar for tenant isolation. Cross-Organization access tests across Neon, OpenSearch, graph, S3, queues and support/operator workflows are release blockers, not post-launch hardening.
- Single-tenant deployment must use the same release artifacts and public APIs as SaaS. Any feature that requires a dedicated code fork is rejected.

- Nango ELv2 internal embedding is treated as permitted based on the user's stated interpretation, but counsel should review exact distribution before commercial launch.
- MVP depends only on Nango free self-hosted Auth + Proxy. Core connectors do not depend on Nango.
- Neo4j packaging/redistribution licensing must be reviewed. The product keeps a GraphStore abstraction.
- EKS Fargate provides a stronger per-Pod VM-backed boundary, but Attack Lab still requires defense-in-depth, test credentials, egress controls and explicit success criteria.
- OpenRouter ZDR is a data-retention control, not a substitute for a BAA or legal review.
- Compliance mappings support customer programs and our evidence collection. They do not certify customers.
- SaaS MVP disaster recovery is backup/restore and rebuild based, not active-active multi-region. Published RPO/RTO must reflect measured rehearsals.
- Current competitors may add similar capabilities. Differentiation depends on workflow quality and execution depth.

## 25. Final Product Decision

**Build the MVP.**

The customer problem is coherent and timely, but the product should not launch as a broad checklist. The MVP proves one valuable enterprise loop, including bounded agentic response:

**onboard quickly, discover an agent, understand credible impact, safely validate it, let a bounded Security Agent plan and take an authorized response, verify containment, and audit the result.**

Everything in P0 either enables that loop or is required to deploy it safely. Everything else waits for customer evidence.
