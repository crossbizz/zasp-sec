# ZaspOps Product Requirements Document

**Product:** ZaspOps  
**Category:** AI-native enterprise context and governed operations platform
**Initial market:** Infrastructure-intensive companies operating shared cloud, Kubernetes, GPU, identity, and service-management environments  
**Document status:** Product definition and MVP specification  

## Executive summary

ZaspOps helps enterprise operations teams understand impact, resolve requests, govern human and agent access, and execute changes using live enterprise context. Infrastructure operations are the initial market wedge, not the boundary of the platform.

The product is built around an **Enterprise Context Layer** that connects people, AI agents, applications, infrastructure, identity, usage, work, and policy systems into a continuously updated graph. ZaspOps uses this graph to answer questions, calculate impact, evaluate access and policy, govern agents, optimize application usage, enrich operational work, and prepare actions with verifiable evidence.

Every recommendation or action includes a **Proof Record** showing:

- the facts used;
- the authority and freshness of each source;
- applicable policy and approval requirements;
- affected resources, services, tenants, and users;
- confidence and unresolved conflicts;
- execution scope, verification steps, and rollback plan.

ZaspOps initially layers over existing systems such as ServiceNow, Jira Service Management, Slack, Microsoft Teams, Okta, Kubernetes, Datadog, and PagerDuty. It does not require customers to replace their ITSM, IAM, or observability platforms.

The MVP focuses on four high-value workflows:

1. Infrastructure investigation and blast-radius analysis.
2. Policy-aware, time-bound access requests.
3. Employee self-service and service-request intake.
4. Incident enrichment and operator-assisted diagnosis.

The first design-partner release delivers the first two workflows. Employee self-service and incident enrichment are added after the core context, policy, and action controls meet production gates.

The long-term product becomes the trusted context, identity, and action substrate for enterprise operations across infrastructure, SaaS applications, AI agents, and future domain packs. Agents may be provided by ZaspOps, built by the customer, or delivered by another vendor, but they use the same identity, policy, evidence, and action controls.

## Product vision

Make every enterprise operational decision and agent action explainable, policy-aware, and safe to execute.

ZaspOps should become the system through which people and AI agents understand:

- what an enterprise resource, application, service, or agent is;
- who owns and uses it;
- what depends on it;
- who can access it;
- what an agent is permitted to know, use, spend, and change;
- whether an application or license is being used appropriately;
- what policies govern it;
- what recently changed;
- what will be affected by an action;
- whether the action is authorized;
- whether the intended outcome was achieved.

## Customer problem

Infrastructure operations are distributed across tools that each contain only part of the truth. A single investigation may require an operator to search an ITSM ticket, inspect Kubernetes, query an observability platform, check an identity provider, review a runbook, contact a service owner, and compare the result with a policy document.

This fragmentation creates five recurring problems:

- **Slow investigations:** Operators spend significant time collecting context before they can diagnose an issue or assess blast radius.
- **Incomplete decisions:** Important dependencies, tenant relationships, ownership data, or recent changes are easy to miss.
- **Unsafe automation:** General-purpose agents can propose or execute actions without proving that their context is fresh, authoritative, complete, or policy-compliant.
- **High service burden:** Employees use chat for help, but requests still become manually triaged tickets because the assistant cannot safely take action.
- **Weak auditability:** Logs show what happened after execution, but reviewers cannot easily reconstruct why an action was considered safe when it was approved.

These problems are especially acute in infrastructure-intensive environments where shared clusters, network fabrics, capacity reservations, privileged access, customer tenants, and compliance boundaries create interconnected risk.

## Goals

### Customer goals

- Reduce the time operators spend collecting context for supported investigations by at least 40% within 90 days of production launch.
- Resolve at least 30% of enabled employee-service requests without manual service-desk handling within 60 days.
- Reduce manual handling time for supported access requests by at least 50% within 90 days.
- Ensure every supported write action has visible evidence, policy evaluation, approval status, verification, and rollback or escalation behavior.
- Let a customer deploy ZaspOps over its existing stack without replacing its ITSM, IAM, observability, or collaboration systems.

### Business goals

- Put the first design partner into production within eight weeks of connector access.
- Convert at least three design partners into paid production customers.
- Expand at least half of production customers from one workflow to three workflows within six months.
- Establish ZaspOps as the infrastructure context and governed-action layer, not as a generic service-desk chatbot.
- Create a reusable integration, entity, policy, and action foundation that reduces the marginal cost of each new workflow.

## Target customers

### Initial ideal customer profile

- 500–10,000 employees.
- Dedicated infrastructure, platform, IT operations, IAM, and security teams.
- Operates Kubernetes, cloud infrastructure, or GPU/accelerated-computing environments.
- Uses Slack or Microsoft Teams for employee and operator collaboration.
- Uses an established ITSM or ticketing system.
- Uses a centralized identity provider.
- Has at least one observability and one incident-management platform.
- Experiences meaningful on-call load, access-request volume, or audit requirements.
- Prefers augmentation of existing systems over a disruptive replacement program.

### Initial vertical wedge

The initial wedge is AI infrastructure and GPU cloud operations, including:

- GPU cloud providers;
- AI model and inference platforms;
- enterprises operating large internal GPU fleets;
- managed Kubernetes and high-performance computing providers;
- infrastructure platforms with multi-tenant capacity, strict access boundaries, or regulated customers.

### Expansion markets

The horizontal platform must support additional domain products without replacing the core graph, identity, policy, Proof Record, or action runtime:

- **SaaS operations:** Application discovery, usage, permissions, license optimization, renewal context, and employee access lifecycle.
- **Agent operations:** AI-agent identity, ownership, delegated authority, tools, data access, budgets, coworkers, evaluations, and action governance.
- **Security operations:** Asset and identity investigations, control evidence, access review, and response coordination.
- **Regulated operations:** Domain packs for healthcare, financial services, public sector, and other environments requiring specialized entities, policies, and evidence.
- **Enterprise service operations:** Additional IT, HR, finance, legal, procurement, and facilities workflows after the platform establishes leadership in infrastructure and identity.

### Economic buyer

- Chief Information Officer.
- Chief Technology Officer.
- VP Infrastructure or Platform Engineering.
- VP IT or Enterprise Technology.
- Chief Information Security Officer.

### Champion

- Head of Infrastructure Operations.
- Head of SRE.
- Head of IT Operations.
- Head of IAM.
- Director of Platform Engineering.

### Daily users

- Infrastructure and platform operators.
- Site reliability engineers.
- Service-desk agents.
- IAM and security administrators.
- Change approvers.
- Employees requesting help or access.

## Prioritized user stories

### MVP-1 P0

- As an infrastructure operator, I want to ask what depends on a resource so that I can assess blast radius before a change.
- As an employee, I want to request the least-privileged, time-bound access appropriate for my job so that I can complete work without receiving excessive privilege.
- As an approver, I want to see the request basis, policy checks, affected resources, duration, and rollback before approval so that I can make a defensible decision.
- As an operator, I want every proposed action previewed with its exact targets and expected outcome so that I do not execute a broad or ambiguous change.
- As a security reviewer, I want an immutable Proof Record for every action so that I can reconstruct why it was authorized and whether it succeeded.
- As an administrator, I want to define source authority and freshness thresholds so that the platform does not treat every connector as equally trustworthy.
- As an administrator, I want connector-health and context-quality visibility so that I know when answers or actions may be incomplete.

### MVP-2 P0

- As an on-call engineer, I want incidents enriched with recent changes, ownership, topology, and tenant impact so that I can diagnose them without searching multiple tools.
- As an employee, I want to request help in Slack and receive guidance based on my identity, existing access, and service context so that I can resolve common issues without opening a portal.
- As a service-desk operator, I want unresolved self-service requests converted into enriched tickets so that I can continue without repeating discovery.

### P1

- As a service-desk lead, I want related incidents clustered by likely root cause so that operators can resolve repetitive issues together.
- As a service owner, I want to certify ownership, runbooks, and dependency context so that important operational knowledge is trusted by agents.
- As a platform team, I want to expose policy-scoped context through MCP and APIs so that internal agents can reuse the same governed context.
- As an operator, I want to simulate a workflow against historical incidents so that I can assess accuracy and safety before enabling automation.
- As a customer using Microsoft tooling, I want Teams and Entra ID support so that I can deploy without changing collaboration or identity systems.
- As a SaaS administrator, I want to see application usage, licenses, permissions, and owners together so that I can reclaim waste and reduce access risk.
- As a security administrator, I want every AI agent represented by a governed enterprise identity so that ownership, authority, credentials, tools, and actions are visible.
- As an AI-workforce manager, I want to assign agents roles, skills, budgets, supervisors, and escalation paths so that agent coworkers operate within defined responsibilities.

### P2

- As an administrator, I want to compose workflows from certified actions and policies so that ZaspOps can support organization-specific operations.
- As an ecosystem partner, I want to publish a certified connector or action pack so that customers can extend the platform safely.
- As an executive, I want cross-workflow operational analytics so that I can measure automation value, risk, and service quality.
- As a domain product team, I want to install a versioned domain pack without changing the core ontology so that ZaspOps can support another vertical predictably.

## Customer value proposition

### For infrastructure and SRE teams

- Investigate incidents and planned changes from one interface.
- See service, tenant, capacity, identity, and policy dependencies together.
- Reduce manual context gathering.
- Preview impact before taking action.
- Execute reversible changes with verification and rollback.

### For IT service teams

- Resolve common requests directly in Slack or Teams.
- Enrich tickets before they reach an operator.
- Cluster related tickets by likely root cause.
- Preserve the existing ITSM system of record.

### For IAM and security teams

- Evaluate access eligibility, segregation-of-duties, ownership, and risk automatically.
- Make approval chains and policy clauses visible before execution.
- Default to time-bound access.
- Produce an immutable decision record for every governed action.

### For executives

- Reduce operating cost without introducing ungoverned automation.
- Improve service reliability and employee experience.
- Increase audit readiness.
- Create a reusable context foundation for enterprise AI.

### For SaaS and application teams

- Discover applications, ownership, licenses, usage, and permissions in one operating model.
- Identify unused licenses, dormant access, duplicate applications, and renewal risk.
- Automate joiner, mover, leaver, and access-review workflows with Proof Records.
- Connect application spend decisions to actual adoption, business ownership, and security posture.

### For AI platform and agent-governance teams

- Register every enterprise agent with a stable identity and accountable owner.
- Control which tools, data, applications, and actions each agent may use.
- Define roles, skills, budgets, supervisors, coworkers, and escalation paths.
- Evaluate agent quality and risk using the same execution evidence used for human-operated workflows.

## Product principles

- **Context before action:** No write action is prepared until required context has been collected and evaluated.
- **Proof before approval:** Approvers see the decision basis, impact, policy, and rollback plan before authorizing execution.
- **Live over manually maintained:** Prefer connector-sourced and event-driven context over manually curated records.
- **Authority is explicit:** Each source has an authority tier for the entity or attribute it contributes.
- **Freshness is a control:** Stale context can lower confidence, require approval, or block execution.
- **Human control scales with risk:** Low-risk reversible actions may be automated; high-risk actions require explicit approval or remain recommendation-only.
- **Layer over existing systems:** ZaspOps augments ITSM, IAM, observability, and infrastructure systems rather than replacing them in the MVP.
- **One context model, many interfaces:** Slack, Teams, the web console, APIs, and external agents use the same context and policy services.
- **Stable core, extensible domains:** New verticals extend shared actor, resource, access, activity, policy, and evidence contracts through versioned domain packs rather than forking the platform.
- **Agents are enterprise actors:** Every agent has identity, ownership, delegated authority, permissions, budgets, and accountable actions.
- **Open activation:** Context is available through governed APIs and MCP, not restricted to the ZaspOps user interface.
- **Verification closes the loop:** An action is not complete until its expected outcome has been checked.

## Non-goals

- Replace ServiceNow, Jira Service Management, Okta, Datadog, PagerDuty, Kubernetes, or other systems of record in the MVP.
- Deliver a complete ITIL or enterprise service-management suite.
- Ship broad HR, finance, legal, procurement, and facilities workflow suites during the initial 12–18 months; the core model must remain capable of supporting them through future domain packs.
- Permit unrestricted natural-language execution against production infrastructure.
- Autonomously execute destructive, irreversible, or broad Tier 4 actions.
- Build a general-purpose AI assistant unrelated to enterprise operations.
- Depend on a manually maintained CMDB as the only source of infrastructure truth.
- Make direct graph editing the primary user experience.
- Maximize connector count before the launch connectors meet quality, security, and freshness requirements.

## Product architecture

### Enterprise Context Layer

The Enterprise Context Layer is the foundation of ZaspOps. It ingests operational metadata and events, resolves entities, builds relationships, evaluates context quality, and serves governed context to humans and agents.

The layer follows four stages:

1. **Unify:** Connect source systems and normalize their entities, events, and relationships.
2. **Bootstrap:** Infer descriptions, ownership, dependencies, classifications, and candidate policies using AI and deterministic rules.
3. **Certify:** Allow domain owners to validate, correct, and certify high-value context.
4. **Activate:** Serve certified, policy-scoped context to ZaspOps workflows and external agents through APIs and MCP.

The Enterprise Context Layer is not a static inventory or manually maintained CMDB. It is a temporal, event-driven operational model in which every attribute and relationship retains its source, observed time, authority, confidence, certification state, and validity period. The layer separates context ingestion from activation so that the same governed operational model can support ZaspOps workflows, customer-built agents, and approved third-party interfaces without duplicating policy or evidence logic.

### Horizontal core ontology

The core ontology is domain-independent. Every domain pack maps its specialized entities into these stable superclasses:

| Core type | Purpose | Examples |
|---|---|---|
| Actor | An identity that can request, approve, observe, or act | Person, team, service account, software service, AI agent, agent team |
| Resource | An object that can be owned, used, accessed, changed, or governed | SaaS application, license, dataset, cluster, GPU, document, tenant |
| Capability | A bounded function an actor or resource can provide | Tool, API operation, agent skill, workflow, diagnostic, application feature |
| Entitlement | Permission to use a resource or capability under conditions | Role, group membership, license assignment, API scope, delegated authority |
| Activity | An observed use, event, decision, or state transition | Login, API call, tool invocation, job run, configuration change, approval |
| Work | A unit of operational intent and coordination | Request, incident, task, change, objective, agent assignment |
| Policy | A machine-evaluable or reference rule governing actors and resources | Access policy, spending limit, retention rule, approval policy, control |
| Evidence | A sourced fact or result supporting a decision | Usage event, graph relationship, approval, evaluation, verification result |

Core types have stable identifiers, tenant scope, lifecycle state, source provenance, observed and ingested timestamps, ownership, classification, and extensible typed attributes. Domain-specific attributes are namespaced and versioned so a new pack cannot silently change the meaning of a core field.

### Universal Actor model

People, service accounts, software services, and AI agents use the same Actor contract. Every Actor supports:

- stable identity and aliases across source systems;
- actor type and lifecycle state;
- accountable owner and organizational home;
- memberships, roles, and coworkers;
- direct and inherited entitlements;
- credentials and workload identities;
- delegated authority and acting-on-behalf-of relationships;
- allowed resources, capabilities, tools, and data classifications;
- spending, rate, time, and environment limits;
- supervisors, approvers, and escalation paths;
- activity history, evaluations, incidents, and Proof Records.

Agent identity uses the following normative boundaries:

- **Agent:** A stable Actor representing one accountable purpose, owner, policy boundary, and business identity. It survives deployments and model changes.
- **Agent Version:** An immutable Resource containing a specific configuration, model, instructions, skills, tool declarations, code or workflow artifact, and evaluation result.
- **Agent Runtime:** An Actor representing one deployed execution boundary for an Agent Version in an environment. Runtime Actors perform actions and can be suspended or quarantined independently.
- **Workload Identity:** An identity principal and credential binding that authenticates exactly one Agent Runtime within a defined environment and validity period. It is linked to, but is not itself, the accountable Agent.
- **Execution:** An Activity linked to the Agent, Agent Version, Agent Runtime, workload identity, initiating Actor or work item, tool calls, policy decisions, cost, and Proof Record.

Credentials rotate without changing the Agent identity. A new configuration or model creates a new Agent Version. A materially separate deployment boundary creates a new Agent Runtime and workload identity. Suspension of an Agent blocks all child runtimes; suspension of one Runtime does not change historical identity or other approved runtimes. Every action records both the accountable Agent and executing Runtime.

An agent team adds a manager, coworker membership, delegation rules, shared objectives, communication boundaries, and aggregate budget. “Agent coworker” is therefore a governed role and operating experience built on the Actor model, not a separate identity architecture.

### Context planes

| Plane | Core entities | Representative questions |
|---|---|---|
| Identity | Actor, person, team, service account, agent, role, group | Who or what is acting, who owns it, and on whose behalf? |
| Access | Entitlement, permission, credential, license, delegation, approval | What can the actor access or do, why, and for how long? |
| Resource | Application, cluster, node, GPU, dataset, document, tenant | What enterprise object is involved? |
| Service | Service, API, capability, dependency, owner, SLA | What depends on this object and who is affected? |
| Usage | Session, login, feature use, API call, tool invocation, job | How, when, and how often is the resource or capability used? |
| Economics | Subscription, license, budget, cost center, commitment, charge | What does it cost, who pays, and is capacity being used? |
| Work | Incident, request, task, change, objective, runbook, action | What happened, what is requested, and what work is underway? |
| Governance | Policy, control, exception, evidence, evaluation, certification | What rules apply and what proof is required? |

### Domain-pack framework

A domain pack extends ZaspOps without forking the core platform. Each pack is a signed, versioned package containing:

- domain entity and relationship schemas mapped to core types;
- connector manifests and source-authority defaults;
- identity, access, usage, economics, and lifecycle semantics;
- policy templates and risk-tier mappings;
- action definitions with required context, approval, verification, and rollback;
- context-quality rules and freshness thresholds;
- workflow definitions and optional user-interface modules;
- evaluation datasets and release tests;
- migration rules for schema upgrades;
- permissions describing what data and actions the pack may access.

Pack installation must validate schema compatibility, requested privileges, policy conflicts, action safety, and migration impact. Packs cannot bypass tenant isolation, Proof Records, policy evaluation, risk tiers, or action verification.

### Domain-pack security model

Domain packs execute with tenant-granted capabilities, not ambient platform privilege. The security contract requires:

- a signed manifest identifying publisher, version, schemas, connectors, policies, actions, user-interface modules, network destinations, and requested capabilities;
- explicit tenant approval for every data class, connector, credential, outbound destination, and action capability;
- separation between pack code, connector credentials, action-runner credentials, and platform administrative credentials;
- isolated execution for pack-provided code and migrations;
- deny-by-default network egress and data export;
- field- and entity-level authorization enforced by core services;
- publisher trust, signature verification, revocation status, and software-bill-of-materials metadata;
- staged upgrade, compatibility validation, database migration plan, rollback package, and previous-version recovery;
- tenant and platform kill switches that immediately disable pack workflows and actions without deleting historical records;
- immutable installation, upgrade, authorization, revocation, and execution audit events.

Customer-authored packs use the same controls. Third-party packs and marketplace distribution cannot launch until the authorization, signing, isolation, revocation, rollback, and kill-switch requirements pass security review.

### Extension interfaces

The platform provides five explicit extension interfaces:

1. **Schema Registry:** Registers versioned entity types, attributes, relationships, mappings to core types, compatibility rules, and migrations.
2. **Connector SDK:** Ingests entities, events, usage, permissions, costs, and lifecycle changes with provenance and health semantics.
3. **Policy SDK:** Adds deterministic rules, eligibility checks, risk mappings, approval routes, and evidence requirements.
4. **Action SDK:** Defines typed inputs, target selectors, credentials, execution, idempotency, verification, rollback, and escalation.
5. **Experience SDK:** Adds workflow cards, detail panels, dashboards, and chat interactions while reusing common identity, policy, and Proof Record components.

All extensions use capability negotiation. A workflow checks whether required schemas, connectors, policies, and actions are installed before it becomes available.

### SaaS operations domain model

The SaaS domain pack adds:

- applications, vendors, application instances, environments, and owners;
- subscriptions, contracts, renewals, products, plans, licenses, and cost centers;
- users, groups, application roles, permission sets, OAuth grants, and API tokens;
- login, session, feature-use, API-use, last-active, and adoption events;
- requested, approved, provisioned, suspended, revoked, and dormant lifecycle states;
- duplicate-application, unused-license, excessive-permission, shadow-application, and renewal-risk findings;
- joiner, mover, leaver, access-review, license-reclamation, and renewal workflows.

Application usage and access remain distinct. Lack of recent usage may support a reclamation recommendation, but it does not by itself authorize removal. Policy, role, business ownership, exceptions, and verification still apply.

### Agent operations domain model

The Agent Operations pack adds:

- agents, agent versions, runtimes, models, owners, and business purposes;
- agent roles, skills, tools, APIs, MCP servers, data sources, and memory stores;
- workload identities, credentials, scopes, delegated authority, and impersonation constraints;
- supervisors, agent managers, coworkers, teams, objectives, handoffs, and escalation paths;
- budgets, spending, token or compute limits, rate limits, schedules, and environment restrictions;
- executions, traces, tool calls, decisions, evaluations, incidents, and Proof Records;
- draft, testing, approved, active, suspended, quarantined, retired, and revoked lifecycle states.

Every agent action must resolve the agent identity, accountable human owner, delegated authority, requested capability, target resource, applicable policy, and evidence requirements. Agent-to-agent delegation creates a new governed work item and cannot transfer more authority, budget, data access, or tool access than the delegating agent possesses.

### Initial infrastructure entity model

The MVP context graph must support:

- organizations, business units, teams, and people;
- services, applications, APIs, and service owners;
- Kubernetes clusters, namespaces, workloads, nodes, and node pools;
- GPU models, GPU devices, hosts, health state, and firmware;
- schedulers, jobs, queues, and reservations;
- tenants, customers, projects, and capacity allocations;
- cloud accounts, regions, availability zones, and resource groups;
- network segments and key service dependencies;
- users, groups, roles, entitlements, and access grants;
- incidents, alerts, service requests, changes, and problems;
- runbooks, knowledge articles, policies, controls, and exceptions;
- actions, approvals, verification results, and rollback events.

### Relationship model

The graph must represent relationships such as:

- owned by;
- member of;
- runs on;
- scheduled on;
- allocated to;
- used by;
- licensed to;
- subscribed through;
- active in;
- has permission;
- can invoke;
- can read;
- can write;
- acts on behalf of;
- delegated to;
- supervised by;
- coworker of;
- shares objective with;
- consumes budget from;
- depends on;
- communicates with;
- affected by;
- monitored by;
- authorized through;
- governed by;
- requested by;
- approved by;
- changed by;
- verified by;
- supersedes;
- derived from.

Every relationship must include provenance, observed time, ingestion time, confidence, and optional validity period.

### Proof Record

The Proof Record is generated from the context graph for a specific answer, recommendation, or action. While work is in progress it is a live draft. At approval or completion, ZaspOps finalizes a persisted, immutable decision snapshot rather than retaining only a query over the mutable graph.

Required fields:

- request and actor;
- actor verification method;
- accountable owner and acting-on-behalf-of chain;
- delegated authority, credential, and capability used;
- target objects and requested operation;
- evidence sources;
- source authority tier;
- source freshness;
- retrieved facts and relevant relationships;
- confidence and conflicts;
- affected services, users, tenants, and resources;
- applicable policy and policy version;
- risk tier;
- applicable usage, budget, rate, and environment limits;
- required approvers;
- execution plan;
- verification plan;
- rollback plan;
- final outcome and post-action evidence.

The finalized snapshot must include:

- record identifier and finalization time;
- requesting, approving, accountable, and executing Actor identifiers;
- complete delegation and acting-on-behalf-of chain;
- canonical entity identifiers and relevant attribute values at evaluation time;
- source record identifiers, observed times, revisions, and content hashes where available;
- policy, schema, connector, domain-pack, model, agent-version, workflow, and action-definition versions;
- deterministic policy inputs and outputs;
- evidence manifest and graph-edge identifiers;
- execution, verification, rollback, and final status events.

Finalization is atomic. The snapshot and its manifest are append-only and content-addressed. Later source corrections, policy changes, entity merges, or evidence revisions create linked amendment events or a superseding Proof Record; they never rewrite the original decision snapshot. The console may render current context alongside the historical snapshot, but it must label the two states separately.

### Context quality

Each entity attribute and graph relationship receives:

- **Authority:** authoritative, corroborating, inferred, or user-supplied.
- **Freshness:** age relative to source-specific thresholds.
- **Confidence:** deterministic or model-derived confidence.
- **Certification:** uncertified, owner-reviewed, or policy-certified.
- **Conflict state:** clear, unresolved conflict, or superseded.

Workflows use minimum quality thresholds. A workflow cannot silently substitute low-quality context when authoritative context is required.

### Product portfolio architecture

| Product | Primary users | Core outcomes | Shared platform services |
|---|---|---|---|
| ZaspOps Core | Platform, security, and enterprise architecture teams | Unified context, identity, policy, evidence, APIs, MCP, and governed actions | Graph, Actor model, policy engine, Proof Records, action runtime, SDKs |
| ZaspOps Infrastructure | Infrastructure, SRE, IT operations, and IAM teams | Investigation, blast radius, incidents, access, changes, capacity | Core plus Infrastructure domain pack |
| ZaspOps SaaS | SaaS, IT asset, procurement, security, and finance teams | Application inventory, adoption, permissions, licenses, renewal, lifecycle | Core plus SaaS Operations domain pack |
| ZaspOps Agents | AI platform, security, IT, and business operations teams | Agent identity, workforce management, tool governance, budget, evaluation, delegation | Core plus Agent Operations domain pack |
| Future domain products | Domain operations teams | Specialized operational workflows and controls | Core plus signed domain packs |

Products share canonical Actors, applications, services, policies, work records, and Proof Records. A SaaS application used by an agent or an infrastructure service must resolve to the same Resource rather than creating product-specific duplicates.

## Product surfaces

### ZaspOps web console

The console is the primary operator and administrator experience. It includes:

- global Ask bar;
- investigation workspace;
- live context explorer;
- Proof Record panel;
- incident and request queue;
- approvals inbox;
- action execution and verification view;
- connector administration;
- policy and risk configuration;
- context-quality dashboard;
- audit and export center.

The console uses installable modules. The Infrastructure module ships first. Future modules include:

- **Application Portfolio:** Application inventory, ownership, licenses, adoption, permissions, costs, renewals, findings, and lifecycle actions.
- **Agent Workforce:** Agent registry, roles, skills, tools, owners, supervisors, coworkers, budgets, evaluations, incidents, and activity.
- **Domain Operations:** Pack-specific queues, investigations, policies, resources, and actions built with shared console components.

### Slack and Microsoft Teams

Chat is the primary employee entry point and a secondary operator entry point. It supports:

- natural-language questions;
- guided troubleshooting;
- service requests;
- access requests;
- approvals;
- incident notifications;
- concise Proof Record summaries;
- links to full records in the console.

Chat identity must be bound to enterprise SSO. Message identity alone is not sufficient authorization.

### APIs and MCP

ZaspOps exposes:

- entity lookup;
- actor and agent registry;
- relationship traversal;
- context search;
- usage and economics queries;
- policy evaluation;
- impact analysis;
- delegated-authority and capability checks;
- Proof Record retrieval;
- approved action invocation;
- action status and verification.

API and MCP responses are scoped to the calling identity and policy. Raw graph access is not unrestricted.

## Core UX model

All operator workflows use a consistent two-pane pattern:

- **Primary pane:** question, incident, request, recommendation, or action.
- **Context pane:** Proof Record with evidence, authority, freshness, policy, impact, and confidence.

The context pane updates for the currently selected answer or action. It does not become an unstructured list of prior sources.

Every workflow has explicit states for:

- loading context;
- sufficient context;
- stale context;
- conflicting context;
- missing required source;
- low confidence;
- approval pending;
- execution in progress;
- verification passed;
- verification failed;
- rollback in progress;
- escalation to a human.

## MVP workflows

### Infrastructure investigation and blast-radius analysis

**User goal:** Determine what will be affected by an incident or planned change without manually searching multiple systems.

**Example question:** “What customer workloads could be affected if we drain node pool gpu-h100-usw2-04 tonight?”

**Flow:**

1. The operator enters a question in the web console, Slack, or Teams.
2. ZaspOps resolves the operator’s identity and authorization.
3. The system identifies referenced entities and asks for clarification if an entity is ambiguous.
4. ZaspOps queries infrastructure, service, observability, identity, ticketing, and change context.
5. The graph computes upstream and downstream dependencies.
6. The answer summarizes likely impact by service, tenant, reservation, and operational risk.
7. The Proof Record lists each source, freshness, authority, and unresolved gap.
8. The operator can notify owners, create a change record, or open a guided action plan.
9. If required sources are stale or unavailable, write actions are disabled and the missing context is named.

**Customer benefit:** Faster and more complete impact analysis with an auditable decision basis.

### Employee self-service

**User goal:** Get help or submit a request without navigating a service portal.

**Example request:** “How do I connect to the production support VPN?”

**Flow:**

1. The employee messages the ZaspOps app in Slack or Teams.
2. SSO-bound identity, team, and existing access context are resolved.
3. ZaspOps classifies the request and retrieves relevant knowledge, identity, service, and prior-request context.
4. The employee receives personalized steps.
5. ZaspOps asks targeted multiple-choice clarification when needed.
6. If a safe automated fix exists, the system presents the action and expected effect.
7. If the issue cannot be resolved, ZaspOps creates an enriched ticket with the request thread, diagnostics, attempted steps, and evidence.
8. The employee can request a human at any time.
9. Resolution feedback updates knowledge quality and workflow evaluation.

**Customer benefit:** Higher self-service completion while preserving a reliable human escalation path.

### Policy-aware access request

**User goal:** Request appropriate access and understand the approval, duration, and policy conditions.

**Example request:** “Give me read-only access to the production capacity dashboard for the next two weeks.”

**Flow:**

1. The requester starts in Slack, Teams, or the web console.
2. ZaspOps resolves the person, manager, team, employment status, and existing entitlement context.
3. The system maps the request to an eligible role or entitlement.
4. Policy evaluation checks least privilege, segregation-of-duties, environment restrictions, and maximum duration.
5. The requester sees the proposed entitlement, duration, approver, and reason.
6. The approver receives the same Proof Record before deciding.
7. Approval triggers provisioning through the authoritative IAM system.
8. ZaspOps verifies that the correct entitlement was applied.
9. The requester receives confirmation and a visible expiration time.
10. ZaspOps revokes access automatically at expiration and verifies removal.
11. Denials include a policy reason and escalation path.

**Customer benefit:** Faster access with lower privilege risk and ready-to-use audit evidence.

### Incident enrichment and guided diagnosis

**User goal:** Receive an incident with the affected service, owner, recent changes, alerts, dependencies, and recommended diagnostic steps already assembled.

**Flow:**

1. ZaspOps ingests incidents, alerts, and recent infrastructure or identity changes.
2. It resolves the affected service, infrastructure objects, owner, on-call responder, and recent relevant changes.
3. The operator sees a prioritized incident summary, suspected cause, affected population, and Proof Record.
4. ZaspOps proposes diagnostic steps or a resolution from an owner-certified runbook.
5. The operator can accept a diagnostic step, reject the proposed cause, add evidence, or escalate.
6. Before any action, ZaspOps previews the exact target, action risk, verification, and rollback behavior.
7. The action runs only after the required confirmation or approval.
8. The system verifies the result and attaches it to the incident.

**Customer benefit:** Lower mean time to diagnosis and fewer context-gathering steps. Root-cause clustering and governed bulk resolution are P1 extensions.

### Governed action execution

**User goal:** Execute a change safely with clear authorization, verification, and rollback.

**Flow:**

1. An investigation, incident, request, or API client proposes an action.
2. ZaspOps builds a Proof Record.
3. The policy engine assigns a risk tier.
4. The interface shows the exact target set and expected effects.
5. Required approvals are collected.
6. ZaspOps obtains short-lived execution credentials.
7. The action is executed through the source system or approved automation runner.
8. ZaspOps verifies the expected state change.
9. Failed verification triggers rollback when safe or escalates with a named failure.
10. All steps are appended to the Proof Record.

**Customer benefit:** Automation that can be trusted because authorization and verification are built into execution.

## Automation risk policy

| Tier | Definition | MVP behavior | Examples |
|---|---|---|---|
| 0: Inform | Read-only answer or recommendation | May run automatically | Explain an alert, find an owner, summarize blast radius |
| 1: Reversible low risk | Narrow, reversible action with low impact | One user confirmation; configurable auto-execution | Create ticket, notify owners, restart a personal agent |
| 2: Controlled access | Entitlement or bounded operational change | Policy evaluation and designated approval | Grant time-bound read access, drain one noncritical node |
| 3: Elevated | Material service, security, or multi-tenant impact | Multiple approvals; execution may require existing automation | Change production policy, rotate shared credential |
| 4: Critical | Irreversible, destructive, or broad impact | Recommendation-only in MVP | Delete production resources, modify core network fabric |

Customers can make policy stricter but cannot remove required evidence, provenance, verification, or immutable logging.

## MVP integrations

The MVP should support a deliberately narrow integration set that covers one complete operating environment. Integration breadth must not come at the expense of context quality or action safety.

### Launch integrations

| Category | Integration | MVP capabilities | Priority |
|---|---|---|---|
| Collaboration | Slack | Questions, requests, approvals, notifications, identity binding | P0 |
| Identity | Okta | Users, groups, roles, manager data, group membership, access provisioning | P0 |
| ITSM | ServiceNow | Incidents, requests, changes, CMDB references, comments, status updates | P0 |
| Infrastructure | Kubernetes | Clusters, namespaces, workloads, nodes, labels, ownership, bounded actions | P0 |
| Observability | Datadog | Monitors, alerts, service catalog, metrics links, recent telemetry context | P0 |
| Incident response | PagerDuty | Services, incidents, on-call schedules, escalation policies | P0 |
| Knowledge | Confluence | Runbooks, policies, knowledge articles, owners, certification metadata | P0 |
| Source control | GitHub | Repositories, CODEOWNERS, deployments, commits, pull requests | P1 |
| Ticketing alternative | Jira Service Management | Requests, incidents, changes, comments, status | P1 |
| Collaboration alternative | Microsoft Teams | Questions, requests, approvals, notifications | P1 |
| Identity alternative | Microsoft Entra ID | Users, groups, roles, access provisioning | P1 |
| Cloud | AWS | Accounts, resources, tags, IAM references, CloudTrail change context | P1 |

### AI-infrastructure integration pack

The first vertical package adds:

| Integration area | MVP or early follow-up capability |
|---|---|
| NVIDIA DCGM | GPU inventory, health, utilization, alerts, diagnostic context |
| Slurm | Jobs, partitions, nodes, queues, reservations, ownership |
| Prometheus/Grafana | Metrics, alerts, dashboard relationships |
| InfiniBand/fabric telemetry | Fabric entities, links, health events, affected-node relationships |
| Capacity or billing system | Tenant reservations, allocations, commitments, utilization context |

Because vendor and customer implementations vary, ZaspOps must also provide a generic event and entity ingestion API in the MVP.

### Future SaaS Operations integration pack

| Integration area | Required capabilities |
|---|---|
| Identity providers | Application assignments, groups, SSO activity, provisioning, revocation |
| SaaS applications | Users, roles, permission sets, licenses, sessions, feature usage, lifecycle actions |
| Finance and procurement | Contracts, subscriptions, renewals, commitments, invoices, cost centers |
| Expense and card systems | Vendor discovery and unapproved-application signals |
| Endpoint and network discovery | Observed application use and shadow-application signals |
| HR systems | Employment state, department, manager, location, joiner/mover/leaver events |
| Security platforms | OAuth grants, risky permissions, application posture, findings |

The first SaaS package should prioritize a reference stack covering Microsoft 365 or Google Workspace, Salesforce, Slack, Zoom, GitHub, an identity provider, an HR source, and a finance or procurement source. Connector certification must distinguish license assignment, login activity, and meaningful feature usage.

### Future Agent Operations integration pack

| Integration area | Required capabilities |
|---|---|
| Model and inference gateways | Agent model use, tokens or compute, cost, policy, and request metadata |
| Agent runtimes and orchestration | Agent identity, version, skills, execution, handoffs, traces, and state |
| MCP and tool gateways | Available tools, scopes, calls, authorization decisions, and failures |
| Secrets and workload identity | Credentials, issuance, rotation, workload principals, and revocation |
| Data and knowledge systems | Permitted data sources, retrieval events, classifications, and lineage |
| Evaluation and observability | Quality, safety, latency, cost, drift, incidents, and human feedback |
| Collaboration and ITSM | Agent assignments, approvals, escalations, coworker interactions, and work records |

The generic Agent Registration API must allow an internal or third-party agent to register its identity, owner, purpose, runtime, model, tools, permissions, budgets, supervisors, and evaluation policy even when no native connector exists.

### Connector requirements

Every connector must:

- support least-privilege authentication;
- document the entities and attributes it treats as authoritative;
- record source event time and ingestion time;
- expose health and last-successful-sync status;
- preserve source identifiers;
- declare core-type and domain-schema mappings in a connector manifest;
- support incremental updates where the source permits;
- distinguish observed usage from inferred or assigned usage;
- handle deletion and revocation events;
- identify schema or permission failures;
- permit per-entity data filtering;
- separate read and write credentials;
- expose supported read, write, usage, cost, identity, and action capabilities;
- emit audit events for every action.

## Functional requirements

### MVP-1 P0 requirements

#### Context ingestion and graph

- Ingest entities and events from all launch integrations.
- Resolve identities, services, infrastructure objects, incidents, and policies across sources.
- Preserve provenance for every attribute and relationship.
- Assign authority and freshness based on connector configuration.
- Detect conflicting values and prevent silent overwrites.
- Support dependency traversal and impact analysis.
- Support tenant-scoped and role-scoped graph queries.

**Acceptance criteria:**

- Given two sources that refer to the same Kubernetes service, when the configured matching keys agree, then ZaspOps produces one canonical entity and preserves both source records.
- Given conflicting owners from ServiceNow and Confluence, when ServiceNow is configured as authoritative, then the canonical owner uses ServiceNow and the conflict remains visible.
- Given a deleted Okta group membership, when the deletion event is ingested, then the relationship is no longer valid and the historical event remains queryable.

#### Ask and investigation

- Accept natural-language questions in the console and Slack.
- Resolve entity references with clarification when necessary.
- Return answers with a Proof Record.
- Name missing, stale, or conflicting context.
- Prevent unsupported claims from being presented as verified facts.
- Allow creation of tickets, notifications, and change drafts from an answer.

**Acceptance criteria:**

- Given an authorized operator asks for blast radius, when required connectors are healthy, then the answer identifies affected entities and shows provenance and freshness.
- Given a required source is past its freshness threshold, when an action is requested, then the action is blocked or escalated according to policy.
- Given an ambiguous cluster name, when multiple entities match, then ZaspOps asks the user to select a target before continuing.

#### Proof Records

- Generate a Proof Record for every answer, recommendation, approval, and action.
- Show evidence before approval or execution.
- Store immutable completed records.
- Export records as JSON and human-readable PDF in a post-MVP follow-up; JSON and console view are P0.
- Link records to source incidents, requests, and changes.

**Acceptance criteria:**

- Given a Tier 2 access request, when an approver opens it, then actor, target entitlement, duration, policy, evidence, and rollback are visible before approval.
- Given an action completes, when verification runs, then the result is appended to the same record.
- Given a source fact is later corrected, when the historical record is viewed, then the original decision context remains unchanged and the correction is shown as a later event.

#### Policy and risk engine

- Assign a risk tier using action type, target environment, blast radius, actor, and policy.
- Evaluate access eligibility and segregation-of-duties.
- Route approvals to named people or groups.
- Support expiration and automatic revocation for access.
- Block critical actions in the MVP.

**Acceptance criteria:**

- Given a request violates segregation-of-duties, when policy evaluation runs, then automatic provisioning is prohibited and the conflict is named.
- Given time-bound access is approved, when the expiration occurs, then ZaspOps initiates revocation and verifies the entitlement was removed.
- Given no approver can be resolved, when the request is submitted, then the request is escalated to the configured fallback queue rather than auto-approved.

#### Action orchestration

- Execute approved actions using short-lived or delegated credentials.
- Preview targets before execution.
- Enforce idempotency.
- Verify expected outcomes.
- Run rollback for supported actions when verification fails.
- Escalate safely when rollback is unavailable.

**Acceptance criteria:**

- Given an operator retries an action after a network timeout, when the same idempotency key is used, then the target action is not duplicated.
- Given an access grant reports success but the entitlement is absent, when verification runs, then the action is marked failed and escalated.
- Given a reversible Kubernetes action fails verification, when rollback is configured and safe, then rollback runs and its outcome is recorded.

#### Slack operator and approval experience

- Bind Slack users to enterprise identity.
- Answer operator questions.
- Submit and approve access requests.
- Display concise evidence and link to the full record.
- Provide an escalation control for investigations and approvals.

**Acceptance criteria:**

- Given a Slack user is not bound to SSO, when an access request is submitted, then ZaspOps requires identity verification before processing.
- Given an approver receives a request, when the request is Tier 2, then the message includes entitlement, duration, policy result, and a link to the full Proof Record.
- Given an operator escalates an investigation, when no existing ticket exists, then ZaspOps creates one with the request details and diagnostic context.

#### Administration

- Configure connectors and authority rules.
- Configure freshness thresholds.
- Define action risk and approval policies.
- Review and certify Tier 1 service ownership, runbooks, and policy references.
- Inspect connector health and context-quality gaps.
- Manage retention and export controls.

**Acceptance criteria:**

- Given a service owner reviews a proposed owner, dependency, or runbook relationship, when the owner certifies it, then the relationship records the certifier, certification time, source evidence, and validity state.
- Given certified context becomes stale or its source is deleted, when the quality job runs, then certification is flagged for review and workflows apply the configured stale-context policy.
- Given a connector has not completed a successful sync within its threshold, when an administrator opens the quality dashboard, then the affected entity classes and workflows are identified.
- Given a policy change is published, when a new governed request is evaluated, then the new policy version is used while completed Proof Records retain the prior version.

#### Platform extensibility

- Map every MVP entity to a horizontal core type.
- Store infrastructure-specific attributes in a versioned domain namespace.
- Support Actor subtypes without hard-coding authorization to human users.
- Provide an internal, migration-aware Schema Registry and manifest validator in MVP-1.
- Register connector capabilities and schema mappings through manifests.
- Keep policy evaluation, Proof Records, and action execution independent of domain-specific user interfaces.
- Reject incompatible schema, pack, or connector versions before activation.

**Acceptance criteria:**

- Given an AI agent is registered as an Actor, when it requests the same capability as a person, then ZaspOps evaluates identity, delegated authority, policy, evidence, and risk using the shared action contract.
- Given a new domain entity maps to Resource and declares namespaced attributes, when the schema is installed, then existing search, ownership, access, evidence, and policy services can operate on it without core-service code changes.
- Given a domain pack declares an action that omits verification, when installation validation runs, then the action is rejected.
- Given a connector upgrade changes a field incompatibly, when its manifest is validated, then activation is blocked until a migration or compatible mapping is supplied.

### MVP-2 P0 requirements

#### Employee self-service and enriched escalation

- Answer supported employee questions using identity, access, service, and certified knowledge context.
- Ask bounded clarification questions.
- Present approved self-service actions with expected outcomes.
- Create enriched ITSM records when self-service does not resolve the request.
- Preserve a human escalation path.

**Acceptance criteria:**

- Given a supported request and sufficient context, when the employee asks for help, then ZaspOps returns personalized steps with evidence and an escalation option.
- Given required context is stale or missing, when the request is evaluated, then ZaspOps names the gap and does not offer an unsupported action.
- Given self-service does not resolve the issue, when the employee escalates, then the ITSM record includes request details, retrieved context, attempted steps, and evidence.

#### Incident enrichment and guided diagnosis

- Resolve affected services, owners, on-call responders, infrastructure objects, alerts, and recent changes.
- Generate a Proof Record and owner-certified diagnostic plan.
- Permit operator correction, added evidence, and escalation.
- Verify and attach the result of any approved diagnostic action.

**Acceptance criteria:**

- Given a supported incident, when enrichment completes, then the record includes the affected service, owner, recent relevant changes, active alerts, dependency context, and evidence quality.
- Given the proposed cause lacks sufficient evidence, when the operator views it, then it is labeled as inferred and no write action is enabled solely from that inference.

### P1 requirements

- Microsoft Teams support.
- Jira Service Management and Microsoft Entra ID alternatives.
- GitHub and AWS context.
- Cross-incident root-cause clustering.
- Bulk resolution with preview and approval.
- Customer-facing status summaries.
- Expanded bulk certification and domain-review workflows.
- External MCP server with policy-scoped tools.
- Proof Record PDF export.
- Simulation against historical incidents.
- Public and partner packaging for the Connector SDK, Policy SDK, Action SDK, and Schema Registry interfaces built internally in MVP-1.
- SaaS Operations beta for application inventory, usage, permissions, licenses, access lifecycle, and reclamation.
- Agent Registry beta with identity, owner, purpose, model, runtime, tools, scopes, budgets, and lifecycle.
- Agent Workforce controls for roles, skills, supervisors, coworkers, delegation, evaluations, and escalation.
- Policy-scoped agent and tool gateway with Proof Records for tool calls and delegated actions.

### P2 requirements

- Visual graph exploration for complex dependency analysis.
- Customer-configurable workflow builder.
- Voice and mobile experiences.
- Multi-agent delegation across specialist operational agents.
- Experience SDK and marketplace for signed connectors, domain packs, policies, actions, and certified runbooks.
- Broader enterprise service management workflows.
- Additional industry and departmental domain packs.
- Cross-company or supplier context sharing.

## Non-functional requirements

### Security

- SAML or OIDC SSO.
- SCIM provisioning.
- Role-based and attribute-based access control.
- Encryption in transit and at rest.
- Customer-specific encryption keys as an enterprise option.
- No use of customer data for model training by default.
- Secrets stored in an enterprise secrets manager.
- Separate read and write connector credentials.
- Short-lived action credentials where supported.
- Unique workload identity for each production agent; shared agent credentials are prohibited.
- Delegated authority cannot exceed the delegating Actor’s permissions, budget, data scope, or validity period.
- Tool and MCP authorization is evaluated at invocation time, not only when an agent is registered.
- Complete administrative and action audit logs.

### Tenant isolation

- Strict logical isolation in all services and indexes.
- Tenant-scoped encryption and authorization checks.
- Automated tests for cross-tenant access.
- No cross-tenant model retrieval.

### Reliability

- Read-only investigation remains available when action services are impaired.
- Connector failures degrade explicitly rather than producing apparently complete answers.
- Action orchestration uses durable state and retry-safe operations.
- High-risk action paths fail closed.

### Performance targets

- Chat acknowledgement: under 1 second at p95.
- Common context answer: under 10 seconds at p95 when sources are available.
- Proof Record initial render: under 5 seconds at p95, with progressive completion allowed.
- Graph entity lookup: under 500 milliseconds at p95.
- Action status update: visible within 2 seconds of source-system response.

### Explainability

- Every factual claim in an operational answer must link to graph evidence.
- Model-generated inference must be labeled as inferred.
- Confidence must never replace a missing authoritative check.
- Users can inspect why an entity match, policy result, or cluster was produced.

### Data governance

- Configurable retention by data class.
- Regional data residency options.
- Field-level redaction.
- Configurable exclusion of sensitive message content.
- Right-to-delete workflows for user-linked content where legally required.

## Success metrics

Targets should be validated during design-partner onboarding and adjusted after baseline measurement.

### Activation

- Time from connector authorization to first useful context answer: under one business day.
- At least five launch systems connected within the first two weeks.
- At least 70% of Tier 1 services mapped to an owner and one infrastructure dependency within 30 days.
- At least 80% of daily operational questions return a Proof Record with no unresolved authoritative-source gap.

### User outcomes

- 40% reduction in median context-gathering time for selected incident classes within 90 days.
- 25% reduction in median time to resolve selected repetitive incidents within 90 days.
- 30% self-service completion for supported employee request categories within 60 days.
- 50% reduction in manual handling time for supported access requests within 90 days.
- Fewer than 2% of automated access actions require manual correction.

### Trust and safety

- 100% of write actions have a completed Proof Record.
- 100% of Tier 2 or higher actions receive required approval.
- 100% of supported actions run verification.
- Zero cross-tenant context leaks.
- Zero Tier 4 autonomous actions.
- Less than 1% unsupported factual claims in reviewed operational answers.

### Product engagement

- At least 40% weekly active usage among enabled operators by day 60.
- At least 25% of operator investigations lead to a saved record, ticket update, notification, or governed action.
- At least 60% approval completion within the chat or console workflow without external follow-up.
- At least 70% positive feedback on supported employee self-service answers.

### Business outcomes

- Design partner reaches production use within eight weeks.
- At least three production design partners demonstrate one measurable operational improvement.
- Expansion from one workflow to at least two additional workflows in half of production customers within six months.
- Competitive win rate and loss reasons tracked separately for ServiceNow, Atomicwork, STLabs, internal tooling, and no decision.

### Platform expansion outcomes

- 100% of MVP infrastructure entities map to documented horizontal core types before MVP-1 launch.
- A reference SaaS application entity and a reference AI-agent entity can use existing ownership, access, policy, search, Proof Record, and action services without core-service code changes.
- A new connector using the Connector SDK reaches test ingestion without a custom ingestion pipeline.
- A new action using the Action SDK cannot activate until identity, policy, evidence, verification, and rollback or escalation contracts pass validation.
- SaaS Operations beta maps at least 90% of application assignments to a person, group, service account, or agent Actor.
- Agent Operations beta maps 100% of production agents to an accountable owner, workload identity, purpose, tool scope, and lifecycle state.

### Metric definitions and ownership

| Metric | Definition | Instrumentation | Owner | Review |
|---|---|---|---|---|
| Context-gathering time | Median elapsed time from investigation start to operator-confirmed sufficient context for the same incident class | ZaspOps event log plus design-partner baseline sample | Product Analytics | Weekly during pilot; monthly after launch |
| Self-service completion | Supported requests completed without agent handling divided by all supported requests started | Slack workflow and ITSM handoff events | Product | Weekly |
| Access handling time | Median human work time from valid request to verified grant or denial | Request, approval, and IAM verification events | Product and IAM customer owner | Weekly |
| Evidence coverage | Answers with all required authoritative sources present and within freshness threshold divided by reviewed answers | Proof Record quality fields | Context Platform | Daily |
| Entity-resolution precision | Correct canonical matches divided by all sampled canonical matches | Stratified human review of matched entities | Context Platform | Before release and monthly |
| Unsupported-claim rate | Reviewed factual claims without supporting graph evidence divided by all reviewed factual claims | Evaluation suite plus human audit sample | AI Quality | Before release and weekly |
| Action correction rate | Automated actions requiring manual reversal or correction divided by completed automated actions | Action and post-action review events | Reliability | Weekly |

Baseline cohorts must use the same incident classes, request categories, and customer teams as the post-launch measurement. Product Analytics owns the measurement plan and freezes definitions before each pilot begins.

## Competitive positioning

ZaspOps should not compete by matching every ITSM feature. It should win on infrastructure depth, context quality, and governed execution.

### Positioning statement

For enterprises that need AI-driven operations without black-box automation, ZaspOps is the enterprise context, identity, and governed-action layer connecting people, agents, applications, infrastructure, work, usage, and policy. ZaspOps enters through infrastructure-intensive operations, proves why an action is safe before it runs, verifies the result afterward, and reuses the same controls across additional operational domains.

### Competitive stance

| Competitor | Customer strength | ZaspOps response |
|---|---|---|
| ServiceNow | Broad system of record, workflow depth, enterprise installed base | Layer over ServiceNow; deliver live cross-system context and governed AI execution without replacement |
| STLabs | AI-native service management and context-led investigation | Go deeper on infrastructure entities, source authority, freshness, policy evidence, and open activation |
| Atomicwork | Broad AI coworker experience across enterprise services | Win the infrastructure wedge, then manage agent coworkers as governed Actors using a reusable context, identity, budget, policy, and Proof Record substrate |
| Internal tools | Exact fit to local workflows | Reduce maintenance burden through reusable connectors, graph semantics, policy controls, and auditability |
| General-purpose agents | Flexible natural-language interface | Provide enterprise context, authorization, action controls, and verification that general agents lack |

ServiceNow documents a persistent Now Assist experience for sourced answers and specialist agents ([ServiceNow](https://www.servicenow.com/docs/r/intelligent-experiences/now-assist-panel-overview.html)). STLabs presents Axiom, self-service, and operator-intelligence workflows around assembled enterprise context ([STLabs](https://stlabs.com/product)). Atomicwork markets AI coworkers and an AI-native service-management platform across IT and employee workflows ([Atomicwork](https://www.atomicwork.com/platform)). ZaspOps differentiates by making the horizontal context graph, universal Actor model, and pre-execution Proof Record the shared substrate for infrastructure, SaaS, and agent operations.

## MVP scope

### MVP-1: Design-partner core

- Enterprise Context Layer and core graph model.
- Horizontal Actor, Resource, Capability, Entitlement, Activity, Work, Policy, and Evidence contracts.
- Infrastructure entities implemented as a versioned domain schema rather than hard-coded core types.
- Internal schema registry, compatibility rules, migrations, and connector-manifest validation.
- Slack, Okta, ServiceNow, Kubernetes, Datadog, PagerDuty, and Confluence integrations.
- Generic entity and event ingestion API.
- Web investigation console.
- Slack operator and approval experience.
- Infrastructure investigation and blast-radius analysis.
- Time-bound access request and approval.
- Risk-tier policy engine.
- Governed actions limited to ticket updates, owner notification, change-draft creation, and time-bound Okta group membership.
- Proof Records, verification, and rollback where supported.
- Connector health, source-authority configuration, and narrow certification of Tier 1 services, owners, runbooks, and policy references.

### MVP-2: Commercial MVP expansion

- Slack employee self-service for a curated set of knowledge and identity request categories.
- Incident enrichment and guided diagnosis.
- Non-production Kubernetes diagnostics and one reversible infrastructure action.
- Context-quality dashboard and expanded administration.
- Production hardening based on MVP-1 usage and safety evaluation.

MVP-2 begins only after MVP-1 meets the release gates for entity resolution, evidence coverage, policy enforcement, action verification, and tenant isolation.

### Explicitly excluded

- Replacement of ServiceNow, Jira, Okta, or observability platforms.
- Full ITIL suite.
- Broad HR, legal, finance, and facilities service management.
- Unrestricted natural-language execution.
- Autonomous production network or fabric changes.
- Destructive or irreversible autonomous actions.
- General-purpose workflow builder.
- Large connector marketplace.
- Customer-facing external support.
- Full asset lifecycle or procurement management.

## Initial action catalog

MVP-1 ships with:

- create or update an incident;
- add diagnostic context to a ticket;
- notify service owners or on-call responders;
- create a change draft;
- grant and revoke time-bound group membership;
- request approval for an eligible entitlement;

MVP-2 may add:

- restart a non-production Kubernetes workload;
- cordon or drain an approved noncritical node pool;
- run an owner-certified diagnostic;
- attach verification results to the originating record.

Every action must define:

- eligible requesting Actor types and acting-on-behalf-of rules;
- required context;
- eligible targets;
- risk tier;
- required permissions;
- approval rule;
- execution adapter;
- success condition;
- verification query;
- rollback behavior;
- timeout and escalation behavior.

## Roadmap

### Now: MVP and design partners

- Build the core graph, provenance, quality model, and Proof Record.
- Deliver the seven launch integrations.
- Ship MVP-1 investigation and access workflows with the restricted action allowlist.
- Meet production gates for identity resolution, evidence coverage, policy enforcement, verification, and isolation.
- Add MVP-2 employee self-service and incident enrichment after MVP-1 gates pass.
- Validate with three to five infrastructure-intensive design partners.
- Establish baseline operational metrics and safety review.

### Next: Infra depth and horizontal platform activation

- Add the AI-infrastructure integration pack.
- Add Microsoft Teams, Entra ID, Jira Service Management, GitHub, and AWS.
- Ship root-cause clustering and governed bulk resolution.
- Expose policy-scoped MCP and developer APIs.
- Add historical simulation and workflow evaluation.
- Add bulk service-owner and domain context certification.
- Release the Schema Registry, Connector SDK, Policy SDK, and Action SDK.
- Launch the Agent Registry beta and policy-scoped tool gateway.
- Launch the SaaS Operations beta for inventory, usage, permissions, licenses, and access lifecycle.

### Later: Domain products and ecosystem

- Launch the Agent Workforce product for agent roles, skills, coworkers, supervisors, budgets, evaluations, and delegation.
- Expand the marketplace for signed connectors, domain packs, policies, actions, and experiences.
- Support customer-authored policies and workflows.
- Add multi-agent operational orchestration.
- Support additional regulated and departmental verticals through domain packs.
- Provide cross-organization context exchange with strict policy boundaries.
- Expand into adjacent enterprise operations only after the horizontal contracts and initial domain products meet quality and safety gates.

## Launch plan

### Design-partner profile

Select customers with:

- clear operational pain in one of the four MVP workflows;
- executive sponsorship;
- an accessible infrastructure and ITSM stack;
- willingness to provide historical incidents and workflow baselines;
- a named security reviewer;
- an operator cohort of at least 10 users;
- ability to begin with read-only connectors before enabling actions.

### Deployment sequence

1. Connect identity, ITSM, collaboration, Kubernetes, observability, incident response, and knowledge systems in read-only mode.
2. Resolve entities and review context-quality gaps.
3. Certify critical services, owners, runbooks, and policies.
4. Launch read-only investigation.
5. Enable the access workflow with sandbox or low-risk entitlements.
6. Enable the MVP-1 action allowlist progressively by risk tier.
7. Review accuracy, action safety, adoption, and operational outcomes weekly.
8. Launch MVP-2 employee self-service and incident enrichment after MVP-1 gates pass.

### Commercial packaging hypothesis

- Platform fee for the Enterprise Context Layer.
- Usage or seat component for operator and employee workflows.
- Premium Infrastructure, SaaS Operations, Agent Operations, and future domain packs.
- Agent-governance usage dimension based on registered production agents or governed actions, not raw model tokens.
- Enterprise tier for regional deployment, customer-managed keys, advanced retention, and policy-scoped APIs.

Pricing must not penalize customers for ingesting more context, because context completeness improves safety.

## Key dependencies

- Reliable source APIs and appropriate customer permissions.
- A graph and event architecture that preserves provenance and temporal validity.
- Identity resolution across collaboration, IAM, ITSM, and infrastructure systems.
- Deterministic policy evaluation separated from model reasoning.
- Secure action runner with short-lived credentials and idempotency.
- Model evaluation for entity extraction, summarization, clustering, and recommendation.
- Design partners willing to validate authority rules and context quality.

## Major risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Incomplete or stale source data | Incorrect conclusions or blocked workflows | Show gaps explicitly, configure freshness thresholds, fail closed for actions |
| Entity resolution errors | Wrong blast radius or authorization | Use deterministic keys first, confidence thresholds, review queue, reversible merges |
| Excessive integration scope | Slow MVP and fragile connectors | Limit launch stack, build generic ingestion API, certify connector quality |
| AI hallucination | Loss of trust and unsafe recommendations | Evidence-linked claims, deterministic policy engine, unsupported-claim evaluation |
| Customer resistance to another console | Low adoption | Slack/Teams entry points, ITSM write-back, APIs, no rip-and-replace |
| Incumbent bundling | Pricing and procurement pressure | Win on infrastructure depth, speed to value, and open context activation |
| Security concern over write access | Delayed deployment | Read-only first, separate credentials, action allowlist, short-lived authorization |
| Poor initial graph quality | Weak first impression | AI bootstrap plus owner certification, quality dashboard, focus on Tier 1 services |
| Automation failure | Operational or customer impact | Tiered autonomy, preview, approval, idempotency, verification, rollback |
| Core ontology becomes too abstract | Slow product development and weak domain fidelity | Keep a small stable core, use typed domain schemas, validate with reference SaaS and agent entities during MVP |
| Domain packs bypass platform controls | Inconsistent security and auditability | Signed manifests, installation validation, mandatory policy, Proof Record, verification, and tenant-isolation contracts |
| Agent identities become shared or ambiguous | Unattributed actions and excessive authority | Unique workload identity, accountable owner, delegation chain, invocation-time authorization, credential rotation |
| Expansion dilutes the initial wedge | Delayed product-market fit | Keep SaaS and Agent Operations out of MVP-1 execution while building their compatibility into core contracts |

## Open product decisions

### Blocking for MVP

- **Graph storage and temporal model, owner: Engineering:** Select architecture for event history, graph traversal, vector retrieval, and tenant isolation.
- **Initial design-partner stack, owner: Product:** Confirm whether ServiceNow or Jira Service Management must be first in every deployment.
- **First access target, owner: Product and Security:** Select Okta group membership, Kubernetes RBAC, or another entitlement as the launch action.
- **First infrastructure action, owner: Product and Infrastructure:** Select a narrow reversible action with a reliable verification and rollback path.
- **Model deployment, owner: Security and Engineering:** Define hosted, private, and customer-model options.
- **Authority defaults, owner: Product:** Define source authority templates for identity, service ownership, incidents, and infrastructure state.
- **Core ontology versioning, owner: Platform Engineering:** Define compatibility, deprecation, namespace, and migration rules before external SDK release.

### Non-blocking

- **Brand expression:** Visual identity, agent name, and tone within Slack and Teams.
- **Graph visualization:** Whether customers need direct graph exploration in the first post-MVP release.
- **Packaging:** Final seat, platform, and usage dimensions.
- **Certification incentives:** How owners are prompted and rewarded for correcting context.
- **Marketplace model:** Partner certification requirements for connectors and action packs.

## MVP release criteria

ZaspOps MVP-1 is ready for controlled production launch when:

- all P0 integrations pass security and connector-health testing;
- all MVP infrastructure entities map to documented core types and versioned infrastructure-domain attributes;
- one fixture-based, read-only reference SaaS application and one fixture-based, non-production AI agent pass ownership, access, search, policy, and Proof Record compatibility tests without core-service schema changes; these tests validate platform extensibility and do not add SaaS or Agent Operations to MVP-1 production scope;
- canonical identity, service, and infrastructure entity-resolution precision is at least 95% in a stratified review sample of at least 500 resolved entities;
- at least 80% of Tier 1 services have a certified owner and one verified infrastructure dependency;
- 100% of reviewed operational answers carry evidence, source authority, and freshness fields;
- at least 95% of reviewed factual claims are supported by retrieved graph evidence, with a target unsupported-claim rate below 1% before general availability;
- all action paths enforce policy and risk tier;
- all Tier 2 actions require configured approval;
- every supported action has verification;
- reversible actions have tested rollback or a documented safe escalation;
- tenant-isolation and authorization tests pass;
- historical replay of at least 100 representative requests demonstrates zero unauthorized Tier 2, Tier 3, or Tier 4 executions;
- the design partner demonstrates at least a 25% reduction in median context-gathering time or access-handling time for the selected cohort;
- operational, security, and product owners approve the production action catalog.

MVP-2 is ready when MVP-1 remains within safety thresholds for 30 days, at least 80% of supported self-service answers have complete evidence coverage, and incident-enrichment accuracy is accepted by operators in at least 80% of a 100-incident review sample.

## Product definition

ZaspOps is not an AI helpdesk with a context feature or an infrastructure-only automation tool. It is an enterprise context, identity, and governed-action platform whose first applications solve infrastructure investigation, employee service, access, and incident operations.

Infrastructure is the first domain pack and commercial wedge. SaaS Operations, Agent Operations, and future verticals extend the same Actor, Resource, Entitlement, Activity, Work, Policy, Evidence, and action contracts. The product becomes defensible as customers connect more authoritative systems, certify more operational knowledge, govern more human and agent identities, record more decisions, and activate more workflows on the same context layer. Each interaction improves the reusable operational model while policy, provenance, and verification keep automation within enterprise control.
