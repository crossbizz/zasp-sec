# Agent Security Platform Technical Implementation Plan

**Version:** 1.5, release-candidate MVP  
**Date:** August 12, 2026

> **Execution rule:** Every backlog item is a microtask with an active-work timebox of <=15 minutes. If the implementer cannot complete the stated deliverable and verification inside the timebox, stop and split the item before continuing. Waiting on an external provisioner or CI job is not hidden as implementation work; long-running checks are started by one task and inspected by another.

## 1. Goal

Implement the PRD v1.5 as one coherent SaaS-first Agent Security Platform with a supported single-tenant deployment profile. The default control plane is multi-tenant and AgentSec-managed on AWS. The same binaries, APIs, schemas and UI can run in a dedicated single-tenant topology. Reused OSS and managed vendors remain behind product-owned contracts.

The implementation must make this end-to-end path real:

**first-admin bootstrap -> corporate SSO -> connect -> discover -> capability/path -> red team -> Attack Lab -> Security Agent plan -> deterministic authorization -> auto-action/approval -> verified containment -> TTL cleanup -> re-test -> session/audit evidence**

## 2. Non-negotiable constraints

- Primary v1 control plane/data plane runs as multi-tenant SaaS in AgentSec-managed AWS. Customer-side sensors/runtime gateways run in customer environments when needed. Single-tenant mode deploys the same product into dedicated AWS infrastructure.
- Stytch B2B is the required v1 human identity provider.
- Neon is the required relational Postgres provider.
- Local development uses LocalStack where AWS behavior is supported; security-critical release parity runs against real AWS.
- PostHog and remote OTLP are optional/non-critical. OpenRouter is optional for the deterministic security plane but is the required planner backend when Security Agents or AI explanations are enabled. Its failure must never weaken existing runtime policy.
- OpenTelemetry is the only application observability interface. Applications do not import Grafana Cloud/New Relic SDKs.
- Tetragon is first-class runtime observation, but not the semantic source of truth.
- Prowler/Cartography findings are normalized and filtered to agent relevance.
- Nango free self-hosted is used only for Auth + Proxy. Do not depend on Functions, Webhooks, MCP server, RBAC or Enterprise-only runtime features.
- Promptfoo is the only required red-team engine in MVP.
- OPA is embedded through the Go SDK in runtime-gateway. No customer-facing Rego.
- EKS Fargate is the reference Attack Lab strong-isolation provider in a dedicated test AWS environment, either AgentSec-managed or customer-provided according to the verification target.
- Native EKS Kubernetes NetworkPolicy is not relied on for Fargate. Use Security Groups for Pods plus the product egress proxy.
- Runtime enforcement must continue from a last-valid signed policy bundle during control-plane/vendor outages.
- Production defaults to metadata-only content collection.
- Every external call has a deadline. Retries are bounded and limited to transient/idempotent operations.
- Every security-relevant mutation is audited.
- Security Agents are MVP but bounded: fixed typed action catalog, no arbitrary shell/HTTP/plugins, deterministic action authorization, product-enforced approval floors, bounded steps/time/cost, idempotent execution and mandatory verification.
- Untrusted finding/session/path content is data to the Security Agent planner, never executable instruction. Model output is structured and cannot create new action types or widen scope.
- Every UI action has a documented OpenAPI operation.
- No user-facing string or route requires knowledge of Cartography, Prowler, Tetragon, Nango, Promptfoo, OPA, Neo4j or OpenSearch.

## 3. Deployables and ownership boundaries

Keep product services small and use the same product artifacts in both deployment modes.

```text
apps/web                       Next.js/React product UI
services/platform              Go codebase, two commands
  agentsec-api                 REST API, auth, admin, product reads/writes
  agentsec-worker              SQS jobs, graph/correlation, connector orchestration, Security Agent planning/execution/verification
services/event-ingest          Go sensor/semantic normalization and SQS batching
services/runtime-gateway       Go MCP/tool/API proxy with embedded OPA
workers/security-python        Cartography/Prowler adapters
workers/redteam-node           Promptfoo adapter
cmd/agentsecctl                edge/single-tenant preflight, recovery and diagnostics
```

**SaaS control plane, primary v1:** AgentSec-managed AWS EKS plus shared SQS/DLQ, OpenSearch Service, S3/KMS, Secrets Manager, graph store, internal Nango, OTel Collector, Stytch and Neon. Shared state is always Organization-scoped.

**Customer-side edge components:** optional sensor/runtime Helm package with Tetragon, runtime gateway and semantic adapters. These authenticate to the SaaS data plane with scoped enrollment credentials and never need direct Stytch, Neon, PostHog or OpenRouter access.

**Single-tenant mode:** deploy the same product images and schemas into dedicated AWS infrastructure using a single-tenant values/Terraform profile. The deployment is pinned to one Organization and may be AgentSec-managed or customer-hosted/BYOC. No separate product fork.

### Boundary rule

Frontend calls only `agentsec-api`. Workers and adapters emit canonical product entities/events. Vendor-native IDs are source metadata, never public primary keys. Runtime gateways consume signed scoped policy bundles so transient SaaS/control-plane loss does not disable already-deployed enforcement.

## 4. Tenancy and authorization

SaaS v1 is multi-tenant:

```text
Organization
  Workspace
    Environment
```

Each Stytch B2B Organization maps to exactly one product Organization. Neon rows, OpenSearch documents, graph nodes/edges, S3 artifact paths, SQS jobs and policy bundles carry Organization scope. The browser never chooses an arbitrary Organization ID; the API derives it from authenticated context.

Stytch owns authentication, Organization membership, SSO/SCIM and coarse roles. Neon stores product principal links and Workspace/Environment grants.

Use Stytch `authenticateJwt` behavior so recent B2B session JWTs can be validated locally when possible, with normal Stytch refresh/revalidation semantics for older/expired JWTs. Do not silently extend JWT validity during an outage. Sensitive control-plane mutations use a product `RequireFreshAuth` guard that forces current Stytch session revalidation and fails closed if revalidation is unavailable; autonomous runtime policy evaluation does not depend on this external call.

Built-in product roles only in MVP:

- Organization Admin
- Security Admin
- Security Engineer
- Developer/Owner
- Compliance Viewer
- Read-only Viewer

Every API handler receives an `AuthorizationContext` containing Organization, permitted Workspaces/Environments and product permissions. Storage queries must include scope predicates server-side. Cross-Organization access is always forbidden through customer product APIs. MVP does not implement customer impersonation. AgentSec production access is governed by separate audited operational controls and must not bypass product tenant predicates in application code.

Single-tenant mode uses the same authorization code but startup configuration pins the deployment to one Organization and rejects mismatched Organization-scoped data.

## 5. Canonical MVP domain

Product-owned entities:

- Organization
- Workspace
- Environment
- Principal
- Integration
- Sensor
- Asset
- Agent
- Tool
- Identity
- Runtime
- Relationship
- Finding
- AttackPath
- TestDefinition
- TestRun
- AttackLabRun
- Policy
- PolicyDecision
- Session
- EvidenceArtifact
- AuditEvent
- ExportJob
- DataControls
- ExternalDataFlow
- SecurityAgent
- SecurityAgentRun
- SecurityAgentPlan
- SecurityAgentAction
- SecurityAgentApproval
- SecurityAgentVerification

### Evidence confidence

- exact
- strong
- probable
- unattributed

### Capability/path state

- configured
- reachable
- observed
- verified
- blocked

Do not conflate confidence, capability state and severity.

## 6. Storage and durability

### Neon Postgres

System of record for transactional product state:

- multi-tenant Organization/Workspace/Environment authorization configuration
- integrations/sensors
- canonical asset ID map and compact summaries
- findings/workflow state
- attack-path summaries
- test/policy/session summaries
- audit events/index
- settings and exports
- AI audit metadata
- Security Agent definitions, immutable run snapshots, plan/action state, approvals, verification results and action idempotency records

Use pooled application connections and direct migration connection. Every SaaS table with customer data includes `organization_id`; repository methods require scoped access, and critical tables use database-level tenant isolation policies as defense in depth. Nango uses its own database/schema/direct connection and encryption key rather than sharing product tables.

### Amazon OpenSearch Service

Searchable event/session store:

- normalized semantic agent events
- relevant filtered runtime/eBPF events
- policy decisions
- session timeline events
- selected provider activity

No raw prompt/response content unless Environment policy explicitly permits it. Every SaaS document contains Organization scope and all queries go through the scoped EventStore abstraction.

### Neo4j

Rebuildable graph projection for assets, identities, tools, permissions, runtimes, resources, evidence relationships and derived capability/path edges.

Cartography runs through a controlled adapter/namespace. For SaaS, Cartography output is tagged/reconciled into a product Organization before it can enter the canonical graph; the M0 proof must demonstrate two Organizations cannot collide. Product normalization owns customer-visible labels/properties.

### S3

- Organization-scoped red-team/Attack Lab artifacts
- large evidence
- compressed normalized runtime-event batch archive within configured retention
- exports
- signed policy bundles
- diagnostic bundles
- backup/recovery manifests and manual graph/snapshot artifacts where needed

### SQS

Queues:

- `agentsec-background`
- `agentsec-runtime-events`
- `agentsec-tests`

Each has a DLQ. Every job/event batch includes Organization scope and consumers verify it before side effects. Security Agent runs use typed jobs on `agentsec-background`; waiting approvals persist in Neon and resume by enqueueing a new idempotent run-step job after a decision. High-volume runtime events are filtered and batched before SQS. Never enqueue one message per syscall.

## 7. Event and connector flows

Runtime/event flow:

```text
Tetragon / OTLP / runtime gateway / Attack Lab evidence
                   |
                   v
              event-ingest
          validate/filter/normalize
                   |
             batch to SQS
                   |
             platform-worker
             /      |        \
            v       v         v
       S3 archive  OpenSearch  correlation + graph
                              |
                         Neo4j/Neon
                              |
                          product API
                              |
                              UI
```

`event-ingest` acknowledges only after the normalized batch is durably accepted by SQS. One idempotent worker pipeline consumes each batch, archives the normalized batch to Organization-scoped S3, indexes searchable events in OpenSearch, and updates correlation/graph state. The SQS message is not acknowledged until the required archive/index/correlation stages reach a durable terminal state. This avoids pretending one SQS queue is a broadcast bus and keeps OpenSearch rebuildable.

Connector flow:

```text
Integration -> SQS job -> native/security-python adapter
                          |
                 Cartography/Prowler or provider API
                          |
                   normalize/reconcile
                          |
                      Neo4j + Neon
```

Red-team flow:

```text
TestRun -> SQS tests -> Promptfoo worker -> normalized attempts
                                      |
                                 S3 artifacts
                                      |
                                 Neon summary
```

Attack Lab flow:

```text
AttackLabRun -> safety preflight -> Fargate provider -> test workload
                      |                     |
                 reject unsafe          egress proxy
                                            |
                         semantic/gateway/cloud evidence
                                            |
                                      verdict evaluator
```


Security Agent response flow:

```text
finding / attack path / runtime signal / manual run
                    |
                    v
          Security Agent trigger matcher
                    |
              evidence snapshot
                    |
              AIGateway planner
        structured typed plan only
                    |
             plan validator
                    |
    deterministic ActionAuthorizer
             /              \
      auto-approved      approval required
           |                   |
           v                   v
     ActionExecutor      Approval record/UI
           |                   |
           +---------< approved+
                    |
                 execute
                    |
                 verify
           /        |        \
     contained   needs human  failed/inconclusive
                    |
        audit + finding/path/session links
```

The planner never calls provider APIs directly. It receives bounded product evidence and returns only versioned action-plan objects. `ActionAuthorizer` is deterministic and checks the Security Agent definition, Organization/Workspace/Environment scope, action risk class, product safety floor, human approval token where required, and per-run budgets before `ActionExecutor` can perform a side effect.

MVP action adapters live inside the product worker/action registry. No custom executable tool SDK is exposed in v1.

**Latency boundary:** synchronous agent/tool/API allow-block remains the runtime-gateway + embedded OPA fast path. Security Agent planning is asynchronous through `agentsec-background`; an OpenRouter call is never required to decide whether the current application request may proceed.

## 8. Public API contract

Use OpenAPI 3.1. Generate the TypeScript frontend client. Normal UI code may not hand-write `/api/v1/` fetch URLs.

All list operations use cursor pagination and explicit filters. All mutations return product IDs, audit correlation ID and stable product error codes.

### MVP operations

```text
GET    /api/v1/home/summary                              getHomeSummary
GET    /api/v1/search                                    globalSearch

GET    /api/v1/organization                              getOrganization
GET    /api/v1/workspaces                                listWorkspaces
POST   /api/v1/workspaces                                createWorkspace
GET    /api/v1/workspaces/{id}                           getWorkspace
PATCH  /api/v1/workspaces/{id}                           updateWorkspace
GET    /api/v1/environments                              listEnvironments
POST   /api/v1/environments                              createEnvironment
GET    /api/v1/environments/{id}                         getEnvironment
PATCH  /api/v1/environments/{id}                         updateEnvironment

GET    /api/v1/me                                        getCurrentPrincipal
GET    /api/v1/admin/members                             listMembers
GET    /api/v1/admin/roles                               listBuiltInRoles
GET    /api/v1/admin/sso-connections                     listSSOConnections
POST   /api/v1/admin/sso-connections                     createSSOConnection
DELETE /api/v1/admin/sso-connections/{id}                deleteSSOConnection
POST   /api/v1/admin/sso-connections/{id}/test           testSSOConnection
GET    /api/v1/admin/scim-connections                    listSCIMConnections
POST   /api/v1/admin/scim-connections                    createSCIMConnection
DELETE /api/v1/admin/scim-connections/{id}               deleteSCIMConnection
GET    /api/v1/admin/group-mappings                      listGroupMappings
PATCH  /api/v1/admin/group-mappings                      updateGroupMappings
GET    /api/v1/admin/api-tokens                          listAPITokens
POST   /api/v1/admin/api-tokens                          createAPIToken
DELETE /api/v1/admin/api-tokens/{id}                     revokeAPIToken

GET    /api/v1/integration-catalog                       listIntegrationCatalog
GET    /api/v1/integrations                              listIntegrations
POST   /api/v1/integrations                              createIntegration
GET    /api/v1/integrations/{id}                         getIntegration
PATCH  /api/v1/integrations/{id}                         updateIntegration
DELETE /api/v1/integrations/{id}                         deleteIntegration
POST   /api/v1/integrations/{id}/authorize               authorizeIntegration
POST   /api/v1/integrations/{id}/sync                    syncIntegration
GET    /api/v1/integrations/{id}/syncs                   listIntegrationSyncs
GET    /api/v1/integrations/{id}/syncs/{syncId}          getIntegrationSync

GET    /api/v1/sensors                                   listSensors
POST   /api/v1/sensors                                   createSensorEnrollment
GET    /api/v1/sensors/{id}                              getSensor
PATCH  /api/v1/sensors/{id}                              updateSensor
DELETE /api/v1/sensors/{id}                              deleteSensor
POST   /api/v1/sensors/{id}/rotate-token                 rotateSensorToken
GET    /api/v1/sensors/{id}/coverage                     getSensorCoverage

GET    /api/v1/agents                                    listAgents
GET    /api/v1/agents/{id}                               getAgent
PATCH  /api/v1/agents/{id}                               updateAgent
GET    /api/v1/agents/{id}/capabilities                  getAgentCapabilities
GET    /api/v1/agents/{id}/relationships                 getAgentRelationships
GET    /api/v1/agents/{id}/sessions                      listAgentSessions
GET    /api/v1/tools                                     listTools
GET    /api/v1/tools/{id}                                getTool
GET    /api/v1/identities                                listIdentities
GET    /api/v1/identities/{id}                           getIdentity
GET    /api/v1/runtimes                                  listRuntimes
GET    /api/v1/runtimes/{id}                             getRuntime
GET    /api/v1/assets/{id}                               getAsset

GET    /api/v1/findings                                  listFindings
GET    /api/v1/findings/{id}                             getFinding
PATCH  /api/v1/findings/{id}                             updateFinding
POST   /api/v1/findings/{id}/accept-risk                 acceptFindingRisk
POST   /api/v1/findings/{id}/ticket                      createFindingTicket
GET    /api/v1/attack-paths                              listAttackPaths
GET    /api/v1/attack-paths/{id}                         getAttackPath
GET    /api/v1/attack-paths/{id}/break-options           getAttackPathBreakOptions

GET    /api/v1/tests                                     listTests
POST   /api/v1/tests                                     createTest
GET    /api/v1/tests/{id}                                getTest
PATCH  /api/v1/tests/{id}                                updateTest
POST   /api/v1/tests/{id}/runs                           runTest
GET    /api/v1/test-runs                                 listTestRuns
GET    /api/v1/test-runs/{id}                            getTestRun
POST   /api/v1/test-runs/{id}/cancel                     cancelTestRun

GET    /api/v1/attack-lab/runs                           listAttackLabRuns
POST   /api/v1/attack-lab/runs                           createAttackLabRun
GET    /api/v1/attack-lab/runs/{id}                      getAttackLabRun
POST   /api/v1/attack-lab/runs/{id}/cancel               cancelAttackLabRun
POST   /api/v1/attack-lab/runs/{id}/rerun                rerunAttackLabRun

GET    /api/v1/policies                                  listPolicies
POST   /api/v1/policies                                  createPolicy
GET    /api/v1/policies/{id}                             getPolicy
PATCH  /api/v1/policies/{id}                             updatePolicy
DELETE /api/v1/policies/{id}                             deletePolicy
POST   /api/v1/policies/{id}/simulate                    simulatePolicy
POST   /api/v1/policies/{id}/rollout                     rolloutPolicy
POST   /api/v1/policies/{id}/disable                     disablePolicy
GET    /api/v1/policies/{id}/decisions                   listPolicyDecisions

GET    /api/v1/security-agent-templates                    listSecurityAgentTemplates
GET    /api/v1/security-actions                            listSecurityActions
GET    /api/v1/security-agents                             listSecurityAgents
POST   /api/v1/security-agents                             createSecurityAgent
GET    /api/v1/security-agents/{id}                        getSecurityAgent
PATCH  /api/v1/security-agents/{id}                        updateSecurityAgent
DELETE /api/v1/security-agents/{id}                        deleteSecurityAgent
POST   /api/v1/security-agents/{id}/simulate               simulateSecurityAgent
POST   /api/v1/security-agents/{id}/runs                   runSecurityAgent
GET    /api/v1/security-agent-runs                         listSecurityAgentRuns
GET    /api/v1/security-agent-runs/{id}                    getSecurityAgentRun
POST   /api/v1/security-agent-runs/{id}/cancel             cancelSecurityAgentRun
GET    /api/v1/security-agent-approvals                    listSecurityAgentApprovals
GET    /api/v1/security-agent-approvals/{id}               getSecurityAgentApproval
POST   /api/v1/security-agent-approvals/{id}/decision      decideSecurityAgentApproval

GET    /api/v1/sessions                                  listSessions
GET    /api/v1/sessions/{id}                             getSession
GET    /api/v1/sessions/{id}/events                      listSessionEvents

GET    /api/v1/compliance/controls                       listComplianceControls
GET    /api/v1/compliance/evidence                       listComplianceEvidence
POST   /api/v1/compliance/exports                        createComplianceExport
GET    /api/v1/compliance/exports/{id}                   getComplianceExport

GET    /api/v1/audit-events                              listAuditEvents
POST   /api/v1/audit-exports                             createAuditExport
GET    /api/v1/audit-exports/{id}                        getAuditExport

GET    /api/v1/settings/data-controls                    getDataControls
PATCH  /api/v1/settings/data-controls                    updateDataControls
GET    /api/v1/settings/external-data-flows              getExternalDataFlows
PATCH  /api/v1/settings/external-data-flows              updateExternalDataFlows

GET    /api/v1/system/status                             getSystemStatus
GET    /api/v1/system/components                         listSystemComponents
GET    /api/v1/system/version                            getSystemVersion

POST   /api/v1/ai/explanations                           createAIExplanation
```

Internal data-plane operations:

```text
POST /internal/v1/events                                 ingestEvents
POST /internal/v1/sensors/heartbeat                      sensorHeartbeat
GET  /internal/v1/policy-bundles/{environmentId}         getPolicyBundle
POST /internal/v1/runtime/decisions                      recordRuntimeDecision
POST /internal/v1/stytch/webhooks                        stytchWebhook
GET  /internal/v1/integration-auth/callback              integrationAuthCallback
```

## 9. UI-to-API traceability

`docs/product/ui-api-map.yaml` is a required checked-in artifact. CI fails when a referenced operation is missing from OpenAPI or when an interactive MVP operation has no mapped screen/action.

| Screen / flow | API operations |
|---|---|
| Home | getHomeSummary, globalSearch |
| First-admin bootstrap and Organization/Workspace/Environment | Stytch B2B authentication/invite is external auth; post-auth product flow uses getCurrentPrincipal, getOrganization, listWorkspaces, createWorkspace, getWorkspace, updateWorkspace, listEnvironments, createEnvironment, getEnvironment, updateEnvironment |
| Identity & Access | getCurrentPrincipal, listMembers, listBuiltInRoles, listSSOConnections, createSSOConnection, deleteSSOConnection, testSSOConnection, listSCIMConnections, createSCIMConnection, deleteSCIMConnection, listGroupMappings, updateGroupMappings |
| API Access | listAPITokens, createAPIToken, revokeAPIToken |
| Connections, including AWS/Kubernetes/GitHub/launch-IdP setup and Generic Webhook | listIntegrationCatalog, listIntegrations, createIntegration, getIntegration, updateIntegration, deleteIntegration, authorizeIntegration, syncIntegration, listIntegrationSyncs, getIntegrationSync |
| Sensors | listSensors, createSensorEnrollment, getSensor, updateSensor, deleteSensor, rotateSensorToken, getSensorCoverage |
| Agents | listAgents, getAgent, updateAgent, getAgentCapabilities, getAgentRelationships, listAgentSessions |
| Tools & MCP | listTools, getTool, getAsset |
| Identities | listIdentities, getIdentity, getAsset |
| Runtimes | listRuntimes, getRuntime, getAsset |
| Findings | listFindings, getFinding, updateFinding, acceptFindingRisk, createFindingTicket |
| Attack Paths | listAttackPaths, getAttackPath, getAttackPathBreakOptions |
| Red Team | listTests, createTest, getTest, updateTest, runTest, listTestRuns, getTestRun, cancelTestRun |
| Attack Lab | listAttackLabRuns, createAttackLabRun, getAttackLabRun, cancelAttackLabRun, rerunAttackLabRun |
| Policies | listPolicies, createPolicy, getPolicy, updatePolicy, deletePolicy, simulatePolicy, rolloutPolicy, disablePolicy, listPolicyDecisions |
| Security Agents | listSecurityAgentTemplates, listSecurityActions, listSecurityAgents, createSecurityAgent, getSecurityAgent, updateSecurityAgent, deleteSecurityAgent, simulateSecurityAgent, runSecurityAgent, listSecurityAgentRuns, getSecurityAgentRun, cancelSecurityAgentRun |
| Security Agent Approvals | listSecurityAgentApprovals, getSecurityAgentApproval, decideSecurityAgentApproval |
| Sessions | listSessions, getSession, listSessionEvents |
| Compliance Evidence | listComplianceControls, listComplianceEvidence, createComplianceExport, getComplianceExport |
| Audit Log | listAuditEvents, createAuditExport, getAuditExport |
| Data & Retention | getDataControls, updateDataControls |
| External Data Flows | getExternalDataFlows, updateExternalDataFlows |
| System Health | getSystemStatus, listSystemComponents, getSystemVersion |
| Explain with AI | createAIExplanation plus the source screen read operation |

## 10. UX implementation rules

- Every list has loading, empty, error and stale/degraded states.
- `0 findings` is never shown when a required data source is stale or unavailable.
- Evidence badges consistently use Configured, Reachable, Observed, Verified, Blocked.
- Correlation badges consistently use Exact, Strong, Probable, Unattributed.
- Finding detail order is Why -> Evidence -> Path -> Fix -> Verify.
- Attack Lab preflight shows target, credentials, destinations, expected side effects and cleanup before Run.
- Policy creation shows enforcement coverage before simulation.
- Destructive or security-relevant mutations require confirmation and create AuditEvent.
- Customer errors use product language and correlation IDs, not vendor exceptions.
- Optional AI appears beside deterministic evidence and is clearly labeled.
- Security Agent UI always separates AI-proposed rationale/plan from deterministic authorization, approval and observed action evidence.
- Security Agent builder exposes only the fixed action catalog and supported target scopes. No arbitrary shell, URL, plugin upload or executable code fields exist in MVP.
- First-admin bootstrap is product-owned and Stytch-backed. No setup step may require a customer to know a Stytch project/dashboard.
- AWS, Kubernetes, GitHub and launch-IdP setup flows use the common Review access -> Configure -> Test connection -> Initial sync -> Review coverage pattern and expose provider-specific permission guidance through product UI.
- Home is the daily Needs-attention queue and must include critical exposure, pending approvals, Security Agent runs needing human attention, stale launch integrations/sensors and recent verified containment.

## 11. Compliance-ready engineering requirements

Required before enterprise beta:

- SSO and SCIM deprovisioning tests
- built-in RBAC and Workspace/Environment authorization tests
- audit log coverage of security-relevant mutations
- TLS and encryption-at-rest configuration
- KMS/S3 and Secrets Manager integration
- metadata-first default collection
- retention/deletion implementation
- backup/restore rehearsal
- signed images and SBOM
- vulnerability/dependency scanning
- dependency/license/subprocessor inventory
- secure-development/release evidence
- incident-response and vulnerability-remediation runbooks
- PostHog/OpenRouter/OTLP privacy filters and disable switches
- Security Agent planner requests use the same AI egress controls plus evidence-as-untrusted-data framing, structured plan schema, plan hash and evidence-reference audit.
- Every Security Agent action records trigger, definition version, plan step, deterministic authorization result, approval decision when applicable, actor/run identity, redacted parameters, execution result and verification result.
- Sensitive approval decisions require fresh authentication and cannot be satisfied by the planner or the Security Agent run itself.
- HIPAA deployment checklist covering AWS BAA, Stytch HIPAA/BAA review where ePHI could reach identity services, and Neon HIPAA/BAA requirements where ePHI could reach Neon

Regulated default profile:

- PostHog off
- OpenRouter off; Security Agent planning and AI explanations remain disabled until an approved AI egress/data-policy profile is configured
- remote OTLP off unless approved
- raw prompt/response storage off
- Stytch BAA/contractual coverage required if ePHI can reach Stytch; otherwise identity payloads restricted to non-ePHI workforce/authentication metadata
- Neon HIPAA/BAA configuration required if ePHI can reach Neon
- AWS BAA required before ePHI use

ZDR is a privacy control, not contractual HIPAA coverage.

## 12. Observability and product health

All services emit OTLP to the in-cluster Collector. Common attributes must be bounded-cardinality.

Never export raw prompt text, tool arguments, secret values or arbitrary high-cardinality customer content as operational telemetry.

Collector output is one of:

- Grafana Cloud
- New Relic
- none

System Health is product-owned and does not depend on remote observability being healthy.

Required product health signals:

- Stytch request/refresh failure rate
- Neon pool wait/error/latency
- SQS queue/DLQ depth and oldest age
- OpenSearch index latency/errors
- Neo4j query/worker lag
- sensor heartbeat, drop rate and kernel capability
- connector freshness/rate-limit state
- policy bundle age and runtime decision latency
- test/Attack Lab queue and failure classes
- Security Agent queued/running/waiting-approval counts, planner failures, oldest approval age, action failures, verification failures and temporary-control cleanup failures
- Security Agent OpenRouter token/cost aggregates without evidence content
- PostHog/OpenRouter/OTLP optional dependency state

## 13. Reliability and scaling patterns

Use only where needed:

- request deadlines
- retry classification with exponential backoff + jitter
- bounded concurrency
- SQS/DLQ for slow asynchronous work
- idempotency keys
- graceful shutdown
- readiness separate from liveness
- local signed policy cache
- per-tenant/workspace query limits
- bounded graph depth/result counts

- OpenRouter unavailable: new Security Agent planning pauses/fails safe; deterministic findings, tests and runtime policies continue. Existing Security Agent side effects do not continue beyond the last deterministically authorized step.
- Security Agent worker crash/retry: action execution uses `(run_id, step_id)` idempotency keys. A step with unknown external outcome stops for reconciliation rather than repeating a destructive action.
- Security Agent approval timeout: run becomes Needs human/Expired; it never auto-approves.
- Security Agent verification failure: run is Failed or Inconclusive, never Remediated. Temporary containment remains only until its bounded TTL unless an authorized operator explicitly replaces/extends it. Expiry cleanup is idempotent, verified and visible if it fails.
- OpenSearch loss: rebuild searchable runtime/session history from retained S3 normalized event archives within configured retention; do not make OpenSearch the only durable copy.
- SaaS disaster recovery: target MVP RPO <=1 hour and RTO <=4 hours using Neon recovery, S3 durable archives and Terraform/Helm rebuild. No active-active multi-region architecture in MVP.

Avoid adding service mesh, Kafka, custom schedulers, distributed transactions or additional databases in MVP unless a measured blocker appears.

Initial performance gates:

- runtime policy p95 <=25 ms in-cluster for metadata-only decisions
- standard API p95 <=750 ms on reference load
- bounded graph path/neighborhood <=3 seconds
- at least 5,000 relevant normalized events/sec on reference hardware and >=2x highest measured design-partner peak before GA
- no unbounded queues/concurrency
- no silent sensor/event drops

## 14. Milestone dependency graph

```text
M0 Technical proofs
        |
        v
M1 Foundation/contracts/local environment
        |\
        | +--------------------+
        v                      v
M1A Real AWS staging      M2 Identity/admin
        |                      |
        +----------+-----------+
                   |
                   v
            M3 Discovery/event plane
                   |
                   v
            M4 Inventory/exposure
             /              \
            v                v
     M5 Red Team/Lab     M6 Runtime policy
            \                /
             +------v--------+
                    M7 Sessions/compliance/admin UX
                           |
                           v
                    M7A Security Agents/response
                           |
                           v
                    M8 SaaS and single-tenant enterprise release gate
```

M1A starts immediately after M1 and creates only the minimum shared AWS staging skeleton needed to exercise later milestones continuously. M2 can progress in parallel, while M3 uses M1A for real-AWS connector/event smoke. M5 and M6 can run in parallel after M4. M7 session work may start after M4, but the M7 gate waits for M6 so policy evidence is part of session/compliance flows.

## 15. Milestone acceptance gates

**M0 Technical proofs:** every uncertain external/OSS assumption has a pass/fail decision, especially Nango free Auth+Proxy, Cartography normalization, Tetragon signal quality, OpenSearch/SQS flow, embedded OPA latency, Stytch session behavior, Neon pool/recovery, Fargate Attack Lab, and bounded Security Agent planning over untrusted evidence.

**M1 Foundation:** local stack boots, schemas/contracts generate, OpenAPI client generates, and UI/API mapping CI works.

**M1A Real AWS staging:** minimal VPC/EKS, S3/KMS/Secrets, SQS/DLQ, OpenSearch and IAM/IRSA staging skeleton deploys through Terraform and product stubs reach required dependencies without public vendor dashboards. This is a continuous test environment, not production hardening.

**M2 Identity/admin:** first-Organization/first-Admin bootstrap, multi-tenant Organization isolation, Workspace/Environment authorization, Stytch SSO/SCIM, API tokens and audit work end to end; single-tenant mode pins the same model to one Organization.

**M3 Discovery/event plane:** AWS/Kubernetes/GitHub/IdP setup wizards and syncs, Tetragon/OTLP ingest, sensor health, S3 event archive and canonical event flow work in local plus the M1A real-AWS staging environment.

**M4 Inventory/exposure:** agent inventory, capabilities, high-signal findings and attack paths show evidence and degrade honestly.

**M5 Safe testing:** Promptfoo test and Fargate Attack Lab produce deterministic normalized result/verdict without production write credentials.

**M6 Protection:** Monitor/Block policy can simulate, stage, enforce from signed local bundle and show Blocked on re-test.

**M7 Investigation/compliance:** session timeline, evidence export, data controls, System Health and every MVP UI/API mapping pass.

**M7A Agentic response:** built-in and custom bounded Security Agents can automatically trigger from findings/paths/runtime signals, simulate, plan, deterministically authorize, auto-act or wait for approval, execute idempotently, expire temporary containment, verify actions and cleanup, fail safe on planner/action uncertainty, surface Needs-attention work on Home, and produce complete audit evidence without crossing tenant/scope/action boundaries.

**M8 Enterprise release:** SaaS deployment/upgrade/disaster-recovery, cross-Organization isolation, single-tenant install/upgrade/restore, dependency failures, real AWS parity, first-admin/launch-connector onboarding usability, regulated profile, SBOM/signing and both golden flows pass.

## 16. Microtask backlog

**Task sizing rule.** Every backlog item is limited to at most 15 minutes of active engineering work including its local verification. If the timebox expires, stop and create a smaller follow-up or blocker task rather than continuing. Long-running CI/load/soak jobs may execute longer than 15 minutes, but defining the job, starting it, and reviewing one bounded result are separate microtasks. The microtask count is execution granularity, not a project-duration estimate.

### M0 - Technical proof gates

**M0-01 - risk register**  
Depends on: `-`  
Deliverable: Create `docs/decisions/mvp-risk-register.md` with a pass/fail exit criterion for each external/OSS uncertainty.  
Verify: File lists Stytch, Neon, LocalStack/real AWS, Cartography, Prowler, Tetragon, Nango free Auth+Proxy, Promptfoo, embedded OPA, OpenSearch/SQS and Fargate.  
Timebox: <=15 minutes.

**M0-02 - Stytch test config**  
Depends on: `M0-01`  
Deliverable: Wire a non-production Stytch project into a one-file proof without committing credentials.  
Verify: A test login/session can be created and repository secret scan remains clean.  
Timebox: <=15 minutes.

**M0-03 - Stytch JWT proof**  
Depends on: `M0-02`  
Deliverable: Validate a fresh B2B session JWT through the Stytch backend SDK local-validation path.  
Verify: Validation succeeds locally when eligible and an expired/old token follows documented remote refresh/auth behavior.  
Timebox: <=15 minutes.

**M0-04 - Neon pooled proof**  
Depends on: `M0-03`  
Deliverable: Connect a tiny Go program through a pooled Neon application URL.  
Verify: Ten concurrent reads complete without connection leak.  
Timebox: <=15 minutes.

**M0-05 - Neon migration proof**  
Depends on: `M0-04`  
Deliverable: Run one up/down migration through a direct Neon connection on a disposable branch.  
Verify: Schema returns to baseline after down migration.  
Timebox: <=15 minutes.

**M0-06 - LocalStack SQS proof**  
Depends on: `M0-05`  
Deliverable: Create queue, DLQ and send/receive a batched event message in LocalStack.  
Verify: Message round trip and redrive attributes are asserted.  
Timebox: <=15 minutes.

**M0-07 - LocalStack storage proof**  
Depends on: `M0-06`  
Deliverable: Exercise LocalStack S3, KMS and Secrets Manager through the AWS SDK abstraction.  
Verify: Encrypted object and secret round trip succeeds.  
Timebox: <=15 minutes.

**M0-08 - OpenSearch proof**  
Depends on: `M0-07`  
Deliverable: Index and filter one session event in a disposable OpenSearch target.  
Verify: Query by session/environment returns the expected event.  
Timebox: <=15 minutes.

**M0-09 - real AWS IAM proof**  
Depends on: `M0-08`  
Deliverable: Assume one disposable cross-account/read-only role in an isolated AWS test account.  
Verify: Allowed call succeeds and denied call fails as expected.  
Timebox: <=15 minutes.

**M0-10 - Cartography proof**  
Depends on: `M0-09`  
Deliverable: Run two minimal Cartography AWS/GitHub fixtures for different Organizations and inspect their graph output.  
Verify: Required source IDs and relationships normalize into separate Organization scopes with no collision or customer-visible Cartography labels.  
Timebox: <=15 minutes.

**M0-11 - Prowler proof**  
Depends on: `M0-10`  
Deliverable: Run a minimal Prowler AWS fixture and parse one relevant finding.  
Verify: Finding maps to a canonical resource ID and normalized evidence.  
Timebox: <=15 minutes.

**M0-12 - Tetragon proof**  
Depends on: `M0-11`  
Deliverable: Capture process, file and outbound-network events for one supported Linux/Kubernetes test workload.  
Verify: Events share workload identity and sensor reports capability/drop state.  
Timebox: <=15 minutes.

**M0-13 - OTLP proof**  
Depends on: `M0-12`  
Deliverable: Send an agent/task/tool trace through a real local OTel Collector.  
Verify: Trace IDs and required agent attributes reach the ingest adapter.  
Timebox: <=15 minutes.

**M0-14a - Nango free boot proof**  
Depends on: `M0-13`  
Deliverable: Start the free self-hosted Nango build with only required Auth/Proxy dependencies.  
Verify: Health endpoint is reachable from the product test network.  
Timebox: <=15 minutes.

**M0-14b - Nango OAuth proof**  
Depends on: `M0-14a`  
Deliverable: Complete one OAuth connection against a fixture provider through the product wrapper.  
Verify: Product receives a durable connection reference.  
Timebox: <=15 minutes.

**M0-14c - Nango API key proof**  
Depends on: `M0-14b`  
Deliverable: Complete one API-key connection against a fixture provider through the product wrapper.  
Verify: Product receives a connection reference without storing the raw provider key in product state.  
Timebox: <=15 minutes.

**M0-14 - Nango free auth proof**  
Depends on: `M0-14c`  
Deliverable: Record the validated Nango free feature boundary for MVP.  
Verify: Proof explicitly marks Functions, Webhooks and MCP as out of scope.  
Timebox: <=15 minutes.

**M0-15 - Nango proxy proof**  
Depends on: `M0-14`  
Deliverable: Proxy one authenticated GET through free self-hosted Nango.  
Verify: Provider response succeeds and product code never persists the raw provider token.  
Timebox: <=15 minutes.

**M0-16 - Promptfoo proof**  
Depends on: `M0-15`  
Deliverable: Run one prompt-injection case against a local fake agent target.  
Verify: Result can be normalized to objective, verdict and evidence reference.  
Timebox: <=15 minutes.

**M0-17 - OPA SDK proof**  
Depends on: `M0-16`  
Deliverable: Evaluate one Allow and one Block decision using OPA Go SDK in-process.  
Verify: Both decisions are deterministic and meet local latency sanity check.  
Timebox: <=15 minutes.

**M0-18 - Fargate verification proof**  
Depends on: `M0-17`  
Deliverable: Run a canary workload on an existing disposable EKS Fargate test profile.  
Verify: Pod is Fargate-scheduled, canary criterion is observed and run resources are deleted.  
Timebox: <=15 minutes.

**M0-19 - Fargate egress proof**  
Depends on: `M0-18`  
Deliverable: Apply a SecurityGroupPolicy that permits only required cluster/DNS plus product egress-proxy path.  
Verify: Direct undeclared egress fails and allowed proxy egress succeeds.  
Timebox: <=15 minutes.

**M0-20 - PostHog privacy proof**  
Depends on: `M0-19`  
Deliverable: Send one allowlisted analytics event to a fake PostHog endpoint.  
Verify: Serializer rejects seeded prompt, secret, IP and raw evidence fields.  
Timebox: <=15 minutes.

**M0-21 - OpenRouter privacy proof**  
Depends on: `M0-20`  
Deliverable: Send one redacted finding explanation to a fake OpenRouter-compatible endpoint.  
Verify: Seeded secret/PII fields are absent and structured result validates.  
Timebox: <=15 minutes.

**M0-21a - Security Agent planner boundary proof**  
Depends on: `M0-21`  
Deliverable: Send a structured security-response planning request containing untrusted injection text and a fixed two-action catalog to a fake OpenRouter-compatible endpoint.  
Verify: Returned plan validates only when it uses catalog actions and in-scope IDs; arbitrary URL/shell/action output is rejected by product validation.  
Timebox: <=15 minutes.

**M0-22 - OTLP export proof**  
Depends on: `M0-21a`  
Deliverable: Export bounded operational telemetry through Collector to a fake OTLP sink.  
Verify: Exporter failure does not block the proof application.  
Timebox: <=15 minutes.

**M0-23 - M0 gate**  
Depends on: `M0-22`  
Deliverable: Record pass/fail and resulting architecture decision for every proof.  
Verify: No unresolved proof is marked passed and blockers are explicit.  
Timebox: <=15 minutes.

### M1 - Foundation, contracts and local environment

**M1-01d - platform API command**  
Depends on: `M0-23`  
Deliverable: Create the platform API directory and minimal Go command.  
Verify: Command compiles and prints build version.  
Timebox: <=15 minutes.

**M1-01e - platform worker command**  
Depends on: `M1-01d`  
Deliverable: Create the platform worker directory and minimal Go command.  
Verify: Command compiles and prints build version.  
Timebox: <=15 minutes.

**M1-01f - event ingest command**  
Depends on: `M1-01e`  
Deliverable: Create the event-ingest directory and minimal Go command.  
Verify: Command compiles and prints build version.  
Timebox: <=15 minutes.

**M1-01a - runtime gateway command**  
Depends on: `M1-01f`  
Deliverable: Create the runtime-gateway directory and minimal Go command.  
Verify: Command compiles and prints build version.  
Timebox: <=15 minutes.

**M1-01b - worker directories**  
Depends on: `M1-01a`  
Deliverable: Create Python security-worker and Node redteam-worker package skeletons.  
Verify: Each worker starts a no-op health command.  
Timebox: <=15 minutes.

**M1-01c - web and CLI directories**  
Depends on: `M1-01b`  
Deliverable: Create Next.js web shell and agentsecctl command skeleton.  
Verify: Web build and agentsecctl version command succeed.  
Timebox: <=15 minutes.

**M1-01 - repo skeleton**  
Depends on: `M1-01c`  
Deliverable: Add root build commands that invoke the already-created service, worker, web and CLI targets.  
Verify: One root build command succeeds without downloading unpinned runtime dependencies.  
Timebox: <=15 minutes.

**M1-02 - dependency lock**  
Depends on: `M1-01`  
Deliverable: Create `build/dependencies.lock.yaml` with exact initial OSS versions/licenses and owners.  
Verify: CI parser validates required fields and no unreviewed copyleft/runtime dependency is added.  
Timebox: <=15 minutes.

**M1-03 - canonical IDs**  
Depends on: `M1-02`  
Deliverable: Define product UUID/ID wrappers and external-source reference type.  
Verify: Unit test prevents external vendor ID from becoming product primary key.  
Timebox: <=15 minutes.

**M1-04 - scope model**  
Depends on: `M1-03`  
Deliverable: Define Organization/Workspace/Environment `Scope`.  
Verify: Validation rejects missing Organization or Environment on scoped security entities.  
Timebox: <=15 minutes.

**M1-05 - evidence model**  
Depends on: `M1-04`  
Deliverable: Define EvidenceRef, confidence and capability/path state enums.  
Verify: Enum round-trip tests pass and confidence is distinct from severity.  
Timebox: <=15 minutes.

**M1-06 - product error envelope**  
Depends on: `M1-05`  
Deliverable: Define stable API error code, message, correlation ID and retryable flag.  
Verify: JSON contract snapshot passes.  
Timebox: <=15 minutes.

**M1-07 - config loader**  
Depends on: `M1-06`  
Deliverable: Create typed config with required/optional dependency groups and secret references.  
Verify: Missing required config fails start; optional config does not.  
Timebox: <=15 minutes.

**M1-08 - external client policy**  
Depends on: `M1-07`  
Deliverable: Create shared timeout/retry/concurrency helper for HTTP clients.  
Verify: Unit tests retry transient errors only and enforce deadline.  
Timebox: <=15 minutes.

**M1-09 - idempotency helper**  
Depends on: `M1-08`  
Deliverable: Create idempotency-key store interface and request helper.  
Verify: Duplicate key returns prior result reference.  
Timebox: <=15 minutes.

**M1-10 - Neon schema baseline**  
Depends on: `M1-09`  
Deliverable: Create initial Neon migration framework and schema-version table.  
Verify: Fresh up migration and down rollback pass on disposable Neon branch.  
Timebox: <=15 minutes.

**M1-11 - Neon pool wrapper**  
Depends on: `M1-10`  
Deliverable: Create pooled application DB wrapper with query timeout and health stats.  
Verify: Pool test reports wait/in-use and closes cleanly.  
Timebox: <=15 minutes.

**M1-12 - S3 artifact interface**  
Depends on: `M1-11`  
Deliverable: Create ArtifactStore interface and S3 implementation skeleton.  
Verify: Put/Get/Delete fixture passes against LocalStack.  
Timebox: <=15 minutes.

**M1-13 - SQS queue interface**  
Depends on: `M1-12`  
Deliverable: Create JobQueue interface and SQS batch implementation skeleton.  
Verify: Batch publish/consume fixture passes against LocalStack.  
Timebox: <=15 minutes.

**M1-14 - OpenSearch EventStore**  
Depends on: `M1-13`  
Deliverable: Create EventStore interface and OpenSearch index/search skeleton.  
Verify: Index/search fixture passes and scope filter is mandatory.  
Timebox: <=15 minutes.

**M1-15 - GraphStore interface**  
Depends on: `M1-14`  
Deliverable: Create product GraphStore interface independent of Neo4j types.  
Verify: Fake implementation passes contract tests.  
Timebox: <=15 minutes.

**M1-16 - Neo4j GraphStore**  
Depends on: `M1-15`  
Deliverable: Implement minimal Neo4j node/edge upsert/read contract.  
Verify: Scoped upsert/read fixture passes.  
Timebox: <=15 minutes.

**M1-17 - audit emitter contract**  
Depends on: `M1-16`  
Deliverable: Define AuditEmitter interface and required mutation fields.  
Verify: Unit test rejects security mutation without actor/action/target/outcome.  
Timebox: <=15 minutes.

**M1-18 - feature flag contract**  
Depends on: `M1-17`  
Deliverable: Define FeatureFlags interface with explicit code default and cache metadata.  
Verify: Fake outage returns configured default.  
Timebox: <=15 minutes.

**M1-19 - analytics contract**  
Depends on: `M1-18`  
Deliverable: Define ProductTelemetry interface and allowlist serializer contract.  
Verify: Unknown field is rejected, not silently forwarded.  
Timebox: <=15 minutes.

**M1-20 - AI gateway contract**  
Depends on: `M1-19`  
Deliverable: Define AIGateway request/result and data-policy metadata.  
Verify: Schema test rejects unapproved purpose.  
Timebox: <=15 minutes.

**M1-21 - observability contract**  
Depends on: `M1-20`  
Deliverable: Define common OTLP resource attributes and correlation helper.  
Verify: Cardinality/unit test rejects raw customer content attributes.  
Timebox: <=15 minutes.

**M1-22 - event envelope**  
Depends on: `M1-21`  
Deliverable: Define SecurityEvent envelope with version, scope, source, time, evidence and correlation fields.  
Verify: Unscoped or unknown-version event is rejected.  
Timebox: <=15 minutes.

**M1-23 - OpenAPI root**  
Depends on: `M1-22`  
Deliverable: Create OpenAPI 3.1 root, auth schemes, pagination/error schemas.  
Verify: OpenAPI linter passes.  
Timebox: <=15 minutes.

**M1-24 - generated TS client**  
Depends on: `M1-23`  
Deliverable: Generate the frontend API client from OpenAPI.  
Verify: Generated package compiles and is reproducible.  
Timebox: <=15 minutes.

**M1-25 - UI API map seed**  
Depends on: `M1-24`  
Deliverable: Create `docs/product/ui-api-map.yaml` with concrete Home and System Health entries using their planned operation IDs.  
Verify: Coverage script resolves both operation IDs once defined.  
Timebox: <=15 minutes.

**M1-26 - UI API coverage CI**  
Depends on: `M1-25`  
Deliverable: Add CI script that fails for missing mapped operation or interactive public operation without a screen mapping.  
Verify: Deliberately removing one op makes test fail.  
Timebox: <=15 minutes.

**M1-27 - raw fetch lint**  
Depends on: `M1-26`  
Deliverable: Add frontend lint rule/test forbidding hand-written `/api/v1/` requests outside generated client.  
Verify: Seeded violation fails lint.  
Timebox: <=15 minutes.

**M1-28a - shared health handler**  
Depends on: `M1-27`  
Deliverable: Implement shared Go health/readiness/version/metrics handler package.  
Verify: Unit test distinguishes liveness, readiness and version responses.  
Timebox: <=15 minutes.

**M1-28b - platform health wiring**  
Depends on: `M1-28a`  
Deliverable: Wire shared health handlers into platform API and worker commands.  
Verify: Both commands expose health/readiness/version/metrics endpoints.  
Timebox: <=15 minutes.

**M1-28c - ingest health wiring**  
Depends on: `M1-28b`  
Deliverable: Wire shared health handlers into event-ingest.  
Verify: event-ingest smoke test distinguishes liveness and readiness.  
Timebox: <=15 minutes.

**M1-28d - gateway health wiring**  
Depends on: `M1-28c`  
Deliverable: Wire shared health handlers into runtime-gateway.  
Verify: runtime-gateway smoke test distinguishes liveness and readiness.  
Timebox: <=15 minutes.

**M1-28 - service health endpoints**  
Depends on: `M1-28d`  
Deliverable: Register common health endpoint contract in OpenAPI/internal service docs.  
Verify: All Go commands expose the same endpoint semantics.  
Timebox: <=15 minutes.

**M1-29 - system health aggregator model**  
Depends on: `M1-28`  
Deliverable: Define component status Healthy/Degraded/Unavailable with reason and last success.  
Verify: Aggregation test handles required vs optional dependencies.  
Timebox: <=15 minutes.

**M1-30a - local product manifests**  
Depends on: `M1-29`  
Deliverable: Create local Kubernetes manifests for product API, worker, event-ingest and runtime-gateway stubs.  
Verify: All four pods become Ready in local Kubernetes.  
Timebox: <=15 minutes.

**M1-30b - local graph manifest**  
Depends on: `M1-30a`  
Deliverable: Add local Neo4j service and persistent test volume configuration.  
Verify: Graph health is reachable only inside the local cluster.  
Timebox: <=15 minutes.

**M1-30c - local observability manifest**  
Depends on: `M1-30b`  
Deliverable: Add local OpenTelemetry Collector with a no-egress debug/test sink.  
Verify: A test span reaches the local sink.  
Timebox: <=15 minutes.

**M1-30d - local AWS emulator manifest**  
Depends on: `M1-30c`  
Deliverable: Add LocalStack service and endpoint environment variables for local AWS clients.  
Verify: A test S3 call uses the LocalStack endpoint.  
Timebox: <=15 minutes.

**M1-30 - local dev manifests**  
Depends on: `M1-30d`  
Deliverable: Add one local start target for the assembled manifests.  
Verify: Local environment starts without vendor dashboards exposed.  
Timebox: <=15 minutes.

**M1-31 - LocalStack client factory**  
Depends on: `M1-30`  
Deliverable: Add AWS endpoint override in product AWS client factory for local/CI only.  
Verify: Test points SQS/S3/KMS/Secrets/OpenSearch clients at LocalStack.  
Timebox: <=15 minutes.

**M1-32 - OpenSearch index template**  
Depends on: `M1-31`  
Deliverable: Create scoped session/runtime event index template with bounded keyword fields.  
Verify: Template rejects dynamic mapping explosion fixture.  
Timebox: <=15 minutes.

**M1-33 - SQS queue definitions**  
Depends on: `M1-32`  
Deliverable: Define three queues and DLQs with message schema/retention settings.  
Verify: LocalStack provision test sees all queues/DLQs.  
Timebox: <=15 minutes.

**M1-34 - S3 bucket layout**  
Depends on: `M1-33`  
Deliverable: Define evidence/export/policy key prefixes and KMS configuration contract.  
Verify: Artifact key builder cannot escape organization/workspace prefix.  
Timebox: <=15 minutes.

**M1-35 - base web shell**  
Depends on: `M1-34`  
Deliverable: Create product shell, unauthenticated-route guard scaffold and left-nav component from PRD IA.  
Verify: Route smoke test renders all MVP nav labels, no OSS labels.  
Timebox: <=15 minutes.

**M1-36a - M1 build check**  
Depends on: `M1-35`  
Deliverable: Run clean-checkout service, worker, web and CLI build checks.  
Verify: All build targets succeed.  
Timebox: <=15 minutes.

**M1-36b - M1 schema check**  
Depends on: `M1-36a`  
Deliverable: Run database/event/domain schema validation checks.  
Verify: All schema checks succeed with no drift.  
Timebox: <=15 minutes.

**M1-36c - M1 OpenAPI check**  
Depends on: `M1-36b`  
Deliverable: Run OpenAPI generation and generated-client drift check.  
Verify: Generated client has no uncommitted diff.  
Timebox: <=15 minutes.

**M1-36d - M1 UI API coverage check**  
Depends on: `M1-36c`  
Deliverable: Run UI/API traceability validator.  
Verify: No interactive operation lacks a mapped UI action or implementation task.  
Timebox: <=15 minutes.

**M1-36e - M1 local infrastructure smoke**  
Depends on: `M1-36d`  
Deliverable: Run local Kubernetes and LocalStack smoke checks.  
Verify: Required local dependencies report healthy.  
Timebox: <=15 minutes.

**M1-37 - deployment mode config**  
Depends on: `M1-07`  
Deliverable: Add `saas` and `single_tenant` deployment-mode configuration plus optional pinned Organization ID for single-tenant mode.  
Verify: SaaS starts without a pinned Organization; single-tenant mode rejects startup without one.  
Timebox: <=15 minutes.

**M1-38 - Neon Organization scope guard**  
Depends on: `M1-04, M1-10`  
Deliverable: Add a scoped repository helper that requires Organization ID for customer-data queries.  
Verify: A fixture query without Organization scope fails before SQL execution.  
Timebox: <=15 minutes.

**M1-39 - OpenSearch Organization scope guard**  
Depends on: `M1-04, M1-14`  
Deliverable: Add Organization scope to EventStore index and query builders.  
Verify: Organization A query cannot return Organization B fixture document.  
Timebox: <=15 minutes.

**M1-40 - S3 Organization artifact prefix**  
Depends on: `M1-04, M1-12`  
Deliverable: Prefix SaaS ArtifactStore keys with immutable Organization scope.  
Verify: Organization A cannot read a fixture key created for Organization B through the product store.  
Timebox: <=15 minutes.

**M1-41 - SQS Organization envelope guard**  
Depends on: `M1-04, M1-13`  
Deliverable: Require Organization scope in background/test/runtime-event queue envelopes.  
Verify: Consumer rejects a message with missing or mismatched Organization scope before side effects.  
Timebox: <=15 minutes.

**M1-42 - graph Organization scope guard**  
Depends on: `M1-04, M1-16`  
Deliverable: Require Organization scope on graph node/edge writes and graph reads.  
Verify: A bounded path query for Organization A cannot traverse Organization B fixture nodes.  
Timebox: <=15 minutes.

**M1-43 - tenant quota primitive**  
Depends on: `M1-04, M1-07`  
Deliverable: Define Organization-scoped concurrency/quota keys for connectors, graph queries, tests and AI requests.  
Verify: Unit fixture separates counters for two Organizations and rejects an over-limit request predictably.  
Timebox: <=15 minutes.

**M1-44 - SaaS tenancy foundation check**  
Depends on: `M1-38, M1-39, M1-40, M1-41, M1-42, M1-43`  
Deliverable: Run the bounded cross-Organization store/queue/graph contract suite.  
Verify: Every cross-Organization fixture is denied and single-tenant mode still passes the same scoped contracts.  
Timebox: <=15 minutes.

**M1-45a - Neon tenant context helper**  
Depends on: `M1-38`  
Deliverable: Add a transaction helper that sets the current Organization context for tenant-protected queries.  
Verify: Unit/integration fixture exposes the expected Organization context only inside the scoped transaction.  
Timebox: <=15 minutes.

**M1-45b - Neon RLS core identity/policy tables**  
Depends on: `M1-45a`  
Deliverable: Enable Row Level Security for Organization, Workspace-grant, integration and policy tables using the scoped Organization context.  
Verify: Direct SQL fixture under Organization A cannot read Organization B rows from those tables.  
Timebox: <=15 minutes.

**M1-45c - Neon RLS security workflow tables**  
Depends on: `M1-45b`  
Deliverable: Enable the same RLS policy pattern for findings, tests, audit metadata and export-job tables.  
Verify: Direct SQL fixture under Organization A cannot read or mutate Organization B workflow rows.  
Timebox: <=15 minutes.

**M1-45d - Neon RLS migration rollback**  
Depends on: `M1-45c`  
Deliverable: Add down migration coverage for tenant RLS policies.  
Verify: Disposable Neon branch migrates up/down without leaving stale tenant policies.  
Timebox: <=15 minutes.

**M1-45 - Neon tenant isolation gate**  
Depends on: `M1-45d`  
Deliverable: Run the bounded RLS cross-Organization fixture suite.  
Verify: Tenant-protected direct SQL paths fail cross-Organization and normal scoped repository tests still pass.  
Timebox: <=15 minutes.

**M1-36 - M1 gate**  
Depends on: `M1-36e, M1-44, M1-45`  
Deliverable: Write the M1 gate result from the five independent checks.  
Verify: Gate record is PASS only when all check artifacts passed.  
Timebox: <=15 minutes.

### M1A - Minimal real AWS staging skeleton

**M1A-01 - staging VPC module**  
Depends on: `M1-36`  
Deliverable: Create minimal VPC/private-subnet Terraform module for the shared non-production SaaS staging environment.  
Verify: `terraform validate` passes and subnet outputs exist.  
Timebox: <=15 minutes.

**M1A-02 - staging EKS module**  
Depends on: `M1A-01`  
Deliverable: Add minimal EKS cluster module consuming the staging VPC outputs.  
Verify: `terraform validate` passes and cluster outputs exist.  
Timebox: <=15 minutes.

**M1A-03 - staging S3 KMS Secrets**  
Depends on: `M1A-02`  
Deliverable: Add staging evidence/event-archive bucket, KMS key and Secrets Manager entries.  
Verify: Terraform plan shows encryption and no public bucket access.  
Timebox: <=15 minutes.

**M1A-04 - staging SQS DLQ**  
Depends on: `M1A-03`  
Deliverable: Add the three staging queues and DLQs using the product queue contract.  
Verify: Terraform plan has redrive policies and queue outputs.  
Timebox: <=15 minutes.

**M1A-05 - staging OpenSearch**  
Depends on: `M1A-04`  
Deliverable: Add private staging OpenSearch domain using the current EventStore contract.  
Verify: Terraform plan has VPC-only access and encryption.  
Timebox: <=15 minutes.

**M1A-06 - staging IAM IRSA**  
Depends on: `M1A-05`  
Deliverable: Add minimum IAM/IRSA roles for product stubs to reach staging S3, SQS and OpenSearch.  
Verify: Policy test denies unrelated write actions.  
Timebox: <=15 minutes.

**M1A-07 - staging product stub deploy**  
Depends on: `M1A-06`  
Deliverable: Deploy web/API/worker/event-ingest stubs from M1 into the staging EKS cluster.  
Verify: Product endpoints become Ready without exposing vendor dashboards.  
Timebox: <=15 minutes.

**M1A-08 - staging AWS dependency smoke**  
Depends on: `M1A-07`  
Deliverable: Exercise one scoped S3, SQS and OpenSearch operation from a product pod.  
Verify: All three calls succeed through IRSA and emit OTLP health evidence.  
Timebox: <=15 minutes.

**M1A-09 - staging deployment evidence**  
Depends on: `M1A-08`  
Deliverable: Record Terraform revision, cluster/version and product image hashes for later milestone smoke tests.  
Verify: Evidence record contains no credentials and is reproducible.  
Timebox: <=15 minutes.

**M1A-10 - M1A gate**  
Depends on: `M1A-09`  
Deliverable: Write the M1A gate result for minimal real-AWS staging readiness.  
Verify: Gate is PASS only when product stubs reach all required staging dependencies with private endpoints.  
Timebox: <=15 minutes.

### M2 - Identity and enterprise administration

**M2-01 - Stytch adapter**  
Depends on: `M1-36`  
Deliverable: Create product Stytch B2B adapter for authenticateJwt, Organization, SSO and SCIM operations.  
Verify: Fake/real test adapter returns product ExternalPrincipal without leaking Stytch SDK types.  
Timebox: <=15 minutes.

**M2-02 - session middleware**  
Depends on: `M2-01`  
Deliverable: Parse Stytch session JWT and create authenticated ExternalPrincipal.  
Verify: Fresh JWT path succeeds; invalid/expired fixture fails with stable auth error.  
Timebox: <=15 minutes.

**M2-02a - fresh-auth guard**  
Depends on: `M2-02`  
Deliverable: Add `RequireFreshAuth` middleware for security-sensitive control-plane mutations.  
Verify: Revoked-session fixture is denied through remote Stytch revalidation; Stytch outage fails the guarded mutation closed.  
Timebox: <=15 minutes.

**M2-03 - principal reconciliation**  
Depends on: `M2-02a`  
Deliverable: Persist Stytch member/org references to product principal table.  
Verify: Repeated reconciliation is idempotent.  
Timebox: <=15 minutes.

**M2-04 - built-in roles**  
Depends on: `M2-03`  
Deliverable: Define built-in role to product-permission mapping.  
Verify: Permission table snapshot matches PRD roles.  
Timebox: <=15 minutes.

**M2-05a - workspace grant store**  
Depends on: `M2-04`  
Deliverable: Create persistence methods for product Workspace/Environment grants.  
Verify: Grant create/list/delete fixture remains scoped to the authenticated Organization.  
Timebox: <=15 minutes.

**M2-05b - workspace grant resolver**  
Depends on: `M2-05a`  
Deliverable: Resolve effective Workspace/Environment permissions for one product principal.  
Verify: Cross-workspace access fixture resolves to denied permission.  
Timebox: <=15 minutes.

**M2-05 - workspace grant store**  
Depends on: `M2-05b`  
Deliverable: Wire grant store and resolver behind the authorization service.  
Verify: Authorized fixture passes and cross-workspace fixture is denied.  
Timebox: <=15 minutes.

**M2-06 - authorization middleware**  
Depends on: `M2-05`  
Deliverable: Resolve AuthorizationContext and enforce required permission/scope.  
Verify: Handler test denies unauthorized scope server-side.  
Timebox: <=15 minutes.

**M2-07 - organization reconciliation**  
Depends on: `M2-06`  
Deliverable: Create idempotent product Organization reconciliation from the authenticated Stytch Organization.  
Verify: Two Stytch Organizations map to two product Organizations; repeated reconciliation returns the existing matching Organization.  
Timebox: <=15 minutes.

**M2-07a - first-Organization bootstrap command**  
Depends on: `M2-07`  
Deliverable: Add an AgentSec operator-only bootstrap command/service that creates or resolves one Stytch Organization plus matching product Organization from customer name/domain and designated first Admin email.  
Verify: Re-running the same bootstrap is idempotent and produces one matching Organization.  
Timebox: <=15 minutes.

**M2-07b - first-Admin Stytch invitation**  
Depends on: `M2-07a`  
Deliverable: Invite the designated first Organization Admin through the Stytch B2B bootstrap sign-in method without creating a local password.  
Verify: Invite references the expected Organization/member and no raw auth secret is persisted in product state.  
Timebox: <=15 minutes.

**M2-07c - first-Admin default scope bootstrap**  
Depends on: `M2-07b`  
Deliverable: On the first successful Admin session, create default Workspace plus production/staging/development Environments if absent.  
Verify: Repeated sign-in is idempotent and does not duplicate scopes.  
Timebox: <=15 minutes.

**M2-07d - first-Admin bootstrap E2E**  
Depends on: `M2-07c`  
Deliverable: Run provision -> invite -> first sign-in -> default scope fixture through product code.  
Verify: Admin reaches Identity & Access with Organization Admin permission and no customer-facing bypass login.  
Timebox: <=15 minutes.

**M2-08 - API getOrganization**  
Depends on: `M2-07d`  
Deliverable: Implement OpenAPI operation `getOrganization` for `GET /api/v1/organization` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-09 - API listWorkspaces**  
Depends on: `M2-08`  
Deliverable: Implement OpenAPI operation `listWorkspaces` for `GET /api/v1/workspaces` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-10 - API createWorkspace**  
Depends on: `M2-09`  
Deliverable: Implement OpenAPI operation `createWorkspace` for `POST /api/v1/workspaces` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-11 - API getWorkspace**  
Depends on: `M2-10`  
Deliverable: Implement OpenAPI operation `getWorkspace` for `GET /api/v1/workspaces/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-12 - API updateWorkspace**  
Depends on: `M2-11`  
Deliverable: Implement OpenAPI operation `updateWorkspace` for `PATCH /api/v1/workspaces/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-13 - API listEnvironments**  
Depends on: `M2-12`  
Deliverable: Implement OpenAPI operation `listEnvironments` for `GET /api/v1/environments` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-14 - API createEnvironment**  
Depends on: `M2-13`  
Deliverable: Implement OpenAPI operation `createEnvironment` for `POST /api/v1/environments` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-15 - API getEnvironment**  
Depends on: `M2-14`  
Deliverable: Implement OpenAPI operation `getEnvironment` for `GET /api/v1/environments/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-16 - API updateEnvironment**  
Depends on: `M2-15`  
Deliverable: Implement OpenAPI operation `updateEnvironment` for `PATCH /api/v1/environments/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-17 - API getCurrentPrincipal**  
Depends on: `M2-16`  
Deliverable: Implement OpenAPI operation `getCurrentPrincipal` for `GET /api/v1/me` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-18 - API listMembers**  
Depends on: `M2-17`  
Deliverable: Implement OpenAPI operation `listMembers` for `GET /api/v1/admin/members` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-19 - API listBuiltInRoles**  
Depends on: `M2-18`  
Deliverable: Implement OpenAPI operation `listBuiltInRoles` for `GET /api/v1/admin/roles` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-20 - SSO service**  
Depends on: `M2-19`  
Deliverable: Create product SSO service that validates product config and calls Stytch adapter.  
Verify: Fake adapter test covers create/list/delete/test semantics.  
Timebox: <=15 minutes.

**M2-21 - API listSSOConnections**  
Depends on: `M2-20`  
Deliverable: Implement OpenAPI operation `listSSOConnections` for `GET /api/v1/admin/sso-connections` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-22 - API createSSOConnection**  
Depends on: `M2-21`  
Deliverable: Implement OpenAPI operation `createSSOConnection` for `POST /api/v1/admin/sso-connections` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-23 - API deleteSSOConnection**  
Depends on: `M2-22`  
Deliverable: Implement OpenAPI operation `deleteSSOConnection` for `DELETE /api/v1/admin/sso-connections/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-24 - API testSSOConnection**  
Depends on: `M2-23`  
Deliverable: Implement OpenAPI operation `testSSOConnection` for `POST /api/v1/admin/sso-connections/{id}/test` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-25 - SCIM config service**  
Depends on: `M2-24`  
Deliverable: Create product SCIM connection service over Stytch.  
Verify: Create/list/delete tests pass without implementing product `/scim/v2` endpoints.  
Timebox: <=15 minutes.

**M2-26 - API listSCIMConnections**  
Depends on: `M2-25`  
Deliverable: Implement OpenAPI operation `listSCIMConnections` for `GET /api/v1/admin/scim-connections` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-27 - API createSCIMConnection**  
Depends on: `M2-26`  
Deliverable: Implement OpenAPI operation `createSCIMConnection` for `POST /api/v1/admin/scim-connections` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-28 - API deleteSCIMConnection**  
Depends on: `M2-27`  
Deliverable: Implement OpenAPI operation `deleteSCIMConnection` for `DELETE /api/v1/admin/scim-connections/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-29 - Stytch webhook verifier**  
Depends on: `M2-28`  
Deliverable: Verify Stytch webhook signature/event identity and deduplicate event ID.  
Verify: Invalid signature fails; replay is idempotent.  
Timebox: <=15 minutes.

**M2-30 - Stytch deprovision reconciliation**  
Depends on: `M2-29`  
Deliverable: Remove product grants for deprovisioned member/group changes.  
Verify: Fixture loses access and emits audit event.  
Timebox: <=15 minutes.

**M2-31 - group mapping store**  
Depends on: `M2-30`  
Deliverable: Create versioned IdP-group to built-in-role/Workspace-grant mapping store.  
Verify: Mapping update changes resolved authorization on next reconciliation.  
Timebox: <=15 minutes.

**M2-32 - API listGroupMappings**  
Depends on: `M2-31`  
Deliverable: Implement OpenAPI operation `listGroupMappings` for `GET /api/v1/admin/group-mappings` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-33 - API updateGroupMappings**  
Depends on: `M2-32`  
Deliverable: Implement OpenAPI operation `updateGroupMappings` for `PATCH /api/v1/admin/group-mappings` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-34 - API token model**  
Depends on: `M2-33`  
Deliverable: Create hashed product API token model with scope, expiry and last-used fields.  
Verify: Raw token is returned only once and never stored.  
Timebox: <=15 minutes.

**M2-35 - API listAPITokens**  
Depends on: `M2-34`  
Deliverable: Implement OpenAPI operation `listAPITokens` for `GET /api/v1/admin/api-tokens` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-36 - API createAPIToken**  
Depends on: `M2-35`  
Deliverable: Implement OpenAPI operation `createAPIToken` for `POST /api/v1/admin/api-tokens` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-37 - API revokeAPIToken**  
Depends on: `M2-36`  
Deliverable: Implement OpenAPI operation `revokeAPIToken` for `DELETE /api/v1/admin/api-tokens/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-38 - API token auth**  
Depends on: `M2-37`  
Deliverable: Authenticate product API token into the same AuthorizationContext.  
Verify: Revoked/expired token fails; scoped token cannot cross Workspace.  
Timebox: <=15 minutes.

**M2-39a - audit event store**  
Depends on: `M2-38`  
Deliverable: Create append-only AuditEvent store and query method.  
Verify: No update/delete store method exists and append/read fixture passes.  
Timebox: <=15 minutes.

**M2-39b - audit metadata redaction**  
Depends on: `M2-39a`  
Deliverable: Add structured audit metadata redaction before persistence.  
Verify: Seeded secret fixture is replaced before store append.  
Timebox: <=15 minutes.

**M2-39 - audit store**  
Depends on: `M2-39b`  
Deliverable: Wire audit append and redaction into the product audit service.  
Verify: Representative event is redacted, append-only and queryable.  
Timebox: <=15 minutes.

**M2-40 - API listAuditEvents**  
Depends on: `M2-39`  
Deliverable: Implement OpenAPI operation `listAuditEvents` for `GET /api/v1/audit-events` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-41 - API createAuditExport**  
Depends on: `M2-40`  
Deliverable: Implement OpenAPI operation `createAuditExport` for `POST /api/v1/audit-exports` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-42 - API getAuditExport**  
Depends on: `M2-41`  
Deliverable: Implement OpenAPI operation `getAuditExport` for `GET /api/v1/audit-exports/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M2-43a - Identity route shell**  
Depends on: `M2-42`  
Deliverable: Create the Identity & Access route shell and section navigation.  
Verify: Route renders all five section labels with generated-client provider.  
Timebox: <=15 minutes.

**M2-43b - Members and roles panel**  
Depends on: `M2-43a`  
Deliverable: Bind members and built-in roles read panels.  
Verify: Loading/empty/error fixtures render correctly.  
Timebox: <=15 minutes.

**M2-43c - SSO panel**  
Depends on: `M2-43b`  
Deliverable: Build SSO connections list/create/test/delete panel.  
Verify: Component test covers test-success and product error.  
Timebox: <=15 minutes.

**M2-43d - SCIM panel**  
Depends on: `M2-43c`  
Deliverable: Build SCIM connections list/create/delete panel.  
Verify: Component test renders connection state and confirmation.  
Timebox: <=15 minutes.

**M2-43e - Group mapping panel**  
Depends on: `M2-43d`  
Deliverable: Build IdP group mapping editor for role and Workspace grants.  
Verify: Component test saves one mapping and shows validation error.  
Timebox: <=15 minutes.

**M2-43 - identity admin UI shell**  
Depends on: `M2-43e`  
Deliverable: Compose Identity & Access panels into one page and run route smoke test.  
Verify: All panels render together with no direct Stytch dashboard dependency.  
Timebox: <=15 minutes.

**M2-44 - identity admin actions**  
Depends on: `M2-43`  
Deliverable: Wire SSO test, SCIM create/delete and group mapping actions with confirmations/errors.  
Verify: E2E fake Stytch flow passes.  
Timebox: <=15 minutes.

**M2-45 - API access UI**  
Depends on: `M2-44`  
Deliverable: Create API Access list/create/revoke flow.  
Verify: E2E displays token once then revokes it.  
Timebox: <=15 minutes.

**M2-46a - Workspace onboarding form**  
Depends on: `M2-45`  
Deliverable: Build create/update Workspace form.  
Verify: Component test validates name and saves through generated client.  
Timebox: <=15 minutes.

**M2-46b - Environment onboarding form**  
Depends on: `M2-46a`  
Deliverable: Build create/update Environment form.  
Verify: Component test sets production/staging/development and saves.  
Timebox: <=15 minutes.

**M2-46c - Scope selector**  
Depends on: `M2-46b`  
Deliverable: Build Workspace/Environment selector backed by authorized scope.  
Verify: Selection persists and inaccessible scope is absent.  
Timebox: <=15 minutes.

**M2-46 - workspace/env onboarding UI**  
Depends on: `M2-46c`  
Deliverable: Compose Workspace/Environment onboarding flow and scope selector.  
Verify: E2E create/update/select flow passes.  
Timebox: <=15 minutes.

**M2-47a - M2 SSO session E2E**  
Depends on: `M2-46`  
Deliverable: Run sign-in, session validation and sign-out/revocation fixture.  
Verify: Expected Stytch-backed session states map to product errors and access.  
Timebox: <=15 minutes.

**M2-47b - M2 SCIM deprovision E2E**  
Depends on: `M2-47a`  
Deliverable: Run user/group provision then deprovision fixture.  
Verify: Workspace grants are removed within the documented revocation behavior.  
Timebox: <=15 minutes.

**M2-47c - M2 workspace authorization E2E**  
Depends on: `M2-47b`  
Deliverable: Run cross-workspace authorization fixture.  
Verify: Unauthorized workspace read and mutation are denied server-side.  
Timebox: <=15 minutes.

**M2-47d - M2 API token E2E**  
Depends on: `M2-47c`  
Deliverable: Create, use and revoke one scoped API token.  
Verify: Revoked token is rejected and all lifecycle actions are audited.  
Timebox: <=15 minutes.

**M2-47e - M2 audit E2E**  
Depends on: `M2-47d`  
Deliverable: Run representative SSO, role/grant and token mutations.  
Verify: Each security-relevant mutation appears in product audit history.  
Timebox: <=15 minutes.

**M2-48 - cross-Organization API authorization**  
Depends on: `M2-06, M2-07`  
Deliverable: Add an authorization fixture with two Stytch Organizations and identical Workspace names.  
Verify: Principal from Organization A receives a stable forbidden result for Organization B resource IDs.  
Timebox: <=15 minutes.

**M2-49 - single-tenant Organization pin guard**  
Depends on: `M1-37, M2-07`  
Deliverable: Reject authenticated Organization IDs that differ from the configured single-tenant Organization.  
Verify: Matching Organization succeeds; mismatched Organization fails before repository access.  
Timebox: <=15 minutes.

**M2-50 - SaaS Organization isolation E2E**  
Depends on: `M2-48, M2-49`  
Deliverable: Run one bounded two-Organization login/read/mutation authorization scenario.  
Verify: Same product routes work for both Organizations independently and no cross-Organization object is returned or mutated.  
Timebox: <=15 minutes.

**M2-47 - M2 gate**  
Depends on: `M2-47e, M2-50`  
Deliverable: Write the M2 gate result from identity/admin checks.  
Verify: Gate record is PASS without any direct Stytch dashboard dependency.  
Timebox: <=15 minutes.

### M3 - Discovery, connectors and event plane

**M3-01 - connector manifest**  
Depends on: `M1-36`  
Deliverable: Define product ConnectorManifest with provider/category/data types/actions/auth mode, product-owned setup schema/access guidance/test semantics and internal adapter key.  
Verify: Public serializer excludes internal adapter/OSS name.  
Timebox: <=15 minutes.

**M3-02 - connector catalog store**  
Depends on: `M3-01`  
Deliverable: Create catalog registry and search/filter.  
Verify: Catalog test returns product descriptions/capabilities only.  
Timebox: <=15 minutes.

**M3-02a - Generic Webhook catalog entry**  
Depends on: `M3-02`  
Deliverable: Add built-in signed Generic Webhook integration metadata with allowlisted HTTPS destination configuration and response/approval notification capability.  
Verify: Catalog exposes product setup fields only and rejects non-HTTPS/arbitrary per-action URLs.  
Timebox: <=15 minutes.

**M3-03 - API listIntegrationCatalog**  
Depends on: `M3-02a`  
Deliverable: Implement OpenAPI operation `listIntegrationCatalog` for `GET /api/v1/integration-catalog` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-04 - API listIntegrations**  
Depends on: `M3-03`  
Deliverable: Implement OpenAPI operation `listIntegrations` for `GET /api/v1/integrations` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-05 - API createIntegration**  
Depends on: `M3-04`  
Deliverable: Implement OpenAPI operation `createIntegration` for `POST /api/v1/integrations` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-06 - API getIntegration**  
Depends on: `M3-05`  
Deliverable: Implement OpenAPI operation `getIntegration` for `GET /api/v1/integrations/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-07 - API updateIntegration**  
Depends on: `M3-06`  
Deliverable: Implement OpenAPI operation `updateIntegration` for `PATCH /api/v1/integrations/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-08 - API deleteIntegration**  
Depends on: `M3-07`  
Deliverable: Implement OpenAPI operation `deleteIntegration` for `DELETE /api/v1/integrations/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-09 - API authorizeIntegration**  
Depends on: `M3-08`  
Deliverable: Implement OpenAPI operation `authorizeIntegration` for `POST /api/v1/integrations/{id}/authorize` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-10 - API syncIntegration**  
Depends on: `M3-09`  
Deliverable: Implement OpenAPI operation `syncIntegration` for `POST /api/v1/integrations/{id}/sync` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-11 - API listIntegrationSyncs**  
Depends on: `M3-10`  
Deliverable: Implement OpenAPI operation `listIntegrationSyncs` for `GET /api/v1/integrations/{id}/syncs` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-12 - API getIntegrationSync**  
Depends on: `M3-11`  
Deliverable: Implement OpenAPI operation `getIntegrationSync` for `GET /api/v1/integrations/{id}/syncs/{syncId}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-13 - integration job payload**  
Depends on: `M3-12`  
Deliverable: Define idempotent IntegrationSync job payload and status transitions.  
Verify: Duplicate job ID does not create duplicate sync.  
Timebox: <=15 minutes.

**M3-14 - AWS credential adapter**  
Depends on: `M3-13,M1A-10`  
Deliverable: Implement AWS role-assumption/identity check using customer integration config.  
Verify: Local fixture plus real-AWS denial fixture pass.  
Timebox: <=15 minutes.

**M3-15 - Cartography runner**  
Depends on: `M3-14`  
Deliverable: Wrap selected Cartography modules and convert source nodes to Organization-scoped normalization input.  
Verify: Two-Organization fixture outputs source records tagged to the correct Organization and exposes no product UI dependency.  
Timebox: <=15 minutes.

**M3-16 - Prowler runner**  
Depends on: `M3-15`  
Deliverable: Wrap selected Prowler AWS checks and parse evidence.  
Verify: Fixture produces canonical resource source ID and evidence.  
Timebox: <=15 minutes.

**M3-17 - AWS normalization**  
Depends on: `M3-16`  
Deliverable: Normalize AWS account/role/policy/resource relationships needed by Agent Security graph.  
Verify: Fixture produces stable product relationships.  
Timebox: <=15 minutes.

**M3-18 - Kubernetes normalization**  
Depends on: `M3-17`  
Deliverable: Normalize cluster/namespace/service-account/workload relationships.  
Verify: Fixture links workload identity to runtime resource.  
Timebox: <=15 minutes.

**M3-19 - GitHub normalization**  
Depends on: `M3-18`  
Deliverable: Normalize org/repo/app/workflow identity/resource relationships needed by agent paths.  
Verify: Fixture links GitHub app/workflow to repo and permission.  
Timebox: <=15 minutes.

**M3-20 - IdP normalization**  
Depends on: `M3-19`  
Deliverable: Normalize Okta or Entra user/group/app/service-principal relationships for launch IdP.  
Verify: Fixture creates product Identity and privilege edges.  
Timebox: <=15 minutes.

**M3-21 - integration freshness**  
Depends on: `M3-20`  
Deliverable: Persist last success/error/rate-limit/stale threshold per Integration.  
Verify: Stale fixture remains visible and does not delete assets.  
Timebox: <=15 minutes.

**M3-22a - Nango private deployment**  
Depends on: `M3-21`  
Deliverable: Create free self-hosted Nango deployment config with no public ingress.  
Verify: Only product services can reach the Nango service endpoint.  
Timebox: <=15 minutes.

**M3-22b - Nango free feature boundary**  
Depends on: `M3-22a`  
Deliverable: Configure product use of Nango to Auth and Proxy only.  
Verify: Config has no Functions, Webhooks or MCP dependency.  
Timebox: <=15 minutes.

**M3-22c - Nango storage secrets**  
Depends on: `M3-22b`  
Deliverable: Wire Nango database connection and encryption key from Kubernetes secrets.  
Verify: Rendered config contains secret references, not raw secret values.  
Timebox: <=15 minutes.

**M3-22 - Nango internal service config**  
Depends on: `M3-22c`  
Deliverable: Add a smoke test for Nango Auth/Proxy health through the product wrapper.  
Verify: Smoke test passes with Nango admin UI unreachable from ingress.  
Timebox: <=15 minutes.

**M3-23 - Nango connection adapter**  
Depends on: `M3-22`  
Deliverable: Create product adapter to create/read a Nango connection reference.  
Verify: Product DB stores reference but not raw provider credential.  
Timebox: <=15 minutes.

**M3-24 - Nango auth callback**  
Depends on: `M3-23`  
Deliverable: Implement internal OAuth callback with state/PKCE validation.  
Verify: CSRF/state mismatch fixture fails.  
Timebox: <=15 minutes.

**M3-25 - Nango proxy wrapper**  
Depends on: `M3-24`  
Deliverable: Wrap authenticated Nango Proxy calls with provider-host allowlist.  
Verify: SSRF fixture to unconfigured host fails.  
Timebox: <=15 minutes.

**M3-26 - sensor enrollment model**  
Depends on: `M3-25`  
Deliverable: Create sensor ID/token hash/config/heartbeat model.  
Verify: Raw enrollment token is returned once only.  
Timebox: <=15 minutes.

**M3-27 - API listSensors**  
Depends on: `M3-26`  
Deliverable: Implement OpenAPI operation `listSensors` for `GET /api/v1/sensors` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-28 - API createSensorEnrollment**  
Depends on: `M3-27`  
Deliverable: Implement OpenAPI operation `createSensorEnrollment` for `POST /api/v1/sensors` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-29 - API getSensor**  
Depends on: `M3-28`  
Deliverable: Implement OpenAPI operation `getSensor` for `GET /api/v1/sensors/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-30 - API updateSensor**  
Depends on: `M3-29`  
Deliverable: Implement OpenAPI operation `updateSensor` for `PATCH /api/v1/sensors/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-31 - API deleteSensor**  
Depends on: `M3-30`  
Deliverable: Implement OpenAPI operation `deleteSensor` for `DELETE /api/v1/sensors/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-32 - API rotateSensorToken**  
Depends on: `M3-31`  
Deliverable: Implement OpenAPI operation `rotateSensorToken` for `POST /api/v1/sensors/{id}/rotate-token` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-33 - API getSensorCoverage**  
Depends on: `M3-32`  
Deliverable: Implement OpenAPI operation `getSensorCoverage` for `GET /api/v1/sensors/{id}/coverage` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M3-34 - sensor heartbeat internal API**  
Depends on: `M3-33`  
Deliverable: Implement `sensorHeartbeat` internal operation.  
Verify: Valid scoped token updates heartbeat/capabilities; invalid token fails.  
Timebox: <=15 minutes.

**M3-35 - Tetragon packaging**  
Depends on: `M3-34`  
Deliverable: Add Tetragon Helm dependency/wrapper and minimal filtered tracing policies.  
Verify: Render includes process, selected sensitive-file and network policies only.  
Timebox: <=15 minutes.

**M3-36 - Tetragon adapter**  
Depends on: `M3-35`  
Deliverable: Convert supported Tetragon events to canonical SecurityEvent.  
Verify: Process/file/network fixtures normalize with workload identity.  
Timebox: <=15 minutes.

**M3-37 - Tetragon sensor health**  
Depends on: `M3-36`  
Deliverable: Collect kernel/BTF support, CPU/memory, event rate and drops into Sensor coverage.  
Verify: Sensor detail fixture displays unsupported/drop state.  
Timebox: <=15 minutes.

**M3-38 - OTLP semantic adapter**  
Depends on: `M3-37`  
Deliverable: Map agent/session/task/tool/sandbox attributes from spans to SecurityEvent.  
Verify: Sample trace preserves trace/session IDs.  
Timebox: <=15 minutes.

**M3-39 - event ingest auth**  
Depends on: `M3-38`  
Deliverable: Authenticate sensor/runtime internal requests and enforce scope.  
Verify: Unscoped/invalid source is rejected before parsing payload.  
Timebox: <=15 minutes.

**M3-40 - event ingest filter**  
Depends on: `M3-39`  
Deliverable: Apply collection mode and event relevance filter before durable queue.  
Verify: Metadata-only fixture removes content but keeps action metadata.  
Timebox: <=15 minutes.

**M3-41 - event batcher**  
Depends on: `M3-40`  
Deliverable: Batch canonical events to bounded size/count before SQS.  
Verify: 10k input events produce bounded batch messages, not 10k SQS calls.  
Timebox: <=15 minutes.

**M3-42 - ingest internal API**  
Depends on: `M3-41`  
Deliverable: Implement `ingestEvents` internal operation.  
Verify: Valid batch acknowledges only after SQS acceptance.  
Timebox: <=15 minutes.

**M3-43a - runtime batch consume**  
Depends on: `M3-42`  
Deliverable: Consume one normalized runtime-event batch idempotently from SQS.  
Verify: Replaying the same message reuses the same deterministic batch ID.  
Timebox: <=15 minutes.

**M3-43b - runtime event S3 archive**  
Depends on: `M3-43a`  
Deliverable: Write the compressed normalized batch to an Organization/date-scoped S3 archive key with deterministic batch ID.  
Verify: Replay overwrites/reuses the same logical archive object and cannot escape the Organization prefix.  
Timebox: <=15 minutes.

**M3-43c - runtime event indexing**  
Depends on: `M3-43b`  
Deliverable: Write consumed runtime events to OpenSearch with deterministic event IDs and S3 archive reference.  
Verify: Replay does not duplicate indexed events.  
Timebox: <=15 minutes.

**M3-43d - runtime correlation update**  
Depends on: `M3-43c`  
Deliverable: Apply correlation/graph evidence updates after archive and event indexing succeed.  
Verify: Replay does not duplicate correlation evidence.  
Timebox: <=15 minutes.

**M3-43 - runtime-event worker**  
Depends on: `M3-43d`  
Deliverable: Wire consume -> S3 archive -> OpenSearch -> correlation with one observable job state and acknowledge SQS only after all required stages are durable.  
Verify: A fixture batch reaches archive, index and correlation exactly once before acknowledgement.  
Timebox: <=15 minutes.

**M3-44 - OpenSearch event indexer**  
Depends on: `M3-43`  
Deliverable: Index normalized event with required scope/session/agent/time fields.  
Verify: Scoped filter query returns expected event only.  
Timebox: <=15 minutes.

**M3-45 - correlation exact path**  
Depends on: `M3-44`  
Deliverable: Correlate exact trace/session IDs into Session/Agent references.  
Verify: Exact fixture scores Exact.  
Timebox: <=15 minutes.

**M3-46 - correlation runtime path**  
Depends on: `M3-45`  
Deliverable: Correlate sandbox/container/cgroup/process lineage when semantic ID absent.  
Verify: Controlled fixture scores Strong, not Exact.  
Timebox: <=15 minutes.

**M3-47 - correlation ambiguity**  
Depends on: `M3-46`  
Deliverable: Leave concurrent ambiguous runtime events Probable/Unattributed.  
Verify: Fixture never upgrades ambiguous event to Exact.  
Timebox: <=15 minutes.

**M3-48a - Connection catalog route**  
Depends on: `M3-47`  
Deliverable: Build integration catalog grid and filters.  
Verify: Fixture renders provider cards without internal adapter names.  
Timebox: <=15 minutes.

**M3-48b - Connection list route**  
Depends on: `M3-48a`  
Deliverable: Build connected integrations table with status/freshness.  
Verify: Healthy/stale/degraded fixtures render.  
Timebox: <=15 minutes.

**M3-48c1 - Connection detail summary**  
Depends on: `M3-48b`  
Deliverable: Build integration detail summary with name, scope, health and last sync.  
Verify: Healthy, stale and error fixtures render the expected product state.  
Timebox: <=15 minutes.

**M3-48c2 - Connection detail data and history**  
Depends on: `M3-48c1`  
Deliverable: Add collected-data capabilities and bounded sync-history list to integration detail.  
Verify: Fixture renders data types and paginated sync history from generated client data.  
Timebox: <=15 minutes.

**M3-48c3 - Connection detail actions**  
Depends on: `M3-48c2`  
Deliverable: Add the supported authorize, sync and delete action controls to integration detail.  
Verify: Capability fixture hides unsupported actions and exposes stable product errors.  
Timebox: <=15 minutes.

**M3-48d - AWS setup wizard UI**  
Depends on: `M3-48c3`  
Deliverable: Add AWS Review access -> role/external-ID configure -> Test connection -> Initial sync -> Coverage flow using generated client operations.  
Verify: Missing permission fixture shows exact remediation and cannot render Healthy.  
Timebox: <=15 minutes.

**M3-48e - Kubernetes setup wizard UI**  
Depends on: `M3-48d`  
Deliverable: Add Kubernetes coverage-choice -> scoped sensor enrollment -> Helm instructions -> heartbeat/test -> Coverage flow.  
Verify: Unsupported kernel or missing gateway state remains visible instead of marking full coverage.  
Timebox: <=15 minutes.

**M3-48f - GitHub setup wizard UI**  
Depends on: `M3-48e`  
Deliverable: Add GitHub access review -> authorize/install -> scope validation -> Initial sync -> Coverage flow.  
Verify: Repository/Organization scope returned by authorization is displayed and missing scope is actionable.  
Timebox: <=15 minutes.

**M3-48g - launch IdP setup wizard UI**  
Depends on: `M3-48f`  
Deliverable: Add launch IdP access review -> credential/authorization -> Test connection -> Initial sync -> Coverage flow, clearly separated from AgentSec SSO configuration.  
Verify: Fixture distinguishes directory-security integration from Stytch sign-in configuration.  
Timebox: <=15 minutes.

**M3-48h - Generic Webhook setup UI**  
Depends on: `M3-48g`  
Deliverable: Add signed Generic Webhook destination configure/test/status flow through Connections.  
Verify: Test delivery shows signature status and arbitrary per-action URL input is impossible.  
Timebox: <=15 minutes.

**M3-48 - Connections UI shell**  
Depends on: `M3-48h`  
Deliverable: Compose catalog/list/detail navigation for Connections.  
Verify: Route smoke test covers all three pages.  
Timebox: <=15 minutes.

**M3-49 - Connections UI actions**  
Depends on: `M3-48`  
Deliverable: Wire connect/authorize/sync/delete and sync-history actions.  
Verify: E2E fake provider flow stays product-branded.  
Timebox: <=15 minutes.

**M3-50 - Sensors UI shell**  
Depends on: `M3-49`  
Deliverable: Create Sensors list/detail/enrollment routes.  
Verify: Routes use generated client and show coverage/freshness.  
Timebox: <=15 minutes.

**M3-51 - Sensors UI actions**  
Depends on: `M3-50`  
Deliverable: Wire enroll/rotate/delete actions with confirmation.  
Verify: E2E sensor lifecycle passes.  
Timebox: <=15 minutes.

**M3-52a - M3 connector E2E**  
Depends on: `M3-51`  
Deliverable: Run AWS/Kubernetes/GitHub/IdP fixture connector E2E.  
Verify: Canonical assets and freshness records are created.  
Timebox: <=15 minutes.

**M3-52b - M3 sensor E2E**  
Depends on: `M3-52a`  
Deliverable: Run sensor enrollment and heartbeat E2E.  
Verify: Coverage page receives sensor health and capability data.  
Timebox: <=15 minutes.

**M3-52c - M3 OTLP eBPF ingest E2E**  
Depends on: `M3-52b`  
Deliverable: Run one semantic OTLP trace plus eBPF runtime fixture through ingest.  
Verify: Both sources create normalized scoped events.  
Timebox: <=15 minutes.

**M3-52d - M3 queue index E2E**  
Depends on: `M3-52c`  
Deliverable: Run normalized event batch through SQS worker, S3 archive and OpenSearch index.  
Verify: Archive/index references agree, replay remains idempotent and DLQ stays empty.  
Timebox: <=15 minutes.

**M3-52e - M3 freshness degrade E2E**  
Depends on: `M3-52d`  
Deliverable: Fail one connector sync after a known-good sync.  
Verify: Last-known inventory remains visible with stale marker.  
Timebox: <=15 minutes.

**M3-52 - M3 gate**  
Depends on: `M3-52e`  
Deliverable: Write the M3 gate result from connector, sensor, ingest, queue/index and freshness checks.  
Verify: Gate record is PASS only when all independent checks passed.  
Timebox: <=15 minutes.

### M4 - Inventory and exposure

**M4-01a - canonical asset ID reconciliation**  
Depends on: `M2-47,M3-52,M1A-10`  
Deliverable: Reconcile one normalized source asset into a stable Organization-scoped canonical Asset ID in Neon.  
Verify: Repeated source record preserves the same product Asset ID and source evidence reference.  
Timebox: <=15 minutes.

**M4-01b - Agent reconciliation**  
Depends on: `M4-01a`  
Deliverable: Reconcile normalized Agent fields onto the canonical Asset record.  
Verify: Repeated Agent source update preserves product ID and updates last-seen/source metadata.  
Timebox: <=15 minutes.

**M4-01c - Tool reconciliation**  
Depends on: `M4-01b`  
Deliverable: Reconcile normalized Tool/MCP fields onto canonical Tool records.  
Verify: Duplicate provider/tool identifiers do not create duplicate product Tools inside one Organization.  
Timebox: <=15 minutes.

**M4-01d - Identity reconciliation**  
Depends on: `M4-01c`  
Deliverable: Reconcile normalized human/service/agent identity fields without storing raw credentials.  
Verify: Credential fixture stores fingerprint/reference only and remains Organization-scoped.  
Timebox: <=15 minutes.

**M4-01e - Runtime reconciliation**  
Depends on: `M4-01d`  
Deliverable: Reconcile runtime/sandbox/workload identity and isolation metadata onto canonical Runtime records.  
Verify: Repeated workload source maps to the same Runtime while preserving source evidence.  
Timebox: <=15 minutes.

**M4-01f - canonical relationship projection**  
Depends on: `M4-01e`  
Deliverable: Upsert one bounded canonical relationship set from reconciled product IDs into GraphStore.  
Verify: Replay is idempotent and no source/vendor ID becomes a public primary key.  
Timebox: <=15 minutes.

**M4-01 - asset reconciliation gate**  
Depends on: `M4-01f`  
Deliverable: Run one fixture through Asset, Agent, Tool, Identity, Runtime and relationship reconciliation.  
Verify: Repeated sync preserves canonical IDs and graph relationships without cross-Organization collision.  
Timebox: <=15 minutes.

**M4-02 - agent ownership/tags**  
Depends on: `M4-01`  
Deliverable: Add owner/team/tag fields and audit mutation.  
Verify: Owner update changes only scoped Agent and emits audit.  
Timebox: <=15 minutes.

**M4-03 - API listAgents**  
Depends on: `M4-02`  
Deliverable: Implement OpenAPI operation `listAgents` for `GET /api/v1/agents` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-04 - API getAgent**  
Depends on: `M4-03`  
Deliverable: Implement OpenAPI operation `getAgent` for `GET /api/v1/agents/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-05 - API updateAgent**  
Depends on: `M4-04`  
Deliverable: Implement OpenAPI operation `updateAgent` for `PATCH /api/v1/agents/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-06 - API getAgentCapabilities**  
Depends on: `M4-05`  
Deliverable: Implement OpenAPI operation `getAgentCapabilities` for `GET /api/v1/agents/{id}/capabilities` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-07 - API getAgentRelationships**  
Depends on: `M4-06`  
Deliverable: Implement OpenAPI operation `getAgentRelationships` for `GET /api/v1/agents/{id}/relationships` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-08 - API listAgentSessions**  
Depends on: `M4-07`  
Deliverable: Implement OpenAPI operation `listAgentSessions` for `GET /api/v1/agents/{id}/sessions` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-09 - API listTools**  
Depends on: `M4-08`  
Deliverable: Implement OpenAPI operation `listTools` for `GET /api/v1/tools` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-10 - API getTool**  
Depends on: `M4-09`  
Deliverable: Implement OpenAPI operation `getTool` for `GET /api/v1/tools/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-11 - API listIdentities**  
Depends on: `M4-10`  
Deliverable: Implement OpenAPI operation `listIdentities` for `GET /api/v1/identities` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-12 - API getIdentity**  
Depends on: `M4-11`  
Deliverable: Implement OpenAPI operation `getIdentity` for `GET /api/v1/identities/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-13 - API listRuntimes**  
Depends on: `M4-12`  
Deliverable: Implement OpenAPI operation `listRuntimes` for `GET /api/v1/runtimes` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-14 - API getRuntime**  
Depends on: `M4-13`  
Deliverable: Implement OpenAPI operation `getRuntime` for `GET /api/v1/runtimes/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-15 - API getAsset**  
Depends on: `M4-14`  
Deliverable: Implement OpenAPI operation `getAsset` for `GET /api/v1/assets/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-16 - capability rule model**  
Depends on: `M4-15`  
Deliverable: Define six MVP capability categories and evidence-state transition rules.  
Verify: State transition tests reject Verified without verification evidence.  
Timebox: <=15 minutes.

**M4-17 - capability graph query**  
Depends on: `M4-16`  
Deliverable: Implement bounded graph query from Agent to tool/identity/resource/action outcomes.  
Verify: Fixture yields read vs write capability correctly.  
Timebox: <=15 minutes.

**M4-18 - capability observed upgrade**  
Depends on: `M4-17`  
Deliverable: Upgrade Reachable to Observed from matching runtime/provider evidence.  
Verify: Runtime fixture updates state without deleting configured edge.  
Timebox: <=15 minutes.

**M4-19 - capability verified/blocked upgrade**  
Depends on: `M4-18`  
Deliverable: Apply Attack Lab Verified and runtime policy Blocked evidence to derived capability state.  
Verify: Fixtures preserve underlying reachability while state changes.  
Timebox: <=15 minutes.

**M4-20 - posture ownerless agent**  
Depends on: `M4-19`  
Deliverable: Implement high-signal posture rule: agent has no owner.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-21 - posture human credential**  
Depends on: `M4-20`  
Deliverable: Implement high-signal posture rule: agent uses a human credential.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-22 - posture shared credential**  
Depends on: `M4-21`  
Deliverable: Implement high-signal posture rule: credential is shared/long-lived across agents.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-23 - posture untrusted write**  
Depends on: `M4-22`  
Deliverable: Implement high-signal posture rule: untrusted/public input plus production write.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-24 - posture shell credential**  
Depends on: `M4-23`  
Deliverable: Implement high-signal posture rule: shell/code execution plus production credential.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-25 - posture egress sensitive**  
Depends on: `M4-24`  
Deliverable: Implement high-signal posture rule: unrestricted egress plus sensitive-data reach.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-26 - posture unapproved tool**  
Depends on: `M4-25`  
Deliverable: Implement high-signal posture rule: unapproved remote MCP/tool.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-27 - posture destructive no control**  
Depends on: `M4-26`  
Deliverable: Implement high-signal posture rule: destructive tool without runtime control.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-28 - posture no runtime coverage**  
Depends on: `M4-27`  
Deliverable: Implement high-signal posture rule: production agent lacks supported runtime policy coverage.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-29 - posture weak runtime isolation**  
Depends on: `M4-28`  
Deliverable: Implement high-signal posture rule: runtime exposes host filesystem or privileged mode.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-30 - posture cicd production secret**  
Depends on: `M4-29`  
Deliverable: Implement high-signal posture rule: agent can modify CI/CD and reach production secrets.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-31 - posture zombie credential**  
Depends on: `M4-30`  
Deliverable: Implement high-signal posture rule: inactive agent retains active credential/permission.  
Verify: Pass/fail graph fixtures store exact supporting evidence for the rule.  
Timebox: <=15 minutes.

**M4-32 - Prowler relevance filter**  
Depends on: `M4-31`  
Deliverable: Mark Prowler findings visible-by-default only when attached to agent/path/compliance context.  
Verify: Unrelated cloud finding stays out of Agent Security default finding list.  
Timebox: <=15 minutes.

**M4-33 - finding risk factors**  
Depends on: `M4-32`  
Deliverable: Compute explainable risk factors without opaque ML score.  
Verify: Fixture exposes top factors and environment/policy evidence.  
Timebox: <=15 minutes.

**M4-34 - API listFindings**  
Depends on: `M4-33`  
Deliverable: Implement OpenAPI operation `listFindings` for `GET /api/v1/findings` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-35 - API getFinding**  
Depends on: `M4-34`  
Deliverable: Implement OpenAPI operation `getFinding` for `GET /api/v1/findings/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-36 - API updateFinding**  
Depends on: `M4-35`  
Deliverable: Implement OpenAPI operation `updateFinding` for `PATCH /api/v1/findings/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-37 - API acceptFindingRisk**  
Depends on: `M4-36`  
Deliverable: Implement OpenAPI operation `acceptFindingRisk` for `POST /api/v1/findings/{id}/accept-risk` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-38 - API createFindingTicket**  
Depends on: `M4-37`  
Deliverable: Implement OpenAPI operation `createFindingTicket` for `POST /api/v1/findings/{id}/ticket` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-39 - ticket webhook action**  
Depends on: `M4-38`  
Deliverable: Implement generic signed remediation webhook for `createFindingTicket`.  
Verify: Fake receiver verifies signature and safe payload excludes secret evidence.  
Timebox: <=15 minutes.

**M4-40 - attack path templates**  
Depends on: `M4-39`  
Deliverable: Define bounded entry-condition to high-impact-sink path templates.  
Verify: Fixture avoids unlimited graph traversal.  
Timebox: <=15 minutes.

**M4-41 - attack path query**  
Depends on: `M4-40`  
Deliverable: Compute supported attack paths with evidence state and current block edge.  
Verify: Potential/Observed/Verified/Blocked fixtures classify correctly.  
Timebox: <=15 minutes.

**M4-42 - break path options**  
Depends on: `M4-41`  
Deliverable: Rank small node/edge/policy changes that break a path.  
Verify: Fixture returns deterministic minimal options with evidence.  
Timebox: <=15 minutes.

**M4-43 - API listAttackPaths**  
Depends on: `M4-42`  
Deliverable: Implement OpenAPI operation `listAttackPaths` for `GET /api/v1/attack-paths` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-44 - API getAttackPath**  
Depends on: `M4-43`  
Deliverable: Implement OpenAPI operation `getAttackPath` for `GET /api/v1/attack-paths/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-45 - API getAttackPathBreakOptions**  
Depends on: `M4-44`  
Deliverable: Implement OpenAPI operation `getAttackPathBreakOptions` for `GET /api/v1/attack-paths/{id}/break-options` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-46 - home summary service**  
Depends on: `M4-45`  
Deliverable: Create base overview counts for agents, new/worsening high-risk paths, stale launch-connector/sensor coverage and recent verified/blocked changes; Security Agent attention fields are added in M7A.  
Verify: Summary never reports healthy when source is stale/degraded.  
Timebox: <=15 minutes.

**M4-47 - API getHomeSummary**  
Depends on: `M4-46`  
Deliverable: Implement OpenAPI operation `getHomeSummary` for `GET /api/v1/home/summary` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-48 - global search service**  
Depends on: `M4-47`  
Deliverable: Search product entities by safe indexed name/type/ID.  
Verify: Search never exposes raw graph query language.  
Timebox: <=15 minutes.

**M4-49 - API globalSearch**  
Depends on: `M4-48`  
Deliverable: Implement OpenAPI operation `globalSearch` for `GET /api/v1/search` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M4-50a - Agents table**  
Depends on: `M4-49`  
Deliverable: Build Agents table and pagination.  
Verify: Fixture renders core columns and loading/empty/error states.  
Timebox: <=15 minutes.

**M4-50b1 - Agents ownership filters**  
Depends on: `M4-50a`  
Deliverable: Add owner, environment and risk filters to the Agents list.  
Verify: Filter-state test generates expected owner/environment/risk API query.  
Timebox: <=15 minutes.

**M4-50b2 - Agents capability filters**  
Depends on: `M4-50b1`  
Deliverable: Add shell/code-execution and high-impact-reach filters to the Agents list.  
Verify: Filter-state test generates the expected capability API query.  
Timebox: <=15 minutes.

**M4-50b3 - Agents coverage filters**  
Depends on: `M4-50b2`  
Deliverable: Add runtime sensor and policy-coverage filters to the Agents list.  
Verify: Filter-state test generates the expected coverage API query.  
Timebox: <=15 minutes.

**M4-50c - Agents coverage indicators**  
Depends on: `M4-50b3`  
Deliverable: Add last-seen, stale-source and policy/sensor coverage indicators.  
Verify: Stale fixture does not render as healthy.  
Timebox: <=15 minutes.

**M4-50 - Agents list UI**  
Depends on: `M4-50c`  
Deliverable: Compose Agents table, filters and coverage indicators.  
Verify: E2E filter plus stale-state flow passes.  
Timebox: <=15 minutes.

**M4-51a - Agent detail header**  
Depends on: `M4-50`  
Deliverable: Build Agent header with owner, status, environment, risk and last seen.  
Verify: Component test renders and owner edit uses generated client.  
Timebox: <=15 minutes.

**M4-51b1 - Agent identity section**  
Depends on: `M4-51a`  
Deliverable: Build the Agent identity section with principal/credential references and evidence state.  
Verify: Fixture links identity references to canonical detail routes.  
Timebox: <=15 minutes.

**M4-51b2 - Agent tools section**  
Depends on: `M4-51b1`  
Deliverable: Build the Agent Tools & MCP section with observed/configured tool relationships.  
Verify: Fixture links tool and MCP references to canonical detail routes.  
Timebox: <=15 minutes.

**M4-51b3 - Agent runtime section**  
Depends on: `M4-51b2`  
Deliverable: Build the Agent runtime/sandbox section with coverage and evidence state.  
Verify: Fixture links runtime references to canonical detail routes.  
Timebox: <=15 minutes.

**M4-51c - Agent capability section**  
Depends on: `M4-51b3`  
Deliverable: Build Effective Capability cards with path/evidence state.  
Verify: Configured/Observed/Verified/Blocked fixtures render consistently.  
Timebox: <=15 minutes.

**M4-51d - Agent exposure section**  
Depends on: `M4-51c`  
Deliverable: Build Findings and Attack Paths sections.  
Verify: Fixture opens linked finding/path.  
Timebox: <=15 minutes.

**M4-51e - Agent sessions/policies section**  
Depends on: `M4-51d`  
Deliverable: Build Sessions and runtime policy coverage sections.  
Verify: Fixture opens session and policy routes.  
Timebox: <=15 minutes.

**M4-51 - Agent detail UI**  
Depends on: `M4-51e`  
Deliverable: Compose Agent detail sections and verify responsive reading order.  
Verify: E2E opens capability, finding, path and session from one Agent.  
Timebox: <=15 minutes.

**M4-52 - Tools UI**  
Depends on: `M4-51`  
Deliverable: Create Tools & MCP list/detail.  
Verify: E2E shows agents using tool and privilege/control state.  
Timebox: <=15 minutes.

**M4-53 - Identities UI**  
Depends on: `M4-52`  
Deliverable: Create Identities list/detail.  
Verify: E2E shows agents, privilege, last use and resource reach.  
Timebox: <=15 minutes.

**M4-54 - Runtimes UI**  
Depends on: `M4-53`  
Deliverable: Create Runtimes list/detail.  
Verify: E2E shows isolation, mounts, egress and sensor coverage.  
Timebox: <=15 minutes.

**M4-55 - Findings list UI**  
Depends on: `M4-54`  
Deliverable: Create Findings list with high-signal default and agent relevance.  
Verify: Unrelated Prowler fixture is hidden by default.  
Timebox: <=15 minutes.

**M4-56 - Finding detail UI**  
Depends on: `M4-55`  
Deliverable: Create Why/Evidence/Path/Fix/Verify layout and actions.  
Verify: E2E can assign, accept risk and create webhook ticket.  
Timebox: <=15 minutes.

**M4-57 - Attack Paths UI**  
Depends on: `M4-56`  
Deliverable: Create bounded path graph and evidence side panel.  
Verify: E2E edge click shows source/confidence/timestamp and Break Path options.  
Timebox: <=15 minutes.

**M4-58 - Home UI**  
Depends on: `M4-57`  
Deliverable: Create Overview page and first-value coverage states.  
Verify: E2E from stale source shows warning, not zero-risk state.  
Timebox: <=15 minutes.

**M4-59a - inventory golden test**  
Depends on: `M4-58`  
Deliverable: Load one canonical fixture agent and verify Inventory rendering/API shape.  
Verify: Agent owner, identity, runtime, tools and coverage render from canonical IDs.  
Timebox: <=15 minutes.

**M4-59b - capability golden test**  
Depends on: `M4-59a`  
Deliverable: Run capability calculation for the fixture agent.  
Verify: Expected production write and shell capabilities include evidence paths.  
Timebox: <=15 minutes.

**M4-59c - posture golden test**  
Depends on: `M4-59b`  
Deliverable: Run high-signal agent posture checks on the fixture graph.  
Verify: Expected agent-specific finding is raised with exact evidence.  
Timebox: <=15 minutes.

**M4-59d - attack path golden test**  
Depends on: `M4-59c`  
Deliverable: Compute attack path from untrusted input to controlled high-impact sink.  
Verify: Path includes ranked break options and evidence states.  
Timebox: <=15 minutes.

**M4-59e - exposure UX golden test**  
Depends on: `M4-59d`  
Deliverable: Open finding and attack-path UI for the fixture.  
Verify: Why, Evidence, Path, Fix and Verify sections use product concepts only.  
Timebox: <=15 minutes.

**M4-59 - M4 gate**  
Depends on: `M4-59e`  
Deliverable: Write the M4 gate result for the one evidence-backed fixture.  
Verify: Gate record is PASS only when inventory through exposure UX is coherent.  
Timebox: <=15 minutes.

### M5 - Red Team and Attack Lab

**M5-01 - test domain**  
Depends on: `M4-59`  
Deliverable: Define TestDefinition/TestRun/TestAttempt and safety metadata.  
Verify: Schema distinguishes engine_error from pass/fail.  
Timebox: <=15 minutes.

**M5-02 - Promptfoo adapter**  
Depends on: `M5-01`  
Deliverable: Wrap Promptfoo target/run output into normalized TestAttempt.  
Verify: One fixture normalizes objective, input artifact ref, behavior, verdict and evidence.  
Timebox: <=15 minutes.

**M5-03 - curated pack selector**  
Depends on: `M5-02`  
Deliverable: Select small test categories from Agent capabilities/tools/data reach.  
Verify: Fixture recommends only relevant categories with explanations.  
Timebox: <=15 minutes.

**M5-04 - test safety preflight**  
Depends on: `M5-03`  
Deliverable: Reject production-write credentials/targets and show expected side effects.  
Verify: Unsafe fixture fails before queueing.  
Timebox: <=15 minutes.

**M5-05 - API listTests**  
Depends on: `M5-04`  
Deliverable: Implement OpenAPI operation `listTests` for `GET /api/v1/tests` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-06 - API createTest**  
Depends on: `M5-05`  
Deliverable: Implement OpenAPI operation `createTest` for `POST /api/v1/tests` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-07 - API getTest**  
Depends on: `M5-06`  
Deliverable: Implement OpenAPI operation `getTest` for `GET /api/v1/tests/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-08 - API updateTest**  
Depends on: `M5-07`  
Deliverable: Implement OpenAPI operation `updateTest` for `PATCH /api/v1/tests/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-09 - API runTest**  
Depends on: `M5-08`  
Deliverable: Implement OpenAPI operation `runTest` for `POST /api/v1/tests/{id}/runs` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-10 - API listTestRuns**  
Depends on: `M5-09`  
Deliverable: Implement OpenAPI operation `listTestRuns` for `GET /api/v1/test-runs` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-11 - API getTestRun**  
Depends on: `M5-10`  
Deliverable: Implement OpenAPI operation `getTestRun` for `GET /api/v1/test-runs/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-12 - API cancelTestRun**  
Depends on: `M5-11`  
Deliverable: Implement OpenAPI operation `cancelTestRun` for `POST /api/v1/test-runs/{id}/cancel` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-13 - test worker queue**  
Depends on: `M5-12`  
Deliverable: Consume TestRun from SQS tests queue and invoke Promptfoo adapter idempotently.  
Verify: Duplicate delivery does not duplicate attempt.  
Timebox: <=15 minutes.

**M5-14 - test evidence artifacts**  
Depends on: `M5-13`  
Deliverable: Persist raw test artifacts to S3 and normalized summary to Neon.  
Verify: Summary references artifact; secret fixture is redacted per policy.  
Timebox: <=15 minutes.

**M5-15 - red team UI list/new**  
Depends on: `M5-14`  
Deliverable: Create Red Team list and new-test wizard.  
Verify: E2E recommended pack and safety step render.  
Timebox: <=15 minutes.

**M5-16 - red team result UI**  
Depends on: `M5-15`  
Deliverable: Create result view grouped by security outcome with Attack Lab eligibility.  
Verify: E2E successful attempt links to Verify safely.  
Timebox: <=15 minutes.

**M5-17 - SandboxProvider contract**  
Depends on: `M5-16`  
Deliverable: Define Create/Run/Cancel/Destroy/Capabilities contract and isolation classification.  
Verify: Fake provider contract tests pass.  
Timebox: <=15 minutes.

**M5-18 - Fargate provider create**  
Depends on: `M5-17`  
Deliverable: Create run-scoped Kubernetes Job/Pod selected by dedicated Attack Lab Fargate profile.  
Verify: Fixture confirms Fargate scheduling labels/profile and cleanup ownership.  
Timebox: <=15 minutes.

**M5-19 - Fargate resource limits**  
Depends on: `M5-18`  
Deliverable: Apply CPU/memory/ephemeral-storage limits and timeout.  
Verify: Timeout fixture ends with bounded reason.  
Timebox: <=15 minutes.

**M5-20 - Fargate service account**  
Depends on: `M5-19`  
Deliverable: Create/use dedicated run service account and test IAM role reference.  
Verify: Run cannot inherit product worker role.  
Timebox: <=15 minutes.

**M5-21 - Fargate SG policy**  
Depends on: `M5-20`  
Deliverable: Attach run network SecurityGroupPolicy for egress-proxy/required control-plane endpoints.  
Verify: Direct undeclared egress fixture is denied.  
Timebox: <=15 minutes.

**M5-22 - Attack Lab egress proxy token**  
Depends on: `M5-21`  
Deliverable: Create per-run signed egress token with domain/method allowlist.  
Verify: Proxy rejects undeclared host and expired token.  
Timebox: <=15 minutes.

**M5-23a - Attack Lab target check**  
Depends on: `M5-22`  
Deliverable: Reject Attack Lab target outside the configured non-production/test allowlist.  
Verify: Production target fixture is rejected before sandbox creation.  
Timebox: <=15 minutes.

**M5-23b - Attack Lab credential check**  
Depends on: `M5-23a`  
Deliverable: Reject production-write or otherwise disallowed credential class.  
Verify: Production-write credential fixture is hard rejected.  
Timebox: <=15 minutes.

**M5-23c - Attack Lab destination check**  
Depends on: `M5-23b`  
Deliverable: Validate requested external destinations against declared per-run allowlist.  
Verify: Undeclared destination fixture is rejected.  
Timebox: <=15 minutes.

**M5-23d - Attack Lab success criteria check**  
Depends on: `M5-23c`  
Deliverable: Require explicit observable success criteria for a verification run.  
Verify: Run without a measurable criterion is rejected.  
Timebox: <=15 minutes.

**M5-23 - Attack Lab preflight**  
Depends on: `M5-23d`  
Deliverable: Assemble target, credential, destination and success-criteria safety checks.  
Verify: Approved fixture returns one product SafetyDecision before sandbox creation.  
Timebox: <=15 minutes.

**M5-24 - Attack Lab canary contract**  
Depends on: `M5-23`  
Deliverable: Create canary resource/credential descriptor and expected-touch criterion.  
Verify: Fixture can touch test resource without real production access.  
Timebox: <=15 minutes.

**M5-25 - Attack Lab evidence collector**  
Depends on: `M5-24`  
Deliverable: Collect semantic/gateway/egress/Kubernetes/cloud side-effect evidence.  
Verify: Fixture records exact source references; no eBPF dependency inside Fargate.  
Timebox: <=15 minutes.

**M5-26 - Attack Lab verdict**  
Depends on: `M5-25`  
Deliverable: Implement Verified/Not Reproduced/Inconclusive evaluator.  
Verify: Infrastructure failure is Inconclusive; exact canary touch is Verified.  
Timebox: <=15 minutes.

**M5-27 - API listAttackLabRuns**  
Depends on: `M5-26`  
Deliverable: Implement OpenAPI operation `listAttackLabRuns` for `GET /api/v1/attack-lab/runs` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-28 - API createAttackLabRun**  
Depends on: `M5-27`  
Deliverable: Implement OpenAPI operation `createAttackLabRun` for `POST /api/v1/attack-lab/runs` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-29 - API getAttackLabRun**  
Depends on: `M5-28`  
Deliverable: Implement OpenAPI operation `getAttackLabRun` for `GET /api/v1/attack-lab/runs/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-30 - API cancelAttackLabRun**  
Depends on: `M5-29`  
Deliverable: Implement OpenAPI operation `cancelAttackLabRun` for `POST /api/v1/attack-lab/runs/{id}/cancel` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-31 - API rerunAttackLabRun**  
Depends on: `M5-30`  
Deliverable: Implement OpenAPI operation `rerunAttackLabRun` for `POST /api/v1/attack-lab/runs/{id}/rerun` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M5-32 - Attack Lab worker**  
Depends on: `M5-31`  
Deliverable: Run preflight -> provider -> evidence -> verdict -> cleanup as idempotent SQS test job.  
Verify: Worker replay does not rerun a completed side effect.  
Timebox: <=15 minutes.

**M5-33a - Attack Lab preflight target UI**  
Depends on: `M5-32`  
Deliverable: Render target, environment and credential class on the safety review page.  
Verify: Fixture shows selected non-production target and test credential class.  
Timebox: <=15 minutes.

**M5-33b - Attack Lab preflight network UI**  
Depends on: `M5-33a`  
Deliverable: Render allowed destinations and expected external side effects.  
Verify: Undeclared destination warning is visible before Run.  
Timebox: <=15 minutes.

**M5-33c - Attack Lab preflight limits UI**  
Depends on: `M5-33b`  
Deliverable: Render runtime/resource limits and cleanup/retention behavior.  
Verify: Fixture displays timeout, resource cap and cleanup mode.  
Timebox: <=15 minutes.

**M5-33 - Attack Lab preflight UI**  
Depends on: `M5-33c`  
Deliverable: Compose the preflight safety sections with the Run action disabled until safety passes.  
Verify: Run is enabled only for an approved SafetyDecision.  
Timebox: <=15 minutes.

**M5-34 - Attack Lab result UI**  
Depends on: `M5-33`  
Deliverable: Create verdict/timeline/canary/network/evidence/re-run result page.  
Verify: E2E distinguishes Inconclusive from Not Reproduced.  
Timebox: <=15 minutes.

**M5-35 - M5 gate**  
Depends on: `M5-34`  
Deliverable: Run staging red-team -> Fargate verification with test/canary resources.  
Verify: A controlled path can become Verified and no production write credential is accepted.  
Timebox: <=15 minutes.

### M6 - Runtime policy and protection

**M6-01 - policy domain**  
Depends on: `M4-59`  
Deliverable: Define product Policy scope, trigger, conditions, Monitor/Block action, rollout and failure mode.  
Verify: Schema rejects approval/redact/custom Rego in MVP.  
Timebox: <=15 minutes.

**M6-02 - policy validator**  
Depends on: `M6-01`  
Deliverable: Validate conditions against supported runtime-gateway capabilities.  
Verify: Unsupported enforcement claim fails before save.  
Timebox: <=15 minutes.

**M6-03 - OPA compiler**  
Depends on: `M6-02`  
Deliverable: Compile product Policy to deterministic internal OPA/Rego representation.  
Verify: Golden output stable across repeated compile.  
Timebox: <=15 minutes.

**M6-04 - embedded evaluator**  
Depends on: `M6-03`  
Deliverable: Evaluate compiled policy through OPA Go SDK in runtime-gateway.  
Verify: Allow/Monitor/Block fixtures pass under latency benchmark.  
Timebox: <=15 minutes.

**M6-05 - policy bundle signer**  
Depends on: `M6-04`  
Deliverable: Create signed bundle manifest and S3 artifact writer.  
Verify: Modified bundle fails verification.  
Timebox: <=15 minutes.

**M6-06 - runtime bundle cache**  
Depends on: `M6-05`  
Deliverable: Load last-valid signed bundle to local runtime-gateway cache.  
Verify: Gateway restart works with cached bundle when control plane is unavailable.  
Timebox: <=15 minutes.

**M6-07 - internal policy bundle API**  
Depends on: `M6-06`  
Deliverable: Implement `getPolicyBundle` internal operation.  
Verify: Scoped runtime token fetches only its Environment bundle.  
Timebox: <=15 minutes.

**M6-08 - API listPolicies**  
Depends on: `M6-07`  
Deliverable: Implement OpenAPI operation `listPolicies` for `GET /api/v1/policies` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M6-09 - API createPolicy**  
Depends on: `M6-08`  
Deliverable: Implement OpenAPI operation `createPolicy` for `POST /api/v1/policies` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M6-10 - API getPolicy**  
Depends on: `M6-09`  
Deliverable: Implement OpenAPI operation `getPolicy` for `GET /api/v1/policies/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M6-11 - API updatePolicy**  
Depends on: `M6-10`  
Deliverable: Implement OpenAPI operation `updatePolicy` for `PATCH /api/v1/policies/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M6-12 - API deletePolicy**  
Depends on: `M6-11`  
Deliverable: Implement OpenAPI operation `deletePolicy` for `DELETE /api/v1/policies/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M6-13 - API simulatePolicy**  
Depends on: `M6-12`  
Deliverable: Implement OpenAPI operation `simulatePolicy` for `POST /api/v1/policies/{id}/simulate` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M6-14 - API rolloutPolicy**  
Depends on: `M6-13`  
Deliverable: Implement OpenAPI operation `rolloutPolicy` for `POST /api/v1/policies/{id}/rollout` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M6-15 - API disablePolicy**  
Depends on: `M6-14`  
Deliverable: Implement OpenAPI operation `disablePolicy` for `POST /api/v1/policies/{id}/disable` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M6-16 - API listPolicyDecisions**  
Depends on: `M6-15`  
Deliverable: Implement OpenAPI operation `listPolicyDecisions` for `GET /api/v1/policies/{id}/decisions` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M6-17 - policy simulator query**  
Depends on: `M6-16`  
Deliverable: Evaluate supported policy against bounded historical OpenSearch session events.  
Verify: Result returns match/would-block counts and examples without full scan.  
Timebox: <=15 minutes.

**M6-18 - rollout state machine**  
Depends on: `M6-17`  
Deliverable: Implement draft -> monitor -> enforce -> disabled transitions and scoped rollout.  
Verify: Invalid transition fails and all transitions audit.  
Timebox: <=15 minutes.

**M6-19 - runtime HTTP proxy**  
Depends on: `M6-18`  
Deliverable: Proxy one supported HTTP/tool action unchanged on Allow.  
Verify: Golden request/response body and headers remain semantically equivalent.  
Timebox: <=15 minutes.

**M6-20 - runtime MCP parser**  
Depends on: `M6-19`  
Deliverable: Parse supported MCP JSON-RPC tool call into canonical ActionContext.  
Verify: Fixture preserves method/tool/resource metadata.  
Timebox: <=15 minutes.

**M6-21 - runtime action context**  
Depends on: `M6-20`  
Deliverable: Normalize principal/agent/session/action/resource/environment for policy evaluation.  
Verify: Missing required scope yields safe error.  
Timebox: <=15 minutes.

**M6-22 - runtime Block response**  
Depends on: `M6-21`  
Deliverable: Return stable product block error and correlation ID.  
Verify: Blocked fixture never calls upstream.  
Timebox: <=15 minutes.

**M6-23 - runtime Monitor event**  
Depends on: `M6-22`  
Deliverable: Allow upstream action and emit monitor decision event.  
Verify: Event includes policy ID and result without sensitive payload.  
Timebox: <=15 minutes.

**M6-24 - runtime decision internal API**  
Depends on: `M6-23`  
Deliverable: Implement `recordRuntimeDecision` internal operation.  
Verify: Scoped idempotent event is accepted once.  
Timebox: <=15 minutes.

**M6-25 - policy bundle fallback**  
Depends on: `M6-24`  
Deliverable: Simulate Neon/control-plane outage while runtime gateway uses last-valid bundle.  
Verify: Known Block remains Block until bundle expires/explicit fail mode.  
Timebox: <=15 minutes.

**M6-26 - policy latency benchmark**  
Depends on: `M6-25`  
Deliverable: Add focused benchmark for metadata-only decision path.  
Verify: Reference p95 <=25 ms in local cluster run.  
Timebox: <=15 minutes.

**M6-27 - Policies list UI**  
Depends on: `M6-26`  
Deliverable: Create policy list/status/coverage view.  
Verify: E2E shows monitor/enforce/disabled and stale bundle state.  
Timebox: <=15 minutes.

**M6-28 - Policy wizard UI**  
Depends on: `M6-27`  
Deliverable: Create Scope -> Trigger -> Conditions -> Action -> Coverage -> Simulate -> Rollout wizard.  
Verify: Unsupported control cannot be selected.  
Timebox: <=15 minutes.

**M6-29 - Policy detail UI**  
Depends on: `M6-28`  
Deliverable: Create simulation results, decisions, rollout and disable actions.  
Verify: E2E monitor then enforce flow passes.  
Timebox: <=15 minutes.

**M6-30 - re-test state update**  
Depends on: `M6-29`  
Deliverable: Apply policy decision evidence so a re-tested supported path/capability can show Blocked.  
Verify: Fixture does not mark Blocked without observed policy decision.  
Timebox: <=15 minutes.

**M6-31a - policy create simulate gate**  
Depends on: `M6-30`  
Deliverable: Create one Monitor policy and simulate it against fixture sessions.  
Verify: Simulation returns expected match and would-block counts.  
Timebox: <=15 minutes.

**M6-31b - policy monitor gate**  
Depends on: `M6-31a`  
Deliverable: Roll the fixture policy to Monitor on a selected agent.  
Verify: Runtime decision is recorded without blocking the action.  
Timebox: <=15 minutes.

**M6-31c - policy enforce gate**  
Depends on: `M6-31b`  
Deliverable: Roll the same fixture policy to Block.  
Verify: Matching runtime action is blocked with product reason and correlation ID.  
Timebox: <=15 minutes.

**M6-31d - policy retest gate**  
Depends on: `M6-31c`  
Deliverable: Re-run the previously Verified test after enforcement.  
Verify: Relevant attack path/capability becomes Blocked while reachability evidence remains.  
Timebox: <=15 minutes.

**M6-31e - policy outage gate**  
Depends on: `M6-31d`  
Deliverable: Interrupt control-plane access after a signed policy bundle is cached.  
Verify: Runtime gateway continues enforcing the last valid policy bundle.  
Timebox: <=15 minutes.

**M6-31 - M6 gate**  
Depends on: `M6-31e`  
Deliverable: Write the M6 gate result from create/simulate/monitor/enforce/retest/outage checks.  
Verify: Gate record is PASS only when all stages passed.  
Timebox: <=15 minutes.

### M7 - Sessions, compliance and admin UX

**M7-01 - session projection**  
Depends on: `M5-35,M6-31,M2-47`  
Deliverable: Create Session summary/projector from correlated semantic/runtime events.  
Verify: Replay is idempotent and keeps confidence per event.  
Timebox: <=15 minutes.

**M7-02 - API listSessions**  
Depends on: `M7-01`  
Deliverable: Implement OpenAPI operation `listSessions` for `GET /api/v1/sessions` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-03 - API getSession**  
Depends on: `M7-02`  
Deliverable: Implement OpenAPI operation `getSession` for `GET /api/v1/sessions/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-04 - API listSessionEvents**  
Depends on: `M7-03`  
Deliverable: Implement OpenAPI operation `listSessionEvents` for `GET /api/v1/sessions/{id}/events` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-05 - session search filters**  
Depends on: `M7-04`  
Deliverable: Implement structured OpenSearch filters for agent/principal/tool/process/file/domain/credential/resource/decision/time.  
Verify: Query builder rejects arbitrary query string/DSL.  
Timebox: <=15 minutes.

**M7-06 - Sessions list UI**  
Depends on: `M7-05`  
Deliverable: Create Sessions list with structured filters and confidence/freshness.  
Verify: E2E filter returns expected fixture session.  
Timebox: <=15 minutes.

**M7-07a - Session timeline shell**  
Depends on: `M7-06`  
Deliverable: Build paginated session timeline container and time ordering.  
Verify: Out-of-order fixture renders by canonical event time.  
Timebox: <=15 minutes.

**M7-07b - Session event row**  
Depends on: `M7-07a`  
Deliverable: Build event row for tool/runtime/network/file/credential/policy classes.  
Verify: Each supported class renders deterministic label and evidence link.  
Timebox: <=15 minutes.

**M7-07c - Session confidence/source**  
Depends on: `M7-07b`  
Deliverable: Add source and Exact/Strong/Probable/Unattributed display.  
Verify: Probable fixture is visibly differentiated from Exact.  
Timebox: <=15 minutes.

**M7-07 - Session detail UI**  
Depends on: `M7-07c`  
Deliverable: Compose session timeline rows with confidence/source and pagination.  
Verify: E2E renders mixed-evidence session without false Exact attribution.  
Timebox: <=15 minutes.

**M7-08 - compliance control model**  
Depends on: `M7-07`  
Deliverable: Define MVP SOC 2 Security/HIPAA safeguard mapping objects and evidence freshness.  
Verify: Mapping references product evidence IDs, not screenshots.  
Timebox: <=15 minutes.

**M7-09 - compliance evidence assembler**  
Depends on: `M7-08`  
Deliverable: Assemble current audit/finding/policy/test/config evidence for one control.  
Verify: Stale evidence is explicitly marked.  
Timebox: <=15 minutes.

**M7-10 - API listComplianceControls**  
Depends on: `M7-09`  
Deliverable: Implement OpenAPI operation `listComplianceControls` for `GET /api/v1/compliance/controls` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-11 - API listComplianceEvidence**  
Depends on: `M7-10`  
Deliverable: Implement OpenAPI operation `listComplianceEvidence` for `GET /api/v1/compliance/evidence` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-12 - API createComplianceExport**  
Depends on: `M7-11`  
Deliverable: Implement OpenAPI operation `createComplianceExport` for `POST /api/v1/compliance/exports` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-13 - API getComplianceExport**  
Depends on: `M7-12`  
Deliverable: Implement OpenAPI operation `getComplianceExport` for `GET /api/v1/compliance/exports/{id}` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-14 - compliance export artifact**  
Depends on: `M7-13`  
Deliverable: Create JSON/CSV plus human-readable evidence package in S3.  
Verify: Package links evidence IDs/timestamps and avoids certification language.  
Timebox: <=15 minutes.

**M7-15a - Compliance framework/control list**  
Depends on: `M7-14`  
Deliverable: Build SOC 2 Security and HIPAA safeguard control list.  
Verify: Fixture renders mapped controls without certification language.  
Timebox: <=15 minutes.

**M7-15b - Compliance evidence table**  
Depends on: `M7-15a`  
Deliverable: Build evidence rows with asset/source/timestamp links.  
Verify: Click opens product evidence target.  
Timebox: <=15 minutes.

**M7-15c - Compliance freshness/gaps**  
Depends on: `M7-15b`  
Deliverable: Add freshness and missing-evidence states.  
Verify: Stale fixture is labeled stale, not passing.  
Timebox: <=15 minutes.

**M7-15d - Compliance export action**  
Depends on: `M7-15c`  
Deliverable: Add evidence export trigger and job-status UI.  
Verify: Queued/completed/error states render.  
Timebox: <=15 minutes.

**M7-15 - Compliance Evidence UI**  
Depends on: `M7-15d`  
Deliverable: Compose Compliance Evidence list, freshness and export interaction.  
Verify: E2E filter/export flow passes.  
Timebox: <=15 minutes.

**M7-16 - data control store**  
Depends on: `M7-15`  
Deliverable: Create Environment collection mode/retention/deletion settings and validation.  
Verify: Production default is metadata-only.  
Timebox: <=15 minutes.

**M7-17 - API getDataControls**  
Depends on: `M7-16`  
Deliverable: Implement OpenAPI operation `getDataControls` for `GET /api/v1/settings/data-controls` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-18 - API updateDataControls**  
Depends on: `M7-17`  
Deliverable: Implement OpenAPI operation `updateDataControls` for `PATCH /api/v1/settings/data-controls` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-19 - retention worker**  
Depends on: `M7-18`  
Deliverable: Delete/expire product-controlled event/evidence references according to data class policy.  
Verify: Fixture deletes expired test data and audits admin policy change.  
Timebox: <=15 minutes.

**M7-20 - external flow model**  
Depends on: `M7-19`  
Deliverable: Define required/optional external destination, allowed data categories, enabled state and health.  
Verify: Raw security evidence category cannot be enabled for PostHog.  
Timebox: <=15 minutes.

**M7-21 - API getExternalDataFlows**  
Depends on: `M7-20`  
Deliverable: Implement OpenAPI operation `getExternalDataFlows` for `GET /api/v1/settings/external-data-flows` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-22 - API updateExternalDataFlows**  
Depends on: `M7-21`  
Deliverable: Implement OpenAPI operation `updateExternalDataFlows` for `PATCH /api/v1/settings/external-data-flows` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-22a - required external-flow guard**  
Depends on: `M7-22`  
Deliverable: Prevent the External Data Flows API from disabling required Stytch or Neon dependencies while allowing optional PostHog, OpenRouter and remote OTLP changes.  
Verify: Required-service disable fixture is rejected; optional-service disable fixture succeeds and is audited.  
Timebox: <=15 minutes.

**M7-23 - PostHog serializer**  
Depends on: `M7-22a`  
Deliverable: Create allowlist-only product event serializer.  
Verify: Prompt/tool args/secrets/IP/raw evidence fixtures fail serialization.  
Timebox: <=15 minutes.

**M7-24 - PostHog flag cache**  
Depends on: `M7-23`  
Deliverable: Implement server-side flag cache with explicit code defaults/max age.  
Verify: PostHog outage returns deterministic defaults.  
Timebox: <=15 minutes.

**M7-25 - OpenRouter redaction**  
Depends on: `M7-24`  
Deliverable: Redact prohibited fields for approved AI explanation purposes.  
Verify: Seeded secret/PII/PHI fixture is absent at fake endpoint.  
Timebox: <=15 minutes.

**M7-26a - OpenRouter purpose and model policy**  
Depends on: `M7-25`  
Deliverable: Reject AI requests whose purpose, model or provider is not allowlisted.  
Verify: Unapproved purpose/model/provider fails before egress.  
Timebox: <=15 minutes.

**M7-26b - OpenRouter request limits**  
Depends on: `M7-26a`  
Deliverable: Enforce per-request token, cost, deadline and concurrency limits.  
Verify: Over-limit fixture is rejected before provider request.  
Timebox: <=15 minutes.

**M7-26c - OpenRouter data policy metadata**  
Depends on: `M7-26b`  
Deliverable: Attach configured data-policy/ZDR requirement metadata to provider selection.  
Verify: Provider selection excludes a fixture that violates the required data policy.  
Timebox: <=15 minutes.

**M7-26 - OpenRouter governance**  
Depends on: `M7-26c`  
Deliverable: Wire AI governance checks into the AIGateway request path.  
Verify: Approved request passes all guards and records governed request metadata.  
Timebox: <=15 minutes.

**M7-27 - API createAIExplanation**  
Depends on: `M7-26`  
Deliverable: Implement OpenAPI operation `createAIExplanation` for `POST /api/v1/ai/explanations` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-28 - AI explanation UI**  
Depends on: `M7-27`  
Deliverable: Create evidence-aware Explain with AI panel and unavailable state.  
Verify: E2E displays sent-field notice and deterministic content stays usable on failure.  
Timebox: <=15 minutes.

**M7-29 - system component probes**  
Depends on: `M7-28`  
Deliverable: Add product probes for required/optional dependencies and internal components.  
Verify: Required vs optional state aggregates correctly.  
Timebox: <=15 minutes.

**M7-30 - API getSystemStatus**  
Depends on: `M7-29`  
Deliverable: Implement OpenAPI operation `getSystemStatus` for `GET /api/v1/system/status` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-31 - API listSystemComponents**  
Depends on: `M7-30`  
Deliverable: Implement OpenAPI operation `listSystemComponents` for `GET /api/v1/system/components` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-32 - API getSystemVersion**  
Depends on: `M7-31`  
Deliverable: Implement OpenAPI operation `getSystemVersion` for `GET /api/v1/system/version` using the existing service/store contract.  
Verify: Handler test covers authorized success plus one stable product error.  
Timebox: <=15 minutes.

**M7-33 - System Health UI**  
Depends on: `M7-32`  
Deliverable: Create component status, version, freshness and action guidance page.  
Verify: E2E vendor failure is shown in product language.  
Timebox: <=15 minutes.

**M7-34 - Data & Retention UI**  
Depends on: `M7-33`  
Deliverable: Create collection/retention settings and regulated-profile warning.  
Verify: E2E changes policy and records audit.  
Timebox: <=15 minutes.

**M7-35 - External Data Flows UI**  
Depends on: `M7-34`  
Deliverable: Create destination/data-category/enablement/health page.  
Verify: E2E cannot enable prohibited PostHog category.  
Timebox: <=15 minutes.

**M7-36 - Audit Log UI**  
Depends on: `M7-35`  
Deliverable: Create filterable audit page and export action.  
Verify: E2E shows SSO/config/policy/test mutations.  
Timebox: <=15 minutes.

**M7-37 - Home/search UI binding**  
Depends on: `M7-36`  
Deliverable: Bind Home and Global Search to final APIs.  
Verify: E2E first-value navigation reaches Agent/Finding/Path without raw graph UI.  
Timebox: <=15 minutes.

**M7-38 - full UI API map**  
Depends on: `M7-37`  
Deliverable: Expand `ui-api-map.yaml` to every MVP screen/action listed in Section 9.  
Verify: Coverage CI reports 100 percent mapped operations.  
Timebox: <=15 minutes.

**M7-39a - stale connector UX**  
Depends on: `M7-38`  
Deliverable: Add E2E fixture for stale connector data on Inventory and Findings.  
Verify: UI shows stale state and never renders a false zero-risk result.  
Timebox: <=15 minutes.

**M7-39b - graph outage UX**  
Depends on: `M7-39a`  
Deliverable: Add E2E fixture for Neo4j unavailable on capability and attack-path screens.  
Verify: Affected screens show Degraded instead of empty/safe.  
Timebox: <=15 minutes.

**M7-39c - event index outage UX**  
Depends on: `M7-39b`  
Deliverable: Add E2E fixture for OpenSearch unavailable on session activity.  
Verify: Session activity shows Degraded and preserves known metadata.  
Timebox: <=15 minutes.

**M7-39d - AI outage UX**  
Depends on: `M7-39c`  
Deliverable: Add E2E fixture for OpenRouter unavailable on Explain with AI.  
Verify: AI action reports unavailable while deterministic evidence remains usable.  
Timebox: <=15 minutes.

**M7-39e - OTLP outage UX**  
Depends on: `M7-39d`  
Deliverable: Add E2E fixture for optional remote OTLP unavailable.  
Verify: System Health reports exporter degradation without marking the security plane unhealthy.  
Timebox: <=15 minutes.

**M7-39 - degraded-state E2E**  
Depends on: `M7-39e`  
Deliverable: Register the five degraded-state fixtures in the milestone E2E suite.  
Verify: Suite reports each degradation independently with product-owned errors.  
Timebox: <=15 minutes.

**M7-40a - M7 session E2E**  
Depends on: `M7-39`  
Deliverable: Run one correlated session detail flow.  
Verify: Semantic and runtime events render in stable order with confidence.  
Timebox: <=15 minutes.

**M7-40b - M7 compliance E2E**  
Depends on: `M7-40a`  
Deliverable: Run compliance evidence filter and export flow.  
Verify: Export references live evidence and freshness metadata.  
Timebox: <=15 minutes.

**M7-40c - M7 data-control E2E**  
Depends on: `M7-40b`  
Deliverable: Change metadata/content retention setting in a fixture environment.  
Verify: Setting is audited and ingest behavior follows the new policy.  
Timebox: <=15 minutes.

**M7-40d - M7 system-health E2E**  
Depends on: `M7-40c`  
Deliverable: Run required/optional dependency health fixture.  
Verify: System Health distinguishes required degradation from optional degradation.  
Timebox: <=15 minutes.

**M7-40e - M7 AI degrade E2E**  
Depends on: `M7-40d`  
Deliverable: Run finding explanation with OpenRouter unavailable.  
Verify: Deterministic finding actions remain enabled.  
Timebox: <=15 minutes.

**M7-40f - M7 UI API coverage E2E**  
Depends on: `M7-40e`  
Deliverable: Run generated-client and ui-api-map coverage check.  
Verify: Every interactive MVP operation maps to a screen/action and handler task.  
Timebox: <=15 minutes.

**M7-40 - M7 gate**  
Depends on: `M7-40f`  
Deliverable: Write the M7 gate result from the six independent E2E checks.  
Verify: Gate record is PASS only when all checks passed.  
Timebox: <=15 minutes.

### M7A - Security Agents, approvals and bounded response

**M7A-01 - Security Agent domain types**  
Depends on: `M7-40`  
Deliverable: Add `SecurityAgent`, trigger, scope, autonomy, limit and verification domain types.  
Verify: Domain validation rejects empty scope, empty allowed-action set and non-positive run limits.  
Timebox: <=15 minutes.

**M7A-02 - Security Agent run domain types**  
Depends on: `M7A-01`  
Deliverable: Add `SecurityAgentRun` states `queued,planning,waiting_approval,running,verifying,contained,remediated,needs_human,failed,inconclusive,cancelled`.  
Verify: Invalid terminal-to-running transition fails.  
Timebox: <=15 minutes.

**M7A-03 - Security Agent plan schema**  
Depends on: `M7A-02`  
Deliverable: Add versioned structured plan with ordered typed action steps and bounded rationale summary.  
Verify: Unknown plan version/action shape fails schema validation.  
Timebox: <=15 minutes.

**M7A-04 - Security action metadata type**  
Depends on: `M7A-03`  
Deliverable: Add action metadata fields for input schema, risk class, target types, approval floor, reversibility, idempotency and verification kind.  
Verify: Registry metadata fixture validates all required fields.  
Timebox: <=15 minutes.

**M7A-05 - Security Agent Neon migration**  
Depends on: `M7A-04`  
Deliverable: Add Organization-scoped `security_agents` table and indexes.  
Verify: Migration applies twice safely and RLS/tenant predicate test passes.  
Timebox: <=15 minutes.

**M7A-06 - Security Agent run Neon migration**  
Depends on: `M7A-05`  
Deliverable: Add Organization-scoped run table with immutable trigger/evidence snapshot references and definition version.  
Verify: Cross-Organization read is denied by repository/RLS fixture.  
Timebox: <=15 minutes.

**M7A-07 - Security Agent step Neon migration**  
Depends on: `M7A-06`  
Deliverable: Add run-step table with action, authorization, approval, execution and verification state.  
Verify: `(run_id, step_index)` uniqueness prevents duplicate step creation.  
Timebox: <=15 minutes.

**M7A-08 - Security Agent approval Neon migration**  
Depends on: `M7A-07`  
Deliverable: Add approval table with expiry, approver, fresh-auth timestamp and decision.  
Verify: Pending approval cannot be reused after terminal decision.  
Timebox: <=15 minutes.

**M7A-09 - Security action idempotency table**  
Depends on: `M7A-08`  
Deliverable: Add `(organization_id, run_id, step_id, action_key)` idempotency/outcome record.  
Verify: Duplicate execution claim returns prior state instead of executing again.  
Timebox: <=15 minutes.

**M7A-10 - Security Agent repository create/get**  
Depends on: `M7A-09`  
Deliverable: Implement scoped create/get repository methods.  
Verify: Repository test cannot retrieve another Organization's definition.  
Timebox: <=15 minutes.

**M7A-11 - Security Agent repository list/update/delete**  
Depends on: `M7A-10`  
Deliverable: Implement cursor list plus update/soft-delete methods.  
Verify: Disabled/deleted definitions no longer match trigger queries.  
Timebox: <=15 minutes.

**M7A-12 - Security Agent run repository**  
Depends on: `M7A-11`  
Deliverable: Implement create/get/list and compare-and-set state transitions.  
Verify: Concurrent state transition fixture allows one winner.  
Timebox: <=15 minutes.

**M7A-13 - Security Agent step repository**  
Depends on: `M7A-12`  
Deliverable: Implement append/read/update step state methods.  
Verify: Step ordering is stable and scoped.  
Timebox: <=15 minutes.

**M7A-14 - Security Agent approval repository**  
Depends on: `M7A-13`  
Deliverable: Implement create/list/get/decide approval methods.  
Verify: Expired or already-decided approval rejects a second decision.  
Timebox: <=15 minutes.

**M7A-15 - Action registry interface**  
Depends on: `M7A-14`  
Deliverable: Add `SecurityAction` registry interface with metadata, validate, execute and verify contracts.  
Verify: Duplicate action key registration fails startup test.  
Timebox: <=15 minutes.

**M7A-16 - Action: temporary runtime policy metadata**  
Depends on: `M7A-15,M6-31`  
Deliverable: Register `create_temporary_policy` with Monitor/Block-only typed parameters and TTL.  
Verify: Permanent/no-TTL autonomous request fails validation.  
Timebox: <=15 minutes.

**M7A-17 - Action: temporary runtime policy execute**  
Depends on: `M7A-16`  
Deliverable: Execute temporary policy through existing policy service using run/step idempotency key.  
Verify: Duplicate call returns same policy ID.  
Timebox: <=15 minutes.

**M7A-18 - Action: temporary runtime policy verify**  
Depends on: `M7A-17`  
Deliverable: Verify signed bundle publication and expected scoped policy state.  
Verify: Missing/stale bundle yields Inconclusive, not success.  
Timebox: <=15 minutes.

**M7A-18a - temporary-control expiry claim**  
Depends on: `M7A-18`  
Deliverable: Add scoped repository query/compare-and-set claim for temporary Security Agent controls whose TTL has expired.  
Verify: Two worker fixtures cannot claim the same expired control simultaneously.  
Timebox: <=15 minutes.

**M7A-18b - temporary-control cleanup executor**  
Depends on: `M7A-18a`  
Deliverable: Disable the expired product-native temporary policy/session isolation idempotently through the existing policy service.  
Verify: Repeated cleanup returns the same terminal disabled state without widening scope.  
Timebox: <=15 minutes.

**M7A-18c - temporary-control cleanup verifier**  
Depends on: `M7A-18b`  
Deliverable: Verify the next signed bundle/effective gateway state no longer contains the expired control and record cleanup audit evidence.  
Verify: Missing verification becomes cleanup_failed/Needs human, never silently cleaned.  
Timebox: <=15 minutes.

**M7A-18d - temporary-control expiry worker loop**  
Depends on: `M7A-18c`  
Deliverable: Add bounded periodic expiry scan to `agentsec-worker` using the claim/cleanup/verify path, without a new scheduler service.  
Verify: Expired fixture is cleaned once and future-TTL fixture is untouched.  
Timebox: <=15 minutes.

**M7A-19 - Action: isolate supported session metadata**  
Depends on: `M7A-18d`  
Deliverable: Register `isolate_session` as a temporary deny policy for supported gateway sessions.  
Verify: Target must be one current Organization-scoped session with supported enforcement coverage.  
Timebox: <=15 minutes.

**M7A-20 - Action: isolate supported session execute/verify**  
Depends on: `M7A-19`  
Deliverable: Create scoped session deny and verify gateway decision evidence.  
Verify: Fixture session becomes blocked while unrelated session remains allowed.  
Timebox: <=15 minutes.

**M7A-21 - Action: run existing test**  
Depends on: `M7A-20,M5-35`  
Deliverable: Register `run_test`/`rerun_test` against an existing TestDefinition.  
Verify: Action cannot create arbitrary new target/prompt content.  
Timebox: <=15 minutes.

**M7A-22 - Action: start Attack Lab verification**  
Depends on: `M7A-21,M5-35`  
Deliverable: Register `start_attack_lab` only for a preflight-approved non-production/test target.  
Verify: Production-write target fails before job enqueue.  
Timebox: <=15 minutes.

**M7A-23 - Action: evidence export**  
Depends on: `M7A-22,M7-40`  
Deliverable: Register `create_evidence_export` using existing export service.  
Verify: Export references only run-scoped evidence IDs.  
Timebox: <=15 minutes.

**M7A-24 - Action: signed webhook handoff**  
Depends on: `M7A-23`  
Deliverable: Register `send_response_webhook` using configured allowlisted webhook destination.  
Verify: Arbitrary URL argument is rejected; payload is redacted and signed.  
Timebox: <=15 minutes.

**M7A-25 - Action: finding response metadata**  
Depends on: `M7A-24`  
Deliverable: Register safe finding assignment/status-note action without closing/marking safe.  
Verify: Planner cannot set finding to Resolved/Safe.  
Timebox: <=15 minutes.

**M7A-26 - Action: supported connection revoke metadata**  
Depends on: `M7A-25`  
Deliverable: Register `revoke_integration_connection` only when connector capability declares support; mark mandatory approval.  
Verify: Unsupported integration does not expose action.  
Timebox: <=15 minutes.

**M7A-27 - Action: supported connection revoke execute**  
Depends on: `M7A-26`  
Deliverable: Execute through IntegrationCredentialBroker after approved step.  
Verify: No approval token means no broker revoke call.  
Timebox: <=15 minutes.

**M7A-28 - Action: supported connection revoke verify**  
Depends on: `M7A-27`  
Deliverable: Re-read connection state and classify revoked/unknown.  
Verify: Provider timeout yields Inconclusive.  
Timebox: <=15 minutes.

**M7A-29 - Built-in template registry**  
Depends on: `M7A-28`  
Deliverable: Add versioned template registry abstraction.  
Verify: Template IDs and default action sets are stable in golden test.  
Timebox: <=15 minutes.

**M7A-30 - Suspicious Egress template**  
Depends on: `M7A-29`  
Deliverable: Add trigger/scope/action defaults for suspicious egress response.  
Verify: Default has temporary block, evidence handoff and verification, no destructive provider action.  
Timebox: <=15 minutes.

**M7A-31 - Credential Exposure template**  
Depends on: `M7A-30`  
Deliverable: Add credential exposure responder defaults.  
Verify: Connection revoke, if available, is approval-required.  
Timebox: <=15 minutes.

**M7A-32 - Prompt/Tool Injection template**  
Depends on: `M7A-31`  
Deliverable: Add Verified-test/path responder defaults with temporary Block plus re-test.  
Verify: Template verification condition requires the linked risk to become Blocked/Not Reproduced for expected reason.  
Timebox: <=15 minutes.

**M7A-33 - Repeated Policy Violation template**  
Depends on: `M7A-32`  
Deliverable: Add repeated high-risk runtime decision responder defaults.  
Verify: Trigger is bounded by agent/session/time window.  
Timebox: <=15 minutes.

**M7A-34 - Shadow Agent Triage template**  
Depends on: `M7A-33`  
Deliverable: Add non-destructive triage responder defaults.  
Verify: Allowed actions contain no Block/revoke by default.  
Timebox: <=15 minutes.

**M7A-35 - Trigger matcher: finding**  
Depends on: `M7A-34`  
Deliverable: Match enabled definition to finding family/severity/environment.  
Verify: Cross-Environment and disabled definitions do not match.  
Timebox: <=15 minutes.

**M7A-36 - Trigger matcher: attack path**  
Depends on: `M7A-35`  
Deliverable: Match configured path evidence state including Verified.  
Verify: Potential path does not match Verified-only trigger.  
Timebox: <=15 minutes.

**M7A-37 - Trigger matcher: runtime decision**  
Depends on: `M7A-36`  
Deliverable: Match policy decision/action/risk pattern with bounded count/window.  
Verify: Event outside window does not trigger.  
Timebox: <=15 minutes.

**M7A-38 - Trigger deduplication**  
Depends on: `M7A-37`  
Deliverable: Derive trigger fingerprint and suppress duplicate run creation for configured cooldown.  
Verify: Replayed source event creates one run.  
Timebox: <=15 minutes.

**M7A-38a - Security trigger event contract**  
Depends on: `M7A-38`  
Deliverable: Define Organization-scoped internal trigger event for finding create/update, attack-path state change and runtime policy-decision pattern inputs.  
Verify: Event schema rejects missing source ID, Environment or Organization scope.  
Timebox: <=15 minutes.

**M7A-38b - automatic Security Agent trigger dispatcher**  
Depends on: `M7A-38a,M7A-12`  
Deliverable: Consume one trigger event, run the matching definition type, apply cooldown deduplication, create the immutable SecurityAgentRun and enqueue `security_agent.run`.  
Verify: Matching fixture creates exactly one queued run; no match creates none.  
Timebox: <=15 minutes.

**M7A-38c - trigger source wiring**  
Depends on: `M7A-38b`  
Deliverable: Emit the internal trigger event from finding state changes, attack-path evidence-state changes and runtime decision aggregation after their own durable state update.  
Verify: One fixture of each source type reaches dispatcher with canonical source reference.  
Timebox: <=15 minutes.

**M7A-38d - automatic trigger E2E**  
Depends on: `M7A-38c`  
Deliverable: Replay duplicate finding/path/runtime trigger fixtures against enabled responders.  
Verify: Expected responders create one run each and replayed events do not create duplicate runs.  
Timebox: <=15 minutes.

**M7A-39 - Evidence snapshot builder**  
Depends on: `M7A-38d,M7-40`  
Deliverable: Build bounded canonical finding/path/agent/session/policy summary and evidence IDs for planner.  
Verify: Snapshot excludes raw secret fields and another Organization's evidence.  
Timebox: <=15 minutes.

**M7A-40 - Planner input separation**  
Depends on: `M7A-39`  
Deliverable: Separate product system policy, operator goal and untrusted evidence fields in planner request.  
Verify: Fixture injection text remains inside untrusted evidence field.  
Timebox: <=15 minutes.

**M7A-41 - Security Agent planner purpose**  
Depends on: `M7A-40,M7-27`  
Deliverable: Add `security_response_plan` purpose to AIGateway policy with structured schema only.  
Verify: Free-form completion path is rejected for this purpose.  
Timebox: <=15 minutes.

**M7A-42 - Planner step/action limit**  
Depends on: `M7A-41`  
Deliverable: Enforce definition/product max action count before plan acceptance.  
Verify: Six-step plan is rejected when max is five.  
Timebox: <=15 minutes.

**M7A-43 - Planner scope/reference validator**  
Depends on: `M7A-42`  
Deliverable: Reject action targets/evidence IDs outside run Organization/Workspace/Environment scope.  
Verify: Cross-tenant injected UUID is rejected.  
Timebox: <=15 minutes.

**M7A-44 - Planner action schema validator**  
Depends on: `M7A-43`  
Deliverable: Validate every planned action against registry schema and definition allowed-action set.  
Verify: Invented action and extra argument both fail.  
Timebox: <=15 minutes.

**M7A-45 - Planner prompt-injection security test**  
Depends on: `M7A-44`  
Deliverable: Seed evidence with instructions to revoke unrelated connection and call arbitrary URL.  
Verify: Accepted plan cannot contain either prohibited action/target.  
Timebox: <=15 minutes.

**M7A-46 - ActionAuthorizer base**  
Depends on: `M7A-45`  
Deliverable: Implement deterministic definition/action/scope authorization result `allow,approval_required,deny`.  
Verify: Planner rationale cannot affect result.  
Timebox: <=15 minutes.

**M7A-47 - Product approval floor rules**  
Depends on: `M7A-46`  
Deliverable: Require approval for connector revoke and any action metadata marked mandatory approval.  
Verify: Definition cannot lower mandatory approval to auto.  
Timebox: <=15 minutes.

**M7A-48 - Creator permission validation**  
Depends on: `M7A-47`  
Deliverable: On enable, require creator/current editor permission for every action class and target scope.  
Verify: User lacking integration-revoke permission cannot enable that action.  
Timebox: <=15 minutes.

**M7A-49 - Security Agent run budget**  
Depends on: `M7A-48`  
Deliverable: Enforce max steps, wall-clock deadline, AI cost/token cap and Organization concurrency limit.  
Verify: Budget breach moves run to Needs human/Failed without new action.  
Timebox: <=15 minutes.

**M7A-50 - Run queue job**  
Depends on: `M7A-49`  
Deliverable: Add Organization-scoped `security_agent.run` background job and idempotent dequeue handler.  
Verify: Replayed SQS delivery does not create second run.  
Timebox: <=15 minutes.

**M7A-51 - Run planner state**  
Depends on: `M7A-50`  
Deliverable: Transition queued -> planning -> persist validated plan.  
Verify: Planner failure records bounded product error and no actions execute.  
Timebox: <=15 minutes.

**M7A-52 - Auto-action executor**  
Depends on: `M7A-51`  
Deliverable: Execute one authorized auto step via registry with idempotency record.  
Verify: Duplicate worker delivery calls underlying action once.  
Timebox: <=15 minutes.

**M7A-53 - Waiting approval state**  
Depends on: `M7A-52`  
Deliverable: Create approval for `approval_required` step and stop run progression.  
Verify: Later steps are not executed while approval is pending.  
Timebox: <=15 minutes.

**M7A-54 - Approval fresh-auth guard**  
Depends on: `M7A-53,M2-47`  
Deliverable: Apply `RequireFreshAuth` to sensitive approval decision operation.  
Verify: Stale/unverifiable session cannot approve mandatory-approval action.  
Timebox: <=15 minutes.

**M7A-55 - Approval decision resume job**  
Depends on: `M7A-54`  
Deliverable: Approved decision enqueues idempotent run resume; denial marks run Needs human/Cancelled according to definition.  
Verify: Replayed approval webhook/request resumes once.  
Timebox: <=15 minutes.

**M7A-56 - Action execution result classifier**  
Depends on: `M7A-55`  
Deliverable: Classify action result success, known failure or unknown outcome.  
Verify: Unknown external outcome never auto-retries side effect.  
Timebox: <=15 minutes.

**M7A-57 - Step verifier dispatcher**  
Depends on: `M7A-56`  
Deliverable: Dispatch expected verification kind from action metadata.  
Verify: Missing verifier yields Inconclusive.  
Timebox: <=15 minutes.

**M7A-58 - Run final outcome evaluator**  
Depends on: `M7A-57`  
Deliverable: Compute Contained/Remediated only from configured passed verification conditions.  
Verify: HTTP/API execution success without verification cannot produce Remediated.  
Timebox: <=15 minutes.

**M7A-59 - Run cancellation**  
Depends on: `M7A-58`  
Deliverable: Cancel future steps while preserving already-completed actions and TTL cleanup.  
Verify: Cancel during pending approval prevents resume.  
Timebox: <=15 minutes.

**M7A-60 - Security Agent audit event helper**  
Depends on: `M7A-59`  
Deliverable: Emit audit events for trigger, plan hash, authorization, approval, execute, verify and terminal outcome.  
Verify: Seeded secrets/action raw credentials are absent from audit metadata.  
Timebox: <=15 minutes.

**M7A-61 - API listSecurityAgentTemplates**  
Depends on: `M7A-60`  
Deliverable: Implement `GET /api/v1/security-agent-templates`.  
Verify: Response contains product templates only, no prompt/vendor internals.  
Timebox: <=15 minutes.

**M7A-62 - API listSecurityActions**  
Depends on: `M7A-61`  
Deliverable: Implement `GET /api/v1/security-actions` filtered by target/scope support.  
Verify: Unsupported integration revoke is absent.  
Timebox: <=15 minutes.

**M7A-63 - API listSecurityAgents**  
Depends on: `M7A-62`  
Deliverable: Implement `GET /api/v1/security-agents`.  
Verify: Cursor/filter and Organization scope test pass.  
Timebox: <=15 minutes.

**M7A-64 - API createSecurityAgent**  
Depends on: `M7A-63`  
Deliverable: Implement `POST /api/v1/security-agents`.  
Verify: Invalid action/approval/limit definition returns stable product error.  
Timebox: <=15 minutes.

**M7A-65 - API getSecurityAgent**  
Depends on: `M7A-64`  
Deliverable: Implement `GET /api/v1/security-agents/{id}`.  
Verify: Cross-Organization ID returns not-found/forbidden per API convention.  
Timebox: <=15 minutes.

**M7A-66 - API updateSecurityAgent**  
Depends on: `M7A-65`  
Deliverable: Implement `PATCH /api/v1/security-agents/{id}` including enable/disable.  
Verify: Enabling runs creator-permission/action-floor validation.  
Timebox: <=15 minutes.

**M7A-67 - API deleteSecurityAgent**  
Depends on: `M7A-66`  
Deliverable: Implement `DELETE /api/v1/security-agents/{id}` as safe soft-delete/disable.  
Verify: Historical runs remain queryable.  
Timebox: <=15 minutes.

**M7A-68 - Security Agent dry-run simulator**  
Depends on: `M7A-67`  
Deliverable: Simulate trigger/evidence/planner/authorization without executing action adapters.  
Verify: Response lists proposed steps and approval points, with zero side effects.  
Timebox: <=15 minutes.

**M7A-69 - API simulateSecurityAgent**  
Depends on: `M7A-68`  
Deliverable: Implement `POST /api/v1/security-agents/{id}/simulate`.  
Verify: E2E fake action registry records zero execution calls.  
Timebox: <=15 minutes.

**M7A-70 - API runSecurityAgent**  
Depends on: `M7A-69`  
Deliverable: Implement manual `POST /api/v1/security-agents/{id}/runs` with optional finding/path/session trigger ref.  
Verify: Invalid cross-scope trigger ref is rejected.  
Timebox: <=15 minutes.

**M7A-71 - API listSecurityAgentRuns**  
Depends on: `M7A-70`  
Deliverable: Implement `GET /api/v1/security-agent-runs`.  
Verify: Filter by agent/status/environment and cursor pagination.  
Timebox: <=15 minutes.

**M7A-72 - API getSecurityAgentRun**  
Depends on: `M7A-71`  
Deliverable: Implement run detail including evidence refs, plan, authorization, approvals, execution and verification.  
Verify: Response redacts protected action arguments.  
Timebox: <=15 minutes.

**M7A-73 - API cancelSecurityAgentRun**  
Depends on: `M7A-72`  
Deliverable: Implement `POST /api/v1/security-agent-runs/{id}/cancel`.  
Verify: Terminal run rejects cancel idempotently.  
Timebox: <=15 minutes.

**M7A-74 - API listSecurityAgentApprovals**  
Depends on: `M7A-73`  
Deliverable: Implement `GET /api/v1/security-agent-approvals`.  
Verify: Only approvals authorized for caller Workspace/Environment are returned.  
Timebox: <=15 minutes.

**M7A-75 - API getSecurityAgentApproval**  
Depends on: `M7A-74`  
Deliverable: Implement `GET /api/v1/security-agent-approvals/{id}`.  
Verify: Includes expected side effect, reversibility/TTL and evidence summary.  
Timebox: <=15 minutes.

**M7A-76 - API decideSecurityAgentApproval**  
Depends on: `M7A-75,M7A-54`  
Deliverable: Implement approve/deny/cancel decision endpoint with fresh-auth guard.  
Verify: Planner/run identity cannot self-approve.  
Timebox: <=15 minutes.

**M7A-77 - Security Agents nav/list UI**  
Depends on: `M7A-76`  
Deliverable: Add Protect -> Security Agents and list columns for status, trigger, scope, autonomy, last outcome, pending approvals and owner.  
Verify: E2E list uses generated client only.  
Timebox: <=15 minutes.

**M7A-78 - Security Agent builder Start/Trigger UI**  
Depends on: `M7A-77`  
Deliverable: Add template/blank choice and bounded trigger step.  
Verify: UI cannot enter arbitrary trigger code/query.  
Timebox: <=15 minutes.

**M7A-79 - Security Agent builder Goal/Scope UI**  
Depends on: `M7A-78`  
Deliverable: Add short goal text plus Workspace/Environment/agent/tag selectors.  
Verify: Goal field does not alter allowed-action list without explicit user action.  
Timebox: <=15 minutes.

**M7A-80 - Security Agent builder Actions UI**  
Depends on: `M7A-79`  
Deliverable: Add action catalog selector showing risk, support and reversibility.  
Verify: No arbitrary tool URL/code/shell controls exist.  
Timebox: <=15 minutes.

**M7A-81 - Security Agent builder Autonomy UI**  
Depends on: `M7A-80`  
Deliverable: Configure auto vs approval-required actions while displaying immutable product floors.  
Verify: Mandatory approval control cannot be toggled off.  
Timebox: <=15 minutes.

**M7A-82 - Security Agent builder Limits UI**  
Depends on: `M7A-81`  
Deliverable: Add step/runtime/temporary-policy/AI-budget/concurrency limits.  
Verify: Server and client reject values above product maxima.  
Timebox: <=15 minutes.

**M7A-83 - Security Agent builder Verification UI**  
Depends on: `M7A-82`  
Deliverable: Add success-condition choices compatible with selected actions.  
Verify: Cannot enable definition with no terminal verification criterion.  
Timebox: <=15 minutes.

**M7A-84 - Security Agent builder Simulate UI**  
Depends on: `M7A-83,M7A-69`  
Deliverable: Show matched evidence, proposed plan and approval points without side effects.  
Verify: E2E simulator shows authorization result per proposed step.  
Timebox: <=15 minutes.

**M7A-85 - Security Agent detail UI**  
Depends on: `M7A-84`  
Deliverable: Show definition, allowed actions, limits, verification and recent runs.  
Verify: Model/provider internals are hidden outside audit metadata.  
Timebox: <=15 minutes.

**M7A-86 - Security Agent run plan UI**  
Depends on: `M7A-85`  
Deliverable: Show trigger/evidence, AI rationale summary and ordered plan with deterministic authorization labels.  
Verify: Rationale is visually distinct from authorization/evidence.  
Timebox: <=15 minutes.

**M7A-87 - Security Agent run action UI**  
Depends on: `M7A-86`  
Deliverable: Show each step state, redacted arguments, result, TTL/rollback and verification.  
Verify: Protected arguments never render.  
Timebox: <=15 minutes.

**M7A-88 - Security Agent Approvals list UI**  
Depends on: `M7A-87`  
Deliverable: Add Protect -> Approvals list with action, agent, target, expiry and requester/run context.  
Verify: Unauthorized approvals are absent.  
Timebox: <=15 minutes.

**M7A-89 - Security Agent Approval detail UI**  
Depends on: `M7A-88`  
Deliverable: Show reason, evidence, expected side effect, risk, reversibility/TTL and Approve/Deny/Cancel.  
Verify: Sensitive approval invokes fresh-auth flow before decision.  
Timebox: <=15 minutes.

**M7A-90 - Security Agent activity links**  
Depends on: `M7A-89`  
Deliverable: Link finding/path/session/audit records to Security Agent run and back.  
Verify: E2E navigation preserves scoped entity IDs.  
Timebox: <=15 minutes.

**M7A-90a - Home Security Agent attention summary**  
Depends on: `M7A-90`  
Deliverable: Extend `getHomeSummary` with pending approval count/oldest age, Needs-human/Failed/Inconclusive run counts and recent Contained/Remediated outcomes.  
Verify: Summary is Organization-scoped and stale/degraded source state is preserved.  
Timebox: <=15 minutes.

**M7A-90b - Home Needs-attention UI**  
Depends on: `M7A-90a`  
Deliverable: Add ordered Home cards for critical exposures, pending approvals, responder runs needing human attention, stale launch integrations/sensors and recent containment.  
Verify: Each card links to canonical list/detail route and empty never overrides degraded.  
Timebox: <=15 minutes.

**M7A-90c - approval-required webhook notification**  
Depends on: `M7A-90b,M3-48h`  
Deliverable: When configured, send one signed `security_agent.approval_required` event through the built-in Generic Webhook integration using approval ID/run context only.  
Verify: Duplicate approval creation produces one notification and no raw evidence/secret is included.  
Timebox: <=15 minutes.

**M7A-90d - Home daily-ops E2E**  
Depends on: `M7A-90c`  
Deliverable: Load one critical path, one pending approval, one Needs-human run and one stale sensor, then clear/route each through product actions.  
Verify: Home exposes every item and no critical item disappears without explicit terminal/assigned/degraded state.  
Timebox: <=15 minutes.

**M7A-91 - Planner unavailable degraded test**  
Depends on: `M7A-90d`  
Deliverable: Fail OpenRouter during new Security Agent run.  
Verify: Run records Planner unavailable and no action executes; existing runtime policy still enforces.  
Timebox: <=15 minutes.

**M7A-92 - Approval expiry degraded test**  
Depends on: `M7A-91`  
Deliverable: Expire a mandatory approval while run waits.  
Verify: Run becomes Needs human/Expired and never resumes automatically.  
Timebox: <=15 minutes.

**M7A-93 - Unknown external outcome test**  
Depends on: `M7A-92`  
Deliverable: Simulate timeout after side-effect request where outcome cannot be verified.  
Verify: Step becomes Inconclusive and is not blindly retried.  
Timebox: <=15 minutes.

**M7A-94 - Cross-tenant planner reference test**  
Depends on: `M7A-93`  
Deliverable: Seed planner output with another Organization's valid-looking asset UUID.  
Verify: Plan is rejected before authorization/execution.  
Timebox: <=15 minutes.

**M7A-95 - Security Agent action budget test**  
Depends on: `M7A-94`  
Deliverable: Exceed action/time/cost budget in fixture.  
Verify: No step starts after budget stop.  
Timebox: <=15 minutes.

**M7A-96 - Security Agent auto-response E2E**  
Depends on: `M7A-95`  
Deliverable: Trigger injection responder, auto-create temporary Block and re-test.  
Verify: Run ends Contained/Remediated only after policy evidence plus re-test verification.  
Timebox: <=15 minutes.

**M7A-97 - Security Agent approval E2E**  
Depends on: `M7A-96`  
Deliverable: Trigger credential responder with supported connection revoke requiring approval.  
Verify: No revoke before approval; approved run executes once and verifies connection state.  
Timebox: <=15 minutes.

**M7A-98 - Security Agent audit completeness E2E**  
Depends on: `M7A-97`  
Deliverable: Inspect one completed auto run and one approved run.  
Verify: Trigger, plan hash, evidence IDs, auth result, approval, execution, verification and terminal outcome are all auditable.  
Timebox: <=15 minutes.

**M7A-99 - Security Agent SaaS isolation E2E**  
Depends on: `M7A-98`  
Deliverable: Run two Organizations concurrently with same-looking agent/action names.  
Verify: Trigger, planner context, approvals, actions and results remain Organization-isolated.  
Timebox: <=15 minutes.

**M7A-100 - Security Agent single-tenant profile E2E**  
Depends on: `M7A-99`  
Deliverable: Execute the same responder flow in dedicated single-tenant profile.  
Verify: Same API/UI/action contracts pass without topology-specific product behavior.  
Timebox: <=15 minutes.

**M7A-101 - M7A gate**  
Depends on: `M7A-100`  
Deliverable: Write Security Agent MVP gate result covering automatic trigger, simulate, plan, authorize, auto-act, approval, execute, temporary-control expiry cleanup, verify, Home attention UX, audit, outage and tenant isolation.  
Verify: PASS only when all preceding Security Agent E2E/security/degraded checks pass.  
Timebox: <=15 minutes.

### M8 - SaaS and single-tenant enterprise release gate

**M8-01a - production overlay VPC review**  
Depends on: `M7A-101,M1A-10`  
Deliverable: Add release overlay settings to the existing M1A VPC module for production CIDRs, endpoints and availability-zone topology without creating a second module.  
Verify: Terraform plan remains private and reuses the M1A module.  
Timebox: <=15 minutes.

**M8-01b - production overlay EKS review**  
Depends on: `M8-01a`  
Deliverable: Add production replica, node-pool and private-endpoint settings to the existing M1A EKS module.  
Verify: Terraform plan reuses the same module and contains no public Kubernetes API exposure beyond approved configuration.  
Timebox: <=15 minutes.

**M8-01c - release Terraform root**  
Depends on: `M8-01b`  
Deliverable: Add the production/SaaS release values to the same Terraform root used by staging.  
Verify: `terraform validate` passes with staging and release tfvars and module addresses remain stable.  
Timebox: <=15 minutes.

**M8-01 - AWS production overlay gate**  
Depends on: `M8-01c`  
Deliverable: Run the release Terraform plan against the reusable M1A modules and record drift.  
Verify: No duplicate AWS foundation module or destructive unexpected replacement appears.  
Timebox: <=15 minutes.

**M8-02 - AWS S3/KMS/Secrets hardening**  
Depends on: `M8-01`  
Deliverable: Apply versioning, retention/lifecycle, encryption and least-privilege production settings to the existing M1A S3/KMS/Secrets resources.  
Verify: Terraform plan shows no public access and event archive/evidence prefixes use the intended KMS key.  
Timebox: <=15 minutes.

**M8-03 - AWS SQS/DLQ hardening**  
Depends on: `M8-02`  
Deliverable: Apply production visibility timeout, retention, DLQ and encryption settings to the existing M1A queues.  
Verify: Terraform plan preserves queue identities and has bounded redrive settings.  
Timebox: <=15 minutes.

**M8-04 - AWS OpenSearch hardening**  
Depends on: `M8-03`  
Deliverable: Apply production capacity, encryption, VPC-only access and snapshot/retention settings to the existing M1A OpenSearch module.  
Verify: Terraform plan has no public endpoint and uses the same EventStore endpoint contract.  
Timebox: <=15 minutes.

**M8-05 - AWS IRSA least-privilege hardening**  
Depends on: `M8-04`  
Deliverable: Tighten M1A service/connector IAM policies to production resource ARNs and document approved cross-account connector actions.  
Verify: Policy tests allow required calls and deny unrelated write actions.  
Timebox: <=15 minutes.

**M8-06 - Fargate profile**  
Depends on: `M8-05`  
Deliverable: Add dedicated Attack Lab Fargate profile, namespace selector and Pod execution role.  
Verify: Terraform/EKS plan selects only Attack Lab namespace/labels.  
Timebox: <=15 minutes.

**M8-07 - Attack Lab security group**  
Depends on: `M8-06`  
Deliverable: Add security group and SecurityGroupPolicy prerequisites for Fargate runs.  
Verify: Default run path reaches required cluster/proxy endpoints only.  
Timebox: <=15 minutes.

**M8-08a - Helm web deployment**  
Depends on: `M8-07`  
Deliverable: Add web Deployment and resource settings.  
Verify: Helm unit/render test sees production replicas and probes.  
Timebox: <=15 minutes.

**M8-08b - Helm API deployment**  
Depends on: `M8-08a`  
Deliverable: Add agentsec-api Deployment and resource settings.  
Verify: Helm unit/render test sees production replicas and probes.  
Timebox: <=15 minutes.

**M8-08c - Helm web/API services**  
Depends on: `M8-08b`  
Deliverable: Add product Services/ingress references and readiness wiring.  
Verify: Render exposes only product endpoints, no vendor UI.  
Timebox: <=15 minutes.

**M8-08 - Helm web/api**  
Depends on: `M8-08c`  
Deliverable: Run final Helm render for web/API manifests.  
Verify: Render exposes product endpoints and required probes only.  
Timebox: <=15 minutes.

**M8-09a - Helm worker deployment**  
Depends on: `M8-08`  
Deliverable: Add agentsec-worker Deployment with queue config.  
Verify: Render has resource requests/limits and no public Service.  
Timebox: <=15 minutes.

**M8-09b - Helm event-ingest deployment**  
Depends on: `M8-09a`  
Deliverable: Add event-ingest Deployment/Service with internal auth config.  
Verify: Render has internal Service and probes.  
Timebox: <=15 minutes.

**M8-09c - Worker/ingest shutdown settings**  
Depends on: `M8-09b`  
Deliverable: Add termination grace and pre-stop/drain configuration.  
Verify: Manifest test sees nonzero grace and drain setting.  
Timebox: <=15 minutes.

**M8-09 - Helm worker/ingest**  
Depends on: `M8-09c`  
Deliverable: Run final Helm render for worker/event-ingest manifests.  
Verify: Render shows correct internal connectivity and shutdown settings.  
Timebox: <=15 minutes.

**M8-10 - Helm runtime gateway**  
Depends on: `M8-09`  
Deliverable: Add runtime-gateway Deployment/Service and local policy volume/cache.  
Verify: Optional dependency loss does not change readiness template.  
Timebox: <=15 minutes.

**M8-11 - Helm Neo4j**  
Depends on: `M8-10`  
Deliverable: Add supported Neo4j reference values/persistence or external endpoint switch.  
Verify: Render chooses exactly one mode and product does not expose Neo4j ingress.  
Timebox: <=15 minutes.

**M8-12 - Helm Nango free**  
Depends on: `M8-11`  
Deliverable: Add Nango free self-hosted internal deployment with direct DB/encryption secret, Auth+Proxy only.  
Verify: No public ingress or Enterprise-only services appear in render.  
Timebox: <=15 minutes.

**M8-13 - Helm OTel Collector**  
Depends on: `M8-12`  
Deliverable: Add Collector memory limiter, batching, redaction and optional Grafana/New Relic OTLP overlays.  
Verify: `none` backend works and remote failure uses bounded sending queue.  
Timebox: <=15 minutes.

**M8-14 - Helm Tetragon**  
Depends on: `M8-13`  
Deliverable: Add Tetragon deployment/permissions and exact privilege documentation.  
Verify: Render permissions match documented requirement and sensor can be disabled for unsupported nodes.  
Timebox: <=15 minutes.

**M8-15 - Pod disruption/topology**  
Depends on: `M8-14`  
Deliverable: Add PDB/topology-spread/graceful termination for critical stateless services.  
Verify: Render test sees expected policies without impossible one-replica PDB.  
Timebox: <=15 minutes.

**M8-16 - preflight base**  
Depends on: `M8-15`  
Deliverable: Create `agentsecctl preflight` command and result model.  
Verify: Command returns product pass/warn/fail sections and nonzero on blockers.  
Timebox: <=15 minutes.

**M8-17a - preflight IAM IRSA**  
Depends on: `M8-16`  
Deliverable: Check required IAM roles, trust and IRSA bindings.  
Verify: Missing trust permission returns the exact product remediation hint.  
Timebox: <=15 minutes.

**M8-17b - preflight S3 KMS Secrets**  
Depends on: `M8-17a`  
Deliverable: Check S3 evidence bucket, KMS key and Secrets Manager access.  
Verify: Denied fixture identifies the failing AWS permission.  
Timebox: <=15 minutes.

**M8-17c - preflight SQS**  
Depends on: `M8-17b`  
Deliverable: Check required SQS queues/DLQs and producer/consumer permissions.  
Verify: Missing queue or permission is reported before install.  
Timebox: <=15 minutes.

**M8-17d - preflight OpenSearch**  
Depends on: `M8-17c`  
Deliverable: Check OpenSearch endpoint reachability and required index permissions.  
Verify: Denied fixture reports an actionable product error.  
Timebox: <=15 minutes.

**M8-17e - preflight EKS Fargate**  
Depends on: `M8-17d`  
Deliverable: Check EKS version, Attack Lab Fargate profile/namespace and required networking prerequisites.  
Verify: Missing Fargate prerequisite blocks Attack Lab readiness only.  
Timebox: <=15 minutes.

**M8-17 - preflight AWS**  
Depends on: `M8-17e`  
Deliverable: Assemble AWS preflight results into one product readiness report.  
Verify: Report separates blocking core prerequisites from optional/feature-specific prerequisites.  
Timebox: <=15 minutes.

**M8-18 - preflight Neon/Stytch**  
Depends on: `M8-17`  
Deliverable: Check Neon migration/pool connectivity and Stytch project/session reachability.  
Verify: Dependency failure is clearly labeled required.  
Timebox: <=15 minutes.

**M8-19 - preflight sensor**  
Depends on: `M8-18`  
Deliverable: Check kernel/BTF/Tetragon prerequisites on selected EC2 node pool.  
Verify: Unsupported kernel returns warning/block based on selected sensor mode.  
Timebox: <=15 minutes.

**M8-20a - backup manifest schema**  
Depends on: `M8-19`  
Deliverable: Define versioned recovery manifest fields for Neon recovery point, S3 evidence/event-archive references and graph rebuild/export reference for SaaS or single-tenant rehearsal.  
Verify: Schema rejects raw credential fields.  
Timebox: <=15 minutes.

**M8-20b - backup metadata collection**  
Depends on: `M8-20a`  
Deliverable: Collect Neon recovery metadata, deployment mode and product configuration references into the manifest.  
Verify: Fixture manifest is scoped to its authenticated/deployment Organization.  
Timebox: <=15 minutes.

**M8-20c - backup graph and evidence refs**  
Depends on: `M8-20b`  
Deliverable: Add graph export reference and S3 evidence location references to the manifest.  
Verify: Manifest contains references only, not copied secret-bearing payloads.  
Timebox: <=15 minutes.

**M8-20 - backup plan**  
Depends on: `M8-20c`  
Deliverable: Expose `agentsecctl backup` to write the completed manifest.  
Verify: Command writes a scoped, versioned manifest and exits nonzero on missing required reference.  
Timebox: <=15 minutes.

**M8-21a - Restore manifest reader**  
Depends on: `M8-20`  
Deliverable: Implement restore-manifest validation and target-environment safety check.  
Verify: Restore refuses production/source target and malformed manifest.  
Timebox: <=15 minutes.

**M8-21b - Start restore rehearsal**  
Depends on: `M8-21a`  
Deliverable: Start restore into disposable target using the current supported recovery mechanisms.  
Verify: Command/job returns a tracked rehearsal ID before 15-minute timebox.  
Timebox: <=15 minutes.

**M8-21c - Inspect restore completion**  
Depends on: `M8-21b`  
Deliverable: Poll the tracked rehearsal and record terminal state.  
Verify: Terminal state and dependency errors are captured without restarting restore.  
Timebox: <=15 minutes.

**M8-21d - Validate restored state**  
Depends on: `M8-21c`  
Deliverable: Compare scoped asset/finding/policy counts and sample evidence references.  
Verify: Validator reports exact mismatches.  
Timebox: <=15 minutes.

**M8-21e - Clean restore target**  
Depends on: `M8-21d`  
Deliverable: Delete disposable restore target/resources after validation.  
Verify: Cleanup leaves no test customer data/resources.  
Timebox: <=15 minutes.

**M8-21 - restore rehearsal**  
Depends on: `M8-21e`  
Deliverable: Record restore rehearsal result and any exact recovery gap.  
Verify: Release evidence links start/completion/validation/cleanup artifacts.  
Timebox: <=15 minutes.

**M8-22a - upgrade version check**  
Depends on: `M8-21`  
Deliverable: Check current and target product version compatibility before upgrade.  
Verify: Unsupported version jump is rejected before mutation.  
Timebox: <=15 minutes.

**M8-22b - upgrade migration check**  
Depends on: `M8-22a`  
Deliverable: Check Neon schema migration compatibility before upgrade.  
Verify: Incompatible migration fixture blocks upgrade.  
Timebox: <=15 minutes.

**M8-22c - upgrade bundle check**  
Depends on: `M8-22b`  
Deliverable: Check policy/content bundle format compatibility before upgrade.  
Verify: Unsupported bundle format blocks upgrade.  
Timebox: <=15 minutes.

**M8-22d - upgrade rollback check**  
Depends on: `M8-22c`  
Deliverable: Check that required rollback artifact and backup/recovery reference exist.  
Verify: Missing rollback prerequisite blocks upgrade.  
Timebox: <=15 minutes.

**M8-22 - upgrade preflight**  
Depends on: `M8-22d`  
Deliverable: Assemble upgrade checks into one read-only preflight command.  
Verify: Incompatible fixture blocks upgrade before any mutation.  
Timebox: <=15 minutes.

**M8-23a - Start upgrade fixture**  
Depends on: `M8-22`  
Deliverable: Deploy previous-supported-version fixture into disposable environment.  
Verify: Fixture reports ready version before timebox ends.  
Timebox: <=15 minutes.

**M8-23b - Run upgrade**  
Depends on: `M8-23a`  
Deliverable: Start current-version upgrade and record migration/release IDs.  
Verify: Upgrade reaches success or tracked failure state.  
Timebox: <=15 minutes.

**M8-23c - Inject rollback condition**  
Depends on: `M8-23b`  
Deliverable: Trigger the documented rollback path in disposable fixture.  
Verify: Rollback command targets the recorded release/version only.  
Timebox: <=15 minutes.

**M8-23d - Validate rollback state**  
Depends on: `M8-23c`  
Deliverable: Compare product version, schema compatibility and sampled policy/evidence state.  
Verify: Validator reports no silent data loss.  
Timebox: <=15 minutes.

**M8-23 - upgrade rollback test**  
Depends on: `M8-23d`  
Deliverable: Record upgrade/rollback rehearsal result.  
Verify: Release evidence links upgrade, rollback and state-validation artifacts.  
Timebox: <=15 minutes.

**M8-24 - diagnostics bundle**  
Depends on: `M8-23`  
Deliverable: Create redacted `agentsecctl diagnostics` bundle with health/config versions and bounded logs.  
Verify: Seeded secrets/vendor tokens are absent.  
Timebox: <=15 minutes.

**M8-25 - real AWS parity IAM**  
Depends on: `M8-24`  
Deliverable: Run bounded IAM/STS/IRSA parity tests in isolated AWS account.  
Verify: Results match intended deny/allow semantics, independent of LocalStack.  
Timebox: <=15 minutes.

**M8-26 - real AWS parity storage**  
Depends on: `M8-25`  
Deliverable: Run S3/KMS/Secrets/SQS/OpenSearch parity smoke in isolated AWS account.  
Verify: Critical operations match LocalStack-backed expectations.  
Timebox: <=15 minutes.

**M8-27 - real AWS Fargate parity**  
Depends on: `M8-26`  
Deliverable: Run Attack Lab Fargate/SG/proxy canary in isolated AWS account.  
Verify: Direct egress denied, proxy-allowed destination succeeds, run cleans up.  
Timebox: <=15 minutes.

**M8-28 - Stytch outage test**  
Depends on: `M8-27`  
Deliverable: Inject Stytch API failure after valid session/policy deployment.  
Verify: New login degrades; runtime enforcement remains active; JWT is not extended beyond normal validity.  
Timebox: <=15 minutes.

**M8-29 - Neon outage test**  
Depends on: `M8-28`  
Deliverable: Inject Neon failure during control-plane mutation and runtime traffic.  
Verify: Mutation fails fast; runtime gateway continues from cached bundle.  
Timebox: <=15 minutes.

**M8-30 - Nango outage test**  
Depends on: `M8-29`  
Deliverable: Stop Nango during long-tail connection usage.  
Verify: Core launch connectors, inventory, paths and runtime policy continue.  
Timebox: <=15 minutes.

**M8-31 - optional vendor outage test**  
Depends on: `M8-30`  
Deliverable: Fail PostHog, OpenRouter and remote OTLP concurrently.  
Verify: Golden deterministic security flow still passes except optional UX.  
Timebox: <=15 minutes.

**M8-32 - OpenSearch outage test**  
Depends on: `M8-31`  
Deliverable: Fail OpenSearch while event batches arrive.  
Verify: Search degrades, SQS backlog is visible and runtime policy continues.  
Timebox: <=15 minutes.

**M8-33 - Neo4j outage test**  
Depends on: `M8-32`  
Deliverable: Fail graph backend during inventory reads.  
Verify: Path/capability shows Degraded and basic inventory remains.  
Timebox: <=15 minutes.

**M8-34 - SQS saturation test**  
Depends on: `M8-33`  
Deliverable: Throttle SQS/event worker and observe backlog/drop behavior.  
Verify: No unbounded process memory growth and queue age is visible.  
Timebox: <=15 minutes.

**M8-35 - runtime latency test**  
Depends on: `M8-34`  
Deliverable: Run metadata policy benchmark at reference concurrency.  
Verify: p95 <=25 ms or release gate fails with measured exception.  
Timebox: <=15 minutes.

**M8-36a - API load scenario**  
Depends on: `M8-35`  
Deliverable: Define bounded representative API workload and success thresholds.  
Verify: Scenario lints and contains no unbounded endpoint/query.  
Timebox: <=15 minutes.

**M8-36b - Run API load**  
Depends on: `M8-36a`  
Deliverable: Run the bounded workload for <=5 minutes on reference deployment.  
Verify: Run produces latency/error artifact.  
Timebox: <=15 minutes.

**M8-36c - Evaluate API load**  
Depends on: `M8-36b`  
Deliverable: Calculate p50/p95/p99/error rate from artifact.  
Verify: Gate result is deterministic and linked to reference profile.  
Timebox: <=15 minutes.

**M8-36 - API reference load**  
Depends on: `M8-36c`  
Deliverable: Record API reference-load gate result.  
Verify: Measured p95 comparison is stored in release evidence.  
Timebox: <=15 minutes.

**M8-37 - graph bounded load**  
Depends on: `M8-36`  
Deliverable: Run bounded path/neighborhood fixtures at reference graph size.  
Verify: Supported query returns <=3 s and depth/result limits hold.  
Timebox: <=15 minutes.

**M8-38a - Event load generator**  
Depends on: `M8-37`  
Deliverable: Create relevant normalized-event batch generator and bounded run config.  
Verify: Generator produces scoped batches at requested rate.  
Timebox: <=15 minutes.

**M8-38b - Run event floor load**  
Depends on: `M8-38a`  
Deliverable: Run 5k relevant events/sec for <=5 minutes.  
Verify: Run produces queue/index/drop metrics artifact.  
Timebox: <=15 minutes.

**M8-38c - Evaluate event floor load**  
Depends on: `M8-38b`  
Deliverable: Check backlog recovery, indexing and observed drops/retries.  
Verify: Gate reports pass/fail with exact measured values.  
Timebox: <=15 minutes.

**M8-38 - event floor load**  
Depends on: `M8-38c`  
Deliverable: Record event-floor gate result.  
Verify: Measured rate/backlog/drop result is stored in release evidence.  
Timebox: <=15 minutes.

**M8-39 - sensor overhead measurement**  
Depends on: `M8-38`  
Deliverable: Measure Tetragon/product adapter CPU/memory on representative workload.  
Verify: Result is documented without universal unsupported percentage claim.  
Timebox: <=15 minutes.

**M8-40a - API tenant isolation security test**  
Depends on: `M8-39`  
Deliverable: Attempt cross-Organization and cross-Workspace REST API reads and mutations.  
Verify: Every request fails server-side with the stable tenant-boundary error and no foreign data.  
Timebox: <=15 minutes.

**M8-40b - graph tenant isolation security test**  
Depends on: `M8-40a`  
Deliverable: Attempt a bounded graph read/path query from Organization A against Organization B fixture nodes.  
Verify: Query returns no cross-Organization node or edge and records the denial/guard result.  
Timebox: <=15 minutes.

**M8-40c - OpenSearch tenant isolation security test**  
Depends on: `M8-40b`  
Deliverable: Attempt Organization A session/activity searches against Organization B indexed fixtures.  
Verify: Search returns no foreign hit and the test records the scoped filter used.  
Timebox: <=15 minutes.

**M8-40d - S3 tenant isolation security test**  
Depends on: `M8-40c`  
Deliverable: Attempt Organization A evidence/export access against Organization B object keys through product APIs.  
Verify: Access is denied and no presigned URL/object body for Organization B is returned.  
Timebox: <=15 minutes.

**M8-40 - Organization/Workspace isolation security result**  
Depends on: `M8-40d`  
Deliverable: Record the API, graph, OpenSearch and S3 tenant-isolation results in one release-evidence record.  
Verify: Release evidence names every tested boundary and all four results are passing.  
Timebox: <=15 minutes.

**M8-41 - connector SSRF security test**  
Depends on: `M8-40`  
Deliverable: Attempt Nango/proxy/provider URL override to arbitrary destination.  
Verify: Request is blocked and audited.  
Timebox: <=15 minutes.

**M8-42a - log secret leakage test**  
Depends on: `M8-41`  
Deliverable: Seed a known secret through representative request/error paths and inspect structured logs.  
Verify: Seeded value never appears in logs.  
Timebox: <=15 minutes.

**M8-42b - PostHog secret leakage test**  
Depends on: `M8-42a`  
Deliverable: Attempt to serialize seeded secret and sensitive security fields to PostHog.  
Verify: Serializer rejects the event before egress.  
Timebox: <=15 minutes.

**M8-42c - AI secret leakage test**  
Depends on: `M8-42b`  
Deliverable: Send seeded secret/PII/PHI fixture through AI redaction pipeline to fake provider.  
Verify: Prohibited fixture values are absent at the provider endpoint.  
Timebox: <=15 minutes.

**M8-42d - OTLP secret leakage test**  
Depends on: `M8-42c`  
Deliverable: Emit seeded sensitive attributes through application telemetry to local Collector.  
Verify: Redaction/filter pipeline removes prohibited values before exporter.  
Timebox: <=15 minutes.

**M8-42e - support bundle leakage test**  
Depends on: `M8-42d`  
Deliverable: Generate support bundle from fixture cluster containing seeded secret.  
Verify: Bundle contains no seeded value.  
Timebox: <=15 minutes.

**M8-42f - evidence leakage policy test**  
Depends on: `M8-42e`  
Deliverable: Store fixture evidence under metadata-only collection mode.  
Verify: Raw seeded content is not durably stored.  
Timebox: <=15 minutes.

**M8-42 - secret leakage security test**  
Depends on: `M8-42f`  
Deliverable: Write the secret-leakage gate result from all egress/storage checks.  
Verify: Gate record is PASS only when every sink is clean.  
Timebox: <=15 minutes.

**M8-43 - runtime policy bypass test**  
Depends on: `M8-42`  
Deliverable: Fuzz malformed HTTP/MCP action context and replay signed decision inputs.  
Verify: Gateway fails safely and cannot bypass Block policy.  
Timebox: <=15 minutes.

**M8-44 - Attack Lab safety test**  
Depends on: `M8-43`  
Deliverable: Attempt production-write credential, host mount and undeclared egress.  
Verify: All are rejected before or during run and verdict never becomes Verified.  
Timebox: <=15 minutes.

**M8-45 - SBOM generation**  
Depends on: `M8-44`  
Deliverable: Generate SPDX/CycloneDX SBOM for every shipped image.  
Verify: Release artifacts contain SBOM with pinned OSS versions.  
Timebox: <=15 minutes.

**M8-46 - image signing**  
Depends on: `M8-45`  
Deliverable: Sign release images and verify signatures in install path/policy.  
Verify: Tampered/unsigned fixture fails verification where enforced.  
Timebox: <=15 minutes.

**M8-47 - dependency vulnerability gate**  
Depends on: `M8-46`  
Deliverable: Run dependency/image scanner and define severity/exception policy.  
Verify: Unaccepted critical vulnerability blocks release.  
Timebox: <=15 minutes.

**M8-48 - license/subprocessor inventory**  
Depends on: `M8-47`  
Deliverable: Generate reviewed OSS license and managed-subprocessor inventory.  
Verify: Nango/Neo4j/Stytch/Neon/PostHog/OpenRouter/OTLP entries have owner/status.  
Timebox: <=15 minutes.

**M8-49 - HIPAA profile test**  
Depends on: `M8-48`  
Deliverable: Apply regulated defaults and run data-egress assertions.  
Verify: PostHog/OpenRouter/remote OTLP/raw content remain off until explicit approved config.  
Timebox: <=15 minutes.

**M8-50 - SOC2 evidence checklist**  
Depends on: `M8-49`  
Deliverable: Map release/access/change/backup/incident/vendor evidence owners for company control program.  
Verify: Checklist has owner, evidence location and cadence, no Type II completion claim.  
Timebox: <=15 minutes.

**M8-51a - Golden stage deploy/discover**  
Depends on: `M8-50`  
Deliverable: Execute install/preflight/connect/sensor/discover stage on release candidate.  
Verify: Stage artifact records successful Agent inventory and source freshness.  
Timebox: <=15 minutes.

**M8-51b - Golden stage exposure/test**  
Depends on: `M8-51a`  
Deliverable: Open credible path and run curated staging Red Team case.  
Verify: Stage artifact records successful high-impact attempt/evidence.  
Timebox: <=15 minutes.

**M8-51c - Golden stage Attack Lab**  
Depends on: `M8-51b`  
Deliverable: Run Fargate verification with canary/test resources.  
Verify: Stage artifact records Verified or a release-blocking failure.  
Timebox: <=15 minutes.

**M8-51d - Golden stage policy/retest**  
Depends on: `M8-51c`  
Deliverable: Create, simulate, enforce Block and re-run the supported test.  
Verify: Stage artifact records observed Blocked decision.  
Timebox: <=15 minutes.

**M8-51e - Golden stage investigate/audit**  
Depends on: `M8-51d`  
Deliverable: Open resulting Session and Audit/Compliance evidence.  
Verify: Stage artifact links session timeline and audit records.  
Timebox: <=15 minutes.

**M8-51 - golden E2E**  
Depends on: `M8-51e`  
Deliverable: Assemble golden-flow stage artifacts into one release gate record.  
Verify: Every golden stage is linked; no stage is rerun inside this task.  
Timebox: <=15 minutes.

**M8-52a - Usability fresh-install setup**  
Depends on: `M8-51`  
Deliverable: Prepare a clean documented reference install target and observer checklist.  
Verify: Target is ready without undocumented bootstrap step.  
Timebox: <=15 minutes.

**M8-52b - Usability install observation**  
Depends on: `M8-52a`  
Deliverable: Have a platform engineer run only documented install/preflight steps for <=15 minutes.  
Verify: Observer records blockers and exact product messages.  
Timebox: <=15 minutes.

**M8-52c - Usability failure diagnosis**  
Depends on: `M8-52b`  
Deliverable: Inject one documented dependency/config failure and have engineer use System Health/preflight.  
Verify: Engineer identifies product action without vendor dashboard.  
Timebox: <=15 minutes.

**M8-52d - Usability diagnostics observation**  
Depends on: `M8-52c`  
Deliverable: Have engineer generate diagnostics bundle and follow remediation guidance.  
Verify: Bundle is produced/redacted and next action is understandable.  
Timebox: <=15 minutes.

**M8-52 - single-tenant install usability test**  
Depends on: `M8-52d`  
Deliverable: Record single-tenant install-usability findings and classify release blockers.  
Verify: Every blocker has product-owned remediation or is explicitly release-blocking.  
Timebox: <=15 minutes.

**M8-53 - design-partner value gate**  
Depends on: `M8-52`  
Deliverable: Record whether at least two design partners changed prioritization/remediation because of verified path/runtime evidence.  
Verify: Gate is explicitly pass/fail and blocks scope expansion if value is unproven.  
Timebox: <=15 minutes.

**M8-55 - SaaS values profile**  
Depends on: `M8-15`  
Deliverable: Add a SaaS deployment values profile that enables multi-tenant mode and excludes customer-only recovery assumptions.  
Verify: Helm render sets deployment mode `saas` and contains no pinned customer Organization.  
Timebox: <=15 minutes.

**M8-56 - single-tenant values profile**  
Depends on: `M8-55`  
Deliverable: Add a single-tenant deployment values profile using the same images with a pinned Organization configuration.  
Verify: Helm render differs only in topology/configuration values, not application image or API surface.  
Timebox: <=15 minutes.

**M8-57a - customer edge sensor values**  
Depends on: `M8-14`  
Deliverable: Add the edge-profile Tetragon sensor values and product event-ingest destination settings.  
Verify: Helm render contains the sensor/adapter resources and no SaaS control-plane workloads.  
Timebox: <=15 minutes.

**M8-57b - customer edge runtime gateway values**  
Depends on: `M8-57a`  
Deliverable: Add the edge-profile runtime gateway, local policy cache and SaaS API destination settings.  
Verify: Helm render contains runtime gateway/policy-cache resources with no Neon or graph dependency.  
Timebox: <=15 minutes.

**M8-57c - customer edge enrollment values**  
Depends on: `M8-57b`  
Deliverable: Add scoped enrollment-token secret references and Organization/Workspace/Environment configuration to the edge profile.  
Verify: Render requires scoped enrollment configuration and does not embed a plaintext token.  
Timebox: <=15 minutes.

**M8-57 - customer edge Helm profile**  
Depends on: `M8-57c`  
Deliverable: Compose the sensor, runtime-gateway and enrollment values into the supported lightweight edge profile.  
Verify: Render contains no Neon, Stytch, Nango, graph or web/API control-plane dependency.  
Timebox: <=15 minutes.

**M8-58a - SaaS quota load fixture**  
Depends on: `M1-43, M8-38`  
Deliverable: Create a two-Organization bounded load fixture with one Organization intentionally over quota.  
Verify: Fixture configuration validates and contains no customer secrets.  
Timebox: <=15 minutes.

**M8-58b - SaaS quota load trigger**  
Depends on: `M8-58a`  
Deliverable: Start the bounded quota load job in CI/reference SaaS environment and record the run ID.  
Verify: Job starts successfully; this task does not wait for completion.  
Timebox: <=15 minutes.

**M8-58 - SaaS Organization quota result**  
Depends on: `M8-58b`  
Deliverable: Inspect the completed quota-load result for the recorded run.  
Verify: Noisy Organization is bounded while the second Organization remains within the stated reference latency target.  
Timebox: <=15 minutes.

**M8-59a1 - SaaS isolation API/Neon fixture references**  
Depends on: `M8-40, M2-50, M1-45`  
Deliverable: Add the existing API and direct-Neon cross-Organization checks to the release isolation suite manifest.  
Verify: Manifest resolves both checks for two isolated Organization fixtures.  
Timebox: <=15 minutes.

**M8-59a2 - SaaS isolation graph/search fixture references**  
Depends on: `M8-59a1`  
Deliverable: Add the existing graph and OpenSearch cross-Organization checks to the release isolation suite manifest.  
Verify: Manifest resolves both checks and their expected denial/no-hit outcomes.  
Timebox: <=15 minutes.

**M8-59a3 - SaaS isolation S3/queue fixture references**  
Depends on: `M8-59a2, M1-41`  
Deliverable: Add S3 evidence/export and scoped SQS job-envelope cross-Organization checks to the release isolation suite manifest.  
Verify: Manifest resolves both checks and expected denial/rejection outcomes.  
Timebox: <=15 minutes.

**M8-59a - SaaS tenant isolation release fixture**  
Depends on: `M8-59a3`  
Deliverable: Validate the complete bounded SaaS tenant-isolation release-suite manifest.  
Verify: Manifest contains API, Neon, graph, OpenSearch, S3 and queue boundaries for two Organizations with no missing expected outcome.  
Timebox: <=15 minutes.

**M8-59b - SaaS tenant isolation trigger**  
Depends on: `M8-59a`  
Deliverable: Start the release isolation suite and record the run ID.  
Verify: Suite starts in the intended SaaS test environment; this task does not wait for completion.  
Timebox: <=15 minutes.

**M8-59 - SaaS tenant isolation result**  
Depends on: `M8-59b`  
Deliverable: Inspect the completed isolation-suite result.  
Verify: All cross-Organization reads/writes fail and no fixture evidence leaks into responses or exports.  
Timebox: <=15 minutes.

**M8-60a - SaaS golden fixture**  
Depends on: `M8-50, M8-55, M8-57, M8-59`  
Deliverable: Prepare the Organization-scoped SaaS golden-flow fixture and test identities/resources.  
Verify: Fixture contains no production write credential and all expected resources have cleanup ownership.  
Timebox: <=15 minutes.

**M8-60b - SaaS golden trigger**  
Depends on: `M8-60a`  
Deliverable: Start the SaaS golden E2E run and record the run ID.  
Verify: The run reaches the first connection stage; this task does not wait for completion.  
Timebox: <=15 minutes.

**M8-60 - SaaS golden result**  
Depends on: `M8-60b`  
Deliverable: Inspect the completed SaaS golden E2E result.  
Verify: First-Admin bootstrap -> corporate SSO -> launch connectors -> optional edge sensor -> discover -> path -> test -> verify -> Security Agent plan -> deterministic authorization -> auto-action or approval -> verified containment -> TTL cleanup when applicable -> re-test -> session/audit completes using only product UI/API.  
Timebox: <=15 minutes.

**M8-61a - single-tenant golden trigger**  
Depends on: `M8-56, M8-60`  
Deliverable: Start the same golden customer workflow against the single-tenant profile and record the run ID.  
Verify: Run starts with the same client/API contract and a pinned Organization.  
Timebox: <=15 minutes.

**M8-61 - single-tenant golden result**  
Depends on: `M8-61a`  
Deliverable: Inspect the completed single-tenant golden result.  
Verify: Workflow behavior and API shapes match SaaS except deployment/system-health metadata.  
Timebox: <=15 minutes.

**M8-62a - SaaS first-Admin bootstrap usability**  
Depends on: `M8-60`  
Deliverable: Observe a fresh designated first Admin complete invite sign-in, default scope bootstrap and reach Identity & Access using only product instructions for <=15 minutes.  
Verify: No local-password/bypass login or AgentSec manual database edit is required.  
Timebox: <=15 minutes.

**M8-62b - SaaS AWS setup usability**  
Depends on: `M8-62a`  
Deliverable: Observe the Admin complete AWS Review access -> Configure -> Test connection using product guidance.  
Verify: Missing-permission fixture yields an actionable product remediation.  
Timebox: <=15 minutes.

**M8-62c - SaaS Kubernetes setup usability**  
Depends on: `M8-62b`  
Deliverable: Observe sensor enrollment/Helm setup through first healthy heartbeat.  
Verify: User can distinguish inventory, sensor and gateway coverage without OSS console access.  
Timebox: <=15 minutes.

**M8-62d - SaaS GitHub setup usability**  
Depends on: `M8-62c`  
Deliverable: Observe GitHub authorization/install and initial scope validation.  
Verify: User can identify selected Organization/repository scope and any missing permission.  
Timebox: <=15 minutes.

**M8-62e - SaaS launch-IdP setup usability**  
Depends on: `M8-62d`  
Deliverable: Observe launch-IdP directory security integration setup, separate from AgentSec SSO configuration.  
Verify: User understands the distinction and reaches initial sync without vendor dashboard knowledge.  
Timebox: <=15 minutes.

**M8-62 - SaaS onboarding usability result**  
Depends on: `M8-62e`  
Deliverable: Record bootstrap and four launch-connector usability blockers.  
Verify: Every blocker has product-owned remediation or is explicitly release-blocking.  
Timebox: <=15 minutes.

**M8-63a - SaaS DR recovery fixture**  
Depends on: `M8-62,M8-20`  
Deliverable: Prepare an isolated SaaS recovery fixture with known Neon state, retained S3 evidence/event archives and derived OpenSearch/graph state.  
Verify: Fixture records source timestamps and contains at least two Organization scopes without production credentials.  
Timebox: <=15 minutes.

**M8-63b - SaaS DR start recovery**  
Depends on: `M8-63a`  
Deliverable: Start recovery into disposable infrastructure from the selected Neon recovery point plus versioned Terraform/Helm release.  
Verify: Recovery run ID and source recovery timestamp are recorded without waiting for completion.  
Timebox: <=15 minutes.

**M8-63c - SaaS DR inspect core recovery**  
Depends on: `M8-63b`  
Deliverable: Inspect recovered Organization/Workspace/policy/finding state and S3 evidence/event archives.  
Verify: Expected scoped records are present and no cross-Organization data mix occurs.  
Timebox: <=15 minutes.

**M8-63d - SaaS DR rebuild derived stores**  
Depends on: `M8-63c`  
Deliverable: Start bounded OpenSearch replay from retained S3 normalized event archives and graph rebuild from canonical inventory/evidence.  
Verify: Rebuild jobs are tracked and do not require raw vendor dashboards.  
Timebox: <=15 minutes.

**M8-63e - SaaS DR measure objectives**  
Depends on: `M8-63d`  
Deliverable: Record measured data recovery point and time until core product plus representative session/path queries are usable.  
Verify: Result explicitly compares measured RPO/RTO to <=1 hour / <=4 hour MVP objectives.  
Timebox: <=15 minutes.

**M8-63 - SaaS DR gate**  
Depends on: `M8-63e`  
Deliverable: Record SaaS disaster-recovery PASS/FAIL and exact gaps; clean disposable recovery resources after evidence capture.  
Verify: PASS requires measured objectives, tenant isolation and usable product UI/API without hidden vendor-console recovery steps.  
Timebox: <=15 minutes.

**M8-54 - M8 release gate**  
Depends on: `M8-53, M8-58, M8-59, M8-60, M8-61, M8-62, M8-63`  
Deliverable: Create release-readiness record containing results/exceptions from all M8 gates.  
Verify: No unresolved blocker is hidden as a documentation note.  
Timebox: <=15 minutes.

**Total microtasks:** 728.

## 17. Definition of done for any UI feature

1. OpenAPI operation exists and lints.
2. Generated client exposes it.
3. Server authorization is tested.
4. Store/engine behavior is independently tested.
5. UI uses generated client only.
6. Loading, empty, stale, degraded and error states are represented.
7. Security-relevant mutations emit audit.
8. `ui-api-map.yaml` maps the interaction.
9. Golden-flow participation has an E2E assertion.

## 18. Definition of done for any external or OSS adapter

1. Product-owned interface exists.
2. Exact version/license is pinned.
3. Contract fixture covers supported input/output.
4. Timeout/retry/degraded behavior is explicit.
5. Upstream dashboard/error model is not customer UX.
6. Secrets/vendor IDs are normalized according to policy.
7. Upgrade test detects a breaking upstream change.

## 19. Product-flow technical trace

**Deploy and first value**  
Technical path: first-Admin Stytch bootstrap -> corporate SSO/SCIM -> Connections provider setup/test -> optional customer edge sensor/gateway -> scoped SQS jobs -> adapters/Tetragon -> S3 event archive + scoped Neon/graph/OpenSearch -> Home/Agent UI  
Milestones: M1, M1A, M2-M4, M8.

**Blast radius**  
Technical path: Agent API -> GraphStore -> capability engine -> attack path -> Finding/Path UI  
Milestones: M4.

**Red Team**  
Technical path: Test API -> SQS tests -> Promptfoo -> S3 evidence + Neon summary -> TestRun UI  
Milestones: M5.

**Attack Lab**  
Technical path: AttackLab API -> preflight -> Fargate provider -> egress proxy/evidence -> verdict -> path/capability state  
Milestones: M5.

**Protect and re-test**  
Technical path: Policy API -> OpenSearch simulation -> signed S3 bundle -> runtime gateway embedded OPA -> decision event -> re-test -> Blocked evidence  
Milestones: M6.

**Agentic Act & Enforce**  
Technical path: finding/path/runtime state change -> trigger dispatcher/dedupe -> evidence snapshot -> OpenRouter AIGateway structured plan -> plan/schema/scope validation -> deterministic ActionAuthorizer -> action registry -> optional fresh-auth approval -> idempotent execution -> verifier/re-test -> temporary-control expiry cleanup -> Home attention + SecurityAgentRun/audit links  
Milestones: M7A.

**Investigate**  
Technical path: Session projection -> OpenSearch events -> Session API -> timeline UI  
Milestones: M7.

**Compliance**  
Technical path: Audit/finding/policy/test/data-control evidence -> Compliance API -> S3 export -> Evidence UI  
Milestones: M7-M8.

**Enterprise identity**  
Technical path: Stytch SSO/SCIM -> webhook -> Neon principal/grant -> auth middleware -> admin UI -> audit  
Milestones: M2.

## 20. Public API implementation coverage

- `getHomeSummary` - `GET /api/v1/home/summary` - implementation: **M4-47**
- `globalSearch` - `GET /api/v1/search` - implementation: **M4-49**
- `getOrganization` - `GET /api/v1/organization` - implementation: **M2-08**
- `listWorkspaces` - `GET /api/v1/workspaces` - implementation: **M2-09**
- `createWorkspace` - `POST /api/v1/workspaces` - implementation: **M2-10**
- `getWorkspace` - `GET /api/v1/workspaces/{id}` - implementation: **M2-11**
- `updateWorkspace` - `PATCH /api/v1/workspaces/{id}` - implementation: **M2-12**
- `listEnvironments` - `GET /api/v1/environments` - implementation: **M2-13**
- `createEnvironment` - `POST /api/v1/environments` - implementation: **M2-14**
- `getEnvironment` - `GET /api/v1/environments/{id}` - implementation: **M2-15**
- `updateEnvironment` - `PATCH /api/v1/environments/{id}` - implementation: **M2-16**
- `getCurrentPrincipal` - `GET /api/v1/me` - implementation: **M2-17**
- `listMembers` - `GET /api/v1/admin/members` - implementation: **M2-18**
- `listBuiltInRoles` - `GET /api/v1/admin/roles` - implementation: **M2-19**
- `listSSOConnections` - `GET /api/v1/admin/sso-connections` - implementation: **M2-21**
- `createSSOConnection` - `POST /api/v1/admin/sso-connections` - implementation: **M2-22**
- `deleteSSOConnection` - `DELETE /api/v1/admin/sso-connections/{id}` - implementation: **M2-23**
- `testSSOConnection` - `POST /api/v1/admin/sso-connections/{id}/test` - implementation: **M2-24**
- `listSCIMConnections` - `GET /api/v1/admin/scim-connections` - implementation: **M2-26**
- `createSCIMConnection` - `POST /api/v1/admin/scim-connections` - implementation: **M2-27**
- `deleteSCIMConnection` - `DELETE /api/v1/admin/scim-connections/{id}` - implementation: **M2-28**
- `listGroupMappings` - `GET /api/v1/admin/group-mappings` - implementation: **M2-32**
- `updateGroupMappings` - `PATCH /api/v1/admin/group-mappings` - implementation: **M2-33**
- `listAPITokens` - `GET /api/v1/admin/api-tokens` - implementation: **M2-35**
- `createAPIToken` - `POST /api/v1/admin/api-tokens` - implementation: **M2-36**
- `revokeAPIToken` - `DELETE /api/v1/admin/api-tokens/{id}` - implementation: **M2-37**
- `listIntegrationCatalog` - `GET /api/v1/integration-catalog` - implementation: **M3-03**
- `listIntegrations` - `GET /api/v1/integrations` - implementation: **M3-04**
- `createIntegration` - `POST /api/v1/integrations` - implementation: **M3-05**
- `getIntegration` - `GET /api/v1/integrations/{id}` - implementation: **M3-06**
- `updateIntegration` - `PATCH /api/v1/integrations/{id}` - implementation: **M3-07**
- `deleteIntegration` - `DELETE /api/v1/integrations/{id}` - implementation: **M3-08**
- `authorizeIntegration` - `POST /api/v1/integrations/{id}/authorize` - implementation: **M3-09**
- `syncIntegration` - `POST /api/v1/integrations/{id}/sync` - implementation: **M3-10**
- `listIntegrationSyncs` - `GET /api/v1/integrations/{id}/syncs` - implementation: **M3-11**
- `getIntegrationSync` - `GET /api/v1/integrations/{id}/syncs/{syncId}` - implementation: **M3-12**
- `listSensors` - `GET /api/v1/sensors` - implementation: **M3-27**
- `createSensorEnrollment` - `POST /api/v1/sensors` - implementation: **M3-28**
- `getSensor` - `GET /api/v1/sensors/{id}` - implementation: **M3-29**
- `updateSensor` - `PATCH /api/v1/sensors/{id}` - implementation: **M3-30**
- `deleteSensor` - `DELETE /api/v1/sensors/{id}` - implementation: **M3-31**
- `rotateSensorToken` - `POST /api/v1/sensors/{id}/rotate-token` - implementation: **M3-32**
- `getSensorCoverage` - `GET /api/v1/sensors/{id}/coverage` - implementation: **M3-33**
- `listAgents` - `GET /api/v1/agents` - implementation: **M4-03**
- `getAgent` - `GET /api/v1/agents/{id}` - implementation: **M4-04**
- `updateAgent` - `PATCH /api/v1/agents/{id}` - implementation: **M4-05**
- `getAgentCapabilities` - `GET /api/v1/agents/{id}/capabilities` - implementation: **M4-06**
- `getAgentRelationships` - `GET /api/v1/agents/{id}/relationships` - implementation: **M4-07**
- `listAgentSessions` - `GET /api/v1/agents/{id}/sessions` - implementation: **M4-08**
- `listTools` - `GET /api/v1/tools` - implementation: **M4-09**
- `getTool` - `GET /api/v1/tools/{id}` - implementation: **M4-10**
- `listIdentities` - `GET /api/v1/identities` - implementation: **M4-11**
- `getIdentity` - `GET /api/v1/identities/{id}` - implementation: **M4-12**
- `listRuntimes` - `GET /api/v1/runtimes` - implementation: **M4-13**
- `getRuntime` - `GET /api/v1/runtimes/{id}` - implementation: **M4-14**
- `getAsset` - `GET /api/v1/assets/{id}` - implementation: **M4-15**
- `listFindings` - `GET /api/v1/findings` - implementation: **M4-34**
- `getFinding` - `GET /api/v1/findings/{id}` - implementation: **M4-35**
- `updateFinding` - `PATCH /api/v1/findings/{id}` - implementation: **M4-36**
- `acceptFindingRisk` - `POST /api/v1/findings/{id}/accept-risk` - implementation: **M4-37**
- `createFindingTicket` - `POST /api/v1/findings/{id}/ticket` - implementation: **M4-38**
- `listAttackPaths` - `GET /api/v1/attack-paths` - implementation: **M4-43**
- `getAttackPath` - `GET /api/v1/attack-paths/{id}` - implementation: **M4-44**
- `getAttackPathBreakOptions` - `GET /api/v1/attack-paths/{id}/break-options` - implementation: **M4-45**
- `listTests` - `GET /api/v1/tests` - implementation: **M5-05**
- `createTest` - `POST /api/v1/tests` - implementation: **M5-06**
- `getTest` - `GET /api/v1/tests/{id}` - implementation: **M5-07**
- `updateTest` - `PATCH /api/v1/tests/{id}` - implementation: **M5-08**
- `runTest` - `POST /api/v1/tests/{id}/runs` - implementation: **M5-09**
- `listTestRuns` - `GET /api/v1/test-runs` - implementation: **M5-10**
- `getTestRun` - `GET /api/v1/test-runs/{id}` - implementation: **M5-11**
- `cancelTestRun` - `POST /api/v1/test-runs/{id}/cancel` - implementation: **M5-12**
- `listAttackLabRuns` - `GET /api/v1/attack-lab/runs` - implementation: **M5-27**
- `createAttackLabRun` - `POST /api/v1/attack-lab/runs` - implementation: **M5-28**
- `getAttackLabRun` - `GET /api/v1/attack-lab/runs/{id}` - implementation: **M5-29**
- `cancelAttackLabRun` - `POST /api/v1/attack-lab/runs/{id}/cancel` - implementation: **M5-30**
- `rerunAttackLabRun` - `POST /api/v1/attack-lab/runs/{id}/rerun` - implementation: **M5-31**
- `listPolicies` - `GET /api/v1/policies` - implementation: **M6-08**
- `createPolicy` - `POST /api/v1/policies` - implementation: **M6-09**
- `getPolicy` - `GET /api/v1/policies/{id}` - implementation: **M6-10**
- `updatePolicy` - `PATCH /api/v1/policies/{id}` - implementation: **M6-11**
- `deletePolicy` - `DELETE /api/v1/policies/{id}` - implementation: **M6-12**
- `simulatePolicy` - `POST /api/v1/policies/{id}/simulate` - implementation: **M6-13**
- `rolloutPolicy` - `POST /api/v1/policies/{id}/rollout` - implementation: **M6-14**
- `disablePolicy` - `POST /api/v1/policies/{id}/disable` - implementation: **M6-15**
- `listPolicyDecisions` - `GET /api/v1/policies/{id}/decisions` - implementation: **M6-16**
- `listSecurityAgentTemplates` - `GET /api/v1/security-agent-templates` - implementation: **M7A-61**
- `listSecurityActions` - `GET /api/v1/security-actions` - implementation: **M7A-62**
- `listSecurityAgents` - `GET /api/v1/security-agents` - implementation: **M7A-63**
- `createSecurityAgent` - `POST /api/v1/security-agents` - implementation: **M7A-64**
- `getSecurityAgent` - `GET /api/v1/security-agents/{id}` - implementation: **M7A-65**
- `updateSecurityAgent` - `PATCH /api/v1/security-agents/{id}` - implementation: **M7A-66**
- `deleteSecurityAgent` - `DELETE /api/v1/security-agents/{id}` - implementation: **M7A-67**
- `simulateSecurityAgent` - `POST /api/v1/security-agents/{id}/simulate` - implementation: **M7A-69**
- `runSecurityAgent` - `POST /api/v1/security-agents/{id}/runs` - implementation: **M7A-70**
- `listSecurityAgentRuns` - `GET /api/v1/security-agent-runs` - implementation: **M7A-71**
- `getSecurityAgentRun` - `GET /api/v1/security-agent-runs/{id}` - implementation: **M7A-72**
- `cancelSecurityAgentRun` - `POST /api/v1/security-agent-runs/{id}/cancel` - implementation: **M7A-73**
- `listSecurityAgentApprovals` - `GET /api/v1/security-agent-approvals` - implementation: **M7A-74**
- `getSecurityAgentApproval` - `GET /api/v1/security-agent-approvals/{id}` - implementation: **M7A-75**
- `decideSecurityAgentApproval` - `POST /api/v1/security-agent-approvals/{id}/decision` - implementation: **M7A-76**
- `listSessions` - `GET /api/v1/sessions` - implementation: **M7-02**
- `getSession` - `GET /api/v1/sessions/{id}` - implementation: **M7-03**
- `listSessionEvents` - `GET /api/v1/sessions/{id}/events` - implementation: **M7-04**
- `listComplianceControls` - `GET /api/v1/compliance/controls` - implementation: **M7-10**
- `listComplianceEvidence` - `GET /api/v1/compliance/evidence` - implementation: **M7-11**
- `createComplianceExport` - `POST /api/v1/compliance/exports` - implementation: **M7-12**
- `getComplianceExport` - `GET /api/v1/compliance/exports/{id}` - implementation: **M7-13**
- `listAuditEvents` - `GET /api/v1/audit-events` - implementation: **M2-40**
- `createAuditExport` - `POST /api/v1/audit-exports` - implementation: **M2-41**
- `getAuditExport` - `GET /api/v1/audit-exports/{id}` - implementation: **M2-42**
- `getDataControls` - `GET /api/v1/settings/data-controls` - implementation: **M7-17**
- `updateDataControls` - `PATCH /api/v1/settings/data-controls` - implementation: **M7-18**
- `getExternalDataFlows` - `GET /api/v1/settings/external-data-flows` - implementation: **M7-21**
- `updateExternalDataFlows` - `PATCH /api/v1/settings/external-data-flows` - implementation: **M7-22**
- `getSystemStatus` - `GET /api/v1/system/status` - implementation: **M7-30**
- `listSystemComponents` - `GET /api/v1/system/components` - implementation: **M7-31**
- `getSystemVersion` - `GET /api/v1/system/version` - implementation: **M7-32**
- `createAIExplanation` - `POST /api/v1/ai/explanations` - implementation: **M7-27**

### Internal data-plane coverage

- `ingestEvents` - `POST /internal/v1/events` - M3 internal ingest task
- `sensorHeartbeat` - `POST /internal/v1/sensors/heartbeat` - M3 sensor heartbeat task
- `getPolicyBundle` - `GET /internal/v1/policy-bundles/{environmentId}` - M6 internal policy bundle task
- `recordRuntimeDecision` - `POST /internal/v1/runtime/decisions` - M6 runtime decision task
- `stytchWebhook` - `POST /internal/v1/stytch/webhooks` - M2 Stytch webhook task
- `integrationAuthCallback` - `GET /internal/v1/integration-auth/callback` - M3 Nango auth callback task

## 21. Final plan audit

This plan intentionally removes v1.1 overengineering: separate graph/correlation/approval/response services, ClickHouse, NATS/Kafka-style messaging, a customer-visible OSS control plane, a full incident system, premature least-privilege automation, every cloud/provider and arbitrary venture-scale load targets.

The product remains enterprise-ready because first-admin bootstrap, launch-connector setup, multi-tenant scope enforcement, identity, audit, SaaS operations/disaster recovery, single-tenant backup/restore and upgrade rollback, data controls, dependency degradation, bounded-response cleanup and release security are not deferred.

Security Agents do not add a new microservice or a general automation platform. They reuse the existing platform worker, OpenRouter gateway, policy service, test/Attack Lab services, integration broker and audit model behind a fixed action registry. This is intentional to keep agentic response MVP-sized and operable.

If a design partner cannot onboard to SaaS or operate the single-tenant profile without opening an internal OSS dashboard, treat that as a product defect. If the golden flow does not change a real security decision, do not compensate by adding more features.
