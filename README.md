# Zasp Agent Security Console

Zasp is an interactive TypeScript SaaS prototype for discovering, governing,
protecting, and adversarially testing agentic systems.

## Product workspaces

- Agentic asset, endpoint, sensitive-data, and change discovery
- Non-human identity inventory, violations, remediation, and policy creation
- Runtime guardrail dashboards, activity, actors, coverage, and policy playground
- Agent red-team scan setup, runs, results, request logs, and finding workflows
- Cloud, model, framework, developer, data, and security connectors
- Prompt hardening, attack testing, report generation, and scheduling

All application UI mutations are deterministic browser-local demo actions
persisted with local storage. Separately documented proof commands use only
their explicit disposable test fixtures; no production resource is changed.

## Base web shell

The base shell exposes exactly 22 product labels in nine groups:

| Group | Labels |
| --- | --- |
| Home | Overview |
| Inventory | Agents; Tools & MCP; Identities; Runtimes |
| Exposure | Findings; Attack Paths |
| Test | Red Team; Attack Lab |
| Protect | Policies; Security Agents; Approvals |
| Investigate | Sessions |
| Compliance | Evidence |
| Integrations | Connections; Sensors |
| Administration | Identity & Access; Audit Log; Data & Retention; External Data Flows; System Health; API Access |

No OSS or provider implementation label appears in the product navigation.
The existing working surfaces continue to use browser-local demonstration data,
while future routes render a bounded heading inside the same shell.

Run the route, navigation, guard, and application smoke contract from the
repository root:

```bash
npm run web:shell:test
```

The unauthenticated-route guard is an inert scaffold with one public sign-in
path and closed redirect targets. It is not wired to a fabricated session and
does not claim that the browser-local prototype is authenticated. M2-01 and
M2-02 now provide the product authentication boundary; wiring it into the web
shell remains later API/UI integration work.

## M1 build check

M1-36a is Complete. It reuses the reviewed clean checkout repository build:

```bash
npm run build:repo
```

The completed gate compiled or executed all eight targets from locked source
and dependency state without adding a duplicate build runner or product
behavior. M1-36b is Complete and owns the separate schema-validation gate.

## M1 schema check

M1-36b is Complete. It composes the five schema authorities already owned by
the platform database migration, canonical domain, SecurityEvent, event-index,
and queue-definition packages:

```bash
npm run schema:check
```

The gate is hermetic and makes no database, provider, network, Docker, or
customer-state call. M1-36c is Complete and separately owns OpenAPI
generation and generated-client drift.

## M1 OpenAPI check

M1-36c is Complete. It runs the reviewed exact-pinned OpenAPI generator and
requires no uncommitted generated-client diff:

```bash
npm run openapi:generate
npm run openapi:check
```

The gate reuses the committed M1-23/M1-24 source, output, and flags and adds no
API operation, schema copy, dependency, or live provider call. M1-36d is
Complete and separately owns UI/API traceability validation.

## M1 UI API coverage check

M1-36d is Complete. It runs the reviewed strict traceability suite and
validator:

```bash
npm run ui-api:test
npm run ui-api:check
```

The current honest result is `UI/API coverage passed: planned=0
api_available=84 available=20 public=104 internal=0.` The gate distinguishes
implemented API contracts from fully wired UI actions.
M1-36e is Complete and separately owns local infrastructure smoke checks.

## M1 local infrastructure smoke

M1-36e is Complete. It reuses the reviewed disposable assembled target and
its hostile local-infrastructure suites:

```bash
node --test deploy/local/start.test.mjs
npm run local:aws-emulator:test
npm run local:start
```

The live gate requires only `Local AWS emulator manifest passed: ready=true
internal=true endpoint=true s3=true cleanup=true.` plus exact owned-resource
absence and unchanged ambient/shared fingerprints afterward. It creates no
persistent local environment or public exposure. M1-37 is Complete.

## Deployment mode configuration

M1-37 is Complete. The typed loader accepts exact
`AGENTSEC_DEPLOYMENT_MODE` values `saas` and `single_tenant`, plus conditional
`AGENTSEC_SINGLE_TENANT_ORGANIZATION_ID`. SaaS starts without an Organization
pin; single-tenant startup requires one canonical product Organization ID.
Authenticated Organization enforcement remains M2-49. M1-38 is Complete.

## Neon Organization scope guard

M1-38 is Complete. The repository query boundary requires one canonical
product Organization ID before SQL execution and prepends its trusted string as
argument `$1`; missing or invalid scope cannot reach the executor. It does not
parse SQL or store tenant state. M1-45a still owns transaction-local tenant
context and later RLS tasks own database enforcement. M1-39 is Complete.

## OpenSearch Organization scope guard

M1-39 is Complete. The EventStore index-document and search-query builders now
require explicit canonical Organization scope before driver I/O. The
same-session fixture proves an Organization A query cannot return an
Organization B document. M1-14 remains
the disposable OpenSearch provider-compatibility authority; its provider
lifecycle stays unchanged, and this task makes no AWS release-parity claim.
M1-40 is Complete.

## S3 Organization artifact prefix

M1-40 is Complete. The existing M1-12 ArtifactStore now uses one
scope-mandatory driver locator, with a same-session fixture proving an
Organization A request cannot read an otherwise identical Organization B
artifact. M1-12 remains the provider-compatibility authority, M1-34 remains the
separate bucket-layout authority, and the existing provider lifecycle stays
unchanged. This product-only guard makes no AWS authorization claim. M1-41
is Complete.

## SQS Organization envelope guard

M1-41 is Complete. One product-only consumer validates exact background,
runtime-event, and test envelopes and requires their canonical
Organization to equal the worker's retained Organization before the handler
can perform any side effect. The binding fixture supplies an Organization B
envelope to an Organization A consumer and proves zero handler calls.

M1-13 remains the SQS adapter and disposable compatibility authority; M1-33
remains the queue-definition and provisioning authority. This task adds no
worker loop, acknowledgement, provider lifecycle, or real-AWS authorization
claim. M1-42 is Complete.

## Graph Organization scope guard

M1-42 is Complete. The existing product GraphStore now routes node and edge
writes plus bounded reads through explicit complete-scope builders. The binding
fixture proves an Organization A path cannot traverse otherwise identical
Organization B graph state, and hostile foreign provider results fail closed.

M1-16 remains the Neo4j adapter and disposable compatibility authority. M1-42
adds no new graph provider or database authorization claim, and does not invoke
the live Neo4j lifecycle. M1-43 is Complete.

## Tenant quota primitive

M1-43 is Complete. The product boundary defines exact Organization-scoped
in-process concurrency keys for connectors, graph queries, tests, and AI
requests. Workspaces and Environments in the same Organization share capacity,
while different Organizations retain independent counters and an over-limit
request fails immediately with one fixed product error.

This primitive is not a distributed rate limiter, billing meter, or
authorization decision. It reads no ambient configuration or provider state;
deployment wiring and distributed enforcement remain later consumer work.
M1-44 is Complete.

## SaaS tenancy foundation check

Run `npm run saas:tenancy:test` to execute the bounded product contract suite
for Neon query guards, OpenSearch documents, S3 artifacts, SQS envelopes,
graph paths, and tenant quota counters. Every fixture exercises two distinct
Organizations, while single-tenant mode passes the same explicitly scoped
contracts.

The check is hermetic: it does not contact a provider or claim database RLS
enforcement. Provider authorization and live Neon policy verification remain
separate lifecycle work. M1-44 is Complete.

## Neon tenant isolation gate

Run `npm run db:tenant-rls:test` for the bounded product and proof contracts.
Run `npm run db:tenant-rls:run` to apply the same policies to eight
tenant-protected tables in a uniquely named schema using the ignored
`DATABASE_URL`. The live fixture enters a temporary non-bypass role and proves
same-Organization access while cross-Organization reads and writes are denied.

The live gate reverses every policy and requires exact schema and role absence.
For MVP validation it uses a unique schema and does not require or mutate a
Neon management branch. M1-45a through M1-45d and the M1-45 gate are Complete.

## M1 foundation gate

M1-36 is PASS. The reviewed build, schema, OpenAPI, UI/API coverage, local
infrastructure, SaaS tenancy, and live Neon isolation boundaries are green.
This opens M1A and M2 implementation without waiving the three existing M0
blockers.

## Identity and authorization foundation

M2-01 through M2-07d are Complete. The product now owns a strict Stytch B2B
adapter, bearer-session authentication, fresh-auth revalidation, idempotent
Organization and principal reconciliation, the six built-in PRD roles,
Organization-scoped Workspace/Environment grants, fail-closed authorization,
and the first-Admin provision-to-sign-in bootstrap path.

The bootstrap persists only product references and creates one default
Workspace with production, staging, and development Environments. It creates
no local password or customer-facing bypass login.

M2-01 through M2-50 and the M2-47 gate are Complete. The product exposes 27 strict identity,
governance, token, and audit operations for Organization, Workspace,
Environment, principal, role, SSO, SCIM, group-mapping, API-token, and audit
workflows. The Identity & Access and API Access routes use the generated product
client for identity administration, scoped credential lifecycle, and authorized
Workspace/Environment onboarding. Sensitive mutations require fresh authorization;
SCIM and API-token credentials appear only in their create responses.
The internal Stytch webhook boundary verifies the Svix-compatible signature,
timestamp, project, event identity, and replay state before deprovisioning a
member, removing product grants, and recording the audit summary.
M2 gate: PASS. The bounded fake-Stytch and product-store suite covers session
revocation, SCIM deprovisioning, scoped API tokens, audit history, two-Organization
SaaS isolation, and the single-tenant Organization pin without direct Stytch
dashboard access.

## Staging foundation and integration APIs

M1A-01 through M1A-06 are Complete. The `deploy/staging` Terraform root defines
the shared non-production VPC, two private subnets, encrypted EKS cluster and
node group, evidence bucket, KMS key, secret slots, the six queue/DLQ resources,
private OpenSearch, and the product IRSA role. Terraform 1.15.8 validation and
an offline 34-create plan pass without applying or contacting a staging account.
M1A-07 remains Pending; no real cloud resource was created by this batch.

M3-01 through M3-13 are Complete. The product now exposes a provider-neutral
connector catalog, a signed Generic Webhook entry, scoped integration CRUD and
authorization, sync history, and an idempotent forward-only sync job contract.
All ten integration operations are present in the OpenAPI document and generated
client as `api_available`; internal adapter and upstream implementation names are
excluded from the public catalog.

M3-14 through M3-34 are implementation-ready but remain In progress. The batch
adds a strict AWS assume-role identity boundary, scoped Cartography/Prowler and
AWS/Kubernetes/GitHub/IdP normalization, freshness retention, an exact-pinned
private Nango Auth/Proxy deployment, secret-safe connection/OAuth/proxy
boundaries, and sensor enrollment, management, coverage, and heartbeat APIs.
The required real AWS staging authority is unavailable, so M1A-07 through
M1A-10 and the real-AWS denial/staging smoke gates have not been claimed or
bypassed.

M3-35 through M3-48c3 are also batched as In progress. The local MVP slice
adds the exact-pinned Tetragon wrapper, process/file/network and OTLP semantic
adapters, scoped pre-parse authentication, metadata filtering, bounded event
batches, deterministic archive/index/correlation worker stages, and the
connection catalog/list/detail product surfaces. Durable AWS queue, object,
index, and staging lifecycle evidence remains gated by M1A-10; the local worker
tests do not substitute for that provider gate.

M3-48d through M3-52 and M4-01a through M4-01 are batched as In progress.
Provider-specific connection setup, sensor lifecycle surfaces, the composed
connector/sensor/runtime fixture, and full-scope canonical reconciliation now
run locally. The M3 gate remains intentionally non-PASS for release purposes:
real SQS, S3, OpenSearch, connector, sensor, and staging evidence still depends
on M1A-10. The M4 reconciliation batch likewise makes no Neon or staging claim.

M4-02 through M4-23 are batched as In progress. The local platform boundary
now supports scoped Agent ownership audits, thirteen generated inventory APIs,
six evidence-state capability categories, and four evidence-backed posture
rules. These are locally tested API and store contracts; they make no Neon,
live-provider, staging, or release-gate claim while M1A-10 and the preceding M3
provider work remain unresolved.

M4-24 through M4-49 are batched as In progress. The same local product
boundary now adds the remaining eight high-signal posture rules,
relevance-filtered findings and signed ticket actions, bounded attack paths and
break options, a stale-aware Home summary, and safe indexed search. Ten more
generated API contracts are `api_available`; no webhook delivery, Neon,
provider, staging, or release-gate success is claimed by the injected local
fixtures.

M4-50a through M4-59 are batched as In progress. One generated-schema Agent
Security surface now covers Agent filters/detail, Tools and MCP, Identities,
Runtimes, Findings, Attack Paths, and stale-aware Home state. Its canonical
fixture drives a five-check local M4 gate across Inventory, Capability,
Posture, Attack Path, and Exposure UX. This is coherent local MVP evidence,
not Neon, provider, staging, external webhook, or release-gate evidence.

M7-39 through M7-40 and M7A-01 through M7A-17 are batched as In progress. The
local M7 gate now binds five degraded-state fixtures and six independent MVP
flows. The Security Agent foundation adds tenant-scoped definitions, runs,
steps, approvals, idempotency, structured plans, an action registry, and a
bounded temporary runtime-policy action. These local contracts do not claim a
live Neon migration, production policy-service adapter, or provider-backed M7
gate.

M7A-18 through M7A-38 are batched as In progress. The Security Agent runtime
now has bounded temporary-control verification and expiry, eight guarded
response actions, five versioned templates, scoped finding/attack-path/runtime
matchers, and cooldown deduplication. External policy, gateway, connector,
webhook, and persistence adapters remain explicit unresolved boundaries.

```bash
go test -C services/platform -race -count=1 ./integration
go test -C services/platform -race -count=1 ./connectors ./sensor
go test -C services/platform -race -count=1 ./runtimeevent
go test -C services/platform -race -count=1 ./m3gate ./reconciliation
terraform -chdir=deploy/staging init -backend=false
terraform -chdir=deploy/staging validate
```

## Development

Requires Node.js `22.23.1` and npm `10.9.8`. `.nvmrc` pins the Node runtime;
after selecting it, activate the matching npm version with Corepack if needed.

```bash
nvm use
corepack prepare npm@10.9.8 --activate
SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm ci
npm run dev
npm run verify
```

`SHARP_IGNORE_GLOBAL_LIBVIPS=1` prevents Homebrew's global libvips from making
Sharp build from source; the locked platform binary is used instead. `npm run
verify` runs tests, type-checking, linting, and the production build in that
order.

## Platform API command

M1-01d is Complete. It established the first minimal Go command at
`services/platform/agentsec-api` and its exact build-version line:

```text
agentsec-api build <version>
```

M1-28b now wires the shared internal health server while preserving that exact
line. It does not add product API routes, load dependency configuration, or
contact credentials or provider state. The development build uses `dev`;
release builds may inject a bounded version at link time.
The completed M1-01d skeleton itself does not start an HTTP server; this later
health-only wiring is the explicit M1-28b extension of that boundary.

## Platform worker command

M1-01e is Complete. It established the second minimal Go command at
`services/platform/agentsec-worker` and its exact build-version line:

```text
agentsec-worker build <version>
```

M1-28b now wires the shared internal health server while preserving that exact
line. It does not start a worker loop, poll a queue, load dependency
configuration, or contact credentials or provider state. The development build
uses `dev`; release builds may inject a bounded version at link time.

## Event ingest command

M1-01f is Complete. It creates the standalone Go service at
`services/event-ingest` and its exact build-version line:

```text
event-ingest build <version>
```

M1-28c now wires the shared internal health handler through one dedicated
bounded `:8081` listener. Liveness is 200 before readiness; readiness is 503
before serving, 200 only during the serving lifetime, and withdrawn before the
independently bounded five-second graceful shutdown. The exact routes are
`/healthz`, `/readyz`, `/version`, and `/metrics`.

```bash
npm run event-ingest:health:test
```

The command uses a private handler rather than the default mux and retains the
exact build line. It still does not accept or normalize events, batch payloads,
contact SQS, load runtime configuration, read credentials or provider state,
or expose a public product API. Deployment remains outside this task; M1-28d is
Complete and M1-28 is Complete. The development build uses `dev`;
release builds may inject a bounded version at link time.

## Runtime gateway command

M1-01a is Complete. It creates the standalone Go service at
`services/runtime-gateway` and its exact build-version line:

```text
runtime-gateway build <version>
```

M1-28d now wires the shared internal health handler through one dedicated
bounded `:8081` listener. Liveness is 200 before readiness; readiness is 503
before serving, 200 only during the serving lifetime, and withdrawn before the
independently bounded five-second graceful shutdown. The exact routes are
`/healthz`, `/readyz`, `/version`, and `/metrics`.

```bash
npm run runtime-gateway:health:test
```

The command uses a private handler rather than the default mux and retains the
exact build line. It still does not start a gateway, proxy, MCP server, tool or
API forwarding, OPA evaluation, authentication, configuration loading,
credential or provider access, or a public product API. Deployment remains
outside this task; M1-28 is Complete. The development build uses `dev`;
release builds may inject a bounded version at link time.

## Worker package commands

M1-01b is Complete. It creates separate Python security-worker and Node
redteam-worker package skeletons. Their only behavior in this task is
one exact no-op health result each:

```text
security-worker health ok
redteam-worker health ok
```

These skeletons do not start worker loops, import Cartography, Prowler, or
Promptfoo adapters, read queues, graphs, prompts, findings, configuration,
credentials, or provider state, open listeners, or perform network operations.
Health listeners for those worker packages remain outside M1-28 and are not yet
implemented.

## Web and CLI directory boundaries

M1-01c is Complete. The `apps/web` package delegates to the existing locked
runnable UI build through this exact command:

```bash
npm --prefix apps/web run build
```

The standalone CLI boundary exposes only this exact version shape:

```text
agentsecctl version <version>
```

Run its independent Go module from the repository root with
`go run -C cmd/agentsecctl . version`.

The CLI does not implement preflight, recovery, diagnostics, provider access,
credential loading, listeners, or network behavior. The web boundary does not
copy or fork the existing product UI.

## Repository build

M1-01 is Complete. The prepared checkout builds every existing service,
worker, web, and CLI target through one root command:

```bash
npm run build:repo
```

The command does not install or download dependencies. It adds no provider,
credential, listener, network, or runtime product behavior, and the existing
Runnable UI verification command remains unchanged.

## Product dependency lock

M1-02 is Complete. Direct dependencies of deployable product manifests are
recorded with an exact resolved version, SPDX license, internal owner, runtime
scope, and explicit review state. Validate that inventory with:

```bash
npm run dependencies:check
```

The check is local and deterministic: it performs no installation, download,
provider, Docker, credential, or network operation. Proof-only, development,
optional peer, and transitive dependencies remain governed by their existing
locks or proof-specific license records rather than this product-runtime lock.

## Canonical product identity

M1-03 is Complete. Product-owned primary IDs use the opaque exact text form
`pid_<canonical-uuid>` and remain a distinct type from bounded external-source
references. A vendor ARN, numeric ID, or UUID-shaped vendor ID is never copied,
hashed, normalized, or parsed into a product primary key. This task adds only
dependency-free platform-domain value types; scope and persistence remain in
later M1 tasks.

## Product scope model

M1-04 is Complete. Every scoped security entity follows the exact
`Organization -> Workspace -> Environment` product-ID hierarchy. Missing,
zero, malformed, or duplicate hierarchy IDs fail closed; vendor identifiers
remain outside the product scope boundary.

## Product evidence model

M1-05 is Complete. Evidence references use canonical product identity;
evidence confidence and capability/path state use separate exact lowercase
vocabularies. Evidence confidence never substitutes for finding severity, and
a reference alone never grants scoped access.

## Product error envelope

M1-06 is Complete. Customer API failures use one stable product error code,
bounded product-language message, canonical correlation ID, and explicit
retryable flag. The exact four-field response excludes vendor exceptions,
debug metadata, credentials, and implicit retry guesses.

## Product configuration loader

M1-07 is Complete. The platform configuration boundary is typed and
reference-only: missing required dependency configuration fails startup, while
PostHog, OpenRouter, and remote OTLP remain optional. Secret configuration uses
strict Secrets Manager references and does not load or expose secret material.

## External client policy

M1-08 is Complete. Shared HTTP client execution uses one total deadline,
bounded concurrency, transient-only retry classification, and capped
exponential backoff with jitter. Read-only and explicitly idempotent operations
may retry; non-idempotent mutations are never retried.

## Idempotency helper

M1-09 is Complete. An Organization-scoped idempotency request binds its
operation, caller key, and exact request fingerprint before any side effect.
Only the unique acquired claim executes; completed duplicates return the prior
canonical product result. In-progress, conflicting, failed, canceled, panicked,
or unknown outcomes remain in progress for explicit reconciliation and are not
executed automatically.

## Neon schema baseline

M1-10 is Complete. It adds the first versioned Neon schema baseline as a
dependency-free platform migration package. The product boundary owns the
embedded SQL and strict transaction protocol; the reviewed disposable Neon
branch proof owns credentials, provider lifecycle, live up/down verification,
and exact branch cleanup. M1-11 is Complete.

The hermetic command exercises the package and retained proof regressions. The
live command reads only `NEON_API_KEY`, `NEON_PROJECT_ID`, and `DATABASE_URL`
through Node's ignored dotenv boundary, creates one exactly owned disposable
branch, applies version 1, re-reads the exact ledger row, rolls it back, proves
the database baseline restored, and deletes the branch.

```bash
npm run db:schema:test
npm run db:schema:run
```

Live success is exactly:

```text
Neon schema baseline passed: up=true version=1 down=true baseline_restored=true branch_deleted=true.
```

Output excludes connection fields, SQL rows, provider identifiers, and
credentials. This task does not add a production pool or automatic startup
migration. Three fresh disposable live runs, exact cleanup, all pinned gates,
secret scans, and zero-finding independent review passed; the pool boundary
remains with M1-11.

## Neon application pool wrapper

M1-11 is Complete. It adds a driver-neutral application pool wrapper with a
bounded query context, bounded health check, validated wait/in-use statistics,
and one clean idempotent close boundary. Product code remains independent of
pgx; the existing reviewed Neon proof module owns the pgxpool adapter and live
provider verification. M1-12 is Complete.

```bash
npm run db:pool:test
npm run db:pool:run
```

The live command reads only the ignored `DATABASE_URL`, derives the strict
pooled endpoint, limits pgxpool to two connections, and requires ten reads to
produce observed wait and in-use statistics before every connection is released
and the wrapper closes. It performs no branch or schema mutation. Success is
exactly:

```text
Neon pool wrapper passed: reads=10 waited=true in_use=true acquired=0 closed=true.
```

The dependency-free product package, strict pgx adapter, exact live contention
proof, focused stability and race suites, repository gates, secret scans, and
zero-finding pre-landing review all passed. M1-12 is Complete.

## S3 artifact interface

M1-12 is Complete. It adds an Organization-scoped ArtifactStore product
boundary for typed Put, Get, and Delete operations. Callers provide validated
product scope, artifact identity, media type, and bytes; provider bucket names,
object keys, encryption identifiers, and credentials remain inside the S3
adapter. M1-13 is Complete.

```bash
npm run artifact:store:test
npm run artifact:store:run
```

The hermetic command exercises the product and adapter boundaries without
Docker or provider access. The live command creates only one uniquely named,
exactly labeled disposable LocalStack container, publishes only its loopback
edge endpoint, and uses synthetic credentials confined to that container.
Success is exactly:

```text
LocalStack artifact store passed: put=true get=true delete=true scoped=true encrypted=true cleanup=true audit=true container_cleanup=true.
```

The dependency-free product package, strict S3/KMS adapter, exact disposable
live lifecycle, reverse cleanup and prefix-wide audit, six final hermetic runs,
all repository gates, secret scans, and zero-finding pre-landing review passed.
The shared development LocalStack container was never selected or changed.
M1-13 is Complete.

## SQS job queue interface

M1-13 is Complete. It adds an Organization-scoped JobQueue as a
dependency-free boundary for bounded batch publish, consume, and explicit
acknowledgement plus a strict SQS adapter and disposable LocalStack queue/DLQ
lifecycle. AWS queue URLs, ARNs, message IDs, receipt handles, credentials, and
provider errors stay outside the product interface. M1-14 is Complete.

```bash
npm run job:queue:test
npm run job:queue:run
```

The hermetic command exercises the product, SQS adapter, lifecycle, and
disposable-runner contracts without Docker or provider access. The live command
creates one exact queue/DLQ pair inside one exact disposable LocalStack
container, publishes only a loopback endpoint, and uses fixed synthetic local
credentials. It does not read dotenv, cloud profiles, proxies, or real AWS credentials.
This is disposable LocalStack SQS compatibility only, not
real-AWS IAM, durability, availability, encryption, or release-parity evidence.
The final exact live lifecycle, Standard-queue partial/order regressions,
candidate-aware cleanup, six hermetic passes, full repository gates, secret
scans, and zero-finding independent review passed. M1-14 is Complete.

## OpenSearch EventStore

M1-14 is Complete. It adds a dependency-free scoped EventStore whose index
and search operations require validated Organization, Workspace, and
Environment scope before provider I/O. OpenSearch index names, query DSL,
provider identifiers, endpoints, credentials, and errors stay outside the
product interface. M1-15 is Complete.

## Product GraphStore interface

M1-15 is Complete. It adds a dependency-free product GraphStore with
canonical product node and edge IDs, exact Organization, Workspace, and
Environment scope, and bounded structured reads. Neo4j types, Cypher, provider
identifiers, endpoints, credentials, and arbitrary customer graph queries stay
outside the product interface. M1-16 is Complete.

```bash
npm run graph:store:test
```

This is a hermetic fake driver contract. It validates canonical projection
upsert, bounded structured read, exact scope and identity, fixed errors,
deadlines, defensive copies, and concurrency without Docker or provider I/O. It
does not run Neo4j or prove persistence, transactions, availability, packaging,
or licensing. M1-16 adds the exact-scoped official-driver adapter and a
disposable Neo4j Community compatibility proof without widening the product
interface; M1-17 is Complete.

## Neo4j GraphStore proof

M1-16 provides a local-only compatibility proof for the product GraphStore
against the official Neo4j Go driver v6.2.0 and the exact disposable image
`neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357`.

```bash
npm run graph:neo4j:test
npm run graph:neo4j:license
npm run graph:neo4j:run
```

The live command creates one exact-owned loopback-only target, proves three
scoped nodes and two edges through the product interface, replays the upsert,
checks outgoing/incoming/both/depth-zero reads and Organization B zero state,
deletes the fixture, and removes its container, anonymous volumes, and owned
temporary directory. Success is exactly:

```text
Neo4j GraphStore proof passed: nodes=3 edges=2 replay=true scoped=true cross_organization_zero=true cleanup=true audit=true.
```

The adapter uses fixed parameterized statements; it does not accept raw Cypher or customer query text.
The runner does not target a shared Neo4j service and
re-proves any shared Neo4j container fingerprint unchanged. The Apache-2.0 Go
driver is an approved product runtime dependency; this proof does not approve Neo4j Community server packaging or redistribution.
Neo4j Community remains a GPL-3.0-only proof-only compatibility target. M1-16
is Complete after whole-range review, final verification, the exact live proof,
and exact-SHA CI; M1-17 is Complete.

## AuditEmitter contract

M1-17 defines a dependency-free product AuditEmitter for security mutations.
Every mutation requires canonical product actor, action, target, and outcome
fields plus exact Organization, Workspace, and Environment scope. The boundary
validates inputs before I/O, performs one bounded, one-attempt append, requires
an exact acknowledgement, and exposes only fixed product errors.

```bash
npm run audit:emitter:test
```

This command runs a hermetic fake driver. It performs no provider, database,
network, Docker, credential, or shared-resource I/O. The hermetic boundary does
not prove persistence, retention, export, or a generic event envelope. M1-18 is
Complete.

## Feature flag contract

M1-18 defines a dependency-free FeatureFlags boundary for exact Organization,
Workspace, and Environment scope. Each boolean request carries a per-call code
default. A valid provider decision returns exact cache hit and age metadata;
outage, panic, timeout, cancellation, or malformed provider state safely returns
that request's default through one bounded driver attempt and fixed product
errors.

```bash
npm run featureflags:test
```

This command runs a hermetic fake driver and performs no provider, cache,
database, network, Docker, credential, or shared-resource I/O. Feature flags
are non-security-critical and never authorize scope, policy, enforcement,
credentials, data access, or audit behavior. This boundary does not prove a
provider adapter, remote evaluation, or cache implementation.
M1-19 is Complete.

## Product telemetry contract

M1-19 is Complete. It defines a dependency-free ProductTelemetry boundary for
exact Organization, Workspace, and Environment scope. Its closed catalog currently
contains only `proof_completed`, with exactly one bounded `source` text field
and one `success` boolean field. The product serializer constructs a typed
driver record and rejects every missing, duplicate, wrong-kind, malformed,
surplus, or unknown field before I/O. Prompt, secret, IP address, raw evidence,
arbitrary context, person-profile, feature-flag, and vendor-native fields are
outside the catalog.

```bash
npm run producttelemetry:test
```

This command runs a hermetic fake driver and performs one bounded capture
attempt with no retry. It performs no provider, database, network, Docker,
credential, or shared-resource I/O. Analytics is optional and
non-authoritative: it never controls scope, authentication, policy,
enforcement, data access, feature flags, or audit behavior. This boundary does
not prove a PostHog adapter, hosted delivery, batching, persistence, or consent
policy.

M1-20 is Complete. It defines a provider-neutral scoped AIGateway with
an exact approved-purpose catalog, complete data-policy metadata, bounded
redacted product content, and a hermetic fake-driver contract. M1-21 is
Complete.

## AI gateway contract

M1-20 is Complete. It defines a dependency-free AIGateway boundary for
exact Organization, Workspace, and Environment scope. The closed purpose
catalog currently approves only `finding_explanation`; an unapproved purpose
fails before driver I/O. Every request requires complete policy metadata with
`redacted_summary` content, explicit secret/PII/PHI/raw-evidence exclusion, an
approved egress state, and `no_provider_storage` retention.

```bash
npm run aigateway:test
```

This command runs a hermetic fake driver and performs one bounded generation
attempt with no retry. It performs no provider, database, network, Docker,
credential, or shared-resource I/O. AI output is non-authoritative: it never
controls scope, deterministic policy, authorization, action execution, or
verification. This boundary does not prove an OpenRouter adapter, hosted
delivery, model routing, streaming, caching, or persistence. M1-21 is Complete
and adds the dependency-free common resource/correlation contract without
changing this AI boundary.

## Observability contract

M1-21 is Complete. It defines a dependency-free, hermetic observability
contract with exactly seven common resource attributes: `service.namespace`,
`service.name`, `service.version`, `deployment.environment.name`,
`organization.id`, `workspace.id`, and `environment.id`. The namespace is
fixed to `agentsec`; service names are limited to `agentsec-api` and
`agentsec-worker`; deployment names are limited to `development`, `test`,
`staging`, and `production`.

```bash
npm run observability:test
```

The closed boundary rejects raw prompt/response text, tool arguments, secrets,
raw evidence, URLs, arbitrary customer content, and every unknown or surplus
resource attribute. Request correlation combines the canonical product
correlation ID with a lowercase 32-character trace ID and 16-character span
ID. Reattaching the same value is idempotent; replacement fails closed.

The command is hermetic and performs no OpenTelemetry SDK, exporter,
Collector, backend, provider, network, credential, database, or Docker I/O.
M1-22 is Complete and adds the dependency-free canonical SecurityEvent value
without changing this observability boundary.

## SecurityEvent envelope

M1-22 defines the dependency-free canonical SecurityEvent value with exactly
six fields: `Version`, `Scope`, `Source`, `Time`, `Evidence`, and `Correlation`.
It accepts exactly version 1, complete Organization/Workspace/Environment
scope, one of `runtime_gateway`, `otlp`, `tetragon`, or `attack_lab`, and a
nonzero time in canonical UTC millisecond precision. Evidence is one valid
typed product evidence reference, and correlation is the reviewed M1-21
product, trace, and span correlation value.

```bash
npm run securityevent:test
```

The envelope deliberately contains no customer content: raw evidence,
payloads, prompts, tool arguments, secrets, arbitrary metadata, and vendor
identifiers are not envelope fields. The command is hermetic and performs no
parser, OpenAPI, transport, adapter, queue, storage, provider, network,
credential, database, Docker, filesystem, or environment I/O. M1-23 is
Complete and defines the OpenAPI root separately. M1-22 is Complete.

## OpenAPI root

The self-contained `openapi/openapi.yaml` document establishes the OpenAPI
3.1.0 product root. Global HTTP bearer authentication accepts `SessionJWT` or
`ProductAPIToken` as separate global security alternatives, so a request uses
one reviewed token boundary rather than requiring both or permitting anonymous
access.

Reusable pagination vocabulary is `Cursor`, `PageCursor`, `PageLimit`, and the
closed two-state `PageInfo`. The public error vocabulary is canonical
`ProductID`, the exact four-field `ProductError`, and `ProductErrorResponse`.
The root deliberately retains `paths: {}` and contains no operations, servers,
callbacks, webhooks, examples, or remote references. M1-24 generates the
TypeScript client only from this reviewed root. Exact-pinned
`openapi-typescript` 7.13.0 writes the committed immutable surface at
`apps/web/api/generated.ts`; exact-pinned `openapi-fetch` 0.17.0 backs the
typed factory at `apps/web/api/client.ts`.

Because the root still has `paths: {}`, the client has no callable endpoint.
The factory has no default remote server, performs no I/O during construction,
and does not hand-write `/api/v1/` URLs. Authentication/session retrieval,
reviewed operations, and UI integration remain later work. M1-23 is Complete.
M1-24 is Complete. M1-25 is Complete. M1-26 is Complete. M1-27 is Complete;
M1-28a is Complete. M1-28b is Complete, M1-28c is Complete, M1-28d is Complete, and M1-28 is Complete. No OpenAPI operation was added by the coverage task
itself.

```bash
npm run openapi:test
npm run openapi:lint
npm run openapi:generate
npm run openapi:check
```

The pinned linter extends its recommended rules and disables only the two
root-only checks `no-empty-servers` and `no-unused-components`. No install,
download, provider, network, credential, environment-file, database, Docker,
or shared-resource I/O occurs during these local verification commands.

## UI-to-API map seed

M1-25 seeds the strict checked-in `docs/product/ui-api-map.yaml`. Home maps its
planned daily-queue and search actions to `getHomeSummary` and `globalSearch`.
System Health maps overall status, component inventory, and version actions to
`getSystemStatus`, `listSystemComponents`, and `getSystemVersion`.

The artifact contains only stable screen/action identity and operation IDs.
Home actions are `api_available` through `getHomeSummary` and `globalSearch`;
the three System Health actions are now `api_available`. API availability records a
generated product contract and does not claim a wired UI or provider integration.

M1-26 adds the reusable bidirectional coverage gate. A `planned` operation must
remain absent from the current OpenAPI document. An `available` operation must
exist exactly once under `/api/v1` and have exactly one mapped screen action;
every other `/api/v1` operation is rejected as unmapped. `/internal/v1`
operations must remain unmapped.

```bash
npm run ui-api:test
npm run ui-api:check
```

The current fixed success line is:

```text
UI/API coverage passed: planned=0 api_available=84 available=20 public=104 internal=0.
```

M5 now has a local MVP slice for normalized Promptfoo attempts, curated packs,
test safety, thirteen generated Red Team and Attack Lab API contracts,
idempotent worker/artifact boundaries, and fail-closed Attack Lab
sandbox/preflight/evidence/verdict UI contracts. M6 has a local Policy domain,
validator, deterministic compiler/evaluator, signed bundle/cache and fallback,
HTTP/MCP action normalization, Monitor/Block decisions, rollout/simulation UI,
and nine generated product API contracts. These slices do not claim live
EKS/Fargate, SQS, S3, Neon, egress-proxy, staging, OPA SDK, or runtime-gateway
integration proof.

M7 now has a local MVP slice for idempotent session projection, structured
session filtering, mixed-confidence timelines, compliance control/evidence
freshness, JSON/CSV/human exports, environment data controls, three product
surfaces, retention, governed external flows, allowlist-only telemetry, bounded
AI explanations, system health, admin/degraded-state surfaces, and fifteen
generated product API contracts. OpenSearch-backed filtering, S3 export writing,
provider persistence/probes/scheduling, and staging verification remain unresolved
and are not claimed by this local slice.

Failure is fixed as `UI/API coverage rejected.` without parser or artifact
details. Both commands are part of root verification. M1-25 is Complete.
M1-26 is Complete. M1-27 is Complete. M1-28a is Complete. M1-28b is Complete,
M1-28c is Complete, M1-28d is Complete, and M1-28 is Complete.

## Raw frontend Fetch lint

M1-27 enforces the generated-client boundary in normal frontend JavaScript and
TypeScript under `app/**` and `apps/web/**`. The local ESLint rule
`zasp/no-raw-fetch` rejects direct, browser-member, computed, optional, and
call/apply/bind raw Fetch forms. Ambient aliases, destructuring, sequence
expressions, and higher-order calls are rejected too, including requests whose
URL was moved into a variable or `Request` object. Lexically scoped local
symbols that merely use the name `fetch` remain valid.

Exactly `apps/web/api/client.ts` and `apps/web/api/generated.ts` are exempt.
Typed generated-client calls and inert API-path strings remain valid; proof
harnesses and backend services are outside this frontend-only rule. The hostile
suite proves that a seeded direct `/api/v1/` violation fails lint.

```bash
npm run raw-fetch:test
npm run lint
```

The hostile suite is part of root verification. M1-27 is Complete. M1-28a is
Complete. M1-28b is Complete, M1-28c is Complete, M1-28d is Complete, and
M1-28 is Complete.

## Shared service health handler

The standalone Go package under `services/health` defines the shared internal
endpoints `/healthz`, `/readyz`, `/version`, and `/metrics`. Every handler
starts not ready; startup and shutdown code may change only that local state
through atomic `SetReady`. Liveness stays independent of readiness, while the
version and bounded Prometheus responses contain only validated service and
build labels.

```bash
npm run health:test
```

The package itself does not open a listener and does not perform dependency I/O,
provider calls, environment reads, or global mux registration. It defines
handler behavior only; it does not authorize external exposure of these
internal endpoints. Platform, event-ingest, and runtime-gateway command wiring
are complete under M1-28b, M1-28c, and M1-28d. M1-28a is Complete.
M1-28b is Complete. M1-28c is Complete, M1-28d is Complete, M1-28 is Complete,
and M1-29 is Complete. M1-30a, M1-30b, M1-30c, and M1-30d are Complete.

## Common internal service health contract

M1-28 registers the four root-level process probe paths in the separate
`openapi/internal-health.yaml` contract and the exact four-command matrix in
`docs/internal/service-health-endpoints.md`. The public product OpenAPI,
generated client, UI/API map, and `/internal/v1` data-plane inventory remain
unchanged.

```bash
npm run health:contract:test
```

The root gate runs the strict internal OpenAPI/service-document contract and
the race suites for the shared handler, platform API and worker, event-ingest,
and runtime-gateway. It makes no provider or external network call. M1-28 and
M1-29 are Complete.

## System health aggregation model

M1-29 is Complete. `services/health` defines the shared Healthy,
Degraded, and Unavailable component value with exact required/optional
classification, a bounded product-owned reason code, and canonical UTC
millisecond last-success state. Any required Unavailable component makes the
aggregate Unavailable. Any Degraded component or optional Unavailable component
makes it Degraded, so an optional failure never permits a false Healthy result.

The pure model validates local values and does not poll dependencies, perform
I/O, or retain caller-owned state. It records system health but does not change
process readiness; later command or deployment work must make that decision
explicitly. Run the model and existing endpoint/command race suites with:

```bash
npm run health:contract:test
```

M1-30a is Complete. It adds the local Kubernetes deployment boundary for the
four existing Go product commands; M1-30b, M1-30c, and M1-30d are Complete.

## Local product Kubernetes manifests

M1-30a is Complete. It packages the real `agentsec-api`, `agentsec-worker`,
`event-ingest`, and `runtime-gateway` commands as hardened, cluster-internal
pods. The hermetic contract requires no Docker daemon or provider access:

```bash
npm run local:product:test
```

The live command supports macOS or Linux and requires Docker 29.4.0, Go 1.25.6,
kubectl 1.35, and outbound HTTPS access to the pinned kind GitHub release
asset. It builds the four static Go services, starts an exact-owned disposable
kind cluster, proves all four pods Ready with four internal services, and
performs reverse cleanup:

```bash
npm run local:product:run
```

Successful live verification emits exactly
`Local product manifests passed: pods=4 ready=4 services=4 internal=true cleanup=true.`
The runner uses its own kubeconfig and proof labels, removes only retained
resources after exact ownership checks, and leaves shared local services
untouched. M1-30b is Complete, M1-30c is Complete, and M1-30d is Complete.
M1-30 is Complete.

## Platform health wiring

The platform API and worker each bind one dedicated internal `:8081` listener
and expose the shared `/healthz`, `/readyz`, `/version`, and `/metrics`
semantics. Readiness becomes true only for the serving lifetime and becomes
false before a bounded five-second graceful shutdown. Both commands keep their
exact existing build-version output line.

```bash
npm run platform:health:test
```

The shared platform runtime uses finite HTTP header/read/write/idle bounds,
does not register on the default mux, reads no environment or provider state,
and adds no product API route or worker queue loop. The `:8081` port is an
internal process/container boundary; later deployment tasks own Services,
network policy, and probe declarations. M1-28b is Complete after full local
verification and zero-finding review. M1-28c is Complete, M1-28d is Complete, and M1-28 is Complete.

## Local graph Kubernetes manifest proof

M1-30b is Complete. Its local Neo4j overlay is an opt-in proof attached to
the disposable local Kubernetes environment; M1-30c is Complete, and M1-30d
is Complete. The
hermetic manifest, runner, and license contracts require Node.js 22.23.1 and
npm 10.9.8, and require neither Docker nor a provider:

```bash
npm run local:graph:test
```

Run the immutable source and license audit separately:

```bash
npm run local:graph:license
```

The disposable live proof supports macOS or Linux and requires Docker 29.4.0,
Go 1.25.6, kubectl 1.35, and outbound HTTPS access to the pinned kind GitHub
release asset:

```bash
npm run local:graph:run
```

Success is exactly
`Local graph manifest passed: ready=true internal=true persistent=true cleanup=true.`
Failures are exactly `Local graph manifest failed: <category> rejected.` The
only failure categories, in order, are `build, cleanup, configuration, deadline, normalization, ownership, panic, provider, readiness`.
The runner creates and uses its own kubeconfig; it does not read `.env`, ambient
kubeconfig, cloud credentials, profiles, proxy variables, provider data, or
shared cluster state. Graph health is reachable only inside the disposable
local cluster through its ClusterIP Service.

The PVC preserves the synthetic marker across an owned Neo4j pod replacement,
but its data is disposable with the owned kind cluster. Cleanup removes only
the runner's exact-owned resources and leaves shared resources untouched.

Neo4j Community is GPL-3.0-only and BusyBox is GPL-2.0-only. They are opt-in
local development targets: this proof does not approve redistribution or
production packaging, and bundled components retain their own terms.

## Local observability Kubernetes manifest proof

M1-30c is Complete, and M1-30d is Complete. The hermetic manifest,
runner, and license contracts require Node.js 22.23.1 and npm 10.9.8, and
require neither Docker nor a provider:

```bash
npm run local:observability:test
```

Run the immutable source and license audit separately:

```bash
npm run local:observability:license
```

The disposable live proof supports macOS or Linux and requires Docker 29.4.0,
Go 1.25.6, kubectl 1.35, and outbound HTTPS access to the pinned kind GitHub
release asset:

```bash
npm run local:observability:run
```

Success is exactly
`Local observability manifest passed: ready=true internal=true no_egress=true spans=1 sink=true cleanup=true.`
Failures are exactly `Local observability manifest failed: <category> rejected.`
The only failure categories, in order, are `build, cleanup, configuration, deadline, normalization, ownership, panic, provider, readiness`.

The runner creates and uses its own kubeconfig and exact-owned disposable kind
cluster. It does not read `.env`, ambient kubeconfig, cloud credentials,
profiles, proxy variables, or provider data. Provider caches are not owned:
shared images are read-only baselines and are never cleaned.

The runner applies the staged Job only after the Collector pod and EndpointSlice
are exact and Ready. The Job sends exactly one fixed synthetic M1-21 span to a
cluster-internal ClusterIP OTLP Service. There is no host-published OTLP port.
The Collector writes to a file-backed `emptyDir` sink, which is ephemeral and
read exactly through its sidecar.

`no_egress=true` is a configuration-level claim: the Collector configuration
contains no remote exporter, destination, credential, proxy, or backend. It is
not NetworkPolicy or firewall enforcement.

OpenTelemetry Collector Contrib is Apache-2.0 and BusyBox is GPL-2.0-only.
The exact targets are
`otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5`
and
`registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9`.
They are opt-in local development targets: this proof does not approve
redistribution or production packaging, and bundled components retain their
own terms. Aggregate M1-30 verification is In progress.

## Local AWS emulator Kubernetes manifest proof

M1-30d is Complete. The selected boundary adds an exact-pinned LocalStack
S3 Deployment and internal ClusterIP Service to the disposable local cluster.
An exact ConfigMap supplies `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_S3` to a
staged one-shot synthetic client Job only after LocalStack is Ready. The Job
makes one explicit endpoint-bound S3 list request with synthetic credentials
fixed to non-secret local values and emits one fixed evidence line.

Run the hermetic contracts and immutable LocalStack Community license audit
from the repository root with pinned Node 22.23.1 and npm 10.9.8:

```bash
npm run local:aws-emulator:test
npm run local:aws-emulator:license
```

The opt-in live proof additionally requires Docker, network access for exact
immutable artifact resolution, and an otherwise disposable local runtime. Run:

```bash
npm run local:aws-emulator:run
```

Success is exactly
`Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.`
Failures are exactly
`Local AWS emulator manifest failed: <category> rejected.` The runtime stages
`localstack-s3-probe` only after exact LocalStack readiness, keeps both
endpoint variables internal to the cluster, and removes only resources it can
freshly re-prove as proof-owned.

This task does not expose LocalStack on the host, reuse a shared LocalStack
target, persist emulator state, read ambient AWS or Kubernetes authority, or
wire product AWS clients. M1-31 is Complete and owns product client-factory
consumption of the endpoint contract. M1-30 is Complete after its separate
assembled local start target passed live verification, cleanup audit,
repository gates, scans, and review.

## LocalStack-aware AWS client factory

M1-31 is Complete. It provides one strict factory for production, local, and CI
construction of SQS, S3, KMS, Secrets Manager, and OpenSearch Service clients.
Run its hermetic tests with:

```bash
npm run aws:client:test
```

Production requires explicit region, credential-provider, and HTTP-client
authority and accepts no endpoint override. Local and CI require the exact
`AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_S3` keys through an injected lookup;
the values must be equal and match the reviewed local or numeric-loopback
form. Those modes replace credential authority with fixed synthetic values,
disable SDK retries, and use a bounded proxy-free HTTP client. The factory
does not read ambient environment, profile, IMDS, web-identity, proxy, dotenv,
or Kubernetes authority.

The tests route five real SDK read operations to one bounded loopback capture
server and assert exact signing and S3 path-style behavior. This boundary does
not create a LocalStack lifecycle or provider resource and does not claim
LocalStack parity. M1-30 is Complete; M1-31 is Complete. M1-32 is Complete
and owns the exact session/runtime event index-template contract.

## OpenSearch session/runtime event template

M1-32 is Complete. Its product-owned contract serializes one deterministic
template for `zasp-session-runtime-events-v1-*` and validates documents against
exactly 12 fields. Run the hermetic contract from the repository root with
pinned Go 1.25.6:

```bash
npm run event:index-template:test
```

The mapping fixes `index.mapping.total_fields.limit=12`, uses `dynamic: strict`,
and assigns an explicit `ignore_above` bound to every keyword field. Its
1,024-field mapping-explosion fixture proves that attacker-controlled dynamic
field names are rejected. The timestamp is the only date field.

This task does not apply the template or perform provider I/O, and it does not
claim OpenSearch or LocalStack parity. It also makes no tenant-isolation claim:
M1-39 owns cross-Organization query and indexing enforcement. M1-31 is Complete,
M1-32 is Complete, and M1-33 is Complete with three exact product SQS queues
and paired DLQs, closed schema metadata, and bounded baseline settings.

## SQS queue definitions proof

M1-33 owns three Standard source queues and their paired dead-letter queues:

| Source queue | Dead-letter queue | Schema ID | Source visibility |
| --- | --- | --- | --- |
| `agentsec-background` | `agentsec-background-dlq` | `agentsec.background.v1` | 300 seconds |
| `agentsec-runtime-events` | `agentsec-runtime-events-dlq` | `agentsec.runtime-events.v1` | 120 seconds |
| `agentsec-tests` | `agentsec-tests-dlq` | `agentsec.tests.v1` | 900 seconds |

The source visibility sequence is exactly 300 / 120 / 900 seconds. Every
source uses 345600-second retention, 20-second long polling, 262144-byte
maximum messages, zero delay, and `maxReceiveCount=5`. Every DLQ uses
1209600-second retention, 30-second DLQ visibility, the same long-poll and
message-size bounds, zero delay, and an exact paired-source redrive-allow
policy.

Run the hermetic contract or the opt-in disposable lifecycle from the
repository root:

```bash
npm run sqs:definitions:test
npm run sqs:definitions:run
```

Live success is exactly
`LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true container_cleanup=true.`
Failures are exactly
`LocalStack queue definitions failed: <category> rejected.` The live command
creates a disposable LocalStack container, uses only its numeric-loopback SQS
endpoint, proves all six resources, and removes its exact container and build
directory. It does not read or mutate a shared LocalStack container, real AWS,
ambient credentials, profiles, proxies, IMDS, or customer state.

This proof does not implement producer or consumer wiring; M1-41 owns that
work. M1A-04 owns replay and DLQ-recovery behavior, and M8-03 owns production
operations. M1-32 is Complete, and M1-33 is Complete after reviewed live
evidence. M1-34 is Complete with the exact evidence, export, and policy key
layout plus customer-managed SSE-KMS configuration contract.

## S3 bucket layout

M1-34 is Complete. It defines one provider-neutral layout beneath the exact prefix
`organizations/<organization-product-id>/workspaces/<workspace-product-id>/environments/<environment-product-id>/<class>/`.
The only class segments are `evidence`, `exports`, and `policies`; callers add
one validated opaque product ID as the final object-key segment. The builder
accepts no raw key, suffix, filename, path, or provider-native identifier, so
constructed keys cannot escape the validated Organization, Workspace, and
Environment scope.

Run the hermetic race-enabled contract from the repository root:

```bash
npm run s3:bucket-layout:test
```

Configuration requires the exact bucket form
`zasp-product-data-<32-lowercase-hex>` and one customer-managed KMS key ARN in
the same partition, Region, and account. Encryption is fixed to `aws:kms` with
the validated ARN and S3 Bucket Key enabled.

This contract does not perform provider I/O and does not define IAM,
versioning, retention, or lifecycle policy. M1A-03 owns the staging S3 and KMS
resources, while M8-02 owns production hardening. M1-33 is Complete. M1-35 is
Complete, aligning the product shell, left navigation, and future
unauthenticated-route guard with the exact PRD information architecture.

## Assembled local development target

M1-30 is Complete. M1-30a, M1-30b, M1-30c, and M1-30d are Complete. The
canonical start-and-verify target requires Node.js `22.23.1` and npm `10.9.8`,
plus the Docker, Go, kubectl, kind asset, and network prerequisites of the
reviewed profiles:

```bash
npm run local:start
```

The opt-in command delegates once to the reviewed M1-30d assembly. It creates
one disposable kind cluster, proves the product, graph, observability, and
LocalStack S3 profiles together, then performs reverse cleanup. All workload
services remain ClusterIP-only, with no Ingress, NodePort, LoadBalancer, or
host workload port, so vendor dashboards are not published outside the
cluster. The command uses its own Docker configuration and kubeconfig and
never reads the ambient kubeconfig, dotenv, cloud credentials, profiles,
proxies, or customer state. It reuses the reviewed graph, observability, and
AWS emulator immutable license audits without adding redistribution approval.

Success is exactly
`Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.`
Failures are exactly
`Local AWS emulator manifest failed: <category> rejected.` The target does not
leave the cluster running, modify shared resources, or wire product AWS
clients. M1-31 is Complete and owns product client-factory consumption of
the endpoint contract.

## Neon pooled proof

The isolated proof module requires Go `1.26.5`. It reads only `DATABASE_URL`,
validates a TLS-required Neon URL, and uses the corresponding pooled endpoint
without changing the ignored `.env` value.

```bash
npm run proof:neon:test
set -a
source .env
set +a
npm run proof:neon:run
```

## Neon migration proof

This proof requires the ignored `DATABASE_URL`, `NEON_API_KEY`, and
`NEON_PROJECT_ID` values. It accepts a validated direct or pooler parent URL,
then uses the official Neon API to match exactly one canonical direct endpoint
inside that project. The proof creates one proof-owned disposable branch and
compute, always connects through the child direct endpoint, runs the versioned
migration up and down, checks the baseline, then deletes the branch. Output
stays fixed and contains no provider or database identifiers.

```bash
npm run proof:neon:migration:test
npm run proof:neon:migration:run
```

Run that sequence from the repository root. The command uses Node's dotenv loader.
It emits a fixed summary and never prints connection-string fields or query
results.

## LocalStack SQS proof

This isolated Go proof reads only `AWS_ENDPOINT_URL` from the ignored `.env`,
requires the configured loopback LocalStack HTTP endpoint, and supplies fixed
non-secret local credentials and region directly to the official AWS SDK v2.
It creates a uniquely tagged Standard queue and DLQ, asserts both redrive
policies, sends one batched message containing two Organization-scoped
normalized events, validates and deletes it, proves the queue empty, and
deletes only its freshly re-proven resources in source-then-DLQ order.

```bash
npm run proof:localstack:sqs:test
npm run proof:localstack:sqs:run
```

The live command performs a second exact-prefix absence audit and emits fixed
output without queue, account, message, payload, tag, or endpoint identifiers.
This is supported local behavior evidence, not real-AWS IAM or release-parity evidence.

## LocalStack storage proof

This proof starts an exact-pinned, proof-owned disposable LocalStack 4.7.0 container
with only S3, KMS, and Secrets Manager enabled on a random loopback port. It does
not stop, restart, reconfigure, or delete the shared development container. The Go
proof supplies fixed local credentials directly to the official AWS SDK v2, creates
a tagged symmetric KMS key, and verifies direct encrypt/decrypt before exercising
S3 and Secrets Manager with that exact key.

The S3 fixture uses path-style requests, default and explicit SSE-KMS settings, an
Organization-scoped object key, exact metadata/tags, and body/digest integrity. The
secret fixture uses atomic proof tags and the same KMS key. Cleanup re-proves every
current resource before deleting the secret, object, bucket, and alias; it schedules
only the proof key for the minimum deletion window, audits zero active resources and
the exact pending key, then removes and proves absence of only the disposable
container.

```bash
npm run proof:localstack:storage:test
npm run proof:localstack:storage:run
```

The commands need Docker and Go but no credential or dotenv input. Output is fixed
and omits payloads, endpoints, ports, tags, ETags, resource/container identifiers,
SDK errors, and credentials. This is supported local SDK evidence, not real-AWS encryption, IAM, durability, recovery, or release-parity evidence.
R-03 remains open until M0-09 supplies the separate real-AWS authorization proof.

## OpenSearch event projection proof

This proof starts an exact-pinned, proof-owned disposable OpenSearch 3.8.0
single-node target on a random loopback port. It creates a strict metadata-only
event index and writes exactly one normalized session event for Organization A
through a narrow scoped `EventStore`. An exact Organization, session, and
Environment query returns that event once for Organization A; the identical
session and Environment query returns zero hits for Organization B.

The runner preflights its generated prefix, bounds readiness and all HTTP
operations, reconciles ambiguous mutations through exact current state, and
re-proves the index mapping, settings, ownership metadata, and document before
cleanup. It audits zero remaining generated-prefix indexes, then removes and
proves absence of only its exact disposable container. It never addresses
shared development services, and its fixed output omits endpoints, ports,
indexes, documents, markers, image references, container identities, and
provider errors.

```bash
npm run proof:opensearch:event:test
npm run proof:opensearch:event:run
```

The commands require Docker and Go but no credential or dotenv input. Security
is disabled only inside the disposable local test target. This is supported local
projection behavior evidence, not AWS OpenSearch Service, IAM, durability, recovery, or release-parity evidence.
OpenSearch remains a rebuildable query projection rather than the durable SQS/S3
event source of truth.

## OpenSearch EventStore proof

This product-boundary mode reuses the same exact-pinned, proof-owned disposable
OpenSearch target while exercising `services/platform/eventstore`. Every index
and search operation requires an exact Organization, Workspace, Environment,
and session scope. The proof indexes one canonical runtime-gateway tool event,
requires one exact Organization A result, and proves that the same session under
Organization B returns zero results before exact cleanup and prefix-wide audit.

```bash
npm run event:store:test
npm run event:store:run
```

The hermetic test command performs no Docker or provider operation. The live
command accepts no dotenv, cloud profile, proxy, credential, or shared service
input; it creates only its generated M1-14 container on a random loopback port.
This local compatibility evidence does not prove AWS OpenSearch Service, IAM,
durability, encryption, availability, retention, rebuild, or release parity.

## Provisional LocalStack IAM compatibility proof

This isolated proof starts an exact-pinned, proof-owned disposable LocalStack
target with IAM and STS only, on a random loopback port. Docker and Go are required.
No credentials are accepted, and IAM enforcement is mandatory.

The proof uses two fixed account values as emulator namespaces. They do not
establish AWS account isolation. It demonstrates a LocalStack-only assumed-role
allowed read, explicit deny, and cleanup result, not real-AWS parity.

```bash
npm run proof:localstack:iam:test
npm run proof:localstack:iam:run
```

The runner accepts no dotenv input, never uses shared development LocalStack,
and emits only a fixed result line. PROV-01 cannot complete M0-09 or R-03.
PROV-01 is Blocked on LocalStack 4.7.0 because the live provider did not return
SourceIdentity and accepted a wrong SourceIdentity despite the required trust
condition. M0-10 is Complete under the Cartography delivery waiver for a
fixture-only normalization and OSS integration proof; it makes no AWS/GitHub
authorization-parity claim. Official LocalStack v4.14.0 source retains the
same unsupported forwarding path; that is source review only, not a claim that
v4.14.0 was live-tested.

## Cartography Organization-scope proof

This proof requires Docker and Python 3.13.11; the test command invokes the
repository's pinned `/opt/homebrew/bin/python3.13` interpreter. It is a
two-Organization fixture-only proof using only the two synthetic `.test`
fixtures. It accepts no dotenv, credential, or proxy input and makes no AWS or GitHub calls.

The disposable runtime loads each fixture into its proof-owned Cartography and
Neo4j containers, compares the isolated normalized graphs, and applies
customer-label normalization so customer-visible node and relationship labels
do not expose Cartography, Neo4j, AWS, or GitHub implementation names. It
cleans up only its exact proof-owned containers, network, and temporary
directories, then verifies their absence. The live command emits only this
fixed result on success:

```text
Cartography scope proof passed: fixtures=2 nodes=8 relationships=4 isolated=true labels_safe=true cleanup=true.
```

```bash
npm run proof:cartography:test
npm run proof:cartography:run
```

This fixture-only integration proof does not prove AWS/GitHub authorization parity. M0-10 is Complete; M0-09 and PROV-01 remain Blocked, and R-03 remains incomplete.

## Prowler evidence proof

M0-11 is Complete as a fixture-only evidence proof. Its hermetic test command
requires Node.js `22.23.1` and npm `10.9.8`, plus Python `3.13.11`; it does not
start Docker or contact a provider. The live command additionally requires
Docker and uses only these exact-pinned images:

- `prowlercloud/prowler:5.39.0@sha256:58c8a0eb0c947517bd89b6214cde0cc1d5f59df4eebbb99a87475ab741914959`
- `localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c`

The live proof creates one private disposable Docker network and one synthetic IAM role,
then runs only the built-in
`iam_role_cross_service_confused_deputy_prevention` check. It retains one
JSON-OCSF result and maps it to the canonical Organization-scoped resource
identity established by M0-10. The commands accept no dotenv, credential,
profile, proxy, provider endpoint or network-target input, disable IMDS, and do
not load host Docker authentication. Only fixed synthetic credentials reach
the disposable LocalStack fixture.

The license audit binds the exact local image metadata to immutable tagged source
fingerprints without reading dotenv files, provider credentials, profiles, proxy
settings, or ambient Docker authentication. Prowler 5.39.0 and its direct
`py-ocsf-models` 0.10.0 adapter dependency are Apache-2.0. The exact free/community
LocalStack Community image is inventoried at the tagged source boundary as
Apache-2.0 plus its tagged community EULA; bundled third-party components retain
their own terms and are not relicensed or covered by that statement.

The live command emits exactly one line. Its fixed success line is:

```text
Prowler evidence proof passed: findings=1 resources=1 evidence=1 linked=true cleanup=true.
```

Every failure uses the fixed line
`Prowler evidence proof failed: <category> rejected.`, where the category is one of `configuration`, `provider`,
`ownership`, `normalization`, `cleanup`, or `operation`. Cleanup re-proves and
removes only the exact proof-owned containers, network, output, and temporary directories,
then verifies their absence.

```bash
npm run proof:prowler:test
npm run proof:prowler:license
npm run proof:prowler:run
```

This fixture-only evidence does not prove real-AWS authorization or parity,
broad Prowler coverage, LocalStack IAM parity, or production runner behavior.
R-06 is PASS with the retained reviewed M0-11 live evidence. M0-09 and PROV-01
remain Blocked, and R-03 remains incomplete.

## OTLP ingest proof

M0-13 provides a local ingest-only proof using Node.js `22.23.1` and npm `10.9.8`.
The hermetic command validates the source trace, strict product
adapter, Collector configuration, stable artifact boundary, exact Docker
ownership, deadlines, fixed output, and cleanup without starting Docker. The
disposable live command uses this immutable Collector Contrib image:

`otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5`

The live lifecycle publishes only the OTLP/HTTP receiver to a random
loopback-only host port. Its Collector pipeline writes to an exact-owned local
artifact for the product adapter; remote OTLP export is disabled. The one
synthetic span carries only bounded Organization, agent, session, task, tool,
and sandbox identifiers. It carries no raw prompts, tool arguments, credentials, or customer payloads.

```bash
npm run proof:otlp:test
npm run proof:otlp:run
```

Success is exactly:

```text
OTLP ingest proof passed: traces=1 spans=1 identity=true cleanup=true.
```

M0-13 is Complete after two consecutive final-code live runs, exact zero-resource
cleanup audits, pinned local gates and scans, and zero-finding independent
review.

This proof establishes local Collector-to-adapter identity preservation only.
Together with M0-22's bounded export/failure proof, this retained ingest
evidence makes R-12 PASS. M0-09 and PROV-01 remain Blocked, and R-03 remains
incomplete.

## OTLP export proof

M0-22 is Complete. It runs an exact-pinned source Collector and fake
sink Collector on one private internal proof network. The first bounded
synthetic operation must reach the sink; after the exact sink is stopped, the
next application operation must still complete within its independent bound.

The proof accepts no hosted telemetry endpoint, credential, dotenv, profile,
proxy, ambient Collector configuration, arbitrary destination, or customer
payload.

```bash
npm run proof:otlp-export:test
npm run proof:otlp-export:run
```

Success is exactly:

```text
OTLP export proof passed: delivered=true bounded=true exporter_failed=true application_unblocked=true cleanup=true.
```

Two consecutive final-code live passes proved first delivery, exact exporter
failure, nonblocking application progress, and exact cleanup. Combined with
the retained M0-13 ingest evidence, R-12 is PASS.

## M0 technical proof gate

M0-23 is Complete as an evidence-only architecture gate. It records one
decision for every M0 risk boundary without rerunning provider or container
proofs. The selected decision is **PROCEED WITH BLOCKED PATHS**. The completed
gate authorizes M1 foundation work after this exact completion SHA passes CI,
but R-03 continues to block real-AWS IAM parity claims and R-11 continues to
block EKS Fargate strong-isolation and egress claims. Neither blocker may be
replaced by LocalStack, fixture-only, source-review, or harness-only evidence.

The current record is `12 PASS / 2 BLOCKED / 0 FAIL / 0 unclassified` in
`docs/decisions/m0-technical-proof-gate.md`. The two blocked decisions are
R-03, awaiting M0-09's isolated real-AWS fixture, and R-11, awaiting M0-18 and
M0-19's isolated real-EKS fixtures.

## PostHog privacy proof

M0-20 is Complete. It proves one allowlisted product analytics event against
a fake PostHog endpoint on a random loopback port. The serializer constructs a
closed event document and rejects seeded prompt, secret, IP-address, and raw-
evidence fields before any network request. It reads no `.env`, credential,
proxy, hosted endpoint, SDK, or ambient PostHog configuration.

```bash
npm run proof:posthog:test
npm run proof:posthog:run
```

Success is exactly:

```text
PostHog privacy proof passed: event=true prompt=false secret=false ip=false evidence=false cleanup=true.
```

Failures are one fixed category line. No raw event, seeded prohibited value,
URL, port, HTTP body, stack trace, or error reaches output. This local proof
does not claim hosted PostHog availability, account configuration, feature-
flag behavior, or production analytics delivery. The exact local proof,
privacy rejections, cleanup, gates, scans, and review passed, so R-13 is PASS.
M0-09, M0-18, M0-19, and PROV-01 remain Blocked.

## OpenRouter privacy proof

M0-21 is Complete. Its local-only boundary sends one redacted synthetic
finding explanation to a fake OpenRouter-compatible endpoint on a random
numeric-loopback port, then accepts only one closed structured explanation
schema. It reads no `.env`, real credential, hosted endpoint, SDK, proxy,
profile, or ambient provider/model configuration.

```bash
npm run proof:openrouter:test
npm run proof:openrouter:run
```

Success is exactly:

```text
OpenRouter privacy proof passed: explanation=true secret=false pii=false structured=true cleanup=true.
```

The product gateway constructs one closed request, removes all seeded secret,
person-name, email, phone, and raw-evidence values, then rejects residual
prohibited material before I/O. The endpoint and client require exact bounded
OpenRouter-compatible request/response documents; product state accepts only a
closed finding-explanation schema. Cleanup closes the retained loopback server
under an independent deadline, and failures emit only a fixed category line.
This is local privacy/schema evidence, not hosted OpenRouter availability,
provider/model quality, production routing, or planner authorization. The exact
proof, seeded-value absence, strict structured validation, cleanup, gates,
audit, scans, and adversarial review passed. M0-21a is Complete, and the
combined explanation/privacy and fixed-action-catalog evidence makes R-14 PASS.

## Security Agent planner boundary proof

M0-21a is Complete. Its local-only boundary sends one structured planning
request containing bounded untrusted injection text, an exact two-action
catalog, and exact in-scope IDs to a fake OpenRouter-compatible endpoint on a
random numeric-loopback port. Product validation must accept only the exact
catalog actions and in-scope identifiers.

The proof has no hosted model, real credential, SDK, dotenv, proxy, profile,
arbitrary network target, general shell, or execution authority. Root commands
are hermetic and contact only the retained numeric-loopback fake endpoint:

```bash
npm run proof:planner:test
npm run proof:planner:run
```

Success is exactly:

```text
Security Agent planner proof passed: catalog=true scope=true injection=false url=false shell=false cleanup=true.
```

The exact proof, six focused runs, full pinned repository gates, production
audit, redacted scans, and adversarial review passed. Combined with M0-21's
redacted explanation proof, R-14 is PASS. M0-22 is Complete and R-12 is PASS.

## EKS Fargate egress proof

M0-19 is Blocked. Its reviewed fail-closed harness is ready to prove the second
half of R-11 against real EKS Security Groups for Pods: one exact
`SecurityGroupPolicy`, a pre-provisioned read-only restricted Pod security
group, and one fresh Fargate canary Job. The required evidence is direct
undeclared HTTPS failure, the same named canary through the product egress
proxy, exact EC2 security-group rules, exact Pod ENI attachment, and reverse
zero-resource cleanup.

This is a real EKS Security Groups for Pods proof boundary.

Run the hermetic lifecycle, strict kubectl/EC2 boundary, supervisor, and audit
tests with `npm run proof:fargate-egress:test`. The live entry point is
`npm run proof:fargate-egress:run`; it requires every documented task-specific
real-provider input before building or making a request. Its only success line
is `EKS Fargate egress proof passed: direct_denied=true proxy_allowed=true eni_attached=true cleanup=true.`
Failures are fixed as `EKS Fargate egress proof failed: <category> rejected.`
Run `npm run proof:fargate-egress:license` to bind the immutable multi-platform
BusyBox image, Kubernetes packaging, and underlying GPL runtime.

The capability audit found 0/19 required inputs: no authenticated disposable
real EKS/EC2 fixture, Fargate profile, restricted Pod security group, product
proxy endpoint, or canary credential. The fixed configuration gate rejects
before building or making a cluster or AWS request. LocalStack cannot provide
AWS-managed Fargate, branch-ENI, or real EKS Security Groups for Pods authority
and cannot emit success. Resume only after all documented task inputs are
available for an isolated disposable real-EKS test fixture. M0-18 remains
Blocked, R-11 remains Not run, and M0-20 is In progress.

## EKS Fargate verification proof

M0-18 is Blocked. The reviewed fail-closed harness is ready for one canary Job
on an explicitly supplied real EKS Fargate disposable test profile. The live
gate requires the selected Pod to bind to the named profile, its assigned node
to report the Fargate compute type, the canary to receive the exact response
through the product proxy, and every proof-owned Kubernetes resource to be
absent after cleanup.

Run the hermetic lifecycle, kubectl-boundary, supervisor, and audit tests with
`npm run proof:fargate:test`. The inert live entry point is
`npm run proof:fargate:run`; it rejects at configuration before building or
contacting a cluster unless all eleven documented real-provider inputs are
present. Its only success line is
`EKS Fargate proof passed: scheduled=true canary=true cleanup=true.` Run
`npm run proof:fargate:license` to bind the immutable multi-platform image,
Kubernetes mirror commit and Apache-2.0 packaging, and the underlying BusyBox
1.36.1 GPL-2.0-only runtime. The packaging license does not relicense BusyBox.

The capability audit found 0/11 required inputs: no real-AWS credential,
authenticated EKS kubeconfig, disposable Fargate profile, product proxy
endpoint, or test canary credential, so the harness performs no cluster
request. LocalStack can exercise generic EKS
and Kubernetes compatibility with embedded k3s/k3d nodes, but it cannot prove
Fargate. R-11 remains Not run; M0-19 is Blocked. M0-09 and PROV-01 remain
Blocked, and R-03 remains incomplete.

## OPA SDK proof

M0-17 is Complete. It evaluates one Allow and one Block decision with OPA
v1.17.0 through the exact-pinned official OPA Go SDK embedded in-process. The
proof prepares one fixed internal policy query, performs 100 warm-ups per decision and 1,000
measured evaluations per decision, and requires each decision-specific p95 at
or below 10 ms. It has no server, subprocess, bundle, network call, customer
Rego, or environment configuration.

Run `npm run proof:opa:test` for race-enabled evaluator tests,
`npm run proof:opa:run` for the direct in-process proof, and
`npm run proof:opa:license` for the immutable official tag, module-sum, and
Apache-2.0 audit. Direct success is exactly
`OPA SDK proof passed: allow=true block=true deterministic=true evaluations=2000 p95_under_10ms=true.`
Two consecutive direct final-code proofs, six race runs, exact dependency and
license audits, full pinned repository gates, and whole-range review passed.
R-10 is PASS. M0-18, M0-09, and PROV-01 are Blocked, and
R-03 remains incomplete.

## Promptfoo red-team proof

M0-16 is Complete. It runs one direct prompt-injection case through the
exact-pinned official Promptfoo 0.121.19 engine against a local fake agent on a
private internal Docker network. The product boundary will retain only the
objective, verdict, and evidence reference; raw prompts, target responses,
Promptfoo-native identifiers, and Docker state must remain outside product
output. The proof uses only synthetic local inputs, no hosted generation, and
no host-published port, and no model or provider credential.

Run `npm run proof:promptfoo:test` for the hermetic suite,
`npm run proof:promptfoo:license` for the immutable source/image/MIT audit, and
`npm run proof:promptfoo:run` for the disposable live lifecycle. Docker prerequisite:
a running local Docker engine with the exact image available or pullable. Live
success is exactly
`Promptfoo red-team proof passed: objective=true verdict=vulnerable evidence=true cleanup=true.`
Only the objective, verdict, and evidence reference are retained; raw prompts, target responses, canaries, Promptfoo-native identifiers, and Docker state
are excluded from product output. Two consecutive final-code live passes,
exact zero-resource cleanup, pinned gates, immutable license and secret scans,
and a zero-finding whole-range review passed. R-09 is PASS.

## Nango proxy proof

M0-15 is Complete. It proves one authenticated provider GET through the
exact-pinned free self-hosted Nango Proxy surface against a private TLS fixture.
The fixture first accepts Nango's exact API-key introspection request, then one
distinct bearer-authenticated `GET /api/v2/events?limit=1`. The product wrapper
calls that provider endpoint only through Nango's authenticated Proxy route and
retains scoped opaque references plus the allowlisted event ID and action.

The hermetic command tests parsing, the ordered fixture, product secrecy,
immutable manifests, exact Docker ownership, bounded mutation settlement,
fixed output, and cleanup without starting Docker. The live command requires
Node.js 22.23.1, npm 10.9.8, Docker, and OpenSSL. It reads no `.env`, profile,
cloud/provider credential, proxy variable, or ambient Docker authentication;
the private internal network publishes no host port.

```bash
npm run proof:nango:proxy:test
npm run proof:nango:proxy:run
```

Success is exactly:

```text
Nango proxy proof passed: get=true response=true product_state_safe=true cleanup=true.
```

The raw provider token, Nango environment key, connect token, database
password, and encryption key never enter product state or fixed output. Two
consecutive final-code live runs, exact zero-resource audits, pinned gates,
license/secret scans, and a zero-finding whole-range review passed.
R-08 is PASS at M0-15.

## Nango free Auth boundary

M0-14 is Complete. The accepted free self-hosted Nango MVP boundary is
long-tail Auth plus Proxy; M0-15 now supplies the authenticated Proxy GET.
Functions, Webhooks, and MCP are out of scope, as are Nango RBAC, full
observability, Connect UI, and Enterprise-only features.

This boundary consolidates the completed M0-14a boot, M0-14b OAuth, and M0-14c
API-key evidence. It adds no runtime or provider call and is not a claim that
every excluded route is absent from the pinned image. Core launch connectors
remain product-owned and bypass Nango. R-08 is PASS at M0-15;
M0-09 and PROV-01 remain Blocked, and R-03 remains incomplete.

## Nango API-key proof

M0-14c is Complete. This proof extends the completed private Nango boot and
OAuth boundaries with one real API-key connection through exact-pinned Nango
v0.70.5 and PostgreSQL 16.0. A generated raw provider key is checked once by
the built-in `1password-events` integration against a private TLS fixture at
`events.1password.com`; the fixture accepts only the exact bearer-authenticated
`GET /api/v2/auth/introspect` request.

The hermetic command validates the workspace, fixture, product wrapper,
immutable four-role manifest, exact Docker ownership, bounded mutation
settlement, fixed output, and cleanup without starting Docker. The live command
requires Node.js 22.23.1, npm 10.9.8, Docker, and OpenSSL. It accepts no `.env`,
real credential, provider endpoint, proxy, profile, or ambient Docker
authentication and publishes no host port.

```bash
npm run proof:nango:api-key:test
npm run proof:nango:api-key:run
```

Success is exactly:

```text
Nango API key proof passed: api_key=true reference=true product_state_safe=true cleanup=true.
```

The product receives only the Organization-scoped durable connection reference.
The raw provider key never enters product state or fixed output. Every live run
uses fresh marker-scoped resources and reverse exact-owned cleanup. R-08 is
PASS at M0-15; M0-09 and PROV-01 remain Blocked, and R-03 remains
incomplete.

## Nango OAuth proof

M0-14b extends the completed Nango free-boot proof with one real OAuth2
authorization-code connection against a private, synthetic TLS fixture provider.
The disposable runtime contains PostgreSQL, Nango v0.70.5, the fixture, and a
one-shot product wrapper on one internal Docker network with no host port
publication. It reads no `.env`, cloud credential, profile, proxy, or ambient
Docker authentication state.

The hermetic command validates the strict wrapper and fixture parsers, PKCE and
single-use behavior, exact image/runtime ownership, bounded mutation settlement,
fixed output, and cleanup without starting Docker. The live command generates a
fresh CA, server certificate, client credentials, authorization code, access
token, database password, and encryption key. Product output retains only the
Organization-scoped durable connection reference; seeded secrets, the Nango API
key, and the connect-session token never cross that boundary.

```bash
npm run proof:nango:oauth:test
npm run proof:nango:oauth:run
```

Success is exactly:

```text
Nango OAuth proof passed: oauth=true reference=true product_state_safe=true cleanup=true.
```

Every live run uses fresh marker-scoped resources and reverse exact-owned
cleanup. M0-14b is Complete after two consecutive final-code live passes,
complete zero-resource audits, full repository gates and scans, and a
zero-finding pre-landing review. R-08 is PASS at M0-15. M0-14c and M0-15 are
Complete.

## Nango free boot proof

M0-14a proves the current free self-hosted Nango server can boot with only its
required PostgreSQL dependency and become database-ready from a product-side
test client on a private internal Docker network. The exact Nango v0.70.5,
PostgreSQL 16.0, and BusyBox probe images are pinned by immutable digest.
Neither service publishes a host port.

The hermetic command validates pins, the free Auth/Proxy boot configuration,
strict readiness parsing, synthetic database/encryption material, complete
Docker ownership, bounded mutation settlement, fixed output, and cleanup
without starting Docker. The live command creates a fresh marker-scoped
database and encryption key, prepares the exact upstream-required `nango` and
`nango_records` schemas inside that isolated database, polls PostgreSQL, then
requires the one-shot product probe to receive exactly `{"result":"ok"}` from
Nango's database-backed `/ready` endpoint.

```bash
npm run proof:nango:test
npm run proof:nango:run
```

Success is exactly:

```text
Nango free boot proof passed: services=2 ready=true product_network=true cleanup=true.
```

The proof does not read `.env`, profiles, cloud credentials, product database
credentials, proxy settings, or ambient Docker authentication. Redis,
Elasticsearch, Connect UI, RBAC, orchestration, and Enterprise mode are absent
or disabled in the exact boot configuration. The proof does not invoke or
depend on Functions, Webhooks, or the MCP server, but does not yet prove those
routes unreachable. It proves minimum free boot and private product-network
readiness only; OAuth, API-key connection, and authenticated Proxy proof were
completed in M0-14b through M0-15.

M0-14a is Complete after two consecutive final-code live runs, exact zero-
resource audits, full gates/scans, and an independent zero-finding review.
R-08 is PASS at M0-15. M0-09 and PROV-01 remain Blocked, and R-03
remains incomplete.

## Tetragon signal proof

M0-12 is Complete under the approved observation-only design. The two consecutive final-code live runs
proved that one exact-owned disposable Kubernetes workload
emitted process, file, and outbound TCP events. The proof retained the same Kubernetes workload identity
and explicit capability and drop state, with zero drop/loss counters.

The selected immutable runtime includes:

- `quay.io/cilium/tetragon:v1.7.0@sha256:deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527`
- `quay.io/cilium/tetragon-operator:v1.7.0@sha256:074ffbd19208eed79f68e191ed606e05009f910b4bb5148efcf2973e13504b82`
- `kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95`

Run the hermetic parser, manifest, and lifecycle tests with Node.js 22.23.1:

```bash
npm run proof:tetragon:test
```

The disposable live proof requires Docker, kind 0.32.0, Helm 3, and kubectl on
the explicit tool path. It downloads and verifies the pinned kind binary and
Helm chart, uses an owned Docker configuration and kubeconfig, and does not load `.env`,
ambient kubeconfig, cloud credentials, profiles, or proxy variables. Run it with:

```bash
npm run proof:tetragon:run
```

Success is exactly:

```text
Tetragon signal proof passed: process=true file=true network=true identity=true capability=true drops=0 cleanup=true.
```

Every lifecycle uses exact-owned cleanup for the namespace, chart, cluster,
node container, network, kubeconfig, downloaded assets, and temporary files.
Failures emit only a fixed category line.

The workload's outbound TCP action targets only an in-cluster fixture sink; it
does not prove internet egress. The proof does not enable enforcement, treat
Tetragon as semantic truth, or claim production-kernel coverage. R-07 is PASS
with retained live, cleanup, gate, license/secret scan, and zero-finding independent review
evidence. M0-09 and PROV-01 remain Blocked, and R-03 remains
incomplete.

## Real AWS cross-account IAM proof

This proof is deliberately real-AWS-only. It requires two explicitly configured,
isolated commercial AWS test accounts: source credentials authorized to assume the
proof role and target-administrator credentials authorized to create and remove
only the unique disposable role. LocalStack cannot satisfy this release-parity authorization gate.

The ignored `.env` must provide these exact task-specific inputs:

- `AWS_M009_ISOLATED_TEST`
- `AWS_M009_REGION`
- `AWS_M009_SOURCE_ACCOUNT_ID`
- `AWS_M009_TARGET_ACCOUNT_ID`
- `AWS_M009_SOURCE_PRINCIPAL_ARN`
- `AWS_M009_SOURCE_ACCESS_KEY_ID`
- `AWS_M009_SOURCE_SECRET_ACCESS_KEY`
- `AWS_M009_TARGET_ADMIN_ACCESS_KEY_ID`
- `AWS_M009_TARGET_ADMIN_SECRET_ACCESS_KEY`

`AWS_M009_SOURCE_SESSION_TOKEN` and
`AWS_M009_TARGET_ADMIN_SESSION_TOKEN` are optional when the corresponding
explicit credential is not temporary. `AWS_M009_ISOLATED_TEST` must equal
`isolated-disposable-aws-test-accounts-only`. Account IDs, role ARNs,
credentials, session values, and provider responses are never printed.

Before mutation, the command authenticates both credential sets, matches the
separately configured expected accounts, proves the accounts differ, and requires
the generated proof path to be empty. It then creates one exactly tagged role
whose trust policy requires a generated external ID, role-session name, source
identity, and session tag. The assumed role can call `iam:GetRole` only for
itself, while an explicit policy denies `iam:ListRoles`. Cleanup independently
re-authenticates the target administrator, re-proves the role, tags, trust and
inline policy, removes them with no mutation retries, and audits the generated
path empty.

```bash
npm run proof:aws:iam:test
npm run proof:aws:iam:run
```

The runner passes only task-specific values to the proof binary; AWS profiles,
shared config, IMDS, ambient proxies, custom endpoints, and provider debug output
are disabled. The current workspace does not contain the task-specific isolated
source/target fixture, so only the deterministic local test command is presently
expected to pass. M0-09 is Blocked and R-03 remains incomplete until the
documented live command proves the real allowed/denied results and exact cleanup
in those isolated accounts. No shared, staging, customer, or production AWS account may be used.

The application uses Vinext and targets the Cloudflare Workers runtime. Optional
local D1 and R2 bindings can be enabled with `CLOUDFLARE_D1_BINDING` and
`CLOUDFLARE_R2_BINDING`; no database or object-storage binding is required for
the browser-local prototype.

Application authentication will use Stytch B2B. The current prototype runs
without an authentication gate until that integration is configured.
