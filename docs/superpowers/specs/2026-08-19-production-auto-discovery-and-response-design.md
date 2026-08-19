# Production Automatic Discovery and Response Design

## Outcome

Zasp must operate as a complete agent-security platform, not only as a web
control plane. A scoped administrator can connect a supported provider,
authorize it without exposing credentials, run or schedule discovery, inspect
durable inventory and evidence, enroll sensors, ingest runtime activity, and
execute governed Security Agent responses. Every visible workflow uses the
production API and durable stores, survives process and browser restarts, and
remains isolated by organization, workspace, and environment.

The v1.5 PRD and its 728-task technical plan remain the governing product
scope. Existing component tests and proofs are reusable evidence, but a task is
production-available only when its behavior participates in the shipped
runtime and passes its production acceptance boundary.

## Current Boundary

The shipped product composes the web application, `agentsec-api`, PostgreSQL,
and Stytch. It exposes 80 durable control-plane operations. Provider sync,
sensor enrollment and ingest, runtime enforcement, and Security Agent
execution are deliberately absent from production composition. The worker,
event-ingest, and runtime-gateway binaries expose health endpoints but do not
run product loops. Their domain packages are mostly memory-backed or proof
adapters.

Consequently, the existing implementation ledger's `Complete` status describes
historical component delivery, not production availability. The audited base
contains 229 production-available tasks, 425 component-only tasks, 61 external
evidence gates, and 13 missing shipping tasks.

## Authority and Data Ownership

PostgreSQL is authoritative for integrations, connection references, syncs,
jobs, snapshots, canonical inventory, source observations, relationships,
evidence metadata, sensors, token hashes, runtime job state, Security Agent
plans/runs/steps/approvals, idempotency, receipts, and audit records.

S3 is authoritative for immutable, checksummed raw provider and runtime-event
evidence. OpenSearch and Neo4j are derived, rebuildable projections. SQS is an
at-least-once transport and never an authority. Provider systems remain the
authority for their native resources; Zasp records scoped observations and
evidence rather than silently inventing provider state.

Every authoritative record and derived document carries exact organization,
workspace, and environment scope. One canonical full-scope product-ID rule is
used across PostgreSQL, S3, OpenSearch, Neo4j, risk projection, audit, and API
responses. Provider-native IDs remain separate attributes.

## Immutable Schema Evolution

Release v10 introduces the discovery and runtime authority:

- integrations and opaque provider-connection references;
- sync attempts, durable jobs, leases, schedules, cursors, and last-good state;
- complete source snapshots, canonical entities, source observations,
  relationships, and evidence references;
- sensors, one-time enrollment-token hashes, rotations, revocations, and
  heartbeat state;
- runtime batches/events, per-stage idempotency, and correlation state;
- a transactional outbox for queue publication.

Release v11 performs the production cutover from generic integration and
inventory payload records to v10 authority. It backfills, validates exact row
equivalence, switches readers and writers, and leaves old rows as read-only
compatibility projections until a later contract migration. Application
rollback is supported only to a version that understands the expanded schema;
schema downgrade is independently data-guarded.

Release v12 introduces Security Agent execution authority:

- definitions and immutable versions;
- trigger receipts, simulations, plans, plan hashes, and evidence bindings;
- runs, ordered steps, action attempts, verification results, and cleanup;
- fresh-auth approvals, expiry, resume state, cancellation, and terminal
  outcomes;
- action idempotency and immutable audit correlation;
- explicit `draft`, `validated`, `supervised`, and `autonomous` activation;
- global, organization, environment, and per-action kill switches.

All releases use exact checksums, semantic fingerprints, RLS, typed database
functions, locked upgrade/downgrade paths, and data-aware rollback guards.
Migrations never rewrite an already released file.

## Provider Authorization and Discovery

Integration creation stores only non-secret configuration and opaque secret or
connection references. AWS, Kubernetes, GitHub, and the launch IdP use
first-party authorization, collection, normalization, evidence, and health
paths. Core launch connectors do not depend on Nango and remain available when
Nango is degraded. Private Nango is limited to explicitly catalogued long-tail
Auth + Proxy integrations. The browser never receives Nango service
credentials, cloud session credentials, or provider refresh tokens.

Every credential class has a declared creator, metadata reader, secret
resolver, rotator, revoker, KMS/storage owner, TTL, audit shape, deletion
policy, and prohibited surfaces. The API can create or bind an opaque reference
but cannot read provider secret material. OAuth terminates at a public,
state-bound return path with PKCE, one-time replay protection, expiry, current
session/scope reauthorization, fixed safe redirects, and no query-string token;
Nango's admin API remains private.

A sync request performs one transaction that authorizes the current exact
scope, creates or replays the durable sync/job, writes its audit record, and
inserts a deterministic outbox event. An outbox publisher claims bounded rows,
publishes the canonical envelope to SQS, and marks it published only after the
provider returns the exact acknowledgement.

The discovery worker:

1. loads the authoritative job and integration by scope and ID;
2. acquires a bounded lease and resolves only opaque credential references;
3. invokes a fixed provider adapter or pinned tool with explicit arguments,
   deadlines, resource limits, bounded output, no shell interpolation, no
   ambient credentials, and fixed egress;
4. uploads raw output and a versioned manifest to immutable S3 keys;
5. strictly parses and validates one complete candidate snapshot;
6. atomically applies observations, entities, relationships, evidence,
   source-owned removals, cursor, counts, and last-good state in PostgreSQL;
7. writes deterministic projection-work records in the same transaction;
8. completes authoritative sync and audit before acknowledging the discovery
   receipt;
9. separate projection workers idempotently update risk, graph, and search and
   report lag/degradation without recollecting or invalidating the snapshot.

A failed or partial collection never replaces the last-good snapshot. The API
labels retained data with its actual freshness and redacted last error. A
multi-replica scheduler claims due schedules with leases, deterministic sync
keys, per-organization fairness, missed-run rules, quotas, and disable/delete
race protection; schedule capability stays absent until this loop is ready.

## Sensors and Runtime Activity

Sensor enrollment returns a credential exactly once. PostgreSQL stores only a
salted hash and lifecycle metadata. Rotation invalidates the previous token;
revocation is immediate. The token resolves exact scope server-side and cannot
be used as a browser or public API credential.

The private event-ingest service authenticates the sensor token, applies its
own source rate limits and request bounds, validates Tetragon or OTLP shapes,
normalizes metadata-only events, and inserts a durable runtime job plus outbox
event. It does not trust scope fields supplied by the sensor.

The runtime worker archives a normalized batch to S3, indexes deterministic
records in OpenSearch, correlates them against canonical inventory, updates
risk/graph projections, commits completion/audit, and acknowledges the queue
receipt last. Each stage is independently idempotent.

The customer-edge runtime gateway uses a distinct audience-bound device
credential, not a sensor or browser token. One-time enrollment, durable
hash/reference, rotation, revocation, signed-policy version/expiry, and replay
protection are server-derived from exact scope. It maintains a bounded signed
policy cache, evaluates supported HTTP and MCP activity locally, emits
metadata-only evidence, and fails according to the configured policy mode
without depending on PostgreSQL or graph access.

## Security Agent Execution

Definitions are durable and versioned. Existing saved definitions are migrated
to inert `draft/configured` state regardless of legacy `enabled` fields. Merely
deploying a worker can never activate them. Activation is a separate fresh-auth
audited mutation, and all execution paths check global, organization,
environment, and action kill switches immediately before side effects.

A simulation freezes current policy,
scope, evidence, capabilities, and topology into a deterministic plan hash.
The server reauthorizes every transition; the worker never trusts authority
copied into a queue message.

Every action implements a fixed typed contract with declared provider,
reversibility, approval rule, freshness rule, timeout, retry class, verifier,
and cleanup. Sensitive action arguments are resolved only inside the worker
from secret references. Approval-required steps pause durably. Approval uses a
fresh human session, records the exact plan hash, expires, and resumes at most
once. Role loss, scope change, evidence drift, cancellation, or approval expiry
fails closed before side effects.

Actions are promoted individually. Production first exposes simulation, then a
supervised internal low-risk action, then a supervised reversible TTL-bounded
containment action. Autonomous support is exposed only for a separately
canaried reversible action. Unsupported Attack Lab, test, export, webhook,
ticket, revocation, or irreversible actions are absent from the server catalog,
planner schemas, capabilities, and UI until their own vertical gate passes.

The worker executes one leased step at a time, persists the provider result,
runs an independent verifier, performs cleanup where required, and records an
immutable audit chain. At-least-once delivery cannot duplicate an external
action because the action idempotency key is stable across retries. An unknown
provider outcome remains unresolved and blocks a fresh attempt until
reconciled.

## Public and Internal APIs

Public OpenAPI adds the production integration authorization/sync/history,
sensor lifecycle/coverage, and Security Agent simulation/run/action/approval
operations already described by the v1.5 plan. Runtime composition and public
OpenAPI remain bidirectionally exact.

All public mutations use current capability and exact active-scope checks,
browser Origin/CSRF or documented PAT semantics, fresh authentication where
required, strict JSON, request/rate/dependency bounds, idempotency, durable
receipts, and audit-before-response. Replays are authorized against current
scope before returning a stored result.

Internal ingest and worker endpoints use separate credentials, listeners,
limits, and network policies. No `/internal`, queue, database, provider admin,
Nango, Neo4j, OpenSearch, or artifact endpoint is publicly routed.

## Frontend Product Flows

The production UI uses the generated client and strict decoders only. It adds:

- connector authorization, connection testing, sync-now, schedule, history,
  last-good freshness, counts, and redacted remediation;
- typed inventory source observations, evidence references, confidence, and
  changed/removed state;
- sensor enrollment, one-time credential copy/acknowledgement, rotation,
  revocation, heartbeat, coverage, drop rate, and degraded states;
- Security Agent simulation, deterministic plan review, fresh-auth approval,
  run progress, cancel, verification, cleanup, and audit backlinks.

Every request aborts on route, scope, capability, or session invalidation.
Mutation ambiguity is retained in the server receipt ledger across reloads.
Sensitive one-time values remain in memory only, are synchronously removed on
fresh-auth/session loss, and never enter URL history, cache, logs, telemetry,
or browser storage. Demo routes and fixtures remain accessible only through
the explicit demo entry and are absent from the production dependency graph.

## Workloads and Least Privilege

The production chart and release contract ship separately buildable images for
web, API, discovery/outbox worker, projection worker, runtime worker,
event-ingest, Security Agent action worker, and runtime gateway. A shared
compiled binary may expose explicit process modes, but no deployment can gain
the union of their privileges. Provider tools use a separate digest-pinned
runner or isolated Job.
Nango and Neo4j are private managed endpoints or explicitly operated internal
dependencies; neither is exposed to browsers.

Each workload has its own unshared service account and role:

- web: no cloud identity;
- API: database, exact secret references, and outbox inserts only;
- event-ingest: sensor lookup and runtime outbox publication only;
- discovery worker: background queue, scoped evidence storage/KMS, permitted
  provider references, discovery database, and derived projection endpoints;
- runtime worker: runtime queue, scoped evidence storage/KMS, event index, and
  correlation database/projection endpoints;
- Security Agent action worker: its dedicated action queue, exact action
  secrets/endpoints, execution database, kill switches, and no discovery or
  runtime queue authority;
- runtime gateway: only control-plane enrollment/policy/event endpoints;
- migration: database migration secret and no runtime provider rights.

All workloads are non-root, read-only-root compatible, bounded, drain-aware,
digest-pinned, and covered by private Services, default-deny NetworkPolicies,
PDBs, topology spread, autoscaling, metrics, alerts, and runbooks.

## Failure and Recovery Invariants

- Queue receipt ACK is last; retries resume idempotently.
- Failed discovery retains the last-good snapshot and its truthful timestamp.
- Source-owned removals cannot remove another source's evidence.
- Provider cursors advance only after complete snapshot commit.
- Projection failure remains observable/retryable without corrupting authority.
- Receipt acknowledgement follows authoritative refetch and current
  authorization.
- Expired leases, approvals, grants, and secrets are cleaned with bounded,
  starvation-free queries.
- A restored environment starts with queues quarantined. Restore epochs,
  completed outbox rows, effect ledgers, approval resumes, unknown outcomes,
  and temporary controls are reconciled before consumers start, so a completed
  external effect cannot replay.
- Shutdown stops new claims, extends or releases current leases safely, drains
  bounded work, and closes dependencies in reverse order.

## Verification and Release Standard

Each implementation task starts with a failing behavioral test and ends with
focused race/contract tests, strict frontend tests, and an independent review.
Every production vertical slice also proves:

- real migrated PostgreSQL with restart and hostile cross-scope cases;
- real queue/artifact/index/graph driver contracts or an owned production-
  equivalent ephemeral environment;
- failure injection after each durable stage and replay without duplicates;
- installed-browser operation through the built frontend and real Go services;
- no product secrets or records in browser storage, URLs, logs, traces, queues,
  or unscoped object paths;
- exact OpenAPI/runtime/client/UI-map parity;
- full Go race, frontend verify/build, migration/fingerprint/down checks,
  dependency/license/secret scans, release-render checks, and cleanup.

Live provider credentials, production secrets, signed registry images, real
DNS/TLS, initialized cloud infrastructure, and a public canary are evidence
gates that require external authority. Their absence does not justify a fake
implementation or a production-ready claim; source and owned ephemeral proof
must be complete first, and the remaining gate must stay explicit.

## Idempotency and Reconciliation Matrix

Every stage has a full-scope deterministic key and canonical request digest.
Same key/same digest replays the authoritative result; same key/different
digest conflicts; missing/unknown external results remain locked for the named
reconciler.

| Stage | Key authority | Completion authority | Unknown outcome owner |
| --- | --- | --- | --- |
| OAuth/connect session | state + integration + principal | durable connection reference | provider/Nango connection reconciler |
| Sync request | scope + integration + request key | sync/job/outbox transaction | API receipt reconciler |
| Outbox publish | outbox ID + payload digest | exact queue acknowledgement | outbox publisher |
| Provider collection | job + attempt + parser/tool version | immutable evidence manifest | discovery worker lease reconciler |
| S3 evidence | scoped object key + checksum | exact persisted checksum/version | artifact reconciler |
| Snapshot apply | source + generation + manifest digest | PostgreSQL last-good generation | snapshot repository |
| Projection | snapshot + projection kind/version | projection-work row | projection worker |
| Runtime batch/event | sensor + batch/event digest | runtime stage ledger | runtime worker |
| Trigger/plan | source event version + definition version | immutable plan hash | Security Agent planner worker |
| Provider action | run + step + input digest | effect ledger + provider reconciliation | action-specific reconciler |
| Approval/notification | approval/version + decision digest | approval/outbox transaction | approval dispatcher |
| Verification/cleanup | effect + verifier/control version | durable evidence/absence result | verifier/cleanup worker |

## Recovery and Retention

Raw evidence is immutable while retained, not immortal. Each object has a
retention class, legal/incident hold state where applicable, approved deletion
epoch, tombstoned references, append-only audit, and deterministic cleanup of
PostgreSQL, OpenSearch, Neo4j, and derived caches. Deletion cannot erase
security audit evidence outside its declared policy.

Backups bind PostgreSQL recovery position, S3 manifest versions, migration and
application compatibility, and projection rebuild cursors. Restore occurs only
to a disposable or explicitly authorized target, with queues and workers held.
The reconciler classifies every outbox/effect/approval/control record before
workers resume. OpenSearch and Neo4j rebuild from authority. Schema rollback
never claims to undo an external provider effect.
