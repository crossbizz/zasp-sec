# Production Web/API Integration Design

## Outcome

Turn the current interactive frontend prototype and separately implemented API
packages into one production-usable product. The public application uses one
origin, every visible production workflow reads and writes through an
authorized API, and durable stores remain authoritative across browser and
process restarts.

The production invariant is simple: a route is backed by an authorized,
durable API or it is not exposed. Browser-local demo state must never be used
as a production fallback.

## Current Boundary

The repository already contains:

- a complete application shell and broad interactive frontend prototype;
- an OpenAPI contract and generated TypeScript client;
- Go HTTP packages for identity, administration, inventory, risk, policy,
  integrations, sensors, sessions, red teaming, security agents, and related
  workflows;
- persistence primitives for PostgreSQL, OpenSearch, Neo4j, S3, and SQS;
- health, deployment, tenancy, authorization, observability, and local
  infrastructure proof boundaries.

Those parts are not assembled into a production product today. The web shell
hydrates `DEMO_STATE` from `localStorage`, several newer views call API methods
only for isolated mutations while rendering static module data, the generated
client has no application-wide transport policy, and `agentsec-api` serves
health without mounting product routes.

The existing UI/API coverage number measures contract mapping. It is not
evidence that a browser request reaches a durable backend.

## Chosen Architecture

### One public origin

The browser uses a single public origin:

- application routes and static assets are served at `/`;
- product requests use relative `/api/v1/*` URLs;
- the edge routes `/api/v1/*` to `agentsec-api` and all other application
  traffic to the web runtime;
- `/internal/*`, database, queue, graph, event-store, and provider endpoints
  are never publicly routed.

This avoids browser-visible service topology and CORS policy, and gives the
server one place to enforce authentication, CSRF protection, request limits,
security headers, and correlation IDs.

### Composed Go API

`agentsec-api` owns two listeners:

- a product listener on port 8080 for `/api/v1/*`;
- an internal listener on port 8081 for liveness and readiness.

A new composition package constructs dependencies once and mounts the existing
domain handlers behind an exact method/path router. Startup fails if OpenAPI
operations are missing, duplicated, or mapped to incompatible handlers.
Unknown methods and paths use the fixed product error envelope.

Readiness remains false until configuration, migrations, required durable
stores, identity verification, and route composition are ready. Shutdown stops
new requests, drains both listeners within bounded deadlines, and closes
providers in reverse dependency order.

### Authentication and request security

The browser does not store provider secrets or long-lived API tokens.
Human sessions use a Secure, HttpOnly, SameSite=Lax `__Host-zasp_session`
cookie issued after the identity-provider callback. The API validates the
session through the existing identity adapter and resolves organization,
workspace, environment, role, and permission before dispatch.

State-changing browser requests also require an exact same-origin check and a
short-lived CSRF value tied to the session. Service and sensor APIs retain the
contracted bearer-token schemes and cannot authenticate through the browser
cookie. Authentication failures are 401; authenticated authorization failures
are 403; neither leaks tenant existence.

### Durable data ownership

PostgreSQL is authoritative for organizations, principals, scopes, policies,
integrations, workflow state, and other transactional records. Existing
PostgreSQL migrations run as an explicit release step and the API refuses to
become ready on schema drift.

OpenSearch remains authoritative for searchable events and findings, Neo4j for
relationship and attack-path projections, S3 for immutable evidence and
exports, and SQS for asynchronous work. The API reads those systems through
existing bounded interfaces. It never silently replaces provider failure with
seed data.

Memory stores remain allowed only in unit tests and an explicit development
fixture process. They are rejected when `ZASP_ENVIRONMENT=production`.

### Frontend data model

One configured API client is created for the application. It always uses
relative URLs, includes same-origin credentials, validates the product error
envelope, adds correlation and CSRF headers where required, and supports
request cancellation.

Feature-specific query modules own decoding, pagination, cache keys, retries,
and mutations. Components receive explicit loading, empty, success, forbidden,
and retryable-error states. Mutation success invalidates the smallest relevant
query set. No feature component imports `DEMO_STATE` or writes product records
to `localStorage`.

Local storage may retain non-sensitive presentation preferences such as table
density or dismissed teaching hints. It must not retain credentials, scopes,
findings, policies, integrations, evidence, or workflow results.

### Production feature policy

Production navigation is generated from server capabilities. A feature is
visible only when its required read operation and every offered mutation are
available to the current principal. This lets complete vertical slices ship
without presenting dead or simulated controls.

The first usable production slice contains:

- sign-in, session bootstrap, scope selection, and sign-out;
- home posture summary and global search;
- asset, identity, finding, and attack-path lists and details;
- finding status/remediation actions;
- policy list, create, update, simulation, and activation;
- integration catalog, connection lifecycle, and sync status;
- security-agent list, detail, plan, approval, run, and audit status;
- health-aware error and degraded-state presentation.

Guardrails, reports, red-team execution, compliance exports, sessions, sensors,
and administration follow in subsequent vertical batches. Until each slice is
complete, its production navigation and command surfaces remain hidden rather
than simulated.

## Request Flow

1. The browser loads the web shell from the public origin.
2. The shell requests `/api/v1/session/bootstrap` with same-origin credentials.
3. The API validates the session and returns the principal, exact scope,
   permissions, capabilities, CSRF value, and correlation ID.
4. Route guards hide unauthorized or unavailable features before rendering.
5. A feature query calls a relative generated-client operation.
6. The API authenticates, authorizes the exact scope and operation, validates
   bounded input, and calls a durable repository or provider interface.
7. The API returns a contracted response or fixed error envelope.
8. Mutations emit an audit event and return only after their authoritative
   state is reconciled.

## Failure Behavior

- No session: redirect to sign-in; do not render cached tenant data.
- Expired session: clear in-memory query state and reauthenticate.
- Forbidden scope: show a 403 boundary without revealing hidden records.
- Provider unavailable: preserve prior rendered data as explicitly stale,
  disable mutations, expose correlation ID, and offer bounded retry.
- Validation or conflict: keep user input and show field/action feedback.
- API/schema mismatch: fail the affected feature closed and emit telemetry.
- Network loss: cancel mutations whose result is not known and reconcile before
  offering retry.

## Deployment

The production deployment contains separate immutable `web` and
`agentsec-api` workloads behind one ingress or edge route. The API is private
except for `/api/v1/*`; its internal health port is reachable only by the
cluster. All images are digest-pinned, non-root, read-only where possible, and
run with bounded CPU, memory, and PID resources.

Secrets are provided by the platform secret manager. Configuration is parsed
once at startup through the existing strict loader. Logs are structured and
redacted. Metrics and traces contain organization-safe identifiers and
correlation IDs but no credentials or request bodies.

## Verification

Each vertical slice must pass four layers before production exposure:

1. repository and handler tests with authorization, tenant isolation, error,
   timeout, and persistence-restart cases;
2. generated-client/component tests for loading, empty, success, forbidden,
   stale, validation, and retry behavior;
3. an in-process browser-to-API integration test using real HTTP and a real
   migrated database boundary;
4. a deployed smoke test that signs in, performs the workflow, reloads the
   browser, and proves the authoritative result remains.

CI additionally requires OpenAPI generation/checks, route-composition parity,
type checking, lint, production builds, dependency and secret scans, Go race
tests, migration checks, and accessibility smoke tests.

## MVP Cuts

The MVP optimizes for complete workflows, not breadth.

Allowed cuts:

- hide incomplete feature routes;
- defer bulk operations, advanced filters, exports, scheduling, and secondary
  visualizations;
- use polling before adding realtime subscriptions;
- support one production deployment profile before edge/customer profiles;
- keep advanced provider setup behind operator configuration.

Not allowed:

- local demo data or optimistic fake success in production;
- in-memory authoritative product state;
- browser-stored session or provider credentials;
- disabled authorization, tenant filters, audit, or migrations;
- public internal/provider endpoints;
- a UI control with no durable backend effect;
- claiming production readiness from mocked or mapping-only tests.

## Delivery Strategy

Implementation proceeds in batches of 20–30 related microtasks. A batch owns a
complete vertical boundary and lands only when its backend, client, UI,
integration tests, deployment wiring, and operational checks are coherent.
Independent backend, frontend, and delivery work runs in parallel, but no batch
is called complete until a real browser-to-durable-store path passes.

