# M1-23 OpenAPI Root Design

## Decision

Create one self-contained OpenAPI 3.1 root at `openapi/openapi.yaml`, governed
by a repository-root `redocly.yaml` and one exact pinned Redocly CLI development
dependency. This task defines shared API vocabulary only: the document has an
empty `paths` object until later operation tasks add reviewed endpoints.

The alternative was a custom schema checker. That would prove only assertions
we happened to write, not conformance to OpenAPI 3.1, and would give M1-24 a
weaker generator input. A pinned standard linter plus focused hostile contract
tests gives both specification validation and product-specific invariants.

## Root document

The root contains exactly these top-level concerns:

- `openapi: 3.1.0`;
- bounded product `info` with API version `1.0.0`;
- the OpenAPI 3.1 base JSON Schema dialect;
- `paths: {}` because M1-23 owns no operation;
- two alternative global bearer security requirements; and
- reusable security, pagination, product-identity, and product-error
  components.

It does not contain example customer data, provider names, vendor IDs,
credentials, servers, webhooks, callbacks, operations, or generated code.
M1-24 owns the generated TypeScript client. Later M1/M2 tasks add operations
one reviewed path at a time.

## Authentication schemes

The public product API accepts either of two independently named HTTP bearer
schemes:

- `SessionJWT` documents the Stytch-backed human session JWT boundary; and
- `ProductAPIToken` documents the product API-token boundary.

Both use the standard `Authorization: Bearer` transport. The alternatives are
separate Security Requirement Objects so a request satisfies one scheme, not
both. They describe transport only; token validation, authentication,
authorization context, fresh-auth enforcement, scope resolution, and API-token
lifecycle remain later M2 work. No cookie, query-string token, OAuth implicit
flow, vendor discovery URL, or anonymous global alternative is declared.

## Pagination components

All future list operations reuse these closed components:

- `Cursor` is an opaque, bounded, canonical base64url string without padding;
- `PageCursor` is the optional `cursor` query parameter;
- `PageLimit` is an optional integer query parameter from 1 through 100 with a
  default of 50; and
- `PageInfo` contains exactly `next_cursor` and `has_more`.

`PageInfo` is a closed two-state union: `has_more: true` requires a non-null
cursor, while `has_more: false` requires `next_cursor: null`. This prevents a
generated client from accepting contradictory pagination state.

## Product error components

`ProductID` mirrors the existing canonical `pid_` plus lowercase UUID-v4
grammar. `ProductError` mirrors the existing four-field JSON snapshot exactly:

- `code`: bounded lowercase product code with single underscores;
- `message`: bounded, nonempty product-language text;
- `correlation_id`: canonical `ProductID`; and
- `retryable`: explicit boolean.

The object is closed and all four fields are required. `ProductErrorResponse`
is the reusable JSON response wrapper. The OpenAPI schema does not expose Go
types, provider exceptions, debug metadata, stack traces, credentials, or
implicit retry inference.

## Lint and dependency boundary

Pin `@redocly/cli` exactly at `2.43.1`, which supports OpenAPI 3.1 and the
repository's pinned Node 22/npm 10 runtime. `redocly.yaml` extends the
recommended ruleset. Only `no-unused-components` is disabled because M1-23 is
deliberately the component root before any operation exists; M1-24 and later
operation tasks consume the components.

The root command is:

```bash
npm run openapi:lint
```

It disables Redocly telemetry and update notices, uses only the locked local
binary and local files, and performs no install, download, provider, network,
credential, environment-file, database, Docker, or shared-resource I/O.

## Verification and status boundary

Tests parse the tracked YAML with the repository's existing exact-pinned
`js-yaml` development dependency, require exact top-level and component key
sets, and reject
hostile mutations for version, security alternatives, token placement,
pagination state, product ID/error shape, unknown keys, paths, remote
references, examples, and provider/customer content. The pinned Redocly
recommended linter must pass with zero errors or warnings.

M1-23 may start only after this design and a tests-first implementation plan
are committed. It may move to Complete only after focused RED/GREEN, repeated
lint and hostile contract stability, full repository verification, dependency
and secret audits, zero-finding whole-range review, push, and exact-SHA
Runnable UI success. M1-24 remains Pending. M0-09, M0-18, and M0-19 remain
Blocked.
