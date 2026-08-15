# M0-14c Nango API-key proof design

## Decision

Prove one complete API-key connection through the exact free self-hosted Nango
v0.70.5 runtime already accepted by M0-14a and M0-14b. The proof uses Nango's
public API-key authorization endpoint, a disposable private TLS fixture for the
built-in `1password-events` provider, and a one-shot product-owned wrapper.
Nango receives and encrypts the synthetic provider key; product state retains
only the Organization ID, integration key, and opaque connection ID.

This is a black-box compatibility proof. It exercises integration creation,
Organization/end-user connect-session scope, `POST
/api-auth/api-key/:providerConfigKey`, Nango's real credential-verification
proxy, encrypted Nango connection storage, and the credential-free connection
read boundary. It does not import credentials directly, call a real provider,
publish a host port, or claim the later proxy requirement.

## Considered approaches

### Selected: private TLS fixture plus real Nango API-key authorization

Run PostgreSQL, Nango, and a one-shot HTTPS fixture on one fresh internal Docker
network. Give the fixture only the `events.1password.com` network alias required
by the pinned `1password-events` provider template. Trust a per-run generated CA
only inside the Nango and wrapper containers. Nango must call exact `GET
/api/v2/auth/introspect` with `Authorization: Bearer <synthetic-key>` before it
accepts and stores the connection.

This proves the real API-key creation and verification path without a real
credential, public network, or customer state.

### Rejected: direct credential import

Posting credentials through a generic Connections API could create provider
state but would skip the public API-key authorization route and the built-in
verification hook. It cannot satisfy the source task.

### Rejected: real provider API key

A real API key would introduce external secret material, third-party state, and
network dependence. None is necessary to answer the compatibility question.

## Immutable runtime and official source contract

- Nango version: `v0.70.5`.
- Nango source commit: `7faf2c303bbb0322333f526e9ca31c0fe95ef58e`.
- Nango tag object: `bf8ea10293c20c6d8affff754205851011023285`.
- Nango image:
  `nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed`.
- PostgreSQL image:
  `postgres:16.0-alpine@sha256:acf5271bbecd4b8733f4e93959a8d2b536a57aeee6cc4b6a71890aaf646425b8`.
- Official v0.70.5 route type: `POST
  /api-auth/api-key/:providerConfigKey`, body `{apiKey}`, success
  `{connectionId, providerConfigKey}`.
- Official built-in provider: `1password-events`, hostname
  `events.1password.com`, verification `GET /api/v2/auth/introspect` with a
  bearer credential.
- Exact source fingerprints are retained in the implementation evidence for
  the route controller, HTTP type, and provider registry.

The Nango image also runs the fixture and wrapper with its exact
`/usr/local/bin/node` interpreter. No additional runtime image is introduced.

## Resource graph

Every run generates one 16-hex marker and owns exactly:

- one canonical `zasp-m0-14c-<marker>-*` workspace;
- one empty isolated Docker configuration directory;
- one generated CA, one fixture certificate/key, a fresh synthetic provider
  key, database password, and Nango encryption key;
- one internal Docker network with no host publication;
- one PostgreSQL container with tmpfs-backed data;
- one Nango container with the exact M0-14a database/schema boundary and the
  generated CA mounted read-only;
- one fixture container with only the `events.1password.com` alias, generated
  certificate/key mounted read-only, read-only root, and bounded tmpfs/resources;
- one one-shot wrapper container with proof sources and CA mounted read-only and
  no writable product-state mount.

The wrapper's stdout is the only product artifact. It is strict bounded JSON
containing exactly `{organizationId, integrationKey, connectionId}`.

## Product-wrapper flow

1. Read the self-hosted dashboard environment's exact full-access Nango API key
   through the local no-auth dashboard boundary and keep it only in memory.
2. Create one marker-scoped `1password-events` integration with no OAuth client
   credential payload and no webhook forwarding.
3. Create one connect session scoped to the synthetic Organization, end user,
   and exact integration.
4. POST the synthetic raw provider key exactly once to
   `/api-auth/api-key/<integration>?connect_session_token=<token>`.
5. Require Nango to call the private fixture at exact
   `https://events.1password.com/api/v2/auth/introspect` with the exact bearer
   key. The fixture accepts one request and returns one bounded 200 response.
6. Require the API-key authorization response to contain exactly the requested
   connection ID and integration key.
7. Poll Nango's authenticated credential-free connection list with bounded
   read-only retries until exactly one matching Organization-scoped connection
   exists.
8. Emit only the three product reference fields. Reject any extra field or any
   occurrence of the provider key, Nango API key, or connect-session token.

All HTTP calls have absolute deadlines, response limits, strict UTF-8 and
duplicate-key JSON rejection, exact status/header/redirect rules, and no proxy
or ambient credential input.

## Fixture contract

The single-use HTTPS fixture accepts only one `GET /api/v2/auth/introspect`
request with:

- TLS SNI/Host `events.1password.com`;
- no query string or request body;
- exactly the required bounded headers;
- `Authorization: Bearer <generated-provider-key>`.

Every other method, host, path, query, body, credential, replay, or connection
fails closed. The fixture's stdout/stderr and top-level errors never emit the
key or request details.

## Ownership, mutations, and cleanup

Reuse the completed M0-14b workspace, parser, bounded-child, image, container,
network, journal, and cleanup architecture under a distinct M0-14c namespace.
Every image, environment member, command, security option, mount, network peer,
and lifecycle state is matched exactly.

Definitive mutation rejection is never reconciled. Thrown, signaled, timed-out,
or malformed successful mutations enter bounded exact-state reconciliation. A
single settlement journal is joined under independent cleanup authority before
cleanup or final audit.

Cleanup runs wrapper, fixture, Nango, PostgreSQL, network, then workspace. It
re-proves exact ownership immediately before every destructive action, retries
only coherent read snapshots, continues after failures, and gives cleanup
failure precedence. Workspace removal requires global container/network
absence. Final audit covers every M0-14c name prefix, proof label, run marker,
and canonical temporary root.

## Fixed output and deadlines

Success is exactly:

`Nango API key proof passed: api_key=true reference=true product_state_safe=true cleanup=true.`

Failure is exactly one fixed category (`configuration`, `provider`, `api_key`,
`normalization`, `ownership`, `cleanup`, or `operation`) followed by
` rejected.` No identifier, URL, key, header, body, Docker output, or path
crosses the boundary.

The main phase is bounded at 360 seconds and cleanup at 90 seconds. Every child
uses SIGKILL supervision, a combined 64 KiB output cap or narrower endpoint cap,
and a reap boundary. Cleanup has independent authority and no operation is
awaited outside a bounded phase.

## Verification and completion boundary

- Hermetic tests cover the strict wrapper, fixture single-use/key behavior,
  exact runtime metadata, ambiguous mutations, phase fencing, cleanup
  continuation/precedence, global absence, and hostile parsers.
- The exact Docker lifecycle completes the API-key flow twice on final code and
  proves zero M0-14c containers, networks, and temporary roots after each.
- Product output contains one durable connection reference and none of the raw
  provider key, Nango API key, or connect-session token.
- M0-14a and M0-14b remain Complete and both proof suites stay green.
- Full pinned repository verification, production dependency audit, license
  inventory, whitespace, and redacted Gitleaks history/evidence scans pass.
- Independent read-only review has zero remaining Critical, Important, or Minor
  findings before M0-14c becomes Complete.

R-08 remains Not run through M0-15. M0-14 and M0-15 are not started.
