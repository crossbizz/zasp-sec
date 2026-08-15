# M0-14b Nango OAuth proof design

## Decision

Prove one complete OAuth 2.0 authorization-code connection through the exact
free self-hosted Nango v0.70.5 runtime from M0-14a. The proof uses a disposable
private TLS fixture provider and a one-shot product-owned wrapper. The product
retains only an opaque Nango connection reference; the fixture authorization
code, access token, client secret, Nango API key, and connect-session token are
never written to product output.

This is a black-box compatibility proof. It exercises Nango's public integration,
connect-session, OAuth redirect/callback, token exchange, and connection-read
boundaries. It does not import OAuth credentials through the Connections API,
call a real provider, expose a host port, or claim the later proxy requirement.

## Considered approaches

### Selected: private TLS fixture plus real Nango OAuth flow

Run PostgreSQL, Nango, and a fixture OAuth provider on one fresh internal Docker
network. Drive the flow from a one-shot product-wrapper container. Give the
fixture only the `github.com` network alias required by Nango's pinned built-in
GitHub OAuth template, and trust only a per-run generated CA through
`NODE_EXTRA_CA_CERTS` in Nango and the wrapper.

This approach proves the real authorization-code state, callback, token
exchange, encrypted Nango connection storage, and durable reference boundary
without an external credential or public network dependency.

### Rejected: import synthetic OAuth credentials

Posting OAuth credentials to `/connections` would create a connection but skip
the authorization redirect, state, callback, and token exchange. It cannot
satisfy M0-14b's requirement to complete an OAuth connection.

### Rejected: real GitHub OAuth application

A real application would add secret material, public callback routing, network
dependence, and external state. Those risks are unnecessary for the source-plan
compatibility question and conflict with the disposable local proof boundary.

## Immutable runtime

- Nango source version: `v0.70.5`.
- Nango source commit: `7faf2c303bbb0322333f526e9ca31c0fe95ef58e`.
- Nango tag object: `bf8ea10293c20c6d8affff754205851011023285`.
- Nango image:
  `nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed`.
- PostgreSQL image:
  `postgres:16.0-alpine@sha256:acf5271bbecd4b8733f4e93959a8d2b536a57aeee6cc4b6a71890aaf646425b8`.
- The Nango image also runs the fixture and one-shot wrapper with its exact
  `/usr/local/bin/node` v22.22.2 interpreter. No additional runtime image is
  introduced.

The proof uses the official `github` provider template because its OAuth
authorization and token endpoints are fixed and therefore can be bound to one
private Docker network alias without accepting user-controlled URLs.

## Resource graph

Every run generates one 16-hex marker and owns exactly:

- one canonical `zasp-m0-14b-<marker>-*` workspace;
- one empty isolated Docker configuration directory;
- one generated CA, one fixture certificate/key, and fresh synthetic OAuth
  client secret, authorization code, access token, database password, and
  Nango encryption key;
- one internal Docker network with no host publication;
- one PostgreSQL container with tmpfs-backed data;
- one Nango container with the exact M0-14a database/schema boundary plus the
  generated CA mounted read-only;
- one fixture-provider container with the exact `github.com` network alias,
  generated certificate/key mounted read-only, read-only root, and bounded
  tmpfs/resources;
- one one-shot product-wrapper container with the proof sources and CA mounted
  read-only and no writable product-state mount.

The wrapper's stdout is the only product artifact. It is a strict bounded JSON
object containing Organization ID, integration key, and opaque connection ID.

## Product wrapper flow

1. Read the self-hosted dashboard's current environment and default full-access
   API key through the no-auth local dashboard boundary. Keep the key in memory.
2. Create one marker-scoped `github` integration using a generated client ID and
   secret.
3. Create one connect session scoped to the synthetic Organization/end user and
   the exact integration.
4. Request `/oauth/connect/<integration>` with the connect-session token and
   require a single redirect to the exact fixture authorization URL.
5. The fixture validates client ID, callback, state, response type, and PKCE,
   then returns a single-use synthetic code to Nango's callback.
6. Nango exchanges the code against the fixture TLS token endpoint. The fixture
   validates the code, client secret, callback, and PKCE verifier before issuing
   one synthetic bearer token.
7. Poll Nango's authenticated connection-read boundary with bounded read-only
   retries until exactly one matching connection exists.
8. Emit only `{organizationId, integrationKey, connectionId}` and verify all
   keys and values exactly. Reject any additional field or any occurrence of a
   generated secret/code/token.

All HTTP requests have absolute deadlines, response-size limits, strict UTF-8,
duplicate-key JSON rejection, exact status/header/redirect rules, and no proxy
or ambient credential input.

## Fixture-provider contract

The fixture is an HTTPS server with exactly two endpoints:

- `GET /login/oauth/authorize`: validates the exact query and responds once with
  `302 Location: <callback>?code=<one-time-code>&state=<exact-state>`.
- `POST /login/oauth/access_token`: validates exact form members, content type,
  generated client credentials, callback, one-time code, and PKCE verifier;
  responds once with strict JSON containing the synthetic access token.

Every other method, host, path, query member, repeated code, redirect target,
or token request fails closed. Logs and errors never emit request values.

## Ownership, mutation, and cleanup

Use the completed M0-14a parser, bounded-child, image, container, network, and
mutation-classification primitives. The M0-14b runtime retains its own exact
resource graph and cross-correlates complete image/config/security/mount/network
metadata and peer identity.

Definitive mutation rejection is never reconciled. Thrown, signaled, timed-out,
or malformed successful mutations enter bounded exact-name/full-ID/state
reconciliation. A single settlement journal is joined under independent cleanup
authority before cleanup or final audit.

Cleanup runs product wrapper, fixture, Nango, PostgreSQL, network, then workspace.
It re-proves exact ownership immediately before every destructive action, retries
only coherent read snapshots, continues after failures, and gives cleanup failure
precedence. Workspace deletion requires global container/network absence. Final
audit covers all M0-14b name prefixes, proof labels, run markers, and canonical
temporary roots.

## Fixed output and deadlines

Success is exactly:

`Nango OAuth proof passed: oauth=true reference=true product_state_safe=true cleanup=true.`

Failure is exactly one of the fixed categories `configuration`, `provider`,
`oauth`, `normalization`, `ownership`, `cleanup`, or `operation` followed by
` rejected.` No exception, URL, identifier, header, credential, token, Docker
output, provider body, or filesystem path crosses the boundary.

The main phase is bounded at 360 seconds and cleanup at 90 seconds. Every child
uses SIGKILL supervision, a combined 64 KiB output cap or a narrower endpoint
cap, and a reap boundary. Cleanup has independent authority and no operation is
awaited outside a bounded phase.

## Verification

- Hermetic unit tests cover parsers, wrapper reference-only output, fixture
  state/PKCE/single-use behavior, exact runtime metadata, ambiguous mutations,
  phase fencing, cleanup continuation/precedence, and global absence.
- The exact Docker lifecycle completes the fixture OAuth flow twice on final
  code and proves zero M0-14b containers, networks, and temp roots after each.
- Product output contains one durable connection reference and none of the
  seeded authorization code, access token, client secret, Nango API key, or
  connect-session token.
- M0-14a remains Complete and its full proof suite remains green.
- Full pinned repository verification, production dependency audit, license
  inventory, whitespace, and redacted Gitleaks history/evidence scans pass.
- Independent review has zero remaining findings before M0-14b becomes Complete.

M0-14b does not change R-08, which remains Not run through M0-15.
