# M0-15 Nango proxy proof design

## Decision

M0-15 proves one authenticated provider GET through exact-pinned free
self-hosted Nango v0.70.5. The proof reuses the reviewed M0-14c private
API-key connection boundary without changing that completed evidence. A new
isolated `proofs/nango-proxy` module creates a disposable Nango/PostgreSQL
runtime, a private TLS provider fixture, and a one-shot product wrapper.

The wrapper first creates one `1password-events` API-key connection through
the public Nango APIs. It then calls Nango's authenticated public Proxy route:

```text
GET /proxy/api/v2/events?limit=1
Authorization: Bearer <Nango environment API key>
Connection-Id: <opaque connection reference>
Provider-Config-Key: <exact integration key>
```

Nango retrieves the encrypted provider key and issues the distinct provider
request `GET /api/v2/events?limit=1` with its configured bearer header. The
product wrapper strictly validates the response and retains only Organization
scope, the two opaque Nango references, and allowlisted normalized event
fields. It never persists or emits the provider key, Nango environment key,
connect-session token, database password, or encryption key.

## Considered approaches

### Selected: new isolated proof over the reviewed connection flow

Create a new proof namespace, temporary workspace, network, labels, fixture,
wrapper, and orchestration tests. Copy the reviewed M0-14c boundary shape and
adapt it to the additional proxied request. Keep shared parsing and immutable
image pins imported from the completed Nango boot proof.

This gives M0-15 exact ownership and cleanup authority without changing the
meaning or reproducibility of M0-14c. It also proves the product wrapper, not a
direct `curl` command, owns the Proxy call and normalization boundary.

### Rejected: extend the completed M0-14c module in place

Adding Proxy behavior to M0-14c would retroactively change a completed task's
success line, fixture request count, runtime contract, tests, and evidence.
That would weaken the audit boundary between API-key authorization and Proxy.

### Rejected: call a public provider

A real provider would require a credential, external network access, and
provider-account cleanup. The proof needs Nango's credential injection and
Proxy semantics, not a third-party availability test. A private TLS fixture
is deterministic and proves the credentialed request without repository or
operator secrets.

### Rejected: use a proxy base-URL override

The selected `1password-events` provider already resolves
`events.1password.com` from validated connection configuration. A base-URL
override would exercise a separate override/denylist surface and would not
prove the accepted provider configuration constructs the request correctly.

## Pinned authority and source contract

The runtime remains pinned to:

- Nango v0.70.5 source commit
  `7faf2c303bbb0322333f526e9ca31c0fe95ef58e`, annotated tag object
  `bf8ea10293c20c6d8affff754205851011023285`, and the existing immutable
  `nangohq/nango-server` digest;
- PostgreSQL 16.0-alpine at the existing immutable digest;
- the reviewed production-license inventory from M0-14a through M0-14c.

The pinned source defines `ALL /proxy/*splat` behind public API
authentication and `environment:proxy` scope. It requires
`provider-config-key` and `connection-id`, derives the provider endpoint from
the `/proxy/` suffix, loads the exact integration and connection, refreshes or
tests the stored credential, then performs the provider request through
`ProxyRequest`. Provider response forwarding is restricted by Nango's own
allowlist.

The selected provider configuration is exact `1password-events`: API-key
authentication, base URL `https://${connectionConfig.domain}`, and injected
`Authorization: Bearer ${apiKey}`. Connection configuration fixes the domain
to `events.1password.com`; no arbitrary provider URL enters product state.

## Private provider fixture

The fixture is a non-root, read-only Nango-image Node process attached only to
the proof's internal Docker network. A per-run CA and server certificate bind
the TLS name `events.1password.com`. There is no host port or external DNS
dependency.

It accepts exactly two ordered requests using the same generated provider key:

1. verification: `GET /api/v2/auth/introspect`, exact Host, Accept, bearer
   header, empty body, and one successful use;
2. proxy: `GET /api/v2/events?limit=1`, the same exact Host, Accept, bearer
   header, empty body, and one successful use after verification.

The proxy response is bounded canonical JSON with one deterministic synthetic
event. Duplicate, reordered, replayed, redirected, uncredentialed, malformed,
oversized, extra-query, or out-of-order requests fail closed. The second
request is distinct from credential verification, so a passing connection
alone cannot satisfy M0-15.

## Product wrapper and persisted result

The wrapper uses only the private Nango server URL and fixed synthetic values.
Its sequence is:

1. read exactly one scoped Nango environment API key;
2. create the exact `1password-events` integration;
3. create one connect session scoped to one synthetic Organization and end
   user;
4. authorize the generated provider key and retain the returned opaque
   connection ID;
5. re-read the exact connection and bind its Organization, end user,
   integration, provider, and tags;
6. call the public Nango Proxy route with the environment key, connection ID,
   and integration key;
7. strictly parse the canonical provider response and normalize only the
   event ID and action into the product result.

The retained result has this exact shape:

```json
{
  "organizationId": "org_<marker>",
  "integrationKey": "zasp-m0-15-<marker>-1password-events",
  "connectionId": "<opaque UUID>",
  "event": {
    "id": "11111111-1111-4111-8111-111111111111",
    "action": "item.usage"
  }
}
```

Before returning, the wrapper serializes the retained result and proves it
contains none of the raw provider key, environment API key, connect token,
database password, or encryption key. Tests also seed each forbidden value
into hostile provider fields, errors, extra keys, and coercion hooks and
require rejection.

## Runtime and ownership model

Each run generates a 16-hex marker and owns only resources with the global
prefix `zasp-m0-15-`, proof label `zasp.dev/proof=m0-15`, exact current run
label, and exact role label. The graph is:

```text
private internal network
├── PostgreSQL 16.0-alpine
├── Nango server v0.70.5
├── private TLS provider fixture
└── one-shot product wrapper
```

All containers use immutable image references, exact platform, non-root image
users where provided, read-only root filesystems, dropped capabilities with
only PostgreSQL's reviewed minimum restored, no-new-privileges, PID/memory/CPU
bounds, exact tmpfs, no host publication, and exact mounts. Docker receives
only `PATH` plus an owned empty `DOCKER_CONFIG`. Runtime identity is re-proved
from full IDs, names, image IDs/config, labels, environment, entrypoint,
command, mounts, security options, network projections, peer identities, and
absence of unexpected ports or resources.

Create, start, schema, and cleanup mutations are single-attempt and journaled.
Only thrown, signaled, or malformed-success outcomes are ambiguous; returned
nonzero results are definitive rejection. Ambiguous outcomes enter bounded
exact-state reconciliation. Main and independent cleanup phases fence late
continuations, join mutation settlements, and preserve cleanup-error
precedence.

## Cleanup and absence proof

Cleanup runs in reverse dependency order and continues after failures:

1. wrapper;
2. fixture;
3. Nango;
4. PostgreSQL;
5. internal network;
6. owned TLS/Docker-config workspace.

Every destructive step immediately re-proves the retained full identity and
current dependency state. A replacement, extra peer, changed mount, changed
label, changed image, or unreadable state is not deleted. Workspace removal is
permitted only after global Docker absence is proved by prefix, proof label,
and current marker. Final absence covers every proof prefix/label/marker and
every `zasp-m0-15-` temporary root. Shared Nango/PostgreSQL containers are
never selected or mutated.

## Fixed output and failure behavior

Success is one line:

```text
Nango proxy proof passed: get=true response=true product_state_safe=true cleanup=true.
```

Failure is one fixed allowlisted category line and exit 1. Child output is
bounded and never forwarded. Credential/provider bodies, Docker identifiers,
paths, TLS material, and native Nango response content never cross the CLI
boundary.

## Status, risk, and completion

M0-15 starts only after M0-14 is Complete. It moves alone from Pending to In
progress during implementation. R-08 remains Not run until the final code
passes the exact live lifecycle, product-state secrecy proof, exact cleanup,
full pinned gates, license/secret audits, and zero-finding whole-range review.

Only then may M0-15 move to Complete and R-08 move to PASS with the exact
evidence path and delivery SHA. M0-09 and PROV-01 remain Blocked, R-03 remains
incomplete, M0-16 remains Pending, and no unrelated status changes.

## Verification

Delivery requires:

- genuine tests-first RED/GREEN for fixture, wrapper, manifest, filesystem,
  orchestrator, scripts, status, and R-08 transitions;
- six consecutive hermetic proof-suite passes;
- two consecutive exact live passes with zero prefix/label/network/temp
  residue after each;
- unchanged shared-service fingerprints;
- full pinned repository tests, typecheck, lint, build, production audit, and
  license inventory;
- whitespace and pinned redacted secret scans over source, evidence, staged
  content, the exact commit, and full history;
- zero remaining Critical, Important, or Minor review findings;
- push of the exact completion SHA and terminal-success Runnable UI evidence.
