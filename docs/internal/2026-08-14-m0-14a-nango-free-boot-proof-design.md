# M0-14a Nango free boot proof design

## Status and scope

M0-14a proves one narrow boundary: the current free self-hosted Nango server
boots with only the dependencies required for its Auth and Proxy surface, and
its database-backed readiness endpoint is reachable from a product-side test
client on a private network. OAuth, API-key connection creation, feature-
boundary acceptance, and authenticated proxying remain M0-14b, M0-14c, M0-14,
and M0-15 respectively.

The official current release is Nango v0.70.5 at source commit
`7faf2c303bbb0322333f526e9ca31c0fe95ef58e`. The proof uses the immutable
free self-hosted image built from that exact commit:

`nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed`

The image is the official single-platform `linux/amd64` self-hosted build. Its
source build removes the jobs, runner, and persist packages from the base
image. Nango is distributed under the Elastic License; this proof makes no
claim that the free self-hosted image contains paid or Enterprise features.

## Minimum runtime

The service runtime has exactly two long-running containers: the Nango server
and PostgreSQL. PostgreSQL is required for migrations and for the `/ready`
database query. Its immutable official image index is:

`postgres:16.0-alpine@sha256:acf5271bbecd4b8733f4e93959a8d2b536a57aeee6cc4b6a71890aaf646425b8`

Redis is optional in the tagged source and is omitted. Elasticsearch, the
orchestrator, function workers/runners, and external telemetry dependencies are
also omitted. Connect UI is disabled. The proof does not invoke or depend on
Functions, Webhooks, MCP server, RBAC, and Enterprise-only runtime features.

A third one-shot product probe is a test client, not a service dependency. It
uses the already reviewed immutable BusyBox test image:

`registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9`

## Storage and secret boundary

Every run creates a separate database container and a marker-scoped database
and separate schema inside that database. The pinned v0.70.5 migration set
contains exact `nango._nango_sync_jobs` and `nango_records.*` references, so
the disposable database uses Nango's fixed `nango` and `nango_records`
schemas while the database, container, credentials, and encryption key remain
per-run.
Nango also receives a fresh synthetic per-run encryption
key. The database credentials and per-run encryption key exist only in the
bounded proof process and disposable container configuration; they are never
read from dotenv, profiles, host credentials, or product tables and are never
printed.

PostgreSQL storage is disposable and has no host bind mount. Nango receives
only the exact database URL/schema values needed for its own migrations and
records storage. It cannot share the product database, product schema, or a
product encryption key.

## Network and readiness boundary

Each run creates one private internal Docker network. Neither PostgreSQL nor
Nango publishes a host port. The one-shot product probe joins that network and
polls only the Nango server name on its fixed internal server port.

Nango v0.70.5 exposes `/health` as process liveness and `/ready` as the stronger
database-backed signal. This proof therefore requires `GET /ready` to return
HTTP 200 with exactly `{"result":"ok"}`. The response is bounded, parsed with
recursive duplicate-key rejection, and rejected for redirects, aliases,
unknown members, type changes, trailing values, or extra bytes. A liveness-only
`/health` response cannot satisfy the proof.

The network is internal, DNS targets are exact retained container names, and
the probe has no published port, host networking, proxy value, credential, or
ambient Docker configuration. Success proves reachability from the product
test network, not public ingress or production topology.

## Free feature boundary

The server is explicitly configured as neither Nango Cloud nor Enterprise.
Connect UI, logs/Elasticsearch, Redis, role-based authorization, and telemetry
SDK output are disabled or absent. No Functions, Webhooks, MCP, job runtime,
or orchestrator endpoint is supplied. Container inspection must match the
complete allowlisted environment and reject extra feature-enabling values.

This boot proof does not yet establish that every excluded route is
unreachable. M0-14 records the validated free feature boundary after the OAuth
and API-key proofs. The only M0-14a success claim is minimum free boot plus
database-backed product-network readiness.

## Ownership and cleanup

Names use `zasp-m0-14a-<16 lowercase hex>-<role>` with exact proof, run, and
role labels. The runtime retains immutable image identities, full container
IDs, the network ID, names, configuration, and peer membership. Docker receives
only an allowlisted `PATH` and an exact-owned empty `DOCKER_CONFIG`.

Ordinary nonzero mutation results are definitive rejection. Only thrown,
signaled, or malformed successful mutation outcomes can enter exact
reconciliation. Every mutation is journaled and settled before dependent
cleanup. Candidate state is retained before result interpretation.

Cleanup runs independently in reverse dependency order: product probe, Nango,
PostgreSQL, network, then exact-owned temporary configuration. Every destructive
step immediately re-proves the retained full identity and complete expected
metadata. Cleanup continues after individual failures, gives cleanup failure
precedence, and ends with a global name-prefix/proof-label/run-marker scan plus
a prefix-wide zero-resource audit.

## Deadlines and fixed output

The main lifecycle has a hard five-minute budget and cleanup has an independent
one-minute budget, both inside the source task's fifteen-minute timebox. Child
processes use bounded combined output, hard kill, reap, deadline revocation,
and mutation settlement before cleanup. Read-only Docker reconciliation is
bounded and retryable; mutations are single-attempt.

Success is exactly:

`Nango free boot proof passed: services=2 ready=true product_network=true cleanup=true.`

Failures use only fixed configuration, provider, readiness, ownership,
cleanup, or operation categories and never include provider output, container
IDs, database values, or synthetic secrets.

## Completion boundary

Completion requires hermetic lifecycle and hostile-parser tests, six stability
passes, two consecutive exact-image live runs, database-backed `/ready` from
the one-shot product probe, exact zero-resource cleanup, dependency/license and
secret scans, full repository verification, and independent review with no
remaining Critical, Important, or Minor findings. R-08 remains Not run until
M0-14b through M0-15 finish the OAuth, API-key, free-feature, and proxy gates.
