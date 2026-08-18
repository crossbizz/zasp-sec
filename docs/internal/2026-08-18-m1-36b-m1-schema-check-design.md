# M1-36b M1 Schema Check Design

Date: August 18, 2026

## Goal

Run one hermetic repository gate that re-proves every completed M1 schema
authority owned by the database, event, and canonical domain boundaries. The
gate detects drift by executing the existing exact fixtures; it does not create
a second schema representation or add product behavior.

## Selected boundary

The repository adds one root command:

```bash
npm run schema:check
```

The command executes exactly five reviewed Go package targets, in dependency
order:

1. `services/platform/migrations` — embedded version-1 database up/down assets,
   pinned checksum, ledger state, and exact transaction order;
2. `services/platform/domain` — product IDs, scope, evidence vocabulary, and the
   product error envelope;
3. `services/platform/securityevent` — the version-1 SecurityEvent envelope
   built on the canonical domain and observability values;
4. `services/platform/eventindex` — the exact 12-field session/runtime event
   index template and strict document-field boundary; and
5. `services/platform/queuedefinition` — the three versioned message-schema
   definitions and their deterministic JSON document.

These packages already own exact asset, field, enum, version, ordering,
serialization, checksum, and hostile-drift assertions. M1-36b composes those
authorities; it does not copy their schemas into a new manifest.

## Runner contract

`scripts/check-m1-schemas.mjs` creates the exact five `go test` invocations. Each
child runs from the repository root with Go race detection and count one. Child
execution receives only `PATH`, `HOME`, `LANG`, and fixed offline Go controls:
`GOENV=off`, `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`, `GOWORK=off`,
while the host's race-supported Go configuration remains in effect. Ambient
cloud credentials, profiles, proxies, dotenv, database URLs, Node options, and
customer configuration do not cross the boundary.

Each child has a 120-second hard `SIGKILL` deadline and separate one-MiB stdout
and stderr limits. A thrown, signaled, timed-out, nonzero, oversized, or
malformed result fails fast. Child output is never forwarded. The process
accepts no arguments and emits exactly one fixed line:

```text
M1 schema check passed: targets=5
```

or, on every failure:

```text
M1 schema check rejected
```

## Drift and side-effect boundary

No target generates files or mutates schema state. The database package uses a
fake transaction boundary and embedded SQL; it does not connect to Neon. The
event and domain packages are value/serialization tests only. The command does
not invoke Drizzle generation, OpenAPI generation, Docker, Kubernetes,
LocalStack, Neo4j, OpenSearch, SQS, a cloud provider, or a network endpoint.

M1-36c separately owns OpenAPI generation and generated-client drift. The
empty optional Cloudflare D1 starter at `db/schema.ts` is not a product M1
database authority and remains outside this gate. Live disposable provider
proofs remain with the tasks that created them and are not repeated here.

## Contract and status

A repository quality contract binds the exact M1-36b source row, completed
M1-36a dependency, five-target inventory, fixed output, offline environment,
no-side-effect boundary, M1-36c Pending state, arithmetic, and exact blockers.
README documents only the schema gate and its command.

M1-36b starts at 650 Pending / 1 In progress / 74 Complete / 3 Blocked overall
and M1 68 total / 17 Pending / 1 In progress / 50 Complete / 0 Blocked. It may
move to Complete only after genuine RED/GREEN, six focused passes, the real
five-target command, full pinned repository and Go verification, production
dependency audit, pinned secret scans, zero-finding whole-range review, push,
and exact-SHA Runnable UI success. M1-36c remains Pending throughout.

## Alternatives rejected

- Calling every live schema proof would mutate providers and duplicate already
  reviewed lifecycle evidence.
- Running the entire platform module would blur this gate with adapters,
  commands, health, and other non-schema behavior.
- Generating a new schema inventory would create a second authority that could
  drift independently from the owning packages.
- Folding OpenAPI or UI/API checks into this gate would pre-claim M1-36c or
  M1-36d.
