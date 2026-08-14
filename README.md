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

All mutations are deterministic browser-local demo actions persisted with local
storage. No credentials or production resources are changed.

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

The application uses Vinext and targets the Cloudflare Workers runtime. Optional
local D1 and R2 bindings can be enabled with `CLOUDFLARE_D1_BINDING` and
`CLOUDFLARE_R2_BINDING`; no database or object-storage binding is required for
the browser-local prototype.

Application authentication will use Stytch B2B. The current prototype runs
without an authentication gate until that integration is configured.
