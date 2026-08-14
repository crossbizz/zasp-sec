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

The application uses Vinext and targets the Cloudflare Workers runtime. Optional
local D1 and R2 bindings can be enabled with `CLOUDFLARE_D1_BINDING` and
`CLOUDFLARE_R2_BINDING`; no database or object-storage binding is required for
the browser-local prototype.

Application authentication will use Stytch B2B. The current prototype runs
without an authentication gate until that integration is configured.
