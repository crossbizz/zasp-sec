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
cd proofs/neon-pooled && go test -race ./...
set -a
source .env
set +a
cd proofs/neon-pooled && go run .
```

The same commands are available from the repository root as `npm run
proof:neon:test` and `npm run proof:neon:run`. The live command emits a fixed
summary; it never prints connection-string fields or query results.

The application uses Vinext and targets the Cloudflare Workers runtime. Optional
local D1 and R2 bindings can be enabled with `CLOUDFLARE_D1_BINDING` and
`CLOUDFLARE_R2_BINDING`; no database or object-storage binding is required for
the browser-local prototype.

Application authentication will use Stytch B2B. The current prototype runs
without an authentication gate until that integration is configured.
