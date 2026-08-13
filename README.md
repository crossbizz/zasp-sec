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

Requires Node.js `>=22.13.0`.

```bash
npm ci
npm run dev
npm test
npm run typecheck
npm run build
```

The application uses Vinext and the OpenAI Sites runtime. Hosting bindings are
declared in `.openai/hosting.json`.
