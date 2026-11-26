# Zasp

Zasp is an agent security platform. It finds the AI agents in your cloud accounts and SaaS tenants, shows what each one can reach and what is wrong with it, tests agents against attacks, and helps you fix what it finds.

It is **agentless**: nothing is installed in the environments it watches. Collectors read provider APIs with read-only credentials that you grant.

## What it does

- **Discovers agents and what they can reach.** AWS (Bedrock agents, AgentCore runtimes, Lambda functions and roles that call a model), Kubernetes, GitHub, Okta, Microsoft (Entra, Copilot Studio, Azure OpenAI, AI Foundry), Salesforce Agentforce, Google Cloud, and SaaS platforms through Nango (Slack, Atlassian, GitLab, Databricks, ServiceNow, Google Workspace, OpenAI, Anthropic). It also finds agents nobody declared, from signals such as a function that holds a model provider key.
- **Builds an inventory.** Agents, non-human identities, tools, MCP servers and runtimes, each with its provider, how it was found, its owner and its last activity.
- **Finds problems.** Posture findings, attack paths with ranked ways to break them, and references to OWASP, MITRE ATLAS, NIST AI RMF, ISO/IEC 42001 and the EU AI Act.
- **Tests agents.** Red team runs from a reviewed probe library, on a schedule or when a target changes, against non-production targets.
- **Guards traffic, without an agent in your environment.** A hosted MCP gateway and model proxy that your agents point at, and a guardrail decision API.
- **Helps fix things.** Security Agents plan a response to a finding; a person approves before anything changes.
- **Controls access.** Organizations, workspaces and environments, roles, API tokens, session investigation and an audit log.

Every screen is backed by a documented API. Some capabilities are switched off until you configure them; the [administrator guide](docs/getting-started/administrator.md#optional-pieces) lists each switch.

## Status

This is pre-release software. Read these three points before you plan around it:

- The local stack has been run end to end on Linux. Sign-in needs a Stytch project and a person at a browser.
- The Kubernetes evaluation chart has been rendered and tested as text. It has not been installed on a cluster.
- The production deployment on AWS (Terraform and a Helm chart) has not been applied to an AWS account.

The administrator guide says, command by command, [what was and was not verified](docs/getting-started/administrator.md#what-was-and-was-not-verified).

## New installations

`./zasp config init` creates a private VPS configuration for a single-node k3s host. Follow the [VPS first-deployment guide](docs/operations/vps-first-deployment.md) to install and check independent services and rehearse offsite recovery. Full application startup on this profile is gated. Use the local evaluation below for a working product demonstration, or the [AWS runbook](docs/operations/production-aws-runbook.md) for the complete production topology.

## Local evaluation

You need Docker, Go, Node.js 22, and a free [Stytch](https://stytch.com/) B2B test project for sign-in. Then:

```bash
./zasp --profile local config init
```

Fill in the three Stytch values and your first administrator in `zasp.env`, and ask what else is missing:

```bash
./zasp doctor
```

Install and start everything:

```bash
./zasp up
```

It ends with the address to open and how to sign in. To stop it:

```bash
./zasp stop
```

The whole product runs on your machine: PostgreSQL, Temporal, OpenFGA, OpenSearch, Neo4j and an AWS emulator with one sample account to connect. No Docker? The administrator guide describes a [reduced mode without containers](docs/getting-started/administrator.md#without-docker).

## Deployment profiles

| Profile | For | How |
| --- | --- | --- |
| `vps` | Independent services on k3s and encrypted backups | [First-deployment guide](docs/operations/vps-first-deployment.md) |
| `local` | Trying it on one machine | `./zasp --profile local config init`, then `./zasp up` |
| `kubernetes` | Trying it on any cluster, from one Helm chart and one values file | `./zasp --profile kubernetes up`, or `helm upgrade --install zasp deploy/kubernetes/zasp -f zasp-values.yaml` |
| `aws` | Production on EKS | `./zasp --profile aws install`, which prints the procedure |

The CLI exposes these operations where the selected profile supports them: `doctor`, `secrets init`, `install`, `bootstrap-admin`, `up`, `start`, `stop`, `status`, `logs`, `upgrade`, `backup`, `restore`, `uninstall`.

Trying the local or Kubernetes evaluation? Fill an environment of its own with sample data for one person, who then signs in as usual:

```bash
./zasp demo seed --email person@example.com
```

`./zasp demo status` shows it and `./zasp demo remove --yes` deletes it. The sample company is fictional, and the command writes only to its own environment. See [Demo data](docs/getting-started/administrator.md#demo-data).

Two things to know up front. The product needs AWS APIs (STS, Secrets Manager, KMS, S3, SQS); the two evaluation profiles emulate them and are not for real data. And sign-in goes through Stytch, a hosted identity provider, in every profile.

## Documentation

| Read this | If you |
| --- | --- |
| [Administrator guide](docs/getting-started/administrator.md) | Install, configure, operate, back up or upgrade Zasp. Every key and secret is listed there. |
| [User guide](docs/getting-started/user.md) | Use Zasp once it runs: connect an account, read findings, run a test. |
| [API contract](openapi/openapi.yaml) | Call the API. It is an OpenAPI 3 document; `npm run openapi:lint` checks it. |
| [Infrastructure providers](docs/operations/infrastructure-providers.md) | Choose providers, check the support matrix, and migrate or roll back a deployment. |
| [Operations reference](docs/operations/) | Need the detail behind the administrator guide: [production deployment](docs/operations/production-deployment.md), [AWS runbook](docs/operations/production-aws-runbook.md), [schema installation](docs/operations/baseline-schema-install.md), [first organization](docs/operations/first-organization-bootstrap.md), [backup and rollback](docs/operations/backup-restore-rollback.md). |
| [Connectors](docs/operations/saas-connectors.md), [Google Cloud](docs/operations/google-cloud-connector.md), [hosted gateway](docs/operations/hosted-gateway.md), [guardrail decision API](docs/operations/guardrail-decision-api.md) | Turn on an optional capability. |
| [Architecture at a glance](docs/getting-started/administrator.md#architecture-at-a-glance) | Want to know which component does what. |

## Documentation and SDKs

The documentation site and four client libraries are built from the API contract with [Fern](https://buildwithfern.com).

| Path | Contents |
| --- | --- |
| [`fern/README.md`](fern/README.md) | How the site and the SDKs are built, checked, previewed and published |
| [`fern/docs.yml`](fern/docs.yml), [`fern/docs/pages/`](fern/docs/pages/) | The site: quickstart, concept pages, one page per integration, guides and the API reference of every operation |
| [`docs/getting-started/user.md`](docs/getting-started/user.md), [`docs/getting-started/administrator.md`](docs/getting-started/administrator.md) | The two guides. Each is also a page of the site, from this one source. |
| [`sdks/`](sdks/README.md) | TypeScript, Python, Go and Java clients for the operations an API token may call. Installed from this repository; not published. |

`npm run docs:check` validates the site and `npm run sdk:test` compiles and tests the TypeScript and Go clients.

## Repository layout

| Path | Contents |
| --- | --- |
| `zasp`, `deploy/zasp/` | The entry point, its configuration example and its tests. |
| `services/platform/` | The backend, in Go: the API, the workers, the collectors, the schema installer. |
| `app/`, `apps/web/` | The web application. |
| `openapi/` | The API contract and its tests. |
| `deploy/local/` | The local stack. |
| `deploy/kubernetes/zasp/` | The evaluation Helm chart. |
| `deploy/staging/`, `deploy/production/` | Terraform, the production Helm chart and the image definitions. `staging` is a historical name: it is the only Terraform root. |
| `docs/` | Guides, operations reference and design records. |

## Development

```bash
npm ci
```

```bash
npm run build
```

```bash
node --test deploy/zasp/zasp.test.mjs
```

Backend packages are tested with `go test` from `services/platform`. The project's detailed implementation status, which this page replaced, is kept unchanged in [docs/internal/README-status-archive.md](docs/internal/README-status-archive.md).

## License and contributing

This repository has no `LICENSE` file and no contributing guide yet. Until a license is added, no rights are granted beyond reading the code; ask the owners before you use or redistribute it.
