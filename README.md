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

All application UI mutations are deterministic browser-local demo actions
persisted with local storage. Separately documented proof commands use only
their explicit disposable test fixtures; no production resource is changed.

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

## Platform API command

M1-01d is Complete. It creates the first minimal Go command at
`services/platform/agentsec-api`. The command's only current behavior is one
exact build-version line:

```text
agentsec-api build <version>
```

This skeleton does not start an HTTP server, load runtime configuration, read
credentials or provider state, or claim API readiness. The development build
uses `dev`; release builds may inject a bounded version at link time.

## Platform worker command

M1-01e is Complete. It adds the second minimal Go command at
`services/platform/agentsec-worker`. Its only current behavior is one exact
build-version line:

```text
agentsec-worker build <version>
```

This skeleton does not start a worker loop, poll a queue, load runtime
configuration, read credentials or provider state, or claim worker readiness.
The development build uses `dev`; release builds may inject a bounded version
at link time.

## Event ingest command

M1-01f is Complete. It creates the standalone Go service at
`services/event-ingest`. Its only current behavior is one exact build-version
line:

```text
event-ingest build <version>
```

This skeleton does not accept events or start a listener, normalize or batch
payloads, contact SQS, load runtime configuration, read credentials or provider
state, or claim ingest readiness. The development build uses `dev`; release
builds may inject a bounded version at link time.

## Runtime gateway command

M1-01a is Complete. It creates the standalone Go service at
`services/runtime-gateway`. Its only behavior in this task is one exact
build-version line:

```text
runtime-gateway build <version>
```

This skeleton does not start a proxy or listener, MCP server, tool/API gateway,
or OPA evaluator; it loads no runtime configuration, credentials, provider
state, or policy bundle and claims no gateway readiness. The development build
uses `dev`; release builds may inject a bounded version at link time.

## Worker package commands

M1-01b is Complete. It creates separate Python security-worker and Node
redteam-worker package skeletons. Their only behavior in this task is
one exact no-op health result each:

```text
security-worker health ok
redteam-worker health ok
```

These skeletons do not start worker loops, import Cartography, Prowler, or
Promptfoo adapters, read queues, graphs, prompts, findings, configuration,
credentials, or provider state, open listeners, or perform network operations.
Shared liveness and readiness endpoints remain deferred to M1-28.

## Web and CLI directory boundaries

M1-01c is Complete. The `apps/web` package delegates to the existing locked
runnable UI build through this exact command:

```bash
npm --prefix apps/web run build
```

The standalone CLI boundary exposes only this exact version shape:

```text
agentsecctl version <version>
```

Run its independent Go module from the repository root with
`go run -C cmd/agentsecctl . version`.

The CLI does not implement preflight, recovery, diagnostics, provider access,
credential loading, listeners, or network behavior. The web boundary does not
copy or fork the existing product UI.

## Repository build

M1-01 is Complete. The prepared checkout builds every existing service,
worker, web, and CLI target through one root command:

```bash
npm run build:repo
```

The command does not install or download dependencies. It adds no provider,
credential, listener, network, or runtime product behavior, and the existing
Runnable UI verification command remains unchanged.

## Product dependency lock

M1-02 is Complete. Direct dependencies of deployable product manifests are
recorded with an exact resolved version, SPDX license, internal owner, runtime
scope, and explicit review state. Validate that inventory with:

```bash
npm run dependencies:check
```

The check is local and deterministic: it performs no installation, download,
provider, Docker, credential, or network operation. Proof-only, development,
optional peer, and transitive dependencies remain governed by their existing
locks or proof-specific license records rather than this product-runtime lock.

## Canonical product identity

M1-03 is Complete. Product-owned primary IDs use the opaque exact text form
`pid_<canonical-uuid>` and remain a distinct type from bounded external-source
references. A vendor ARN, numeric ID, or UUID-shaped vendor ID is never copied,
hashed, normalized, or parsed into a product primary key. This task adds only
dependency-free platform-domain value types; scope and persistence remain in
later M1 tasks.

## Product scope model

M1-04 is Complete. Every scoped security entity follows the exact
`Organization -> Workspace -> Environment` product-ID hierarchy. Missing,
zero, malformed, or duplicate hierarchy IDs fail closed; vendor identifiers
remain outside the product scope boundary.

## Product evidence model

M1-05 is Complete. Evidence references use canonical product identity;
evidence confidence and capability/path state use separate exact lowercase
vocabularies. Evidence confidence never substitutes for finding severity, and
a reference alone never grants scoped access.

## Product error envelope

M1-06 is Complete. Customer API failures use one stable product error code,
bounded product-language message, canonical correlation ID, and explicit
retryable flag. The exact four-field response excludes vendor exceptions,
debug metadata, credentials, and implicit retry guesses.

## Product configuration loader

M1-07 is Complete. The platform configuration boundary is typed and
reference-only: missing required dependency configuration fails startup, while
PostHog, OpenRouter, and remote OTLP remain optional. Secret configuration uses
strict Secrets Manager references and does not load or expose secret material.

## External client policy

M1-08 is Complete. Shared HTTP client execution uses one total deadline,
bounded concurrency, transient-only retry classification, and capped
exponential backoff with jitter. Read-only and explicitly idempotent operations
may retry; non-idempotent mutations are never retried.

## Idempotency helper

M1-09 is In progress. An Organization-scoped idempotency request binds its
operation, caller key, and exact request fingerprint before any side effect.
Only the unique acquired claim executes; completed duplicates return the prior
canonical product result. In-progress, conflicting, failed, canceled, panicked,
or unknown outcomes remain in progress for explicit reconciliation and are not
executed automatically.

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

## Provisional LocalStack IAM compatibility proof

This isolated proof starts an exact-pinned, proof-owned disposable LocalStack
target with IAM and STS only, on a random loopback port. Docker and Go are required.
No credentials are accepted, and IAM enforcement is mandatory.

The proof uses two fixed account values as emulator namespaces. They do not
establish AWS account isolation. It demonstrates a LocalStack-only assumed-role
allowed read, explicit deny, and cleanup result, not real-AWS parity.

```bash
npm run proof:localstack:iam:test
npm run proof:localstack:iam:run
```

The runner accepts no dotenv input, never uses shared development LocalStack,
and emits only a fixed result line. PROV-01 cannot complete M0-09 or R-03.
PROV-01 is Blocked on LocalStack 4.7.0 because the live provider did not return
SourceIdentity and accepted a wrong SourceIdentity despite the required trust
condition. M0-10 is Complete under the Cartography delivery waiver for a
fixture-only normalization and OSS integration proof; it makes no AWS/GitHub
authorization-parity claim. Official LocalStack v4.14.0 source retains the
same unsupported forwarding path; that is source review only, not a claim that
v4.14.0 was live-tested.

## Cartography Organization-scope proof

This proof requires Docker and Python 3.13.11; the test command invokes the
repository's pinned `/opt/homebrew/bin/python3.13` interpreter. It is a
two-Organization fixture-only proof using only the two synthetic `.test`
fixtures. It accepts no dotenv, credential, or proxy input and makes no AWS or GitHub calls.

The disposable runtime loads each fixture into its proof-owned Cartography and
Neo4j containers, compares the isolated normalized graphs, and applies
customer-label normalization so customer-visible node and relationship labels
do not expose Cartography, Neo4j, AWS, or GitHub implementation names. It
cleans up only its exact proof-owned containers, network, and temporary
directories, then verifies their absence. The live command emits only this
fixed result on success:

```text
Cartography scope proof passed: fixtures=2 nodes=8 relationships=4 isolated=true labels_safe=true cleanup=true.
```

```bash
npm run proof:cartography:test
npm run proof:cartography:run
```

This fixture-only integration proof does not prove AWS/GitHub authorization parity. M0-10 is Complete; M0-09 and PROV-01 remain Blocked, and R-03 remains incomplete.

## Prowler evidence proof

M0-11 is Complete as a fixture-only evidence proof. Its hermetic test command
requires Node.js `22.23.1` and npm `10.9.8`, plus Python `3.13.11`; it does not
start Docker or contact a provider. The live command additionally requires
Docker and uses only these exact-pinned images:

- `prowlercloud/prowler:5.39.0@sha256:58c8a0eb0c947517bd89b6214cde0cc1d5f59df4eebbb99a87475ab741914959`
- `localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c`

The live proof creates one private disposable Docker network and one synthetic IAM role,
then runs only the built-in
`iam_role_cross_service_confused_deputy_prevention` check. It retains one
JSON-OCSF result and maps it to the canonical Organization-scoped resource
identity established by M0-10. The commands accept no dotenv, credential,
profile, proxy, provider endpoint or network-target input, disable IMDS, and do
not load host Docker authentication. Only fixed synthetic credentials reach
the disposable LocalStack fixture.

The license audit binds the exact local image metadata to immutable tagged source
fingerprints without reading dotenv files, provider credentials, profiles, proxy
settings, or ambient Docker authentication. Prowler 5.39.0 and its direct
`py-ocsf-models` 0.10.0 adapter dependency are Apache-2.0. The exact free/community
LocalStack Community image is inventoried at the tagged source boundary as
Apache-2.0 plus its tagged community EULA; bundled third-party components retain
their own terms and are not relicensed or covered by that statement.

The live command emits exactly one line. Its fixed success line is:

```text
Prowler evidence proof passed: findings=1 resources=1 evidence=1 linked=true cleanup=true.
```

Every failure uses the fixed line
`Prowler evidence proof failed: <category> rejected.`, where the category is one of `configuration`, `provider`,
`ownership`, `normalization`, `cleanup`, or `operation`. Cleanup re-proves and
removes only the exact proof-owned containers, network, output, and temporary directories,
then verifies their absence.

```bash
npm run proof:prowler:test
npm run proof:prowler:license
npm run proof:prowler:run
```

This fixture-only evidence does not prove real-AWS authorization or parity,
broad Prowler coverage, LocalStack IAM parity, or production runner behavior.
R-06 is PASS with the retained reviewed M0-11 live evidence. M0-09 and PROV-01
remain Blocked, and R-03 remains incomplete.

## OTLP ingest proof

M0-13 provides a local ingest-only proof using Node.js `22.23.1` and npm `10.9.8`.
The hermetic command validates the source trace, strict product
adapter, Collector configuration, stable artifact boundary, exact Docker
ownership, deadlines, fixed output, and cleanup without starting Docker. The
disposable live command uses this immutable Collector Contrib image:

`otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5`

The live lifecycle publishes only the OTLP/HTTP receiver to a random
loopback-only host port. Its Collector pipeline writes to an exact-owned local
artifact for the product adapter; remote OTLP export is disabled. The one
synthetic span carries only bounded Organization, agent, session, task, tool,
and sandbox identifiers. It carries no raw prompts, tool arguments, credentials, or customer payloads.

```bash
npm run proof:otlp:test
npm run proof:otlp:run
```

Success is exactly:

```text
OTLP ingest proof passed: traces=1 spans=1 identity=true cleanup=true.
```

M0-13 is Complete after two consecutive final-code live runs, exact zero-resource
cleanup audits, pinned local gates and scans, and zero-finding independent
review.

This proof establishes local Collector-to-adapter identity preservation only.
Together with M0-22's bounded export/failure proof, this retained ingest
evidence makes R-12 PASS. M0-09 and PROV-01 remain Blocked, and R-03 remains
incomplete.

## OTLP export proof

M0-22 is Complete. It runs an exact-pinned source Collector and fake
sink Collector on one private internal proof network. The first bounded
synthetic operation must reach the sink; after the exact sink is stopped, the
next application operation must still complete within its independent bound.

The proof accepts no hosted telemetry endpoint, credential, dotenv, profile,
proxy, ambient Collector configuration, arbitrary destination, or customer
payload.

```bash
npm run proof:otlp-export:test
npm run proof:otlp-export:run
```

Success is exactly:

```text
OTLP export proof passed: delivered=true bounded=true exporter_failed=true application_unblocked=true cleanup=true.
```

Two consecutive final-code live passes proved first delivery, exact exporter
failure, nonblocking application progress, and exact cleanup. Combined with
the retained M0-13 ingest evidence, R-12 is PASS.

## M0 technical proof gate

M0-23 is Complete as an evidence-only architecture gate. It records one
decision for every M0 risk boundary without rerunning provider or container
proofs. The selected decision is **PROCEED WITH BLOCKED PATHS**. The completed
gate authorizes M1 foundation work after this exact completion SHA passes CI,
but R-03 continues to block real-AWS IAM parity claims and R-11 continues to
block EKS Fargate strong-isolation and egress claims. Neither blocker may be
replaced by LocalStack, fixture-only, source-review, or harness-only evidence.

The current record is `12 PASS / 2 BLOCKED / 0 FAIL / 0 unclassified` in
`docs/decisions/m0-technical-proof-gate.md`. The two blocked decisions are
R-03, awaiting M0-09's isolated real-AWS fixture, and R-11, awaiting M0-18 and
M0-19's isolated real-EKS fixtures.

## PostHog privacy proof

M0-20 is Complete. It proves one allowlisted product analytics event against
a fake PostHog endpoint on a random loopback port. The serializer constructs a
closed event document and rejects seeded prompt, secret, IP-address, and raw-
evidence fields before any network request. It reads no `.env`, credential,
proxy, hosted endpoint, SDK, or ambient PostHog configuration.

```bash
npm run proof:posthog:test
npm run proof:posthog:run
```

Success is exactly:

```text
PostHog privacy proof passed: event=true prompt=false secret=false ip=false evidence=false cleanup=true.
```

Failures are one fixed category line. No raw event, seeded prohibited value,
URL, port, HTTP body, stack trace, or error reaches output. This local proof
does not claim hosted PostHog availability, account configuration, feature-
flag behavior, or production analytics delivery. The exact local proof,
privacy rejections, cleanup, gates, scans, and review passed, so R-13 is PASS.
M0-09, M0-18, M0-19, and PROV-01 remain Blocked.

## OpenRouter privacy proof

M0-21 is Complete. Its local-only boundary sends one redacted synthetic
finding explanation to a fake OpenRouter-compatible endpoint on a random
numeric-loopback port, then accepts only one closed structured explanation
schema. It reads no `.env`, real credential, hosted endpoint, SDK, proxy,
profile, or ambient provider/model configuration.

```bash
npm run proof:openrouter:test
npm run proof:openrouter:run
```

Success is exactly:

```text
OpenRouter privacy proof passed: explanation=true secret=false pii=false structured=true cleanup=true.
```

The product gateway constructs one closed request, removes all seeded secret,
person-name, email, phone, and raw-evidence values, then rejects residual
prohibited material before I/O. The endpoint and client require exact bounded
OpenRouter-compatible request/response documents; product state accepts only a
closed finding-explanation schema. Cleanup closes the retained loopback server
under an independent deadline, and failures emit only a fixed category line.
This is local privacy/schema evidence, not hosted OpenRouter availability,
provider/model quality, production routing, or planner authorization. The exact
proof, seeded-value absence, strict structured validation, cleanup, gates,
audit, scans, and adversarial review passed. M0-21a is Complete, and the
combined explanation/privacy and fixed-action-catalog evidence makes R-14 PASS.

## Security Agent planner boundary proof

M0-21a is Complete. Its local-only boundary sends one structured planning
request containing bounded untrusted injection text, an exact two-action
catalog, and exact in-scope IDs to a fake OpenRouter-compatible endpoint on a
random numeric-loopback port. Product validation must accept only the exact
catalog actions and in-scope identifiers.

The proof has no hosted model, real credential, SDK, dotenv, proxy, profile,
arbitrary network target, general shell, or execution authority. Root commands
are hermetic and contact only the retained numeric-loopback fake endpoint:

```bash
npm run proof:planner:test
npm run proof:planner:run
```

Success is exactly:

```text
Security Agent planner proof passed: catalog=true scope=true injection=false url=false shell=false cleanup=true.
```

The exact proof, six focused runs, full pinned repository gates, production
audit, redacted scans, and adversarial review passed. Combined with M0-21's
redacted explanation proof, R-14 is PASS. M0-22 is Complete and R-12 is PASS.

## EKS Fargate egress proof

M0-19 is Blocked. Its reviewed fail-closed harness is ready to prove the second
half of R-11 against real EKS Security Groups for Pods: one exact
`SecurityGroupPolicy`, a pre-provisioned read-only restricted Pod security
group, and one fresh Fargate canary Job. The required evidence is direct
undeclared HTTPS failure, the same named canary through the product egress
proxy, exact EC2 security-group rules, exact Pod ENI attachment, and reverse
zero-resource cleanup.

This is a real EKS Security Groups for Pods proof boundary.

Run the hermetic lifecycle, strict kubectl/EC2 boundary, supervisor, and audit
tests with `npm run proof:fargate-egress:test`. The live entry point is
`npm run proof:fargate-egress:run`; it requires every documented task-specific
real-provider input before building or making a request. Its only success line
is `EKS Fargate egress proof passed: direct_denied=true proxy_allowed=true eni_attached=true cleanup=true.`
Failures are fixed as `EKS Fargate egress proof failed: <category> rejected.`
Run `npm run proof:fargate-egress:license` to bind the immutable multi-platform
BusyBox image, Kubernetes packaging, and underlying GPL runtime.

The capability audit found 0/19 required inputs: no authenticated disposable
real EKS/EC2 fixture, Fargate profile, restricted Pod security group, product
proxy endpoint, or canary credential. The fixed configuration gate rejects
before building or making a cluster or AWS request. LocalStack cannot provide
AWS-managed Fargate, branch-ENI, or real EKS Security Groups for Pods authority
and cannot emit success. Resume only after all documented task inputs are
available for an isolated disposable real-EKS test fixture. M0-18 remains
Blocked, R-11 remains Not run, and M0-20 is In progress.

## EKS Fargate verification proof

M0-18 is Blocked. The reviewed fail-closed harness is ready for one canary Job
on an explicitly supplied real EKS Fargate disposable test profile. The live
gate requires the selected Pod to bind to the named profile, its assigned node
to report the Fargate compute type, the canary to receive the exact response
through the product proxy, and every proof-owned Kubernetes resource to be
absent after cleanup.

Run the hermetic lifecycle, kubectl-boundary, supervisor, and audit tests with
`npm run proof:fargate:test`. The inert live entry point is
`npm run proof:fargate:run`; it rejects at configuration before building or
contacting a cluster unless all eleven documented real-provider inputs are
present. Its only success line is
`EKS Fargate proof passed: scheduled=true canary=true cleanup=true.` Run
`npm run proof:fargate:license` to bind the immutable multi-platform image,
Kubernetes mirror commit and Apache-2.0 packaging, and the underlying BusyBox
1.36.1 GPL-2.0-only runtime. The packaging license does not relicense BusyBox.

The capability audit found 0/11 required inputs: no real-AWS credential,
authenticated EKS kubeconfig, disposable Fargate profile, product proxy
endpoint, or test canary credential, so the harness performs no cluster
request. LocalStack can exercise generic EKS
and Kubernetes compatibility with embedded k3s/k3d nodes, but it cannot prove
Fargate. R-11 remains Not run; M0-19 is Blocked. M0-09 and PROV-01 remain
Blocked, and R-03 remains incomplete.

## OPA SDK proof

M0-17 is Complete. It evaluates one Allow and one Block decision with OPA
v1.17.0 through the exact-pinned official OPA Go SDK embedded in-process. The
proof prepares one fixed internal policy query, performs 100 warm-ups per decision and 1,000
measured evaluations per decision, and requires each decision-specific p95 at
or below 10 ms. It has no server, subprocess, bundle, network call, customer
Rego, or environment configuration.

Run `npm run proof:opa:test` for race-enabled evaluator tests,
`npm run proof:opa:run` for the direct in-process proof, and
`npm run proof:opa:license` for the immutable official tag, module-sum, and
Apache-2.0 audit. Direct success is exactly
`OPA SDK proof passed: allow=true block=true deterministic=true evaluations=2000 p95_under_10ms=true.`
Two consecutive direct final-code proofs, six race runs, exact dependency and
license audits, full pinned repository gates, and whole-range review passed.
R-10 is PASS. M0-18, M0-09, and PROV-01 are Blocked, and
R-03 remains incomplete.

## Promptfoo red-team proof

M0-16 is Complete. It runs one direct prompt-injection case through the
exact-pinned official Promptfoo 0.121.19 engine against a local fake agent on a
private internal Docker network. The product boundary will retain only the
objective, verdict, and evidence reference; raw prompts, target responses,
Promptfoo-native identifiers, and Docker state must remain outside product
output. The proof uses only synthetic local inputs, no hosted generation, and
no host-published port, and no model or provider credential.

Run `npm run proof:promptfoo:test` for the hermetic suite,
`npm run proof:promptfoo:license` for the immutable source/image/MIT audit, and
`npm run proof:promptfoo:run` for the disposable live lifecycle. Docker prerequisite:
a running local Docker engine with the exact image available or pullable. Live
success is exactly
`Promptfoo red-team proof passed: objective=true verdict=vulnerable evidence=true cleanup=true.`
Only the objective, verdict, and evidence reference are retained; raw prompts, target responses, canaries, Promptfoo-native identifiers, and Docker state
are excluded from product output. Two consecutive final-code live passes,
exact zero-resource cleanup, pinned gates, immutable license and secret scans,
and a zero-finding whole-range review passed. R-09 is PASS.

## Nango proxy proof

M0-15 is Complete. It proves one authenticated provider GET through the
exact-pinned free self-hosted Nango Proxy surface against a private TLS fixture.
The fixture first accepts Nango's exact API-key introspection request, then one
distinct bearer-authenticated `GET /api/v2/events?limit=1`. The product wrapper
calls that provider endpoint only through Nango's authenticated Proxy route and
retains scoped opaque references plus the allowlisted event ID and action.

The hermetic command tests parsing, the ordered fixture, product secrecy,
immutable manifests, exact Docker ownership, bounded mutation settlement,
fixed output, and cleanup without starting Docker. The live command requires
Node.js 22.23.1, npm 10.9.8, Docker, and OpenSSL. It reads no `.env`, profile,
cloud/provider credential, proxy variable, or ambient Docker authentication;
the private internal network publishes no host port.

```bash
npm run proof:nango:proxy:test
npm run proof:nango:proxy:run
```

Success is exactly:

```text
Nango proxy proof passed: get=true response=true product_state_safe=true cleanup=true.
```

The raw provider token, Nango environment key, connect token, database
password, and encryption key never enter product state or fixed output. Two
consecutive final-code live runs, exact zero-resource audits, pinned gates,
license/secret scans, and a zero-finding whole-range review passed.
R-08 is PASS at M0-15.

## Nango free Auth boundary

M0-14 is Complete. The accepted free self-hosted Nango MVP boundary is
long-tail Auth plus Proxy; M0-15 now supplies the authenticated Proxy GET.
Functions, Webhooks, and MCP are out of scope, as are Nango RBAC, full
observability, Connect UI, and Enterprise-only features.

This boundary consolidates the completed M0-14a boot, M0-14b OAuth, and M0-14c
API-key evidence. It adds no runtime or provider call and is not a claim that
every excluded route is absent from the pinned image. Core launch connectors
remain product-owned and bypass Nango. R-08 is PASS at M0-15;
M0-09 and PROV-01 remain Blocked, and R-03 remains incomplete.

## Nango API-key proof

M0-14c is Complete. This proof extends the completed private Nango boot and
OAuth boundaries with one real API-key connection through exact-pinned Nango
v0.70.5 and PostgreSQL 16.0. A generated raw provider key is checked once by
the built-in `1password-events` integration against a private TLS fixture at
`events.1password.com`; the fixture accepts only the exact bearer-authenticated
`GET /api/v2/auth/introspect` request.

The hermetic command validates the workspace, fixture, product wrapper,
immutable four-role manifest, exact Docker ownership, bounded mutation
settlement, fixed output, and cleanup without starting Docker. The live command
requires Node.js 22.23.1, npm 10.9.8, Docker, and OpenSSL. It accepts no `.env`,
real credential, provider endpoint, proxy, profile, or ambient Docker
authentication and publishes no host port.

```bash
npm run proof:nango:api-key:test
npm run proof:nango:api-key:run
```

Success is exactly:

```text
Nango API key proof passed: api_key=true reference=true product_state_safe=true cleanup=true.
```

The product receives only the Organization-scoped durable connection reference.
The raw provider key never enters product state or fixed output. Every live run
uses fresh marker-scoped resources and reverse exact-owned cleanup. R-08 is
PASS at M0-15; M0-09 and PROV-01 remain Blocked, and R-03 remains
incomplete.

## Nango OAuth proof

M0-14b extends the completed Nango free-boot proof with one real OAuth2
authorization-code connection against a private, synthetic TLS fixture provider.
The disposable runtime contains PostgreSQL, Nango v0.70.5, the fixture, and a
one-shot product wrapper on one internal Docker network with no host port
publication. It reads no `.env`, cloud credential, profile, proxy, or ambient
Docker authentication state.

The hermetic command validates the strict wrapper and fixture parsers, PKCE and
single-use behavior, exact image/runtime ownership, bounded mutation settlement,
fixed output, and cleanup without starting Docker. The live command generates a
fresh CA, server certificate, client credentials, authorization code, access
token, database password, and encryption key. Product output retains only the
Organization-scoped durable connection reference; seeded secrets, the Nango API
key, and the connect-session token never cross that boundary.

```bash
npm run proof:nango:oauth:test
npm run proof:nango:oauth:run
```

Success is exactly:

```text
Nango OAuth proof passed: oauth=true reference=true product_state_safe=true cleanup=true.
```

Every live run uses fresh marker-scoped resources and reverse exact-owned
cleanup. M0-14b is Complete after two consecutive final-code live passes,
complete zero-resource audits, full repository gates and scans, and a
zero-finding pre-landing review. R-08 is PASS at M0-15. M0-14c and M0-15 are
Complete.

## Nango free boot proof

M0-14a proves the current free self-hosted Nango server can boot with only its
required PostgreSQL dependency and become database-ready from a product-side
test client on a private internal Docker network. The exact Nango v0.70.5,
PostgreSQL 16.0, and BusyBox probe images are pinned by immutable digest.
Neither service publishes a host port.

The hermetic command validates pins, the free Auth/Proxy boot configuration,
strict readiness parsing, synthetic database/encryption material, complete
Docker ownership, bounded mutation settlement, fixed output, and cleanup
without starting Docker. The live command creates a fresh marker-scoped
database and encryption key, prepares the exact upstream-required `nango` and
`nango_records` schemas inside that isolated database, polls PostgreSQL, then
requires the one-shot product probe to receive exactly `{"result":"ok"}` from
Nango's database-backed `/ready` endpoint.

```bash
npm run proof:nango:test
npm run proof:nango:run
```

Success is exactly:

```text
Nango free boot proof passed: services=2 ready=true product_network=true cleanup=true.
```

The proof does not read `.env`, profiles, cloud credentials, product database
credentials, proxy settings, or ambient Docker authentication. Redis,
Elasticsearch, Connect UI, RBAC, orchestration, and Enterprise mode are absent
or disabled in the exact boot configuration. The proof does not invoke or
depend on Functions, Webhooks, or the MCP server, but does not yet prove those
routes unreachable. It proves minimum free boot and private product-network
readiness only; OAuth, API-key connection, and authenticated Proxy proof were
completed in M0-14b through M0-15.

M0-14a is Complete after two consecutive final-code live runs, exact zero-
resource audits, full gates/scans, and an independent zero-finding review.
R-08 is PASS at M0-15. M0-09 and PROV-01 remain Blocked, and R-03
remains incomplete.

## Tetragon signal proof

M0-12 is Complete under the approved observation-only design. The two consecutive final-code live runs
proved that one exact-owned disposable Kubernetes workload
emitted process, file, and outbound TCP events. The proof retained the same Kubernetes workload identity
and explicit capability and drop state, with zero drop/loss counters.

The selected immutable runtime includes:

- `quay.io/cilium/tetragon:v1.7.0@sha256:deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527`
- `quay.io/cilium/tetragon-operator:v1.7.0@sha256:074ffbd19208eed79f68e191ed606e05009f910b4bb5148efcf2973e13504b82`
- `kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95`

Run the hermetic parser, manifest, and lifecycle tests with Node.js 22.23.1:

```bash
npm run proof:tetragon:test
```

The disposable live proof requires Docker, kind 0.32.0, Helm 3, and kubectl on
the explicit tool path. It downloads and verifies the pinned kind binary and
Helm chart, uses an owned Docker configuration and kubeconfig, and does not load `.env`,
ambient kubeconfig, cloud credentials, profiles, or proxy variables. Run it with:

```bash
npm run proof:tetragon:run
```

Success is exactly:

```text
Tetragon signal proof passed: process=true file=true network=true identity=true capability=true drops=0 cleanup=true.
```

Every lifecycle uses exact-owned cleanup for the namespace, chart, cluster,
node container, network, kubeconfig, downloaded assets, and temporary files.
Failures emit only a fixed category line.

The workload's outbound TCP action targets only an in-cluster fixture sink; it
does not prove internet egress. The proof does not enable enforcement, treat
Tetragon as semantic truth, or claim production-kernel coverage. R-07 is PASS
with retained live, cleanup, gate, license/secret scan, and zero-finding independent review
evidence. M0-09 and PROV-01 remain Blocked, and R-03 remains
incomplete.

## Real AWS cross-account IAM proof

This proof is deliberately real-AWS-only. It requires two explicitly configured,
isolated commercial AWS test accounts: source credentials authorized to assume the
proof role and target-administrator credentials authorized to create and remove
only the unique disposable role. LocalStack cannot satisfy this release-parity authorization gate.

The ignored `.env` must provide these exact task-specific inputs:

- `AWS_M009_ISOLATED_TEST`
- `AWS_M009_REGION`
- `AWS_M009_SOURCE_ACCOUNT_ID`
- `AWS_M009_TARGET_ACCOUNT_ID`
- `AWS_M009_SOURCE_PRINCIPAL_ARN`
- `AWS_M009_SOURCE_ACCESS_KEY_ID`
- `AWS_M009_SOURCE_SECRET_ACCESS_KEY`
- `AWS_M009_TARGET_ADMIN_ACCESS_KEY_ID`
- `AWS_M009_TARGET_ADMIN_SECRET_ACCESS_KEY`

`AWS_M009_SOURCE_SESSION_TOKEN` and
`AWS_M009_TARGET_ADMIN_SESSION_TOKEN` are optional when the corresponding
explicit credential is not temporary. `AWS_M009_ISOLATED_TEST` must equal
`isolated-disposable-aws-test-accounts-only`. Account IDs, role ARNs,
credentials, session values, and provider responses are never printed.

Before mutation, the command authenticates both credential sets, matches the
separately configured expected accounts, proves the accounts differ, and requires
the generated proof path to be empty. It then creates one exactly tagged role
whose trust policy requires a generated external ID, role-session name, source
identity, and session tag. The assumed role can call `iam:GetRole` only for
itself, while an explicit policy denies `iam:ListRoles`. Cleanup independently
re-authenticates the target administrator, re-proves the role, tags, trust and
inline policy, removes them with no mutation retries, and audits the generated
path empty.

```bash
npm run proof:aws:iam:test
npm run proof:aws:iam:run
```

The runner passes only task-specific values to the proof binary; AWS profiles,
shared config, IMDS, ambient proxies, custom endpoints, and provider debug output
are disabled. The current workspace does not contain the task-specific isolated
source/target fixture, so only the deterministic local test command is presently
expected to pass. M0-09 is Blocked and R-03 remains incomplete until the
documented live command proves the real allowed/denied results and exact cleanup
in those isolated accounts. No shared, staging, customer, or production AWS account may be used.

The application uses Vinext and targets the Cloudflare Workers runtime. Optional
local D1 and R2 bindings can be enabled with `CLOUDFLARE_D1_BINDING` and
`CLOUDFLARE_R2_BINDING`; no database or object-storage binding is required for
the browser-local prototype.

Application authentication will use Stytch B2B. The current prototype runs
without an authentication gate until that integration is configured.
