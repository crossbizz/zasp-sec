# Real-dependency local stack

`stack.sh` runs the unmodified product API binary on one machine against real dependencies:

- PostgreSQL 18.3 with the baseline schema installed by `agentsec-migrate install-baseline`, as a non-superuser operator, the way managed PostgreSQL requires
- the pinned Temporal 1.32.0 and OpenFGA 1.21.0 servers from `../temporal-openfga.compose.yaml`
- the product authorization model published to that OpenFGA
- a real Stytch B2B project, through its API credentials
- LocalStack 4.7.0 standing in for AWS STS, IAM, Secrets Manager, KMS, S3, SQS and EC2, including one emulated customer account for an AWS integration to connect to
- a single-node OpenSearch 3.8.0 standing in for the managed search domain
- Neo4j 5.26 Community standing in for the managed graph database, serving Bolt over TLS only

It exists because every other harness in this repository replaces Stytch with a loopback fake and seeds memberships with hand-written SQL. This one uses the operator commands a deployment uses: `agentsec-migrate`, `zasp-bootstrap` and `zasp-authorization-reconcile`. See [the baseline installation guide](../../../docs/operations/baseline-schema-install.md).

It is local component evidence. It does not prove a deployment. AWS is emulated, so nothing here proves IAM policy, KMS key policy or network behavior in a real account.

## Development mode and the local cloud endpoint

The binaries are the production binaries. One setting redirects every AWS client to LocalStack:

```bash
export ZASP_ENVIRONMENT=development   # or test
export ZASP_LOCAL_CLOUD_ENDPOINT=http://127.0.0.1:4566
```

The endpoint must be plain HTTP on a loopback or private address with an explicit port. It is honored only when `ZASP_ENVIRONMENT` is `development` or `test`. With any other environment value, including `production`, a process that finds `ZASP_LOCAL_CLOUD_ENDPOINT` set refuses to start and prints `startup refused: stage=local-cloud`. Without the setting, the code path is unchanged: clients use the real regional AWS endpoints. The same switch lets the search driver use the local OpenSearch node over HTTP.

`stack.sh` sets both for the processes it starts.

### What behaves differently in development mode

Everything below is active only when the local cloud endpoint is accepted, that is only with `ZASP_ENVIRONMENT` set to `development` or `test`. Each has a unit test showing the production behavior is unchanged.

| Behavior | Production | Development mode | Why |
| --- | --- | --- | --- |
| Regions the AWS collector reads instances from | Every region AWS lists as enabled. A region that is not enabled in the answer refuses the whole collection. | Regions listed as `not-opted-in`, and `cn-*` and `us-gov-*` regions, are skipped. | LocalStack lists regions that a real account never sees, and answers for China and GovCloud regions with the `us-east-1` instances. |
| Where the posture analyzer (Prowler) re-attests the customer credential | `https://sts.us-east-1.amazonaws.com`, over TLS | The local cloud endpoint. The analyzer applies the same rule itself and refuses a local endpoint in any other environment. | Credentials that LocalStack issued are unknown to AWS. The check is the same; only the host differs. |
| Worker health port | `:8081` | `127.0.0.1:$ZASP_LOCAL_HEALTH_PORT` when that is set to a port number | Several worker modes run on one machine. |
| Certificate authorities the graph worker trusts for Neo4j | The system trust store | Only the authorities in the PEM file `ZASP_LOCAL_NEO4J_CA_FILE` names, when it is set. Certificate and host name verification stay on, and the `neo4j+s` scheme stays required. A named file that cannot be read refuses the start. | The local Neo4j serves a certificate from an authority created on this machine. |
| What the graph worker verifies about its Neo4j user | The user name, that its roles are exactly `PUBLIC` and the expected role, that the role holds exactly four privileges, and the five owned constraints | Against a server that reports the Community edition: the user name, that no password change is pending, and the five owned constraints. Any other edition gets the production check. | Community has no roles and cannot list privileges (`CREATE ROLE` and `SHOW USER ... PRIVILEGES` answer "Unsupported administration command"). Only Neo4j Enterprise can satisfy the production check. |

Nothing is skipped: role assumption with the external ID, the caller identity check, the allow-list of customer roles and both analyzers run as they do in production. LocalStack does not enforce IAM, so it accepts any external ID and never denies an action. A connection that succeeds here says nothing about the trust policy or the permissions of a real customer role.

## Requirements

Docker, Go (the toolchain in `services/platform/go.mod`), `curl` and `openssl`. The web application needs Node.js (the version in `package.json`) and `npm ci`. `psql` is used when installed; otherwise the script runs the one inside the database container. The script is written for bash 3.2, the macOS system bash, as well as current bash; it has not been run on macOS. Stytch credentials in the environment:

```bash
export STYTCH_PROJECT_ID=... STYTCH_SECRET=... STYTCH_PUBLIC_TOKEN=...
```

The same three lines without `export` can be kept in `$ZASP_REAL_STACK_STATE/provider.env` instead; every command reads that file.

The public origin defaults to `https://zasp.local-stack.test:8443`. It must be HTTPS and must not be `localhost`, `*.localhost`, `*.local` or an IP address, because the connector OAuth callbacks refuse those hosts. Map it to loopback:

```bash
echo '127.0.0.1 zasp.local-stack.test' | sudo tee -a /etc/hosts
```

The API and workers read their workload identity token from a fixed path, `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`. `stack.sh up` writes a placeholder token there (LocalStack accepts any token; it is not a credential). The directory must be writable by the user running the script:

```bash
sudo mkdir -p /var/run/secrets/eks.amazonaws.com/serviceaccount
sudo chown "$USER" /var/run/secrets/eks.amazonaws.com/serviceaccount
```

## Everything at once

A tester's walk-through is in [docs/operations/local-self-test.md](../../../docs/operations/local-self-test.md).

```bash
deploy/local/real-stack/stack.sh start    # everything, in the background
deploy/local/real-stack/stack.sh status   # one line per dependency and process
deploy/local/real-stack/stack.sh stop     # stops the processes 'start' started
```

`start` runs `up` when it has not completed or a dependency is not running, then starts the API, seven workers (scheduler, discovery, outbox, the three projection workers and the Security Agent action worker), the permission projector and the web application behind its TLS front. Each runs the foreground command described below, with its pid in `$ZASP_REAL_STACK_STATE/run/` and its output in `$ZASP_REAL_STACK_STATE/logs/`. It is safe to repeat: a process that already runs, or whose port already answers, is left alone. Before the first `bootstrap` it stops after `up` and prints the `bootstrap` command. It rebuilds the web application when its sources are newer than the last build; it does not rebuild the Go binaries (`up` does).

What runs when everything is up:

| `status` line | Command | Health port | Started by `start` |
| --- | --- | --- | --- |
| `api` | `stack.sh api` | 4081 (product listener 4000) | yes |
| `worker-scheduler` | `stack.sh worker scheduler` | 8081 | yes |
| `worker-discovery` | `stack.sh worker discovery` | 8082 | yes |
| `worker-outbox` | `stack.sh worker outbox` | 8083 | yes |
| `worker-projection-graph` | `stack.sh worker projection-graph` | 8091 | yes |
| `worker-projection-search` | `stack.sh worker projection-search` | 8092 | yes |
| `worker-projection-risk` | `stack.sh worker projection-risk` | 8093 | yes |
| `worker-security-agent-action` | `stack.sh worker security-agent-action` | 8085 | yes |
| (not listed) | `OPENROUTER_API_KEY=... stack.sh worker security-agent` | 8084 | no: by hand, it needs the OpenRouter token |
| `projector` | `stack.sh project` | none | yes |
| `ui` | `stack.sh ui` | serves 8443 | yes |

The Security Agent planning worker is the eighth worker. Without it a Security Agent run stays `queued`. Without the permission projector nothing new can be read.

## The web application and its TLS front

```bash
deploy/local/real-stack/stack.sh ui
```

Runs `front.mjs` in the foreground: an HTTPS listener on the public origin's port, on loopback. It starts the built web application (`dist/standalone/server.js`, the file the production web image runs) on `127.0.0.1:3100` and forwards everything to it except `/api`, which goes to the API on `127.0.0.1:4000`. Whatever the browser sent as `Host`, `Forwarded` or `X-Forwarded-*` is dropped and replaced with the public origin's values, which is what the API requires of its ingress. A request for any other host name gets `421` and a note naming the right address.

The certificate is created on first use in `$ZASP_REAL_STACK_STATE/tls/`: a certificate authority (`ca.crt`) whose name constraint permits only the stack's host name, and a server certificate valid for 825 days. The authority's private key is deleted once the server certificate is signed. Trust `ca.crt` in the browser or accept the warning.

The script checks `/etc/hosts` for the host name and prints the line to add. It never edits system files.

## The permission projector

```bash
deploy/local/real-stack/stack.sh project
```

Runs `zasp-authorization-reconcile -mode reconcile -limit 20` every 5 seconds (`ZASP_REAL_STACK_PROJECT_INTERVAL`), the command the production CronJob runs once a minute. Without it a new member, session or resource answers `authorization_pending` or `authorization_unavailable` until someone runs a pass, so it must keep running while the product is used. On 2026-11-13 a new browser session answered `authorization_pending` for a few seconds until the next pass. On 2026-11-14, with the projector running, the read that follows a change in the browser answered `503 authorization_unavailable` or `409 authorization_changed` for 5 to 15 seconds; the web application repeats such a request and shows "Applying recent changes…" meanwhile.

## Use

```bash
deploy/local/real-stack/stack.sh up
```

Starts Temporal, OpenFGA, LocalStack, OpenSearch, Neo4j and the product database, runs the production search-schema job (`projection-search-init`) against the local search node and the production graph-schema job (`projection-graph-init`) against the local Neo4j, creates the AWS resources described under [The emulated AWS account](#the-emulated-aws-account), creates the `zasp_operator` role (no superuser) and its database, installs the baseline schema with its 31 least-privilege service logins, registers the worker, authorization and approval-delivery verifiers, and publishes the authorization model. With the images present, a clean run took about 15 seconds before it created the AWS resources; creating them adds about 30 seconds.

```bash
deploy/local/real-stack/stack.sh bootstrap "Acme Security" acme.example admin@acme.example
```

Creates or resolves the Stytch Organization, invites or resolves the administrator, writes the product records, binds this stack's sign-in to that Organization, and runs one projector pass. See [the bootstrap guide](../../../docs/operations/first-organization-bootstrap.md) for the Stytch dashboard settings an invitation needs.

```bash
deploy/local/real-stack/stack.sh api
```

Runs the API in the foreground. The product listener is `127.0.0.1:4000` and the health listener is `127.0.0.1:4081`. The product listener only accepts requests that carry the headers a trusted TLS proxy sends:

```bash
curl -i http://127.0.0.1:4000/api/v1/session/bootstrap \
  -H 'Host: zasp.local-stack.test:8443' -H 'X-Forwarded-Proto: https' \
  -H 'X-Forwarded-Host: zasp.local-stack.test:8443' -H 'X-Forwarded-Port: 8443' \
  -H 'X-Forwarded-For: 198.51.100.7'
```

That returns `401 authentication_required`. `GET /api/v1/session/start?return_to=/` returns a `302` to the Stytch OAuth start. `curl http://127.0.0.1:4081/readyz` returns `200 {"status":"ready"}` about 20 seconds after start.

```bash
deploy/local/real-stack/stack.sh security-workers
```

Installs the two Python analyzers the AWS collector runs as subprocesses (Cartography 0.139.1 and Prowler 5.39.1) into `/opt/zasp/security`, the fixed path the worker executes, from the hash-pinned lock files the worker image is built from. It needs Python 3.13, a writable `/opt/zasp/security`, access to PyPI and about 4 GB of disk. Run it once, and again after changing `workers/security-python`. Without it the discovery worker starts, and every AWS discovery run fails at its second page.

```bash
deploy/local/real-stack/stack.sh worker scheduler   # health on 127.0.0.1:8081
deploy/local/real-stack/stack.sh worker discovery   # health on 127.0.0.1:8082
deploy/local/real-stack/stack.sh worker outbox      # health on 127.0.0.1:8083
```

Runs one worker mode in the foreground. The three can run at the same time. `scheduler` polls its schedules. `outbox` publishes queued discovery jobs, for example a sync requested through the API, to the discovery queue. `discovery` consumes that queue, starts the Temporal workflow and runs the collector. `outbox` and `discovery` first create what they address in LocalStack: the job queue with its dead-letter queue, a versioned KMS-encrypted evidence bucket, placeholder provider secrets and the emulated AWS account. That takes about 30 seconds.

A refused start prints `agentsec-worker startup refused: stage=<stage>`, for example `stage=dependencies:discovery-readiness-queue`.

```bash
deploy/local/real-stack/stack.sh worker projection-graph    # health on 127.0.0.1:8091
deploy/local/real-stack/stack.sh worker projection-search   # health on 127.0.0.1:8092
deploy/local/real-stack/stack.sh worker projection-risk     # health on 127.0.0.1:8093
```

The three projection workers; see [The projection workers](#the-projection-workers).

```bash
OPENROUTER_API_KEY=... deploy/local/real-stack/stack.sh worker security-agent   # health on 127.0.0.1:8084
deploy/local/real-stack/stack.sh worker security-agent-action                   # health on 127.0.0.1:8085
```

The two Security Agent workers. `security-agent` plans and executes runs through Temporal; it needs an OpenRouter API token (written only to the fixed path the worker reads) and direct egress to `openrouter.ai`, and it is started by hand. `security-agent-action` executes temporary-policy, session-isolation and connector-revocation effects and signs the policy envelopes; it needs only the database and the gateway signing key the script generates, and `start` launches it.

A planner request the provider refuses outright ends the run within seconds in state `needs_human` with the stop reason `planner_provider_rejected`: nothing was generated, nothing was charged and the reserved budget is released. The worker treats HTTP 401, 402 (the OpenRouter account has no credits) and 429 this way. Other failures, for example 403, a timeout or a 5xx answer, may have been processed by the provider; such a run ends in `needs_human` with `budget_usage_unknown`, and it keeps holding its agent's capacity. A run that ended before any request left the product records `planner_not_sent`. `GET /api/v1/security-agent-runs/{id}` with `X-Zasp-Run-Lifecycle: v1` returns the code as `stop_reason` (and `X-Zasp-Budget-Details: v1` the budget stop). On 2026-11-14 every run started from the web application ended with `planner_provider_rejected`, about 15 seconds after it was started; nothing after planning has been exercised on this stack.

A run in `needs_human` is closed by a person: `POST /api/v1/security-agent-runs/{id}/close` with a reason (`no_action_required` or `resolved_outside_product`; `usage_unknown_accepted` is required, and only accepted, for a run with unknown usage). The run keeps its state, the closure is recorded, and a closed run no longer holds its agent's capacity. The web application offers this as **Close run** in the run's dialog.

A planner request needs the Environment's pricing approval first (`PUT /api/v1/security-agent-planner-pricing`, a browser session with fresh authentication and `manage_identity`). Without one the planning step is refused before anything is sent and the run stays `queued`, so approve pricing before activating an agent. There is no screen for it and no route that reads the approval back; [the tester's guide](../../../docs/operations/local-self-test.md#planner-pricing) has a snippet for the browser's developer console, which replaced the approval of this stack on 2026-11-14.

An enabled agent whose trigger mode is not "Manual only" starts runs on its own: on 2026-11-14 enabling a Finding Response agent with the default trigger mode started one run for each of the nine open findings with the rule `credential` in the local database. The emulated AWS account produces no finding with that rule, so on a fresh stack a run cannot be started from a finding of the sync (`409 operation_conflict`).

A requested sync passes through all three: the API writes the sync and an outbox row, `outbox` publishes it, `discovery` starts the Temporal workflow and collects four pages, then applies the snapshot. Syncs of the emulated account requested from the browser took 97 seconds on 2026-11-13 and 77 and 78 seconds on 2026-11-14 on this machine; every provider request of a page is authorized on its own.

Three things end a run early here that a quiet deployment does not see:

- **A worker configured with another collector version.** The installed schema hands every run the collector version `collector_v1`; `stack.sh` sets the worker to the same value.
- **Stopping the discovery worker during a page.** The page is recorded as `outcome_unknown`, the sync fails, and the integration stays reserved for that run: a later sync waits in `queued` with `last_error_code` `retryable`. Once the abandoned run has been quiet for ten minutes, the next sync that reaches its first page releases it (`zasp_temporal72.release_abandoned` in `completion.sql`). The release was not exercised in the browser run of 2026-11-13.
- **Changing the schema or restarting the API during a run.** The per-request authorization is refused while the baseline seal is open, and the run ends as `revoked`.

## The projection workers

A discovery run that completes stores a snapshot and queues three rows in `zasp_projection_work`, one each of kind `graph`, `search` and `risk` (`zasp_discovery_apply_snapshot` does both). There is no queue in between: each projection worker polls that table through `zasp_execution_claim_projection_work`, reads the snapshot's entities, relationships and evidence page by page, applies them, and records a receipt in `zasp_discovery_projection_receipts`.

| Worker | Reads | Writes | Needs |
| --- | --- | --- | --- |
| `projection-graph` | entities and relationships | Neo4j: one `ZaspInventoryGraphNode` per entity, one `ZASP_INVENTORY_GRAPH_EDGE` per relationship and one `ZaspGraphProjection` marker per integration | Neo4j at `neo4j+s://localhost:7687`, the secret `zasp-real-stack/projection/neo4j/auth/graph-worker`, the role `arn:aws:iam::000000000000:role/zasp-real-stack-projection-graph`, the five constraints the graph-schema job creates |
| `projection-search` | entities | OpenSearch index `zasp-inventory-v1`: one document per entity and one snapshot marker | the search node on `127.0.0.1:4092`, the role `...:role/zasp-real-stack-projection-search`, the index the search-schema job creates |
| `projection-risk` | entities, relationships and evidence | PostgreSQL: `zasp_discovery_risk_projection_current` and `_items`, then findings (`zasp_risk_findings` with their evidence, factors and break options) and attack paths (`zasp_risk_attack_paths` with their nodes and evidence) | the product database only |

The API reads none of this from Neo4j or from the inventory index. `GET /api/v1/search`, `/findings`, `/attack-paths` and `/agents/{id}/relationships` answer from PostgreSQL, so of the three only the risk projection changes what those routes return. The graph and the search index are written and can be inspected directly. `GET /api/v1/integrations/{id}/freshness`, and the integration dialog in the web application, report the state of all three.

`up` starts Neo4j in the container `zasp-real-stack-neo4j` (image `ZASP_REAL_STACK_NEO4J_IMAGE`, by default `public.ecr.aws/docker/library/neo4j:5.26-community`) on `127.0.0.1:7687`. Bolt refuses plaintext; the HTTP interface and usage reporting are off. The certificate is created in `$ZASP_REAL_STACK_STATE/tls/neo4j/`: an authority (`ca.crt`) whose name constraint permits only `localhost`, and a server certificate from it. The authority's private key is deleted once the certificate is signed. The files in that directory are world-readable because the container reads them as another user; the directory above it is private to the user running the script.

`up` also creates the Neo4j user `zasp_graph_worker` and stores two credentials in LocalStack Secrets Manager, in the JSON form the workers read (`{"scheme":"basic","principal":...,"credentials":...}`): `zasp-real-stack/projection/neo4j/auth/graph-schema` (the administrator, used once by the graph-schema job) and `zasp-real-stack/projection/neo4j/auth/graph-worker`. Both passwords are generated into `$ZASP_REAL_STACK_STATE/secrets/`. The administrator password takes effect only when the container is first created: after deleting the state directory, remove the container as well.

The graph worker is told to expect the role `zasp_graph_writer`. Community has no roles, so nothing creates it and the worker's role and privilege check is replaced as described under [What behaves differently in development mode](#what-behaves-differently-in-development-mode). On Community every user can do everything, including changing the schema, so this stack proves nothing about the worker's least-privilege role. To run the production check locally, run Neo4j Enterprise (it needs a license or its evaluation terms accepted, which this script does not do), create the role with the four privileges listed in `expectedWorkerPrivilegeCommands` (`services/platform/graphstore/neo4jstore/adapter.go`) and grant it to the user. That has not been tried.

To look at the result:

```bash
# Graph: nodes and relationships by kind.
NEO4J_USERNAME=neo4j NEO4J_PASSWORD="$(cat ~/.local/state/zasp-real-stack/secrets/neo4j-admin.password)" \
  docker exec -e NEO4J_USERNAME -e NEO4J_PASSWORD zasp-real-stack-neo4j cypher-shell -a neo4j+ssc://localhost:7687 \
  "MATCH (n:ZaspInventoryGraphNode) RETURN n.kind, count(*); MATCH ()-[r:ZASP_INVENTORY_GRAPH_EDGE]->() RETURN r.kind, count(*);"
# Search index: number of documents (one is the schema marker).
curl -s http://127.0.0.1:4092/zasp-inventory-v1/_count
# Work queue: one row per snapshot and kind.
psql "postgres://postgres@127.0.0.1:55434/zasp?sslmode=disable" -c 'select kind, state, attempt, last_error from zasp_projection_work'
```

Verified on 2026-11-13 on Linux: the three workers start and report ready against these dependencies, and `projection-graph-init` creates the constraints over verified TLS. A sync of the emulated account requested from the web application completed at 22:29:27 UTC, and the three projections of its snapshot were recorded as `current` by 22:29:31. Afterwards Neo4j held 13 `ZaspInventoryGraphNode` nodes (kinds `account` 1, `role` 4, `policy` 6, `service` 1, `resource` 1) and 21 `ZASP_INVENTORY_GRAPH_EDGE` relationships, and the index `zasp-inventory-v1` held 15 documents. `zasp_projection_work` also holds earlier rows in state `failed` with `projection_rejected` for all three kinds, from syncs earlier that day.

## The emulated AWS account

`stack.sh up`, `api` (when the role is missing), `worker outbox` and `worker discovery` create the customer side of an AWS integration in LocalStack account `000000000000`. LocalStack keeps nothing across a restart, so the same commands recreate it.

| Resource | Value |
| --- | --- |
| Role the product assumes | `arn:aws:iam::000000000000:role/zasp-reference/customer-read`. The API only assumes roles below a path prefix it is configured with (`ZASP_AWS_CUSTOMER_ROLE_PREFIXES`) that are also listed exactly (`ZASP_AWS_CUSTOMER_ROLE_ARNS`), so a role without a path can never be connected. |
| External ID | A random value kept in `$ZASP_REAL_STACK_STATE/secrets/aws-external-id` and stored as two secrets: `zasp-real-stack/connectors/aws/external-id/localstack-dev-0001` for the API and `zasp-real-stack/discovery/aws/external-id/localstack-dev-0001` for the discovery worker. Both resolve the reference `ref:aws/external-id/localstack-dev-0001`. |
| Fixture | Three roles under `/agents/` (`agent-orchestrator`, `support-copilot-runtime`, `claims-triage-agent`) with five customer-managed policies for model, tool and data access, a trust from the orchestrator to `claims-triage-agent`, the AWS-managed `AdministratorAccess` policy on the orchestrator, and one EC2 instance that allows IMDSv1. |

Create the integration with this configuration:

```json
{"region": "us-east-1", "role_arn": "arn:aws:iam::000000000000:role/zasp-reference/customer-read", "external_id_reference": "ref:aws/external-id/localstack-dev-0001"}
```

A collection of this account yields 13 entities (the account, 4 roles, 6 policies, the EC2 service and the instance), 21 relationships and 5 posture results, 2 of them failing: administrator access on `agent-orchestrator` and IMDSv1 on the instance. The collector reads IAM roles with their attached managed policies and EC2 instances in every enabled region. It reads nothing else, and no Bedrock resource.

Posture results become findings only through the `projection-risk` worker: after a run with that worker running, `GET /api/v1/findings` lists the two failing checks, and the Findings page shows them as "Discovered AWS control iam_role_administratoraccess_policy" and "Discovered AWS control ec2_instance_imdsv2_enabled". After the sync of 2026-11-13 22:27 UTC the integration's freshness reported the risk, graph and search projections as `current`.

The product classifies an IAM role as an identity and every other AWS entity as an asset. After a run, `GET /api/v1/identities` and the Identities page list the four roles (`customer-read` and the three under `/agents/`). `/agents`, `/tools` and `/runtimes` are fed by the Kubernetes, Okta and GitHub connectors; an AWS run adds nothing to them.

```bash
deploy/local/real-stack/stack.sh down
```

The product database listens on `127.0.0.1:55434`, uses `trust` authentication and accepts loopback connections only: any local process can connect as any role, including the cluster superuser `postgres`. It is a disposable database for one developer machine.

Stops the processes `start` started, then the containers, and keeps their data. State lives in `$ZASP_REAL_STACK_STATE`, by default `~/.local/state/zasp-real-stack`.

## Two things that fail without a clear message

- **Schema installation.** A refused installation prints `baseline refused: stage=<stage>` with a reason, for example `reason=the database collation must be C or C.UTF-8`. `stack.sh` creates the database with `C` collation.
- **API startup.** A refused start now prints `agentsec-api startup refused: stage=<stage>` on stderr, for example `stage=configuration` or `stage=dependency:connector-providers`.
- **API readiness.** When `/readyz` returns 503 the API logs one line naming the first check that refused, for example `{"event":"readiness_refused","service":"agentsec-api","check":"approval-notifications"}`. The name comes from a fixed list and carries no configuration value.

## What this stack cannot do

| Not available | Why |
| --- | --- |
| Completing a sign-in without a person | Stytch must have this origin's redirect URLs registered, and a person must complete OAuth or follow the invitation email in a browser, through `stack.sh ui`. On 2026-11-13 a headless browser reached the Google sign-in page through this front; nobody has completed a sign-in through it yet. The signed-in pages were walked on 2026-11-13 and 2026-11-14 with a session issued in the local database as a test fixture; the second time every change of the golden path was made in the browser. See [the tester's guide](../../../docs/operations/local-self-test.md) for what they showed and what failed. |
| Completing the deletion of an authorized integration | Deleting an `active` integration moves it to `revoking` and requests its revocation. Nothing on this stack completes a revocation, so the integration stays `revoking`, and the web application keeps every change locked for that user until the deletion is confirmed. An integration in `pending_authorization` is deleted at once. |
| Webhook delivery status and test delivery | `GET /api/v1/integrations/{id}/delivery-status` and `POST /api/v1/integrations/{id}/test-delivery` answer `503`: they depend on a readiness record that the baseline does not create. |
| Exports | The export routes are not mounted and answer `404`. |
| Discovery of a real account | LocalStack answers the AWS calls for one emulated account with a small fixture. There is no third-party provider, and the GitHub and Okta secrets are placeholders. |
| Proving IAM | LocalStack accepts any external ID and never denies an action. |
| Worker modes other than `scheduler`, `outbox`, `discovery`, the three projection modes and the two Security Agent modes | Each needs queues, keys and endpoints the script does not create yet. |
| Connecting an integration without a person | `POST /api/v1/integrations/{id}/reference-authorization` accepts only a browser session that authenticated minutes ago. |

## Using an external PostgreSQL (for example a Neon development branch)

Set these before any `stack.sh` command to use a managed database instead of the local container:

| Setting | Value |
| --- | --- |
| `ZASP_REAL_STACK_DATABASE_HOST` | The database host. The database must be named `zasp`. |
| `ZASP_REAL_STACK_OPERATOR_DSN_FILE` | A file holding the `zasp_operator` DSN. |
| `ZASP_REAL_STACK_DATABASE_PASSWORD_FILE` | A file holding the one password set on every `zasp_svc_*` login of that database. |
| `ZASP_POSTGRES_TRANSPORT=websocket` | Only where port 5432 is not reachable. See [baseline-schema-install.md](../../../docs/operations/baseline-schema-install.md). |

Use a separate state directory (`ZASP_REAL_STACK_STATE`) for each database: the stack registers its own verification keys there. Never point the stack at a production database. It writes development data: LocalStack resource names and a local OpenFGA store.

On 2026-11-12 `up` and the scheduler worker ran this way against a development branch of the Neon project, over the WebSocket transport. `bootstrap` and the API were not run there: the identity provider was not reachable from that environment at the time.
