# Real-dependency local stack

`stack.sh` runs the unmodified product API binary on one machine against real dependencies:

- PostgreSQL 18.3 with the baseline schema installed by `agentsec-migrate install-baseline`, as a non-superuser operator, the way managed PostgreSQL requires
- the pinned Temporal 1.32.0 and OpenFGA 1.21.0 servers from `../temporal-openfga.compose.yaml`
- the product authorization model published to that OpenFGA
- a real Stytch B2B project, through its API credentials
- LocalStack 4.7.0 standing in for AWS STS, IAM, Secrets Manager, KMS, S3, SQS and EC2, including one emulated customer account for an AWS integration to connect to
- a single-node OpenSearch 3.8.0 standing in for the managed search domain

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

Nothing is skipped: role assumption with the external ID, the caller identity check, the allow-list of customer roles and both analyzers run as they do in production. LocalStack does not enforce IAM, so it accepts any external ID and never denies an action. A connection that succeeds here says nothing about the trust policy or the permissions of a real customer role.

## Requirements

Docker, Go (the toolchain in `services/platform/go.mod`), `psql`, `curl` and `openssl`. Stytch credentials in the environment:

```bash
export STYTCH_PROJECT_ID=... STYTCH_SECRET=... STYTCH_PUBLIC_TOKEN=...
```

The public origin defaults to `https://zasp.local-stack.test:8443`. It must be HTTPS and must not be `localhost`, `*.localhost`, `*.local` or an IP address, because the connector OAuth callbacks refuse those hosts. Map it to loopback:

```bash
echo '127.0.0.1 zasp.local-stack.test' | sudo tee -a /etc/hosts
```

The API and workers read their workload identity token from a fixed path, `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`. `stack.sh up` writes a placeholder token there (LocalStack accepts any token; it is not a credential). The directory must be writable by the user running the script:

```bash
sudo mkdir -p /var/run/secrets/eks.amazonaws.com/serviceaccount
sudo chown "$USER" /var/run/secrets/eks.amazonaws.com/serviceaccount
```

## Use

```bash
deploy/local/real-stack/stack.sh up
```

Starts Temporal, OpenFGA, LocalStack, OpenSearch and the product database, runs the production search-schema job (`projection-search-init`) against the local search node, creates the AWS resources described under [The emulated AWS account](#the-emulated-aws-account), creates the `zasp_operator` role (no superuser) and its database, installs the baseline schema with its 31 least-privilege service logins, registers the worker, authorization and approval-delivery verifiers, and publishes the authorization model. With the images present, a clean run took about 15 seconds before it created the AWS resources; creating them adds about 30 seconds.

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

On 2026-11-13 `outbox` refused to start on the installed baseline with `stage=dependencies:database-startup-profile`: its database role `zasp_outbox_worker` may not call `zasp_authorization80_worker.runtime_ready()`, which the startup check requires. Until the baseline grants that, a requested sync stays `queued`.

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

The product classifies every AWS entity as an asset. An AWS run therefore adds nothing to `GET /api/v1/agents`, `/identities`, `/tools` or `/runtimes`; those lists are fed by the Kubernetes, Okta and GitHub connectors.

```bash
deploy/local/real-stack/stack.sh down
```

The product database listens on `127.0.0.1:55434`, uses `trust` authentication and accepts loopback connections only: any local process can connect as any role, including the cluster superuser `postgres`. It is a disposable database for one developer machine.

Stops the containers and keeps their data. State lives in `$ZASP_REAL_STACK_STATE`, by default `~/.local/state/zasp-real-stack`.

## Two things that fail without a clear message

- **Schema installation.** A refused installation prints `baseline refused: stage=<stage>` with a reason, for example `reason=the database collation must be C or C.UTF-8`. `stack.sh` creates the database with `C` collation.
- **API startup.** A refused start now prints `agentsec-api startup refused: stage=<stage>` on stderr, for example `stage=configuration` or `stage=dependency:connector-providers`.
- **API readiness.** When `/readyz` returns 503 the API logs one line naming the first check that refused, for example `{"event":"readiness_refused","service":"agentsec-api","check":"approval-notifications"}`. The name comes from a fixed list and carries no configuration value.

## What this stack cannot do

| Not available | Why |
| --- | --- |
| Completing a browser sign-in | Stytch must have this origin's redirect URLs registered, and a person must complete OAuth or follow the invitation email. Both are outside the project API. |
| Discovery of a real account | LocalStack answers the AWS calls for one emulated account with a small fixture. There is no Neo4j or third-party provider, and the GitHub and Okta secrets are placeholders. |
| Proving IAM | LocalStack accepts any external ID and never denies an action. |
| Worker modes other than `scheduler`, `outbox` and `discovery` | Each needs queues, keys and endpoints the script does not create yet, and the Security Agent worker needs an OpenRouter API token. |
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
