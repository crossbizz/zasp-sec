# Real-dependency local stack

`stack.sh` runs the unmodified product API binary on one machine against real dependencies:

- PostgreSQL 18.3 with the baseline schema installed by `agentsec-migrate install-baseline`, as a non-superuser operator, the way managed PostgreSQL requires
- the pinned Temporal 1.32.0 and OpenFGA 1.21.0 servers from `../temporal-openfga.compose.yaml`
- the product authorization model published to that OpenFGA
- a real Stytch B2B project, through its API credentials
- LocalStack 4.7.0 standing in for AWS STS, IAM, Secrets Manager, KMS, S3 and SQS
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

Starts Temporal, OpenFGA, LocalStack, OpenSearch and the product database, runs the production search-schema job (`projection-search-init`) against the local search node, creates the `zasp_operator` role (no superuser) and its database, installs the baseline schema with its 31 least-privilege service logins, registers the worker, authorization and approval-delivery verifiers, and publishes the authorization model. With the images present, a clean run takes about 15 seconds.

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
deploy/local/real-stack/stack.sh worker scheduler
deploy/local/real-stack/stack.sh worker discovery
```

Runs one worker mode in the foreground. `scheduler` polls its schedules. `discovery` first creates what it addresses in LocalStack (the job queue with its dead-letter queue, a versioned KMS-encrypted evidence bucket, placeholder provider secrets), then connects to Temporal and OpenFGA and consumes the queue. Both report ready on `127.0.0.1:8081/readyz`.

Every worker uses the same health port, so run one at a time. A refused start prints `agentsec-worker startup refused: stage=<stage>`, for example `stage=dependencies:discovery-readiness-queue`.

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
| Real connector discovery | LocalStack answers the AWS calls, but there is no customer AWS account, Neo4j or third-party provider behind them. |
| Worker modes other than `scheduler` and `discovery` | Their database startup checks pass on the baseline. Each also needs queues, keys and endpoints the script does not create yet, and the Security Agent worker needs an OpenRouter API token. |
| A discovery run | The discovery worker runs, but no connector is connected: connecting one needs a signed-in user, and the provider secrets here are placeholders. |

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
