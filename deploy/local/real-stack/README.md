# Real-dependency local stack

`stack.sh` runs the unmodified product API binary on one machine against real dependencies:

- PostgreSQL 18.3 with the current schema profile installed by `agentsec-migrate`
- the pinned Temporal 1.32.0 and OpenFGA 1.21.0 servers from `../temporal-openfga.compose.yaml`
- the product authorization model published to that OpenFGA
- a real Stytch B2B project, through its API credentials
- LocalStack 4.7.0 standing in for AWS STS, IAM, Secrets Manager, KMS, S3 and SQS
- a single-node OpenSearch 3.8.0 standing in for the managed search domain

It exists because every other harness in this repository replaces Stytch with a loopback fake and seeds memberships with hand-written SQL. This one uses the operator commands a deployment uses: `agentsec-migrate`, `zasp-bootstrap` and `zasp-authorization-reconcile`.

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

Starts Temporal, OpenFGA, LocalStack, OpenSearch and the product database, runs the production search-schema job (`projection-search-init`) against the local search node, creates the 30 least-privilege database logins, installs the schema, registers the worker and authorization verifiers, and publishes the authorization model. A clean run takes about 95 seconds.

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

That returns `401 authentication_required`. `GET /api/v1/session/start?return_to=/` returns a `302` to the Stytch OAuth start.

```bash
deploy/local/real-stack/stack.sh down
```

The product database uses `trust` authentication and listens on loopback only: any local process can connect as its superuser. It is a disposable database for one developer machine.

Stops the containers and keeps their data. State lives in `$ZASP_REAL_STACK_STATE`, by default `~/.local/state/zasp-real-stack`.

## Two things that fail without a clear message

- **Database collation.** The migration compares catalog fingerprints that are sorted with the database's default collation. The database must use `C` or `C.UTF-8` collation. With any other locale, `agentsec-migrate` stops at release 13 with `release migration failed` and PostgreSQL logs no error. `stack.sh` creates the database with `--no-locale` and checks it.
- **API startup.** A refused start now prints `agentsec-api startup refused: stage=<stage>` on stderr, for example `stage=configuration` or `stage=dependency:connector-providers`.
- **API readiness.** When `/readyz` returns 503 the API logs one line naming the first check that refused, for example `{"event":"readiness_refused","service":"agentsec-api","check":"approval-notifications"}`. The name comes from a fixed list and carries no configuration value.

## What this stack cannot do

| Not available | Why |
| --- | --- |
| `/readyz` returns 503 | On the current schema profile readiness stops at `approval-notifications`: `zasp_production_approval_notification_readiness` is false and the approval-maintenance profile it needs has no installer. The checks before it (repositories, policy history, identity provider, exports) pass against LocalStack and the local search node. The product listener still serves requests. |
| Completing a browser sign-in | Stytch must have this origin's redirect URLs registered, and a person must complete OAuth or follow the invitation email. Both are outside the project API. |
| Real connector discovery | LocalStack answers the AWS calls, but there is no customer AWS account, Neo4j or third-party provider behind them. |
| Background workers | On a database with the current schema profile, the Security Agent, discovery and scheduler worker modes refuse to start: `zasp_authorization80_worker.runtime_ready()` is defined as `... AND false`. |
