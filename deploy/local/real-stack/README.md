# Real-dependency local stack

`stack.sh` runs the unmodified product API binary on one machine against real dependencies:

- PostgreSQL 18.3 with the current schema profile installed by `agentsec-migrate`
- the pinned Temporal 1.32.0 and OpenFGA 1.21.0 servers from `../temporal-openfga.compose.yaml`
- the product authorization model published to that OpenFGA
- a real Stytch B2B project, through its API credentials

It exists because every other harness in this repository replaces Stytch with a loopback fake and seeds memberships with hand-written SQL. This one uses the operator commands a deployment uses: `agentsec-migrate`, `zasp-bootstrap` and `zasp-authorization-reconcile`.

It is local component evidence. It does not prove a deployment, and it has no AWS account, so anything that needs AWS stays unavailable (see the last section).

## Requirements

Docker, Go (the toolchain in `services/platform/go.mod`), `psql`, `curl` and `openssl`. Stytch credentials in the environment:

```bash
export STYTCH_PROJECT_ID=... STYTCH_SECRET=... STYTCH_PUBLIC_TOKEN=...
```

The public origin defaults to `https://zasp.local-stack.test:8443`. It must be HTTPS and must not be `localhost`, `*.localhost`, `*.local` or an IP address, because the connector OAuth callbacks refuse those hosts. Map it to loopback:

```bash
echo '127.0.0.1 zasp.local-stack.test' | sudo tee -a /etc/hosts
```

The API reads its connector credential from a fixed path. Create any non-empty file there:

```bash
sudo mkdir -p /var/run/secrets/eks.amazonaws.com/serviceaccount
echo local | sudo tee /var/run/secrets/eks.amazonaws.com/serviceaccount/token
```

## Use

```bash
deploy/local/real-stack/stack.sh up
```

Starts Temporal, OpenFGA and the product database, creates the 30 least-privilege database logins, installs the schema, registers the worker and authorization verifiers, and publishes the authorization model. A clean run takes about 95 seconds.

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

## What this stack cannot do

| Not available | Why |
| --- | --- |
| `/readyz` returns 503 | Readiness needs the policy-history OpenSearch index and the connector secrets in AWS Secrets Manager. Neither exists here. The product listener still serves requests. |
| Completing a browser sign-in | Stytch must have this origin's redirect URLs registered, and a person must complete OAuth or follow the invitation email. Both are outside the project API. |
| Connectors, discovery, exports, runtime pipeline | They need AWS (STS, Secrets Manager, KMS, S3, SQS) and, for some, OpenSearch and Neo4j. |
| Background workers | On a database with the current schema profile, the Security Agent, discovery and scheduler worker modes refuse to start: `zasp_authorization80_worker.runtime_ready()` is defined as `... AND false`. |
