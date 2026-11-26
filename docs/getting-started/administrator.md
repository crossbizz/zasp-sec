# Administrator guide

This guide is for the person who installs and operates Zasp. The person who uses it once it runs wants the [user guide](user.md).

Zasp is an agent security platform. It finds the AI agents, identities, tools and model access in your cloud accounts and SaaS tenants by reading provider APIs with read-only credentials, so nothing is installed in the environments it watches. It then shows findings and attack paths, tests agents, and lets a Security Agent propose fixes that a person approves.

## How this guide marks what was tried

Every command in this guide was either run while it was written, or is marked **not run in the authoring environment**. Read that mark literally. The authoring environment had no Docker, no Kubernetes cluster, no AWS account and no identity provider project. What that leaves is stated in [What was and was not verified](#what-was-and-was-not-verified).

## One entry point

Everything goes through one script in the repository root, `./zasp`, and one configuration file, `zasp.env`. A new `./zasp config init` selects the single-node VPS profile. See the [VPS first-deployment guide](../operations/vps-first-deployment.md) for the required operator steps and current application startup gate. Existing configurations retain their chosen profile and providers.

| You want | Profile | What you get |
| --- | --- | --- |
| To prepare a single-node k3s installation | `vps` | Independent services, provider checks and encrypted backup operations. Full product startup is gated. |
| To try it on your laptop | `local` | The product and every dependency on one machine. AWS is emulated. |
| To try it on a cluster with one Helm chart | `kubernetes` | The same stack in one pod, on any cluster, from one values file. AWS is emulated. |
| To run it for real | `aws` | The production topology on EKS, created with Terraform and the hosted chart. |

For the local, Kubernetes evaluation and AWS profiles, the command guide is below. The VPS guide lists component targets, restore staging and the operations available for that profile.

| Command | What it does |
| --- | --- |
| `./zasp config init` | Writes a new private `zasp.env`. Select `--profile local`, `--profile kubernetes` or `--profile aws` for those examples. |
| `./zasp doctor` | Checks prerequisites and configuration. Prints exactly what is missing and how to fix it. Changes nothing. |
| `./zasp secrets init` | Generates the keys that can be generated. Lists the ones a person must supply. Never prints a value. |
| `./zasp install` | Installs dependencies and the database schema. |
| `./zasp bootstrap-admin` | Creates the first organization and invites its first administrator. |
| `./zasp up` | `install`, `bootstrap-admin` (when configured) and `start`, in one command. |
| `./zasp start`, `stop`, `status`, `logs` | Day-to-day operation. |
| `./zasp upgrade` | Rolls out the current checkout. |
| `./zasp backup`, `restore` | Writes a backup; replaces the data with one. |
| `./zasp uninstall --yes` | Removes the deployment and its data. |

Select the target with `--config` and its recorded `ZASP_PROFILE`. The CLI rejects a conflicting profile on backup, upgrade, stop, restore or uninstall. A config without a recorded profile requires an explicit choice. `--dry-run` previews supported actions in the VPS, Kubernetes and AWS profiles. Destructive operations require `--yes`.

## Architecture at a glance

| Component | What it is | What it needs |
| --- | --- | --- |
| Web application | The browser interface. Static pages and a small Node.js server. | The API, on the same origin. |
| API (`agentsec-api`) | Every product request. Also serves the hosted gateway when enabled. | PostgreSQL, Temporal, OpenFGA, the identity provider, AWS APIs, a search endpoint. |
| Workers (`agentsec-worker`, one process per mode) | Scheduler, discovery, outbox publisher, three projection workers (risk, graph, search), Security Agent planner and action worker. | PostgreSQL. Discovery also needs a queue, an evidence bucket and its key. The graph worker needs Neo4j, the search worker OpenSearch. |
| Permission projector | Copies permission changes from PostgreSQL to OpenFGA, every few seconds locally and once a minute in production. | PostgreSQL, OpenFGA. |
| PostgreSQL 16 or later (18 is the reference) | The system of record. Every decision is made from it. | A database with `C` collation and a role named `zasp_operator`. |
| Temporal 1.32 | Runs long workflows: discovery and Security Agent runs. | Its own database. |
| OpenFGA 1.21 | Answers "may this member do this". | Its own database. |
| OpenSearch 3 | Search index and policy history. A projection: it can be rebuilt. | — |
| Neo4j 5 | Relationship graph. A projection: it can be rebuilt. | A TLS certificate the workers can verify. |
| AWS: STS, IAM, Secrets Manager, KMS, S3, SQS | Workload identity, connector secrets, evidence storage, job queues. | A real AWS account in production. LocalStack in the two evaluation profiles. |
| Identity provider: Stytch B2B | Sign-in, organizations, invitations. A hosted service. | A Stytch project. It cannot be self-hosted. |
| Model provider: OpenRouter | Plans Security Agent runs. Optional. | An API key. |
| Nango | OAuth sign-in to SaaS platforms for the SaaS connectors. Optional. | Its own database. Production chart only. |

Two requirements are worth knowing before you choose a profile:

- **The product needs AWS APIs.** There is no other object store or queue driver in the code. The `local` and `kubernetes` profiles satisfy them with LocalStack, an emulator, in a development mode the programs accept only with `ZASP_ENVIRONMENT` set to `test` or `development`. In that mode AWS behaviour is emulated and IAM is not enforced. A deployment that holds real data needs a real AWS account: the `aws` profile.
- **The product needs Stytch.** No profile works without a Stytch B2B project, and a person must complete the first sign-in in a browser. A test project is enough for evaluation.

Deeper references: [production deployment](../operations/production-deployment.md), [Temporal and OpenFGA](../operations/temporal-openfga.md), [the local stack](../../deploy/local/real-stack/README.md).

## Prerequisites

### Profile `vps`

Prepare the k3s host, persistent storage, workload identities and independent recovery material using the [first-deployment guide](../operations/vps-first-deployment.md). It includes DNS, TLS, supported alternatives, backup and rollback.

### Profile `local`

| Need | Why |
| --- | --- |
| Linux or macOS, about 8 GB of free memory and 10 GB of disk | Six dependency containers and ten product processes. The script was run on Linux only. |
| Docker with the Compose plugin | Runs PostgreSQL, Temporal, OpenFGA, LocalStack, OpenSearch and Neo4j. See [Without Docker](#without-docker) for the reduced alternative. |
| Go | Builds the API and worker programs. The exact toolchain in `services/platform/go.mod` is downloaded automatically. |
| Node.js 22.23.1 and npm | Builds and serves the web application. |
| `curl`, `openssl` | Used by every step. |
| A Stytch B2B project | Sign-in. See [Stytch settings](#stytch-settings). |
| Permission to add one line to `/etc/hosts` | The browser must reach the stack under a real host name. `./zasp doctor` prints the exact command. This is the only step that needs root; see [Running without root](#running-without-root). |
| Python 3.13, optional | The AWS collector runs two analyzers (Cartography and Prowler). Without them an AWS sync fails. `./zasp install --with-analyzers` installs them (about 4 GB). |

### Profile `kubernetes`

| Need | Why |
| --- | --- |
| A cluster running Kubernetes 1.29 or later | The chart orders its dependencies with restartable init containers. |
| One node with about 8 GB of free memory | Everything runs in one pod. |
| A default StorageClass, or `persistence.enabled: false` | PostgreSQL and Temporal data. |
| Helm 3.16 or later, `kubectl`, `openssl` | On the machine you install from. |
| A registry the cluster can pull from, and Docker to build | The three product images are not published anywhere. You build them. |
| A Stytch B2B project | Sign-in. |

### Profile `aws`

Production. Read [the AWS runbook](../operations/production-aws-runbook.md) first: it lists eleven decisions you must make (region, internet path, graph database, TLS) and what each costs. In short you need an AWS account with administrator access, a domain, a PostgreSQL database you manage (the runbook uses Neon), a live Stytch project, an OpenRouter key, and on your machine Terraform 1.15.8 exactly, Helm, `kubectl`, the AWS CLI v2, Docker with buildx, `psql`, `openssl` and `jq`.

## Quick start: local

Nine steps, six of them commands. The first command is not run in the authoring environment; the others were run there with `ZASP_DEPENDENCIES=native`, because it has no Docker.

1. Get the code. Not run in the authoring environment.

```bash
git clone https://github.com/zasp-ai/zasp-sec.git
```

2. Enter the directory.

```bash
cd zasp-sec
```

3. Write the configuration file. It is created readable by you only.

```bash
./zasp --profile local config init
```

4. Open `zasp.env` in an editor. Fill in the three `STYTCH_` values, and the first organization: `ZASP_ORGANIZATION_NAME`, `ZASP_ORGANIZATION_DOMAIN` and `ZASP_ADMIN_EMAIL`. Everything else has a working default.

5. Ask what is missing.

```bash
./zasp doctor
```

It prints one line per check. A line that starts with `MISSING` comes with the command or the setting that fixes it. For example:

```text
  MISSING  zasp.local-stack.test is not mapped to this machine
           run: echo '127.0.0.1 zasp.local-stack.test' | sudo tee -a /etc/hosts
```

Fix every `MISSING` line and run it again until it ends with `0 missing`.

6. Generate the keys. The command lists every key with `present` or `MISSING` and never prints a value.

```bash
./zasp secrets init
```

7. Install, create the first administrator, and start.

```bash
./zasp up
```

The first run pulls images and builds the programs and the web application; allow ten minutes. A repeat run takes under a minute. It ends with:

```text
Zasp is running.
  Open       https://zasp.local-stack.test:8443/
  Sign in    The first administrator opens the invitation email from the identity provider (Stytch) and accepts it
             on the page it leads to. Later sign-ins use the sign-in page (OAuth: google).
```

8. Check it.

```bash
./zasp status
```

9. Open `https://zasp.local-stack.test:8443/` in a browser. The certificate comes from an authority created on your machine: trust `~/.local/state/zasp-real-stack/tls/ca.crt`, or accept the warning once. Then follow [First sign-in](#first-sign-in).

What to do next in the product, starting with connecting the emulated AWS account, is in the [user guide](user.md) and in [the tester's walk-through](../operations/local-self-test.md).

### Without Docker

Set `ZASP_DEPENDENCIES=native` in `zasp.env`. PostgreSQL, OpenFGA, the Temporal development server and moto (an AWS emulator) then run as ordinary processes that you install yourself; `./zasp doctor` names each one and how to get it. This is a **reduced stack**:

- Nothing can be synced. The outbox and discovery workers are not started, because they verify details of SQS, S3 and KMS that moto answers differently from AWS and LocalStack.
- There is no search and no graph: OpenSearch and Neo4j have no native mode here.
- The API's `/readyz` answers `503` with the check `policy-history`, because it has no search endpoint. `/healthz` answers `200` and the product pages load.
- The Security Agent planning worker is not started.

It is enough to see the product start, sign in, and look around. As root, PostgreSQL runs as the system user `postgres`; set `ZASP_POSTGRES_DATA` to a directory that user can reach.

### Running without root

No program in the `local` profile runs as root, and nothing it installs needs root.

- **Key files and analyzers.** In a pod the programs read their key files from fixed paths under `/var/run`, and the analyzers from `/opt/zasp/security`. Locally the same paths start from a private directory inside the state directory, `<state directory>/runtime`, which `./zasp` creates for you.
- **PostgreSQL.** The server runs as the user who runs `./zasp`. PostgreSQL refuses to run as root, so when `./zasp` itself is run by root the server runs as the system user `postgres`.
- **The host name.** Adding a line to `/etc/hosts` is the one step that needs root. A name that already resolves to `127.0.0.1` avoids it: set `ZASP_ORIGIN` to that name.

| Setting | Meaning |
| --- | --- |
| `ZASP_RUNTIME_DIR` unset | `<state directory>/runtime`. No root. |
| `ZASP_RUNTIME_DIR=/some/directory` | A directory you own, used instead. |
| `ZASP_RUNTIME_DIR=system` | `/var/run` and `/opt/zasp` themselves, as in a pod. Creating those directories takes root once; `./zasp doctor` prints the commands. |

The programs accept the moved paths only outside Kubernetes, and only when the directory is owned by the user running them and closed to other users. In a cluster the setting is ignored and the paths are exactly the ones Kubernetes mounts.

## Install on Kubernetes

The chart is `deploy/kubernetes/zasp`. It is an evaluation chart: one StatefulSet with one pod that holds the product and every dependency, the cluster form of the local stack. It does not scale out and AWS is emulated inside the pod. Its header in [`values.yaml`](../../deploy/kubernetes/zasp/values.yaml) explains why.

**The chart was rendered with Helm 3.16.4 and checked as text. It was never installed on a cluster.** Expect to fix things on a first install, and please report them.

1. On a new evaluation installation run `./zasp --profile kubernetes config init`. In its `zasp.env`, set `ZASP_ORIGIN` (for example `https://zasp.example.test:8443`), the `STYTCH_` values, the first organization, and `ZASP_IMAGE_REGISTRY` (a registry you can push to and the cluster can pull from).

2. Generate the values file. This writes `zasp-values.yaml`, readable by you only, with every generated key and certificate, and `zasp-values.ca.crt`, the authority your browser must trust.

```bash
./zasp secrets init
```

3. Build and push the three product images, and install. Not run in the authoring environment.

```bash
./zasp up --build-images
```

That is the whole installation. If you prefer plain Helm, the same thing is one command once the images are in the values file. Not run in the authoring environment.

```bash
helm upgrade --install zasp deploy/kubernetes/zasp --namespace zasp --create-namespace -f zasp-values.yaml
```

To see what would be installed without a cluster (this was run):

```bash
helm template zasp deploy/kubernetes/zasp --kube-version 1.29.0 -f zasp-values.yaml
```

4. Reach it. The service is not exposed outside the cluster by default. Forward its port and map the host name to your machine. Not run in the authoring environment.

```bash
kubectl -n zasp port-forward service/zasp 8443:8443
```

Add `127.0.0.1 zasp.example.test` to `/etc/hosts`, then open the origin.

To expose it properly, set `service.type: LoadBalancer`, or `ingress.enabled: true` with an ingress controller that re-encrypts to the service (the pod terminates TLS itself) and a TLS Secret. Replace the generated certificate in `secrets.frontTlsCertificate` and `secrets.frontTlsKey` with one from your own authority.

### What you can switch off or point elsewhere

| Dependency | In the pod by default | To use your own |
| --- | --- | --- |
| PostgreSQL (product database) | Yes, on loopback, with a persistent volume | `database.external.enabled: true`, `database.external.host`, `secrets.operatorDsn`, `secrets.servicePassword`. Prepare it as [the schema guide](../operations/baseline-schema-install.md) describes. |
| Temporal | Yes: the development server with a SQLite file | Not possible in this chart. Outside development mode the programs require Temporal over mutual TLS. Use the `aws` profile. |
| OpenFGA | Yes, with a database in the pod's PostgreSQL | Not possible in this chart, for the same reason: plaintext is accepted on loopback only. |
| OpenSearch, Neo4j | Yes, without persistence. The next sync rebuilds them. | Not possible in this chart. |
| Object store, queue, secrets, keys | LocalStack | Not possible: the product speaks to AWS APIs only, and a real AWS account means the `aws` profile. |
| Nango | No | Production chart only. |

This table is the honest answer to "can each dependency be an external managed service": for the product database, yes. For the others the product's own rules tie plaintext dependencies to the loopback interface, so the choice is between this pod and the production topology.

**Users in the pod.** No step runs as root by default. The data volume is made writable through the pod's `fsGroup` (`securityContext.fsGroup`), and PostgreSQL runs as the image's unprivileged user (`securityContext.postgresUser`, 999). The product runs as 65532 and Temporal as 1000. LocalStack and Neo4j keep the users their images define. For storage that ignores `fsGroup`, such as some hostPath and NFS volumes, `volumePermissions.enabled=true` adds one init container that runs as root and hands the data directories to those users.

## Install on AWS (production)

The `aws` profile wraps the Terraform root `deploy/staging`, the hosted chart `deploy/staging/product` and the commands of [the AWS runbook](../operations/production-aws-runbook.md). **None of it has been applied to an AWS account, by the authors of the runbook or of this entry point.** The commands below were exercised only against stand-ins for `terraform`, `helm`, `kubectl` and `aws`. Use `--dry-run` first, and read the runbook section each step names.

Two files hold your configuration. Copy them outside the repository and edit them:

| File | Copy of | Holds |
| --- | --- | --- |
| `ZASP_AWS_TFVARS` | `deploy/production/example.tfvars` | Account, region, network, sizing. Replace every `REPLACE`. |
| `ZASP_AWS_VALUES` | `deploy/production/values-production.example.yaml` | Public origin, images, what Terraform cannot know. Replace every `REQUIRED`. |

For a fresh EKS installation run `./zasp --profile aws config init`, then set the `ZASP_AWS_` settings in that installation’s `zasp.env`.

```bash
./zasp doctor
```

Print the procedure. This was run; it changes nothing.

```bash
./zasp install
```

It lists twelve steps and marks the ones `./zasp` runs. The others need a person, because they are decisions or need access this script should not have: preparing the database, installing cluster add-ons, DNS and TLS, and installing Temporal and OpenFGA.

Each of the following is not run in the authoring environment.

Plan the AWS resources. Nothing is created yet.

```bash
./zasp install infrastructure
```

Apply the plan you reviewed. About 300 resources; 30 to 45 minutes.

```bash
./zasp install infrastructure --yes
```

Build and push the nine product images to ECR.

```bash
./zasp install images
```

Generate the keys into Secrets Manager and see which entries you still have to fill.

```bash
./zasp secrets init
```

Install the chart. The first install runs the schema job.

```bash
./zasp install release
```

Give every service login a password and store its DSN.

```bash
./zasp install dsns
```

Create the first organization.

```bash
./zasp bootstrap-admin "Example Security" example.com admin@example.com
```

Roll out and look.

```bash
./zasp up
```

## Keys, secrets and settings

### Supplied by you

| Name | What it is for | Required | How to obtain it |
| --- | --- | --- | --- |
| `STYTCH_PROJECT_ID`, `STYTCH_SECRET`, `STYTCH_PUBLIC_TOKEN` | Sign-in, organizations and invitations. Read by the API and by `bootstrap-admin`. | Required to run the complete product | Create a B2B project at stytch.com. The three values are on its API keys page. A test project for evaluation, a live project for production. |
| Stytch webhook secret | Verifies webhooks from Stytch. | `aws` only. The evaluation profiles generate a value and receive no webhooks. | Stytch dashboard, webhooks. |
| `ZASP_ORGANIZATION_NAME`, `ZASP_ORGANIZATION_DOMAIN`, `ZASP_ADMIN_EMAIL` | The first organization and its first administrator. | For `./zasp up` to finish in one command | Your choice. Lower case domain and address. |
| `OPENROUTER_API_KEY` | Model provider key for the Security Agent planner. | No. Without it Security Agent runs stay `queued`. | Create a key at openrouter.ai. The model is fixed to `openai/gpt-5-mini`. |
| `ZASP_OAUTH_PROVIDER` | The OAuth provider returning members sign in with. | No, default `google` | Must be enabled in the Stytch project. The production chart is fixed to Google. |
| GitHub App ID, client ID, client secret, private key | The GitHub connector. | No. Placeholders are used until you connect GitHub. | Create a GitHub App in your GitHub organization. `aws`: Terraform variables and the Secrets Manager entries `connectors/github/*`. |
| Okta client ID and client secret | The Okta connector. | No. Placeholders are used. | Create an API services application in Okta. `aws`: as for GitHub, `connectors/okta/client-secret`. |
| Nango secret key (`service-key`), database URL, encryption key | SaaS connectors that sign in through Nango. | No | Generate the keys yourself; `aws` only, Kubernetes Secret `nango-storage`. See [SaaS connectors](../operations/saas-connectors.md). |
| AWS role ARNs of customer accounts | The roles the product may assume to read a customer account. | To connect a real AWS account | The customer creates a read role under the path `/zasp-reference/`; you list it in the Terraform variables. Runbook step 12. |
| Neo4j endpoint and credentials | The graph projection. | `aws`: yes for three workloads | Your Neo4j (AuraDB or self-run). The evaluation profiles run their own. |
| Operator DSN | Installs the schema, as the database role `zasp_operator`. | `aws`; `kubernetes` with an external database | You create the role and the database: [schema guide](../operations/baseline-schema-install.md). |
| TLS certificate for the public host | HTTPS. | `aws`: yes. Evaluation profiles generate one. | Your certificate authority, or cert-manager. |

### Generated by `./zasp secrets init`

| Key | What it is for | Where it is kept |
| --- | --- | --- |
| Workflow signing key | Signs session and workflow attestations (API). | `local`: `<state>/secrets/keys.env`. `kubernetes`: `secrets.workflowSigningKey`. `aws`: Secrets Manager `workflow-signing-key`. |
| Token reveal key | Encrypts a new API token until it is shown once. | Same places, `tokenRevealKey` / `token-reveal-key`. |
| Authorization worker keys (forward and compensation) | Let the discovery and Security Agent workers prove each provider request was authorized. | `forward.seed`, `compensation.seed`; `aws`: `authorization-worker-forward-key`, `authorization-worker-compensation-key`. |
| Approval delivery key | Signs approval notifications (API, workers, projector). | `approval-delivery.key`; `aws`: `approval-maintenance-key`. |
| OpenFGA token | Shared between the product and OpenFGA. | Evaluation profiles only. In production you create it with OpenFGA. |
| Gateway policy signing key | Signs the policies the Security Agent action worker issues. | Evaluation profiles. `aws`: you supply `gateway-policy-signing-private-key`. |
| Graph database passwords, emulated AWS external ID, TLS certificates | The in-stack Neo4j, the emulated customer account, the local HTTPS front. | Evaluation profiles only. |
| Database passwords | `local`: none; the database listens on loopback and trusts it. `kubernetes`: none in the pod. `aws`: generated by `./zasp install dsns`, one per service login, stored only in Secrets Manager. | — |

`<state>` is `~/.local/state/zasp-real-stack` unless `ZASP_STATE_DIR` says otherwise.

**Keep the generated keys.** The database records which keys it trusts when the schema is installed. A deployment whose keys are lost cannot be repaired; it has to be reinstalled. In the `kubernetes` profile the keys live in `zasp-values.yaml`: back that file up like a secret.

### Stytch settings

In the Stytch dashboard for your project. The API credentials cannot change these:

- **Redirect URLs.** `<origin>/auth/callback?state={}` for Login and Signup, and `<origin>/auth/callback` for Invite. `<origin>` is `ZASP_ORIGIN`, for example `https://zasp.local-stack.test:8443`.
- **An OAuth provider** enabled for returning members: the one named by `ZASP_OAUTH_PROVIDER`.
- **Email sending.** Until billing is verified, Stytch sends email only to addresses on the account owner's own domain. Use such an address as `ZASP_ADMIN_EMAIL`, or verify billing.

Details: [first organization bootstrap](../operations/first-organization-bootstrap.md).

## First administrator

A new installation has no organization and no member, and there is no self-signup. `bootstrap-admin` is the only way in. It creates the organization in Stytch and in the product, a default workspace with Production, Staging and Development environments, and the first administrator, who receives an invitation by email. It prints no credential.

`./zasp up` runs it for you when the three settings are in `zasp.env`. To run it by hand, or to add a second administrator later:

```bash
./zasp bootstrap-admin "Example Security" example.com admin@example.com
```

Every step is safe to repeat. A second run with the same values changes nothing and sends no second invitation.

### First sign-in

1. The administrator opens the invitation email from Stytch and follows the link.
2. The page asks them to accept. This step exists so that a mail scanner opening the link does not use up the single-use token.
3. They are signed in. For a few seconds the page may say "Authorization pending": the permission projector has not yet applied the new permissions.
4. Later sign-ins start from the sign-in page and go through the OAuth provider.

A sign-in could not be completed in the authoring environment, which has no Stytch project. What was observed there: the sign-in page loads, and sign-in start answers with a redirect to the identity provider.

## Demo data

A new installation has nothing to show until a source is connected. `./zasp demo` fills one environment with sample data, so that a person can look at agents, findings, MCP servers and attack paths before any source exists. The person signs in with their own account, the normal way. No session is created for them and no setting of the deployment is changed.

The sample company is fictional ("Northwind Robotics"): about 60 agents in an AWS account, a Google Cloud project, a Kubernetes cluster, a GitHub organization, an Okta tenant, a Microsoft tenant, a Salesforce org, and Databricks, OpenAI, ServiceNow and Slack tenants. It holds no credential and reaches no provider.

### Seed

See what would be seeded. This connects to nothing:

```bash
./zasp --dry-run demo seed --email person@example.com
```

Seed it:

```bash
./zasp demo seed --email person@example.com
```

Run the same command again to refresh the data. Nothing is duplicated.

Where the data goes depends on who the person is:

| The person | Where the demo goes | How they open it |
| --- | --- | --- |
| Is already a member of the organization this deployment signs people in to | A workspace of its own, `Zasp Demo`, with one environment, `Demo`, inside that organization. Only this person is given access to it. | They sign in as usual and choose the environment `Demo`. |
| Is not a member | An organization of its own, `Zasp Demo`, with one workspace and one environment of that name. The identity provider sends the person an invitation to it. | They open the invitation, as in [First sign-in](#first-sign-in). |

You can decide yourself:

```bash
./zasp demo seed --email person@example.com --into-existing-organization <organization id>
```

```bash
./zasp demo seed --email person@example.com --dedicated-organization
```

`--into-existing-organization` never creates a membership and never sends an invitation: an address that is not an active member of that organization is refused. `--organization`, `--workspace`, `--environment` and `--domain` change the names; `--providers aws,kubernetes` seeds only some providers; `./zasp demo help` lists every option.

A dedicated organization has a limit you should know. Sign-in from the sign-in page is bound to one organization per deployment (see [first organization bootstrap](../operations/first-organization-bootstrap.md), "Known limits"). A person in the dedicated demo organization enters through the invitation link. For a person who already signs in to this deployment, the workspace inside their organization is the better place, and it is what the command chooses.

### What it creates

- Eleven integrations whose names start with `Demo:`. They have no credential, no connection and no schedule, so no worker ever collects them.
- The inventory, relationships, findings, MCP servers and attack paths of those integrations. They are not written by hand: the product's own collectors run over bundled provider answers, and the result is applied with the same database functions the discovery worker uses.
- Four decisions in the approved-servers registry (three approved, one blocked).

What it does not create: red team runs, guardrail decisions, gateway activity, runtime sessions and Security Agent runs. Evidence files of demo entities are not stored, so an evidence download answers that the object is missing. Demo data is not in the search index or the graph database.

Audit records in the demo environment name the person the demo was seeded for as the actor.

### Status and removal

```bash
./zasp demo status
```

```bash
./zasp demo remove --yes
```

Without `--yes`, `remove` lists what it would delete and stops.

`remove` deletes the rows of the demo environment, then the environment and its workspace. The product has no operation that deletes an environment, so this is done directly in the database by the operator role, and only for an environment in which every integration is a demo integration. Three things stay:

- The retired inventory rows of the deleted environment (about 200). The operator role is not allowed to delete them. They belong to an environment that no longer exists and cannot be reached.
- The record of a dedicated demo organization, empty, where the permission service refers to it. A later `seed` uses it again.
- The organization and the member in the identity provider. Delete them in the Stytch dashboard if you want them gone.

### Safety on a production deployment

The command is confined to its own environment:

- It refuses to seed into, or remove, an environment that holds any integration that is not a demo integration, and it refuses a production environment.
- Every statement it runs names the demo environment's organization, workspace and environment.
- It queues no discovery job, so the workers never contact a provider for a demo integration.
- It turns no provider on and changes no deployment setting.

It needs what `bootstrap-admin` needs: the `zasp_operator` database role and, for `seed`, the identity provider settings. On Kubernetes it runs in the toolbox container of the release. On AWS it runs as a one-off container of the API image on your machine:

```bash
./zasp --profile kubernetes demo seed --email person@example.com
```

```bash
./zasp --profile aws demo seed --email person@example.com
```

Both are not run in the authoring environment. With `--dry-run` they print the command they would run; that was run.

What was run in the authoring environment: the dry run above; and `seed` (twice), `status` and `remove --yes` of the same program against an installed schema, as the non-superuser `zasp_operator` role, with the identity provider stand-in of the test suite. `./zasp demo seed` against a running local stack was not run there, because the stack's native dependencies are not installed there.

## Day-2 operations

All of the commands in this section were run in the authoring environment for the `local` profile with native dependencies. For `kubernetes` and `aws` they are not run in the authoring environment.

### Start, stop, status

```bash
./zasp stop
```

Stops the product and its dependencies. Data is kept.

```bash
./zasp start
```

Starts everything again. After a machine restart this is all that is needed.

```bash
./zasp status
```

Prints one line per dependency and per process: `running` or `stopped`, and `ready` or `not ready`.

| Profile | `stop` does | `start` does |
| --- | --- | --- |
| `local` | Stops the processes, then the containers. | Starts containers and processes; repeats installation steps that are missing. |
| `kubernetes` | Scales the StatefulSet to zero. The volume stays. | Scales it to one and waits. |
| `aws` | Scales every Deployment to zero. | Runs the chart again, which restores every replica count. |

### Logs

```bash
./zasp logs
```

Lists what has logs: process names locally, container names on Kubernetes, Deployments on AWS.

```bash
./zasp logs api
```

Shows the last 100 lines. Add `--follow` to keep reading. The API and the workers log one JSON object per line.

### Upgrade

Get the new code (not run in the authoring environment):

```bash
git pull
```

Then:

```bash
./zasp upgrade
```

Locally this stops the processes, rebuilds the programs and the web application, and starts again. On Kubernetes and AWS it runs the chart again with your values; build and reference new images first (`--build-images` on Kubernetes, `./zasp install images` on AWS).

**There is no in-place schema upgrade between releases.** Each release carries one schema artifact. When the installed schema came from another artifact, `./zasp upgrade` stops and says so, and the only way forward is to reinstall: back up for reference, uninstall, install. Organizations, members, integrations and API tokens are lost. This is a property of the product today, described in [the schema guide](../operations/baseline-schema-install.md#reinstalling-over-an-earlier-artifact). To see which artifact is installed:

```bash
deploy/local/real-stack/stack.sh verify
```

It prints `{"sealed":true,"intact":true,"artifact":"<sha256>","current":true}`. `current` is `false` when the database was installed from a different release.

### Backup and restore

```bash
./zasp backup
```

Writes `zasp-backup-<profile>-<time>.tar.gz` in the current directory, readable by you only. It contains keys: store it like a secret.

```bash
./zasp restore zasp-backup-local-20261114T220100Z.tar.gz --yes
```

Replaces the databases and keys with the backup's, verifies the schema, and tells you to start.

| Profile | A backup contains | It does not contain |
| --- | --- | --- |
| `local` | A dump of the product database server (every database and role), the OpenFGA database, the keys and settings of the state directory. With native dependencies also Temporal's database file. | With Docker: Temporal's workflow history. The search index and the graph, which the next sync rebuilds. |
| `kubernetes` | A dump of the pod's PostgreSQL, the persistent state files, and your values file. | An external product database, Temporal's history, the search index and the graph. |
| `aws` | A logical dump for reference, the release's values and image references. | It is not the backup of record. Take your database provider's snapshot before every release; `./zasp restore` refuses in this profile and points to [backup, restore and rollback](../operations/backup-restore-rollback.md). |

In the authoring environment a native local stack was backed up, uninstalled, installed again and restored; afterwards the organization had its original identifier, the schema verified as sealed and intact, and the product started. The Docker and Kubernetes paths of backup and restore are not run in the authoring environment.

A backup can only be restored into the release it was taken from, because of the schema rule above.

### Rotate secrets

Rotation is not automated, and for some keys the product does not support it yet. Stated plainly:

| Secret | How to rotate |
| --- | --- |
| Stytch secret, OpenRouter key | Create the new one at the provider, put it in `zasp.env` (or the values file, or Secrets Manager), then `./zasp stop` and `./zasp start`. On Kubernetes run `./zasp upgrade`. |
| Service database passwords (`aws`) | Run `./zasp install dsns` again, then restart the workloads. It sets a new password on every login. |
| TLS certificate | Replace the certificate. Locally, delete `<state>/tls` and start; a new authority is created and must be trusted again. |
| Workflow signing key, authorization worker keys, approval delivery key | Not supported in place. The database trusts the keys registered at installation. `agentsec-migrate` has registration commands (`register-authorization-verifier` and others, see [the schema guide](../operations/baseline-schema-install.md#registering-the-verification-keys-by-hand)), and whether registering a new key retires the old one was not established for this guide. Treat a leaked key as a reason to reinstall until that is documented. |
| API tokens and sessions of users | In the product: rotate or revoke the token, revoke the session. See the [user guide](user.md). |

### Scale

| Profile | Scaling |
| --- | --- |
| `local`, `kubernetes` | None. One process of each kind. They are for evaluation. |
| `aws` | The hosted chart runs two or three replicas of every workload with autoscalers. Change `replicas.*` in your values file and run `./zasp upgrade`. The sizes in the examples are guesses, not a measured capacity plan (runbook decision D4). |

### Uninstall

```bash
./zasp uninstall --yes
```

| Profile | Removes | Leaves |
| --- | --- | --- |
| `local` | Containers or processes, every database, the keys. | `zasp.env`, the images, the repository. |
| `kubernetes` | The release and its volume. | The namespace and `zasp-values.yaml`. |
| `aws` | The Helm release. | Every AWS resource, which keeps costing money, and the database. Add `--destroy-infrastructure` to run `terraform destroy`; Terraform asks for its own confirmation. |

## Optional pieces

None of the switches in this section were exercised in the authoring environment. Each links to the page that describes the feature.

| Piece | `local` | `aws` | Reference |
| --- | --- | --- | --- |
| AWS discovery | On. Connect the emulated account with the role, region and external ID reference given in [the local stack README](../../deploy/local/real-stack/README.md#the-emulated-aws-account). | On. List each customer role in the Terraform variables. | [Runbook step 12](../operations/production-aws-runbook.md) |
| Kubernetes, GitHub, Okta discovery | Registered, with placeholder credentials. Nothing real to read. | Supply the GitHub App and Okta application. | [Production deployment](../operations/production-deployment.md) |
| Microsoft (Entra, Copilot Studio) and Azure (Azure OpenAI, AI Foundry) | Off. Export `ZASP_DISCOVERY_MICROSOFT_COLLECTOR_VERSION=collector_v1` before `./zasp start`; Azure also needs `ZASP_DISCOVERY_MICROSOFT_AZURE=enabled`. | `discovery.microsoftCollectorVersion`, `discovery.microsoftAzure` and the Microsoft address ranges. | [Runbook step 13](../operations/production-aws-runbook.md) |
| Salesforce (Agentforce) | Off. `ZASP_DISCOVERY_SALESFORCE_COLLECTOR_VERSION=collector_v1`. | `discovery.salesforceCollectorVersion`. | [Runbook step 14](../operations/production-aws-runbook.md) |
| Google Cloud | Off. `ZASP_DISCOVERY_GCP_COLLECTOR_VERSION=collector_v1`. | Terraform `discovery_optional_providers.gcp_collector`. | [Google Cloud connector](../operations/google-cloud-connector.md) |
| SaaS connectors through Nango (Slack, Atlassian, GitLab, Databricks, ServiceNow, Google Workspace, OpenAI, Anthropic) | Not available: the local stack runs no Nango. | `discovery.saasCollectorVersion: collector_v1`, the Secret `nango-storage`, and each platform's address ranges. | [SaaS connectors](../operations/saas-connectors.md) |
| Hosted gateway (MCP gateway and model proxy) | Off. | `hostedGateway.enabled: true` and `hostedGateway.egressCIDRs`. | [Hosted gateway](../operations/hosted-gateway.md) |
| Remediation role (the Security Agent changes a customer AWS account after approval) | Off. | `securityAgentRemediation.*`, and a remediation role in the customer account. | [Runbook step 16](../operations/production-aws-runbook.md) |
| Runtime agent discovery in a customer cluster | Off. | The customer-edge values of the hosted chart. This is the one feature that installs something at a customer. | [Runbook step 15](../operations/production-aws-runbook.md) |
| Security Agent planner | Set `OPENROUTER_API_KEY`. | Secrets Manager `openrouter-security-agent-api-key`. | [Local stack README](../../deploy/local/real-stack/README.md) |

The evaluation chart (`kubernetes` profile) has none of these switches except the planner (`securityAgent.planner`).

## Health checks

| What | How | Healthy answer |
| --- | --- | --- |
| Everything, at a glance | `./zasp status` | Every line `running` and `ready`. |
| API is alive | `curl http://127.0.0.1:4081/healthz` (local) | `200` `{"status":"live"}` |
| API can serve | `curl http://127.0.0.1:4081/readyz` (local) | `200` `{"status":"ready"}`, about 20 seconds after start. |
| A worker | The same two paths on its health port: scheduler 8081, discovery 8082, outbox 8083, Security Agent 8084 and 8085, projections 8091 to 8093. | `200` |
| The front and the API through it | `curl --cacert ~/.local/state/zasp-real-stack/tls/ca.crt https://zasp.local-stack.test:8443/api/v1/session/bootstrap` | `401` with `"code":"authentication_required"`. That is the correct answer without a session. |
| The schema | `deploy/local/real-stack/stack.sh verify` | `"sealed":true,"intact":true,"current":true` |

The `curl` lines were run in the authoring environment with `--noproxy '*'`, and the last one with `--resolve zasp.local-stack.test:8443:127.0.0.1` in place of the hosts entry. With native dependencies the log names are `dependency-temporal`, `dependency-openfga` and `dependency-aws-emulator`.

In production each pod serves `/healthz` and `/readyz` on port 8081, and the chart wires them to its probes.

## Troubleshooting

These are the messages the programs really print. Each comes from a fixed list and never contains a credential.

| You see | It means | Do this |
| --- | --- | --- |
| `zasp: prerequisites are missing (see above)` | `doctor` found a `MISSING` line. | Fix the lines above the message. |
| `real-stack: STYTCH_PROJECT_ID is required (Stytch B2B project credentials)` | The identity provider settings are not in `zasp.env`. | Fill in the three `STYTCH_` values. |
| `real-stack: this machine's stack belongs to the state directory '<a>'; '<b>' is another one.` | One machine runs one local stack, and another state directory holds it. | Use that state directory, or see [one stack per machine](../../deploy/local/real-stack/README.md#one-stack-per-machine). |
| `baseline refused: stage=preconditions reason=the database collation must be C or C.UTF-8` | The database was not created with `C` collation. | Create it again as [the schema guide](../operations/baseline-schema-install.md) shows. |
| `baseline refused: stage=preconditions reason=the database already contains a product schema` | The database holds a schema from another release. | There is no in-place upgrade. See [Upgrade](#upgrade). |
| `bootstrap refused: stage=identity-provider` | Stytch refused. Usually a missing redirect URL, or `billing_not_verified_for_email` for an address outside your own domain. | Check [Stytch settings](#stytch-settings). |
| `bootstrap refused: stage=existing-records` | The organization already exists and disagrees with what you asked for. Nothing was written. | Use the same name and domain as the first time. |
| `agentsec-api startup refused: stage=configuration` | A setting is missing or malformed. | Run `./zasp doctor`. In production compare with [cloud launch configuration](../operations/cloud-launch-configuration.md). |
| `agentsec-api startup refused: stage=local-cloud` | An emulator endpoint is set in an environment that is not `test` or `development`. | Never set `ZASP_LOCAL_CLOUD_ENDPOINT` in production. |
| `agentsec-api startup refused: stage=dependency:native-services` | Temporal or OpenFGA does not answer. | `./zasp status`, then `./zasp logs temporal` or `openfga`. |
| `agentsec-api startup refused: stage=dependency:core-postgres` | The database does not answer, or the service login is refused. | `./zasp status`; in production check the DSN secret. |
| `{"event":"readiness_refused","service":"agentsec-api","check":"<name>"}` in the API log while `/readyz` answers `503` | The named dependency is not ready. `policy-history` is the search endpoint; `identity-provider` is Stytch. | Fix that dependency. With native dependencies `policy-history` is expected. |
| `agentsec-worker startup refused: stage=dependencies:discovery-readiness-queue` | The discovery queue or its dead-letter queue is missing or misconfigured. | Locally run `./zasp start` again: LocalStack keeps nothing across a restart and is provisioned again. |
| `agentsec-worker startup refused: stage=dependencies:discovery-readiness-cloud` | The evidence bucket, its key or a provider secret is missing. | As above. |
| The browser shows `421` and "This is the Zasp local stack. Open https://…" | You opened the stack under another host name or an IP address. | Open exactly `ZASP_ORIGIN`. |
| The browser shows "Authorization pending" or the API answers `authorization_pending` | Permissions have changed and the projector has not applied them yet. | Wait a few seconds. If it stays, `./zasp logs projector`. |
| Stytch shows `query_params_do_not_match` at sign-in | The redirect URL is registered without the `?state={}` suffix. | Fix it in the Stytch dashboard. |
| A Security Agent run stays `queued` | No planner key, or no pricing approval for the environment. | Set `OPENROUTER_API_KEY`; see [planner pricing](../operations/local-self-test.md#planner-pricing). |
| A Security Agent run ends `needs_human` with `planner_provider_rejected` | The model provider refused the request (bad key, no credit, rate limit). Nothing was charged. | Check the key and the account at the provider, then close the run. |
| An AWS sync fails at its second page | The security analyzers are not installed. | `./zasp install --with-analyzers`. |

More failure modes of the local stack, with what was observed on each: [testing the product on your own machine](../operations/local-self-test.md#when-something-does-not-start).

## Security notes

### What is exposed

| Profile | Reachable from outside | Everything else |
| --- | --- | --- |
| `local` | Nothing. Every listener binds `127.0.0.1`, including the HTTPS front on port 8443. | The product database trusts loopback connections: any local process can connect as any role. It is a disposable database for one developer machine. |
| `kubernetes` | Port 8443 of the pod: the HTTPS front. | A NetworkPolicy admits ingress to that port only (`networkPolicy.enabled`). It takes effect only where the cluster enforces NetworkPolicy. Egress is not restricted by this chart. OpenSearch runs without its security plugin and PostgreSQL trusts loopback; both are reachable only from inside the pod. |
| `aws` | The ingress, over HTTPS, routing `/api/v1` to the API and everything else to the web application. | The EKS API endpoint is private. Workloads have one IAM role each, limited to their own secret, queue, bucket prefix and key. |

### Default-deny networking

The hosted chart renders one NetworkPolicy per workload as allow-lists of address ranges; whatever is not listed is denied, in both directions. NetworkPolicy matches addresses, not names, so you must supply and refresh the ranges of the database, Stytch, OpenRouter and each provider. Enforcing them is your decision (runbook decision D6): it removes a class of mistakes and adds a maintenance duty. The hosted gateway, when enabled, is the one deliberate wide egress, and it refuses private addresses itself.

The evaluation profiles do not give you this. Do not use them where egress control matters.

### What the product stores

| Stored | Where |
| --- | --- |
| Organizations, members, roles, sessions and API tokens (a token's secret is shown once, through a reveal step) | PostgreSQL |
| Inventory metadata read from providers: agents, identities, roles, policies, tools, resources and their relationships | PostgreSQL; copies in OpenSearch and Neo4j |
| Findings, attack paths, policies, approvals, audit records | PostgreSQL |
| Discovery evidence and exports | The evidence bucket, encrypted with a customer-managed key |
| References to customer credentials: a role ARN, an external ID reference, a secret name | PostgreSQL. The secret values are in Secrets Manager. |
| Hosted gateway decision records, when the gateway is enabled | PostgreSQL, deleted after `decisionRetentionDays` |

### What it does not store

- **Customer credentials in its database.** OAuth tokens and client secrets live in Secrets Manager (or in Nango for the SaaS connectors). The database holds references.
- **Secret values it sees while reading a provider.** Collectors record names and metadata. They do not record secrets, tokens, the values of environment variables, file contents, prompts or payloads.
- **Passwords.** Sign-in is delegated to the identity provider.
- **Anything in the environments it reads.** Discovery uses read-only provider APIs. The exceptions are opt-in and listed under [Optional pieces](#optional-pieces): the remediation role, and runtime discovery in a customer cluster.

A new environment is created with metadata-only data controls.

### Secrets on the administrator's machine

`zasp.env`, `zasp-values.yaml` and every backup hold credentials or keys. `./zasp` creates them readable by their owner only and `doctor` warns when a configuration file is readable by others. They are listed in `.gitignore`. `./zasp` never prints a value. It hands values to other programs through private files, standard input or the environment, with one exception: in the `aws` profile, `./zasp install dsns` and `./zasp backup` give `psql` and `pg_dump` the operator DSN as a command-line argument for as long as they run. Run those two on a machine where other users cannot list your processes.

## What was and was not verified

Written on 2026-11-14, in an environment with Go, Node.js and PostgreSQL 18, and without Docker, Kubernetes, AWS or a Stytch project.

| Claim | Evidence |
| --- | --- |
| `./zasp` argument handling, the configuration file, `doctor`, and the commands each profile issues | Automated: `node --test deploy/zasp/zasp.test.mjs`, 38 tests, against stand-ins for Docker, Helm, `kubectl`, Terraform and the AWS CLI. |
| Local profile, native dependencies: `up` from nothing, `status`, `logs`, `stop`, `start`, `upgrade`, `backup`, `uninstall`, `up` again, `restore` | Run. `up` took 39 seconds with the programs already built. The API answered `/healthz` `200`, the front served `/sign-in` `200`, `/api/v1/session/bootstrap` answered `401 authentication_required`, and sign-in start answered `302` to the identity provider. `/readyz` answered `503` (`policy-history`), as expected without a search endpoint. |
| The identity provider in that run | A loopback stand-in (`deploy/zasp/testing/fake-identity-provider.mjs`) that answers the four directory requests `bootstrap-admin` makes. It issues no session. No sign-in was completed. |
| Local profile with Docker, through `./zasp` | **Not run.** The commands `./zasp` issues are the ones `deploy/local/real-stack/README.md` records as run on 2026-11-13 and 2026-11-14. The additions in this change (starting the planner worker with the stack, `dump`, `load`) were not run with Docker. |
| The evaluation chart | Rendered and linted with Helm 3.16.4; structure, required values and switches checked by tests. **Never installed on a cluster.** One image assumption is marked `UNVERIFIED` in `values.yaml`. |
| The chart's start script (`files/entrypoint.sh`) | Run once outside a cluster, on a machine laid out like the pod (the same paths, the Secret's keys as files from the rendered chart, PostgreSQL on port 5432, OpenFGA, the Temporal development server, moto and the identity stand-in on loopback). Its steps `prepare`, `fga-model`, `schema` (which installed the schema and created the first organization), `api`, three worker modes, `projector`, `front`, `status`, `verify` and `bootstrap` ran; the front answered `/sign-in` with `200` and `/api/v1/session/bootstrap` with `401`. That exercises the script, not Kubernetes: the init container order, probes, volumes, image contents, LocalStack's provisioning hook, OpenSearch and Neo4j were not exercised. |
| Running without root | Automated: the worker accepts a key path beneath the local runtime directory, and refuses it inside Kubernetes or when the directory is open to other users (`services/platform/runtimepath`, `agentsec-worker/local_runtime_root_test.go`); `./zasp doctor` asks for no root-owned directory; the rendered chart has no container running as user 0 unless `volumePermissions.enabled=true`. **Not run:** the local stack end to end with the moved paths, and the chart's `fsGroup` ownership on a real volume. |
| The `aws` profile | **Not run.** Checked against stand-ins only. The runbook it wraps has itself never been applied to an account. |
| Shell scripts | `./zasp`, `deploy/zasp/lib/*.sh` and the chart's two scripts pass ShellCheck 0.11.0 with no findings. |
