# Production deployment on AWS: runbook

This is the ordered procedure from an empty AWS account to a running product that an administrator can sign in to. It covers the hosted control plane (`saas` mode) on the baseline schema.

**Status: nothing in this runbook has been applied to an AWS account or a cluster.** The Terraform and Helm files were checked statically only ([Static checks](#static-checks-that-were-run)). Every command, expected output and AWS behaviour below is unverified unless that section says otherwise. Expect to correct things on the first real run, and record what you correct.

Related guides: [Production deployment](production-deployment.md) (chart behaviour, schema job), [Installing the product schema](baseline-schema-install.md), [Cloud launch configuration](cloud-launch-configuration.md), [First Organization bootstrap](first-organization-bootstrap.md), [Temporal and OpenFGA](temporal-openfga.md).

## What runs where

| Component | Where | Created by |
| --- | --- | --- |
| Product database (PostgreSQL 18) | Neon, existing project | The owner. Not Terraform. |
| Identity | Stytch B2B, existing live project | The owner |
| Security Agent planner | OpenRouter | The owner (API key) |
| VPC, EKS cluster and node group, Fargate profile for Attack Lab | AWS | Terraform (`deploy/staging`) |
| One IAM role per workload (IRSA), KMS keys, S3 buckets, SQS queues with dead-letter queues, Secrets Manager entries, OpenSearch domain, VPC endpoints | AWS | Terraform |
| Public subnets, NAT gateway, ECR repositories, cert-manager role, database instance for Temporal, OpenFGA and Nango | AWS | Terraform, opt-in (`deploy/staging/production.tf`) |
| Temporal 1.32.0 and OpenFGA 1.21.0 | In the cluster, namespace `zasp-runtime` | Pinned upstream charts, operator |
| Product workloads (33 Deployments, or 29 without recovery), Nango, OpenTelemetry Collector | In the cluster, namespace `agentsec` | Helm chart `deploy/staging/product` |
| Secrets store driver, ingress-nginx, cert-manager, Prometheus Operator, metrics-server | In the cluster | Operator. No file in this repository installs them. |
| Neo4j (graph projection) | Not provided | The owner (decision D8) |

The Terraform root is `deploy/staging`. Its name is historical: it is the only root, and `environment = "production"` selects production. The cluster is EKS; the chart assumes EKS (IRSA annotations, `SecurityGroupPolicy`, the AWS secrets provider).

## Decisions the owner must make

| # | Decision | Where it is set | Notes |
| --- | --- | --- | --- |
| D1 | AWS region and two availability zones | `region`, `availability_zones` | Example uses `us-west-2`. Choose the region of the Neon project to keep database latency low. |
| D2 | Deployment mode | Helm `global.deploymentMode` | `saas`. `single_tenant` has never been installed. |
| D3 | Internet path | `public_subnet_cidrs` | Two CIDRs create public subnets, an internet gateway and **one** NAT gateway (single availability zone). Empty leaves the VPC with no internet path, which cannot run the product: Neon, Stytch and OpenRouter are on the internet. |
| D4 | Cluster and search sizing | `node_*`, `node_instance_types`, `opensearch_*` | The example values are a guess, not a measured capacity plan. |
| D5 | Public host name and TLS certificate | Helm `ingress.host`, `ingress.tlsSecretName`; `route53_zone_id` | The chart needs a Kubernetes TLS Secret and ingress-nginx. It does not use an ALB or an ACM certificate. With a Route 53 zone, cert-manager can issue the certificate; otherwise supply one. |
| D6 | NetworkPolicy enforcement | `vpc_cni_network_policy_enabled` | The chart renders 56 NetworkPolicy objects (60 with recovery) as CIDR allow-lists. Enforcing them requires correct address lists for Neon, Stytch, OpenRouter, GitHub and Okta, which change without notice. Not enforcing them removes that layer of egress control. Recommended for a first deployment: `false`, then enforce once the lists are known. |
| D7 | Databases for Temporal, OpenFGA and Nango | `runtime_services_rds_enabled` | `true` creates one private RDS PostgreSQL 17 instance. `false` means you provide four databases elsewhere. Temporal on Neon is untested. |
| D8 | Graph store | `neo4j_endpoint`, `neo4j_endpoint_cidr` | The graph projection and two runtime workers need a `neo4j+s://` endpoint on port 7687 with a certificate the workers can verify. Nothing here creates one. Options: Neo4j AuraDB, or Neo4j in the cluster behind a verified certificate. Until one exists those three workloads do not become ready; the rest of the product is unaffected. |
| D9 | Recovery workloads | Helm `recovery.canaryEnabled` | `true` adds four backup and restore workloads, which need a Neon project API key. The example sets `false`. |
| D10 | Terraform state | Backend configuration | `versions.tf` declares no backend, so state is a local file. Use a remote, encrypted, locked backend for production. |
| D11 | Operator access to the cluster | Outside Terraform | Production requires a private EKS API endpoint (`endpoint_public_access = false` is enforced). `kubectl` and `helm` must run from inside the VPC: an AWS CloudShell VPC environment, a VPN, or a bastion. Terraform creates none of them. |

## What the owner must provide

| Item | Detail |
| --- | --- |
| AWS account and credentials | A principal that can create IAM roles and OIDC providers, VPC, EKS, KMS, S3, SQS, Secrets Manager, OpenSearch, ECR, RDS and Route 53 records. In practice `AdministratorAccess`. A least-privilege apply policy has not been written. |
| Domain | A host name for the product, and control of its DNS. |
| Stytch | The **live** B2B project: project ID, secret, public token, and a webhook signing secret. Dashboard settings in step 10. The chart is fixed to `https://api.stytch.com` and to Google as the OAuth provider. |
| OpenRouter | An API key. The chart is fixed to the model `openai/gpt-5-mini`. |
| Neon | The project and branch, a direct (non-pooled) host name, and an administrative role that can run the SQL in step 1. If Neon's IP allow-list is on, add the NAT gateway address (Terraform output `nat_public_ip`). |
| GitHub App and Okta application | Optional for sign-in, but the API and the discovery worker need syntactically valid identifiers and the three provider secrets must hold a value. Placeholders work until the connectors are used. |
| Customer AWS roles | For each customer account, a role under the path `/zasp-reference/` that trusts the two product roles with an external ID (step 12). |
| Tools on the operator machine | Terraform 1.15.8 exactly, Helm 3.16 or later, kubectl, AWS CLI v2, Docker with buildx, `psql`, `openssl`, `jq`. |

## Gap analysis of the Terraform

Checked against what the chart mounts and what `deploy/local/real-stack/stack.sh` shows each binary needs.

| Need | State before | Now |
| --- | --- | --- |
| VPC, private subnets, isolated Attack Lab subnets | Created | Unchanged |
| Internet path (NAT, public subnets for a load balancer) | Missing. The VPC had no internet gateway. | Opt-in: `public_subnet_cidrs` |
| EKS cluster, node group, VPC CNI with pod security groups, Fargate profile, OIDC provider | Created. The cluster is created, not assumed. | Unchanged. Optional network-policy flag added. |
| IRSA role per workload | Created: 38 workload roles, each bound to one service account, each limited to its own secret, queue, bucket prefix and key. Service account names match the chart. | Unchanged |
| API connector role: assume customer roles | Created. `sts:AssumeRole` is limited to the exact ARNs in `aws_reference_role_arns`, which must sit under a prefix in `aws_reference_role_prefixes`. The discovery worker has the same permission. | Unchanged |
| SQS queues, dead-letter queues, redrive | Created: 9 queues, each with a KMS-encrypted dead-letter queue and a redrive allow policy | Unchanged |
| S3 buckets | Created: evidence, runtime raw, Red Team evidence, Attack Lab evidence. All are versioned, KMS-encrypted by default and block public access. **The evidence bucket has no bucket-owner-enforced ownership control and no bucket policy**; the other three have both. | Not changed. The closed IAM source profile lists every resource, so adding one needs that profile and its tests updated. |
| KMS keys | Created: 5 symmetric keys and one signing key, with rotation, on the default key policy (access is granted by IAM policies) | Unchanged |
| Secrets Manager entries | Created empty: 45 product entries, plus connector, Neo4j, recovery, Red Team target and worker-key entries | Added: approval-maintenance DSN and key |
| Database login names | Variable defaults were the historical names (`zasp_api_runtime`, …), which do not exist on the baseline | `schema_install = "baseline"` (default) fixes them to `zasp_operator` and `zasp_svc_*` in tags and outputs |
| Approval-maintenance key and DSN | Missing | Created with the named profile on the baseline |
| OpenSearch domain | Created in the VPC. Needs the OpenSearch service-linked role, which Terraform did not create. With two zones the node count must be even: `release.tfvars` sets 3. | Opt-in role: `create_opensearch_service_linked_role`. The example sets 2 nodes. |
| ECR repositories | Missing | Opt-in: `ecr_repositories_enabled` |
| Image build and push | Dockerfiles exist in `deploy/production`. No script builds or pushes them. | Commands in step 5 |
| Ingress, certificate, DNS | Missing. The chart expects ingress-nginx and a TLS Secret. | Opt-in cert-manager role. The load balancer and DNS record are operator steps. |
| Temporal and OpenFGA | Not in Terraform. Self-hosted in the cluster from pinned charts; they need three PostgreSQL databases and TLS certificates. | Opt-in RDS instance. Certificates and installation are operator steps. |
| Nango | The chart deploys it. It needs its own PostgreSQL database and a Kubernetes Secret. | The opt-in RDS instance can hold the database. |
| Neo4j | Assumed to exist. Terraform takes an endpoint and creates two empty credential entries. | Unchanged (decision D8) |
| Helm values from Terraform outputs | Outputs existed, in shapes that had to be copied by hand | New output `helm_values` in the chart's own shape |

The Helm chart was read and not changed: the values Terraform now emits and the chart's values agree ([Static checks](#static-checks-that-were-run)).

## Procedure

Shell variables used below:

```sh
export AWS_REGION=us-west-2 CLUSTER=zasp-production
export ACCOUNT_ID=<twelve digits> HOST=<public host name>
export TF="terraform -chdir=deploy/staging"
```

### 1. Prepare the Neon database

As Neon's administrative role, on a direct connection, with SQL (roles created through the Neon console or API cannot be altered later):

```sql
CREATE ROLE zasp_operator LOGIN CREATEROLE BYPASSRLS PASSWORD '<generated>';
GRANT zasp_operator TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;
CREATE DATABASE zasp OWNER zasp_operator TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C';
REVOKE zasp_operator FROM CURRENT_USER;
```

Neon's administrative role is not a superuser. Without the `GRANT`, `CREATE DATABASE` fails with `must be able to SET ROLE "zasp_operator"`; the `REVOKE` removes that grant again.

The operator DSN is `postgres://zasp_operator:<password>@<direct host>/zasp?sslmode=require`.

Verify: `psql "$OPERATOR_DSN" -Atc "select current_user, datcollate from pg_database where datname = current_database()"` prints `zasp_operator|C`.

The baseline guide records that the production Neon project already had the schema installed on 2026-11-12. If so, skip the statements. The chart's schema job then verifies that installation; it accepts it only if it came from the same baseline artifact as the release you deploy (`"current":true` in step 8). A database installed from an older artifact cannot be upgraded in place: drop it and create it again as [Reinstalling over an earlier artifact](baseline-schema-install.md#reinstalling-over-an-earlier-artifact) describes. That procedure was run on a Neon development branch on 2026-11-14, not on the production project.

### 2. Create the AWS resources

```sh
cp deploy/production/example.tfvars ~/zasp-production.tfvars   # edit every REPLACE
$TF init -input=false -lockfile=readonly
$TF plan  -var-file="$HOME/zasp-production.tfvars" -out=zasp.plan
$TF apply zasp.plan
```

Expected: the plan adds about 300 resources and changes or destroys none. Creation takes 30 to 45 minutes; the OpenSearch domain and the EKS cluster are the slow parts.

Verify:

```sh
$TF output -json helm_values > values-terraform.json
$TF output -json operator_secret_names | jq length          # 62 with the example variables
$TF output -json postgres_dsn_secret_logins | jq length     # 31
aws eks describe-cluster --name "$CLUSTER" --query cluster.status          # "ACTIVE"
aws opensearch describe-domain --domain-name "$CLUSTER-events" --query DomainStatus.Processing   # false
```

### 3. Reach the cluster and install the cluster add-ons

From a host inside the VPC (decision D11), as the IAM principal that ran `terraform apply` (EKS makes the creator a cluster administrator):

```sh
aws eks update-kubeconfig --name "$CLUSTER" --region "$AWS_REGION"
kubectl get nodes        # every node Ready
```

Install, at versions you choose and record (this repository pins none of them):

| Add-on | Required setting | Why |
| --- | --- | --- |
| Secrets Store CSI driver | `syncSecret.enabled=true` | The chart mounts every Secrets Manager entry through it and syncs some into Kubernetes Secrets. |
| AWS provider for the Secrets Store CSI driver | — | `provider: aws` in every `SecretProviderClass` |
| ingress-nginx, in namespace `ingress-nginx` | Snippet annotations allowed (`controller.allowSnippetAnnotations=true`; recent versions also need `annotations-risk-level: Critical`). Service of type LoadBalancer, internet-facing NLB. | The chart's two Ingress objects use `configuration-snippet` for security headers. |
| Prometheus Operator CRDs, namespace `monitoring` | — | The chart renders 27 ServiceMonitor objects (31 with recovery) and a PrometheusRule. Alternatively set `monitoring.enabled: false`. |
| metrics-server | — | 25 HorizontalPodAutoscaler objects (29 with recovery) |
| cert-manager, service account `cert-manager/cert-manager` annotated with `cert_manager_role_arn` | Only with `route53_zone_id` | Issues the product certificate |

Verify: `kubectl get crd secretproviderclasses.secrets-store.csi.x-k8s.io servicemonitors.monitoring.coreos.com securitygrouppolicies.vpcresources.k8s.aws` lists all three, and `kubectl -n ingress-nginx get svc` shows an external host name.

### 4. DNS and TLS

1. Point `$HOST` at the load balancer host name from step 3 (a CNAME, or a Route 53 alias record).
2. Create the namespace and the certificate Secret named by `ingress.tlsSecretName`:

```sh
kubectl create namespace agentsec
# Either: a cert-manager Certificate for $HOST (DNS-01, Route 53) with secretName zasp-product-tls
# Or:     kubectl -n agentsec create secret tls zasp-product-tls --cert=fullchain.pem --key=privkey.pem
```

Verify: `kubectl -n agentsec get secret zasp-product-tls -o jsonpath='{.type}'` prints `kubernetes.io/tls`, and `dig +short "$HOST"` resolves to the load balancer.

### 5. Build and push the images

From the repository root, at the reviewed commit. Building needs the internet (base images are pinned by digest).

```sh
REGISTRY="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"; VERSION="$(git rev-parse HEAD)"
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$REGISTRY"
while read -r name dockerfile; do
  docker buildx build --platform linux/amd64 --pull --build-arg VERSION="$VERSION" \
    -f "deploy/production/$dockerfile" -t "$REGISTRY/zasp/$name:$VERSION" --push .
  echo "$name $(aws ecr describe-images --repository-name "zasp/$name" --image-ids imageTag="$VERSION" --query 'imageDetails[0].imageDigest' --output text)"
done <<'EOF' | tee image-digests.txt
web web.Dockerfile
agentsec-api api.Dockerfile
agentsec-worker worker.Dockerfile
attack-lab-runner attack-lab-runner.Dockerfile
red-team-worker redteam-worker.Dockerfile
event-ingest event-ingest.Dockerfile
gateway-control gateway-control.Dockerfile
runtime-gateway runtime-gateway.Dockerfile
sensor-agent sensor-agent.Dockerfile
EOF
```

Put each image into `global.productImages` as `<registry>/zasp/<name>@<digest>`; the chart refuses a tag. `recovery.runnerImage` is the `agentsec-worker` reference.

Verify: `image-digests.txt` has nine lines, each ending in `sha256:` and 64 hex digits.

Not covered by these commands: the release gate (`npm run production:release:gate`), image scanning, SBOMs and signing described in [Production deployment](production-deployment.md#build-and-attest). `production-deployment.md` lists eight product images; the chart needs nine (it omits `attack-lab-runner`). Nango, the OpenTelemetry Collector, Temporal and OpenFGA images are pulled from their public registries through the NAT gateway.

### 6. Temporal, OpenFGA and their databases

Follow [Temporal and OpenFGA](temporal-openfga.md#staging-with-an-operator) with these production differences. None of this has been run against a cluster.

1. Databases. With `runtime_services_rds_enabled`, read the master credential from the secret in `$TF output runtime_services_rds`, connect from inside the VPC and create a role and database for each of `temporal`, `temporal_visibility`, `openfga` and `nango`.
2. `kubectl create namespace zasp-runtime`, then the Secrets that guide lists: `temporal-persistence` and `temporal-visibility` (key `password`), `openfga-datastore` (key `uri`), `openfga-auth` (key `keys`), `runtime-database-ca` (key `ca.crt`; for RDS, the regional RDS certificate bundle), and the three TLS Secrets `temporal-internode-tls`, `temporal-frontend-tls` and `openfga-tls` issued by a private CA you create for this purpose, with the service names in the staging values as subject alternative names.
3. The staging files name staging database hosts. Copy `deploy/production/temporal.values-production.example.yaml`, set the database host, and pass it after `deploy/staging/temporal.values.yaml`. Change `SQL_HOST` in a copy of `deploy/staging/temporal-migrate.yaml` to the same host. `node deploy/staging/temporal-openfga.mjs --deploy` cannot be used as it is: it takes no override file.
4. Apply `deploy/staging/temporal-openfga-network.yaml`, run the migration job, then install both pinned charts (URLs and checksums are in `deploy/staging/temporal-openfga.mjs`).
5. Publish the authorization model and record both identifiers:

```sh
# through a port-forward to the OpenFGA service, with its CA and preshared token
curl -fsS --cacert openfga-ca.crt -H "Authorization: Bearer $FGA_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"zasp-production"}' https://<forwarded>/stores                       # -> "id": store ULID
curl -fsS --cacert openfga-ca.crt -H "Authorization: Bearer $FGA_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @services/platform/authorization/model.json https://<forwarded>/stores/<store>/authorization-models
```

6. In namespace `agentsec`, create `zasp-runtime-services-client` with `temporal-ca.crt`, `temporal-client.crt`, `temporal-client.key`, `openfga-ca.crt` and `openfga-token`.

Verify: `kubectl -n zasp-runtime get pods` shows every pod Ready; both identifiers are 26-character ULIDs; `temporal operator namespace describe -n zasp-production` succeeds from the admin-tools image.

### 7. Generate keys and fill the secrets

Terraform created every Secrets Manager entry empty. **A pod whose entry has no value cannot start**, because its volume mount fails. List the entries with `$TF output -json operator_secret_names`. Write values with `aws secretsmanager put-secret-value --secret-id <name> --secret-string <value>` (or `--secret-binary fileb://<file>` for raw bytes); never put a value on a command line that is logged.

Names below are relative to `zasp-production/`.

| Entry | Content |
| --- | --- |
| `postgres-migration-dsn` | The operator DSN from step 1 |
| `stytch-project-id`, `stytch-secret`, `stytch-public-token`, `stytch-webhook-secret` | From the Stytch live project |
| `stytch-organization-id` | Written in step 10. Until then the API cannot start. |
| `openrouter-security-agent-api-key` | The OpenRouter key |
| `workflow-signing-key` | `openssl rand -hex 32` |
| `token-reveal-key` | `openssl rand 32 \| basenc --base64url \| tr -d '=\n'` |
| `authorization-worker-forward-key`, `authorization-worker-compensation-key` | `openssl rand 64` each, raw bytes |
| `approval-maintenance-key` | `openssl rand 32`, raw bytes. Exactly 32. |
| The 31 service DSNs | Written in step 9 |
| `gateway-policy-signing-private-key`, `attack-lab-egress-signing-key`, `red-team-adapter-token`, `red-team-adapter-tls-certificate`, `red-team-adapter-tls-private-key`, `attack-lab-proxy-tls-certificate`, `attack-lab-proxy-tls-private-key`, `canary-read-token` | Required by the Security Agent action, policy deployment, Red Team, Attack Lab and canary workloads. **Their exact formats were not established in this review**; read the loaders in `services/platform/agentsec-worker`, `services/platform/red-team-adapter` and `services/platform/attack-lab-proxy`. The gateway key decodes to a 64-byte Ed25519 private key. |
| `connectors/github/client-secret`, `connectors/github/app-private-key`, `connectors/okta/client-secret` | The provider credentials, or a placeholder until the connectors are used |
| `connectors/aws/external-id/<id>`, `connectors/kubernetes/*/<id>` | Per-customer references (step 12) |
| `connectors/microsoft/client-secret/<id>`, `connectors/salesforce/client-secret/<id>` | Only with the optional provider enabled: the customer's OAuth client secret (steps 13 and 14) |
| `projection/neo4j/auth/runtime`, `projection/neo4j/auth/schema` | Neo4j credentials (decision D8) |
| `zasp-recovery/neon/project-api-key`, `zasp/red-team/targets/readiness-0001` | Only with recovery enabled; Red Team readiness target credential |

The chart reads eight objects from Kubernetes, not through the driver. Create them in namespace `agentsec` before the first install; the names are the ones in `values-production.example.yaml`:

```sh
get() { aws secretsmanager get-secret-value --secret-id "zasp-production/$1" --query "$2" --output text; }
get authorization-worker-forward-key SecretBinary | base64 -d > forward.seed
get authorization-worker-compensation-key SecretBinary | base64 -d > compensation.seed
get approval-maintenance-key SecretBinary | base64 -d > approval.seed
kubectl -n agentsec create secret generic zasp-worker-forward-key --from-file=seed=forward.seed
kubectl -n agentsec create secret generic zasp-worker-compensation-key --from-file=seed=compensation.seed
kubectl -n agentsec create secret generic zasp-approval-maintenance-key --from-file=seed=approval.seed
shred -u forward.seed compensation.seed approval.seed
```

Also: the Secret `nango-storage` (`database-url`, `encryption-key`, `service-key`), the ConfigMap `zasp-gateway-policy-verifiers` (`policy-keys.json`, the public half of the gateway signing key, see [Temporal and OpenFGA](temporal-openfga.md)), and the ConfigMap `zasp-temporal-pricing` (`bindings.json`). The four DSN Secrets are created in step 9.

Verify: `wc -c` on the three seed files prints 64, 64 and 32 before they are removed; `kubectl -n agentsec get secret,configmap` lists the objects.

### 8. First Helm install: the schema

```sh
cp deploy/production/values-production.example.yaml ~/values-production.yaml   # replace every REQUIRED value
API_IMAGE=<the agentsec-api reference from step 5>
docker run --rm --entrypoint /app/agentsec-migrate "$API_IMAGE" approval-maintenance-checksum   # -> approvalMaintenance.profileChecksum
helm upgrade --install zasp deploy/staging/product --namespace agentsec \
  -f values-terraform.json -f ~/values-production.yaml --timeout 20m
```

Do not pass `--wait` or `--atomic`: the workloads cannot become ready yet. The pre-install job `agentsec-schema-v61` installs or verifies the schema and registers four verifiers, as `zasp_operator`.

Verify, from a machine that can reach Neon:

```sh
docker run --rm -e ZASP_POSTGRES_DSN="$OPERATOR_DSN" --entrypoint /app/agentsec-migrate "$API_IMAGE" verify-baseline
# {"sealed":true,"intact":true,"artifact":"<sha256>","current":true}
psql "$OPERATOR_DSN" -Atc "select count(*) from pg_roles where rolname like 'zasp_svc_%'"   # 31
```

If the job fails, `kubectl -n agentsec logs job/agentsec-schema-v61` shows one `baseline refused: stage=…` line; the table of stages is in [Installing the product schema](baseline-schema-install.md#refusals).

### 9. Service login passwords and DSNs

For each login, set a password as the operator and store its DSN. `postgres_dsn_secret_logins` maps each Secrets Manager entry to its login:

```sh
NEON_HOST=<direct host>
$TF output -json postgres_dsn_secret_logins | jq -r 'to_entries[] | "\(.key) \(.value)"' |
while read -r secret login; do
  password="$(openssl rand -hex 24)"
  # psql substitutes variables only in input it reads, not in -c.
  psql "$OPERATOR_DSN" -v ON_ERROR_STOP=1 -v login="$login" -v password="$password" -q <<'SQL'
ALTER ROLE :"login" PASSWORD :'password';
SQL
  aws secretsmanager put-secret-value --secret-id "$secret" \
    --secret-string "postgres://$login:$password@$NEON_HOST/zasp?sslmode=require" >/dev/null
done
```

Then create the four DSN Secrets the chart reads from Kubernetes (key `postgres-dsn`):

```sh
for pair in zasp-temporal-executor:postgres-temporal-executor-dsn zasp-temporal-compensation:postgres-temporal-compensation-dsn \
            zasp-authorization-adapter:postgres-red-team-adapter-dsn zasp-approval-maintenance-dsn:postgres-approval-maintenance-dsn; do
  kubectl -n agentsec create secret generic "${pair%%:*}" \
    --from-literal=postgres-dsn="$(aws secretsmanager get-secret-value --secret-id "zasp-production/${pair##*:}" --query SecretString --output text)"
done
```

The approval-maintenance DSN must have the same host, database and parameters as the Security Agent API DSN; the loop above guarantees that.

Verify: `psql "$(aws secretsmanager get-secret-value --secret-id zasp-production/postgres-api-dsn --query SecretString --output text)" -Atc 'select current_user'` prints `zasp_svc_api`.

### 10. First Organization

In the Stytch dashboard for the live project ([provider prerequisites](first-organization-bootstrap.md#provider-prerequisites)):

- Redirect URLs: `https://$HOST/auth/callback?state={}` for Login and Signup, and `https://$HOST/auth/callback` for Invite.
- Billing verified. Without it Stytch sends invitations only to the account owner's own email domain.
- Google enabled as an OAuth provider (the chart's sign-in start is fixed to Google).

Then, from a machine that can reach Neon and Stytch:

```sh
docker run --rm --entrypoint /app/zasp-bootstrap \
  -e ZASP_POSTGRES_DSN="$OPERATOR_DSN" -e ZASP_PUBLIC_ORIGIN="https://$HOST" \
  -e ZASP_DEPLOYMENT_MODE=saas -e ZASP_ORGANIZATION_ID= \
  -e ZASP_STYTCH_BASE_URL=https://api.stytch.com -e ZASP_STYTCH_PROJECT_ID -e ZASP_STYTCH_SECRET \
  -e ZASP_OPENFGA_STORE_ID=<store> -e ZASP_OPENFGA_MODEL_ID=<model> \
  "$API_IMAGE" -organization-name "<name>" -domain <domain> -admin-email <address>
```

It prints one JSON object. Store its `organization_reference` and register the identity verifiers:

```sh
aws secretsmanager put-secret-value --secret-id zasp-production/stytch-organization-id --secret-string '<organization_reference>'
helm upgrade --install zasp deploy/staging/product --namespace agentsec \
  -f values-terraform.json -f ~/values-production.yaml --set schema.registerIdentityVerifiers=true --timeout 20m
```

Set `schema.registerIdentityVerifiers: true` in the values file afterwards and keep it.

Verify: the JSON has `"organization_created":true` and `"admin_created":true` on the first run; the administrator receives a Stytch invitation email.

### 11. Check the running product

```sh
kubectl -n agentsec get deploy                      # web, agentsec-api and the workers below Available
kubectl -n agentsec get cronjob zasp-authorization-projector   # last schedule within a minute
kubectl -n agentsec port-forward deploy/agentsec-api 8081:8081 &
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/readyz   # 200
curl -s -o /dev/null -w '%{http_code}\n' "https://$HOST/"               # 200, valid certificate
```

Then the administrator opens the invitation, accepts it on `https://$HOST/auth/callback`, and reaches the product. "Authorization pending" clears after the next projector run, normally within a minute.

Expected to be ready on a first deployment: `web`, `agentsec-api`, discovery scheduler, discovery worker, outbox publisher, risk and search projection, the runtime pipeline. Expected **not** ready until their prerequisites exist: the Security Agent worker (pricing bindings, see known gaps), graph projection and runtime correlation and projection (Neo4j), Red Team and Attack Lab workloads (their keys and certificates), Nango (its database). This split is inferred from the launch plan and the chart, not observed.

### 12. Connect a customer AWS account

For each customer account: a role under `/zasp-reference/` whose trust policy allows `connector_role_arn` and `worker_role_arn` (Terraform outputs) with `sts:ExternalId`; the role ARN in `aws_reference_role_arns` and its prefix in `aws_reference_role_prefixes`; the external ID as the value of `zasp-production/connectors/aws/external-id/<id>`; then `terraform apply` and `helm upgrade` with a fresh `values-terraform.json`. `provision_customer_account` in `deploy/local/real-stack/stack.sh` shows the trust policy and a minimal read policy. The read policy's `bedrock:ListAgents`, `bedrock:GetAgent`, `bedrock-agentcore:ListAgentRuntimes`, `bedrock-agentcore:GetAgentRuntime`, `bedrock-agentcore:ListGateways` and `lambda:ListFunctions` actions are optional: they let the sync find the account's AI agents (Bedrock agents, AgentCore runtimes and gateways, and Lambda functions that can call a model), and without them the sync still succeeds and the AI service shows `access_denied` in the inventory. Six more optional actions feed the agentless runtime signal and the agent checks: `cloudtrail:LookupEvents` (roles that invoked a model in the last seven days become inferred agents), `iam:GetRole` (an agent whose execution role was not used for 90 days gets a finding), and `route53resolver:ListResolverQueryLogConfigs`, `ec2:DescribeFlowLogs`, `logs:StartQuery` and `logs:GetQueryResults` (an EC2 instance that resolved a model API's name and then connected to the answered address becomes an inferred agent). The last four work only when Route 53 Resolver query logs and VPC Flow Logs are delivered to CloudWatch Logs; restrict the two `logs` actions to those log groups. Logs delivered only to S3 are not read. When a permission or a log is missing the sync still succeeds and the integration's "Agent discovery coverage" names what is missing. Logs Insights queries are billed to the customer's account: two bounded queries per region and sync, over the last 24 hours. Nothing is installed in the account and no query name, address or event leaves it; only the names of the matched services are kept. Every new customer account is a Terraform change. No connector has been connected against real AWS.

### 13. Connect Microsoft (Entra and Copilot Studio)

Optional, and off by default. **Neither this connector nor the Salesforce one has been run against a real tenant or org.** The collectors and the token exchange were tested against recorded shapes and fake endpoints only.

What it finds: Entra agent identities, AI enterprise applications of the tenant, and, when a Dataverse environment is configured, Copilot Studio agents.

In the customer's tenant:

1. Register an application in Microsoft Entra (single tenant). Note the Directory (tenant) ID and the Application (client) ID.
2. Add the Microsoft Graph **application** permission `Application.Read.All` and, for Entra Agent ID, `AgentIdentity.Read.All`. Grant admin consent. No delegated permission is used.
3. Create a client secret. Note its expiry: the customer rotates it, and the stored value must be replaced before it expires.
4. For Copilot Studio only: in the Power Platform environment that holds the agents, add the application as an **application user** with a security role that can read the `bot` table. Note the environment URL, `https://<name>.crm<n>.dynamics.com`.

In the deployment (a Terraform change, like a new AWS account):

```hcl
discovery_optional_providers = {
  microsoft_collector        = "collector_v1"     # the version the installed schema hands a run
  microsoft_client_secret_id = "customer-0001"    # lower case, 8 to 128 characters
  microsoft_egress_cidrs     = ["..."]            # see below
}
```

`terraform apply` creates the empty secret `zasp-production/connectors/microsoft/client-secret/customer-0001` under the connector KMS key and lets the API role and the discovery worker role read it. Put the client secret there as the secret value (the secret string, nothing else), then `helm upgrade` with a fresh `values-terraform.json`. That sets `ZASP_DISCOVERY_MICROSOFT_COLLECTOR_VERSION` on the API and on the discovery worker: the worker registers the collector, and the API lists the connector in the catalog. Unset, the worker refuses a Microsoft job and the catalog does not show the connector.

In the product, create the integration "Microsoft Entra and Copilot Studio" with:

| Field | Value |
| --- | --- |
| `tenant_id` | The Directory (tenant) ID, a lower-case GUID. It becomes the integration's subject. |
| `client_id` | The Application (client) ID, a lower-case GUID. |
| `client_secret_reference` | `ref:microsoft/client-secret/customer-0001`. A reference, never the secret. |
| `dataverse_url` | Optional. `https://<name>.crm<n>.dynamics.com`. Leave empty to skip Copilot Studio. It cannot be added later by editing; create the integration again. |

Then "Authorize Microsoft reference". The API reads the secret and requests an application token from `https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token` for `https://graph.microsoft.com/.default` (and for `<dataverse_url>/.default` when configured). It records the tenant only if a token is issued. Every discovery run repeats the exchange; the client secret never leaves Secrets Manager and the API and worker memory, and the token is never stored.

Network. The API and the discovery worker need HTTPS to `login.microsoftonline.com`, `graph.microsoft.com` and the Dataverse environment. The chart's NetworkPolicy matches addresses, not names, so `microsoft_egress_cidrs` is a snapshot of those addresses and no wildcard such as `*.dynamics.com` can be expressed. Microsoft publishes the ranges (the `AzureActiveDirectory` service tag and the Microsoft 365 endpoint list); they are shared with other Microsoft services, so the policy admits more addresses than the three hosts, and it must be refreshed when the ranges change. The process itself calls only those hosts. A deployment that needs name-based egress needs a CNI with FQDN policy or an egress proxy; neither is part of this chart.

### 14. Connect Salesforce (Agentforce)

Optional, and off by default. Not run against a real org (see step 13).

What it finds: the Agentforce agents of one org.

In the customer's org:

1. Create a connected app (or an external client app) with OAuth enabled and the scope `api` ("Manage user data via APIs").
2. Enable the **client credentials flow** and set a run-as user. That user needs the permissions **API Enabled** and **View Setup and Configuration**, and nothing more.
3. Note the consumer key and the consumer secret, the org's My Domain URL (`https://<name>.my.salesforce.com`) and the 18-character Organization ID (Setup, Company Information; it starts with `00D`).

In the deployment:

```hcl
discovery_optional_providers = {
  salesforce_collector        = "collector_v1"
  salesforce_client_secret_id = "customer-0001"
  salesforce_egress_cidrs     = ["..."]
}
```

`terraform apply`, put the consumer secret in `zasp-production/connectors/salesforce/client-secret/customer-0001`, then `helm upgrade`. That sets `ZASP_DISCOVERY_SALESFORCE_COLLECTOR_VERSION` on the API and the discovery worker.

In the product, create the integration "Salesforce Agentforce" with:

| Field | Value |
| --- | --- |
| `instance_url` | The My Domain URL, `https://<name>.my.salesforce.com`. Not `login.salesforce.com`. |
| `organization_id` | The 18-character Organization ID. It becomes the integration's subject. |
| `client_id` | The consumer key. |
| `client_secret_reference` | `ref:salesforce/client-secret/customer-0001`. |

Then "Authorize Salesforce reference". The API posts the client-credentials grant to `<instance_url>/services/oauth2/token` and requires the response to name the configured instance, and the configured org when the response carries an identity URL. Salesforce reports no token lifetime, so the worker treats a token as good for 20 minutes and requests a new one on every run.

Network. The API and the discovery worker need HTTPS to the customer's My Domain host. As in step 13, `salesforce_egress_cidrs` is an address snapshot (Salesforce publishes its ranges per instance; they are shared across orgs), and `*.my.salesforce.com` cannot be expressed.

Each additional tenant or org is another reference secret. The Terraform variable provisions one per provider; more need a further `connector_reference` secret under the same path.

### 15. Turn on runtime agent discovery in a customer cluster

Optional. It finds workloads that call a model API or a remote MCP server at run time, including ones whose pod template says nothing about AI. It needs the customer-edge chart with the sensor and Tetragon already installed.

What it adds to each node: one pod (`sensor-egress`) in the host network namespace, running as root with every capability dropped except `NET_RAW`. It does two things on the node:

- captures DNS answers (UDP from port 53) on every interface, which includes the host side of each pod's veth;
- reads Tetragon's `tcp_connect` events from the local socket.

When a pod was given an address as the answer for a name in the product's catalog (for example `api.openai.com`, `bedrock-runtime.<region>.amazonaws.com`, `mcp.<vendor>`), and then connected to that address, the pod's workload is recorded under the catalog token (`openai`, `bedrock`, `mcp_remote`). Names outside the catalog are dropped on the node. The pod writes the result to a ConfigMap named `zasp-egress-<digest>` in the release namespace, labelled `zasp.ai/egress-observations=v1`, and sends nothing anywhere else. No name, address, payload or pod name is stored: `kubectl get configmap -l zasp.ai/egress-observations=v1 -o yaml` shows everything that is kept.

Enable it:

```yaml
sensorAgent:
  egressDiscovery:
    enabled: true
    healthPort: 18083      # a free port on every node; the pod uses the host network
    publishInterval: 5m0s
```

The Kubernetes discovery credential must be allowed to list ConfigMaps so the collector can read the observations. If the credential is bound to the built-in `view` ClusterRole it already can. Otherwise add, in the release namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: zasp-discovery-egress-observations }
rules:
  - apiGroups: [""]
    resources: [configmaps]
    verbs: [list]
```

bound to the discovery identity. The collector lists ConfigMaps across namespaces with the label selector; Kubernetes cannot limit a list to a label, so this grants reading all ConfigMaps. Without it discovery still completes and judges workloads on their pod templates alone.

When the permission is missing, the integration's detail says so under "Agent discovery coverage" ("Runtime agent discovery: the discovery credential may not list ConfigMaps..."). The line disappears after the first sync with the permission in place. It does not tell whether the sensor role is installed, only whether its output could be read.

Check it on the cluster with the two workloads in `deploy/local/egress-discovery/`:

```bash
kubectl apply -f deploy/local/egress-discovery/smoke.yaml
```

Wait for one publish interval, then:

```bash
deploy/local/egress-discovery/report.sh --check-smoke
```

`egress-smoke` calls `api.anthropic.com` without a credential once a minute and must be recorded under `anthropic`; `egress-control` calls `example.com` and must not be recorded. The script passes only when both hold. Without the flag it prints every recorded workload and totals per token, which is the list to compare against the workloads you know call a model (misses) and those you know do not (false positives). It needs `kubectl` and `jq` and reads ConfigMaps only. Remove the workloads with `kubectl delete -f deploy/local/egress-discovery/smoke.yaml`. The image tag in `smoke.yaml` is not pinned by digest.

Also: `kubectl -n <namespace> logs ds/sensor-egress` prints `egress-discovery published workloads=<n> ...` after a workload has called a model API; after the next Kubernetes sync the workload is on the Agents page as unmanaged, and "How it was found" lists `egress:<token>`.

What it does not see:

- A workload that reaches the model through an HTTP proxy or an egress gateway: the proxy resolves the name, not the pod. The gateway or the proxy shows up instead.
- DNS over HTTPS or over TCP.
- Pods on the host network, and the `kube-system` and `cilium` namespaces (Tetragon's events for them are filtered out).
- CNIs that do not pass pod traffic through an interface in the host network namespace (IPVLAN in L3S mode, some SR-IOV setups).
- Which MCP tool or which model was called. That needs the traffic in plain text, which the runtime gateway and OpenTelemetry instrumentation provide for managed agents.

An observation counts for seven days after it was last seen. Detection takes effect at the next Kubernetes sync.

### 16. Allow provider remediations in a customer AWS account

Optional. Without it nothing changes: the product only reads the customer account, and a remediation request for the account is refused with `remediation_role_not_configured`.

Two Security Agent actions change a customer's account after a person approved them: `attach_bedrock_guardrail` (attaches an existing guardrail to a Bedrock agent; answers the finding `agent_guardrail_missing`) and `detach_role_administrator_policy` (detaches one managed policy from the agent's execution role; answers `agent_role_administrator_access`). They are never executed with the discovery role of step 12. Each integration names a separate remediation role, and the database refuses a remediation role that is the read role or that belongs to another account.

In the customer account, create a second role, for example `zasp-remediation`:

- Trust policy: the action worker's own role (below) with the same `sts:ExternalId` as the read role of step 12. The remediation role uses the integration's external ID; no second secret is stored.
- Permissions, and nothing else:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["bedrock:GetAgent", "bedrock:UpdateAgent", "bedrock:PrepareAgent"], "Resource": "arn:aws:bedrock:*:<account>:agent/*" },
    { "Effect": "Allow", "Action": ["iam:ListAttachedRolePolicies", "iam:DetachRolePolicy"], "Resource": "arn:aws:iam::<account>:role/*" }
  ]
}
```

  `bedrock:GetAgent` reads the agent before and after the change. `bedrock:UpdateAgent` attaches the guardrail; the call sends the agent's whole configuration back unchanged except for the guardrail. `bedrock:PrepareAgent` prepares the working draft afterwards. `iam:ListAttachedRolePolicies` proves the policy is attached before anything is detached and proves it is gone afterwards. `iam:DetachRolePolicy` detaches it. Narrow the two `Resource` values to the agents and execution roles you want the product to be able to change. `UpdateAgent` names the agent's execution role again; AWS documents that passing a role to a service needs `iam:PassRole` on that role (with `iam:PassedToService` `bedrock.amazonaws.com`). Whether `UpdateAgent` needs it when the role does not change has not been verified against a live account: if the first guardrail attachment ends as `provider_access_denied`, add that statement.

Then, per integration, name the role:

```sh
curl -sS -X PUT "$API/api/v1/integrations/$INTEGRATION_ID/remediation-role" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: remediation-role-0001' -H 'If-Match: "0"' \
  -d '{"role_arn":"arn:aws:iam::<account>:role/zasp-remediation"}'
```

`GET` on the same path shows the setting; `{"role_arn":""}` with the current version in `If-Match` removes it. The change is audited.

On the product side the Security Agent action worker (`agentsec-worker` in mode `security-agent-action`) performs remediations only when it is given its own AWS identity. Set all three, or none:

| Variable | Value |
| --- | --- |
| `ZASP_SECURITY_AGENT_REMEDIATION_ROLE_ARN` | An IAM role for the action worker's service account (web identity). It needs `sts:AssumeRole` on the customers' remediation roles and `secretsmanager:GetSecretValue` on the external ID secrets (`<prefix>/aws/external-id/*`). It needs nothing else, and in particular no access to the discovery role. |
| `ZASP_SECURITY_AGENT_REMEDIATION_WEB_IDENTITY_TOKEN_FILE` | `/var/run/secrets/eks.amazonaws.com/serviceaccount/token` |
| `ZASP_SECURITY_AGENT_REMEDIATION_SECRET_PREFIX` | The same value as `ZASP_DISCOVERY_SECRET_PREFIX`, so the worker finds the integration's external ID. |

`ZASP_AWS_REGION` must be set as well. Without these variables the worker runs as before and approved remediations stay dispatched until a worker with the variables takes them. The Terraform and the Helm chart do not create this role or set these variables yet; add them by hand.

How a remediation runs:

1. Create a Security Agent from the template “Attach Bedrock Guardrail” or “Detach Administrator Policy from Agent Role”, validate it and enable supervised execution. Enabling it switches on execution for its action in the Environment.
2. On the finding, choose “Fix with a Security Agent”, name the guardrail (identifier or ARN, and a version) or the policy ARN, and request approval. The same request over the API is `POST /api/v1/security-agents/{id}/runs` with `trigger_kind: finding`, the finding as `trigger_id` and a `remediation`.
3. A person other than the requester approves the run. A policy detachment needs an identity administrator (Organization or Security administrator). The approval is valid for 24 hours.
4. The action worker assumes the remediation role, reads the agent, makes the change, and reads it back. Only a confirmed read-back ends the run as `remediated`.
5. The run's audit event `effect_verified` carries the rollback record: for a guardrail, the guardrail configuration the agent had before (or none); for a policy, the role and the policy that was detached. Nothing is rolled back automatically. To undo a guardrail attachment, set the agent's guardrail back to the recorded value; to undo a detachment, attach the recorded policy to the recorded role again.
6. The finding closes at the next sync of the AWS integration, when discovery reads the agent again.

A run that ends as `needs_human` names why in its last error: `remediation_role_denied` (the role could not be assumed), `provider_access_denied`, `target_not_found`, `target_mismatch` (the provider no longer describes the agent the approval was for), `policy_not_attached` (nothing is detached that is not attached to the agent's own role), `provider_rejected` (for example a guardrail that does not exist), `verification_mismatch` (the read-back did not show the change) or `provider_outcome_unknown` (a change may have been made and could not be confirmed; check the agent or the role by hand).

## Rollback

| Situation | Action |
| --- | --- |
| A Helm upgrade made things worse | `helm -n agentsec rollback zasp <revision>`. The schema job is an install and upgrade hook and does not run on rollback; the database is not touched. |
| The schema job refused | Nothing was changed: `install-baseline` is one transaction. Fix the cause and repeat. |
| The schema must be removed | Drop and recreate the empty database ([the steps](baseline-schema-install.md#reinstalling-over-an-earlier-artifact)), or restore a Neon branch from before the install. There is no down-migration, and a sealed catalog cannot be altered and re-sealed. |
| A release with a different baseline artifact | Not supported in place. Either replace the database as in the row above, which discards its data, or make a reviewed schema change ending in `zasp_baseline.accept`. |
| Terraform change went wrong | `terraform plan` against the previous variables and apply. Secrets Manager entries are deleted with a 30-day recovery window, KMS keys with a 30-day window; recreating an entry of the same name inside the window fails until it is restored or force-deleted. S3 buckets with objects, the RDS instance (deletion protection) and the OpenSearch domain do not delete cleanly. |
| A leaked or wrong service password | Repeat step 9 for that login and restart its workload. |

Backup and restore of the product database is in [Backup, restore and rollback](backup-restore-rollback.md); it has not been rehearsed on this deployment.

## Resources that cost money

With `example.tfvars`. Prices are rough list prices from memory for `us-west-2`, not looked up; treat the total as an order of magnitude.

| Resource | Quantity | Rough monthly cost (USD) |
| --- | --- | --- |
| EKS control plane | 1 | 75 |
| EC2 nodes `m7i.xlarge`, on demand | 6 to 10 | 900 to 1,500 |
| OpenSearch `r7g.large.search` with 100 GB gp3 | 2 | 300 |
| RDS `db.t4g.medium`, Multi-AZ, 50 GB | 1 | 110 |
| Interface VPC endpoints | 7 services in 2 zones | 100 |
| NAT gateway and its data transfer | 1 | 35 plus traffic |
| Network load balancer | 1 | 20 plus traffic |
| Secrets Manager entries | about 65 | 26 |
| KMS keys | 6 | 6 plus requests |
| S3, SQS, ECR storage, CloudWatch, Route 53, Fargate (per Attack Lab run) | usage | small at first |

Roughly 1,600 to 2,200 per month before traffic, plus Neon, Stytch, OpenRouter and any Neo4j service.

## Not yet verified, and known gaps

From [the launch plan](../internal/mvp-launch-plan-2026-11-12.md) and this review.

Deployment:

- **Nothing has been applied to a real AWS account.** No `terraform apply`, no Helm install on any cluster, no pod has pulled an image or mounted a secret. IAM, KMS and network behaviour is untested against AWS; development used LocalStack, which does not enforce IAM.
- **Provider remediations (step 16) have not run against AWS.** The two actions were tested against in-memory Bedrock and IAM clients that implement the SDK interfaces, and the database path was run on PostgreSQL 18. No `UpdateAgent`, `PrepareAgent` or `DetachRolePolicy` call has reached AWS; the error codes the worker treats as refusals and the `iam:PassRole` requirement are from the AWS documentation as remembered. The Terraform and the Helm chart do not yet give the action worker its remediation identity.
- **Runtime agent discovery (step 15) has not run on a cluster.** The packet capture ran for real on a loopback interface and the Tetragon stream against a stand-in gRPC server; no veth, CNI, real Tetragon or real DNS server has been in the path. The chart block was rendered with a stand-in for Helm, not Helm.
- The chart's schema job has not run in a cluster. The same commands ran outside Kubernetes on the local stack.
- The approval-maintenance key and DSN wiring in a running API pod is untested.
- Whether nodes in the private subnets join the cluster is untested. The VPC has no `ec2` interface endpoint, so without the NAT gateway the VPC CNI cannot reach the EC2 API.
- `single_tenant` mode is unproven: never installed, and it needs its own release evidence.
- `postgres.transport: websocket` is rendered but not accepted by the release contract. Event ingest and gateway control need PostgreSQL on port 5432.
- The Attack Lab proxy's database egress rule allows private CIDRs only (`attack_lab_database_egress_cidrs`). Neon is on the internet, so the proxy cannot reach the product database as configured.
- Attack Lab needs EKS Fargate and has never run.
- The evidence bucket lacks bucket-owner enforcement and a TLS-only bucket policy.
- One NAT gateway is a single-zone dependency for all egress.
- The release contract (`renderRelease`) uses fixture CIDRs and historical values; a production install uses the values files here instead and is not checked by that contract. The release gates (history secret scan, SBOM, image scan, signing) are not part of this runbook, and 7 deploy tests fail in this environment for missing tools.
- Secret formats for the Red Team, Attack Lab, gateway signing and canary entries were not established.
- The Microsoft and Salesforce connectors (steps 13 and 14) have not been run against a real tenant or org. The chart and Terraform changes for them were not rendered or planned: this environment has neither Helm nor Terraform. The production release contract (`renderRelease`) does not accept the two providers, so a release rendered through it leaves both disabled.

Product, as measured on 2026-11-12 and 2026-11-13 against a Neon development branch:

- First sign-in completed once, by invitation token. Not exercised: Google OAuth redirect, the UI in a browser, SSO, members beyond bootstrapped administrators, SaaS Organization selection.
- 21 of 42 parameterless read routes answer. Agents, tools, identities, runtimes, Organization and member administration, Security Agent runs, tests and audit events are refused or time out. Answers take 5 to 8 seconds.
- The Security Agent worker does not start: it needs a per-Organization pricing-bindings file, which cannot serve a multi-tenant deployment. Its planner ignores HTTPS proxies and needs direct egress.
- No discovery run, connector connection, projection, runtime event, policy enforcement, Red Team run or approval notification has been driven end to end.
- Product-started sign-in is bound to one Stytch Organization (`stytch-organization-id`).
- The PRD §21 release gates (tenant-isolation test on the deployed system, disaster-recovery rehearsal, single-tenant install, performance targets, SBOM and signing) are open.

On 2026-11-14 the same development branch was reinstalled from this release's artifact ([the steps](baseline-schema-install.md#reinstalling-over-an-earlier-artifact)) and the product was run against it from the [local stack](../../deploy/local/real-stack/README.md), over the WebSocket transport, with LocalStack standing in for AWS. This supersedes the second and fourth items above for that setup; it is still not a cluster and not real AWS.

- The API reported ready 14 seconds after start; the scheduler, outbox and discovery workers after 4, 26 and 43 seconds, the last two including the creation of their LocalStack resources.
- With an API token, the home summary, integrations, identities, findings, policies, Security Agents, agents, tools, runtimes, Security Agent runs, tests and search routes answered `200`. The home summary took 3.3 seconds; the others 0.9 to 1.9 seconds.
- An AWS integration was created, connected and synchronized once: the run took 2 minutes 51 seconds and stored 13 entities. The risk projection worker then produced the two expected findings. For a few seconds after the snapshot was applied, three routes answered `503 authorization_unavailable` until the permission projector had run.
- The session used to connect the integration and to create the API token was issued in the database as a test fixture. No person signed in.

## Static checks that were run

On 2026-11-13, without AWS credentials, with Terraform 1.15.8 and the locked providers (aws 6.60.0, tls 4.3.0) installed from `releases.hashicorp.com` into a local mirror because the Terraform registry was unreachable, and Helm 3.16.

| Check | Result |
| --- | --- |
| `terraform fmt -check` on `deploy/staging` and `deploy/production/example.tfvars` | Clean |
| `terraform validate` | Valid |
| `terraform test` for the seven files in `deploy/staging/tests`, with `release.tfvars`, one file at a time | Same as before the change: six pass; `compliance_exports_iam` fails one run and crashes Terraform, as it does at HEAD |
| The IAM policy union gate (`iam-policy-union-v1.mjs --plan`) on the default profile | Passes: the default profile has no new resource |
| A plan of `example.tfvars` under mocked providers | Plans; baseline login names, 31 DSN entries, approval-maintenance entries and every opt-in resource are present |
| `helm lint` and `helm template` of the chart with the `helm_values` output of that mocked plan, `values-production.example.yaml` and stand-ins for its REQUIRED fields | Renders. With recovery enabled it yields the same 315 resources, with the same structure, as the baseline release the release contract accepts; values differ only where expected. |
| `helm template` of the pinned Temporal chart with `temporal.values-production.example.yaml` | Renders with the overridden host and namespace |
| `node --test deploy/production/*.test.mjs deploy/staging/*.test.mjs` | 442 pass, 7 fail, 3 skipped, before and after; the same 7 (missing Go 1.26.8, promtool and gitleaks) |

A mocked plan proves that the configuration is internally consistent. It does not prove that AWS accepts any resource.
