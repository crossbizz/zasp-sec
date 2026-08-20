# Production deployment

## Supported topology

Zasp deploys immutable `web`, `agentsec-api`, and `agentsec-worker` images. Only web and API sit behind the TLS ingress: `/api/v1` routes to API port 8080 and every other path routes to web port 3000. Scheduler, outbox, discovery, and risk, graph, and search projection workers expose only private health, readiness, and metrics port 8081. Provider and projection endpoints have no public ingress.

The supported first profile is `values-saas.yaml`. Single-tenant requires its own release evidence before use. Helm fails closed when `customer_edge` is selected; an exact image, entrypoint, security review and deployed proof must ship before that profile can be enabled.

## Build and attest

Use the repository root as the build context. Supply the reviewed version to both Go builds and record all three resulting digests:

```sh
docker build --pull --build-arg VERSION="$REVIEWED_SHA" -f deploy/production/api.Dockerfile -t "$API_IMAGE" .
docker build --pull --build-arg VERSION="$REVIEWED_SHA" -f deploy/production/worker.Dockerfile -t "$WORKER_IMAGE" .
docker build --pull -f deploy/production/web.Dockerfile -t "$WEB_IMAGE" .
npm run production:release:gate
```

The required CI gate scans all tracked Git history with the pinned Gitleaks version, produces and license-checks npm and shipped Go-package SPDX inventories, audits locked dependencies offline, and checks every Docker `FROM` by exact manifest digest. The release system must additionally create an SPDX SBOM for each built image, scan both built image digests, reject critical/high findings without an approved exception, sign the digests, and retain provenance. The repository gate does not claim that an unbuilt image was scanned.

## Configure

Create secret values only in the approved secret manager. Helm values contain object names and credential references, never values. Every PostgreSQL principal has its own DSN object and service account. The discovery worker alone receives its queue, evidence bucket and KMS key, connector reference namespace, provider identifiers, and explicit STS web-identity token. Risk is DB-only. Graph receives its DB principal plus the exact non-admin `ref:neo4j/auth/runtime` reference; the graph schema Job uses a distinct DDL secret and role. Search receives its DB principal and exact signed OpenSearch index paths; its index-init Job uses a distinct schema role. Web and the recurring canary receive no cloud identity, and application containers disable ambient service-account tokens. Configure exact TLS host, certificate secret, trusted ingress CIDRs, fixed provider/dependency CIDRs, immutable implementation versions, and immutable product image digests. `global.publicOrigin` must equal `https://<ingress.host>` exactly.

Render and review before applying:

```sh
helm lint deploy/staging/product -f deploy/staging/product/values-saas.yaml -f release-values.yaml
helm template zasp deploy/staging/product --namespace agentsec -f deploy/staging/product/values-saas.yaml -f release-values.yaml > rendered-release.yaml
helm upgrade --install zasp deploy/staging/product --namespace agentsec --create-namespace --atomic --timeout 15m -f deploy/staging/product/values-saas.yaml -f release-values.yaml
```

The pre-install/pre-upgrade lifecycle is serialized. The migration service account (-30), secret-provider class (-20), and bounded migration Job (-10) establish exact schema v13 first. Neo4j schema authority then installs the exact graph constraints with its DDL-only principal. OpenSearch index authority installs the strict mapping and immutable schema marker with its init-only principal. Only after every hook succeeds may Helm roll the scheduler, outbox, discovery, and projection Deployments. This ordering works on a fresh install without pre-existing Kubernetes Secrets, but it requires the Secrets Store CSI driver/provider, exact IRSA trusts, and reachable private dependency CIDRs. A failed hook or readiness check blocks promotion. Do not bypass, reorder, or reuse an init identity for a runtime worker.

## Verify and promote

Require all eight Deployments available, every schema/init Job complete, PDBs, topology spread, HPAs, default-deny NetworkPolicies, and internal Services/ServiceMonitors present. Prove port 8081 is unreachable outside the monitoring namespace and that no worker or provider Service is a LoadBalancer or NodePort. Verify exact worker identity and schema/principal readiness, queue redrive policy, evidence bucket versioning/KMS/owner checks, graph mapping/constraints, search mapping/marker, and the read-only public canary before promotion. Capacity/readiness alerts must be healthy; queue and projection lag evidence remains a required external metric gate until the worker exports a bounded lag series. Record the reviewed Git SHA, image digests, chart fingerprint, init receipts, CI run, public URL, and all external gate results.

Never run this procedure against a shared namespace from a developer harness. The local combined proof owns its PostgreSQL/API/web/Chrome processes and temporary root, fingerprints them, and removes only those resources.
