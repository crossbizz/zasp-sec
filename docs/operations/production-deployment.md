# Production deployment

## Supported topology

Zasp deploys only the immutable `web` and `agentsec-api` images behind one TLS host. The ingress sends `/api/v1` to API port 8080 and every other path to web port 3000. API health, readiness and metrics use private port 8081. Worker, ingest and runtime-gateway executables are not shipped by this release, and provider endpoints have no public ingress.

The supported first profile is `values-saas.yaml`. Single-tenant requires its own release evidence before use. Helm fails closed when `customer_edge` is selected; an exact image, entrypoint, security review and deployed proof must ship before that profile can be enabled.

## Build and attest

Use the repository root as the build context. Supply the reviewed version to the API build and record both resulting digests:

```sh
docker build --pull --build-arg VERSION="$REVIEWED_SHA" -f deploy/production/api.Dockerfile -t "$API_IMAGE" .
docker build --pull -f deploy/production/web.Dockerfile -t "$WEB_IMAGE" .
npm run production:release:gate
```

The required CI gate scans all tracked Git history with the pinned Gitleaks version, produces and license-checks npm and shipped Go-package SPDX inventories, audits locked dependencies offline, and checks every Docker `FROM` by exact manifest digest. The release system must additionally create an SPDX SBOM for each built image, scan both built image digests, reject critical/high findings without an approved exception, sign the digests, and retain provenance. The repository gate does not claim that an unbuilt image was scanned.

## Configure

Create secret values only in the approved secret manager. The Helm values name secret-manager objects for PostgreSQL, Stytch, workflow signing, token reveal and the read-only canary PAT; they never contain those values. The API service account may read only the seven API objects, the migration service account may read only PostgreSQL, and the short-lived canary sync account may read only the canary token. Web and the recurring canary do not receive a cloud identity, and all workload service accounts disable ambient token mounting. Configure exact TLS host, certificate secret, trusted ingress CIDRs, dependency CIDRs and immutable product image digests. `global.publicOrigin` must equal `https://<ingress.host>` exactly.

Render and review before applying:

```sh
helm lint deploy/staging/product -f deploy/staging/product/values-saas.yaml -f release-values.yaml
helm template zasp deploy/staging/product --namespace agentsec -f deploy/staging/product/values-saas.yaml -f release-values.yaml > rendered-release.yaml
helm upgrade --install zasp deploy/staging/product --namespace agentsec --create-namespace --atomic --timeout 15m -f deploy/staging/product/values-saas.yaml -f release-values.yaml
```

The pre-install/pre-upgrade lifecycle creates the migration service account at hook weight -30, its secret-provider class at -20, and the bounded migration Job at -10. The Job reads PostgreSQL from the CSI-mounted file and runs `agentsec-migrate up` to exact schema v9. This ordering works on a fresh Helm install without a pre-existing Kubernetes Secret. It still requires the cluster Secrets Store CSI driver/provider and IRSA prerequisites. A failed Job blocks rollout; API readiness also fails on schema drift. Do not bypass either gate.

## Verify and promote

Require both Deployments available, migration Job complete, PDBs and NetworkPolicies present, internal port 8081 unreachable outside the monitoring namespace, and no provider Service of type LoadBalancer/NodePort. Verify the read-only canary, response security headers, the `agentsec-api` ServiceMonitor scrape, emitted request/repository/provider spans and the exact Prometheus histogram before promotion. Record the reviewed Git SHA, image digests, chart rendering fingerprint, CI run and public URL in release evidence.

Never run this procedure against a shared namespace from a developer harness. The local combined proof owns its PostgreSQL/API/web/Chrome processes and temporary root, fingerprints them, and removes only those resources.
