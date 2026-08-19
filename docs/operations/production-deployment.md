# Production deployment

## Supported topology

Zasp deploys immutable `web` and `agentsec-api` images behind one TLS host. The ingress sends `/api/v1` to API port 8080 and every other path to web port 3000. API health, readiness and metrics use private port 8081. Worker, ingest, runtime-gateway and provider endpoints have no public ingress.

The supported first profile is `values-saas.yaml`. Single-tenant and customer-edge profiles require their own release evidence before use.

## Build and attest

Use the repository root as the build context. Supply the reviewed version to the API build and record both resulting digests:

```sh
docker build --pull --build-arg VERSION="$REVIEWED_SHA" -f deploy/production/api.Dockerfile -t "$API_IMAGE" .
docker build --pull -f deploy/production/web.Dockerfile -t "$WEB_IMAGE" .
npm run production:release:gate
```

The release system must create an SPDX SBOM, scan both built image digests, reject critical/high findings without an approved exception, sign the digests, and retain provenance. This repository gate validates source dependencies and container definitions; it does not claim that an unbuilt image was scanned.

## Configure

Create secret values only in the approved secret manager. The Helm values name secret-manager objects for PostgreSQL, Stytch, workflow signing, token reveal and the read-only canary PAT; they never contain those values. Configure exact TLS host, certificate secret, trusted ingress CIDRs, dependency CIDRs and immutable product image digests. `global.publicOrigin` must equal `https://<ingress.host>` exactly.

Render and review before applying:

```sh
helm lint deploy/staging/product -f deploy/staging/product/values-saas.yaml -f release-values.yaml
helm template zasp deploy/staging/product --namespace agentsec -f deploy/staging/product/values-saas.yaml -f release-values.yaml > rendered-release.yaml
helm upgrade --install zasp deploy/staging/product --namespace agentsec --create-namespace --atomic --timeout 15m -f deploy/staging/product/values-saas.yaml -f release-values.yaml
```

The pre-install/pre-upgrade Job runs `agentsec-migrate up` to exact schema v9. A failed Job blocks rollout; API readiness also fails on schema drift. Do not bypass either gate.

## Verify and promote

Require all Deployments available, migration Job complete, PDBs and NetworkPolicies present, internal port 8081 unreachable outside the monitoring namespace, and no provider Service of type LoadBalancer/NodePort. Verify the read-only canary, response security headers, metrics and traces before promotion. Record the reviewed Git SHA, image digests, chart rendering fingerprint, CI run and public URL in release evidence.

Never run this procedure against a shared namespace from a developer harness. The local combined proof owns its PostgreSQL/API/web/Chrome processes and temporary root, fingerprints them, and removes only those resources.
