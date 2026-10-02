# Temporal/OpenFGA connections, before cutover

P1 installs dependency connections. It doesn't route a product run to Temporal or authorize a product request through OpenFGA. Those switches belong to P2-P7. Keep `ZASP_RUNTIME_SERVICES_ENABLED` unset or `false` until the required endpoints, namespace and FGA model exist. Existing product startup is unchanged while disabled. `true` makes startup and readiness require both real services; a missing model, bad credential or unavailable endpoint fails closed.

## What is pinned

The platform requires Go 1.25.4 (verified with host 1.25.6). Direct SDKs are Temporal 1.48.0, Temporal API 1.63.4 and OpenFGA 0.8.2. Temporal's graph raises the existing direct `golang.org/x/sys` pin to 0.45.0. The exact dependency validator still applies. License files in the fetched modules identify Temporal SDK/API as MIT and OpenFGA SDK as Apache-2.0.

The reviewed dependency fix pins indirect gRPC 1.83.1 and `golang.org/x/text` 0.39.0 in `go.mod`/`go.sum`, fixing [GO-2026-6348](https://pkg.go.dev/vuln/GO-2026-6348) and [GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970). Both patched modules support Go 1.25; the resolved graph also updates genproto and x/sync to their required compatible versions. The direct-dependency lock policy is unchanged.

The amended, scoped `govulncheck` run still reports 26 reachable standard-library vulnerabilities in the host's Go 1.25.6, with fixes through Go 1.25.13. Don't publish using this toolchain without remediation and a fresh scan. It also reports 5 imported-package and 18 required-module findings that the scanned code doesn't appear to call. Complete output is retained under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p1-evidence/fix1/govulncheck-final.txt`; this isn't a whole-repository or container-image scan.

| Artifact | Release | Immutable identity |
| --- | --- | --- |
| Temporal server | 1.32.0 | `sha256:c3e752127759616bb1615e0f9ba0e21635aeb5fdeb922de4f371c350955f46ae` |
| Temporal admin tools | 1.32.0, bundles CLI 1.9.0 | `sha256:a9f84fb9a374b2374fe2e67c8efc0468ff3f1c66c8a0b14597ec86e349e62bca` |
| OpenFGA server/migrator | 1.21.0 | `sha256:2113c664a486b5da8d7a2cdab479e0d4e30639c80fd2c000540f645c1dbc1e55` |
| OpenFGA CLI | 0.8.0 | `sha256:5e6ba91d1830bb70f0464ae9949e2b37a65897f388bbb595ad583c89bfbd0673` |
| Disposable PostgreSQL | 17.7-alpine | `sha256:bb377b7239d2774ac8cc76f481596ce96c5a6b5e9d141f6d0a0ee371a6e7c0f2` |
| Temporal chart archive | 1.7.0 | SHA256 `f7b443f637b71fcbddd12900e5be9fe4c18cf741495d7b2cb247670681bf57d4` |
| OpenFGA chart archive | 0.3.15 | SHA256 `bde4e1fa8962314f403c8f52a49294fd583597e920465be21a78ba165bcc0894` |

These pins establish identity and tested wiring, not security clearance. Run the repository advisory/image scans before publication. No live-provider or production acceptance is implied.

Sources: [Temporal SDK release](https://github.com/temporalio/sdk-go/releases/tag/v1.48.0), [Temporal chart](https://github.com/temporalio/helm-charts/releases/tag/temporal-1.7.0), [OpenFGA SDK](https://github.com/openfga/go-sdk/releases/tag/v0.8.2), [OpenFGA chart](https://github.com/openfga/helm-charts/releases/tag/openfga-0.3.15). Server and tooling image digests were resolved from registry manifests on 2026-09-22 Pacific time.

## Run the disposable stack

From the repository root:

```sh
docker compose -f deploy/local/temporal-openfga.compose.yaml config --quiet
docker compose -f deploy/local/temporal-openfga.compose.yaml up -d
docker compose -f deploy/local/temporal-openfga.compose.yaml ps -a
ZASP_LOCAL_RUNTIME_SMOKE=1 go test -C services/platform ./runtimeservices -run '^TestLocalServiceConnectionSmoke$' -count=1 -v
```

Wait for `temporal-migrate`, `openfga-migrate` and `temporal-namespace` to exit zero before the smoke. The smoke creates an isolated FGA store and a one-type connection fixture; it does not publish the product permission model or write permission tuples. It uses the same SDK connection/readiness code as API and worker startup.

Three PostgreSQL containers hold separate databases and roles: `temporal`, `temporal_visibility` and `openfga`. None connect to product storage. All data volumes belong to this Compose project. The checked-in passwords/token are disposable local fixtures, never staging credentials. Temporal's single-process server is the official persistent server, not the development server. It is unauthenticated only on the private Compose network and host loopback. FGA requires the local preshared token. There is no UI.

`127.0.0.1:7233` is Temporal; `127.0.0.1:8088` is FGA HTTPS-disabled local HTTP. Metrics are loopback ports 9090 and 2112. Local namespace retention is 24 hours. Use `docker compose ... stop` to release compute while preserving evidence. Don't use `down --volumes` against retained data without explicit approval.

## Application settings

API `loadRuntimeConfig` and worker `loadWorkerRuntimeConfig` both call `runtimeservices.Load`. Their production builders call `Connect`, add the real-service check to readiness and close the SDK clients during shutdown. P1 wires the API and discovery-scheduler staging deployments as connection consumers; other workflow families remain disabled until their packets migrate them.

Required when enabled:

| Environment variable | Meaning |
| --- | --- |
| `ZASP_ENVIRONMENT` | `production`, `development` or `test`; plaintext exceptions require loopback and non-production |
| `ZASP_RUNTIME_SERVICES_TIMEOUT` | Positive duration, at most 30 seconds, shared connection/readiness bound |
| `ZASP_TEMPORAL_ADDRESS` | Private host and numeric port |
| `ZASP_TEMPORAL_NAMESPACE` | Existing namespace |
| `ZASP_TEMPORAL_TASK_QUEUE`, `ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE` | Distinct queues; registration is P2-P4 |
| `ZASP_TEMPORAL_TLS_CA_FILE`, `ZASP_TEMPORAL_TLS_CERT_FILE`, `ZASP_TEMPORAL_TLS_KEY_FILE` | Mounted CA and mTLS identity, mandatory outside local loopback |
| `ZASP_OPENFGA_URL` | Private HTTPS service origin, without userinfo/path/query |
| `ZASP_OPENFGA_STORE_ID`, `ZASP_OPENFGA_MODEL_ID` | Explicit ULIDs; no latest-model fallback |
| `ZASP_OPENFGA_TOKEN_FILE` | Mounted preshared token; required even locally |
| `ZASP_OPENFGA_TLS_CA_FILE` | Optional private CA, otherwise system trust roots |

The application disables redirects and ambient HTTP proxies for FGA. It bounds the HTTP pool at 16 connections (8 idle) and uses TLS 1.2 minimum. Raw SDK errors and payload logging are suppressed at the application boundary. Readiness verifies the actual Temporal namespace and FGA model, not a fabricated success response. No fallback turns dependency readiness green. Product permission enforcement itself remains P7.

## Staging, with an operator

Render the exact dependency charts and migration job without touching a cluster:

```sh
node deploy/staging/temporal-openfga.mjs --render
```

The command downloads the official release archives, checks their SHA256 values, and consumes `temporal.values.yaml` and `openfga.values.yaml`. `--deploy` runs the Temporal migration job first, waits for completion, then installs the pinned charts with Helm's bounded job/deployment wait. It doesn't create a namespace, secret or database for you.

The platform-data operator must first create namespace `zasp-runtime`, resolve the configured private DNS names to dedicated database instances, and provide:

- `temporal-persistence/password` and `temporal-visibility/password`, for their separate DB owners. The DB names and hosts are explicit in the values and migration job; keep both files aligned if staging DNS differs.
- A `runtime-database-ca` secret containing `ca.crt`.
- `temporal-internode-tls` and `temporal-frontend-tls` with `tls.crt`, `tls.key`, `ca.crt`, matching the SANs in the values. Frontend and internode require verified client certificates. The frontend trusts the internode issuing CA for internal clients.
- `openfga-datastore/uri`, using its own role/database and `sslmode=verify-full&sslrootcert=/etc/database-ca/ca.crt`. `openfga-auth/keys` holds the preshared token. `openfga-tls` contains `tls.crt`, `tls.key`, `ca.crt` for the private service SAN.

Both OpenFGA probes dial `127.0.0.1:8081` inside the pod and explicitly verify `openfga.zasp-runtime.svc.cluster.local` against `ca.crt`. Keep the configured server name aligned with the issued DNS SAN. Each probe bounds connection and RPC time to one second each; certificate verification stays on. The opt-in check `ZASP_RUNTIME_TLS_PROBE_SMOKE=1 node --test deploy/staging/runtime-services-probes.test.mjs` exercises the rendered command with a temporary DNS-SAN certificate and rejects a wrong server name. It removes only its disposable test container and generated keys.

Temporal chart 1.7.0 doesn't mount `server.additionalVolumes` in its schema job. Our small `temporal-migrate.yaml` calls the official SQL tool with the mounted database CA; chart schema management is off. OpenFGA's official migration job has its own CA mount. Neither edits upstream tables by hand.

The dependency ingress policy permits runtime-internal traffic, API/discovery-scheduler calls from namespace `agentsec`, and metrics scraping from `monitoring`. Product egress rules add only those private services to the existing DNS/database/provider rules. No public ingress, playground, profiler or Temporal Web deployment is enabled. Require the cluster's CNI to enforce NetworkPolicy. Operator access uses audited Kubernetes RBAC and short-lived port-forwarding, not a public service UI.

Initial staging bounds: two replicas per service role, Temporal requests 250m CPU/512Mi and limits 2 CPU/2Gi per pod; FGA requests 100m/128Mi and limits 1 CPU/512Mi. Each Temporal process/datastore pool and each FGA pod has at most 10 open and 5 idle DB connections. Account for all server roles and rollout overlap when sizing DB connection budgets. These are starting caps, not a measured capacity plan. Load measurement, autoscaling and SLO thresholds remain a deployment gate.

After P5 publishes the product store/model, create `zasp-runtime-services-client` in namespace `agentsec` with `temporal-ca.crt`, `temporal-client.crt`, `temporal-client.key`, `openfga-ca.crt`, `openfga-token`. Product pods need read-only mode 0440 with their existing group 65532. Server credentials are separate from application credentials. Rotate by updating the secret and rolling clients; P1 loads files at startup.

The product overlay is consumed by the existing chart:

```sh
helm upgrade --install zasp deploy/staging/product --namespace agentsec \
  -f /secure/verified-product-release-values.yaml \
  -f deploy/staging/temporal-openfga.values.yaml \
  --set-string runtimeServices.storeID="$FGA_STORE_ID" \
  --set-string runtimeServices.modelID="$FGA_MODEL_ID" \
  --wait --timeout 10m
```

Use verified product image digests and all existing release gates. The overlay's empty IDs intentionally fail rendering; don't deploy smoke IDs. The existing `renderRelease` entrypoint also accepts `options.runtimeServices`, and a rendered-resource test checks the API and worker credential wiring. Enabling P1 readiness does not enable new orchestration or permissions.

The named worker profile also requires
`authorizationTemporal.gatewayPolicyKeysConfigMap`. Provision that ConfigMap in
the product namespace with a `policy-keys.json` key containing only the canonical
public verifier document: `{"keys":[{"key_id":"<configured ID>","public_key":"<base64url Ed25519 public key>"}]}`.
Use the public keys corresponding to the authorized gateway signing keys;
never put private key bytes in this ConfigMap. The reference must be distinct
from pricing, database, worker-purpose and service credential references. The
chart copies the projected file into a regular0400 file owned by the nonroot
security-agent user, and mounts that destination read-only at
`/var/run/zasp-policy-verifier/policy-keys.json`. Updating the source requires a
worker rollout because the copy is made at startup. Render validation proves
the wiring only; it does not prove file contents, matching keys or authorized
signing behavior.

Current-profile event ingestion and runtime processing deployments explicitly
set `ZASP_RUNTIME_DATABASE_PROFILE=canonical61-temporal78-authorization79-80-runtime-v1`.
This selects SQL adapters independently of event codec versions. SQL-only
runtime workers do not receive Temporal/OpenFGA client credentials. Their
registered database role and installed current-runtime readiness must still
pass; this does not open unfinished Security Agent workflow families.

## Keep the data recoverable

Platform-data owns migrations, encrypted DB backups and restore drills for the two Temporal stores and FGA datastore. Product SQL has separate ownership and backup policy. Configure PITR and daily snapshots with the organization's retention policy before staging acceptance; record a restore point and confirm a bounded restore drill. Never restore FGA projection alone and call authorization ready: P6 must reconcile desired/applied revision and model generation. Temporal histories retain IDs and redacted summaries only once workflows are implemented. Staging namespace history retention is three days; audit and effect evidence remains in product stores under existing retention.

Scrape dependency metrics on private ports. Alert on unavailable readiness, migration failures, pool exhaustion and disk/backup failures; pending permission projection and workflow/business metrics arrive with later packets. Restrict service logs and backups to operators, keep payload/debug logging off, and don't write credentials, resource bodies or provider responses into workflow history.

Live staging deployment, real store/model publication, certificate issuance, credential rotation, restore drills, capacity evidence and advisory clearance are still external gates. Get those records before marking any original product task production-available.
