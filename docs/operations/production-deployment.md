# Production deployment

## Supported topology

Zasp deploys immutable `web`, `agentsec-api`, `agentsec-worker`, `event-ingest`, `gateway-control`, `runtime-gateway`, and `sensor-agent` images. Web and API use the product TLS ingress. A separate bounded runtime ingress on the same TLS origin routes only the private gateway-control and sensor heartbeat/event paths, with a 64 MiB limit isolated from the 16 KiB product API limit. Scheduler, outbox, discovery, projection, and runtime pipeline workers expose only private health, readiness, and metrics port 8081.

The supported hosted profile is `values-saas.yaml`. Single-tenant requires its own release evidence before use. The `customer_edge` profile renders one database-free runtime gateway, one non-root sensor-agent DaemonSet, and exact-pinned Tetragon 1.7.0. It has regular-file credential materialization, a durable policy-cache PVC, durable node-local sensor cursors, no cloud identity, bounded egress, and no public ingress. Tetragon is the sole privileged container.

## Build and attest

Use the repository root as the build context. Supply the reviewed version to every Go build and record all seven resulting digests:

```sh
docker build --pull --build-arg VERSION="$REVIEWED_SHA" -f deploy/production/api.Dockerfile -t "$API_IMAGE" .
docker build --pull --build-arg VERSION="$REVIEWED_SHA" -f deploy/production/worker.Dockerfile -t "$WORKER_IMAGE" .
docker build --pull --build-arg VERSION="$REVIEWED_SHA" -f deploy/production/event-ingest.Dockerfile -t "$EVENT_INGEST_IMAGE" .
docker build --pull --build-arg VERSION="$REVIEWED_SHA" -f deploy/production/gateway-control.Dockerfile -t "$GATEWAY_CONTROL_IMAGE" .
docker build --pull --build-arg VERSION="$REVIEWED_SHA" -f deploy/production/runtime-gateway.Dockerfile -t "$RUNTIME_GATEWAY_IMAGE" .
docker build --pull --build-arg VERSION="$REVIEWED_SHA" -f deploy/production/sensor-agent.Dockerfile -t "$SENSOR_AGENT_IMAGE" .
docker build --pull -f deploy/production/web.Dockerfile -t "$WEB_IMAGE" .
npm run production:release:gate
```

The required CI gate scans all tracked Git history with the pinned Gitleaks version, produces and license-checks npm and shipped Go-package SPDX inventories, audits locked dependencies offline, and checks every Docker `FROM` by exact manifest digest. The release system must additionally create an SPDX SBOM for each built image, scan both built image digests, reject critical/high findings without an approved exception, sign the digests, and retain provenance. The repository gate does not claim that an unbuilt image was scanned.

## Configure

Create secret values only in the approved secret manager. Helm values contain object names and credential references, never values. Every PostgreSQL principal has its own DSN object and service account. Discovery receives only its queue, evidence bucket/KMS key, connector references, and explicit web identity. Risk is DB-only. Graph and search use separate runtime and schema-init authorities. Task 6 adds a distinct runtime-events queue/DLQ, versioned runtime-raw bucket and KMS key, runtime OpenSearch index, and a non-union role for ingest, gateway control, outbox, coordinator, archive, index, correlation, projection, and completion. Web and the recurring canary receive no cloud identity, and application containers disable ambient service-account tokens. Configure exact TLS host, certificate secret, trusted ingress CIDRs, fixed provider/dependency CIDRs, immutable implementation versions, and immutable product image digests. `global.publicOrigin` must equal `https://<ingress.host>` exactly.

Render and review before applying:

```sh
helm lint deploy/staging/product -f deploy/staging/product/values-saas.yaml -f release-values.yaml
helm template zasp deploy/staging/product --namespace agentsec -f deploy/staging/product/values-saas.yaml -f release-values.yaml > rendered-release.yaml
helm upgrade --install zasp deploy/staging/product --namespace agentsec --create-namespace --atomic --timeout 15m -f deploy/staging/product/values-saas.yaml -f release-values.yaml
```

## Install the customer edge

Use a dedicated namespace. The Tetragon DaemonSet needs privileged Pod Security admission, host networking, and cluster-scoped CRD/RBAC installation; don't install unrelated workloads there. Supply exact immutable `runtimeGateway` and `sensorAgent` image digests, three distinct Secret names, encrypted storage class, the SaaS control-plane CIDRs, Kubernetes API service/control-plane CIDRs, and the customer node CIDRs. `sensorAgent.stateHostPath` must remain `/var/lib/zasp-sensor`. Because Tetragon requires host networking for process visibility, also restrict node security-group or host-firewall egress to the Kubernetes API and approved operational dependencies; generic Kubernetes NetworkPolicy is not sufficient authority for that pod.

The sensor Secret contains one key named `token`. Its value is the exact one-time enrolled 81-byte sensor credential. Helm mounts the source only into a root init container, copies it to an `emptyDir`, changes ownership to UID/GID 65532, and sets mode 0600; the main container never mounts the source Secret. Runtime-gateway credential and policy-key Secrets keep their existing exact keys.

```sh
kubectl create namespace agentsec-edge
kubectl label namespace agentsec-edge pod-security.kubernetes.io/enforce=privileged --overwrite
helm lint deploy/staging/tetragon --namespace agentsec-edge
helm lint deploy/staging/product --namespace agentsec-edge -f deploy/staging/product/values-customer-edge.yaml -f customer-edge-values.yaml
helm upgrade --install zasp-tetragon deploy/staging/tetragon --namespace agentsec-edge --atomic --timeout 15m
helm upgrade --install zasp deploy/staging/product --namespace agentsec-edge --atomic --timeout 15m -f deploy/staging/product/values-customer-edge.yaml -f customer-edge-values.yaml
```

The vendored Tetragon dependency archive must hash to `4935787067939cacfe779366e9959962458d0cb6accdb368ec2554c1b733b3b2`. The release renderer rejects any other bytes. Tetragon writes only process exec/exit plus the two approved file/network kprobe classes to `/var/run/cilium/tetragon/tetragon.log` with mode 0644 and retains four uncompressed 32 MiB rotations. Its file exporter removes command arguments and working directories before writing, and its metric labels exclude pod and binary cardinality. The adapter drains version-pinned rotated inodes before the current file; a missing or ambiguous unread inode fails readiness instead of skipping evidence. Every node forwards its own events and writes a bounded node-report Lease. One Lease-elected adapter sends the cluster heartbeat; an exact pending heartbeat is stored before network I/O so takeover replays the same sequence after a crash or lost response.

Before promotion, require `zasp-tetragon` and `sensor-agent` desired/ready counts to match, both tracing policies present, every `zasp-sensor-node-*` Lease fresh, exactly one unexpired `zasp-sensor-heartbeat-leader`, and the SaaS sensor detail to advance without drop growth. Test leader-pod deletion and node-log rotation. `ZaspSensorAgentNotReady` and `ZaspEdgeDaemonSetUnavailable` must stay clear.

The pre-install/pre-upgrade lifecycle is serialized. The migration service account (-30), secret-provider class (-20), and bounded migration Job (-10) establish exact schema v15 first. Neo4j and OpenSearch init authorities then install their exact constraints, mappings, and immutable markers. Only after every hook succeeds may Helm roll discovery, projection, gateway-control, ingest, and runtime pipeline Deployments. This ordering works on a fresh install without pre-existing Kubernetes Secrets, but it requires the Secrets Store CSI driver/provider, exact IRSA trusts, and reachable private dependency CIDRs. A failed hook or readiness check blocks promotion. Do not bypass, reorder, or reuse an init identity for a runtime worker.

## Verify and promote

Require all 17 hosted Deployments available, every schema/init Job complete, PDBs, topology spread, HPAs, default-deny NetworkPolicies, and internal Services/ServiceMonitors present. Prove port 8081 is unreachable outside the monitoring namespace and that no worker Service is a LoadBalancer or NodePort. Verify exact identities, schema/principal readiness, both queue redrive policies, both versioned buckets and KMS keys, graph constraints, discovery and runtime search mappings/markers, gateway policy readiness, and the read-only public canary before promotion. Capacity/readiness alerts must be healthy; queue and projection lag evidence remains a required external metric gate until each source exports a bounded durable lag series. Record the reviewed Git SHA, seven image digests, chart fingerprint, init receipts, CI run, public URL, and all external gate results.

Never run this procedure against a shared namespace from a developer harness. The local combined proof owns its PostgreSQL/API/web/Chrome processes and temporary root, fingerprints them, and removes only those resources.
