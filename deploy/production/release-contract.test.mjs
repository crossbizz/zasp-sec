import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { promisify } from "node:util";
import { load } from "js-yaml";

import { inspectContainerBuilds, renderCustomerEdgeRelease, renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { customerEdgeReleaseFixture as edgeRelease, productionReleaseFixture as release } from "./release-fixture.mjs";

const exec = promisify(execFile);

test("production container builds are exact, non-root, health-bound, and secret-free", async () => {
  const builds = await inspectContainerBuilds();
  assert.deepEqual(builds.map(({ name, user, port }) => ({ name, user, port })), [
    { name: "web", user: "65532:65532", port: 3000 },
    { name: "agentsec-api", user: "65532:65532", port: 8080 },
    { name: "agentsec-worker", user: "65532:65532", port: 8081 },
    { name: "event-ingest", user: "65532:65532", port: 8081 },
    { name: "gateway-control", user: "65532:65532", port: 8081 },
    { name: "runtime-gateway", user: "65532:65532", port: 8081 },
    { name: "sensor-agent", user: "65532:65532", port: 8081 },
  ]);
  for (const build of builds) {
    assert.equal(build.readOnlyCompatible, true);
    assert.equal(build.containsSecret, false);
    assert.match(build.healthcheck, /127\.0\.0\.1/);
    assert.equal(build.digestPinned, true);
  }
  const webDockerfile = await readFile(new URL("./web.Dockerfile", import.meta.url), "utf8");
  assert.doesNotMatch(webDockerfile, /(?:ARG|ENV)\s+.*(?:SECRET|TOKEN|PASSWORD|DSN)/i);
  assert.match(webDockerfile, /\/src\/dist\/standalone/);
  assert.doesNotMatch(webDockerfile, /\/src\/node_modules/);
  assert.match(await readFile(new URL("../../next.config.ts", import.meta.url), "utf8"), /output:\s*["']standalone["']/);
});

test("customer edge renders database-free gateway, multi-node sensor, and pinned Tetragon", async () => {
  const resources = await renderCustomerEdgeRelease(edgeRelease);
  const deployment = one(resources, "Deployment", "runtime-gateway");
  const pod = deployment.spec.template.spec;
  const container = pod.containers[0];
  assert.equal(container.image, edgeRelease.image);
  assert.equal(pod.serviceAccountName, "runtime-gateway");
  assert.equal(pod.automountServiceAccountToken, false);
  assert.equal(pod.securityContext.fsGroupChangePolicy, "OnRootMismatch");
  assert.equal(container.securityContext.readOnlyRootFilesystem, true);
  assert.deepEqual(envOf(deployment), {
    ZASP_GATEWAY_CONTROL_BASE_URL: edgeRelease.controlPlaneURL,
    ZASP_GATEWAY_ORGANIZATION_ID: edgeRelease.organizationID,
    ZASP_GATEWAY_WORKSPACE_ID: edgeRelease.workspaceID,
    ZASP_GATEWAY_ENVIRONMENT_ID: edgeRelease.environmentID,
    ZASP_GATEWAY_DEVICE_ID: edgeRelease.deviceID,
    ZASP_GATEWAY_CREDENTIAL_ID: edgeRelease.credentialID,
    ZASP_GATEWAY_PRIVATE_KEY_FILE: "/var/run/secrets/zasp-config/credential.json",
    ZASP_GATEWAY_POLICY_KEYS_FILE: "/var/run/secrets/zasp-config/policy-keys.json",
    ZASP_GATEWAY_POLICY_CACHE_FILE: "/var/lib/zasp/policy/cache.json",
    ZASP_GATEWAY_EVIDENCE_STORE_DIRECTORY: "/var/lib/zasp/policy/evidence",
    ZASP_GATEWAY_EVIDENCE_MAX_BYTES: "8589934592",
    ZASP_GATEWAY_BOOTSTRAP_FAILURE_MODE: "closed", ZASP_GATEWAY_MAX_REQUEST_BYTES: "65536",
    ZASP_GATEWAY_MAX_PENDING_EVENTS: "1024", ZASP_GATEWAY_OPERATION_TIMEOUT: "10s",
    ZASP_GATEWAY_SYNC_INTERVAL: "30s", ZASP_GATEWAY_SHUTDOWN_TIMEOUT: "15s",
  });
  assert.doesNotMatch(JSON.stringify(deployment), /ZASP_(?:POSTGRES|DATABASE)|postgres|DATABASE_URL/);
  assert.deepEqual(pod.volumes.find(({ name }) => name === "credential-source").secret, { defaultMode: 288, secretName: edgeRelease.credentialSecretName });
  assert.deepEqual(pod.volumes.find(({ name }) => name === "policy-keys-source").secret, { defaultMode: 288, secretName: edgeRelease.policyKeysSecretName });
  assert.match(pod.initContainers[0].args[0], /cp \/source\/credential\/credential\.json \/config\/credential\.json/);
  assert.match(pod.initContainers[0].args[0], /chmod 600 \/config\/credential\.json \/config\/policy-keys\.json/);
  assert.equal(container.volumeMounts.some(({ name }) => name === "credential-source" || name === "policy-keys-source"), false);
  assert.equal(pod.volumes.find(({ name }) => name === "policy-cache").persistentVolumeClaim.claimName, "runtime-gateway-cache");
  const claim = one(resources, "PersistentVolumeClaim", "runtime-gateway-cache");
  assert.equal(claim.spec.storageClassName, edgeRelease.storageClassName);
  assert.equal(claim.spec.resources.requests.storage, "32Gi");
  assert.equal(resources.some(({ kind }) => kind === "Ingress"), false);
  assert.equal(resources.some(({ kind }) => kind === "PodDisruptionBudget"), false);
  const egress = one(resources, "NetworkPolicy", "runtime-gateway-control-plane");
  assert.deepEqual(egress.spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock.cidr)), edgeRelease.controlPlaneCIDRs);
  const monitoring = one(resources, "NetworkPolicy", "runtime-gateway-monitoring");
  assert.deepEqual(monitoring.spec.ingress[0].ports, [{ protocol: "TCP", port: 8081 }]);
  assert.equal(one(resources, "ServiceMonitor", "runtime-gateway").spec.endpoints[0].path, "/metrics");

  const sensor = one(resources, "DaemonSet", "sensor-agent");
  const sensorPod = sensor.spec.template.spec;
  const sensorContainer = sensorPod.containers.find(({ name }) => name === "sensor-agent");
  assert.equal(sensorContainer.image, edgeRelease.sensorImage);
  assert.equal(sensorPod.serviceAccountName, "sensor-agent");
  assert.equal(sensorPod.automountServiceAccountToken, true);
  assert.equal(sensorContainer.securityContext.privileged, false);
  assert.equal(sensorContainer.securityContext.readOnlyRootFilesystem, true);
  assert.equal(sensorContainer.securityContext.runAsUser, 65532);
  assert.equal(sensorPod.hostNetwork, false);
  assert.deepEqual(envOf(sensor), {
    ZASP_SENSOR_CONTROL_PLANE_URL: edgeRelease.controlPlaneURL,
    ZASP_SENSOR_TOKEN_FILE: "/var/run/secrets/zasp-sensor/token",
    ZASP_TETRAGON_LOG_FILE: "/var/run/cilium/tetragon/tetragon.log",
    ZASP_SENSOR_CURSOR_FILE: "/var/lib/zasp-sensor/cursor.json",
    ZASP_SENSOR_NAMESPACE: "fieldRef:metadata.namespace",
    ZASP_SENSOR_POD_NAME: "fieldRef:metadata.name",
    ZASP_SENSOR_NODE_NAME: "fieldRef:spec.nodeName",
    HOST_IP: "fieldRef:status.hostIP",
    ZASP_SENSOR_KERNEL_FILE: "/host/proc/sys/kernel/osrelease",
    ZASP_SENSOR_BTF_FILE: "/host/sys/kernel/btf/vmlinux",
    ZASP_TETRAGON_METRICS_URL: "http://$(HOST_IP):2112/metrics",
    ZASP_SENSOR_BATCH_SIZE: "100",
    ZASP_SENSOR_MAX_PROCESSES: "10000",
    ZASP_SENSOR_POLL_INTERVAL: "1s",
    ZASP_SENSOR_OPERATION_TIMEOUT: "10s",
    ZASP_SENSOR_SHUTDOWN_TIMEOUT: "15s",
    ZASP_SENSOR_LEASE_DURATION: "15s",
    ZASP_SENSOR_REPORT_TTL: "30s",
  });
  assert.equal(sensorPod.volumes.find(({ name }) => name === "token-source").secret.secretName, edgeRelease.sensorTokenSecretName);
  assert.equal(sensorPod.volumes.find(({ name }) => name === "token-source").secret.defaultMode, 0o440);
  assert.equal(sensorPod.volumes.find(({ name }) => name === "state").hostPath.path, edgeRelease.stateHostPath);
  assert.equal(sensorPod.volumes.find(({ name }) => name === "tetragon-log").hostPath.type, "DirectoryOrCreate");
  assert.equal(sensorContainer.volumeMounts.some(({ name }) => name === "token-source"), false);
  const materializer = sensorPod.initContainers.find(({ name }) => name === "materialize-sensor-authority");
  assert.equal(materializer.image, edgeRelease.sensorImage);
  assert.deepEqual(materializer.command, ["/bin/sh", "-ec"]);
  assert.match(materializer.args[0], /chown 65532:65532 \/config\/token \/state; chmod 0600 \/config\/token; chmod 0700 \/state/);
  assert.equal(materializer.securityContext.runAsUser, 0);
  assert.deepEqual(materializer.securityContext.capabilities, { drop: ["ALL"], add: ["CHOWN", "DAC_OVERRIDE", "FOWNER"] });
  assert.deepEqual(one(resources, "Role", "sensor-agent").rules, [
    { apiGroups: ["coordination.k8s.io"], resources: ["leases"], verbs: ["get", "list", "create", "update"] },
    { apiGroups: [""], resources: ["pods"], verbs: ["list"] },
  ]);
  assert.equal(one(resources, "RoleBinding", "sensor-agent").subjects[0].name, "sensor-agent");
  assert.deepEqual(one(resources, "NetworkPolicy", "sensor-agent-kubernetes-api").spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock.cidr)), edgeRelease.kubernetesAPICIDRs);
  assert.deepEqual(one(resources, "NetworkPolicy", "sensor-agent-node-metrics").spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock.cidr)), edgeRelease.nodeCIDRs);
  assert.equal(one(resources, "ServiceMonitor", "sensor-agent").spec.endpoints[0].path, "/metrics");
  const edgeAlerts = one(resources, "PrometheusRule", "zasp-customer-edge").spec.groups.flatMap(({ rules }) => rules);
  assert.deepEqual(edgeAlerts.map(({ alert }) => alert), [
    "ZaspRuntimeGatewayNotReady",
    "ZaspRuntimeGatewayEvidenceCapacityWarning",
    "ZaspRuntimeGatewayEvidenceCapacityCritical",
    "ZaspRuntimeGatewayEvidenceDatabaseCapacityCritical",
    "ZaspRuntimeGatewayEvidenceVolumeFreeCritical",
    "ZaspRuntimeGatewayEvidenceQuarantined",
    "ZaspSensorAgentNotReady",
    "ZaspEdgeDaemonSetUnavailable",
  ]);
  assert.equal(
    edgeAlerts.find(({ alert }) => alert === "ZaspRuntimeGatewayNotReady").expr,
    'agentsec_ready{namespace="agentsec",service="runtime-gateway"} == 0 or absent(agentsec_ready{namespace="agentsec",service="runtime-gateway"})',
  );
  assert.equal(
    edgeAlerts.find(({ alert }) => alert === "ZaspRuntimeGatewayEvidenceCapacityWarning").expr,
    'zasp_gateway_evidence_receipt_utilization_ratio{namespace="agentsec",service="runtime-gateway"} >= 0.8',
  );
  assert.equal(
    edgeAlerts.find(({ alert }) => alert === "ZaspRuntimeGatewayEvidenceCapacityCritical").expr,
    'zasp_gateway_evidence_receipt_utilization_ratio{namespace="agentsec",service="runtime-gateway"} >= 0.95',
  );
  assert.equal(
    edgeAlerts.find(({ alert }) => alert === "ZaspRuntimeGatewayEvidenceDatabaseCapacityCritical").expr,
    'zasp_gateway_evidence_database_utilization_ratio{namespace="agentsec",service="runtime-gateway"} >= 0.8',
  );
  assert.equal(
    edgeAlerts.find(({ alert }) => alert === "ZaspRuntimeGatewayEvidenceVolumeFreeCritical").expr,
    'kubelet_volume_stats_available_bytes{namespace="agentsec",persistentvolumeclaim="runtime-gateway-cache"} / kubelet_volume_stats_capacity_bytes{namespace="agentsec",persistentvolumeclaim="runtime-gateway-cache"} <= 0.25',
  );
  assert.equal(
    edgeAlerts.find(({ alert }) => alert === "ZaspRuntimeGatewayEvidenceQuarantined").expr,
    'zasp_gateway_evidence_quarantined{namespace="agentsec",service="runtime-gateway"} > 0',
  );
  const tracingPolicies = resources.filter(({ kind }) => kind === "TracingPolicy");
  assert.deepEqual(tracingPolicies.map(({ metadata }) => metadata.name).sort(), ["zasp-network-connect", "zasp-sensitive-file"]);
  assert.equal(tracingPolicies.every(({ spec }) => JSON.stringify(spec.podSelector) === "{}"), true);
  assert.equal(tracingPolicies.every(({ spec }) => JSON.stringify(spec.containerSelector) === JSON.stringify({ matchExpressions: [{ key: "name", operator: "Exists" }] })), true);

  const tetragon = resources.find(({ kind, spec }) => kind === "DaemonSet" && spec?.template?.spec?.containers?.some(({ name }) => name === "tetragon"));
  assert.ok(tetragon);
  const tetragonContainer = tetragon.spec.template.spec.containers.find(({ name }) => name === "tetragon");
  assert.match(tetragonContainer.image, /^quay\.io\/cilium\/tetragon:v1\.7\.0@sha256:[0-9a-f]{64}$/);
  assert.equal(tetragonContainer.securityContext.privileged, true);
  const tetragonConfig = one(resources, "ConfigMap", "zasp-tetragon-config");
  assert.equal(tetragonConfig.data["cluster-name"], "zasp-runtime");
  assert.equal(tetragonConfig.data["export-file-perm"], "644");
  assert.equal(tetragonConfig.data["export-file-max-backups"], "4");
  assert.deepEqual(tetragonConfig.data["export-denylist"].split("\n").sort(), ['{"health_check":true}', '{"namespace":["","cilium","kube-system"]}'].sort());
  assert.equal(tetragonConfig.data["field-filters"], '{"fields":"process.arguments,parent.arguments,ancestors.arguments,process.cwd,parent.cwd,ancestors.cwd","action":"EXCLUDE"}');
  assert.equal(tetragonConfig.data["metrics-label-filter"], "namespace,workload");
  assert.equal(resources.some((resource) => resource.kind === "Deployment" && /tetragon-operator/.test(resource.metadata?.name ?? "")), false);
  assert.equal(resources.filter(({ kind }) => kind === "ServiceAccount").every(({ metadata }) => metadata.annotations?.["eks.amazonaws.com/role-arn"] === undefined), true);
  assert.doesNotMatch(JSON.stringify(resources), /ZASP_(?:POSTGRES|DATABASE)|DATABASE_URL/);
});

test("customer edge rejects mutable sensors, broad networks, shared secrets, and ambient state", async () => {
  for (const value of [
    { ...edgeRelease, sensorImage: "zasp/sensor-agent:latest" },
    { ...edgeRelease, sensorTokenSecretName: edgeRelease.credentialSecretName },
    { ...edgeRelease, kubernetesAPICIDRs: [] },
    { ...edgeRelease, nodeCIDRs: ["0.0.0.0/0"] },
    { ...edgeRelease, stateHostPath: "/tmp/zasp-sensor" },
    { ...edgeRelease, extra: "ambient" },
  ]) await assert.rejects(() => renderCustomerEdgeRelease(value), /edge release rejected/);
});

test("production release renders private Nango dependency plus a fail-closed local Collector", async () => {
  const resources = await renderRelease(release);

  const nango = one(resources, "Deployment", "nango");
  assert.equal(nango.spec.replicas, 2);
  assert.match(nango.spec.template.spec.containers[0].image, /^nangohq\/nango-server:hosted-[a-f0-9]+@sha256:[a-f0-9]{64}$/);
  assert.equal(nango.spec.template.spec.serviceAccountName, "nango");
  assert.equal(nango.spec.template.spec.automountServiceAccountToken, false);
  assert.equal(nango.spec.template.spec.securityContext.runAsUser, 1000);
  assert.equal(nango.spec.template.spec.securityContext.runAsGroup, 1000);
  assert.equal(nango.spec.template.spec.containers[0].securityContext.runAsUser, 1000);
  assert.equal(nango.spec.template.spec.containers[0].securityContext.runAsGroup, 1000);
  assert.deepEqual(Object.fromEntries(nango.spec.template.spec.containers[0].env.filter(({ value }) => value !== undefined).map(({ name, value }) => [name, value])), {
    CSP_REPORT_ONLY: "true",
    FLAG_AUTH_ROLES_ENABLED: "false",
    FLAG_SERVE_CONNECT_UI: "false",
    NANGO_CLOUD: "false",
    NANGO_DB_APPLICATION_NAME: "zasp-production-nango",
    NANGO_DB_POOL_MAX: "20",
    NANGO_DB_POOL_MIN: "0",
    NANGO_DB_SCHEMA: "nango",
    NANGO_DB_SSL: "true",
    NANGO_ENTERPRISE: "false",
    NANGO_LOGS_ENABLED: "false",
    NANGO_MIGRATE_AT_START: "false",
    NANGO_SERVER_URL: "http://nango.agentsec.svc.cluster.local:3003",
    NANGO_PUBLIC_SERVER_URL: "http://nango.agentsec.svc.cluster.local:3003",
    NANGO_TELEMETRY_SDK: "false",
    RECORDS_DATABASE_POOL_MAX: "20",
    RECORDS_DATABASE_POOL_MIN: "0",
    RECORDS_DATABASE_SCHEMA: "nango_records",
    RECORDS_DATABASE_SSL: "true",
    SERVER_PORT: "3003",
  });
  assert.deepEqual(nango.spec.template.spec.containers[0].env.find(({ name }) => name === "NANGO_DATABASE_URL").valueFrom.secretKeyRef, { name: release.nango.storageSecretName, key: "database-url" });
  assert.equal(nango.spec.template.spec.containers[0].env.some(({ name }) => name === "FLAG_AUTH_ENABLED"), false);
  assert.match(nango.spec.template.spec.containers[0].args[0], /sslmode.*verify-full/);
  assert.match(nango.spec.template.spec.containers[0].args[0], /exec node packages\/server\/dist\/server\.js/);
  assert.doesNotMatch(nango.spec.template.spec.containers[0].args[0], /packages\/server\/entrypoint\.sh/);
  const databaseURLGuard = nango.spec.template.spec.containers[0].args[0].split("\n")[0];
  const fixtureDatabaseURL = ({
    username = "nango",
    password = "fixture-only",
    port = "5432",
    query = "?sslmode=verify-full",
  } = {}) => {
    const value = new URL(`postgresql://db.internal.example:${port}/nango${query}`);
    value.username = username;
    if (password !== null) value.password = password;
    return value.href;
  };
  const validDatabaseURL = fixtureDatabaseURL();
  const runDatabaseURLGuard = (nangoURL, recordsURL = nangoURL) => exec("/bin/sh", ["-ec", databaseURLGuard], {
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "", NANGO_DATABASE_URL: nangoURL, RECORDS_DATABASE_URL: recordsURL },
  });
  assert.deepEqual(await runDatabaseURLGuard(validDatabaseURL), { stdout: "", stderr: "" });
  for (const [nangoURL, recordsURL] of [
    [fixtureDatabaseURL({ query: "" }), undefined],
    [fixtureDatabaseURL({ query: "?sslmode=no-verify" }), undefined],
    [fixtureDatabaseURL({ query: "?sslmode=verify-full&sslmode=disable" }), undefined],
    [fixtureDatabaseURL({ query: "?sslmode=verify-full&application_name=unsafe" }), undefined],
    [fixtureDatabaseURL({ port: "6432" }), undefined],
    [fixtureDatabaseURL({ password: null }), undefined],
    [validDatabaseURL, fixtureDatabaseURL({ username: "other" })],
  ]) await assert.rejects(() => runDatabaseURLGuard(nangoURL, recordsURL));
  assert.equal(nango.spec.template.spec.containers[0].env.some(({ name }) => name === "NANGO_DB_NAME"), false);
  assert.deepEqual(nango.spec.template.spec.containers[0].env.find(({ name }) => name === "NANGO_ENCRYPTION_KEY").valueFrom.secretKeyRef, { name: release.nango.storageSecretName, key: "encryption-key" });
  assert.deepEqual(nango.spec.template.spec.containers[0].env.find(({ name }) => name === "RECORDS_DATABASE_URL").valueFrom.secretKeyRef, { name: release.nango.storageSecretName, key: "database-url" });
  assert.deepEqual(nango.spec.template.spec.containers[0].startupProbe.httpGet, { path: "/ready", port: "http", scheme: "HTTP" });
  assert.deepEqual(nango.spec.template.spec.containers[0].readinessProbe.httpGet, { path: "/ready", port: "http", scheme: "HTTP" });
  assert.deepEqual(nango.spec.template.spec.containers[0].livenessProbe.httpGet, { path: "/health", port: "http", scheme: "HTTP" });
  assert.equal(nango.spec.template.spec.containers[0].env.find(({ name }) => name === "NANGO_MIGRATE_AT_START").value, "false");
  const nangoMigration = one(resources, "Job", "nango-migrate");
  assert.equal(nangoMigration.metadata.annotations["helm.sh/hook"], "pre-install,pre-upgrade");
  assert.equal(nangoMigration.metadata.annotations["helm.sh/hook-weight"], "-20");
  assert.equal(nangoMigration.metadata.annotations["helm.sh/hook-delete-policy"], "before-hook-creation,hook-succeeded");
  assert.equal(nangoMigration.spec.backoffLimit, 1);
  assert.equal(nangoMigration.spec.activeDeadlineSeconds, 600);
  assert.equal(nangoMigration.spec.template.spec.serviceAccountName, "nango-migrate");
  assert.equal(nangoMigration.spec.template.spec.automountServiceAccountToken, false);
  assert.equal(nangoMigration.spec.template.spec.containers[0].image, nango.spec.template.spec.containers[0].image);
  assert.deepEqual(nangoMigration.spec.template.spec.containers[0].command, ["/bin/sh", "-ec"]);
  assert.match(nangoMigration.spec.template.spec.containers[0].args[0], /sslmode.*verify-full/);
  assert.match(nangoMigration.spec.template.spec.containers[0].args[0], /exec node packages\/server\/dist\/migrate\.js/);
  assert.equal(nangoMigration.spec.template.spec.containers[0].securityContext.runAsUser, 1000);
  assert.equal(nangoMigration.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem, true);
  assert.equal(nangoMigration.spec.template.spec.containers[0].env.find(({ name }) => name === "RECORDS_DATABASE_SSL").value, "true");
  assert.equal(nangoMigration.spec.template.spec.containers[0].env.some(({ name, value }) => name === "NANGO_MIGRATE_AT_START" && value === "true"), false);
  const migrationAccount = one(resources, "ServiceAccount", "nango-migrate");
  assert.equal(migrationAccount.metadata.annotations["helm.sh/hook"], "pre-install,pre-upgrade");
  assert.equal(migrationAccount.metadata.annotations["helm.sh/hook-weight"], "-22");
  assert.equal(migrationAccount.metadata.annotations["helm.sh/hook-delete-policy"], "before-hook-creation");
  const migrationNetwork = one(resources, "NetworkPolicy", "nango-migrate-private");
  assert.equal(migrationNetwork.metadata.annotations["helm.sh/hook"], "pre-install,pre-upgrade");
  assert.equal(migrationNetwork.metadata.annotations["helm.sh/hook-weight"], "-21");
  assert.equal(migrationNetwork.metadata.annotations["helm.sh/hook-delete-policy"], "before-hook-creation");
  assert.deepEqual(migrationNetwork.spec.podSelector.matchLabels, { "app.kubernetes.io/name": "nango-migrate" });
  assert.equal(one(resources, "Service", "nango").spec.type, "ClusterIP");
  assert.equal(one(resources, "PodDisruptionBudget", "nango").spec.minAvailable, 1);
  const nangoNetwork = one(resources, "NetworkPolicy", "nango-private");
  assert.deepEqual(nangoNetwork.spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock?.cidr).filter(Boolean)).sort(), [...release.nango.databaseEgressCIDRs, ...release.nango.providerEgressCIDRs].sort());
  assert.doesNotMatch(JSON.stringify(nangoNetwork), /0\.0\.0\.0\/0|::\/0/);
  assert.equal(resources.some(({ kind, metadata }) => kind === "Ingress" && /nango/i.test(metadata.name)), false);
  assert.equal(resources.some(({ metadata }) => /(?:runner|persist|orchestrat|functions|webhooks|jobs)/i.test(metadata.name) && /nango/i.test(metadata.name)), false);

  const collector = one(resources, "Deployment", "otel-collector");
  assert.equal(collector.spec.replicas, 2);
  assert.match(collector.spec.template.spec.containers[0].image, /^otel\/opentelemetry-collector-contrib:0\.158\.0@sha256:[a-f0-9]{64}$/);
  assert.equal(collector.spec.template.spec.automountServiceAccountToken, false);
  assert.equal(one(resources, "Service", "otel-collector").spec.type, "ClusterIP");
  assert.deepEqual(one(resources, "Service", "otel-collector").spec.ports.map(({ port }) => port), [4317, 4318, 13133, 8888]);
  assert.equal(one(resources, "PodDisruptionBudget", "otel-collector").spec.minAvailable, 1);
  const config = load(one(resources, "ConfigMap", "otel-collector").data["collector.yaml"]);
  assert.deepEqual(config.processors.memory_limiter, { check_interval: "1s", limit_mib: 384, spike_limit_mib: 64 });
  assert.deepEqual(config.processors.batch, { send_batch_size: 512, send_batch_max_size: 1024, timeout: "5s" });
  assert.deepEqual(config.processors["transform/redact_content"], {
    error_mode: "propagate",
    trace_statements: [
      'set(resource.schema_url, "")',
      'set(resource.attributes["service.namespace"], "agentsec")',
      'set(resource.attributes["service.name"], "unknown") where resource.attributes["service.name"] != "agentsec-api" and resource.attributes["service.name"] != "agentsec-worker"',
      'set(resource.attributes["service.version"], "redacted")',
      'set(resource.attributes["deployment.environment.name"], "unknown") where resource.attributes["deployment.environment.name"] != "development" and resource.attributes["deployment.environment.name"] != "test" and resource.attributes["deployment.environment.name"] != "staging" and resource.attributes["deployment.environment.name"] != "production"',
      'set(scope.name, "redacted")',
      'set(scope.version, "")',
      'set(scope.schema_url, "")',
      'set(scope.attributes, {})',
      'set(span.name, "redacted")',
      'set(span.status.message, "")',
      'set(span.trace_state, "")',
      'set(spanevent.name, "redacted")',
    ],
    metric_statements: [
      'set(resource.schema_url, "")',
      'set(resource.attributes["service.namespace"], "agentsec")',
      'set(resource.attributes["service.name"], "unknown") where resource.attributes["service.name"] != "agentsec-api" and resource.attributes["service.name"] != "agentsec-worker"',
      'set(resource.attributes["service.version"], "redacted")',
      'set(resource.attributes["deployment.environment.name"], "unknown") where resource.attributes["deployment.environment.name"] != "development" and resource.attributes["deployment.environment.name"] != "test" and resource.attributes["deployment.environment.name"] != "staging" and resource.attributes["deployment.environment.name"] != "production"',
      'set(scope.name, "redacted")',
      'set(scope.version, "")',
      'set(scope.schema_url, "")',
      'set(scope.attributes, {})',
      'set(metric.description, "")',
      'set(metric.unit, "")',
      'set(metric.metadata, {})',
      'set(exemplar.filtered_attributes, {})',
    ],
    log_statements: [
      'set(resource.schema_url, "")',
      'set(resource.attributes["service.namespace"], "agentsec")',
      'set(resource.attributes["service.name"], "unknown") where resource.attributes["service.name"] != "agentsec-api" and resource.attributes["service.name"] != "agentsec-worker"',
      'set(resource.attributes["service.version"], "redacted")',
      'set(resource.attributes["deployment.environment.name"], "unknown") where resource.attributes["deployment.environment.name"] != "development" and resource.attributes["deployment.environment.name"] != "test" and resource.attributes["deployment.environment.name"] != "staging" and resource.attributes["deployment.environment.name"] != "production"',
      'set(scope.name, "redacted")',
      'set(scope.version, "")',
      'set(scope.schema_url, "")',
      'set(scope.attributes, {})',
      'set(log.body, "")',
      'set(log.event_name, "redacted")',
      'set(log.severity_text, "")',
    ],
  });
  assert.deepEqual(config.processors["filter/drop_unsafe_trace_links"], { error_mode: "propagate", trace_conditions: ["Len(span.links) > 0"] });
  assert.deepEqual(config.processors["filter/allow_metrics"], {
    error_mode: "propagate",
    metric_conditions: ['metric.name != "agentsec_ready" and metric.name != "agentsec_build_info" and metric.name != "zasp_http_requests_total" and metric.name != "zasp_http_request_duration_seconds" and metric.name != "zasp_http_slo_requests_total" and metric.name != "zasp_http_slo_request_duration_seconds" and metric.name != "zasp_http_rate_limited_total" and metric.name != "zasp_auth_rejections_total" and metric.name != "zasp_dependency_operations_total" and metric.name != "zasp_job_operations_total" and metric.name != "zasp_postgres_pool_connections" and metric.name != "zasp_metrics_render_overflow" and metric.name != "zasp_worker_claimed_total" and metric.name != "zasp_worker_active" and metric.name != "zasp_worker_inflight" and metric.name != "zasp_worker_lease_loss_total" and metric.name != "zasp_worker_retry_total" and metric.name != "zasp_worker_exhaustion_total" and metric.name != "zasp_worker_failure_total" and metric.name != "zasp_worker_driver_ready" and metric.name != "zasp_worker_projection_backlog_age_seconds"'],
  });
  assert.equal(config.processors.redaction.allow_all_keys, false);
  assert.equal(config.processors.redaction.summary, "silent");
  assert.deepEqual(config.service.telemetry.metrics.readers, [{ pull: { exporter: { prometheus: { host: "0.0.0.0", port: 8888 } } } }]);
  assert.deepEqual(Object.keys(config.exporters), ["nop"]);
  assert.deepEqual(config.service.pipelines.traces.processors, ["memory_limiter", "filter/drop_unsafe_trace_links", "transform/redact_content", "redaction", "batch"]);
  assert.deepEqual(config.service.pipelines.metrics.processors, ["memory_limiter", "transform/redact_content", "filter/allow_metrics", "redaction", "batch"]);
  assert.deepEqual(config.service.pipelines.logs.processors, ["memory_limiter", "transform/redact_content", "redaction", "batch"]);
  for (const signal of ["traces", "metrics", "logs"]) assert.deepEqual(config.service.pipelines[signal].exporters, ["nop"]);
  const collectorNetwork = one(resources, "NetworkPolicy", "otel-collector-private");
  assert.equal(collectorNetwork.spec.egress.length, 1);
  assert.deepEqual(collectorNetwork.spec.ingress[0], {
    from: [{ podSelector: { matchLabels: { "app.kubernetes.io/part-of": "zasp" } } }],
    ports: [{ protocol: "TCP", port: 4317 }, { protocol: "TCP", port: 4318 }, { protocol: "TCP", port: 13133 }],
  });
  assert.deepEqual(one(resources, "ServiceMonitor", "otel-collector").spec.endpoints, [{ interval: "30s", path: "/metrics", port: "metrics", scrapeTimeout: "5s" }]);
  assert.equal(resources.some(({ kind, metadata }) => kind === "PrometheusRule" && metadata.name === "otel-collector"), false);
  assert.equal(resources.some(({ kind, metadata }) => kind === "Ingress" && /otel/i.test(metadata.name)), false);
  assert.doesNotMatch(JSON.stringify(collector), /OTEL_EXPORTER_OTLP_(?:ENDPOINT|AUTHORIZATION)/);
});

test("rendered release rejects an unreviewed job identity", async () => {
  const resources = await renderRelease(release);
  const names = resources.filter(({ kind }) => kind === "Job").map(({ metadata }) => metadata.name).sort();
  assert.deepEqual(names, ["agentsec-projection-graph-init-v1", "agentsec-projection-search-init-v1", "agentsec-schema-v16", "nango-migrate", "zasp-canary-secret-sync"]);
  assert.throws(() => validateRenderedRelease([...resources, {
    apiVersion: "batch/v1",
    kind: "Job",
    metadata: { name: "unreviewed-job" },
    spec: { template: { spec: { serviceAccountName: "nango" } } },
  }], "123456789012"), /release rejected/);
});

test("Grafana and New Relic Collector overlays bound remote failure with one exact secret", async () => {
  for (const telemetry of [
    { backend: "grafana", endpoint: "https://otlp-gateway-prod-us-west-0.grafana.net/otlp", authSecretName: "otel-grafana", egressCIDRs: ["192.0.2.16/28"] },
    { backend: "newrelic", endpoint: "https://otlp.nr-data.net", authSecretName: "otel-newrelic", egressCIDRs: ["198.51.100.16/28"] },
  ]) {
    const resources = await renderRelease({ ...release, telemetry });
    const collector = one(resources, "Deployment", "otel-collector");
    const config = load(one(resources, "ConfigMap", "otel-collector").data["collector.yaml"]);
    assert.deepEqual(config.exporters["otlphttp/remote"], {
      endpoint: "${env:OTEL_EXPORTER_OTLP_ENDPOINT}",
      headers: { Authorization: "${env:OTEL_EXPORTER_OTLP_AUTHORIZATION}" },
      timeout: "5s",
      sending_queue: { enabled: true, num_consumers: 2, queue_size: 256, sizer: "requests", wait_for_result: false, block_on_overflow: false },
      retry_on_failure: { enabled: true, initial_interval: "1s", max_interval: "5s", max_elapsed_time: "60s" },
    });
    for (const signal of ["traces", "metrics", "logs"]) assert.deepEqual(config.service.pipelines[signal].exporters, ["otlphttp/remote"]);
    const env = collector.spec.template.spec.containers[0].env;
    assert.equal(env.find(({ name }) => name === "OTEL_EXPORTER_OTLP_ENDPOINT").value, telemetry.endpoint);
    assert.deepEqual(env.find(({ name }) => name === "OTEL_EXPORTER_OTLP_AUTHORIZATION").valueFrom.secretKeyRef, { name: telemetry.authSecretName, key: "authorization" });
    const network = one(resources, "NetworkPolicy", "otel-collector-private");
    assert.deepEqual(network.spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock?.cidr).filter(Boolean)), telemetry.egressCIDRs);
    const queueRule = one(resources, "PrometheusRule", "otel-collector");
    assert.deepEqual(queueRule.spec.groups[0].rules, [
      {
        alert: "ZaspOTelCollectorQueueLoss",
        expr: 'sum(increase({__name__=~"otelcol_exporter_enqueue_failed_(log_records|metric_points|spans)",service="otel-collector",exporter="otlphttp/remote"}[5m])) > 0',
        labels: { severity: "page" },
        annotations: {
          summary: "OpenTelemetry remote queue dropped telemetry",
          runbook_url: "https://zasp.example/runbooks/observability-and-canaries#collector",
        },
      },
      {
        alert: "ZaspOTelCollectorQueueMetricMissing",
        expr: 'absent(otelcol_exporter_queue_capacity{service="otel-collector",exporter="otlphttp/remote"})',
        for: "10m",
        labels: { severity: "page" },
        annotations: {
          summary: "OpenTelemetry remote queue capacity metric disappeared",
          runbook_url: "https://zasp.example/runbooks/observability-and-canaries#collector",
        },
      },
    ]);
    assert.equal(resources.some(({ kind }) => kind === "Secret"), false);
  }
});

test("release renders one TLS origin, split ports, private internals, and migration/schema gates", async () => {
  const resources = await renderRelease(release);
  const ingress = one(resources, "Ingress", "zasp-product");
  assert.equal(ingress.spec.tls[0].secretName, release.tlsSecretName);
  assert.deepEqual(ingress.spec.rules[0].http.paths.map(({ path, backend }) => [path, backend.service.name, backend.service.port.number]), [
    ["/api/v1", "agentsec-api", 8080], ["/", "web", 3000],
  ]);
  const runtimeIngress = one(resources, "Ingress", "zasp-runtime");
  assert.equal(runtimeIngress.spec.tls[0].secretName, release.tlsSecretName);
  assert.equal(runtimeIngress.spec.rules[0].host, release.host);
  assert.equal(runtimeIngress.metadata.annotations["nginx.ingress.kubernetes.io/proxy-body-size"], "64m");
  assert.deepEqual(runtimeIngress.spec.rules[0].http.paths.map(({ path, backend }) => [path, backend.service.name, backend.service.port.number]), [
    ["/internal/v1/runtime-gateway/authority", "agentsec-gateway-control", 8080],
    ["/internal/v1/policy-bundles", "agentsec-gateway-control", 8080],
    ["/internal/v1/runtime/decisions", "agentsec-gateway-control", 8080],
    ["/internal/v1/runtime/events", "agentsec-event-ingest", 8080],
    ["/internal/v1/sensor/heartbeat", "agentsec-event-ingest", 8080],
  ]);
  const annotations = ingress.metadata.annotations;
  for (const value of ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]) {
    assert.match(annotations["nginx.ingress.kubernetes.io/configuration-snippet"], new RegExp(value));
  }
  assert.deepEqual(one(resources, "Service", "agentsec-api").spec.ports.map(({ name, port }) => [name, port]), [["product", 8080], ["internal", 8081]]);
  assert.deepEqual(resources.filter(({ kind }) => kind === "Ingress").map(({ metadata }) => metadata.name).sort(), ["zasp-product", "zasp-runtime"]);
  assert.equal(resources.some(({ kind, metadata }) => kind === "Service" && ["neo4j", "nango", "otel-collector"].includes(metadata.name) && metadata.annotations?.["service.beta.kubernetes.io/aws-load-balancer-type"]), false);
  assert.equal(one(resources, "Job", "agentsec-schema-v16").metadata.annotations["helm.sh/hook"], "pre-install,pre-upgrade");
  assert.match(one(resources, "Job", "agentsec-schema-v16").spec.template.spec.containers[0].args[0], /exec \/app\/agentsec-migrate up/);
  const migration = one(resources, "Job", "agentsec-schema-v16");
  assert.equal(migration.spec.template.spec.serviceAccountName, "agentsec-migration");
  assert.equal(migration.spec.template.spec.containers[0].env.some(({ valueFrom }) => valueFrom?.secretKeyRef), false);
  assert.equal(migration.spec.template.spec.containers[0].volumeMounts[0].mountPath, "/var/run/secrets/zasp-migration");
  assert.deepEqual(Object.fromEntries(migration.spec.template.spec.containers[0].env.map(({ name, value }) => [name, value])), {
    ZASP_MIGRATION_TIMEOUT: "10m",
    ZASP_MIGRATION_DB_PRINCIPAL: "zasp_migration",
    ZASP_DISCOVERY_API_DB_PRINCIPAL: "zasp_api_runtime",
    ZASP_DISCOVERY_WORKER_DB_PRINCIPAL: "zasp_discovery_runtime",
    ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL: "zasp_scheduler_runtime",
    ZASP_PROJECTION_RISK_DB_PRINCIPAL: "zasp_projection_risk_runtime",
    ZASP_PROJECTION_GRAPH_DB_PRINCIPAL: "zasp_projection_graph_runtime",
    ZASP_PROJECTION_SEARCH_DB_PRINCIPAL: "zasp_projection_search_runtime",
    ZASP_RUNTIME_INGEST_DB_PRINCIPAL: "zasp_ingest_runtime",
    ZASP_RUNTIME_WORKER_DB_PRINCIPAL: "zasp_runtime_worker_runtime",
    ZASP_OUTBOX_WORKER_DB_PRINCIPAL: "zasp_outbox_runtime",
    ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL: "zasp_gateway_runtime",
    ZASP_RUNTIME_COORDINATOR_DB_PRINCIPAL: "zasp_runtime_coordinator_runtime",
    ZASP_RUNTIME_ARCHIVE_DB_PRINCIPAL: "zasp_runtime_archive_runtime",
    ZASP_RUNTIME_INDEX_DB_PRINCIPAL: "zasp_runtime_index_runtime",
    ZASP_RUNTIME_CORRELATION_DB_PRINCIPAL: "zasp_runtime_correlation_runtime",
    ZASP_RUNTIME_PROJECTION_DB_PRINCIPAL: "zasp_runtime_projection_runtime",
    ZASP_GATEWAY_CONTROL_DB_PRINCIPAL: "zasp_gateway_control_runtime",
  });
  for (const [kind, name, weight] of [["ServiceAccount", "agentsec-migration", "-30"], ["SecretProviderClass", "zasp-production-migration-secrets", "-20"], ["Job", "agentsec-schema-v16", "-10"]]) {
    const resource = one(resources, kind, name);
    assert.equal(resource.metadata.annotations["helm.sh/hook"], "pre-install,pre-upgrade");
    assert.equal(resource.metadata.annotations["helm.sh/hook-weight"], weight);
  }
  assert.equal(one(resources, "Deployment", "agentsec-api").spec.template.metadata.annotations["zasp.io/schema-version"], "16");
  assert.equal(one(resources, "Deployment", "agentsec-api").spec.template.spec.containers[0].env.find(({ name }) => name === "ZASP_EXPECTED_SCHEMA_VERSION").value, "16");
  assert.equal(one(resources, "Deployment", "agentsec-api").spec.template.spec.containers[0].env.find(({ name }) => name === "ZASP_DATABASE_AUTHORITY").value, "zasp_discovery_api");
  assert.equal(one(resources, "SecretProviderClass", release.secretProviderClass).spec.secretObjects[0].data.length, 7);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-migration-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-worker-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-scheduler-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-canary-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(one(resources, "ServiceAccount", "agentsec-api").metadata.annotations["eks.amazonaws.com/role-arn"], "arn:aws:iam::123456789012:role/zasp-production-api");
  assert.equal(one(resources, "ServiceAccount", "agentsec-migration").metadata.annotations["eks.amazonaws.com/role-arn"], "arn:aws:iam::123456789012:role/zasp-production-migration");
  assert.equal(one(resources, "ServiceAccount", "zasp-discovery-worker").metadata.annotations["eks.amazonaws.com/role-arn"], release.discovery.roleArn);
  assert.equal(one(resources, "ServiceAccount", "zasp-discovery-scheduler").metadata.annotations["eks.amazonaws.com/role-arn"], "arn:aws:iam::123456789012:role/zasp-production-discovery-scheduler");
  const rendered = JSON.stringify(resources);
  assert.match(rendered, /zasp\/production\/postgres-api-dsn/);
  assert.match(rendered, /zasp\/production\/postgres-worker-dsn/);
  assert.match(rendered, /zasp\/production\/postgres-scheduler-dsn/);
  assert.match(rendered, /zasp\/production\/postgres-migration-dsn/);
  assert.doesNotMatch(rendered, /zasp\/production\/postgres-dsn"/);
  for (const name of ["agentsec-web", "agentsec-canary"]) {
    assert.equal(one(resources, "ServiceAccount", name).metadata.annotations?.["eks.amazonaws.com/role-arn"], undefined);
  }
});

test("release applies non-root rollout, zone and host spread, drain, PDB, and default-deny policies", async () => {
  const resources = await renderRelease(release);
  const workloadNames = ["agentsec-api", "agentsec-discovery-scheduler", "agentsec-discovery-worker", "agentsec-event-ingest", "agentsec-gateway-control", "agentsec-outbox-publisher", "agentsec-projection-graph", "agentsec-projection-risk", "agentsec-projection-search", "agentsec-runtime-archive", "agentsec-runtime-complete", "agentsec-runtime-coordinator", "agentsec-runtime-correlation", "agentsec-runtime-index", "agentsec-runtime-outbox", "agentsec-runtime-projection", "nango", "otel-collector", "web"];
  assert.deepEqual(resources.filter(({ kind }) => kind === "Deployment").map(({ metadata }) => metadata.name).sort(), workloadNames);
  assert.deepEqual(resources.filter(({ kind }) => kind === "Service").map(({ metadata }) => metadata.name).sort(), workloadNames);
  for (const name of workloadNames) {
    const deployment = one(resources, "Deployment", name);
    assert.deepEqual(deployment.spec.strategy.rollingUpdate, { maxSurge: 1, maxUnavailable: 0 });
    assert.equal(deployment.spec.template.spec.securityContext.seccompProfile.type, "RuntimeDefault");
    if (name !== "nango") assert.equal(deployment.spec.template.spec.containers[0].securityContext.runAsUser, 65532);
    else assert.equal(deployment.spec.template.spec.containers[0].securityContext.runAsNonRoot, true);
    assert.equal(deployment.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem, true);
    assert.equal(deployment.spec.template.spec.containers[0].lifecycle.preStop.exec.command.at(-1), "sleep 10");
    if (name !== "web" && name !== "nango" && name !== "otel-collector") {
      const shutdown = deployment.spec.template.spec.containers[0].env.find(({ name: key }) => ["ZASP_SHUTDOWN_TIMEOUT", "ZASP_EVENT_INGEST_SHUTDOWN_TIMEOUT", "ZASP_GATEWAY_CONTROL_SHUTDOWN_TIMEOUT"].includes(key));
      assert.equal(shutdown.value, "15s");
      assert.ok(10 + Number.parseInt(shutdown.value, 10) + 5 <= deployment.spec.template.spec.terminationGracePeriodSeconds);
    }
    assert.deepEqual(deployment.spec.template.spec.topologySpreadConstraints.map(({ topologyKey }) => topologyKey), ["topology.kubernetes.io/zone", "kubernetes.io/hostname"]);
    assert.equal(one(resources, "PodDisruptionBudget", name).spec.minAvailable, 1);
  }
  const policies = resources.filter(({ kind }) => kind === "NetworkPolicy");
  assert.ok(policies.some(({ metadata }) => metadata.name === "default-deny"));
  assert.ok(policies.some(({ metadata }) => metadata.name === "web-from-ingress"));
  assert.ok(policies.some(({ metadata }) => metadata.name === "api-from-ingress"));
  assert.ok(policies.some(({ metadata }) => metadata.name === "internal-monitoring"));
  const scheduler = one(resources, "Deployment", "agentsec-discovery-scheduler");
  const schedulerEnv = Object.fromEntries(scheduler.spec.template.spec.containers[0].env.map(({ name, value }) => [name, value]));
  assert.equal(schedulerEnv.ZASP_WORKER_MODE, "scheduler");
  assert.equal(schedulerEnv.ZASP_DATABASE_AUTHORITY, "zasp_discovery_scheduler");
  assert.equal(schedulerEnv.ZASP_DISCOVERY_PARSER_VERSION, release.discovery.parserVersion);
  assert.equal(schedulerEnv.ZASP_DISCOVERY_TOOL_VERSION, release.discovery.toolVersion);
  assert.equal(scheduler.spec.template.spec.containers[0].env.find(({ name }) => name === "ZASP_WORKER_ID").valueFrom.fieldRef.fieldPath, "metadata.name");
  assert.doesNotMatch(JSON.stringify(scheduler), /ZASP_DISCOVERY_QUEUE_URL|ZASP_OPENSEARCH_ENDPOINT|ZASP_NEO4J_URI|ZASP_CONNECTOR_/);
  const search = one(resources, "Deployment", "agentsec-projection-search");
  const searchEnv = Object.fromEntries(search.spec.template.spec.containers[0].env.map(({ name, value }) => [name, value]));
  assert.deepEqual(Object.fromEntries(Object.entries(searchEnv).filter(([name]) => name !== "ZASP_WORKER_ID")), {
    ZASP_WORKER_MODE: "projection-search", ZASP_DATABASE_AUTHORITY: "zasp_projection_search_worker", ZASP_POLL_INTERVAL: "1s", ZASP_LEASE_DURATION: "30s", ZASP_BATCH_SIZE: "8", ZASP_SHUTDOWN_TIMEOUT: "15s",
    ZASP_AWS_REGION: release.projectionSearch.awsRegion, ZASP_PROJECTION_ROLE_ARN: release.projectionSearch.roleArn, ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE: release.projectionSearch.webIdentityTokenFile,
    ZASP_OPENSEARCH_ENDPOINT: release.projectionSearch.endpoint, ZASP_OPENSEARCH_INDEX: release.projectionSearch.index,
  });
  assert.equal(search.spec.template.spec.serviceAccountName, "zasp-projection-search");
  assert.equal(one(resources, "ServiceAccount", "zasp-projection-search").metadata.annotations["eks.amazonaws.com/role-arn"], release.projectionSearch.roleArn);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-projection-search-secrets").spec.secretObjects[0].data.length, 1);
  assert.doesNotMatch(JSON.stringify(search), /ZASP_NEO4J|ZASP_CONNECTOR_|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/);
  assert.equal(resources.some(({ kind, metadata }) => kind === "Deployment" && metadata?.name === "runtime-gateway"), false);
  assert.deepEqual(one(resources, "Service", "otel-collector").spec.ports.map(({ port }) => port), [4317, 4318, 13133, 8888]);
});

test("release ships the complete v15 runtime data plane behind exact workload authorities", async () => {
  const resources = await renderRelease(release);
  const expected = [
    ["agentsec-event-ingest", "eventIngest", "zasp-runtime-ingest", release.runtime.eventIngestRoleArn],
    ["agentsec-gateway-control", "gatewayControl", "zasp-gateway-control", release.runtime.gatewayControlRoleArn],
    ["agentsec-runtime-outbox", "agentsecWorker", "zasp-runtime-outbox", release.runtime.outboxRoleArn],
    ["agentsec-runtime-coordinator", "agentsecWorker", "zasp-runtime-coordinator", release.runtime.coordinatorRoleArn],
    ["agentsec-runtime-archive", "agentsecWorker", "zasp-runtime-archive", release.runtime.archiveRoleArn],
    ["agentsec-runtime-index", "agentsecWorker", "zasp-runtime-index", release.runtime.indexRoleArn],
    ["agentsec-runtime-correlation", "agentsecWorker", "zasp-runtime-correlation", release.runtime.correlationRoleArn],
    ["agentsec-runtime-projection", "agentsecWorker", "zasp-runtime-projection", release.runtime.projectionRoleArn],
    ["agentsec-runtime-complete", "agentsecWorker", "zasp-runtime-complete", release.runtime.completeRoleArn],
  ];
  for (const [name, imageKey, serviceAccount, roleArn] of expected) {
    const deployment = one(resources, "Deployment", name);
    const pod = deployment.spec.template.spec;
    assert.equal(pod.serviceAccountName, serviceAccount);
    assert.equal(pod.containers[0].image, release.images[imageKey]);
    assert.equal(one(resources, "ServiceAccount", serviceAccount).metadata.annotations?.["eks.amazonaws.com/role-arn"], roleArn);
    assert.equal(pod.automountServiceAccountToken, false);
    assert.equal(pod.containers[0].securityContext.readOnlyRootFilesystem, true);
  }
  const modes = new Map([
    ["agentsec-runtime-outbox", ["runtime-outbox", "zasp_outbox_worker"]],
    ["agentsec-runtime-coordinator", ["runtime-coordinator", "zasp_runtime_coordinator"]],
    ["agentsec-runtime-archive", ["runtime-archive", "zasp_runtime_archive_worker"]],
    ["agentsec-runtime-index", ["runtime-index", "zasp_runtime_index_worker"]],
    ["agentsec-runtime-correlation", ["runtime-correlation", "zasp_runtime_correlation_worker"]],
    ["agentsec-runtime-projection", ["runtime-projection", "zasp_runtime_projection_worker"]],
    ["agentsec-runtime-complete", ["runtime-complete", "zasp_runtime_coordinator"]],
  ]);
  for (const [name, [mode, authority]] of modes) {
    const env = envOf(one(resources, "Deployment", name));
    assert.equal(env.ZASP_WORKER_MODE, mode);
    assert.equal(env.ZASP_DATABASE_AUTHORITY, authority);
    assert.equal(env.AWS_ACCESS_KEY_ID, undefined);
    assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
    assert.equal(env.AWS_SESSION_TOKEN, undefined);
  }
  assert.deepEqual(envOf(one(resources, "Deployment", "agentsec-gateway-control")), {
    ZASP_GATEWAY_CONTROL_MAX_BODY_BYTES: "65536", ZASP_GATEWAY_CONTROL_OPERATION_TIMEOUT: "5s",
    ZASP_GATEWAY_CONTROL_READINESS_TTL: "30s", ZASP_GATEWAY_CONTROL_SHUTDOWN_TIMEOUT: "15s",
  });
  assert.deepEqual(envOf(one(resources, "Deployment", "agentsec-event-ingest")), {
    ZASP_AWS_REGION: release.runtime.awsRegion, ZASP_EVENT_INGEST_ROLE_ARN: release.runtime.eventIngestRoleArn,
    ZASP_EVENT_INGEST_WEB_IDENTITY_TOKEN_FILE: release.runtime.webIdentityTokenFile,
    ZASP_RUNTIME_RAW_BUCKET: release.runtime.rawBucket, ZASP_RUNTIME_RAW_BUCKET_OWNER: release.runtime.rawBucketOwner,
    ZASP_RUNTIME_RAW_KMS_KEY_ARN: release.runtime.rawKMSKeyArn, ZASP_EVENT_INGEST_MAX_BYTES: "67108864",
    ZASP_EVENT_INGEST_OPERATION_TIMEOUT: "10s", ZASP_EVENT_INGEST_SHUTDOWN_TIMEOUT: "15s",
  });
});

test("release gives the runtime data plane bounded ingress and dependency egress", async () => {
  const resources = await renderRelease(release);
  for (const [policyName, workload] of [["event-ingest-from-ingress", "agentsec-event-ingest"], ["gateway-control-from-ingress", "agentsec-gateway-control"]]) {
    const policy = one(resources, "NetworkPolicy", policyName);
    assert.deepEqual(policy.spec.podSelector.matchLabels, { "app.kubernetes.io/name": workload });
    assert.deepEqual(policy.spec.ingress[0].ports, [{ protocol: "TCP", port: 8080 }]);
  }
  const gateway = one(resources, "NetworkPolicy", "gateway-control-database");
  assert.deepEqual(gateway.spec.egress, [{ to: [{ ipBlock: { cidr: "10.30.0.0/24" } }], ports: [{ protocol: "TCP", port: 5432 }] }]);
  const monitoring = one(resources, "NetworkPolicy", "task6-runtime-monitoring");
  assert.deepEqual(monitoring.spec.podSelector.matchExpressions[0].values.sort(), ["agentsec-event-ingest", "agentsec-gateway-control", "agentsec-runtime-archive", "agentsec-runtime-complete", "agentsec-runtime-coordinator", "agentsec-runtime-correlation", "agentsec-runtime-index", "agentsec-runtime-outbox", "agentsec-runtime-projection"].sort());
  assert.deepEqual(monitoring.spec.ingress[0].ports, [{ protocol: "TCP", port: 8081 }]);
  for (const name of ["event-ingest-dependencies", "runtime-outbox-dependencies", "runtime-coordinator-dependencies", "runtime-stage-dependencies", "runtime-index-dependencies"]) {
    const policy = one(resources, "NetworkPolicy", name);
    const rendered = JSON.stringify(policy);
    assert.doesNotMatch(rendered, /0\.0\.0\.0\/0|::\/0/);
    const cidrs = policy.spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock.cidr));
    assert.ok(cidrs.includes("10.30.0.0/24"));
    for (const cidr of release.runtime.egressCIDRs) assert.ok(cidrs.includes(cidr));
    assert.equal(cidrs.includes("10.50.0.0/24"), name === "runtime-index-dependencies");
  }
});

test("release monitors, scales, and independently alerts every runtime workload", async () => {
  const resources = await renderRelease(release);
  const workloads = ["agentsec-event-ingest", "agentsec-gateway-control", "agentsec-runtime-outbox", "agentsec-runtime-coordinator", "agentsec-runtime-archive", "agentsec-runtime-index", "agentsec-runtime-correlation", "agentsec-runtime-projection", "agentsec-runtime-complete"];
  const rules = one(resources, "PrometheusRule", "zasp-production-slos").spec.groups.flatMap(({ rules: groupRules }) => groupRules);
  for (const name of workloads) {
    const hpa = one(resources, "HorizontalPodAutoscaler", name);
    assert.equal(hpa.spec.scaleTargetRef.name, name);
    assert.equal(hpa.spec.minReplicas, 2);
    assert.equal(hpa.spec.maxReplicas, 10);
    assert.deepEqual(one(resources, "ServiceMonitor", name).spec.endpoints, [{ interval: "30s", path: "/metrics", port: "internal", scrapeTimeout: "5s" }]);
    const alert = rules.find(({ labels, expr }) => labels?.workload === name && expr.includes(`deployment="${name}"`));
    assert.ok(alert, `${name} availability alert`);
    assert.match(alert.expr, /absent\(/);
  }
  const readiness = rules.find(({ alert }) => alert === "ZaspTask6RuntimeDependencyNotReady");
  assert.ok(readiness.expr.includes('service=~"agentsec-(event-ingest|gateway-control|runtime-'));
});

test("release mounts distinct risk and graph projections behind exact DB, Neo4j, and schema authorities", async () => {
  const resources = await renderRelease(release);
  const risk = one(resources, "Deployment", "agentsec-projection-risk");
  const riskEnv = Object.fromEntries(risk.spec.template.spec.containers[0].env.map(({ name, value }) => [name, value]));
  assert.deepEqual(Object.fromEntries(Object.entries(riskEnv).filter(([name]) => name !== "ZASP_WORKER_ID")), {
    ZASP_WORKER_MODE: "projection-risk", ZASP_DATABASE_AUTHORITY: "zasp_projection_risk_worker", ZASP_POLL_INTERVAL: "1s", ZASP_LEASE_DURATION: "30s", ZASP_BATCH_SIZE: "8", ZASP_SHUTDOWN_TIMEOUT: "15s",
  });
  assert.equal(risk.spec.template.spec.serviceAccountName, "zasp-projection-risk");
  assert.doesNotMatch(JSON.stringify(risk), /ZASP_AWS_REGION|ZASP_PROJECTION_ROLE_ARN|ZASP_OPENSEARCH|ZASP_NEO4J|web-identity/);

  const graph = one(resources, "Deployment", "agentsec-projection-graph");
  const graphPod = graph.spec.template.spec;
  const graphEnv = Object.fromEntries(graphPod.containers[0].env.map(({ name, value }) => [name, value]));
  assert.deepEqual(Object.fromEntries(Object.entries(graphEnv).filter(([name]) => name !== "ZASP_WORKER_ID")), {
    ZASP_WORKER_MODE: "projection-graph", ZASP_DATABASE_AUTHORITY: "zasp_projection_graph_worker", ZASP_POLL_INTERVAL: "1s", ZASP_LEASE_DURATION: "30s", ZASP_BATCH_SIZE: "8", ZASP_SHUTDOWN_TIMEOUT: "15s",
    ZASP_AWS_REGION: release.projectionGraph.awsRegion, ZASP_PROJECTION_ROLE_ARN: release.projectionGraph.roleArn, ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE: release.projectionGraph.webIdentityTokenFile,
    ZASP_PROJECTION_SECRET_PREFIX: release.projectionGraph.secretPrefix, ZASP_NEO4J_URI: release.projectionGraph.endpoint, ZASP_NEO4J_CREDENTIAL_REFERENCE: release.projectionGraph.credentialReference,
    ZASP_NEO4J_EXPECTED_PRINCIPAL: release.projectionGraph.expectedPrincipal, ZASP_NEO4J_EXPECTED_ROLE: release.projectionGraph.expectedRole,
  });
  assert.equal(graphPod.serviceAccountName, "zasp-projection-graph");
  assert.equal(one(resources, "ServiceAccount", "zasp-projection-risk").metadata.annotations["eks.amazonaws.com/role-arn"], release.projectionRisk.roleArn);
  assert.equal(one(resources, "ServiceAccount", "zasp-projection-graph").metadata.annotations["eks.amazonaws.com/role-arn"], release.projectionGraph.roleArn);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-projection-risk-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-projection-graph-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(resources.some(({ kind, metadata }) => kind === "Job" && metadata.name === "agentsec-neo4j-schema-v1"), false);
  const graphInit = one(resources, "Job", "agentsec-projection-graph-init-v1");
  const searchInit = one(resources, "Job", "agentsec-projection-search-init-v1");
  for (const init of [graphInit, searchInit]) {
    assert.equal(init.metadata.annotations["helm.sh/hook"], "pre-install,pre-upgrade");
    assert.equal(init.metadata.annotations["helm.sh/hook-weight"], "-7");
    assert.equal(init.spec.backoffLimit, 0);
    assert.equal(init.spec.activeDeadlineSeconds, 60);
    assert.equal(init.spec.template.spec.containers[0].image, release.images.agentsecWorker);
    assert.deepEqual(init.spec.template.spec.containers[0].volumeMounts, [{ name: "projection-init-web-identity", mountPath: "/var/run/secrets/eks.amazonaws.com/serviceaccount", readOnly: true }]);
  }
  assert.deepEqual(envOf(graphInit), {
    ZASP_WORKER_MODE: "projection-graph-init", ZASP_AWS_REGION: release.projectionGraph.awsRegion, ZASP_PROJECTION_INIT_ROLE_ARN: release.projectionGraph.initRoleArn,
    ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE: release.projectionGraph.webIdentityTokenFile, ZASP_PROJECTION_INIT_TIMEOUT: "20s",
    ZASP_PROJECTION_SECRET_PREFIX: release.projectionGraph.secretPrefix, ZASP_NEO4J_URI: release.projectionGraph.endpoint, ZASP_NEO4J_SCHEMA_CREDENTIAL_REFERENCE: release.projectionGraph.schemaCredentialReference,
  });
  assert.deepEqual(envOf(searchInit), {
    ZASP_WORKER_MODE: "projection-search-init", ZASP_AWS_REGION: release.projectionSearch.awsRegion, ZASP_PROJECTION_INIT_ROLE_ARN: release.projectionSearch.initRoleArn,
    ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE: release.projectionSearch.webIdentityTokenFile, ZASP_PROJECTION_INIT_TIMEOUT: "20s",
    ZASP_OPENSEARCH_ENDPOINT: release.projectionSearch.endpoint, ZASP_OPENSEARCH_INDEX: release.projectionSearch.index,
  });
  assert.equal(graphInit.spec.template.spec.serviceAccountName, "agentsec-projection-graph-init");
  assert.equal(searchInit.spec.template.spec.serviceAccountName, "agentsec-projection-search-init");
  assert.notEqual(one(resources, "ServiceAccount", "agentsec-projection-graph-init").metadata.annotations["eks.amazonaws.com/role-arn"], release.projectionGraph.roleArn);
  assert.notEqual(one(resources, "ServiceAccount", "agentsec-projection-search-init").metadata.annotations["eks.amazonaws.com/role-arn"], release.projectionSearch.roleArn);
  for (const name of ["agentsec-projection-risk", "agentsec-projection-graph", "agentsec-projection-search"]) {
    assert.equal(one(resources, "HorizontalPodAutoscaler", name).spec.maxReplicas, 10);
    assert.equal(one(resources, "ServiceMonitor", name).spec.endpoints[0].path, "/metrics");
  }
});

test("release isolates the discovery outbox publisher behind exact DB, queue, and web-identity authority", async () => {
  const resources = await renderRelease(release);
  const deployment = one(resources, "Deployment", "agentsec-outbox-publisher");
  const pod = deployment.spec.template.spec;
  const container = pod.containers[0];
  const env = Object.fromEntries(container.env.map(({ name, value }) => [name, value]));
  assert.deepEqual(Object.fromEntries(Object.entries(env).filter(([name]) => name !== "ZASP_WORKER_ID")), {
    ZASP_WORKER_MODE: "outbox", ZASP_DATABASE_AUTHORITY: "zasp_outbox_worker", ZASP_POLL_INTERVAL: "1s", ZASP_LEASE_DURATION: "30s", ZASP_BATCH_SIZE: "10", ZASP_SHUTDOWN_TIMEOUT: "15s",
    ZASP_DISCOVERY_QUEUE_URL: release.outbox.queueURL, ZASP_AWS_REGION: release.outbox.awsRegion, ZASP_OUTBOX_ROLE_ARN: release.outbox.roleArn, ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE: release.outbox.webIdentityTokenFile,
  });
  assert.equal(pod.serviceAccountName, "zasp-outbox-publisher");
  assert.equal(one(resources, "ServiceAccount", "zasp-outbox-publisher").metadata.annotations["eks.amazonaws.com/role-arn"], release.outbox.roleArn);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-outbox-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(container.env.find(({ name }) => name === "ZASP_WORKER_ID").valueFrom.fieldRef.fieldPath, "metadata.name");
  assert.equal(pod.automountServiceAccountToken, false);
  assert.deepEqual(container.volumeMounts.find(({ name }) => name === "outbox-web-identity"), { name: "outbox-web-identity", mountPath: "/var/run/secrets/eks.amazonaws.com/serviceaccount", readOnly: true });
  assert.deepEqual(one(resources, "NetworkPolicy", "outbox-dependencies").spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock.cidr)).sort(), ["10.30.0.0/24", ...release.outbox.egressCIDRs].sort());
  assert.doesNotMatch(JSON.stringify(deployment), /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|ZASP_PROJECTION_|ZASP_CONNECTOR_/);
  assert.equal(one(resources, "HorizontalPodAutoscaler", "agentsec-outbox-publisher").spec.maxReplicas, 6);
  assert.equal(one(resources, "HorizontalPodAutoscaler", "agentsec-discovery-scheduler").spec.maxReplicas, 6);
  assert.equal(one(resources, "ServiceMonitor", "agentsec-outbox-publisher").spec.endpoints[0].path, "/metrics");
  assert.equal(one(resources, "ServiceMonitor", "agentsec-discovery-scheduler").spec.endpoints[0].path, "/metrics");
});

test("release mounts one readiness-gated discovery worker with exact provider and artifact authority", async () => {
  const resources = await renderRelease(release);
  const deployment = one(resources, "Deployment", "agentsec-discovery-worker");
  const pod = deployment.spec.template.spec;
  const container = pod.containers[0];
  const env = Object.fromEntries(container.env.map(({ name, value }) => [name, value]));
  assert.deepEqual(Object.fromEntries(Object.entries(env).filter(([name]) => name !== "ZASP_WORKER_ID")), {
    ZASP_WORKER_MODE: "discovery", ZASP_DATABASE_AUTHORITY: "zasp_discovery_worker", ZASP_POLL_INTERVAL: "1s", ZASP_LEASE_DURATION: "30s", ZASP_BATCH_SIZE: "8", ZASP_SHUTDOWN_TIMEOUT: "15s",
    ZASP_DISCOVERY_QUEUE_URL: release.discovery.queueURL, ZASP_AWS_REGION: release.discovery.awsRegion,
    ZASP_EVIDENCE_BUCKET: release.discovery.evidenceBucket, ZASP_EVIDENCE_BUCKET_OWNER: release.discovery.evidenceBucketOwner, ZASP_EVIDENCE_KMS_KEY_ARN: release.discovery.evidenceKMSKeyArn,
    ZASP_DISCOVERY_ROLE_ARN: release.discovery.roleArn, ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE: release.discovery.webIdentityTokenFile, ZASP_DISCOVERY_SECRET_PREFIX: release.discovery.secretPrefix,
    ZASP_DISCOVERY_AWS_COLLECTOR_VERSION: release.discovery.awsCollectorVersion, ZASP_DISCOVERY_KUBERNETES_COLLECTOR_VERSION: release.discovery.kubernetesCollectorVersion,
    ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION: release.discovery.githubCollectorVersion, ZASP_DISCOVERY_OKTA_COLLECTOR_VERSION: release.discovery.oktaCollectorVersion,
    ZASP_DISCOVERY_PARSER_VERSION: release.discovery.parserVersion, ZASP_DISCOVERY_TOOL_VERSION: release.discovery.toolVersion,
    ZASP_KUBERNETES_EGRESS_CIDRS: release.connectorEgressCIDRs.kubernetes.join(","),
    ZASP_GITHUB_APP_ID: release.discovery.githubAppID, ZASP_GITHUB_PRIVATE_KEY_REFERENCE: release.discovery.githubPrivateKeyReference,
    ZASP_OKTA_CLIENT_ID: release.discovery.oktaClientID, ZASP_OKTA_CLIENT_SECRET_REFERENCE: release.discovery.oktaClientSecretReference,
    ZASP_PROVIDER_TIMEOUT: release.discovery.providerTimeout, ZASP_DISCOVERY_READINESS_TIMEOUT: release.discovery.readinessTimeout,
  });
  assert.equal(pod.serviceAccountName, "zasp-discovery-worker");
  assert.equal(pod.automountServiceAccountToken, false);
  assert.equal(container.env.find(({ name }) => name === "ZASP_WORKER_ID").valueFrom.fieldRef.fieldPath, "metadata.name");
  assert.deepEqual(container.volumeMounts.find(({ name }) => name === "discovery-web-identity"), { name: "discovery-web-identity", mountPath: "/var/run/secrets/eks.amazonaws.com/serviceaccount", readOnly: true });
  assert.deepEqual(pod.volumes.find(({ name }) => name === "discovery-web-identity").projected.sources, [{ serviceAccountToken: { audience: "sts.amazonaws.com", expirationSeconds: 900, path: "token" } }]);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-worker-secrets").spec.secretObjects[0].data.length, 1);
  assert.deepEqual(one(resources, "NetworkPolicy", "discovery-worker-dependencies").spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock.cidr)).sort(), ["10.30.0.0/24", ...Object.values(release.connectorEgressCIDRs).flat()].sort());
  const hpa = one(resources, "HorizontalPodAutoscaler", "agentsec-discovery-worker");
  assert.equal(hpa.spec.minReplicas, 2);
  assert.equal(hpa.spec.maxReplicas, 10);
  assert.equal(hpa.spec.scaleTargetRef.name, "agentsec-discovery-worker");
  assert.doesNotMatch(JSON.stringify(deployment), /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|ZASP_CONNECTOR_|ZASP_OUTBOX_|ZASP_PROJECTION_/);
});

test("release gives only API an explicit connector identity, reference-only config, and bounded provider egress", async () => {
  const resources = await renderRelease(release);
  const api = one(resources, "Deployment", "agentsec-api");
  const pod = api.spec.template.spec;
  const container = pod.containers[0];
  const env = Object.fromEntries(container.env.map(({ name, value }) => [name, value]));
  assert.deepEqual(Object.fromEntries(Object.entries(env).filter(([name]) => name.startsWith("ZASP_CONNECTOR_") || name.startsWith("ZASP_GITHUB_") || name.startsWith("ZASP_OKTA_") || name === "ZASP_AWS_CUSTOMER_ROLE_PREFIXES" || name === "ZASP_AWS_CUSTOMER_ROLE_ARNS" || name === "ZASP_KUBERNETES_EGRESS_CIDRS")), {
    ZASP_CONNECTOR_AWS_REGION: release.connectors.awsRegion,
    ZASP_CONNECTOR_ROLE_ARN: release.connectors.roleArn,
    ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE: release.connectors.webIdentityTokenFile,
    ZASP_CONNECTOR_KMS_KEY_ARN: release.connectors.kmsKeyArn,
    ZASP_CONNECTOR_SECRET_PREFIX: release.connectors.secretPrefix,
    ZASP_AWS_CUSTOMER_ROLE_PREFIXES: JSON.stringify(release.connectors.awsCustomerRolePrefixes),
    ZASP_AWS_CUSTOMER_ROLE_ARNS: JSON.stringify(release.connectors.awsCustomerRoleARNs),
    ZASP_KUBERNETES_EGRESS_CIDRS: release.connectorEgressCIDRs.kubernetes.join(","),
    ZASP_GITHUB_CLIENT_ID: release.connectors.githubClientID,
    ZASP_GITHUB_CLIENT_SECRET_REFERENCE: release.connectors.githubClientSecretReference,
    ZASP_GITHUB_APP_ID: release.connectors.githubAppID,
    ZASP_GITHUB_PRIVATE_KEY_REFERENCE: release.connectors.githubPrivateKeyReference,
    ZASP_OKTA_CLIENT_ID: release.connectors.oktaClientID,
    ZASP_OKTA_CLIENT_SECRET_REFERENCE: release.connectors.oktaClientSecretReference,
  });
  for (const ambient of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_REGION"]) assert.equal(Object.hasOwn(env, ambient), false, ambient);
  assert.equal(pod.automountServiceAccountToken, false);
  assert.deepEqual(container.volumeMounts.find(({ name }) => name === "connector-web-identity"), {
    name: "connector-web-identity",
    mountPath: "/var/run/secrets/eks.amazonaws.com/serviceaccount",
    readOnly: true,
  });
  assert.deepEqual(pod.volumes.find(({ name }) => name === "connector-web-identity"), {
    name: "connector-web-identity",
    projected: {
      defaultMode: 256,
      sources: [{ serviceAccountToken: { audience: "sts.amazonaws.com", expirationSeconds: 900, path: "token" } }],
    },
  });
  for (const account of resources.filter(({ kind }) => kind === "ServiceAccount")) {
    assert.doesNotMatch(JSON.stringify(account.metadata.annotations ?? {}), new RegExp(release.connectors.roleArn.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), account.metadata.name);
  }
  for (const workload of resources.filter(({ kind }) => ["Deployment", "Job", "CronJob"].includes(kind))) {
    if (workload.metadata.name === "agentsec-api") continue;
    assert.doesNotMatch(JSON.stringify(workload), /connector-web-identity|ZASP_CONNECTOR_/, workload.metadata.name);
    if (workload.metadata.name !== "agentsec-discovery-worker") assert.doesNotMatch(JSON.stringify(workload), /ZASP_GITHUB_|ZASP_OKTA_/, workload.metadata.name);
  }

  const connectorEgress = one(resources, "NetworkPolicy", "api-connector-egress");
  assert.deepEqual(connectorEgress.spec.podSelector.matchLabels, { "app.kubernetes.io/name": "agentsec-api" });
  assert.equal(connectorEgress.metadata.annotations["zasp.io/network-policy-boundary"], "native-cidr-snapshot");
  assert.deepEqual(connectorEgress.spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock.cidr)).sort(), [
    ...release.connectorEgressCIDRs.aws,
    ...release.connectorEgressCIDRs.github,
    ...release.connectorEgressCIDRs.okta,
    ...release.connectorEgressCIDRs.kubernetes,
		...release.findingTicketEgressCIDRs,
  ].sort());
  assert.ok(connectorEgress.spec.egress.every(({ ports }) => JSON.stringify(ports) === JSON.stringify([{ protocol: "TCP", port: 443 }])));
  assert.doesNotMatch(JSON.stringify(connectorEgress), /0\.0\.0\.0\/0|::\/0/);

  const rendered = JSON.stringify(resources);
  for (const workload of resources.filter(({ kind, metadata }) => ["Deployment", "Job", "CronJob"].includes(kind) && !["nango", "nango-migrate"].includes(metadata.name))) assert.doesNotMatch(JSON.stringify(workload), /NANGO_/);
  assert.equal(resources.filter(({ kind }) => kind === "Deployment").some(({ metadata }) => /nango-(?:runner|persist|orchestrat|functions|webhooks|jobs)/i.test(metadata.name)), false);
  assert.doesNotMatch(rendered, /github-client-secret-value|okta-client-secret-value/);
  assert.equal(one(resources, "SecretProviderClass", release.secretProviderClass).spec.secretObjects[0].data.length, 7);
});

test("release gives finding tickets exact API-only webhook egress and secret-read authority", async () => {
	const findingTicketEgressCIDRs = ["192.0.2.64/28"];
	const resources = await renderRelease({ ...release, findingTicketEgressCIDRs });
	const api = one(resources, "Deployment", "agentsec-api");
	const env = envOf(api);
	assert.equal(env.ZASP_FINDING_TICKET_EGRESS_CIDRS, findingTicketEgressCIDRs.join(","));
	const egress = one(resources, "NetworkPolicy", "api-connector-egress");
	assert.deepEqual(egress.spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock.cidr)).sort(), [
		...Object.values(release.connectorEgressCIDRs).flat(),
		...findingTicketEgressCIDRs,
	].sort());
	for (const workload of resources.filter(({ kind, metadata }) => ["Deployment", "Job", "CronJob"].includes(kind) && metadata.name !== "agentsec-api")) {
		assert.doesNotMatch(JSON.stringify(workload), /ZASP_FINDING_TICKET_EGRESS_CIDRS/);
	}
	const terraform = await readFile(new URL("../staging/main.tf", import.meta.url), "utf8");
	assert.match(terraform, /secret:\$\{local\.connector_secret_root\}\/webhook\/\*/);
	assert.match(terraform, /kms:EncryptionContext:SecretARN[\s\S]*connector_secret_root[\s\S]*webhook\/\*/);
});

test("release renders read-only synthetic and exact SLO budgets without credential values", async () => {
  const resources = await renderRelease(release);
  const canary = one(resources, "CronJob", "production-readonly-canary");
  assert.equal(canary.spec.concurrencyPolicy, "Forbid");
  assert.equal(canary.spec.jobTemplate.spec.activeDeadlineSeconds, 60);
  const container = canary.spec.jobTemplate.spec.template.spec.containers[0];
  assert.equal(canary.spec.jobTemplate.spec.template.spec.serviceAccountName, "agentsec-canary");
  assert.match(container.args[0], /\/sign-in/);
  assert.match(container.args[0], /\/api\/v1\/home\/summary/);
  assert.deepEqual(container.env[1].valueFrom.secretKeyRef, { name: "zasp-canary-secrets", key: "ZASP_CANARY_READ_TOKEN" });
  assert.doesNotMatch(JSON.stringify(canary), /Bearer [A-Za-z0-9_-]{16}/);
  const monitor = one(resources, "ServiceMonitor", "agentsec-api");
  assert.deepEqual(monitor.spec.endpoints, [{ interval: "30s", path: "/metrics", port: "internal", scrapeTimeout: "5s" }]);
  const rules = one(resources, "PrometheusRule", "zasp-production-slos");
  const rendered = JSON.stringify(rules);
  for (const budget of ["0.01", "0.5", "ZaspAPIErrorBudgetBurn", "ZaspAPIReadLatencyBudget", "ZaspAPIMutationLatencyBudget", "ZaspWebUnavailable", "ZaspAPIUnavailable", "ZaspDiscoveryWorkerUnavailable"]) assert.match(rendered, new RegExp(budget));
  const discoveryMonitor = one(resources, "ServiceMonitor", "agentsec-discovery-worker");
  assert.deepEqual(discoveryMonitor.spec.endpoints, [{ interval: "30s", path: "/metrics", port: "internal", scrapeTimeout: "5s" }]);
  assert.match(rendered, /zasp_http_slo_request_duration_seconds_bucket/);
  assert.doesNotMatch(rendered, /http_server_request_duration_seconds_bucket/);
  const errorBudget = rules.spec.groups.flatMap(({ rules: groupRules }) => groupRules).find(({ alert }) => alert === "ZaspAPIErrorBudgetBurn");
  assert.match(errorBudget.expr, /zasp_http_slo_requests_total/);
  assert.doesNotMatch(errorBudget.expr, /clamp_min/);
  assert.match(errorBudget.expr, /sum\(rate\(zasp_http_slo_requests_total\[5m\]\)\) > 0/);
  for (const [alert, workload] of [
    ["ZaspWebUnavailable", "web"],
    ["ZaspAPIUnavailable", "agentsec-api"],
    ["ZaspDiscoverySchedulerUnavailable", "agentsec-discovery-scheduler"],
    ["ZaspDiscoveryWorkerUnavailable", "agentsec-discovery-worker"],
    ["ZaspOutboxPublisherUnavailable", "agentsec-outbox-publisher"],
    ["ZaspProjectionRiskUnavailable", "agentsec-projection-risk"],
    ["ZaspProjectionGraphUnavailable", "agentsec-projection-graph"],
    ["ZaspProjectionSearchUnavailable", "agentsec-projection-search"],
  ]) {
    const availability = rules.spec.groups.flatMap(({ rules: groupRules }) => groupRules).find((rule) => rule.alert === alert);
    assert.match(availability.expr, new RegExp(`deployment="${workload}"`));
    assert.match(availability.expr, /absent\(/);
  }
  for (const [alert, metric] of [
    ["ZaspTask4WorkerDependencyNotReady", 'agentsec_ready{namespace="agentsec",service=~"agentsec-(discovery-(scheduler|worker)|outbox-publisher|projection-(risk|graph|search))"} == 0'],
    ["ZaspProjectionBacklogAge", "zasp_worker_projection_backlog_age_seconds"],
    ["ZaspWorkerLeaseLoss", "zasp_worker_lease_loss_total"],
    ["ZaspWorkerExhaustion", "zasp_worker_exhaustion_total"],
  ]) {
    const rule = rules.spec.groups.flatMap(({ rules: groupRules }) => groupRules).find((candidate) => candidate.alert === alert);
    assert.ok(rule.expr.includes(metric));
  }
  for (const [alert, service] of [
    ["ZaspProjectionRiskDriverNotReady", "agentsec-projection-risk"],
    ["ZaspProjectionGraphDriverNotReady", "agentsec-projection-graph"],
    ["ZaspProjectionSearchDriverNotReady", "agentsec-projection-search"],
  ]) {
    const rule = rules.spec.groups.flatMap(({ rules: groupRules }) => groupRules).find((candidate) => candidate.alert === alert);
    assert.equal(rule.expr, `zasp_worker_driver_ready{service="${service}"} == 0 or absent(zasp_worker_driver_ready{service="${service}"})`);
  }
});

test("release rejects unpinned images and hostile public identifiers", async () => {
  await assert.doesNotReject(() => renderRelease({ ...release, connectors: { ...release.connectors, kmsKeyArn: "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab" } }));
  await assert.rejects(() => renderRelease({ ...release, host: "app.zasp.example\nmalicious: true" }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, images: { ...release.images, web: "zasp/web:latest" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, discovery: { ...release.discovery, parserVersion: "parser-v1" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, discovery: { ...release.discovery, roleArn: release.outbox.roleArn } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, projectionSearch: { ...release.projectionSearch, roleArn: "arn:aws:iam::210987654321:role/zasp-production-projection-search", initRoleArn: "arn:aws:iam::210987654321:role/zasp-production-projection-search-init" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, roleArn: "arn:aws:iam::210987654321:role/zasp-production-api-connectors", kmsKeyArn: "arn:aws:kms:us-west-2:210987654321:key/11111111-1111-4111-8111-111111111111" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, discovery: { ...release.discovery, queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-discovery-jobs" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, discovery: { ...release.discovery, secretPrefix: release.connectors.secretPrefix } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, discovery: { ...release.discovery, githubAppID: "654321" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, projectionRisk: { roleArn: release.projectionGraph.roleArn } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, projectionGraph: { ...release.projectionGraph, credentialReference: "ref:neo4j/runtime" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, projectionGraph: { ...release.projectionGraph, schemaCredentialReference: release.projectionGraph.credentialReference } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, projectionGraph: { ...release.projectionGraph, initRoleArn: release.projectionGraph.roleArn } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, projectionGraph: { ...release.projectionGraph, expectedRole: "admin" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, projectionSearch: { ...release.projectionSearch, initRoleArn: release.projectionSearch.roleArn } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, projectionGraph: { ...release.projectionGraph, endpoint: "neo4j://neo4j.internal.example:7687" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, tlsSecretName: "" }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, roleArn: "arn:aws:iam::123456789012:role/zasp-production-api" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, webIdentityTokenFile: "/tmp/token" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, githubClientSecretReference: "raw-secret" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, awsCustomerRolePrefixes: ["arn:aws:iam::123456789012:role/*"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, awsCustomerRolePrefixes: [release.connectors.awsCustomerRolePrefixes[0], release.connectors.awsCustomerRolePrefixes[0]] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, awsCustomerRoleARNs: ["arn:aws:iam::333333333333:role/zasp-reference/unprovisioned"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, awsCustomerRolePrefixes: Array.from({ length: 65 }, (_, index) => `arn:aws:iam::${String(index + 1).padStart(12, "0")}:role/zasp-reference/`) } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectorEgressCIDRs: { ...release.connectorEgressCIDRs, github: ["0.0.0.0/0"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectorEgressCIDRs: { ...release.connectorEgressCIDRs, okta: [] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectorEgressCIDRs: { ...release.connectorEgressCIDRs, kubernetes: [] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, storageSecretName: "" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, databaseEgressCIDRs: ["0.0.0.0/0"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, databaseEgressCIDRs: ["10.0.0.0/8"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, databaseEgressCIDRs: ["172.16.0.0/12"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, databaseEgressCIDRs: ["192.168.0.0/16"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, databaseEgressCIDRs: ["203.0.113.32/28"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, providerEgressCIDRs: release.nango.databaseEgressCIDRs } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, providerEgressCIDRs: ["0.0.0.0/1", "128.0.0.0/1"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, providerEgressCIDRs: ["10.40.0.0/24"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, providerEgressCIDRs: ["192.0.2.0/24", "192.0.2.0/25"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, databaseEgressCIDRs: ["10.30.0.0/24", "10.30.0.0/25"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, nango: { ...release.nango, ambient: true } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, telemetry: { backend: "none", endpoint: "https://otlp.nr-data.net", authSecretName: "", egressCIDRs: [] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, telemetry: { backend: "grafana", endpoint: "https://example.com/otlp", authSecretName: "otel-grafana", egressCIDRs: ["192.0.2.16/28"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, telemetry: { backend: "grafana", endpoint: "https://otlp-gateway-prod-us-west-0.grafana.net/otlp", authSecretName: release.nango.storageSecretName, egressCIDRs: ["192.0.2.16/28"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, telemetry: { backend: "grafana", endpoint: "https://otlp-gateway-prod-us-west-0.grafana.net/otlp", authSecretName: "otel-grafana", egressCIDRs: ["0.0.0.0/1", "128.0.0.0/1"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, telemetry: { backend: "grafana", endpoint: "https://otlp-gateway-prod-us-west-0.grafana.net/otlp", authSecretName: "otel-grafana", egressCIDRs: ["10.40.0.0/24"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, telemetry: { backend: "grafana", endpoint: "https://otlp-gateway-prod-us-west-0.grafana.net/otlp", authSecretName: "otel-grafana", egressCIDRs: ["192.0.2.0/24", "192.0.2.0/25"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, telemetry: { backend: "newrelic", endpoint: "https://otlp-gateway-prod-us-west-0.grafana.net/otlp", authSecretName: "otel-newrelic", egressCIDRs: ["198.51.100.16/28"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, telemetry: { backend: "newrelic", endpoint: "https://otlp.nr-data.net", authSecretName: "otel-newrelic", egressCIDRs: [] } }), /release rejected/);
});

test("terraform binds each shipped secret consumer to one exact least-privilege IRSA role", async () => {
  const [terraform, variables, outputs] = await Promise.all([
    readFile(new URL("../staging/main.tf", import.meta.url), "utf8"),
    readFile(new URL("../staging/variables.tf", import.meta.url), "utf8"),
    readFile(new URL("../staging/outputs.tf", import.meta.url), "utf8"),
  ]);
  assert.doesNotMatch(terraform, /aws_iam_role"\s+"product"|system:serviceaccount:agentsec:agentsec-product/);
  assert.doesNotMatch(terraform, /Principal\s*=\s*\{\s*AWS\s*=\s*aws_iam_role\.api\.arn/);
  for (const [role, account, secret] of [
    ["api", "agentsec-api", "api_secret_names"],
    ["worker", "zasp-discovery-worker", "postgres-worker-dsn"],
    ["scheduler", "zasp-discovery-scheduler", "postgres-scheduler-dsn"],
    ["outbox", "zasp-outbox-publisher", "postgres-outbox-worker-dsn"],
    ["projection_risk", "zasp-projection-risk", "postgres-projection-risk-dsn"],
    ["projection_graph", "zasp-projection-graph", "postgres-projection-graph-dsn"],
    ["projection_search", "zasp-projection-search", "postgres-projection-search-dsn"],
    ["projection_graph_init", "agentsec-projection-graph-init", "neo4j_projection_schema"],
    ["projection_search_init", "agentsec-projection-search-init", "zasp-inventory-v1/_mapping"],
    ["migration", "agentsec-migration", "postgres-migration-dsn"],
    ["canary_secret_sync", "agentsec-canary-secret-sync", "canary-read-token"],
  ]) {
    assert.match(terraform, new RegExp(`resource "aws_iam_role" "${role}"`));
    assert.match(terraform, new RegExp(`system:serviceaccount:agentsec:${account}`));
    assert.match(terraform, new RegExp(secret));
  }
  for (const policy of ["api", "scheduler", "migration", "canary_secret_sync"]) {
    const block = terraform.slice(terraform.indexOf(`resource "aws_iam_role_policy" "${policy}"`));
    assert.match(block.slice(0, block.indexOf("\n}\n") + 3), /secretsmanager:DescribeSecret.*secretsmanager:GetSecretValue/s);
    assert.doesNotMatch(block.slice(0, block.indexOf("\n}\n") + 3), /s3:|sqs:|es:|kms:Encrypt|kms:GenerateDataKey/);
  }
  const workerPolicyStart = terraform.indexOf('resource "aws_iam_role_policy" "worker"');
  const workerPolicy = terraform.slice(workerPolicyStart, terraform.indexOf("\nresource ", workerPolicyStart + 1));
  for (const action of ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes", "s3:PutObject", "s3:GetObject", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey", "secretsmanager:GetSecretValue", "sts:AssumeRole", "sts:GetCallerIdentity"]) assert.match(workerPolicy, new RegExp(action.replace(":", "\\:")));
  assert.match(workerPolicy, /aws_sqs_queue\.work\["discovery-jobs"\]\.arn/);
  assert.match(workerPolicy, /aws_s3_bucket\.evidence\.arn/);
  assert.match(workerPolicy, /aws_kms_key\.staging\.arn/);
  assert.match(workerPolicy, /aws_kms_key\.connector_oauth\.arn/);
  assert.match(workerPolicy, /connector_provider\["github_app_private_key"\]/);
  assert.match(workerPolicy, /connector_provider\["okta_client_secret"\]/);
  assert.doesNotMatch(workerPolicy, /connector_provider\["github_client_secret"\]/);
  assert.doesNotMatch(workerPolicy, /sqs:SendMessage|sqs:\*|s3:\*|secretsmanager:CreateSecret|secretsmanager:DeleteSecret|Action\s*=\s*\[[^\]]*"sqs:[^\]]*\][\s\S]{0,200}?Resource\s*=\s*"\*"/);
  const projectionPolicyStart = terraform.indexOf('resource "aws_iam_role_policy" "projection_search"');
  const projectionPolicy = terraform.slice(projectionPolicyStart, terraform.indexOf("\nresource ", projectionPolicyStart + 1));
  assert.match(projectionPolicy, /secretsmanager:DescribeSecret.*secretsmanager:GetSecretValue/s);
  assert.match(projectionPolicy, /es:ESHttpGet.*es:ESHttpPost.*es:ESHttpPut/s);
  for (const path of ["_mapping", "_zasp_schema_v1", "active_", "_bulk", "_mget", "_search", "_delete_by_query"]) assert.match(projectionPolicy, new RegExp(path));
  assert.match(projectionPolicy, /aws_opensearch_domain\.events\.arn/);
  assert.doesNotMatch(projectionPolicy, /es:\*|Action\s*=\s*\[[^\]]*"es:[^\]]*\][^}]{0,200}?Resource\s*=\s*"\*"|s3:|sqs:/);
  const graphPolicyStart = terraform.indexOf('resource "aws_iam_role_policy" "projection_graph"');
  const graphPolicy = terraform.slice(graphPolicyStart, terraform.indexOf("\nresource ", graphPolicyStart + 1));
  assert.match(graphPolicy, /postgres-projection-graph-dsn/);
  assert.match(graphPolicy, /aws_secretsmanager_secret\.neo4j_projection_runtime\.arn/);
  assert.match(graphPolicy, /sts:GetCallerIdentity/);
  assert.doesNotMatch(graphPolicy, /aws_secretsmanager_secret\.neo4j_projection_schema\.arn|s3:|sqs:|es:/);
  const schemaPolicyStart = terraform.indexOf('resource "aws_iam_role_policy" "projection_graph_init"');
  const schemaPolicy = terraform.slice(schemaPolicyStart, terraform.indexOf("\nresource ", schemaPolicyStart + 1));
  assert.match(schemaPolicy, /aws_secretsmanager_secret\.neo4j_projection_schema\.arn/);
  assert.match(schemaPolicy, /sts:GetCallerIdentity/);
  assert.doesNotMatch(schemaPolicy, /neo4j_projection_runtime|postgres-|s3:|sqs:|es:/);
  const searchInitPolicyStart = terraform.indexOf('resource "aws_iam_role_policy" "projection_search_init"');
  const searchInitPolicy = terraform.slice(searchInitPolicyStart, terraform.indexOf("\nresource ", searchInitPolicyStart + 1));
  assert.match(searchInitPolicy, /es:ESHttpGet.*_mapping.*_zasp_schema_v1/s);
  assert.match(searchInitPolicy, /es:ESHttpPut.*zasp-inventory-v1.*_zasp_schema_v1/s);
  assert.doesNotMatch(searchInitPolicy, /_bulk|_mget|_delete_by_query|secretsmanager:|s3:|sqs:/);
  const outboxPolicyStart = terraform.indexOf('resource "aws_iam_role_policy" "outbox"');
  const outboxPolicy = terraform.slice(outboxPolicyStart, terraform.indexOf("\nresource ", outboxPolicyStart + 1));
  assert.match(outboxPolicy, /sqs:SendMessage.*sqs:GetQueueAttributes/s);
  assert.match(outboxPolicy, /aws_sqs_queue\.work\["discovery-jobs"\]\.arn/);
  assert.match(outboxPolicy, /kms:ViaService[\s\S]*sqs\.\$\{var\.region\}\.amazonaws\.com/);
  assert.match(outboxPolicy, /kms:EncryptionContext:aws:sqs:arn/);
  assert.doesNotMatch(outboxPolicy, /kms:EncryptionContext:aws:sqs:queue-arn/);
  assert.doesNotMatch(outboxPolicy, /sqs:\*|Resource\s*=\s*"\*"|sqs:ReceiveMessage|sqs:DeleteMessage/);
  const apiSecrets = terraform.slice(terraform.indexOf("api_secret_names"), terraform.indexOf("queue_contract"));
  assert.match(apiSecrets, /postgres-api-dsn/);
  assert.doesNotMatch(apiSecrets, /postgres-worker-dsn|postgres-migration-dsn/);
  assert.match(terraform, /database_principals\s*=\s*\{/);
  for (const principal of ["migration", "api", "discovery_worker", "runtime_ingest", "runtime_worker", "outbox_worker", "runtime_gateway", "discovery_scheduler", "projection_risk", "projection_graph", "projection_search"]) {
    assert.match(terraform, new RegExp(`${principal}\\s*=\\s*var\\.database_principals`));
  }
  assert.match(terraform, /DatabasePrincipal/);
  assert.match(variables, /variable "discovery_implementation_versions"/);
  for (const version of ["parser", "tool", "aws_collector", "kubernetes_collector", "github_collector", "okta_collector"]) assert.match(variables, new RegExp(`${version}\\s*=\\s*string`));
  assert.match(variables, /variable "neo4j_endpoint"[\s\S]*neo4j\\\\\+s/);
  assert.match(variables, /variable "neo4j_endpoint_cidr"/);
  for (const output of ["discovery_runtime_config", "projection_risk_role_arn", "projection_graph_runtime_config", "projection_graph_init_authority", "projection_search_init_authority"]) assert.match(outputs, new RegExp(`output "${output}"`));
  for (const env of ["ZASP_DISCOVERY_AWS_COLLECTOR_VERSION", "ZASP_DISCOVERY_KUBERNETES_COLLECTOR_VERSION", "ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION", "ZASP_DISCOVERY_OKTA_COLLECTOR_VERSION", "ZASP_NEO4J_CREDENTIAL_REFERENCE"]) assert.match(outputs, new RegExp(env));
  assert.doesNotMatch(outputs, /neo4j.*(?:password|credential_value)|github.*private_key_value|okta.*secret_value/i);
});

test("terraform isolates connector mutation and reference authorization behind one API-only web-identity role", async () => {
  const [terraform, variables, outputs] = await Promise.all([
    readFile(new URL("../staging/main.tf", import.meta.url), "utf8"),
    readFile(new URL("../staging/variables.tf", import.meta.url), "utf8"),
    readFile(new URL("../staging/outputs.tf", import.meta.url), "utf8"),
  ]);
  for (const resource of [
    'resource "aws_kms_key" "connector_oauth"',
    'resource "aws_kms_alias" "connector_oauth"',
    'resource "aws_secretsmanager_secret" "connector_provider"',
    'resource "aws_secretsmanager_secret" "connector_reference"',
    'resource "aws_iam_role" "api_connectors"',
    'resource "aws_iam_role_policy" "api_connectors"',
  ]) assert.match(terraform, new RegExp(resource.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  for (const [key, suffix, credentialClass] of [
    ["github_client_secret", "github/client-secret", "github_oauth_client_secret"],
    ["github_app_private_key", "github/app-private-key", "github_app_private_key"],
    ["okta_client_secret", "okta/client-secret", "okta_oauth_client_secret"],
  ]) {
    assert.match(terraform, new RegExp(`${key}\\s*=\\s*\\{[\\s\\S]*?name\\s*=\\s*"\\$\\{local\\.connector_secret_root\\}/${suffix}"[\\s\\S]*?credential_class\\s*=\\s*"${credentialClass}"`));
  }
  assert.match(terraform, /tags\s*=\s*\{ CredentialClass = each\.value\.credential_class \}/);
  const role = terraform.slice(terraform.indexOf('resource "aws_iam_role" "api_connectors"'), terraform.indexOf('resource "aws_iam_role_policy" "api_connectors"'));
  assert.match(role, /system:serviceaccount:agentsec:agentsec-api/);
  assert.match(role, /sts:AssumeRoleWithWebIdentity/);
  const policyStart = terraform.indexOf('resource "aws_iam_role_policy" "api_connectors"');
  const policy = terraform.slice(policyStart, terraform.indexOf("\nresource ", policyStart + 1));
  const actions = [...policy.matchAll(/Action\s*=\s*\[([\s\S]*?)\]/g)].flatMap(([, list]) => [...list.matchAll(/"([^"]+)"/g)].map(([, action]) => action)).sort();
  assert.deepEqual(actions, ["kms:Decrypt", "kms:Decrypt", "kms:GenerateDataKey", "secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue", "secretsmanager:GetSecretValue", "secretsmanager:GetSecretValue", "secretsmanager:GetSecretValue", "sts:AssumeRole"].sort());
  assert.match(policy, /Action\s*=\s*\["secretsmanager:GetSecretValue"\][\s\S]*?Resource\s*=\s*\[for secret in aws_secretsmanager_secret\.connector_provider : secret\.arn\]/);
  assert.doesNotMatch(policy, /secret:\$\{local\.connector_secret_root\}\/github\/\*/);
  assert.doesNotMatch(policy, /secret:\$\{local\.connector_secret_root\}\/okta\/\*/);
  assert.match(policy, /Action\s*=\s*\["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"\][\s\S]*?Resource\s*=\s*\[for secret in aws_secretsmanager_secret\.connector_reference : secret\.arn\]/);
  assert.match(policy, /Action\s*=\s*\["sts:AssumeRole"\][\s\S]*?Resource\s*=\s*var\.aws_reference_role_arns/);
  assert.match(policy, /kms:EncryptionContext:SecretARN/);
  for (const namespace of [
    "secret:${local.connector_secret_prefix}/*",
    "secret:${local.connector_secret_root}/github/effect-manifest/*",
    "secret:${local.connector_secret_root}/github/effect-outcome/*",
    "secret:${local.connector_secret_root}/github/revoked-installation/*",
    "secret:${local.connector_secret_root}/okta/effect-manifest/*",
    "secret:${local.connector_secret_root}/okta/effect-access/*",
    "secret:${local.connector_secret_root}/okta/effect-outcome/*",
    "secret:${local.connector_secret_root}/okta/refresh/*",
    "secret:${local.connector_secret_root}/okta/revoked-refresh/*",
		"secret:${local.connector_secret_root}/webhook/*",
  ]) assert.match(policy, new RegExp(namespace.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(policy, /aws_kms_key\.connector_oauth\.arn/);
  assert.match(terraform, /connector_secret_root\s*=\s*"\$\{var\.cluster_name\}\/connectors"/);
  assert.match(terraform, /connector_secret_prefix\s*=\s*"\$\{local\.connector_secret_root\}\/oauth"/);
  for (const name of ["api", "migration", "canary_secret_sync"]) {
    const start = terraform.indexOf(`resource "aws_iam_role_policy" "${name}"`);
    const block = terraform.slice(start, terraform.indexOf("\nresource ", start + 1));
    assert.doesNotMatch(block, /aws_kms_key\.connector_oauth\.arn|connector_secret_prefix|connector_secret_root/, name);
  }
  assert.match(variables, /variable "connector_client_ids"/);
  assert.match(variables, /variable "aws_reference_role_prefixes"/);
  assert.match(variables, /variable "aws_reference_role_arns"/);
  assert.match(variables, /variable "connector_reference_ids"/);
  assert.match(outputs, /output "connector_role_arn"/);
  assert.match(outputs, /output "connector_kms_key_arn"/);
  assert.match(outputs, /output "connector_secret_prefix"/);
  assert.match(outputs, /output "connector_runtime_config"/);
  for (const name of ["ZASP_CONNECTOR_AWS_REGION", "ZASP_CONNECTOR_ROLE_ARN", "ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE", "ZASP_CONNECTOR_KMS_KEY_ARN", "ZASP_CONNECTOR_SECRET_PREFIX", "ZASP_AWS_CUSTOMER_ROLE_PREFIXES", "ZASP_AWS_CUSTOMER_ROLE_ARNS", "ZASP_KUBERNETES_EGRESS_CIDRS", "ZASP_FINDING_TICKET_EGRESS_CIDRS", "ZASP_GITHUB_CLIENT_ID", "ZASP_GITHUB_CLIENT_SECRET_REFERENCE", "ZASP_GITHUB_APP_ID", "ZASP_GITHUB_PRIVATE_KEY_REFERENCE", "ZASP_OKTA_CLIENT_ID", "ZASP_OKTA_CLIENT_SECRET_REFERENCE"]) assert.match(outputs, new RegExp(name));
  assert.doesNotMatch(terraform, /aws_secretsmanager_secret_version|secret_string|secret_binary/i);
});

test("terraform provisions the exact encrypted v15 runtime plane and isolated identities", async () => {
  const [terraform, variables, outputs] = await Promise.all([
    readFile(new URL("../staging/main.tf", import.meta.url), "utf8"),
    readFile(new URL("../staging/variables.tf", import.meta.url), "utf8"),
    readFile(new URL("../staging/outputs.tf", import.meta.url), "utf8"),
  ]);
  for (const resource of [
    'resource "aws_kms_key" "runtime_raw"',
    'resource "aws_s3_bucket" "runtime_raw"',
    'resource "aws_s3_bucket_public_access_block" "runtime_raw"',
    'resource "aws_s3_bucket_versioning" "runtime_raw"',
    'resource "aws_s3_bucket_server_side_encryption_configuration" "runtime_raw"',
    'resource "aws_s3_bucket_lifecycle_configuration" "runtime_raw"',
    'resource "aws_iam_role" "runtime"',
    'resource "aws_iam_role_policy" "runtime"',
  ]) assert.match(terraform, new RegExp(resource.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(terraform, /runtime-events\s*=\s*\{ visibility = 120, schema = "agentsec\.runtime-events\.v1" \}/);
  assert.match(terraform, /runtime_raw_bucket_name\s*=\s*"zasp-runtime-raw-\$\{md5\(var\.account_id\)\}"/);
  assert.match(terraform, /versioning_configuration \{ status = "Enabled" \}/);
  assert.match(terraform, /kms_master_key_id = aws_kms_key\.runtime_raw\.arn/);
  for (const [key, account, secret] of [
    ["ingest", "zasp-runtime-ingest", "postgres-runtime-ingest-dsn"],
    ["gateway_control", "zasp-gateway-control", "postgres-gateway-control-dsn"],
    ["outbox", "zasp-runtime-outbox", "postgres-outbox-worker-dsn"],
    ["coordinator", "zasp-runtime-coordinator", "postgres-runtime-coordinator-dsn"],
    ["archive", "zasp-runtime-archive", "postgres-runtime-archive-dsn"],
    ["index", "zasp-runtime-index", "postgres-runtime-index-dsn"],
    ["correlation", "zasp-runtime-correlation", "postgres-runtime-correlation-dsn"],
    ["projection", "zasp-runtime-projection", "postgres-runtime-projection-dsn"],
    ["complete", "zasp-runtime-complete", "postgres-runtime-coordinator-dsn"],
  ]) {
    assert.match(terraform, new RegExp(`${key}\\s*=\\s*\\{[\\s\\S]*?principal\\s*=\\s*"system:serviceaccount:agentsec:${account}"[\\s\\S]*?database_secret\\s*=\\s*"${secret}"`));
  }
  const runtimePolicy = terraform.slice(terraform.indexOf('resource "aws_iam_role_policy" "runtime"'), terraform.indexOf("\nresource ", terraform.indexOf('resource "aws_iam_role_policy" "runtime"') + 1));
  for (const action of ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue", "sts:GetCallerIdentity", "sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes", "s3:PutObject", "s3:GetObject", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey", "es:ESHttpGet", "es:ESHttpPost", "es:ESHttpPut"]) assert.match(runtimePolicy, new RegExp(action.replace(":", "\\:")));
  assert.match(runtimePolicy, /aws_sqs_queue\.work\["runtime-events"\]\.arn/);
  assert.match(runtimePolicy, /aws_s3_bucket\.runtime_raw\.arn/);
  assert.match(runtimePolicy, /aws_opensearch_domain\.events\.arn/);
  assert.doesNotMatch(runtimePolicy, /"(?:s3|sqs|es):\*"/);
  for (const principal of ["runtime_coordinator", "runtime_archive", "runtime_index", "runtime_correlation", "runtime_projection", "gateway_control"]) {
    assert.match(variables, new RegExp(`${principal}\\s*=\\s*string`));
    assert.match(terraform, new RegExp(`${principal}\\s*=\\s*var\\.database_principals\\.${principal}`));
  }
  assert.match(outputs, /output "runtime_release_authority"/);
  for (const name of ["queue_url", "raw_bucket", "raw_kms_key_arn", "opensearch_endpoint", "ingest_role_arn", "gateway_control_role_arn", "outbox_role_arn", "coordinator_role_arn", "archive_role_arn", "index_role_arn", "correlation_role_arn", "projection_role_arn", "complete_role_arn"]) assert.match(outputs, new RegExp(`${name}\\s*=`));
  assert.doesNotMatch(terraform, /aws_secretsmanager_secret_version|secret_string|secret_binary/i);
});

function one(resources, kind, name) {
  const found = resources.filter((resource) => resource.kind === kind && resource.metadata?.name === name);
  assert.equal(found.length, 1, `${kind}/${name} count`);
  return found[0];
}

function envOf(workload) {
  return Object.fromEntries(workload.spec.template.spec.containers[0].env.map(({ name, value, valueFrom }) => [name, value ?? "fieldRef:" + valueFrom?.fieldRef?.fieldPath]));
}
