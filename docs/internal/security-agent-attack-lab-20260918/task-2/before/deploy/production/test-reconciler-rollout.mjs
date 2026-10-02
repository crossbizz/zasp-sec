import { validAuditExportCIDRs } from "./audit-export-network.mjs";
import { isDeepStrictEqual } from "node:util";
import { load, JSON_SCHEMA } from "js-yaml";
import { validateTestReconcilerNetwork } from "./test-reconciler-network.mjs";

const keys = ["enabled", "awsRegion", "roleArn", "databaseSecretArn", "evidenceBucket", "evidenceOwner", "evidenceKMSKeyArn", "databaseCIDRs", "stsCIDRs", "s3CIDRs", "kmsCIDRs"];
function requireValue(condition) {
  if (!condition) throw new Error("release rejected: test reconciler authority");
}

export function validateTestReconcilerResources(resources, expected, schemaVersion) {
  requireValue(Array.isArray(resources));
  const name = "zasp-test-reconciler", marker = /zasp-test-reconciler|ZASP_TEST_RECONCILER_|security-agent-test-reconciler/;
  if (expected === undefined) {
    // The shared DNS policy deliberately excludes the inactive worker label.
    for (const resource of resources) if (resource.kind !== "NetworkPolicy") requireValue(!marker.test(JSON.stringify(resource)));
    return;
  }
  requireValue([55, 56].includes(schemaVersion));
  const trusted = validateTestReconcilerNetwork(resources, expected);
  const equal = (a, b) => requireValue(isDeepStrictEqual(a, b));
  const one = (kind, resourceName = name) => {
    const found = resources.filter(r => r.kind === kind && r.metadata?.name === resourceName);
    requireValue(found.length === 1 && [undefined, "agentsec"].includes(found[0].metadata.namespace));
    trusted.add(found[0]); return found[0];
  };
  const labels = { "app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "zasp" };
  const selector = { matchLabels: { "app.kubernetes.io/name": name } };
  const account = one("ServiceAccount");
  requireValue(account.apiVersion === "v1" && account.automountServiceAccountToken === false);
  requireValue(Object.keys(account).every(k => ["apiVersion", "kind", "metadata", "automountServiceAccountToken"].includes(k)));
  equal(account.metadata.annotations, { "eks.amazonaws.com/role-arn": expected.roleArn });
  const provider = one("SecretProviderClass", `${name}-secrets`);
  requireValue(provider.apiVersion === "secrets-store.csi.x-k8s.io/v1");
  equal(Object.keys(provider.spec).sort(), ["parameters", "provider"]);
  equal(Object.keys(provider.spec.parameters).sort(), ["objects", "region"]);
  requireValue(provider.spec.provider === "aws" && provider.spec.parameters.region === expected.awsRegion);
  let objects;
  try { objects = load(provider.spec.parameters.objects, { schema: JSON_SCHEMA }); } catch { requireValue(false); }
  equal(objects, [{ objectName: expected.databaseSecretArn, objectType: "secretsmanager", objectAlias: "postgres-dsn" }]);
  const deployment = one("Deployment"), pod = deployment.spec?.template?.spec;
  requireValue(deployment.apiVersion === "apps/v1" && pod && Number.isInteger(pod.terminationGracePeriodSeconds) && pod.terminationGracePeriodSeconds > 20 && pod.terminationGracePeriodSeconds <= 300);
  equal(deployment.spec.template.metadata, { labels, annotations: { "zasp.io/schema-version": String(schemaVersion) } });
  const image = resources.find(r => r.kind === "Deployment" && r.metadata?.name === "agentsec-security-agent")?.spec?.template?.spec?.containers?.[0]?.image;
  requireValue(matches(image, /^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$/));
  const value = (name, value) => ({ name, value });
  const container = {
    name: "worker", image, imagePullPolicy: "IfNotPresent", command: ["/bin/sh", "-ec"],
    args: ['export ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-test-reconciler/postgres-dsn)"; exec /app/agentsec-worker'],
    ports: [{ name: "internal", containerPort: 8081 }],
    env: [value("ZASP_WORKER_MODE", "security-agent-test-reconciler"), value("ZASP_DATABASE_AUTHORITY", "zasp_security_agent_worker"),
      { name: "ZASP_WORKER_ID", valueFrom: { fieldRef: { fieldPath: "metadata.name" } } },
      value("ZASP_POLL_INTERVAL", "1s"), value("ZASP_LEASE_DURATION", "60s"), value("ZASP_BATCH_SIZE", "1"), value("ZASP_SHUTDOWN_TIMEOUT", "20s"),
      value("ZASP_AWS_REGION", expected.awsRegion), value("ZASP_EVIDENCE_BUCKET", expected.evidenceBucket), value("ZASP_EVIDENCE_BUCKET_OWNER", expected.evidenceOwner), value("ZASP_EVIDENCE_KMS_KEY_ARN", expected.evidenceKMSKeyArn),
      value("ZASP_TEST_RECONCILER_ROLE_ARN", expected.roleArn), value("ZASP_TEST_RECONCILER_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/eks.amazonaws.com/serviceaccount/token")],
    volumeMounts: [{ name: "database", mountPath: "/var/run/secrets/zasp-test-reconciler", readOnly: true }, { name: "identity", mountPath: "/var/run/secrets/eks.amazonaws.com/serviceaccount", readOnly: true }],
    startupProbe: { httpGet: { path: "/healthz", port: "internal" }, failureThreshold: 30, periodSeconds: 2, timeoutSeconds: 1 },
    readinessProbe: { httpGet: { path: "/readyz", port: "internal" }, failureThreshold: 3, periodSeconds: 5, timeoutSeconds: 2 },
    livenessProbe: { httpGet: { path: "/healthz", port: "internal" }, failureThreshold: 3, periodSeconds: 10, timeoutSeconds: 2 },
    resources: { requests: { cpu: "100m", memory: "128Mi" }, limits: { cpu: "1", memory: "1Gi" } },
    securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] }, privileged: false, readOnlyRootFilesystem: true },
  };
  equal(pod, {
    serviceAccountName: name, automountServiceAccountToken: false, enableServiceLinks: false, terminationGracePeriodSeconds: pod.terminationGracePeriodSeconds,
    topologySpreadConstraints: [
      { maxSkew: 1, topologyKey: "topology.kubernetes.io/zone", whenUnsatisfiable: "DoNotSchedule", labelSelector: selector },
      { maxSkew: 1, topologyKey: "kubernetes.io/hostname", whenUnsatisfiable: "ScheduleAnyway", labelSelector: selector },
    ],
    securityContext: { runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532, seccompProfile: { type: "RuntimeDefault" } },
    containers: [container],
    volumes: [{ name: "database", csi: { driver: "secrets-store.csi.k8s.io", readOnly: true, volumeAttributes: { secretProviderClass: `${name}-secrets` } } },
      { name: "identity", projected: { sources: [{ serviceAccountToken: { audience: "sts.amazonaws.com", expirationSeconds: 3600, path: "token" } }] } }],
  });
  equal(deployment.spec, { replicas: 2, revisionHistoryLimit: 3, progressDeadlineSeconds: 600,
    strategy: { type: "RollingUpdate", rollingUpdate: { maxSurge: 1, maxUnavailable: 0 } }, selector, template: { metadata: { labels, annotations: { "zasp.io/schema-version": String(schemaVersion) } }, spec: pod } });
  const pdb = one("PodDisruptionBudget"), hpa = one("HorizontalPodAutoscaler");
  requireValue(pdb.apiVersion === "policy/v1" && hpa.apiVersion === "autoscaling/v2");
  equal(pdb.spec, { minAvailable: 1, selector });
  equal(hpa.spec, { scaleTargetRef: { apiVersion: "apps/v1", kind: "Deployment", name }, minReplicas: 2, maxReplicas: 6,
    metrics: [{ type: "Resource", resource: { name: "cpu", target: { type: "Utilization", averageUtilization: 70 } } }] });
  const service = one("Service"), monitor = one("ServiceMonitor"), alerts = one("PrometheusRule", `${name}-availability`);
  requireValue(service.apiVersion === "v1" && monitor.apiVersion === "monitoring.coreos.com/v1" && alerts.apiVersion === "monitoring.coreos.com/v1");
  equal(service.metadata.labels, labels);
  equal(service.spec, { type: "ClusterIP", publishNotReadyAddresses: true, selector: selector.matchLabels,
    ports: [{ name: "internal", port: 8081, targetPort: "internal", protocol: "TCP" }] });
  equal(monitor.spec, { selector: { matchLabels: labels }, namespaceSelector: { matchNames: ["agentsec"] },
    endpoints: [{ port: "internal", path: "/metrics", interval: "30s", scrapeTimeout: "5s" }] });
  const deploymentMetric = `kube_deployment_status_replicas_available{namespace="agentsec",deployment="${name}"}`;
  const up = `up{namespace="agentsec",service="${name}"}`, ready = `agentsec_ready{namespace="agentsec",service="${name}"}`;
  equal(alerts.spec, { groups: [{ name: "zasp.test-reconciler.availability", rules: [
    { alert: "ZaspTestReconcilerUnavailable", expr: `${deploymentMetric} < 1 or absent(${deploymentMetric})`, for: "5m", labels: { severity: "page" }, annotations: { summary: "Test reconciler workload is unavailable or absent" } },
    { alert: "ZaspTestReconcilerNotReady", expr: `${ready} == 0 or ${up} == 0 or (${up} == 1 unless on (namespace,service,instance) ${ready}) or absent(${up})`, for: "10m", labels: { severity: "ticket" }, annotations: { summary: "Test reconciler readiness is unavailable" } },
  ] }] });
  for (const resource of resources) {
    if (trusted.has(resource) || resource.kind === "NetworkPolicy") continue;
    if (["RoleBinding", "ClusterRoleBinding"].includes(resource.kind)) {
      // A binding in any namespace can grant this identity permissions there.
      // Group grants cover the worker without naming its service account.
      requireValue(Array.isArray(resource.subjects));
      const workerGroups = ["system:serviceaccounts:agentsec", "system:serviceaccounts", "system:authenticated"];
      requireValue(!resource.subjects.some(subject => subject?.kind === "Group" && workerGroups.includes(subject.name)));
    }
    requireValue(!marker.test(JSON.stringify(resource)));
  }
}
function matches(value, pattern) { return typeof value === "string" && pattern.test(value); }

// Omission is the only disabled form. Copy before asynchronous rendering so a
// caller cannot alter credentials or endpoint authority after validation.
export function normalizeTestReconciler(value, account, schemaVersion, phase) {
  if (value === undefined) return undefined;
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype);
  const ownKeys = Reflect.ownKeys(value);
  requireValue(ownKeys.length === keys.length && ownKeys.every(key => typeof key === "string" && keys.includes(key)));
  requireValue(Object.values(Object.getOwnPropertyDescriptors(value)).every(d => "value" in d && d.enumerable));
  requireValue(value.enabled === true && [55, 56].includes(schemaVersion) && ["precision-consumers", "precision-intake"].includes(phase));
  requireValue(matches(account, /^[0-9]{12}$/) && account !== "000000000000" && value.evidenceOwner === account);
  requireValue(matches(value.awsRegion, /^[a-z]{2}(-gov)?-[a-z]+-[0-9]$/));
  requireValue(matches(value.roleArn, new RegExp(`^arn:aws:iam::${account}:role/[A-Za-z0-9+=,.@_/-]{1,128}$`)));
  requireValue(matches(value.databaseSecretArn, new RegExp(`^arn:aws:secretsmanager:${value.awsRegion}:${account}:secret:[A-Za-z0-9/_+=.@-]{1,512}$`)));
  requireValue(matches(value.evidenceBucket, /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/));
  requireValue(matches(value.evidenceKMSKeyArn, new RegExp(`^arn:aws:kms:${value.awsRegion}:${account}:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)));
  for (const field of ["databaseCIDRs", "stsCIDRs", "s3CIDRs", "kmsCIDRs"]) requireValue(validAuditExportCIDRs(value[field]));
  return structuredClone(value);
}
