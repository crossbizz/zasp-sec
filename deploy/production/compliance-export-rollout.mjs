import { attackLabReconcilerMigrationCommand } from "./attack-lab-reconciler-rollout.mjs";
import { isDeepStrictEqual } from "node:util";
import { load } from "js-yaml";
import { validAuditExportCIDRs } from "./audit-export-network.mjs";
import { validateComplianceExportNetwork } from "./compliance-export-network.mjs";
import { validateAPIStartup } from "./api-startup.mjs";

const keys = ["enabled", "awsRegion", "bucket", "bucketOwner", "kmsKeyArn", "readerRoleArn", "writerRoleArn", "cleanupRoleArn", "workerDSNSecretArn", "cleanupDSNSecretArn", "workerPrincipal", "cleanupPrincipal", "databaseCIDRs", "stsCIDRs", "s3CIDRs"];
const prefix = "ZASP_COMPLIANCE_";
const names = ["zasp-compliance-export-worker", "zasp-compliance-cleanup-worker"];
const tokenPath = "/var/run/secrets/eks.amazonaws.com/serviceaccount";
const requireValue = value => { if (!value) throw new Error("release rejected"); };
const equal = (actual, expected) => requireValue(isDeepStrictEqual(actual, expected));
const matches = (v, p) => typeof v === "string" && !/[\r\n]/.test(v) && p.test(v);
function strings(value) {
  if (typeof value === "string") return [value];
  return value && typeof value === "object" ? Object.values(value).flatMap(strings) : [];
}
function closed(value, fields) {
  requireValue(value && Object.getPrototypeOf(value) === Object.prototype);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  requireValue(Reflect.ownKeys(value).every(k => typeof k === "string") && Object.values(descriptors).every(d => "value" in d && d.enumerable));
  equal(Object.keys(value).sort(), [...fields].sort());
}
export function normalizeComplianceExports(value, account, schemaVersion, phase) {
  if (value === undefined) return undefined;
  closed(value, keys);
  requireValue(value.enabled === true && [56, 57, 58].includes(schemaVersion) && ["precision-consumers", "precision-intake"].includes(phase));
  requireValue(matches(account, /^[0-9]{12}$/) && account !== "000000000000" && value.bucketOwner === account);
  requireValue(matches(value.awsRegion, /^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$/) && matches(value.bucket, /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/));
  requireValue(matches(value.kmsKeyArn, new RegExp(`^arn:aws:kms:${value.awsRegion}:${account}:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)));
  const roles = [value.readerRoleArn, value.writerRoleArn, value.cleanupRoleArn];
  requireValue(new Set(roles).size === 3 && roles.every(v => matches(v, new RegExp(`^arn:aws:iam::${account}:role/[A-Za-z0-9+=,.@_/-]{1,128}$`))));
  const secrets = [value.workerDSNSecretArn, value.cleanupDSNSecretArn];
  requireValue(new Set(secrets).size === 2 && secrets.every(v => matches(v, new RegExp(`^arn:aws:secretsmanager:${value.awsRegion}:${account}:secret:[A-Za-z0-9/_+=.@-]{1,512}$`))));
  requireValue(value.workerPrincipal !== value.cleanupPrincipal && [value.workerPrincipal, value.cleanupPrincipal].every(v => matches(v, /^[a-z][a-z0-9_]{2,62}$/) && !v.startsWith("zasp_")));
  for (const key of ["databaseCIDRs", "stsCIDRs", "s3CIDRs"]) requireValue(validAuditExportCIDRs(value[key]) && value[key].every(v => !/[\r\n]/.test(v)));
  return structuredClone(value);
}

// Called before rendering starts. The complete release and both optional
// predecessors contribute identities and storage that compliance cannot reuse.
export function validateComplianceExportCollisions(value, config, audit, reconciler) {
  if (!config) return;
  const occupied = strings([value, audit, reconciler]);
  for (const field of ["bucket", "readerRoleArn", "writerRoleArn", "cleanupRoleArn", "workerDSNSecretArn", "cleanupDSNSecretArn", "workerPrincipal", "cleanupPrincipal"]) requireValue(!occupied.includes(config[field]));
}
export function complianceExportMigrationCommand(schemaVersion, auditExportsEnabled) {
  requireValue([56, 57, 58].includes(schemaVersion) && typeof auditExportsEnabled === "boolean");
  return 'ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-migration/postgres-dsn)" && export ZASP_POSTGRES_DSN && /app/agentsec-migrate up-to-' + schemaVersion +
    (auditExportsEnabled ? " && /app/agentsec-migrate register-audit-export-api && /app/agentsec-migrate register-audit-export-workers && /app/agentsec-migrate configure-audit-exports" : "") +
    " && exec /app/agentsec-migrate register-compliance-workers";
}
function environment(container, expected, exact = false) {
  requireValue(container && container.envFrom === undefined && Array.isArray(container.env));
  const entries = container.env;
  requireValue(entries.every(e => typeof e?.name === "string") && new Set(entries.map(e => e.name)).size === entries.length);
  const selected = entries.filter(e => exact || e.name.startsWith(prefix));
  equal(selected.map(e => e.name).sort(), Object.keys(expected).sort());
  for (const entry of selected) equal(entry, typeof expected[entry.name] === "string" ? { name: entry.name, value: expected[entry.name] } : { name: entry.name, valueFrom: expected[entry.name] });
}
function podOf(resource) {
  const pod = resource.spec?.template?.spec;
  requireValue(pod && pod.containers?.length === 1 && !pod.initContainers?.length && !pod.ephemeralContainers?.length);
  requireValue(["hostNetwork", "hostPID", "hostIPC"].every(k => pod[k] === undefined || pod[k] === false));
  return pod;
}
function objects(provider) {
  requireValue(provider.spec?.provider === "aws" && typeof provider.spec?.parameters?.objects === "string");
  try { const values = load(provider.spec.parameters.objects); requireValue(Array.isArray(values)); return values; } catch { throw new Error("release rejected"); }
}
export function validateComplianceExportResources(resources, config, schemaVersion, attackLabReconciler, evidenceExportWorkflow = false) {
  requireValue(Array.isArray(resources));
  const marker = /ZASP_COMPLIANCE_|zasp_compliance_|zasp-compliance-/;
  if (!config) {
    for (const resource of resources) requireValue(!marker.test(JSON.stringify(resource)));
    return;
  }
  requireValue([56, 57, 58].includes(schemaVersion));
  const one = (kind, name) => {
    const rows = resources.filter(r => r?.kind === kind && r.metadata?.name === name);
    requireValue(rows.length === 1 && [undefined, "agentsec"].includes(rows[0].metadata.namespace));
    return rows[0];
  };
  const trusted = validateComplianceExportNetwork(resources, config, evidenceExportWorkflow);
  const common = { ZASP_COMPLIANCE_EXPORT_BUCKET: config.bucket, ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER: config.bucketOwner, ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN: config.kmsKeyArn, ZASP_COMPLIANCE_EXPORT_WEB_IDENTITY_TOKEN_FILE: `${tokenPath}/token` };
  for (const [i, name] of names.entries()) {
    const role = i === 0 ? config.writerRoleArn : config.cleanupRoleArn;
    const secret = i === 0 ? config.workerDSNSecretArn : config.cleanupDSNSecretArn;
    const deployment = one("Deployment", name), account = one("ServiceAccount", name), provider = one("SecretProviderClass", `${name}-secrets`);
    [deployment, account, provider].forEach(r => trusted.add(r));
    const pod = podOf(deployment), c = pod.containers[0];
    equal(deployment.spec.template.metadata, { labels: { "app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "zasp" }, annotations: { "zasp.io/schema-version": String(schemaVersion) } });
    requireValue(deployment.spec.replicas === 2 && pod.serviceAccountName === name && pod.automountServiceAccountToken === false && pod.enableServiceLinks === false && pod.terminationGracePeriodSeconds > 20 && pod.terminationGracePeriodSeconds <= 300);
    equal(deployment.spec.selector, { matchLabels: { "app.kubernetes.io/name": name } });
    equal(pod.securityContext, { runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532, seccompProfile: { type: "RuntimeDefault" } });
    requireValue(matches(c.image, /^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$/));
    equal(c.image, one("Deployment", "agentsec-discovery-worker").spec.template.spec.containers[0].image);
    equal(c.command, ["/bin/sh", "-ec"]);
    equal(c.args, ['ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-compliance/postgres-dsn)" && export ZASP_POSTGRES_DSN && exec /app/agentsec-worker']);
    environment(c, { ...common, ZASP_WORKER_MODE: i === 0 ? "compliance-export" : "compliance-export-cleanup", ZASP_DATABASE_AUTHORITY: i === 0 ? "zasp_compliance_worker" : "zasp_compliance_cleanup", ZASP_WORKER_ID: { fieldRef: { fieldPath: "metadata.name" } }, ZASP_AWS_REGION: config.awsRegion, ZASP_POLL_INTERVAL: "1s", ZASP_LEASE_DURATION: "60s", ZASP_BATCH_SIZE: "1", ZASP_SHUTDOWN_TIMEOUT: "20s", ZASP_PROVIDER_TIMEOUT: "5s", ZASP_COMPLIANCE_EXPORT_ROLE_ARN: role }, true);
    equal(c.volumeMounts, [{ name: "database", mountPath: "/var/run/secrets/zasp-compliance", readOnly: true }, { name: "identity", mountPath: tokenPath, readOnly: true }]);
    equal(pod.volumes, [{ name: "database", csi: { driver: "secrets-store.csi.k8s.io", readOnly: true, volumeAttributes: { secretProviderClass: `${name}-secrets` } } }, { name: "identity", projected: { sources: [{ serviceAccountToken: { audience: "sts.amazonaws.com", expirationSeconds: 3600, path: "token" } }] } }]);
    equal(c.securityContext, { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] }, privileged: false, readOnlyRootFilesystem: true, runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532 });
    equal(c.ports, [{ name: "internal", containerPort: 8081 }]);
    equal(c.resources, { requests: { cpu: "100m", memory: "128Mi" }, limits: { cpu: "1", memory: "1Gi" } });
    for (const [key, url, failures, period, timeout] of [["startupProbe", "/healthz", 30, 2, 1], ["readinessProbe", "/readyz", 3, 5, 2], ["livenessProbe", "/healthz", 3, 10, 2]]) equal(c[key], { httpGet: { path: url, port: "internal" }, failureThreshold: failures, periodSeconds: period, timeoutSeconds: timeout });
    requireValue(account.automountServiceAccountToken === false && account.metadata.annotations?.["eks.amazonaws.com/role-arn"] === role);
    equal(objects(provider), [{ objectName: secret, objectType: "secretsmanager", objectAlias: "postgres-dsn" }]);
    requireValue(provider.spec.secretObjects === undefined && provider.spec.parameters.region === config.awsRegion);
  }
  const api = one("Deployment", "agentsec-api"), apiPod = podOf(api), apiContainer = apiPod.containers[0];
  trusted.add(api);
  validateAPIStartup(apiContainer, resources.some(r => r.kind === "Deployment" && r.metadata?.name === "zasp-audit-export-worker"));
  environment(apiContainer, { ...common, ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN: config.readerRoleArn });
  equal(apiPod.volumes?.filter(v => v.name === "connector-web-identity"), [{ name: "connector-web-identity", projected: { defaultMode: 256, sources: [{ serviceAccountToken: { audience: "sts.amazonaws.com", expirationSeconds: 900, path: "token" } }] } }]);
  equal(apiContainer.volumeMounts?.filter(v => v.name === "connector-web-identity"), [{ name: "connector-web-identity", mountPath: tokenPath, readOnly: true }]);
  const migration = one("Job", `agentsec-schema-v${schemaVersion}`), migrationContainer = podOf(migration).containers[0];
  trusted.add(migration);
  environment(migrationContainer, { ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL: config.workerPrincipal, ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL: config.cleanupPrincipal });
  equal(migrationContainer.command, ["/bin/sh", "-ec"]);
  const migrationCommand = complianceExportMigrationCommand(schemaVersion, resources.some(r => r.kind === "Deployment" && r.metadata?.name === "zasp-audit-export-worker"));
  equal(migrationContainer.args, [attackLabReconciler ? attackLabReconcilerMigrationCommand(migrationCommand) : migrationCommand]);
  const privateValues = [config.writerRoleArn, config.cleanupRoleArn, config.readerRoleArn, config.workerDSNSecretArn, config.cleanupDSNSecretArn, config.workerPrincipal, config.cleanupPrincipal, config.bucket];
  for (const r of resources) if (!trusted.has(r)) {
    const wire = JSON.stringify(r);
    requireValue(!marker.test(wire) && !privateValues.some(v => wire.includes(v)));
  }
  const all = resources.flatMap(strings);
  for (const r of resources.filter(r => r.kind === "SecretProviderClass")) all.push(...strings(objects(r)));
  for (const [value, count] of [[config.readerRoleArn, 1], [config.writerRoleArn, 2], [config.cleanupRoleArn, 2], [config.workerDSNSecretArn, 1], [config.cleanupDSNSecretArn, 1], [config.workerPrincipal, 1], [config.cleanupPrincipal, 1], [config.bucket, 3], ...names.map(n => [`${n}-secrets`, 2])]) equal(all.filter(v => v === value).length, count);
}
