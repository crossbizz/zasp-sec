import { complianceExportMigrationCommand } from "./compliance-export-rollout.mjs";
import { isDeepStrictEqual } from "node:util";
import { load } from "js-yaml";
import { validAuditExportCIDRs, validateAuditExportNetwork } from "./audit-export-network.mjs";
import { validateAuditExportOperations } from "./audit-export-operations.mjs";
import { validateAPIStartup } from "./api-startup.mjs";

// These checks validate a rendered artifact, not authority to activate a live release.
export function auditExportMigrationCommand(schemaVersion = 52) {
  requireValue([52, 53, 54, 55, 56].includes(schemaVersion));
  return `ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-migration/postgres-dsn)" && export ZASP_POSTGRES_DSN && /app/agentsec-migrate up-to-${schemaVersion} && /app/agentsec-migrate register-audit-export-api && /app/agentsec-migrate register-audit-export-workers && exec /app/agentsec-migrate configure-audit-exports`;
}

const prefix = "ZASP_AUDIT_EXPORT_";
const tokenPath = "/var/run/secrets/eks.amazonaws.com/serviceaccount";
const cursorAlias = "audit-export-cursor-signing-key";
const workerNames = ["zasp-audit-export-worker", "zasp-audit-export-outbox"];
const configKeys = ["enabled", "awsRegion", "queueURL", "writerRoleArn", "publisherRoleArn", "readerRoleArn", "workerDSNSecretArn", "outboxDSNSecretArn", "cursorSecretArn", "policies", "currentPolicyID", "expectedCurrentPolicyID", "workerPrincipal", "outboxPrincipal", "stsCIDRs", "sqsCIDRs", "s3CIDRs"];
const policyKeys = ["schema", "policy_id", "bucket", "expected_bucket_owner", "kms_key_arn", "maximum_export_bytes", "maximum_retained_bytes", "maximum_inflight", "capture_timeout_seconds"];
const idPattern = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function requireValue(condition) { if (!condition) throw new Error("release rejected: audit export authority"); }
function equal(actual, expected) { requireValue(isDeepStrictEqual(actual, expected)); }
function closed(value, keys) {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype);
  const ownKeys = Reflect.ownKeys(value);
  requireValue(ownKeys.every(key => typeof key === "string"));
  equal(ownKeys.sort(), [...keys].sort());
  requireValue(Object.values(Object.getOwnPropertyDescriptors(value)).every(d => "value" in d && d.enumerable));
}
function matches(value, pattern) { return typeof value === "string" && pattern.test(value); }

export function normalizeAuditExports(value, account, schemaVersion, phase) {
  if (value === undefined) return undefined;
  closed(value, configKeys);
  for (const key of ["stsCIDRs", "sqsCIDRs", "s3CIDRs"]) requireValue(validAuditExportCIDRs(value[key]));
  requireValue(value.enabled === true && [52, 53, 54, 55, 56].includes(schemaVersion) && ["precision-consumers", "precision-intake"].includes(phase));
  requireValue(matches(account, /^[0-9]{12}$/) && account !== "000000000000" && matches(value.awsRegion, /^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$/));
  const roles = [value.writerRoleArn, value.publisherRoleArn, value.readerRoleArn];
  requireValue(new Set(roles).size === 3 && roles.every(v => matches(v, new RegExp(`^arn:aws:iam::${account}:role/[A-Za-z0-9+=,.@_/-]{1,128}$`))));
  equal(value.queueURL, `https://sqs.${value.awsRegion}.amazonaws.com/${account}/agentsec-audit-exports`);
  const secrets = [value.workerDSNSecretArn, value.outboxDSNSecretArn, value.cursorSecretArn];
  requireValue(new Set(secrets).size === 3 && secrets.every(v => matches(v, new RegExp(`^arn:aws:secretsmanager:${value.awsRegion}:${account}:secret:[A-Za-z0-9/_+=.@-]{1,512}$`))));
  const principals = [value.workerPrincipal, value.outboxPrincipal];
  requireValue(new Set(principals).size === 2 && principals.every(v => matches(v, /^[a-z][a-z0-9_]{2,62}$/) && !["zasp_audit_export_worker", "zasp_audit_export_outbox"].includes(v)));
  requireValue(matches(value.currentPolicyID, idPattern) && typeof value.expectedCurrentPolicyID === "string" && (value.expectedCurrentPolicyID === "" || matches(value.expectedCurrentPolicyID, idPattern) && value.expectedCurrentPolicyID !== value.currentPolicyID));
  requireValue(Array.isArray(value.policies) && value.policies.length >= 1 && value.policies.length <= 64);
  const arrayKeys = Reflect.ownKeys(value.policies);
  requireValue(Object.getPrototypeOf(value.policies) === Array.prototype && arrayKeys.every(key => typeof key === "string"));
  equal(arrayKeys.sort(), [...value.policies.keys()].map(String).concat("length").sort());
  requireValue(Object.values(Object.getOwnPropertyDescriptors(value.policies)).every(d => "value" in d));
  const seen = new Set();
  for (const policy of value.policies) {
    closed(policy, policyKeys);
    requireValue(policy.schema === "audit-export-policy-v1" && matches(policy.policy_id, idPattern) && !seen.has(policy.policy_id));
    seen.add(policy.policy_id);
    requireValue(matches(policy.bucket, /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/) && matches(policy.expected_bucket_owner, /^[0-9]{12}$/));
    requireValue(matches(policy.kms_key_arn, /^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/));
    for (const [key, max] of [["maximum_export_bytes", Number.MAX_SAFE_INTEGER], ["maximum_retained_bytes", Number.MAX_SAFE_INTEGER], ["maximum_inflight", 2147483647], ["capture_timeout_seconds", 120]]) requireValue(Number.isSafeInteger(policy[key]) && policy[key] >= 1 && policy[key] <= max);
  }
  requireValue(seen.has(value.currentPolicyID) && Buffer.byteLength(JSON.stringify(value.policies)) <= 131072);
  // Copy synchronously: later caller mutation cannot alter Helm input or validation pins.
  return structuredClone(value);
}

function one(resources, kind, name) {
  const rows = resources.filter(r => r?.kind === kind && r.metadata?.name === name);
  requireValue(rows.length === 1);
  return rows[0];
}
function workload(resource) {
  const pod = resource.spec?.template?.spec;
  requireValue(pod && Array.isArray(pod.containers) && pod.containers.length === 1 && !pod.initContainers?.length && !pod.ephemeralContainers?.length);
  return [pod, pod.containers[0]];
}
function envMap(container) {
  requireValue(container.envFrom === undefined && Array.isArray(container.env));
  const map = new Map();
  for (const entry of container.env) {
    requireValue(typeof entry?.name === "string" && !map.has(entry.name));
    map.set(entry.name, entry);
  }
  return map;
}
function expectEnvironment(container, expected, exact = false) {
  const map = envMap(container);
  const actualKeys = [...map.keys()].filter(k => exact || k.startsWith(prefix));
  equal(actualKeys.sort(), Object.keys(expected).sort());
  for (const [key, value] of Object.entries(expected)) {
    if (key === "ZASP_AUDIT_EXPORT_POLICIES_JSON") {
      const entry = map.get(key);
      closed(entry, ["name", "value"]);
      requireValue(typeof entry.value === "string");
      // Helm sorts JSON map keys. Exact serialization also rejects duplicate JSON keys.
      equal(entry.value, JSON.stringify(value.map(p => Object.fromEntries(Object.entries(p).sort(([a], [b]) => a.localeCompare(b))))));
    } else equal(map.get(key), typeof value === "string" ? { name: key, value } : { name: key, valueFrom: value });
  }
  return map;
}
function objects(provider) {
  requireValue(provider.spec?.provider === "aws" && typeof provider.spec?.parameters?.objects === "string");
  let entries;
  try { entries = load(provider.spec.parameters.objects); } catch { requireValue(false); }
  requireValue(Array.isArray(entries));
  const names = new Set();
  for (const entry of entries) {
    requireValue(typeof entry?.objectAlias === "string" && !names.has(entry.objectAlias));
    names.add(entry.objectAlias);
  }
  return entries;
}
function tokenVolume(name, seconds, defaultMode) {
  return { name, projected: { ...(defaultMode === undefined ? {} : { defaultMode }), sources: [{ serviceAccountToken: { audience: "sts.amazonaws.com", expirationSeconds: seconds, path: "token" } }] } };
}
function csiVolume(name, provider) { return { name, csi: { driver: "secrets-store.csi.k8s.io", readOnly: true, volumeAttributes: { secretProviderClass: provider } } }; }
function mount(name, path) { return { name, mountPath: path, readOnly: true }; }
function strings(value) {
  if (typeof value === "string") return [value];
  if (!value || typeof value !== "object") return [];
  return Object.values(value).flatMap(strings);
}

export function validateAuditExportResources(resources, expected, schemaVersion = 52, complianceExports) {
  requireValue(Array.isArray(resources));
  const marker = /ZASP_AUDIT_EXPORT_|zasp_audit_export|audit-export/;
  if (expected === undefined) {
    for (const resource of resources) requireValue(!marker.test(JSON.stringify(resource)));
    return;
  }
  requireValue([52, 53, 54, 55, 56].includes(schemaVersion));
  const trusted = validateAuditExportNetwork(resources, expected);
  for (const resource of validateAuditExportOperations(resources)) trusted.add(resource);
  for (const [index, name] of workerNames.entries()) {
    const role = index === 0 ? expected.writerRoleArn : expected.publisherRoleArn;
    const secret = index === 0 ? expected.workerDSNSecretArn : expected.outboxDSNSecretArn;
    const deployment = one(resources, "Deployment", name);
    const serviceAccount = one(resources, "ServiceAccount", name);
    const provider = one(resources, "SecretProviderClass", `${name}-secrets`);
    [deployment, serviceAccount, provider].forEach(r => trusted.add(r));
    for (const r of [deployment, serviceAccount, provider]) requireValue(r.metadata.namespace === undefined || r.metadata.namespace === "agentsec");
    const [pod, c] = workload(deployment);
    requireValue(pod.serviceAccountName === name && pod.automountServiceAccountToken === false && pod.enableServiceLinks === false && pod.terminationGracePeriodSeconds > 20);
    for (const flag of ["hostNetwork", "hostPID", "hostIPC"]) requireValue(pod[flag] === undefined || pod[flag] === false);
    equal(pod.securityContext, { runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532, seccompProfile: { type: "RuntimeDefault" } });
    requireValue(deployment.spec.replicas === 2 && deployment.spec.template.metadata?.annotations?.["zasp.io/schema-version"] === String(schemaVersion));
    equal(deployment.spec.selector?.matchLabels, { "app.kubernetes.io/name": name });
    requireValue(deployment.spec.template.metadata?.labels?.["app.kubernetes.io/name"] === name);
    requireValue(matches(c.image, /^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$/));
    equal(c.command, ["/bin/sh", "-ec"]);
    equal(c.args, ['export ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-export/postgres-dsn)"; exec /app/agentsec-worker']);
    expectEnvironment(c, {
      ZASP_WORKER_MODE: index === 0 ? "audit-export" : "audit-export-outbox", ZASP_DATABASE_AUTHORITY: index === 0 ? "zasp_audit_export_worker" : "zasp_audit_export_outbox",
      ZASP_WORKER_ID: { fieldRef: { fieldPath: "metadata.name" } }, ZASP_AWS_REGION: expected.awsRegion,
      ZASP_POLL_INTERVAL: "1s", ZASP_LEASE_DURATION: "300s", ZASP_BATCH_SIZE: "1", ZASP_SHUTDOWN_TIMEOUT: "20s", ZASP_PROVIDER_TIMEOUT: "5s",
      ZASP_AUDIT_EXPORT_QUEUE_URL: expected.queueURL, ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE: `${tokenPath}/token`,
      ...(index === 0 ? { ZASP_AUDIT_EXPORT_WRITER_ROLE_ARN: role, ZASP_AUDIT_EXPORT_POLICIES_JSON: expected.policies } : { ZASP_AUDIT_EXPORT_PUBLISHER_ROLE_ARN: role }),
    }, true);
    equal(c.volumeMounts, [mount("database", "/var/run/secrets/zasp-export"), mount("identity", tokenPath)]);
    equal(pod.volumes, [csiVolume("database", `${name}-secrets`), tokenVolume("identity", 3600)]);
    equal(c.securityContext, { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] }, privileged: false, readOnlyRootFilesystem: true, runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532 });
    equal(c.ports, [{ name: "internal", containerPort: 8081 }]);
    for (const [probe, path] of [["startupProbe", "/healthz"], ["readinessProbe", "/readyz"], ["livenessProbe", "/healthz"]]) requireValue(c[probe]?.httpGet?.path === path && c[probe]?.httpGet?.port === "internal" && c[probe].timeoutSeconds > 0 && c[probe].timeoutSeconds <= 5);
    requireValue(serviceAccount.automountServiceAccountToken === false && serviceAccount.metadata.annotations?.["eks.amazonaws.com/role-arn"] === role);
    equal(objects(provider), [{ objectName: secret, objectType: "secretsmanager", objectAlias: "postgres-dsn" }]);
    requireValue(provider.spec.parameters.region === expected.awsRegion && provider.spec.secretObjects === undefined);
  }
  const api = one(resources, "Deployment", "agentsec-api");
  const [apiPod, apiContainer] = workload(api);
  trusted.add(api);
  expectEnvironment(apiContainer, { ZASP_AUDIT_EXPORT_POLICIES_JSON: expected.policies, ZASP_AUDIT_EXPORT_READER_ROLE_ARN: expected.readerRoleArn, ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE: `${tokenPath}/token` });
  const apiEnv = envMap(apiContainer);
  requireValue(![expected.writerRoleArn, expected.publisherRoleArn, expected.readerRoleArn].includes(apiEnv.get("ZASP_CONNECTOR_ROLE_ARN")?.value));
  validateAPIStartup(apiContainer, true);
  const apiVolume = apiPod.volumes?.filter(v => v.name === "runtime-secrets");
  requireValue(apiVolume?.length === 1);
  const providerName = apiVolume[0].csi?.volumeAttributes?.secretProviderClass;
  requireValue(typeof providerName === "string");
  equal(apiVolume[0], csiVolume("runtime-secrets", providerName));
  equal(apiPod.volumes.filter(v => v.name === "connector-web-identity"), [tokenVolume("connector-web-identity", 900, 256)]);
  for (const expectedMount of [mount("runtime-secrets", "/var/run/secrets/zasp"), mount("connector-web-identity", tokenPath)]) equal(apiContainer.volumeMounts?.filter(m => m.name === expectedMount.name), [expectedMount]);
  const apiProvider = one(resources, "SecretProviderClass", providerName);
  trusted.add(apiProvider);
  equal(objects(apiProvider).filter(o => o.objectAlias === cursorAlias || o.objectName === expected.cursorSecretArn), [{ objectName: expected.cursorSecretArn, objectType: "secretsmanager", objectAlias: cursorAlias }]);
  requireValue(apiProvider.spec.parameters.region === expected.awsRegion);

  const migration = one(resources, "Job", `agentsec-schema-v${schemaVersion}`);
  trusted.add(migration);
  const [, migrationContainer] = workload(migration);
  const p = expected.policies.find(p => p.policy_id === expected.currentPolicyID);
  expectEnvironment(migrationContainer, {
    ZASP_AUDIT_EXPORT_WORKER_DB_PRINCIPAL: expected.workerPrincipal, ZASP_AUDIT_EXPORT_OUTBOX_DB_PRINCIPAL: expected.outboxPrincipal,
    ZASP_AUDIT_EXPORT_POLICY_ID: p.policy_id, ZASP_AUDIT_EXPORT_EXPECTED_CURRENT_POLICY_ID: expected.expectedCurrentPolicyID,
    ZASP_AUDIT_EXPORT_BUCKET: p.bucket, ZASP_AUDIT_EXPORT_EXPECTED_BUCKET_OWNER: p.expected_bucket_owner, ZASP_AUDIT_EXPORT_KMS_KEY_ARN: p.kms_key_arn,
    ZASP_AUDIT_EXPORT_MAXIMUM_EXPORT_BYTES: String(p.maximum_export_bytes), ZASP_AUDIT_EXPORT_MAXIMUM_RETAINED_BYTES: String(p.maximum_retained_bytes),
    ZASP_AUDIT_EXPORT_MAXIMUM_INFLIGHT: String(p.maximum_inflight), ZASP_AUDIT_EXPORT_CAPTURE_TIMEOUT_SECONDS: String(p.capture_timeout_seconds),
  });
  for (const entry of migrationContainer.env.filter(e => !e.name.startsWith(prefix))) requireValue(![expected.workerPrincipal, expected.outboxPrincipal].includes(entry.value));
  equal(migrationContainer.command, ["/bin/sh", "-ec"]);
  equal(migrationContainer.args, [complianceExports ? complianceExportMigrationCommand(schemaVersion, true) : auditExportMigrationCommand(schemaVersion)]);

  // Export secrets stay CSI-only. Unrelated resources cannot acquire export settings,
  // roles, secret references or mounted copies through sidecars or nested pod specs.
  const privateValues = [expected.workerDSNSecretArn, expected.outboxDSNSecretArn, expected.cursorSecretArn, expected.writerRoleArn, expected.publisherRoleArn, expected.readerRoleArn, providerName];
  for (const r of resources) {
    if (r.kind === "SecretProviderClass") {
      const entries = objects(r);
      requireValue(!marker.test(JSON.stringify(r.spec.secretObjects ?? [])));
      if (r === apiProvider) {
        requireValue(!entries.some(e => [expected.workerDSNSecretArn, expected.outboxDSNSecretArn].includes(e.objectName)));
        requireValue(!(r.spec.secretObjects ?? []).some(s => s.data?.some(e => e.objectName === cursorAlias)));
      }
    }
    if (!trusted.has(r)) {
      const wire = JSON.stringify(r);
      requireValue(!marker.test(wire) && !privateValues.some(value => wire.includes(value)));
    }
  }
  // Count exact typed references as well as the environment names. This prevents
  // an otherwise trusted API pod from gaining a writer identity under an alias.
  const values = resources.flatMap(strings);
  for (const r of resources.filter(r => r.kind === "SecretProviderClass")) values.push(...strings(objects(r)));
  for (const [value, count] of [
    [expected.writerRoleArn, 2], [expected.publisherRoleArn, 2], [expected.readerRoleArn, 1],
    [expected.workerDSNSecretArn, 1], [expected.outboxDSNSecretArn, 1], [expected.cursorSecretArn, 1],
    ...workerNames.map(name => [`${name}-secrets`, 2]),
  ]) equal(values.filter(actual => actual === value).length, count);
}
