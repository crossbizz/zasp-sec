import { isDeepStrictEqual } from "node:util";

const names = ["agentsec-security-agent", "agentsec-security-agent-action", "zasp-compliance-export-worker", "zasp-compliance-cleanup-worker"];
const prefix = "ZASP_SECURITY_AGENT_EVIDENCE_EXPORT_WORKFLOW";
const policyPrefix = "export-workflow-readiness-";
const apiSelector = { matchLabels: { "app.kubernetes.io/name": "agentsec-api" } };
const workers = { matchExpressions: [{ key: "app.kubernetes.io/name", operator: "In", values: names }] };
const ports = [{ protocol: "TCP", port: 8081 }];
function requireValue(value) { if (!value) throw new Error("release rejected: export workflow readiness"); }
function equal(actual, expected) { requireValue(isDeepStrictEqual(actual, expected)); }
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const labelValue = value => typeof value === "string" && value.length <= 63 && /^(?:[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?)?$/.test(value);
function labelKey(key) {
  if (typeof key !== "string") return false;
  const parts = key.split("/"), name = parts.at(-1);
  return parts.length <= 2 && name.length > 0 && labelValue(name) && (parts.length === 1 ||
    parts[0].length <= 253 && parts[0].split(".").every(part => part.length <= 63 && /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/.test(part)));
}
function maySelect(selector, fixedLabels) {
  requireValue(object(selector) && Object.keys(selector).every(key => ["matchLabels", "matchExpressions"].includes(key)));
  const matches = selector.matchLabels === undefined ? {} : selector.matchLabels;
  const expressions = selector.matchExpressions === undefined ? [] : selector.matchExpressions;
  requireValue(object(matches) && Array.isArray(expressions));
  // Validate every requirement before deciding disjointness: a contradiction must
  // not hide a malformed later requirement. Non-identity labels are unconstrained,
  // including labels added by Deployment controllers such as pod-template-hash.
  const labelMatches = Object.entries(matches).map(([key, value]) => {
    requireValue(labelKey(key) && labelValue(value));
    return !Object.hasOwn(fixedLabels, key) || fixedLabels[key] === value;
  });
  const expressionMatches = expressions.map(expression => {
    requireValue(object(expression) && Object.keys(expression).every(key => ["key", "operator", "values"].includes(key)) && labelKey(expression.key));
    const { key, operator, values } = expression;
    if (["In", "NotIn"].includes(operator)) {
      requireValue(Array.isArray(values) && values.length > 0 && values.every(labelValue));
      if (!Object.hasOwn(fixedLabels, key)) return true;
      return operator === "In" ? values.includes(fixedLabels[key]) : !values.includes(fixedLabels[key]);
    }
    requireValue(["Exists", "DoesNotExist"].includes(operator) && (values === undefined || Array.isArray(values) && values.length === 0));
    return !Object.hasOwn(fixedLabels, key) || operator === "Exists";
  });
  return labelMatches.every(Boolean) && expressionMatches.every(Boolean);
}

export function normalizeEvidenceExportWorkflow(value, schemaVersion, complianceExports) {
  if (value === undefined) return undefined;
  requireValue(value === true && schemaVersion === 58 && complianceExports?.enabled === true);
  return true;
}

// The returned policies are trusted only after their complete private scope is checked.
export function validateExportWorkflowReadiness(resources, enabled) {
  const one = (kind, name) => {
    const rows = resources.filter(r => r.kind === kind && r.metadata?.name === name);
    requireValue(rows.length === 1 && [undefined, "agentsec"].includes(rows[0].metadata.namespace));
    return rows[0];
  };
  const api = one("Deployment", "agentsec-api");
  for (const resource of resources) if (resource !== api) requireValue(!JSON.stringify(resource).includes(prefix));
  const entries = api.spec.template.spec.containers[0].env.filter(e => e.name.startsWith(prefix));
  const policies = resources.filter(r => r.kind === "NetworkPolicy" && r.metadata?.name?.startsWith(policyPrefix));
  if (!enabled) { equal(entries, []); equal(policies, []); return new Set(); }
  equal(entries, [{ name: prefix, value: "enabled" }]);
  requireValue(policies.length === 2);
  const ingress = one("NetworkPolicy", `${policyPrefix}ingress`), egress = one("NetworkPolicy", `${policyPrefix}egress`);
  for (const policy of [ingress, egress]) requireValue(policy.apiVersion === "networking.k8s.io/v1");
  equal(ingress.spec, { podSelector: workers, policyTypes: ["Ingress"], ingress: [{ from: [{ podSelector: apiSelector }], ports }] });
  equal(egress.spec, { podSelector: apiSelector, policyTypes: ["Egress"], egress: [{ to: [{ podSelector: workers }], ports }] });
  for (const name of names) {
    const service = one("Service", name), pod = one("Deployment", name).spec.template;
    equal(service.spec.selector, { "app.kubernetes.io/name": name });
    requireValue(service.spec.type === "ClusterIP" && service.spec.externalName === undefined && service.spec.externalIPs === undefined);
    equal(service.spec.ports.filter(p => p.name === "internal"), [{ name: "internal", port: 8081, targetPort: "internal", protocol: "TCP" }]);
    requireValue(pod.metadata.labels["app.kubernetes.io/name"] === name);
    const internal = pod.spec.containers.flatMap(c => c.ports ?? []).filter(p => p.name === "internal");
    requireValue(internal.length === 1 && internal[0].containerPort === 8081 && [undefined, "TCP"].includes(internal[0].protocol));
  }
  const monitoring = resources.filter(r => r.kind === "NetworkPolicy" && r.metadata?.name === "task4-worker-monitoring");
  requireValue(monitoring.length === 1);
  equal(monitoring[0].spec, { podSelector: { matchExpressions: [{ key: "app.kubernetes.io/name", operator: "In", values: ["agentsec-discovery-scheduler", "agentsec-security-agent", "agentsec-outbox-publisher"] }] }, policyTypes: ["Ingress"], ingress: [{ from: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "monitoring" } } }], ports }] });
  const laterValidated = new Set(["zasp-compliance-export-worker-dependencies", "zasp-compliance-cleanup-worker-dependencies", "attack-lab-workflow-readiness-ingress"]);
  for (const policy of resources.filter(r => r.kind === "NetworkPolicy" && ![ingress, egress, monitoring[0]].includes(r) && (r.spec?.ingress?.length ?? 0) > 0)) {
    const selectsWorker = names.some(name => maySelect(policy.spec?.podSelector, { "app.kubernetes.io/name": name }));
    requireValue(!selectsWorker || laterValidated.has(policy.metadata?.name));
  }
  return new Set([ingress, egress]);
}
