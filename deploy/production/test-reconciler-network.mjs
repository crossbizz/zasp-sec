import { isDeepStrictEqual } from "node:util";
import { validAuditExportCIDRs } from "./audit-export-network.mjs";

const name = "zasp-test-reconciler";
const labels = { "app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "zasp" };
const selector = { matchLabels: { "app.kubernetes.io/name": name } };
function requireValue(value) { if (!value) throw new Error("release rejected: test reconciler network"); }
function equal(value, expected) { requireValue(isDeepStrictEqual(value, expected)); }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }

function selects(value) {
  requireValue(object(value) && Object.keys(value).every(k => ["matchLabels", "matchExpressions"].includes(k)));
  const matchLabels = value.matchLabels ?? {}, expressions = value.matchExpressions ?? [];
  requireValue(object(matchLabels) && Object.values(matchLabels).every(v => typeof v === "string") && Array.isArray(expressions));
  // Validate every expression, even when a preceding label doesn't match.
  const results = expressions.map(expression => {
    requireValue(object(expression) && Object.keys(expression).every(k => ["key", "operator", "values"].includes(k)) && typeof expression.key === "string" && expression.key.length > 0);
    const { key, operator, values } = expression;
    const present = Object.hasOwn(labels, key);
    switch (operator) {
      case "In":
      case "NotIn": {
        requireValue(Array.isArray(values) && values.length > 0 && values.every(v => typeof v === "string"));
        const contains = present && values.includes(labels[key]);
        return operator === "In" ? contains : !contains;
      }
      case "Exists":
      case "DoesNotExist":
        requireValue(values === undefined || Array.isArray(values) && values.length === 0);
        return operator === "Exists" ? present : !present;
      default: requireValue(false); return false;
    }
  });
  return Object.entries(matchLabels).every(([key, value]) => labels[key] === value) && results.every(Boolean);
}

// NetworkPolicy permissions are additive. Validate the actual selected policy
// set, not just the policy named after this worker. Configuration is normalized
// separately against the platform account before this rendered-artifact check.
export function validateTestReconcilerNetwork(resources, expected) {
  requireValue(Array.isArray(resources) && object(expected));
  for (const field of ["databaseCIDRs", "stsCIDRs", "s3CIDRs", "kmsCIDRs"]) requireValue(validAuditExportCIDRs(expected[field]));
  const one = (kind, resourceName) => {
    const matches = resources.filter(r => r?.kind === kind && r.metadata?.name === resourceName);
    requireValue(matches.length === 1 && [undefined, "agentsec"].includes(matches[0].metadata.namespace));
    return matches[0];
  };
  equal(one("Deployment", name).spec?.template?.metadata?.labels, labels);
  const dependencies = one("NetworkPolicy", `${name}-dependencies`);
  const targets = cidrs => cidrs.map(cidr => ({ ipBlock: { cidr } }));
  equal(dependencies.spec, {
    podSelector: selector, policyTypes: ["Ingress", "Egress"],
    ingress: [{ from: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "monitoring" } } }], ports: [{ protocol: "TCP", port: 8081 }] }],
    egress: [
      { to: targets(expected.databaseCIDRs), ports: [{ protocol: "TCP", port: 5432 }] },
      { to: targets([...new Set([...expected.stsCIDRs, ...expected.s3CIDRs, ...expected.kmsCIDRs])]), ports: [{ protocol: "TCP", port: 443 }] },
      { to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "kube-system" } }, podSelector: { matchLabels: { "k8s-app": "kube-dns" } } }], ports: [{ protocol: "UDP", port: 53 }, { protocol: "TCP", port: 53 }] },
    ],
  });
  const deny = one("NetworkPolicy", "default-deny");
  equal(deny.spec, { podSelector: {}, policyTypes: ["Ingress", "Egress"] });
  for (const policy of resources.filter(r => r?.kind === "NetworkPolicy" && [undefined, "agentsec"].includes(r.metadata?.namespace))) {
    if (policy === dependencies || policy === deny) continue;
    requireValue(!selects(policy.spec?.podSelector));
  }
  return new Set([dependencies, deny]);
}
