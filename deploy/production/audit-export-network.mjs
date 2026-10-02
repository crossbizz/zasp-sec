import { isIP } from "node:net";
import { isDeepStrictEqual } from "node:util";

export function validAuditExportCIDRs(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 64 || Reflect.ownKeys(values).length !== values.length + 1) return false;
  if (Object.getPrototypeOf(values) !== Array.prototype || Object.entries(Object.getOwnPropertyDescriptors(values)).some(([key, descriptor]) => !("value" in descriptor) || key !== "length" && !descriptor.enumerable)) return false;
  const ranges = [];
  for (const cidr of values) {
    if (typeof cidr !== "string") return false;
    const match = /^([^/]+)\/(1[6-9]|2[0-9]|3[0-2])$/.exec(cidr);
    if (!match || isIP(match[1]) !== 4) return false;
    const octets = match[1].split(".").map(Number);
    if (octets[0] === 0 || octets[0] === 127 || octets[0] >= 224 || octets[0] === 169 && octets[1] === 254) return false;
    const start = octets.reduce((n, part) => n * 256 + part, 0);
    const size = 2 ** (32 - Number(match[2]));
    if (start % size !== 0) return false;
    ranges.push([start, start + size - 1]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  return ranges.every((range, index) => index === 0 || ranges[index - 1][1] < range[0]);
}

export function validateAuditExportNetwork(resources, expected) {
  const trusted = new Set();
  const fail = () => { throw new Error("release rejected: audit export network"); };
  const equal = (actual, wanted) => { if (!isDeepStrictEqual(actual, wanted)) fail(); };
  const one = (kind, name) => {
    const found = resources.filter(r => r.kind === kind && r.metadata?.name === name);
    if (found.length !== 1 || ![undefined, "agentsec"].includes(found[0].metadata.namespace)) fail();
    trusted.add(found[0]); return found[0];
  };
  const selector = name => ({ matchLabels: { "app.kubernetes.io/name": name } });
  const https = cidrs => ({ to: [...new Set(cidrs)].map(cidr => ({ ipBlock: { cidr } })), ports: [{ protocol: "TCP", port: 443 }] });
  const database = { to: [{ ipBlock: { cidr: "10.30.0.0/24" } }], ports: [{ protocol: "TCP", port: 5432 }] };
  const monitoring = { from: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "monitoring" } } }], ports: [{ protocol: "TCP", port: 8081 }] };
  for (const suffix of ["worker", "outbox"]) {
    const name = `zasp-audit-export-${suffix}`;
    equal(one("NetworkPolicy", `${name}-dependencies`).spec, { podSelector: selector(name), policyTypes: ["Egress"], egress: [database, https([...expected.stsCIDRs, ...expected.sqsCIDRs, ...(suffix === "worker" ? expected.s3CIDRs : [])])] });
    equal(one("NetworkPolicy", `${name}-monitoring`).spec, { podSelector: selector(name), policyTypes: ["Ingress"], ingress: [monitoring] });
    const labels = { "app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "zasp" };
    equal(one("Deployment", name).spec.template.metadata.labels, labels);
    const service = one("Service", name);
    equal(service.metadata.labels, labels);
    equal(service.spec, { type: "ClusterIP", selector: selector(name).matchLabels, ports: [{ name: "internal", port: 8081, targetPort: "internal", protocol: "TCP" }] });
    equal(one("PodDisruptionBudget", name).spec, { minAvailable: 1, selector: selector(name) });
    equal(one("ServiceMonitor", name).spec, { selector: { matchLabels: labels }, namespaceSelector: { matchNames: ["agentsec"] }, endpoints: [{ port: "internal", path: "/metrics", interval: "30s", scrapeTimeout: "5s" }] });
  }
  equal(one("NetworkPolicy", "zasp-audit-export-api-dependencies").spec, { podSelector: selector("agentsec-api"), policyTypes: ["Egress"], egress: [https([...expected.stsCIDRs, ...expected.s3CIDRs])] });
  // NetworkPolicies are additive. A second policy must not silently widen either
  // worker's access, even when its own name does not mention audit exports.
  const inherited = new Set();
  const inheritedPolicy = name => {
    const found = resources.filter(r => r.kind === "NetworkPolicy" && r.metadata?.name === name);
    if (found.length !== 1 || ![undefined, "agentsec"].includes(found[0].metadata.namespace)) fail();
    inherited.add(found[0]); return found[0];
  };
  equal(inheritedPolicy("default-deny").spec, { podSelector: {}, policyTypes: ["Ingress", "Egress"] });
  equal(inheritedPolicy("dns-egress").spec, {
    podSelector: { matchLabels: { "app.kubernetes.io/part-of": "zasp" }, matchExpressions: [{ key: "app.kubernetes.io/name", operator: "NotIn", values: ["zasp-test-reconciler", "security-agent-attack-lab-reconciler", ...(resources.some(r => r.kind === "Deployment" && r.metadata?.name === "zasp-compliance-export-worker") ? ["zasp-compliance-export-worker", "zasp-compliance-cleanup-worker"] : [])] }] }, policyTypes: ["Egress"],
    egress: [{ to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "kube-system" } } }], ports: [{ protocol: "UDP", port: 53 }, { protocol: "TCP", port: 53 }] }],
  });
  for (const policy of resources.filter(r => r.kind === "NetworkPolicy" && [undefined, "agentsec"].includes(r.metadata?.namespace) && !trusted.has(r) && !inherited.has(r))) {
    for (const suffix of ["worker", "outbox"]) {
      const labels = { "app.kubernetes.io/name": `zasp-audit-export-${suffix}`, "app.kubernetes.io/part-of": "zasp" };
      const selected = policy.spec?.podSelector;
      if (!selected) fail();
      const matchesLabels = Object.entries(selected.matchLabels ?? {}).every(([key, value]) => labels[key] === value);
      const matchesExpressions = (selected.matchExpressions ?? []).every(expression => {
        switch (expression.operator) {
          case "In": return expression.values?.includes(labels[expression.key]);
          case "NotIn": return !expression.values?.includes(labels[expression.key]);
          case "Exists": return Object.hasOwn(labels, expression.key);
          case "DoesNotExist": return !Object.hasOwn(labels, expression.key);
          default: fail(); return false;
        }
      });
      if (matchesLabels && matchesExpressions) fail();
    }
  }
  return trusted;
}
