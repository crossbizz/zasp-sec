import { isDeepStrictEqual } from "node:util";

const names = ["zasp-compliance-export-worker", "zasp-compliance-cleanup-worker"];
const requireValue = v => { if (!v) throw new Error("release rejected"); };
const equal = (a, b) => requireValue(isDeepStrictEqual(a, b));
const object = v => v !== null && typeof v === "object" && !Array.isArray(v);
function selects(selector, labels) {
  requireValue(object(selector) && Object.keys(selector).every(k => ["matchLabels", "matchExpressions"].includes(k)));
  const matches = selector.matchLabels ?? {}, expressions = selector.matchExpressions ?? [];
  requireValue(object(matches) && Object.values(matches).every(v => typeof v === "string") && Array.isArray(expressions));
  const results = expressions.map(e => {
    requireValue(object(e) && Object.keys(e).every(k => ["key", "operator", "values"].includes(k)) && typeof e.key === "string" && e.key.length > 0);
    const present = Object.hasOwn(labels, e.key);
    if (["In", "NotIn"].includes(e.operator)) {
      requireValue(Array.isArray(e.values) && e.values.length > 0 && e.values.every(v => typeof v === "string"));
      const contains = present && e.values.includes(labels[e.key]);
      return e.operator === "In" ? contains : !contains;
    }
    requireValue(["Exists", "DoesNotExist"].includes(e.operator) && (e.values === undefined || Array.isArray(e.values) && e.values.length === 0));
    return e.operator === "Exists" ? present : !present;
  });
  return Object.entries(matches).every(([k, v]) => labels[k] === v) && results.every(Boolean);
}
export function validateComplianceExportNetwork(resources, config) {
  const trusted = new Set();
  const one = (kind, name) => {
    const rows = resources.filter(r => r.kind === kind && r.metadata?.name === name);
    requireValue(rows.length === 1 && [undefined, "agentsec"].includes(rows[0].metadata.namespace));
    trusted.add(rows[0]); return rows[0];
  };
  const selector = name => ({ matchLabels: { "app.kubernetes.io/name": name } });
  const targets = cidrs => cidrs.map(cidr => ({ ipBlock: { cidr } }));
  const https = { to: targets([...new Set([...config.stsCIDRs, ...config.s3CIDRs])]), ports: [{ protocol: "TCP", port: 443 }] };
  const dns = { to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "kube-system" } }, podSelector: { matchLabels: { "k8s-app": "kube-dns" } } }], ports: [{ protocol: "UDP", port: 53 }, { protocol: "TCP", port: 53 }] };
  const rules = [];
  for (const [i, name] of names.entries()) {
    const labels = { "app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "zasp" };
    equal(one("NetworkPolicy", `${name}-dependencies`).spec, { podSelector: selector(name), policyTypes: ["Ingress", "Egress"], ingress: [{ from: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "monitoring" } } }], ports: [{ protocol: "TCP", port: 8081 }] }], egress: [{ to: targets(config.databaseCIDRs), ports: [{ protocol: "TCP", port: 5432 }] }, https, dns] });
    const service = one("Service", name);
    equal(service.metadata.labels, labels);
    equal(service.spec, { type: "ClusterIP", selector: selector(name).matchLabels, ports: [{ name: "internal", port: 8081, targetPort: "internal", protocol: "TCP" }] });
    equal(one("PodDisruptionBudget", name).spec, { minAvailable: 1, selector: selector(name) });
    equal(one("ServiceMonitor", name).spec, { selector: { matchLabels: labels }, namespaceSelector: { matchNames: ["agentsec"] }, endpoints: [{ port: "internal", path: "/metrics", interval: "30s", scrapeTimeout: "5s" }] });
    const deployment = one("Deployment", name);
    equal(deployment.spec.strategy, { type: "RollingUpdate", rollingUpdate: { maxSurge: 1, maxUnavailable: 0 } });
    equal(deployment.spec.template.spec.topologySpreadConstraints, [{ maxSkew: 1, topologyKey: "topology.kubernetes.io/zone", whenUnsatisfiable: "DoNotSchedule", labelSelector: selector(name) }, { maxSkew: 1, topologyKey: "kubernetes.io/hostname", whenUnsatisfiable: "ScheduleAnyway", labelSelector: selector(name) }]);
    equal(one("HorizontalPodAutoscaler", name).spec, { scaleTargetRef: { apiVersion: "apps/v1", kind: "Deployment", name }, minReplicas: 2, maxReplicas: 6, behavior: { scaleUp: { stabilizationWindowSeconds: 60, policies: [{ type: "Percent", value: 100, periodSeconds: 60 }] }, scaleDown: { stabilizationWindowSeconds: 300, policies: [{ type: "Percent", value: 25, periodSeconds: 60 }] } }, metrics: [{ type: "Resource", resource: { name: "cpu", target: { type: "Utilization", averageUtilization: 70 } } }] });
    const available = `kube_deployment_status_replicas_available{namespace="agentsec",deployment="${name}"}`, up = `up{namespace="agentsec",service="${name}"}`, ready = `agentsec_ready{namespace="agentsec",service="${name}"}`;
    const alert = i === 0 ? "ZaspComplianceExportWorker" : "ZaspComplianceCleanupWorker";
    rules.push({ alert: `${alert}Unavailable`, expr: `${available} < 1 or absent(${available})`, for: "5m", labels: { severity: "page" }, annotations: { summary: "Compliance export workload is unavailable or absent" } }, { alert: `${alert}NotReady`, expr: `${ready} == 0 or ${up} == 0 or (${up} == 1 unless on (namespace,service,instance) ${ready}) or absent(${up})`, for: "10m", labels: { severity: "ticket" }, annotations: { summary: "Compliance export worker readiness is unavailable" } });
  }
  equal(one("PrometheusRule", "zasp-compliance-export-availability").spec, { groups: [{ name: "zasp.compliance-export.availability", rules }] });
  equal(one("NetworkPolicy", "zasp-compliance-export-api-dependencies").spec, { podSelector: selector("agentsec-api"), policyTypes: ["Egress"], egress: [https] });
  equal(one("NetworkPolicy", "default-deny").spec, { podSelector: {}, policyTypes: ["Ingress", "Egress"] });
  equal(one("NetworkPolicy", "dns-egress").spec, { podSelector: { matchLabels: { "app.kubernetes.io/part-of": "zasp" }, matchExpressions: [{ key: "app.kubernetes.io/name", operator: "NotIn", values: ["zasp-test-reconciler", ...names] }] }, policyTypes: ["Egress"], egress: [{ to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "kube-system" } } }], ports: [{ protocol: "UDP", port: 53 }, { protocol: "TCP", port: 53 }] }] });
  for (const policy of resources.filter(r => r.kind === "NetworkPolicy" && [undefined, "agentsec"].includes(r.metadata?.namespace) && !trusted.has(r))) for (const name of names) requireValue(!selects(policy.spec?.podSelector, { "app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "zasp" }));
  for (const binding of resources.filter(r => ["RoleBinding", "ClusterRoleBinding"].includes(r.kind))) {
    requireValue(Array.isArray(binding.subjects));
    for (const s of binding.subjects) {
      requireValue(object(s) && typeof s.kind === "string" && typeof s.name === "string");
      const ns = s.namespace ?? binding.metadata?.namespace ?? "agentsec";
      requireValue(!(s.kind === "ServiceAccount" && ns === "agentsec" && names.includes(s.name)));
      requireValue(!(s.kind === "User" && names.some(n => s.name === `system:serviceaccount:agentsec:${n}`)));
      requireValue(!(s.kind === "Group" && ["system:serviceaccounts", "system:serviceaccounts:agentsec", "system:authenticated"].includes(s.name)));
    }
  }
  return trusted;
}
