import { isDeepStrictEqual } from "node:util";

const names = ["agentsec-security-agent", "agentsec-attack-lab-outbox", "agentsec-attack-lab-controller", "agentsec-attack-lab-proxy", "security-agent-attack-lab-reconciler"];
const prefix = "ZASP_SECURITY_AGENT_ATTACK_LAB_WORKFLOW";
const policyPrefix = "attack-lab-workflow-readiness-";
const apiSelector = { matchLabels: { "app.kubernetes.io/name": "agentsec-api" } };
const workers = { matchExpressions: [{ key: "app.kubernetes.io/name", operator: "In", values: names }] };
const ports = [{ protocol: "TCP", port: 8081 }];
function requireValue(value) { if (!value) throw new Error("release rejected: attack lab workflow readiness"); }
function equal(value, expected) { requireValue(isDeepStrictEqual(value, expected)); }

export function validateAttackLabWorkflowReadiness(resources, enabled) {
  const one = (kind, name) => {
    const values = resources.filter(r => r.kind === kind && r.metadata?.name === name);
    requireValue(values.length === 1 && [undefined, "agentsec"].includes(values[0].metadata.namespace));
    return values[0];
  };
  const api = one("Deployment", "agentsec-api").spec.template.spec.containers[0];
  const entries = api.env.filter(e => e.name.startsWith(prefix));
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
  return new Set([ingress, egress]);
}
