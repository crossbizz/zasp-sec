import { isDeepStrictEqual } from "node:util";

export function validateAuditExportOperations(resources) {
  const trusted = new Set();
  const fail = () => { throw new Error("release rejected: audit export operations"); };
  const equal = (actual, expected) => { if (!isDeepStrictEqual(actual, expected)) fail(); };
  const one = (kind, name) => {
    const found = resources.filter(r => r.kind === kind && r.metadata?.name === name);
    if (found.length !== 1 || ![undefined, "agentsec"].includes(found[0].metadata.namespace)) fail();
    trusted.add(found[0]); return found[0];
  };
  const rules = [];
  for (const [suffix, prefix] of [["worker", "ZaspAuditExportWorker"], ["outbox", "ZaspAuditExportOutbox"]]) {
    const name = `zasp-audit-export-${suffix}`;
    const deploymentResource = one("Deployment", name);
    equal(deploymentResource.spec.strategy, { type: "RollingUpdate", rollingUpdate: { maxSurge: 1, maxUnavailable: 0 } });
    equal(deploymentResource.spec.template.spec.containers?.[0]?.resources?.requests?.cpu, "100m");
    equal(deploymentResource.spec.template.spec.topologySpreadConstraints, [
      { maxSkew: 1, topologyKey: "topology.kubernetes.io/zone", whenUnsatisfiable: "DoNotSchedule", labelSelector: { matchLabels: { "app.kubernetes.io/name": name } } },
      { maxSkew: 1, topologyKey: "kubernetes.io/hostname", whenUnsatisfiable: "ScheduleAnyway", labelSelector: { matchLabels: { "app.kubernetes.io/name": name } } },
    ]);
    equal(one("HorizontalPodAutoscaler", name).spec, {
      scaleTargetRef: { apiVersion: "apps/v1", kind: "Deployment", name }, minReplicas: 2, maxReplicas: 10,
      behavior: { scaleUp: { stabilizationWindowSeconds: 60, policies: [{ type: "Percent", value: 100, periodSeconds: 60 }] }, scaleDown: { stabilizationWindowSeconds: 300, policies: [{ type: "Percent", value: 25, periodSeconds: 60 }] } },
      metrics: [{ type: "Resource", resource: { name: "cpu", target: { type: "Utilization", averageUtilization: 70 } } }],
    });
    const deployment = `kube_deployment_status_replicas_available{namespace="agentsec",deployment="${name}"}`;
    const up = `up{namespace="agentsec",service="${name}"}`;
    const ready = `agentsec_ready{namespace="agentsec",service="${name}"}`;
    rules.push(
      { alert: `${prefix}Unavailable`, expr: `${deployment} < 1 or absent(${deployment})`, for: "5m", labels: { severity: "page" }, annotations: { summary: "Audit export workload is unavailable or absent" } },
      { alert: `${prefix}NotReady`, expr: `${ready} == 0 or ${up} == 0 or (${up} == 1 unless on (namespace,service,instance) ${ready}) or absent(${up})`, for: "10m", labels: { severity: "ticket" }, annotations: { summary: "Audit export worker readiness is unavailable" } },
    );
  }
  equal(one("PrometheusRule", "zasp-audit-export-availability").spec, { groups: [{ name: "zasp.audit-export.availability", rules }] });
  return trusted;
}
