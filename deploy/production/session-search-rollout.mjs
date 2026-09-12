// Manifest validation is not authorization to apply a live transition.
export function validSessionSearchPhase(schema, phase) {
  return (phase === "compatibility" && [48, 49].includes(schema)) ||
    (schema === 50 && ["backfill", "query"].includes(phase)) ||
    (schema === 51 && ["precision-consumers", "precision-intake"].includes(phase));
}

export function validateSessionSearchResources(resources, phase) {
  const precise = ["precision-consumers", "precision-intake"].includes(phase);
  const fail = () => { throw new Error("release rejected"); };
  const one = (kind, name) => {
    const rows = resources.filter(r => r.kind === kind && r.metadata?.name === name);
    if (rows.length !== 1) fail();
    return rows[0];
  };
  const container = resource => {
    const rows = resource.spec?.template?.spec?.containers;
    if (!Array.isArray(rows) || rows.length !== 1) fail();
    return rows[0];
  };
  const expectEnv = (resource, key, value) => {
    const entries = container(resource).env?.filter(e => e.name === key);
    if (entries?.length !== 1 || entries[0].value !== value || entries[0].valueFrom !== undefined) fail();
  };
  expectEnv(one("Deployment", "agentsec-api"), "ZASP_RUNTIME_SESSION_INDEX", phase === "query" || precise ? "zasp-runtime-sessions-v2" : "zasp-runtime-sessions-v1");
  if (precise) {
    expectEnv(one("Deployment", "agentsec-event-ingest"), "ZASP_RUNTIME_INGEST_SCHEMA", phase === "precision-intake" ? "runtime-event-v2" : "runtime-event-v1");
    for (const name of ["outbox", "coordinator"]) expectEnv(one("Deployment", `agentsec-runtime-${name}`), "ZASP_RUNTIME_DELIVERY_SCHEMA", "runtime-event-v2");
  } else {
    for (const [name, key] of [["agentsec-event-ingest", "ZASP_RUNTIME_INGEST_SCHEMA"], ["agentsec-runtime-outbox", "ZASP_RUNTIME_DELIVERY_SCHEMA"], ["agentsec-runtime-coordinator", "ZASP_RUNTIME_DELIVERY_SCHEMA"]]) {
      if (container(one("Deployment", name)).env?.some(e => e.name === key)) fail();
    }
  }
  for (const [name, version] of [["archive",precise ? 2 : 1], ["correlation",precise ? 4 : 2], ["projection",precise ? 3 : 1], ["complete",precise ? 3 : 1], ["index",1]]) expectEnv(one("Deployment", `agentsec-runtime-${name}`), "ZASP_RUNTIME_STAGE_VERSION", `runtime-${name}-v${version}`);
  expectEnv(one("Deployment", "agentsec-runtime-index"), "ZASP_RUNTIME_SESSION_INDEX", "zasp-runtime-sessions-v1");
  const v1init = one("Job", "agentsec-projection-search-init-v1");
  expectEnv(v1init, "ZASP_RUNTIME_SESSION_INDEX", "zasp-runtime-sessions-v1");
  for (const init of [v1init, one("Job", "agentsec-projection-graph-init-v1")]) {
    if (init.metadata.annotations?.["helm.sh/hook-weight"] !== "-7" || init.metadata.annotations?.["helm.sh/hook"] !== "pre-install,pre-upgrade") fail();
  }
  const migrations = resources.filter(r => r.kind === "Job" && r.metadata.name.startsWith("agentsec-schema-v"));
  if (migrations.length !== 1 || migrations[0].metadata.annotations?.["helm.sh/hook-weight"] !== "-10" || migrations[0].metadata.annotations?.["helm.sh/hook"] !== "pre-install,pre-upgrade") fail();
  if (phase === "compatibility") return;

  const name = "agentsec-runtime-session-index-v2";
  const worker = one("Deployment", name);
  expectEnv(worker, "ZASP_RUNTIME_SESSION_INDEX", "zasp-runtime-sessions-v2");
  expectEnv(worker, "ZASP_DATABASE_AUTHORITY", "zasp_runtime_index_worker");
  expectEnv(worker, "ZASP_WORKER_MODE", "runtime-index");
  expectEnv(worker, "ZASP_RUNTIME_STAGE_VERSION", precise ? "runtime-index-v2" : "runtime-index-v1");
  const c = container(worker);
  for (const [group, values] of Object.entries({ requests: { cpu: "100m", memory: "128Mi", "ephemeral-storage": "64Mi" }, limits: { cpu: "1", memory: "512Mi", "ephemeral-storage": "256Mi" } })) {
    for (const [key, value] of Object.entries(values)) if (c.resources?.[group]?.[key] !== value) fail();
  }
  if (worker.spec?.selector?.matchLabels?.["app.kubernetes.io/name"] !== name || worker.spec?.template?.metadata?.labels?.["app.kubernetes.io/name"] !== name || worker.spec.replicas < 1) fail();
  for (const [probe, path] of [["startupProbe", "/healthz"], ["livenessProbe", "/healthz"], ["readinessProbe", "/readyz"]]) {
    if (c[probe]?.httpGet?.path !== path || c[probe]?.httpGet?.port !== 8081 || !(c[probe].timeoutSeconds > 0 && c[probe].timeoutSeconds <= 5)) fail();
  }
  const selector = one("Service", name).spec?.selector;
  if (selector?.["app.kubernetes.io/name"] !== name || one("PodDisruptionBudget", name).spec?.selector?.matchLabels?.["app.kubernetes.io/name"] !== name || one("HorizontalPodAutoscaler", name).spec?.scaleTargetRef?.name !== name || one("ServiceMonitor", name).spec?.selector?.matchLabels?.["app.kubernetes.io/name"] !== name) fail();
  for (const policy of ["runtime-index-dependencies", "task6-runtime-monitoring"]) {
    const expressions = one("NetworkPolicy", policy).spec?.podSelector?.matchExpressions;
    if (!expressions?.some(e => e.key === "app.kubernetes.io/name" && e.operator === "In" && e.values?.includes(name))) fail();
  }
  const monitor = one("ServiceMonitor", name);
  if (monitor.spec.endpoints?.length !== 1 || monitor.spec.endpoints[0].port !== "internal" || monitor.spec.endpoints[0].path !== "/metrics" || monitor.spec.endpoints[0].scrapeTimeout !== "5s") fail();
  const ports = one("Service", name).spec.ports;
  if (ports?.length !== 1 || ports[0].name !== "internal" || ports[0].port !== 8081 || ports[0].targetPort !== "internal" || ports[0].protocol !== "TCP") fail();
  const ingress = one("NetworkPolicy", "task6-runtime-monitoring").spec;
  if (!ingress.policyTypes?.includes("Ingress") || !ingress.ingress?.some(rule => rule.ports?.some(p => p.protocol === "TCP" && p.port === 8081) && rule.from?.some(peer => peer.namespaceSelector?.matchLabels?.["kubernetes.io/metadata.name"] === "monitoring"))) fail();
  const dependencies = one("NetworkPolicy", "runtime-index-dependencies").spec;
  if (!dependencies.policyTypes?.includes("Egress")) fail();
  // These private ranges are the fixed network contract supplied by renderRelease.
  for (const [port, cidr] of [[5432, "10.30.0.0/24"], [443, "10.50.0.0/24"]]) {
    if (!dependencies.egress?.some(rule => rule.ports?.length === 1 && rule.ports[0].protocol === "TCP" && rule.ports[0].port === port && rule.to?.length === 1 && rule.to[0].ipBlock?.cidr === cidr)) fail();
  }
  const alerts = resources.filter(r => r.kind === "PrometheusRule").flatMap(r => r.spec?.groups ?? []).flatMap(g => g.rules ?? []);
  if (!alerts.some(r => r.alert === "ZaspRuntimeSessionIndexV2Unavailable" && r.expr?.includes(`deployment="${name}"`)) || !alerts.some(r => r.alert === "ZaspRuntimeSessionIndexV2NotReady" && r.expr?.includes(`service="${name}"`))) fail();
  const init = one("Job", "agentsec-projection-search-init-v2");
  expectEnv(init, "ZASP_RUNTIME_SESSION_INDEX", "zasp-runtime-sessions-v2");
  expectEnv(init, "ZASP_WORKER_MODE", "projection-search-init");
  if (init.metadata.annotations?.["helm.sh/hook-weight"] !== "-6" || init.metadata.annotations?.["helm.sh/hook"] !== "pre-install,pre-upgrade" || init.spec.activeDeadlineSeconds !== 60 || init.spec.backoffLimit !== 0) fail();
}
