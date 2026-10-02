import { execFile } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const fail = () => { throw new Error("schema60 transition rejected"); };
const identity = value => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/.test(value);
const immutableImage = value => typeof value === "string" && /^[^\s]+@sha256:[a-f0-9]{64}$/.test(value);
const absolute = value => typeof value === "string" && path.isAbsolute(value);

function validateOptions(options) {
  if (!options || !absolute(options.kubeconfig) || !absolute(options.chart) || !Array.isArray(options.values) || options.values.length < 1 || options.values.some(value => !absolute(value))) fail();
  for (const value of [options.context, options.namespace, options.namespaceUID, options.release]) if (!identity(value)) fail();
  if (!immutableImage(options.expectedSchedulerImage)) fail();
}

function helmArgs(options, schema, phase) {
  return [
    "upgrade", "--install", options.release, options.chart,
    "--kubeconfig", options.kubeconfig,
    "--kube-context", options.context,
    "--namespace", options.namespace,
    "--atomic", "--wait", "--timeout", "15m",
    ...options.values.flatMap(value => ["-f", value]),
    "--set-string", `schema.expectedVersion=${schema}`,
    "--set-string", `rollout.discoveryScheduleReplayPhase=${phase}`,
  ];
}

function parseJSON(stdout) {
  if (typeof stdout !== "string" || Buffer.byteLength(stdout) > 4 * 1024 * 1024) fail();
  try { return JSON.parse(stdout); } catch { fail(); }
}

function validNamespace(value, options) {
  return value?.apiVersion === "v1" && value.kind === "Namespace" && value.metadata?.name === options.namespace && value.metadata.uid === options.namespaceUID && !value.metadata.deletionTimestamp;
}

function schedulerContainer(deployment, options, schema) {
  if (deployment?.apiVersion !== "apps/v1" || deployment.kind !== "Deployment" || deployment.metadata?.name !== "agentsec-discovery-scheduler" || deployment.metadata.namespace !== options.namespace || deployment.metadata.deletionTimestamp) fail();
  if (!Number.isSafeInteger(deployment.metadata.generation) || deployment.metadata.generation < 1 || deployment.status?.observedGeneration !== deployment.metadata.generation) fail();
  if (deployment.spec?.template?.metadata?.annotations?.["zasp.io/schema-version"] !== String(schema)) fail();
  const containers = deployment.spec?.template?.spec?.containers;
  if (!Array.isArray(containers) || containers.length !== 1 || containers[0].name !== "scheduler" || containers[0].image !== options.expectedSchedulerImage) fail();
  return containers[0];
}

function validateMaintenance(deployment, pods, hpas, options) {
  schedulerContainer(deployment, options, 59);
  if (deployment.spec.replicas !== 0) fail();
  for (const field of ["replicas", "updatedReplicas", "readyReplicas", "availableReplicas", "unavailableReplicas", "terminatingReplicas"]) if ((deployment.status?.[field] ?? 0) !== 0) fail();
  if (pods.length !== 0 || hpas.some(item => item.metadata?.name === "agentsec-discovery-scheduler")) fail();
}

function validateActive(deployment, pods, hpas, options) {
  schedulerContainer(deployment, options, 60);
  if (deployment.spec.replicas !== 2) fail();
  for (const field of ["replicas", "updatedReplicas", "readyReplicas", "availableReplicas"]) if (deployment.status?.[field] !== 2) fail();
  if ((deployment.status.unavailableReplicas ?? 0) !== 0 || (deployment.status.terminatingReplicas ?? 0) !== 0 || pods.length !== 2) fail();
  const expectedDigest = options.expectedSchedulerImage.slice(options.expectedSchedulerImage.indexOf("@sha256:"));
  for (const pod of pods) {
    if (pod.apiVersion !== "v1" || pod.kind !== "Pod" || pod.metadata?.namespace !== options.namespace || pod.metadata.deletionTimestamp || pod.status?.phase !== "Running") fail();
    if (pod.status.conditions?.filter(condition => condition.type === "Ready" && condition.status === "True").length !== 1) fail();
    const containers = pod.spec?.containers;
    const statuses = pod.status?.containerStatuses;
    if (!Array.isArray(containers) || containers.length !== 1 || containers[0].name !== "scheduler" || containers[0].image !== options.expectedSchedulerImage) fail();
    if (!Array.isArray(statuses) || statuses.length !== 1 || statuses[0].name !== "scheduler" || statuses[0].ready !== true || typeof statuses[0].imageID !== "string" || !statuses[0].imageID.endsWith(expectedDigest)) fail();
  }
  const schedulerHPAs = hpas.filter(item => item.metadata?.name === "agentsec-discovery-scheduler");
  if (schedulerHPAs.length !== 1 || schedulerHPAs[0].apiVersion !== "autoscaling/v2" || schedulerHPAs[0].kind !== "HorizontalPodAutoscaler" || schedulerHPAs[0].metadata.namespace !== options.namespace || schedulerHPAs[0].metadata.deletionTimestamp || schedulerHPAs[0].spec?.scaleTargetRef?.apiVersion !== "apps/v1" || schedulerHPAs[0].spec.scaleTargetRef.kind !== "Deployment" || schedulerHPAs[0].spec.scaleTargetRef.name !== "agentsec-discovery-scheduler") fail();
}

export async function executeDiscoverySchema60Transition(options, { run = exec } = {}) {
  validateOptions(options);
  const settings = { encoding: "utf8", timeout: 16 * 60 * 1000, maxBuffer: 4 * 1024 * 1024 };
  const kubectlBase = ["--kubeconfig", options.kubeconfig, "--context", options.context];
  const read = async (resource, extra = []) => {
    const { stdout } = await run("kubectl", [...kubectlBase, "get", resource, ...extra, "--output=json", "--request-timeout=10s"], settings);
    return parseJSON(stdout);
  };
  const readList = async (resource, selector, apiVersion, kind) => {
    const value = await read(resource, ["--namespace", options.namespace, "--selector", selector]);
    const generic = value.apiVersion === "v1" && value.kind === "List";
    const typed = value.apiVersion === apiVersion && value.kind === `${kind}List`;
    if ((!generic && !typed) || !Array.isArray(value.items)) fail();
    return value.items;
  };
  const observe = async (schema, phase) => {
    if (!validNamespace(await read("namespace", [options.namespace]), options)) fail();
    const deployment = await read("deployment", ["agentsec-discovery-scheduler", "--namespace", options.namespace]);
    const pods = await readList("pods", "app.kubernetes.io/name=agentsec-discovery-scheduler", "v1", "Pod");
    const hpas = await readList("horizontalpodautoscalers", "app.kubernetes.io/name=agentsec-discovery-scheduler", "autoscaling/v2", "HorizontalPodAutoscaler");
    if (phase === "maintenance") validateMaintenance(deployment, pods, hpas, options);
    else validateActive(deployment, pods, hpas, options);
    return { deployment, pods, hpas, schema };
  };

  try {
    if (!validNamespace(await read("namespace", [options.namespace]), options)) fail();
    await run("helm", helmArgs(options, 59, "maintenance"), settings);
    await observe(59, "maintenance");
    await run("helm", helmArgs(options, 60, "active"), settings);
    const active = await observe(60, "active");
    return { namespaceUID: options.namespaceUID, maintenanceSchema: 59, activeSchema: 60, schedulerImage: options.expectedSchedulerImage, replicas: active.deployment.spec.replicas };
  } catch { fail(); }
}

function parseArguments(argv) {
  const options = { values: [] };
  const names = new Map([
    ["--kubeconfig", "kubeconfig"], ["--context", "context"], ["--namespace", "namespace"], ["--namespace-uid", "namespaceUID"],
    ["--release", "release"], ["--chart", "chart"], ["--scheduler-image", "expectedSchedulerImage"],
  ]);
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === "--values" && value !== undefined) options.values.push(value);
    else if (names.has(flag) && value !== undefined && options[names.get(flag)] === undefined) options[names.get(flag)] = value;
    else fail();
  }
  return options;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  executeDiscoverySchema60Transition(parseArguments(process.argv.slice(2)))
    .then(result => process.stdout.write(`${JSON.stringify(result)}\n`))
    .catch(() => { process.stderr.write("schema60 transition rejected\n"); process.exitCode = 1; });
}
