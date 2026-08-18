import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  AWS_EMULATOR_CONSTANTS,
  LOCALSTACK_IMAGE,
  buildAwsEmulatorCoreResources,
  buildAwsEmulatorResources,
  buildAwsEmulatorS3Resources,
  parseAwsEmulatorManifest,
  renderAwsEmulatorCoreManifest,
  renderAwsEmulatorS3Manifest,
  validateAwsEmulatorResources,
} from "./aws-emulator-manifest.mjs";

const image = "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c";
const endpoint = "http://localstack.zasp-local.svc.cluster.local:4566";

function clone(value) {
  return structuredClone(value);
}

test("builds the exact split AWS emulator resources and committed bytes", async () => {
  assert.equal(LOCALSTACK_IMAGE, image);
  assert.deepEqual(AWS_EMULATOR_CONSTANTS, {
    namespace: "zasp-local",
    configName: "local-aws-endpoints",
    localstackName: "localstack",
    s3JobName: "localstack-s3-probe",
    endpoint,
    port: 4566,
    region: "us-east-1",
    successMarker: "localstack-s3-endpoint-ready",
  });

  const all = buildAwsEmulatorResources();
  const core = buildAwsEmulatorCoreResources();
  const s3 = buildAwsEmulatorS3Resources();
  assert.deepEqual(all.map(({ kind }) => kind), ["ConfigMap", "Deployment", "Service", "Job"]);
  assert.deepEqual(core, all.slice(0, 3));
  assert.deepEqual(s3, all.slice(3));
  assert.ok(Object.isFrozen(all));
  assert.throws(() => buildAwsEmulatorResources("input"), TypeError);
  assert.throws(() => buildAwsEmulatorCoreResources({}), TypeError);
  assert.throws(() => buildAwsEmulatorS3Resources([]), TypeError);

  const [coreText, s3Text] = await Promise.all([
    readFile(new URL("./aws-emulator.yaml", import.meta.url), "utf8"),
    readFile(new URL("./aws-emulator-s3.yaml", import.meta.url), "utf8"),
  ]);
  assert.equal(renderAwsEmulatorCoreManifest(core), coreText);
  assert.equal(renderAwsEmulatorS3Manifest(s3), s3Text);
  assert.deepEqual(parseAwsEmulatorManifest(coreText, "core"), core);
  assert.deepEqual(parseAwsEmulatorManifest(s3Text, "s3"), s3);
  assert.throws(() => parseAwsEmulatorManifest(coreText, "s3"), TypeError);
  assert.throws(() => parseAwsEmulatorManifest(s3Text, "core"), TypeError);
  assert.deepEqual(validateAwsEmulatorResources(all), all);
});

test("pins the S3-only LocalStack server and internal endpoint contract", () => {
  const [config, deployment, service] = buildAwsEmulatorCoreResources();
  assert.deepEqual(config.data, {
    AWS_ENDPOINT_URL: endpoint,
    AWS_ENDPOINT_URL_S3: endpoint,
  });
  assert.deepEqual(deployment.spec.selector.matchLabels, { "app.kubernetes.io/name": "localstack" });
  assert.deepEqual(deployment.spec.strategy, { type: "Recreate" });
  const pod = deployment.spec.template.spec;
  assert.deepEqual({
    automountServiceAccountToken: pod.automountServiceAccountToken,
    dnsPolicy: pod.dnsPolicy,
    enableServiceLinks: pod.enableServiceLinks,
    hostIPC: pod.hostIPC,
    hostNetwork: pod.hostNetwork,
    hostPID: pod.hostPID,
    restartPolicy: pod.restartPolicy,
    securityContext: pod.securityContext,
  }, {
    automountServiceAccountToken: false,
    dnsPolicy: "ClusterFirst",
    enableServiceLinks: false,
    hostIPC: false,
    hostNetwork: false,
    hostPID: false,
    restartPolicy: "Always",
    securityContext: { runAsNonRoot: false, seccompProfile: { type: "RuntimeDefault" } },
  });
  assert.equal(pod.containers.length, 1);
  const container = pod.containers[0];
  assert.equal(container.image, image);
  assert.deepEqual(container.env, [
    { name: "AWS_DEFAULT_REGION", value: "us-east-1" },
    { name: "DEBUG", value: "0" },
    { name: "PERSISTENCE", value: "0" },
    { name: "SERVICES", value: "s3" },
  ]);
  assert.deepEqual(container.ports, [{ containerPort: 4566, name: "edge", protocol: "TCP" }]);
  assert.deepEqual(container.securityContext, {
    allowPrivilegeEscalation: false,
    capabilities: { drop: ["ALL"] },
    privileged: false,
    readOnlyRootFilesystem: false,
    runAsNonRoot: false,
    runAsUser: 0,
  });
  assert.deepEqual(container.resources, {
    limits: { cpu: "500m", memory: "512Mi" },
    requests: { cpu: "25m", memory: "64Mi" },
  });
  const probeCommand = "awslocal --endpoint-url http://127.0.0.1:4566 s3api list-buckets --query 'length(Buckets)' --output text >/dev/null 2>&1";
  assert.deepEqual(container.startupProbe, { exec: { command: ["sh", "-ec", probeCommand] }, failureThreshold: 90, periodSeconds: 2, successThreshold: 1, timeoutSeconds: 1 });
  assert.deepEqual(container.readinessProbe, { exec: { command: ["sh", "-ec", probeCommand] }, failureThreshold: 3, periodSeconds: 2, successThreshold: 1, timeoutSeconds: 1 });
  assert.deepEqual(container.livenessProbe, { exec: { command: ["sh", "-ec", probeCommand] }, failureThreshold: 3, periodSeconds: 10, successThreshold: 1, timeoutSeconds: 1 });
  assert.deepEqual(container.volumeMounts, [
    { mountPath: "/tmp", name: "localstack-tmp", readOnly: false },
    { mountPath: "/var/lib/localstack", name: "localstack-state", readOnly: false },
  ]);
  assert.deepEqual(pod.volumes, [
    { emptyDir: { sizeLimit: "256Mi" }, name: "localstack-state" },
    { emptyDir: { sizeLimit: "128Mi" }, name: "localstack-tmp" },
  ]);
  assert.deepEqual(service.spec, {
    ipFamilies: ["IPv4"],
    ipFamilyPolicy: "SingleStack",
    ports: [{ name: "edge", port: 4566, protocol: "TCP", targetPort: "edge" }],
    selector: { "app.kubernetes.io/name": "localstack" },
    sessionAffinity: "None",
    type: "ClusterIP",
  });
  assert.equal("nodePort" in service.spec.ports[0], false);
  assert.equal("externalIPs" in service.spec, false);
  assert.equal("hostPath" in JSON.parse(JSON.stringify(pod)), false);
});

test("pins one staged S3 endpoint call with synthetic authority and fixed output", () => {
  const [job] = buildAwsEmulatorS3Resources();
  assert.deepEqual({
    activeDeadlineSeconds: job.spec.activeDeadlineSeconds,
    backoffLimit: job.spec.backoffLimit,
    completions: job.spec.completions,
    parallelism: job.spec.parallelism,
    podReplacementPolicy: job.spec.podReplacementPolicy,
  }, { activeDeadlineSeconds: 30, backoffLimit: 0, completions: 1, parallelism: 1, podReplacementPolicy: "Failed" });
  const pod = job.spec.template.spec;
  assert.deepEqual({
    automountServiceAccountToken: pod.automountServiceAccountToken,
    dnsPolicy: pod.dnsPolicy,
    enableServiceLinks: pod.enableServiceLinks,
    hostIPC: pod.hostIPC,
    hostNetwork: pod.hostNetwork,
    hostPID: pod.hostPID,
    restartPolicy: pod.restartPolicy,
    securityContext: pod.securityContext,
  }, {
    automountServiceAccountToken: false,
    dnsPolicy: "ClusterFirst",
    enableServiceLinks: false,
    hostIPC: false,
    hostNetwork: false,
    hostPID: false,
    restartPolicy: "Never",
    securityContext: { runAsNonRoot: false, seccompProfile: { type: "RuntimeDefault" } },
  });
  assert.equal(pod.containers.length, 1);
  const container = pod.containers[0];
  assert.equal(container.image, image);
  assert.deepEqual(container.env, [
    { name: "AWS_ACCESS_KEY_ID", value: "test" },
    { name: "AWS_DEFAULT_REGION", value: "us-east-1" },
    { name: "AWS_EC2_METADATA_DISABLED", value: "true" },
    { name: "AWS_ENDPOINT_URL", valueFrom: { configMapKeyRef: { key: "AWS_ENDPOINT_URL", name: "local-aws-endpoints" } } },
    { name: "AWS_ENDPOINT_URL_S3", valueFrom: { configMapKeyRef: { key: "AWS_ENDPOINT_URL_S3", name: "local-aws-endpoints" } } },
    { name: "AWS_REGION", value: "us-east-1" },
    { name: "AWS_SECRET_ACCESS_KEY", value: "test" },
    { name: "HOME", value: "/tmp" },
  ]);
  assert.deepEqual(container.command.slice(0, 2), ["sh", "-ec"]);
  const script = container.command[2];
  assert.equal((script.match(/s3api list-buckets/gu) ?? []).length, 1);
  assert.match(script, /--endpoint-url "\$AWS_ENDPOINT_URL_S3"/u);
  assert.match(script, /\[ "\$AWS_ENDPOINT_URL" = "\$AWS_ENDPOINT_URL_S3" \]/u);
  assert.match(script, /\[ "\$value" = "0" \]/u);
  assert.match(script, /printf 'localstack-s3-endpoint-ready\\n'/u);
  for (const prohibited of ["until", "while", "curl", "wget", "http://169.254.169.254", "amazonaws.com"]) {
    assert.doesNotMatch(script, new RegExp(prohibited, "u"));
  }
  assert.deepEqual(container.securityContext, {
    allowPrivilegeEscalation: false,
    capabilities: { drop: ["ALL"] },
    privileged: false,
    readOnlyRootFilesystem: true,
    runAsNonRoot: false,
    runAsUser: 0,
  });
  assert.deepEqual(container.volumeMounts, [{ mountPath: "/tmp", name: "job-tmp", readOnly: false }]);
  assert.deepEqual(pod.volumes, [{ emptyDir: { sizeLimit: "8Mi" }, name: "job-tmp" }]);
});

test("rejects manifest aliases, field drift, hostile shapes, and noncanonical YAML", () => {
  const resources = buildAwsEmulatorResources();
  const mutations = [];
  for (const mutate of [
    (value) => { value[0].data.AWS_ENDPOINT_URL = "http://localhost:4566"; },
    (value) => { value[1].spec.template.spec.hostNetwork = true; },
    (value) => { value[1].spec.template.spec.containers[0].env.push({ name: "AWS_PROFILE", value: "default" }); },
    (value) => { value[2].spec.type = "NodePort"; },
    (value) => { value[3].spec.template.spec.containers[0].command[2] += "\ntrue"; },
    (value) => { value.push(value[3]); },
  ]) {
    const value = clone(resources);
    mutate(value);
    mutations.push(value);
  }
  for (const value of mutations) assert.throws(() => validateAwsEmulatorResources(value), TypeError);
  const accessor = clone(resources);
  const endpointValue = accessor[0].data.AWS_ENDPOINT_URL;
  Object.defineProperty(accessor[0].data, "AWS_ENDPOINT_URL", { enumerable: true, get: () => endpointValue });
  assert.throws(() => validateAwsEmulatorResources(accessor), TypeError);
  assert.throws(() => validateAwsEmulatorResources({ toString() { throw new Error("coercion"); } }), TypeError);

  const text = renderAwsEmulatorCoreManifest(buildAwsEmulatorCoreResources());
  assert.throws(() => parseAwsEmulatorManifest(`${text}\n`, "core"), TypeError);
  assert.throws(() => parseAwsEmulatorManifest(text.replace("kind: List", "kind: List\nkind: List"), "core"), TypeError);
  assert.throws(() => parseAwsEmulatorManifest(text.replace("- apiVersion: v1", "- &resource apiVersion: v1"), "core"), TypeError);
  assert.throws(() => parseAwsEmulatorManifest(text.replace("apiVersion: v1", "apiVersion: !!str v1"), "core"), TypeError);
  assert.throws(() => parseAwsEmulatorManifest(`${text}---\n${text}`, "core"), TypeError);
  assert.throws(() => parseAwsEmulatorManifest(`apiVersion: v1\nkind: List\nitems: []\n#${"x".repeat(262_144)}`, "core"), TypeError);
  assert.throws(() => parseAwsEmulatorManifest(text, "other"), TypeError);
});

test("rejects accessor-backed arrays and never invokes caller coercion", () => {
  const resources = clone(buildAwsEmulatorResources());
  let reads = 0;
  Object.defineProperty(resources, "0", {
    enumerable: true,
    get() {
      reads += 1;
      return buildAwsEmulatorResources()[0];
    },
  });
  assert.throws(() => validateAwsEmulatorResources(resources), TypeError);
  assert.equal(reads, 0);
  for (const value of [null, true, 1, "resources", Symbol("resources"), new Date()]) {
    assert.throws(() => validateAwsEmulatorResources(value), TypeError);
  }
});
