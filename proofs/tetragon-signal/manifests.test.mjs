import assert from "node:assert/strict";
import test from "node:test";

import { PINS, buildFixture, validateMarker } from "./manifests.mjs";

const marker = "0123456789abcdef";

test("pins exact official kind, Kubernetes, Tetragon, chart, and fixture artifacts", () => {
  assert.deepEqual(PINS.kind, {
    version: "v0.32.0",
    assets: {
      "darwin/amd64": {
        url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-darwin-amd64",
        sha256: "295ac6d0d634c9819c9907df45e3017d1f13166bd13c3404c45e79f7faa47498",
      },
      "darwin/arm64": {
        url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-darwin-arm64",
        sha256: "dca67911095a110c2b5c36e26df6cac860c602033e456c0db47be498cdef1ebb",
      },
      "linux/amd64": {
        url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-linux-amd64",
        sha256: "50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54",
      },
      "linux/arm64": {
        url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-linux-arm64",
        sha256: "b92cd615e97585de8ddade28ed5cd7feb4248d717c233eea5b03c37298900f5d",
      },
    },
  });
  assert.equal(PINS.node.reference, "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95");
  assert.deepEqual(PINS.node.platformDigests, {
    "linux/amd64": "sha256:397bcc4ab091b9632fb3639d5cf020943ca40e90fe7bcc38409738a4a0d056ee",
    "linux/arm64": "sha256:625f4633a546aba1e159ab56e52f9111b1b5044a165cc64ffe46d15d3dd0b0bf",
  });
  assert.equal(PINS.chart.url, "https://helm.cilium.io/tetragon-1.7.0.tgz");
  assert.equal(PINS.chart.sha256, "2d142ecff37a05bc2efab4c3f90cac2a545e8951d845fd15d023e1cbc31685f5");
  assert.equal(PINS.tetragon.reference, "quay.io/cilium/tetragon:v1.7.0@sha256:deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527");
  assert.equal(PINS.operator.reference, "quay.io/cilium/tetragon-operator:v1.7.0@sha256:074ffbd19208eed79f68e191ed606e05009f910b4bb5148efcf2973e13504b82");
  assert.equal(PINS.busybox.reference, "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9");
  assert.equal(PINS.tetragon.platformDigests["linux/arm64"], "sha256:1bffeee60f1d47e367d237129e576729d14fe8db748440328aded8a6091c4a40");
  assert.equal(PINS.operator.platformDigests["linux/arm64"], "sha256:0fba45be5e814c72b3d10bf02a842278450a3487722adda18bce97eebe4bab31");
  assert.equal(PINS.busybox.platformDigests["linux/amd64"], "sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb");
  assert.equal(PINS.busybox.platformDigests["linux/arm64"], "sha256:55c89c6d9404d6668eb237dda92f28a99eb14e640f1c177a55cc9d738c53c303");
});

test("validates only the exact lowercase proof marker grammar without coercion", () => {
  assert.equal(validateMarker(marker), marker);
  let coerced = false;
  const hostile = { toString() { coerced = true; return marker; } };
  for (const value of [null, true, 1, hostile, "ABCDEF0123456789", "0123456789abcde", "0123456789abcdef0", "0123456789abcdeg"]) {
    assert.throws(() => validateMarker(value), TypeError);
  }
  assert.equal(coerced, false);
});

test("generates an exact loopback kind cluster and pinned Helm boundary", () => {
  const fixture = buildFixture({ marker, platform: "linux/arm64", hostPlatform: "darwin/arm64" });

  assert.deepEqual(fixture.names, {
    prefix: `zasp-m0-12-${marker}`,
    cluster: `zasp-m0-12-${marker}`,
    namespace: `zasp-m0-12-${marker}`,
    sinkPod: "sink",
    sinkService: "sink",
    workloadPod: "workload",
    filePolicy: `zasp-m0-12-file-${marker}`,
    networkPolicy: `zasp-m0-12-connect-${marker}`,
  });
  assert.deepEqual(fixture.kindConfig, {
    apiVersion: "kind.x-k8s.io/v1alpha4",
    kind: "Cluster",
    networking: { apiServerAddress: "127.0.0.1" },
    nodes: [{
      role: "control-plane",
      image: PINS.node.reference,
      extraMounts: [{ hostPath: "/proc", containerPath: "/procHost", readOnly: true }],
    }],
  });
  assert.equal(fixture.kindBinary.url, PINS.kind.assets["darwin/arm64"].url);
  assert.equal(fixture.kindBinary.sha256, PINS.kind.assets["darwin/arm64"].sha256);
  assert.equal(fixture.platform.nodeDigest, PINS.node.platformDigests["linux/arm64"]);
  assert.equal(fixture.platform.tetragonDigest, PINS.tetragon.platformDigests["linux/arm64"]);
  assert.equal(fixture.platform.operatorDigest, PINS.operator.platformDigests["linux/arm64"]);
  assert.equal(fixture.platform.busyboxDigest, PINS.busybox.platformDigests["linux/arm64"]);
  assert.deepEqual(fixture.helmValues, {
    export: { mode: "" },
    podLabels: { "zasp.dev/proof": "m0-12", "zasp.dev/run": marker },
    tetragon: {
      clusterName: fixture.names.cluster,
      enableK8sAPI: true,
      enableKeepSensorsOnExit: false,
      enablePolicyFilter: true,
      enableProcessCred: true,
      enableProcessNs: true,
      exportAllowList: `{"namespace":["${fixture.names.namespace}"],"pod_regex":["^${fixture.names.workloadPod}$"],"event_set":["PROCESS_EXEC"]}`,
      exportDenyList: '{"health_check":true}\n{"namespace":["cilium","kube-system"]}',
      exportFileCompress: false,
      exportFileMaxBackups: 1,
      exportFileMaxSizeMB: 16,
      exportFilename: "tetragon.log",
      exportRateLimit: -1,
      hostProcPath: "/procHost",
      image: { override: PINS.tetragon.reference },
      prometheus: { address: "", enabled: true, port: 2112, serviceMonitor: { enabled: false } },
      resources: {
        limits: { cpu: "1000m", memory: "1Gi" },
        requests: { cpu: "100m", memory: "256Mi" },
      },
    },
    tetragonOperator: {
      enabled: true,
      image: { override: PINS.operator.reference, pullPolicy: "IfNotPresent" },
      extraPodLabels: { "zasp.dev/proof": "m0-12", "zasp.dev/run": marker },
      prometheus: { enabled: false },
      tracingPolicy: { enabled: true },
    },
  });
});

test("generates only the exact non-root fixture pods, service, and tracing policies", () => {
  const fixture = buildFixture({ marker, platform: "linux/arm64", hostPlatform: "darwin/arm64" });
  const [namespace, sinkPod, sinkService, workloadPod, filePolicy, networkPolicy] = fixture.resources;

  assert.equal(fixture.resources.length, 6);
  assert.deepEqual(namespace, {
    apiVersion: "v1",
    kind: "Namespace",
    metadata: { name: fixture.names.namespace, labels: fixture.labels },
  });
  for (const [pod, name, app, command] of [
    [sinkPod, fixture.names.sinkPod, "zasp-m0-12-sink", ["/bin/sh", "-c", "exec nc -lk -p 18080"]],
    [workloadPod, fixture.names.workloadPod, "zasp-m0-12-workload", ["/bin/sh", "-c", "exec sleep 3600"]],
  ]) {
    assert.equal(pod.apiVersion, "v1");
    assert.equal(pod.kind, "Pod");
    assert.equal(pod.metadata.name, name);
    assert.equal(pod.metadata.namespace, fixture.names.namespace);
    assert.deepEqual(pod.metadata.labels, { ...fixture.labels, "app.kubernetes.io/name": app });
    assert.equal(pod.spec.automountServiceAccountToken, false);
    assert.equal(pod.spec.enableServiceLinks, false);
    assert.equal(pod.spec.hostNetwork, false);
    assert.equal(pod.spec.restartPolicy, "Never");
    assert.equal(pod.spec.containers.length, 1);
    assert.equal(pod.spec.containers[0].image, PINS.busybox.reference);
    assert.deepEqual(pod.spec.containers[0].command, command);
    assert.deepEqual(pod.spec.containers[0].env, []);
    assert.deepEqual(pod.spec.containers[0].ports, []);
    assert.deepEqual(pod.spec.containers[0].securityContext, {
      allowPrivilegeEscalation: false,
      capabilities: { drop: ["ALL"] },
      privileged: false,
      readOnlyRootFilesystem: true,
      runAsGroup: 65532,
      runAsNonRoot: true,
      runAsUser: 65532,
      seccompProfile: { type: "RuntimeDefault" },
    });
  }
  assert.deepEqual(sinkService, {
    apiVersion: "v1",
    kind: "Service",
    metadata: { name: "sink", namespace: fixture.names.namespace, labels: fixture.labels },
    spec: {
      type: "ClusterIP",
      selector: { ...fixture.labels, "app.kubernetes.io/name": "zasp-m0-12-sink" },
      ports: [{ name: "fixture", port: 18080, protocol: "TCP", targetPort: 18080 }],
    },
  });
  assert.equal(filePolicy.kind, "TracingPolicy");
  assert.equal(filePolicy.metadata.name, fixture.names.filePolicy);
  assert.deepEqual(filePolicy.metadata.labels, fixture.labels);
  assert.deepEqual(filePolicy.spec.podSelector, { matchLabels: {
    ...fixture.labels,
    "app.kubernetes.io/name": "zasp-m0-12-workload",
  } });
  assert.deepEqual(filePolicy.spec.containerSelector, {
    matchExpressions: [{ key: "name", operator: "In", values: [fixture.names.workloadPod] }],
  });
  assert.deepEqual(filePolicy.spec.kprobes, [{
    call: "security_file_permission",
    syscall: false,
    args: [{ index: 0, type: "file" }, { index: 1, type: "int" }],
    selectors: [{ matchArgs: [
      { index: 0, operator: "Prefix", values: ["/tmp/zasp-m0-12-proof.txt"] },
      { index: 1, operator: "Equal", values: ["2"] },
    ] }],
  }]);
  assert.equal(networkPolicy.kind, "TracingPolicy");
  assert.equal(networkPolicy.metadata.name, fixture.names.networkPolicy);
  assert.deepEqual(networkPolicy.metadata.labels, fixture.labels);
  assert.deepEqual(networkPolicy.spec.podSelector, filePolicy.spec.podSelector);
  assert.deepEqual(networkPolicy.spec.containerSelector, filePolicy.spec.containerSelector);
  assert.deepEqual(networkPolicy.spec.kprobes, [{
    call: "tcp_connect",
    syscall: false,
    args: [{ index: 0, type: "sock" }],
    selectors: [{ matchArgs: [{ index: 0, operator: "DPort", values: ["18080"] }] }],
  }]);
});

test("contains no mutable image, host port, secret, cloud, or enforcement surface", () => {
  const fixture = buildFixture({ marker, platform: "linux/arm64", hostPlatform: "darwin/arm64" });
  const serialized = JSON.stringify(fixture);

  assert.doesNotMatch(serialized, /:latest|hostPort|hostPID|hostIPC|serviceAccountName|Secret|AWS_|GOOGLE_|AZURE_|credential|proxy/i);
  assert.doesNotMatch(serialized, /SIGKILL|KPROBE_ACTION|enforcer|enforcement/i);
  assert.doesNotMatch(serialized, /"privileged":true/);
  assert.match(serialized, /"hostNetwork":false/);
  assert.throws(() => { fixture.names.cluster = "mutated"; }, TypeError);
  assert.throws(() => { fixture.resources.push({}); }, TypeError);
});

test("rejects unsupported host and node platform combinations", () => {
  for (const input of [
    { marker, platform: "linux/s390x" },
    { marker, platform: "darwin/arm64" },
    { marker, platform: "linux/arm64", hostPlatform: "win32/arm64" },
    { marker, platform: "linux/arm64", hostPlatform: "darwin/s390x" },
    null,
    [],
  ]) {
    assert.throws(() => buildFixture(input), TypeError);
  }
  assert.equal(buildFixture({ marker, platform: "linux/amd64", hostPlatform: "linux/amd64" }).kindBinary.sha256, PINS.kind.assets["linux/amd64"].sha256);
});
