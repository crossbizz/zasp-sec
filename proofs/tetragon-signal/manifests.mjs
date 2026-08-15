const proofLabel = "m0-12";
const markerPattern = /^[0-9a-f]{16}$/;
const nodePlatforms = new Set(["linux/amd64", "linux/arm64"]);

export const PINS = deepFreeze({
  kind: {
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
  },
  node: {
    reference: "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95",
    platformDigests: {
      "linux/amd64": "sha256:397bcc4ab091b9632fb3639d5cf020943ca40e90fe7bcc38409738a4a0d056ee",
      "linux/arm64": "sha256:625f4633a546aba1e159ab56e52f9111b1b5044a165cc64ffe46d15d3dd0b0bf",
    },
  },
  chart: {
    version: "1.7.0",
    url: "https://helm.cilium.io/tetragon-1.7.0.tgz",
    sha256: "2d142ecff37a05bc2efab4c3f90cac2a545e8951d845fd15d023e1cbc31685f5",
  },
  tetragon: {
    reference: "quay.io/cilium/tetragon:v1.7.0@sha256:deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527",
    platformDigests: {
      "linux/amd64": "sha256:eec0f2991bd11f02b3c2fe7a1740e01ca58ec6b2c5a1e57e395448e5c4822548",
      "linux/arm64": "sha256:1bffeee60f1d47e367d237129e576729d14fe8db748440328aded8a6091c4a40",
    },
  },
  operator: {
    reference: "quay.io/cilium/tetragon-operator:v1.7.0@sha256:074ffbd19208eed79f68e191ed606e05009f910b4bb5148efcf2973e13504b82",
    platformDigests: {
      "linux/amd64": "sha256:044d85f39e91195d350a31ca5ffb815aef1ceef3464753261ac1a22e48e43c83",
      "linux/arm64": "sha256:0fba45be5e814c72b3d10bf02a842278450a3487722adda18bce97eebe4bab31",
    },
  },
  busybox: {
    reference: "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
    platformDigests: {
      "linux/amd64": "sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb",
      "linux/arm64": "sha256:55c89c6d9404d6668eb237dda92f28a99eb14e640f1c177a55cc9d738c53c303",
    },
  },
});

export function validateMarker(value) {
  if (typeof value !== "string" || !markerPattern.test(value)) {
    throw new TypeError("proof marker is invalid");
  }
  return value;
}

export function buildFixture(input) {
  expectInput(input);
  const marker = validateMarker(input.marker);
  if (!nodePlatforms.has(input.platform)) throw new TypeError("node platform is unsupported");
  const kindBinary = PINS.kind.assets[input.hostPlatform];
  if (kindBinary === undefined) throw new TypeError("host platform is unsupported");

  const prefix = `zasp-m0-12-${marker}`;
  const labels = {
    "zasp.dev/proof": proofLabel,
    "zasp.dev/run": marker,
  };
  const names = {
    prefix,
    cluster: prefix,
    namespace: prefix,
    sinkPod: "sink",
    sinkService: "sink",
    workloadPod: "workload",
    filePolicy: `zasp-m0-12-file-${marker}`,
    networkPolicy: `zasp-m0-12-connect-${marker}`,
  };

  const fixture = {
    pins: PINS,
    names,
    labels,
    kindBinary: { ...kindBinary },
    platform: {
      host: input.hostPlatform,
      node: input.platform,
      nodeDigest: PINS.node.platformDigests[input.platform],
      tetragonDigest: PINS.tetragon.platformDigests[input.platform],
      operatorDigest: PINS.operator.platformDigests[input.platform],
      busyboxDigest: PINS.busybox.platformDigests[input.platform],
    },
    kindConfig: {
      apiVersion: "kind.x-k8s.io/v1alpha4",
      kind: "Cluster",
      networking: { apiServerAddress: "127.0.0.1" },
      nodes: [{
        role: "control-plane",
        image: PINS.node.reference,
        extraMounts: [{ hostPath: "/proc", containerPath: "/procHost", readOnly: true }],
      }],
    },
    helmValues: buildHelmValues(names, labels),
    resources: buildResources(names, labels),
  };
  return deepFreeze(fixture);
}

function buildHelmValues(names, labels) {
  return {
    export: { mode: "" },
    podLabels: { ...labels },
    tetragon: {
      clusterName: names.cluster,
      enableK8sAPI: true,
      enableKeepSensorsOnExit: false,
      enablePolicyFilter: true,
      enableProcessCred: true,
      enableProcessNs: true,
      exportAllowList: `{"namespace":["${names.namespace}"],"pod_regex":["^${names.workloadPod}$"],"event_set":["PROCESS_EXEC"]}`,
      exportDenyList: '{"health_check":true}\n{"namespace":["cilium","kube-system"]}',
      exportFileCompress: false,
      exportFileMaxBackups: 1,
      exportFileMaxSizeMB: 16,
      exportFilename: "tetragon.log",
      exportRateLimit: -1,
      hostProcPath: "/procHost",
      image: { override: PINS.tetragon.reference },
      prometheus: {
        address: "",
        enabled: true,
        port: 2112,
        serviceMonitor: { enabled: false },
      },
      resources: {
        limits: { cpu: "1000m", memory: "1Gi" },
        requests: { cpu: "100m", memory: "256Mi" },
      },
    },
    tetragonOperator: {
      enabled: true,
      image: { override: PINS.operator.reference, pullPolicy: "IfNotPresent" },
      podLabels: { ...labels },
      prometheus: { enabled: false },
      tracingPolicy: { enabled: true },
    },
  };
}

function buildResources(names, labels) {
  const sinkLabels = { ...labels, "app.kubernetes.io/name": "zasp-m0-12-sink" };
  const workloadLabels = { ...labels, "app.kubernetes.io/name": "zasp-m0-12-workload" };
  return [
    {
      apiVersion: "v1",
      kind: "Namespace",
      metadata: { name: names.namespace, labels: { ...labels } },
    },
    fixturePod({
      name: names.sinkPod,
      namespace: names.namespace,
      labels: sinkLabels,
      command: ["/bin/sh", "-c", "exec nc -lk -p 18080"],
    }),
    {
      apiVersion: "v1",
      kind: "Service",
      metadata: { name: names.sinkService, namespace: names.namespace, labels: { ...labels } },
      spec: {
        type: "ClusterIP",
        selector: sinkLabels,
        ports: [{ name: "fixture", port: 18080, protocol: "TCP", targetPort: 18080 }],
      },
    },
    fixturePod({
      name: names.workloadPod,
      namespace: names.namespace,
      labels: workloadLabels,
      command: ["/bin/sh", "-c", "exec sleep 3600"],
    }),
    {
      apiVersion: "cilium.io/v1alpha1",
      kind: "TracingPolicy",
      metadata: { name: names.filePolicy, labels: { ...labels } },
      spec: {
        kprobes: [{
          call: "security_file_permission",
          syscall: false,
          args: [{ index: 0, type: "file" }, { index: 1, type: "int" }],
          selectors: [{ matchArgs: [
            { index: 0, operator: "Prefix", values: ["/tmp/zasp-m0-12-proof.txt"] },
            { index: 1, operator: "Equal", values: ["2"] },
          ] }],
        }],
      },
    },
    {
      apiVersion: "cilium.io/v1alpha1",
      kind: "TracingPolicy",
      metadata: { name: names.networkPolicy, labels: { ...labels } },
      spec: {
        kprobes: [{
          call: "tcp_connect",
          syscall: false,
          args: [{ index: 0, type: "sock" }],
          selectors: [{ matchArgs: [
            { index: 0, operator: "DPort", values: ["18080"] },
          ] }],
        }],
      },
    },
  ];
}

function fixturePod({ name, namespace, labels, command }) {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name, namespace, labels: { ...labels } },
    spec: {
      automountServiceAccountToken: false,
      enableServiceLinks: false,
      hostNetwork: false,
      restartPolicy: "Never",
      securityContext: {
        fsGroup: 65532,
        fsGroupChangePolicy: "OnRootMismatch",
        runAsGroup: 65532,
        runAsNonRoot: true,
        runAsUser: 65532,
        seccompProfile: { type: "RuntimeDefault" },
      },
      terminationGracePeriodSeconds: 1,
      containers: [{
        name,
        image: PINS.busybox.reference,
        imagePullPolicy: "IfNotPresent",
        command,
        env: [],
        ports: [],
        resources: {
          limits: { cpu: "100m", memory: "32Mi" },
          requests: { cpu: "10m", memory: "8Mi" },
        },
        securityContext: {
          allowPrivilegeEscalation: false,
          capabilities: { drop: ["ALL"] },
          privileged: false,
          readOnlyRootFilesystem: true,
          runAsGroup: 65532,
          runAsNonRoot: true,
          runAsUser: 65532,
          seccompProfile: { type: "RuntimeDefault" },
        },
        volumeMounts: [{ name: "tmp", mountPath: "/tmp" }],
      }],
      volumes: [{ name: "tmp", emptyDir: { sizeLimit: "16Mi" } }],
    },
  };
}

function expectInput(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("fixture input must be an object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("fixture input must be a plain object");
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== 3 ||
    keys.some((key) => typeof key !== "string") ||
    !["hostPlatform", "marker", "platform"].every((key) => keys.includes(key))
  ) {
    throw new TypeError("fixture input keys are invalid");
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("fixture input must contain data properties");
    }
  }
  if (typeof value.platform !== "string" || typeof value.hostPlatform !== "string") {
    throw new TypeError("fixture platforms are invalid");
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const entry of Object.values(value)) deepFreeze(entry);
    Object.freeze(value);
  }
  return value;
}
