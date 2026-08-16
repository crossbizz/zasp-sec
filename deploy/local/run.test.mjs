import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import { PRODUCTS, buildProductResources } from "./manifests.mjs";
import {
  KIND_PINS,
  SUCCESS_LINE,
  DockerKindRuntime,
  LocalProductSystem,
  Failure,
  buildChildEnvironment,
  buildKindConfig,
  buildKindCreateArguments,
  buildServicePlan,
  classifyMutationResult,
  fetchBoundedAsset,
  orchestrate,
  parseContainerdImageTargets,
  parseBoundedJson,
  runBounded,
  runMain,
  validateImportedImageIndex,
  validateImageInspection,
  validateKindNodeInspection,
  validateKubernetesState,
} from "./run.mjs";

const owned = Object.freeze({
  contextRoot: "/owned/images",
  dockerConfig: "/owned/docker",
  dockerfile: "/repository/deploy/local/Dockerfile",
  goCache: "/owned/go-build",
  goModuleCache: "/owned/go-mod",
  repositoryRoot: "/repository",
});
const marker = "0123456789abcdef";
const productManifestPath = join(import.meta.dirname, "product-stubs.yaml");

function imageDocument(product, overrides = {}) {
  const id = `sha256:${"a".repeat(64)}`;
  return [{
    Architecture: "arm64",
    Config: {
      Entrypoint: ["/service"],
      Env: ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
      ExposedPorts: { "8081/tcp": {} },
      Labels: {
        "zasp.dev/component": product.name,
        "zasp.dev/proof": "m1-30a",
        "zasp.dev/run": marker,
      },
      User: "65532:65532",
    },
    Id: id,
    Os: "linux",
    RepoDigests: [],
    RepoTags: [product.image],
    RootFS: { Layers: [`sha256:${"b".repeat(64)}`], Type: "layers" },
    ...overrides,
  }];
}

function rawImageDocument(product, overrides = {}) {
  const projected = imageDocument(product, overrides)[0];
  return [{
    Architecture: projected.Architecture,
    Config: projected.Config,
    Created: "2026-08-16T00:00:00Z",
    GraphDriver: { Data: null, Name: "overlay2" },
    Id: projected.Id,
    Metadata: { LastTagTime: "2026-08-16T00:00:00Z" },
    Os: projected.Os,
    Parent: "",
    RepoDigests: projected.RepoDigests,
    RepoTags: projected.RepoTags,
    RootFS: projected.RootFS,
    Size: 1,
  }];
}

function kindNodeDocument(cluster, networkId, token) {
  const imageId = "sha256:8b8d852fef3a95a2b04fd9e6890044bf6092c7810df66da4f9b503fb4341da60";
  const volumeToken = "c".repeat(64);
  return [{
    Config: {
      Cmd: null,
      Entrypoint: ["/usr/local/bin/entrypoint", "/sbin/init"],
      Env: [
        "KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER",
        "KUBECONFIG=/etc/kubernetes/admin.conf",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "container=docker", "HTTP_PROXY=", "HTTPS_PROXY=", "NO_PROXY=",
      ],
      Hostname: `${cluster}-control-plane`,
      Image: KIND_PINS.node.reference,
      Labels: { "io.x-k8s.kind.cluster": cluster, "io.x-k8s.kind.role": "control-plane" },
      User: "",
    },
    HostConfig: {
      Binds: ["/lib/modules:/lib/modules:ro", "/dev/mapper:/dev/mapper"],
      CapAdd: null,
      CapDrop: null,
      CgroupnsMode: "private",
      DeviceRequests: null,
      Devices: [],
      IpcMode: "private",
      PidMode: "",
      PortBindings: { "6443/tcp": [{ HostIp: "127.0.0.1", HostPort: "51234" }] },
      Privileged: true,
      ReadonlyRootfs: false,
      SecurityOpt: ["seccomp=unconfined", "apparmor=unconfined", "label=disable"],
      Tmpfs: { "/run": "", "/tmp": "" },
      UsernsMode: "",
    },
    Id: token,
    Image: imageId,
    Mounts: [
      { Destination: "/lib/modules", Mode: "ro", Propagation: "rprivate", RW: false, Source: "/lib/modules", Type: "bind" },
      { Destination: "/dev/mapper", Mode: "", Propagation: "rprivate", RW: true, Source: "/dev/mapper", Type: "bind" },
      { Destination: "/var", Driver: "local", Mode: "", Name: volumeToken, Propagation: "", RW: true, Source: `/var/lib/docker/volumes/${volumeToken}/_data`, Type: "volume" },
    ],
    Name: `/${cluster}-control-plane`,
    NetworkSettings: {
      Networks: { [cluster]: {
        Aliases: null,
        DriverOpts: null,
        Gateway: "172.20.0.1",
        IPAddress: "172.20.0.2",
        IPPrefixLen: 24,
        MacAddress: "02:42:ac:14:00:02",
        NetworkID: networkId,
      } },
      Ports: { "6443/tcp": [{ HostIp: "127.0.0.1", HostPort: "51234" }] },
    },
  }];
}

function kubeconfigDocument(cluster, port = "51234") {
  const name = `kind-${cluster}`;
  return [
    "apiVersion: v1",
    "clusters:",
    `- cluster:`,
    "    certificate-authority-data: Y2E=",
    `    server: https://127.0.0.1:${port}`,
    `  name: ${name}`,
    "contexts:",
    "- context:",
    `    cluster: ${name}`,
    `    user: ${name}`,
    `  name: ${name}`,
    `current-context: ${name}`,
    "kind: Config",
    "users:",
    `- name: ${name}`,
    "  user:",
    "    client-certificate-data: Y2VydA==",
    "    client-key-data: a2V5",
    "",
  ].join("\n");
}

function fakeChild(action) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killedWith = [];
  child.kill = (signal) => { child.killedWith.push(signal); return true; };
  queueMicrotask(() => action(child));
  return child;
}

test("Dockerfile is an exact dependency-free non-root scratch boundary", async () => {
  const text = await readFile(join(import.meta.dirname, "Dockerfile"), "utf8");
  assert.equal(text, [
    "FROM scratch",
    "ARG BINARY=service",
    "COPY --chown=65532:65532 ${BINARY} /service",
    "USER 65532:65532",
    "EXPOSE 8081",
    "ENTRYPOINT [\"/service\"]",
    "",
  ].join("\n"));
  assert.doesNotMatch(text, /RUN|ADD|https?:|apk|apt|shell|latest/i);
});

test("runner invokes only the fixed main boundary when executed directly", async () => {
  const text = await readFile(join(import.meta.dirname, "run.mjs"), "utf8");
  assert.match(text, /if \(process\.argv\[1\] === fileURLToPath\(import\.meta\.url\)\) \{\n {2}await runMain\(\);\n\}\n$/);
});

test("builds exact host Go and Docker plans for all four real commands", () => {
  for (const product of PRODUCTS) {
    assert.deepEqual(buildServicePlan(product, owned, marker, "linux/arm64"), {
      binary: `/owned/images/${product.name}/service`,
      buildContext: `/owned/images/${product.name}`,
      docker: {
        arguments: [
          "build", "--file", "/repository/deploy/local/Dockerfile",
          "--build-arg", "BINARY=service",
          "--label", `zasp.dev/component=${product.name}`,
          "--label", "zasp.dev/proof=m1-30a",
          "--label", `zasp.dev/run=${marker}`,
          "--tag", product.image,
          `/owned/images/${product.name}`,
        ],
        command: "docker",
      },
      go: {
        arguments: [
          "build", "-trimpath", "-ldflags=-s -w -X main.buildVersion=m1-30a",
          "-o", `/owned/images/${product.name}/service`, product.package,
        ],
        command: "go",
        cwd: `/repository/${product.module}`,
        environment: {
          CGO_ENABLED: "0",
          GOCACHE: "/owned/go-build",
          GOARCH: "arm64",
          GOENV: "off",
          GOOS: "linux",
          GOMODCACHE: "/owned/go-mod",
          GOWORK: "off",
        },
      },
      image: product.image,
      name: product.name,
    });
  }
});

test("rejects forged products, paths, and proof markers before building", () => {
  const cases = [
    [structuredClone(PRODUCTS[0]), { ...owned }, "short", "linux/arm64"],
    [{ ...PRODUCTS[0], image: "busybox:latest" }, { ...owned }, marker, "linux/arm64"],
    [{ ...PRODUCTS[0], package: "../agentsec-worker" }, { ...owned }, marker, "linux/arm64"],
    [{ ...PRODUCTS[0], unexpected: true }, { ...owned }, marker, "linux/arm64"],
    [PRODUCTS[0], { ...owned, repositoryRoot: "relative" }, marker, "linux/arm64"],
    [PRODUCTS[0], { ...owned, contextRoot: "/owned/../escape" }, marker, "linux/arm64"],
    [PRODUCTS[0], { ...owned, dockerfile: "/other/Dockerfile" }, marker, "linux/arm64"],
    [PRODUCTS[0], { ...owned, extra: "/owned/extra" }, marker, "linux/arm64"],
    [PRODUCTS[0], { ...owned }, marker, "darwin/arm64"],
  ];
  for (const value of cases) assert.throws(() => buildServicePlan(...value), { name: "TypeError" });
});

test("constructs an exact child environment and never forwards ambient authority", () => {
  const result = buildChildEnvironment({
    DOCKER_CONFIG: "/ambient/docker",
    HOME: "/Users/test",
    LANG: "en_US.UTF-8",
    PATH: "/usr/bin:/bin",
    RANDOM_VALUE: "ignored",
  }, owned);
  assert.deepEqual(result, {
    DOCKER_CONFIG: "/owned/docker",
    HOME: "/Users/test",
    LANG: "C.UTF-8",
    PATH: "/usr/bin:/bin",
  });
  assert.equal(Object.values(result).some((value) => value.includes("ambient")), false);
});

test("rejects absent or unsafe required host environment", () => {
  for (const environment of [
    {},
    { HOME: "/Users/test", PATH: "relative" },
    { HOME: "relative", PATH: "/usr/bin" },
    { HOME: "/Users/test", PATH: "/usr/bin", KUBECONFIG: "/ambient" },
    { HOME: "/Users/test", PATH: "/usr/bin", DOCKER_HOST: "tcp://remote" },
    { HOME: "/Users/test", PATH: "/usr/bin", AWS_PROFILE: "real" },
    { HOME: "/Users/test", PATH: "/usr/bin", HTTP_PROXY: "http://proxy.invalid" },
  ]) assert.throws(() => buildChildEnvironment(environment, owned), { name: "Failure" });
});

test("binds the complete immutable image identity and rejects drift", () => {
  const product = PRODUCTS[0];
  const document = imageDocument(product);
  const identity = validateImageInspection(document, product, marker, "linux/arm64");
  assert.deepEqual(identity, {
    architecture: "arm64",
    id: `sha256:${"a".repeat(64)}`,
    layers: [`sha256:${"b".repeat(64)}`],
    reference: product.image,
  });

  const mutations = [
    (value) => { value.push(structuredClone(value[0])); },
    (value) => { value[0].Id = "sha256:short"; },
    (value) => { value[0].RepoTags = ["zasp-local/agentsec-api:other"]; },
    (value) => { value[0].Config.User = "0"; },
    (value) => { value[0].Config.Entrypoint = ["/bin/sh"]; },
    (value) => { value[0].Config.Env = ["AWS_ACCESS_KEY_ID=seeded"]; },
    (value) => { value[0].Config.Labels["zasp.dev/run"] = "fedcba9876543210"; },
    (value) => { value[0].Config.Labels.extra = "value"; },
    (value) => { value[0].Config.ExposedPorts["80/tcp"] = {}; },
    (value) => { value[0].RootFS.Layers.push(`sha256:${"d".repeat(64)}`); },
    (value) => { value[0].Architecture = "amd64"; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(document);
    mutate(value);
    assert.throws(() => validateImageInspection(value, product, marker, "linux/arm64"), { name: "Failure" });
  }
});

test("classifies only genuine mutation uncertainty as reconcilable", () => {
  assert.equal(classifyMutationResult({ status: 0, signal: null, stderr: "", stdout: "" }), "applied");
  for (const result of [
    { status: null, signal: "SIGKILL", stderr: "", stdout: "" },
    { status: 0, signal: null, stderr: "", stdout: "unexpected" },
    { status: null, signal: null, stderr: "", stdout: "", thrown: true },
    { status: null, signal: null, stderr: "", stdout: "", timedOut: true },
  ]) assert.equal(classifyMutationResult(result), "ambiguous");
  for (const result of [
    { status: 1, signal: null, stderr: "rejected", stdout: "" },
    { status: 125, signal: null, stderr: "rejected", stdout: "" },
  ]) assert.equal(classifyMutationResult(result), "definitive");
});

test("bounds combined process output and reaps successful children", async () => {
  const child = fakeChild((value) => {
    value.stdout.end("ready\n");
    value.stderr.end();
    value.emit("close", 0, null);
  });
  const result = await runBounded("fixture", ["ok"], {
    environment: { PATH: "/usr/bin" },
    outputLimit: 16,
    timeoutMilliseconds: 100,
  }, () => child);
  assert.deepEqual(result, {
    signal: null,
    status: 0,
    stderr: "",
    stdout: "ready\n",
    thrown: false,
    timedOut: false,
  });
  assert.deepEqual(child.killedWith, []);
});

test("kills and reaps timed-out, overflowing, and pipe-error children", async (context) => {
  await context.test("timeout", async () => {
    const child = fakeChild(() => {});
    const pending = runBounded("fixture", [], {
      environment: { PATH: "/usr/bin" }, outputLimit: 16, timeoutMilliseconds: 10,
    }, () => child);
    setTimeout(() => child.emit("close", null, "SIGKILL"), 20);
    const result = await pending;
    assert.equal(result.timedOut, true);
    assert.deepEqual(child.killedWith, ["SIGKILL"]);
  });

  await context.test("combined output", async () => {
    const child = fakeChild((value) => {
      value.stdout.write("123456789");
      value.stderr.write("abcdefghi");
      value.emit("close", null, "SIGKILL");
    });
    const result = await runBounded("fixture", [], {
      environment: { PATH: "/usr/bin" }, outputLimit: 16, timeoutMilliseconds: 100,
    }, () => child);
    assert.equal(result.status, null);
    assert.deepEqual(child.killedWith, ["SIGKILL"]);
  });

  await context.test("pipe error", async () => {
    const child = fakeChild((value) => {
      value.stdout.emit("error", new Error("pipe"));
      value.emit("close", null, "SIGKILL");
    });
    const result = await runBounded("fixture", [], {
      environment: { PATH: "/usr/bin" }, outputLimit: 16, timeoutMilliseconds: 100,
    }, () => child);
    assert.equal(result.thrown, true);
    assert.deepEqual(child.killedWith, ["SIGKILL"]);
  });

  await context.test("external cancellation", async () => {
    const controller = new AbortController();
    const child = fakeChild(() => {});
    child.kill = (signal) => {
      child.killedWith.push(signal);
      queueMicrotask(() => child.emit("close", null, signal));
      return true;
    };
    const pending = runBounded("fixture", [], {
      environment: { PATH: "/usr/bin" }, outputLimit: 16, signal: controller.signal,
      timeoutMilliseconds: 100,
    }, () => child);
    controller.abort();
    const result = await pending;
    assert.equal(result.timedOut, false);
    assert.deepEqual(child.killedWith, ["SIGKILL"]);
  });
});

test("uses fixed failure categories without retaining provider text", () => {
  assert.equal(new Failure("build", "provider token abc").category, "build");
  assert.equal(new Failure("unknown", "provider token abc").category, "operation");
  assert.equal(String(new Failure("ownership", "provider token abc")), "Failure: provider token abc");
});

test("parses only bounded UTF-8 JSON with unique keys and finite structure", () => {
  assert.deepEqual(parseBoundedJson('{"a":[1,true,null,"value"]}\n', 1024), {
    a: [1, true, null, "value"],
  });
  for (const value of [
    '',
    '{"a":1,"a":1}',
    '{"__proto__":{}}',
    '{"a":NaN}',
    `${'{"a":'.repeat(70)}0${'}'.repeat(70)}`,
    `{"a":"\ud800"}`,
    `${" ".repeat(1025)}{}`,
  ]) assert.throws(() => parseBoundedJson(value, 1024), { name: "SyntaxError" });
});

test("follows the official release redirect only under the pinned byte and hash boundary", async () => {
  const calls = [];
  const bytes = Buffer.from("official asset");
  const result = await fetchBoundedAsset("https://github.com/example/releases/asset", 1024,
    new AbortController().signal, async (url, options) => {
      calls.push({ options, url });
      let sent = false;
      return {
        body: { getReader() { return { async read() {
          if (sent) return { done: true };
          sent = true;
          return { done: false, value: bytes };
        } }; } },
        headers: { get(name) { return name === "content-length" ? String(bytes.length) : null; } },
        ok: true,
        status: 200,
        url: "https://release-assets.githubusercontent.com/owned",
      };
    });
  assert.deepEqual(result, bytes);
  assert.equal(calls[0].options.redirect, "follow");
});

test("binds each containerd import index to one exact loaded product target", () => {
  const targets = PRODUCTS.map((product, index) =>
    `docker.io/${product.image} application/vnd.oci.image.manifest.v1+json sha256:${String(index + 1).repeat(64)} 1.0 MiB linux/arm64 -`);
  const parsed = parseContainerdImageTargets([
    "REF TYPE DIGEST SIZE PLATFORMS LABELS",
    ...targets,
    "",
  ].join("\n"), "linux/arm64");
  assert.deepEqual(Object.fromEntries(parsed), Object.fromEntries(PRODUCTS.map((product, index) => [
    product.name, `sha256:${String(index + 1).repeat(64)}`,
  ])));

  const product = PRODUCTS[0];
  const target = parsed.get(product.name);
  const imported = `sha256:${"9".repeat(64)}`;
  const retained = {
    architecture: "arm64",
    id: `sha256:${"a".repeat(64)}`,
    layers: [`sha256:${"b".repeat(64)}`],
    reference: product.image,
  };
  const document = {
    manifests: [{
      annotations: {
        "io.containerd.image.name": `docker.io/${product.image}`,
        "org.opencontainers.image.ref.name": "m1-30a",
      },
      digest: target,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      size: 1234,
    }],
    mediaType: "application/vnd.oci.image.index.v1+json",
    schemaVersion: 2,
  };
  const targetManifest = {
    config: { digest: retained.id, mediaType: "application/vnd.oci.image.config.v1+json", size: 123 },
    layers: [{ digest: `sha256:${"c".repeat(64)}`, mediaType: "application/vnd.oci.image.layer.v1.tar", size: 456 }],
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    schemaVersion: 2,
  };
  const imageConfig = {
    architecture: "arm64",
    os: "linux",
    rootfs: { diff_ids: retained.layers, type: "layers" },
  };
  assert.deepEqual(validateImportedImageIndex(document, product, target,
    `docker.io/library/import-2026-08-16@${imported}`, retained, targetManifest, imageConfig,
    "linux/arm64"), {
    canonicalImage: product.image,
    canonicalImageID: `docker-pullable://${product.image}@${imported}`,
    providerImage: `docker.io/${product.image}`,
    providerImageID: `docker.io/library/import-2026-08-16@${imported}`,
  });
  for (const value of [
    { ...document, extra: true },
    { ...document, manifests: [] },
    { ...document, manifests: [{ ...document.manifests[0], digest: `sha256:${"8".repeat(64)}` }] },
    { ...document, manifests: [{ ...document.manifests[0], annotations: {
      ...document.manifests[0].annotations, "io.containerd.image.name": "docker.io/other/image:tag",
    } }] },
  ]) {
    assert.throws(() => validateImportedImageIndex(value, product, target,
      `docker.io/library/import-2026-08-16@${imported}`), { name: "Failure" });
  }
  for (const [manifestValue, configValue, platform] of [
    [{ ...targetManifest, config: { ...targetManifest.config, digest: `sha256:${"d".repeat(64)}` } }, imageConfig, "linux/arm64"],
    [{ ...targetManifest, layers: [] }, imageConfig, "linux/arm64"],
    [targetManifest, { ...imageConfig, architecture: "amd64" }, "linux/arm64"],
    [targetManifest, { ...imageConfig, rootfs: { ...imageConfig.rootfs, diff_ids: [`sha256:${"d".repeat(64)}`] } }, "linux/arm64"],
    [targetManifest, imageConfig, "linux/amd64"],
  ]) {
    assert.throws(() => validateImportedImageIndex(document, product, target,
      `docker.io/library/import-2026-08-16@${imported}`, retained, manifestValue, configValue, platform),
    { name: "Failure" });
  }
  assert.throws(() => parseContainerdImageTargets([
    "REF TYPE DIGEST SIZE PLATFORMS LABELS",
    targets[0],
    targets[0],
    "",
  ].join("\n"), "linux/arm64"), { name: "Failure" });
  assert.throws(() => parseContainerdImageTargets([
    "REF TYPE DIGEST SIZE PLATFORMS LABELS",
    ...targets.map((line) => line.replace("linux/arm64", "linux/amd64")),
    "",
  ].join("\n"), "linux/arm64"), { name: "Failure" });
});

function kubernetesState(overrides = {}) {
  const nodeName = "zasp-m1-30a-0123456789abcdef-control-plane";
  const namespace = {
    apiVersion: "v1",
    kind: "Namespace",
    metadata: {
      labels: {
        "app.kubernetes.io/part-of": "zasp",
        "kubernetes.io/metadata.name": "zasp-local",
        "zasp.dev/environment": "local",
      },
      name: "zasp-local",
      resourceVersion: "100",
      uid: "10000000-0000-4000-8000-000000000000",
    },
    spec: { finalizers: ["kubernetes"] },
    status: { phase: "Active" },
  };
  const pods = PRODUCTS.map((product, index) => ({
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      labels: {
        "app.kubernetes.io/name": product.name,
        "app.kubernetes.io/part-of": "zasp",
        "pod-template-hash": String(index + 1).padStart(10, "a"),
        "zasp.dev/environment": "local",
      },
      name: `${product.name}-${String(index + 1).padStart(10, "a")}-abcde`,
      namespace: "zasp-local",
      ownerReferences: [{
        apiVersion: "apps/v1",
        blockOwnerDeletion: true,
        controller: true,
        kind: "ReplicaSet",
        name: `${product.name}-${String(index + 1).padStart(10, "a")}`,
        uid: `30000000-0000-4000-8000-00000000000${index}`,
      }],
      resourceVersion: String(300 + index),
      uid: `00000000-0000-4000-8000-00000000000${index}`,
    },
    spec: {
      automountServiceAccountToken: false,
      containers: [structuredClone(buildProductResources().find((resource) =>
        resource.kind === "Deployment" && resource.metadata.name === product.name).spec.template.spec.containers[0])],
      dnsPolicy: "ClusterFirst",
      enableServiceLinks: false,
      ephemeralContainers: [],
      hostAliases: [],
      hostIPC: false,
      hostNetwork: false,
      hostPID: false,
      imagePullSecrets: [],
      initContainers: [],
      nodeName,
      restartPolicy: "Always",
      securityContext: structuredClone(buildProductResources().find((resource) =>
        resource.kind === "Deployment" && resource.metadata.name === product.name).spec.template.spec.securityContext),
      serviceAccountName: "default",
      shareProcessNamespace: false,
      volumes: [],
    },
    status: {
      conditions: [{ status: "True", type: "Ready" }],
      containerStatuses: [{
        containerID: `containerd://${String(index + 1).repeat(64)}`,
        image: product.image,
        imageID: `docker-pullable://${product.image}@sha256:${String(index + 5).repeat(64)}`,
        name: product.name,
        ready: true,
        restartCount: 0,
        started: true,
        state: { running: { startedAt: "2026-08-16T00:00:00Z" } },
      }],
      phase: "Running",
      podIP: `10.244.0.${index + 10}`,
    },
  }));
  for (const pod of pods) Object.assign(pod.spec.containers[0], {
    args: [], command: [], env: [], envFrom: [], volumeMounts: [],
  });
  const deployments = PRODUCTS.map((product, index) => ({
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: {
      generation: 1,
      name: product.name,
      namespace: "zasp-local",
      resourceVersion: String(200 + index),
      uid: `20000000-0000-4000-8000-00000000000${index}`,
    },
    spec: {
      replicas: 1,
      selector: { matchLabels: { "app.kubernetes.io/name": product.name } },
      template: {
        metadata: { labels: structuredClone(buildProductResources().find((resource) =>
          resource.kind === "Deployment" && resource.metadata.name === product.name).spec.template.metadata.labels) },
        spec: structuredClone(pods[index].spec),
      },
    },
    status: {
      availableReplicas: 1,
      conditions: [{ status: "True", type: "Available" }],
      observedGeneration: 1,
      readyReplicas: 1,
      replicas: 1,
      unavailableReplicas: 0,
      updatedReplicas: 1,
    },
  }));
  for (const deployment of deployments) delete deployment.spec.template.spec.nodeName;
  const replicaSets = PRODUCTS.map((product, index) => ({
    apiVersion: "apps/v1",
    kind: "ReplicaSet",
    metadata: {
      labels: {
        "app.kubernetes.io/name": product.name,
        "app.kubernetes.io/part-of": "zasp",
        "pod-template-hash": String(index + 1).padStart(10, "a"),
        "zasp.dev/environment": "local",
      },
      name: `${product.name}-${String(index + 1).padStart(10, "a")}`,
      namespace: "zasp-local",
      ownerReferences: [{
        apiVersion: "apps/v1", blockOwnerDeletion: true, controller: true, kind: "Deployment",
        name: product.name, uid: deployments[index].metadata.uid,
      }],
      resourceVersion: String(250 + index),
      uid: `30000000-0000-4000-8000-00000000000${index}`,
    },
    spec: {
      replicas: 1,
      selector: { matchLabels: {
        "app.kubernetes.io/name": product.name,
        "pod-template-hash": String(index + 1).padStart(10, "a"),
      } },
    },
    status: { availableReplicas: 1, fullyLabeledReplicas: 1, observedGeneration: 1, readyReplicas: 1, replicas: 1 },
  }));
  const services = PRODUCTS.map((product, index) => ({
    apiVersion: "v1",
    kind: "Service",
    metadata: {
      name: product.name,
      namespace: "zasp-local",
      resourceVersion: String(400 + index),
      uid: `40000000-0000-4000-8000-00000000000${index}`,
    },
    spec: {
      clusterIP: `10.96.0.${index + 10}`,
      clusterIPs: [`10.96.0.${index + 10}`],
      externalIPs: [],
      ipFamilies: ["IPv4"],
      ipFamilyPolicy: "SingleStack",
      ports: [{ name: "health", port: 8081, protocol: "TCP", targetPort: "health" }],
      selector: { "app.kubernetes.io/name": product.name },
      sessionAffinity: "None",
      type: "ClusterIP",
    },
    status: { loadBalancer: {} },
  }));
  const endpointSlices = PRODUCTS.map((product, index) => ({
    addressType: "IPv4",
    apiVersion: "discovery.k8s.io/v1",
    endpoints: [{
      addresses: [pods[index].status.podIP],
      conditions: { ready: true, serving: true, terminating: false },
      nodeName,
      targetRef: {
        kind: "Pod", name: pods[index].metadata.name, namespace: "zasp-local", uid: pods[index].metadata.uid,
      },
    }],
    kind: "EndpointSlice",
    metadata: {
      labels: {
        "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
        "kubernetes.io/service-name": product.name,
      },
      name: `${product.name}-abcde`,
      namespace: "zasp-local",
      ownerReferences: [{
        apiVersion: "v1", blockOwnerDeletion: true, controller: true, kind: "Service",
        name: product.name, uid: services[index].metadata.uid,
      }],
      resourceVersion: String(500 + index),
      uid: `50000000-0000-4000-8000-00000000000${index}`,
    },
    ports: [{ name: "health", port: 8081, protocol: "TCP" }],
  }));
  return { deployments, endpointSlices, namespace, nodeName, pods, replicaSets, services, ...overrides };
}

function containerdTarget(product) {
  return `sha256:${["a", "b", "c", "d"][PRODUCTS.indexOf(product)].repeat(64)}`;
}

function containerdImport(product) {
  return `sha256:${String(PRODUCTS.indexOf(product) + 5).repeat(64)}`;
}

function containerdInventory() {
  return [
    "REF TYPE DIGEST SIZE PLATFORMS LABELS",
    ...PRODUCTS.map((product) => [
      `docker.io/${product.image}`,
      "application/vnd.oci.image.manifest.v1+json",
      containerdTarget(product),
      "1.0MiB",
      "linux/arm64",
      "-",
    ].join(" ")),
    "",
  ].join("\n");
}

function containerdImportIndex(product) {
  return {
    manifests: [{
      annotations: {
        "io.containerd.image.name": `docker.io/${product.image}`,
        "org.opencontainers.image.ref.name": "m1-30a",
      },
      digest: containerdTarget(product),
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      size: 1234,
    }],
    mediaType: "application/vnd.oci.image.index.v1+json",
    schemaVersion: 2,
  };
}

function containerdTargetManifest(product) {
  const index = PRODUCTS.indexOf(product);
  return {
    config: {
      digest: `sha256:${String(index + 1).repeat(64)}`,
      mediaType: "application/vnd.oci.image.config.v1+json",
      size: 123,
    },
    layers: [{
      digest: `sha256:${["e", "f", "a", "b"][index].repeat(64)}`,
      mediaType: "application/vnd.oci.image.layer.v1.tar",
      size: 456,
    }],
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    schemaVersion: 2,
  };
}

function containerdImageConfig(product) {
  const index = PRODUCTS.indexOf(product);
  return {
    architecture: "arm64",
    os: "linux",
    rootfs: { diff_ids: [`sha256:${String(index + 5).repeat(64)}`], type: "layers" },
  };
}

function providerKubernetesState() {
  const state = structuredClone(kubernetesState());
  for (const product of PRODUCTS) {
    const deployment = state.deployments.find((item) => item.metadata.name === product.name);
    delete deployment.spec.template.spec.serviceAccountName;
    const pod = state.pods.find((item) => item.metadata.labels["app.kubernetes.io/name"] === product.name);
    pod.status.containerStatuses[0].image = `docker.io/${product.image}`;
    pod.status.containerStatuses[0].imageID =
      `docker.io/library/import-2026-08-16@${containerdImport(product)}`;
  }
  return state;
}

async function verifyProjectedProviderState(state, requests = undefined) {
  const fixture = createConcreteFixture(async (command, arguments_) => {
    if (command !== "kubectl") throw new Error("unexpected command");
    const resource = ["namespace", "deployment", "replicaset", "pod", "service", "endpointslice", "ingress"]
      .find((value) => arguments_.includes(value));
    requests?.push(resource);
    if (resource === "namespace") return {
      signal: null, status: 0, stderr: "", stdout: `${JSON.stringify(state.namespace)}\n`, thrown: false, timedOut: false,
    };
    const items = resource === "deployment" ? state.deployments
      : resource === "replicaset" ? state.replicaSets
        : resource === "pod" ? state.pods
          : resource === "service" ? state.services
            : resource === "endpointslice" ? state.endpointSlices : [];
    return {
      signal: null, status: 0, stderr: "",
      stdout: `${JSON.stringify({ apiVersion: "v1", items, kind: "List", metadata: { resourceVersion: "" } })}\n`,
      thrown: false, timedOut: false,
    };
  });
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await fixture.system.initialize(phase);
  fixture.system.verifyCluster = async () => {};
  fixture.system.verifyImportedPodImages = async () => new Map(PRODUCTS.map((product) => [product.name, {
    canonicalImage: product.image,
    canonicalImageID: `docker-pullable://${product.image}@sha256:${String(PRODUCTS.indexOf(product) + 5).repeat(64)}`,
    providerImage: `docker.io/${product.image}`,
    providerImageID: `docker.io/library/import-2026-08-16@${containerdImport(product)}`,
  }]));
  return fixture.system.verifyReadiness(phase);
}

test("pins an exact loopback kind cluster and owned kubeconfig", () => {
  assert.deepEqual(KIND_PINS, {
    kind: {
      version: "v0.32.0",
      assets: {
        "darwin/amd64": {
          sha256: "55b3f27c325ec6cf37fa651f3f53e01954eb4b95c10827d91bfee46e0835f2fb",
          url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-darwin-amd64",
        },
        "darwin/arm64": {
          sha256: "dca67911095a110c2b5c36e26df6cac860c602033e456c0db47be498cdef1ebb",
          url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-darwin-arm64",
        },
        "linux/amd64": {
          sha256: "6e811cf0a7422033e7442f78b767464a8ba19b2d96c78659652077f67172192b",
          url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-linux-amd64",
        },
        "linux/arm64": {
          sha256: "b92cd615e97585de8ddade28ed5cd7feb4248d717c233eea5b03c37298900f5d",
          url: "https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-linux-arm64",
        },
      },
    },
    node: {
      configDigests: {
        "linux/amd64": "sha256:caf23176b804ea639d96b2266829fdff42ca8f064bd9d32c00ad913b23ced7d9",
        "linux/arm64": "sha256:8b8d852fef3a95a2b04fd9e6890044bf6092c7810df66da4f9b503fb4341da60",
      },
      platformDigests: {
        "linux/amd64": "sha256:397bcc4ab091b9632fb3639d5cf020943ca40e90fe7bcc38409738a4a0d056ee",
        "linux/arm64": "sha256:625f4633a546aba1e159ab56e52f9111b1b5044a165cc64ffe46d15d3dd0b0bf",
      },
      reference: "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95",
    },
  });
  assert.deepEqual(buildKindConfig(), {
    apiVersion: "kind.x-k8s.io/v1alpha4",
    kind: "Cluster",
    networking: { apiServerAddress: "127.0.0.1" },
    nodes: [{ role: "control-plane" }],
  });
  assert.deepEqual(buildKindCreateArguments({
    cluster: "zasp-m1-30a-0123456789abcdef",
    config: "/owned/kind.json",
    kubeconfig: "/owned/kubeconfig",
  }), [
    "create", "cluster", "--name", "zasp-m1-30a-0123456789abcdef",
    "--config", "/owned/kind.json", "--kubeconfig", "/owned/kubeconfig",
    "--image", KIND_PINS.node.reference, "--wait", "180s",
  ]);
});

test("binds the kind API to one numeric loopback port and the exact kubeconfig", async () => {
  const cluster = `zasp-m1-30a-${marker}`;
  const networkId = "a".repeat(64);
  const token = "b".repeat(64);
  const expected = {
    cluster,
    hostPlatform: "darwin/arm64",
    imageId: KIND_PINS.node.configDigests["linux/arm64"],
    name: `${cluster}-control-plane`,
    networkId,
    reference: KIND_PINS.node.reference,
    token,
  };
  const identity = validateKindNodeInspection(kindNodeDocument(cluster, networkId, token), expected);
  assert.equal(identity.apiPort, "51234");

  for (const mutate of [
    (value) => { value[0].HostConfig.PortBindings["6443/tcp"][0].HostIp = "0.0.0.0"; },
    (value) => { value[0].NetworkSettings.Ports["6443/tcp"][0].HostPort = "51235"; },
    (value) => { value[0].NetworkSettings.Ports["6443/tcp"] = null; },
  ]) {
    const value = structuredClone(kindNodeDocument(cluster, networkId, token));
    mutate(value);
    assert.throws(() => validateKindNodeInspection(value, expected), { name: "Failure" });
  }

  let fixture;
  fixture = createConcreteFixture(async (command, arguments_) => {
    if (command === "docker" && arguments_[0] === "ps") {
      return { signal: null, status: 0, stderr: "", stdout: `${token}|${cluster}-control-plane\n`, thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "inspect") {
      return { signal: null, status: 0, stderr: "", stdout: `${JSON.stringify(kindNodeDocument(cluster, networkId, token))}\n`, thrown: false, timedOut: false };
    }
    throw new Error("unexpected command");
  });
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await fixture.system.initialize(phase);
  fixture.recordFile(`${fixture.root}/kubeconfig`, Buffer.from(kubeconfigDocument(cluster)));
  fixture.system.networkIdentity = { id: networkId, name: cluster };
  await fixture.system.verifyCluster(phase, "ownership");
  fixture.files.set(`${fixture.root}/kubeconfig`, Buffer.from(kubeconfigDocument(cluster, "51235")));
  await assert.rejects(() => fixture.system.verifyCluster(phase, "ownership"), { name: "Failure" });
});

test("validates exactly four Ready product pods and four internal services", () => {
  const state = kubernetesState();
  assert.deepEqual(validateKubernetesState(state), {
    internal: true,
    pods: 4,
    ready: 4,
    services: 4,
  });
  const mutations = [
    (value) => { value.pods.pop(); },
    (value) => { value.pods.push(structuredClone(value.pods[0])); },
    (value) => { value.pods[0].status.phase = "Pending"; },
    (value) => { value.pods[0].status.containerStatuses[0].ready = false; },
    (value) => { value.pods[0].status.containerStatuses[0].restartCount = 1; },
    (value) => { value.pods[0].spec.containers[0].image = "busybox:latest"; },
    (value) => { value.pods[0].metadata.labels.extra = "value"; },
    (value) => { value.pods[0].spec.securityContext.runAsUser = 0; },
    (value) => { value.pods[0].spec.containers[0].securityContext.readOnlyRootFilesystem = false; },
    (value) => { value.pods[0].spec.containers[0].readinessProbe.httpGet.path = "/healthz"; },
    (value) => { value.pods[0].spec.containers[0].env = [{ name: "AWS_ACCESS_KEY_ID", value: "fixture" }]; },
    (value) => { value.pods[0].spec.hostNetwork = true; },
    (value) => { value.deployments[0].status.readyReplicas = 0; },
    (value) => { value.deployments[0].status.observedGeneration = 0; },
    (value) => { value.services[0].spec.type = "NodePort"; },
    (value) => { value.services[0].spec.externalIPs = ["127.0.0.1"]; },
    (value) => { value.services[0].spec.selector["app.kubernetes.io/name"] = "event-ingest"; },
    (value) => { value.services.push(structuredClone(value.services[0])); },
    (value) => { value.namespace.metadata.uid = "invalid"; },
    (value) => { value.replicaSets[0].metadata.ownerReferences[0].uid = value.deployments[1].metadata.uid; },
    (value) => { value.pods[0].metadata.ownerReferences[0].uid = value.replicaSets[1].metadata.uid; },
    (value) => { value.endpointSlices[0].endpoints = []; },
    (value) => { value.endpointSlices[0].endpoints[0].targetRef.uid = value.pods[1].metadata.uid; },
    (value) => { value.nodeName = "shared-node"; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(state);
    mutate(value);
    assert.throws(() => validateKubernetesState(value), { name: "Failure" });
  }
});

test("projects every dangerous pod field and proves exact workload-to-endpoint ownership", async () => {
  const requests = [];
  assert.deepEqual(await verifyProjectedProviderState(providerKubernetesState(), requests), {
    internal: true, pods: 4, ready: 4, services: 4,
  });
  assert.deepEqual(requests, [
    "namespace", "deployment", "replicaset", "pod", "service", "endpointslice", "ingress",
  ]);

  const mutations = [
    (value) => { value.pods[0].spec.containers[0].command = ["/bin/sh"]; },
    (value) => { value.pods[0].spec.containers[0].args = ["--unsafe"]; },
    (value) => { value.pods[0].spec.containers[0].env = [{ name: "AWS_SECRET_ACCESS_KEY", value: "fixture" }]; },
    (value) => { value.pods[0].spec.containers[0].envFrom = [{ secretRef: { name: "fixture" } }]; },
    (value) => { value.pods[0].spec.containers[0].volumeMounts = [{ mountPath: "/secret", name: "secret" }]; },
    (value) => { value.pods[0].spec.initContainers = [structuredClone(value.pods[0].spec.containers[0])]; },
    (value) => { value.pods[0].spec.ephemeralContainers = [{}]; },
    (value) => { value.pods[0].spec.imagePullSecrets = [{ name: "registry-secret" }]; },
    (value) => { value.pods[0].spec.hostAliases = [{ ip: "127.0.0.1", hostnames: ["provider"] }]; },
    (value) => { value.pods[0].spec.shareProcessNamespace = true; },
    (value) => { value.pods[0].spec.serviceAccountName = "privileged"; },
    (value) => { value.deployments[0].metadata.uid = value.deployments[1].metadata.uid; },
    (value) => { value.deployments[0].spec.template.spec.containers[0].env = [{ name: "TOKEN", value: "fixture" }]; },
    (value) => { value.replicaSets[0].metadata.ownerReferences[0].uid = value.deployments[1].metadata.uid; },
    (value) => { value.pods[0].metadata.ownerReferences[0].uid = value.replicaSets[1].metadata.uid; },
    (value) => { value.services[0].metadata.uid = value.services[1].metadata.uid; },
    (value) => { value.endpointSlices[0].endpoints[0].addresses = [value.pods[1].status.podIP]; },
    (value) => { value.endpointSlices[0].endpoints[0].targetRef.uid = value.pods[1].metadata.uid; },
    (value) => { value.endpointSlices[0].metadata.labels["kubernetes.io/service-name"] = PRODUCTS[1].name; },
  ];
  for (const mutate of mutations) {
    const value = providerKubernetesState();
    mutate(value);
    await assert.rejects(() => verifyProjectedProviderState(value), { name: "Failure" });
  }
});

class FakeLifecycle {
  constructor(failures = {}) {
    this.events = [];
    this.failures = failures;
  }
  async call(name, phase) {
    if (phase.signal.aborted) throw new Failure("deadline");
    this.events.push(name);
    if (this.failures[name]) throw this.failures[name];
  }
  initialize(phase) { return this.call("initialize", phase); }
  preflight(phase) { return this.call("preflight", phase); }
  buildImages(phase) { return this.call("buildImages", phase); }
  createNetwork(phase) { return this.call("createNetwork", phase); }
  createCluster(phase) { return this.call("createCluster", phase); }
  loadImages(phase) { return this.call("loadImages", phase); }
  applyManifests(phase) { return this.call("applyManifests", phase); }
  async verifyReadiness(phase) {
    await this.call("verifyReadiness", phase);
    return { internal: true, pods: 4, ready: 4, services: 4 };
  }
  joinMutations(phase) { return this.call("joinMutations", phase); }
  cleanup(phase) { return this.call("cleanup", phase); }
  auditAbsence(phase) { return this.call("auditAbsence", phase); }
}

test("orchestrates the exact main and independent reverse cleanup sequence", async () => {
  const runtime = new FakeLifecycle();
  assert.deepEqual(await orchestrate(runtime, {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 20,
  }), { cleanup: true, internal: true, pods: 4, ready: 4, services: 4 });
  assert.deepEqual(runtime.events, [
    "initialize", "preflight", "buildImages", "createNetwork", "createCluster",
    "loadImages", "applyManifests", "verifyReadiness", "joinMutations", "cleanup", "auditAbsence",
  ]);
});

test("cleanup continues and wins over main and audit failures after settlement", async () => {
  const runtime = new FakeLifecycle({
    applyManifests: new Failure("provider"),
    cleanup: new Failure("cleanup"),
    auditAbsence: new Failure("ownership"),
  });
  await assert.rejects(orchestrate(runtime, {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 20,
  }), (error) => error instanceof Failure && error.category === "cleanup");
  assert.deepEqual(runtime.events.slice(-3), ["joinMutations", "cleanup", "auditAbsence"]);
});

test("unproved mutation settlement blocks destructive cleanup and absence audit", async () => {
  const runtime = new FakeLifecycle({
    applyManifests: new Failure("provider"),
    joinMutations: new Failure("deadline"),
  });
  await assert.rejects(orchestrate(runtime, {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 20,
  }), (error) => error instanceof Failure && error.category === "cleanup");
  assert.deepEqual(runtime.events.slice(-1), ["joinMutations"]);
  assert.equal(runtime.events.includes("cleanup"), false);
  assert.equal(runtime.events.includes("auditAbsence"), false);
});

test("bounds an uncooperative main phase before independent cleanup", async () => {
  const runtime = new FakeLifecycle();
  runtime.buildImages = async (phase) => {
    runtime.events.push("buildImages");
    await new Promise((resolve) => phase.signal.addEventListener("abort", resolve, { once: true }));
    throw new Failure("deadline");
  };
  await assert.rejects(orchestrate(runtime, {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 10,
    settlementTimeoutMilliseconds: 20,
  }), (error) => error instanceof Failure && error.category === "deadline");
  assert.deepEqual(runtime.events.slice(-3), ["joinMutations", "cleanup", "auditAbsence"]);
});

test("runMain emits exactly one fixed success or categorized failure line", async () => {
  const success = { text: "", write(value) { this.text += value; } };
  const successError = { text: "", write(value) { this.text += value; } };
  let exitCode;
  assert.equal(await runMain(new FakeLifecycle(), {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 20,
    setExitCode(value) { exitCode = value; },
    stderr: successError,
    stdout: success,
  }), 0);
  assert.equal(success.text, `${SUCCESS_LINE}\n`);
  assert.equal(successError.text, "");
  assert.equal(exitCode, 0);

  const failure = { text: "", write(value) { this.text += value; } };
  assert.equal(await runMain(new FakeLifecycle({ preflight: new Error("secret provider output") }), {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 20,
    setExitCode(value) { exitCode = value; },
    stderr: failure,
    stdout: { write() {} },
  }), 1);
  assert.equal(failure.text, "Local product manifests failed: panic rejected.\n");
  assert.doesNotMatch(failure.text, /secret|provider output/);
  assert.equal(exitCode, 1);

  const cleanupPanic = { text: "", write(value) { this.text += value; } };
  assert.equal(await runMain(new FakeLifecycle({ cleanup: new Error("cleanup panic detail") }), {
    cleanupTimeoutMilliseconds: 100,
    mainTimeoutMilliseconds: 100,
    settlementTimeoutMilliseconds: 20,
    setExitCode(value) { exitCode = value; },
    stderr: cleanupPanic,
    stdout: { write() {} },
  }), 1);
  assert.equal(cleanupPanic.text, "Local product manifests failed: panic rejected.\n");
  assert.doesNotMatch(cleanupPanic.text, /detail/);
});

test("constructs a concrete process runtime without ambient kube authority", () => {
  const runtime = DockerKindRuntime.fromProcess({
    HOME: "/Users/test",
    LANG: "C.UTF-8",
    PATH: "/usr/local/bin:/usr/bin:/bin",
  });
  assert.ok(runtime instanceof DockerKindRuntime);
  assert.equal(runtime.input.hostPlatform, process.platform === "darwin" ? `darwin/${process.arch === "arm64" ? "arm64" : "amd64"}` : `linux/${process.arch === "arm64" ? "arm64" : "amd64"}`);
  assert.equal(runtime.input.nodePlatform, process.arch === "arm64" ? "linux/arm64" : "linux/amd64");
  assert.match(runtime.input.marker, /^[0-9a-f]{16}$/);

  const nativeEnvironment = Object.create(Object.getPrototypeOf(process.env));
  nativeEnvironment.HOME = "/Users/test";
  nativeEnvironment.LANG = "C.UTF-8";
  nativeEnvironment.PATH = "/usr/local/bin:/usr/bin:/bin";
  assert.ok(DockerKindRuntime.fromProcess(nativeEnvironment) instanceof DockerKindRuntime);
});

test("concrete lifecycle admits only an exact-owned empty workspace", async () => {
  const root = "/safe/tmp/zasp-m1-30a-0123456789abcdef-runtime-owned";
  const directories = new Map([
    ["/safe/tmp", []],
  ]);
  const files = new Map();
  const identities = new Map([
    ["/safe/tmp", { dev: 1, ino: 1 }],
  ]);
  const dependencies = {
    canonicalPath: async (path) => path,
    changeMode: async () => {},
    command: async () => ({ signal: null, status: 0, stderr: "", stdout: "", thrown: false, timedOut: false }),
    fetchBytes: async () => Buffer.alloc(0),
    hashBytes: () => KIND_PINS.kind.assets["darwin/arm64"].sha256,
    makeDirectory: async (path) => {
      directories.set(path, []);
      identities.set(path, { dev: 2, ino: identities.size + 2 });
    },
    makeTemp: async (prefix) => {
      assert.equal(prefix, "/safe/tmp/zasp-m1-30a-0123456789abcdef-runtime-");
      directories.set(root, []);
      identities.set(root, { dev: 2, ino: 2 });
      return root;
    },
    readDirectory: async (path) => directories.get(path) ?? [],
    readPath: async (path) => files.get(path),
    removePath: async () => {},
    statPath: async (path) => {
      const identity = identities.get(path);
      if (!identity) {
        const error = new Error("missing");
        error.code = "ENOENT";
        throw error;
      }
      return {
        ...identity,
        isDirectory: () => directories.has(path),
        isFile: () => files.has(path),
        isSymbolicLink: () => false,
        mode: files.has(path) ? 0o100600 : 0o40700,
        size: files.get(path)?.length ?? 0,
      };
    },
    tempParent: "/safe/tmp",
    writePath: async (path, value) => {
      files.set(path, value);
      identities.set(path, { dev: 2, ino: identities.size + 2 });
    },
  };
  const input = {
    home: "/Users/test",
    hostPlatform: "darwin/arm64",
    marker,
    nodePlatform: "linux/arm64",
    path: "/usr/local/bin:/usr/bin:/bin",
    repositoryRoot: "/repository",
  };
  const system = new LocalProductSystem(input, dependencies);
  const controller = new AbortController();
  const phase = { assertActive() {}, signal: controller.signal };
  await system.initialize(phase);
  assert.equal(system.paths.root, root);
  assert.deepEqual(system.temporaryIdentity, { dev: 2, ino: 2, path: root });
  assert.equal(files.get(`${root}/kind.json`), `${JSON.stringify(buildKindConfig())}\n`);
  assert.equal(files.get(`${root}/manifests.yaml`), await readFile(productManifestPath, "utf8"));
  assert.equal(system.environment.KUBECONFIG, `${root}/kubeconfig`);
  assert.equal(system.environment.KIND_EXPERIMENTAL_DOCKER_NETWORK, "zasp-m1-30a-0123456789abcdef");
  assert.equal(system.environment.DOCKER_CONFIG, `${root}/docker`);
  assert.equal(system.mutationSettlements.length, 8,
    "mkdtemp, five directories, and two files are journaled before interpretation");
});

test("concrete lifecycle retains and safely cleans a post-mkdtemp validation failure", async () => {
  const fixture = createConcreteFixture(async () => ({
    signal: null, status: 0, stderr: "", stdout: "", thrown: false, timedOut: false,
  }));
  const originalCanonical = fixture.dependencies.canonicalPath;
  let rejectCandidate = true;
  fixture.dependencies.canonicalPath = async (path) => {
    if (path === fixture.root && rejectCandidate) throw new Error("transient validation failure");
    return originalCanonical(path);
  };
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await assert.rejects(() => fixture.system.initialize(phase), { name: "Failure" });
  assert.equal(fixture.directories.has(fixture.root), true);
  rejectCandidate = false;
  await fixture.system.auditAbsence(phase);
  assert.equal(fixture.directories.has(fixture.root), false);
});

function createConcreteFixture(command) {
  const root = "/safe/tmp/zasp-m1-30a-0123456789abcdef-runtime-owned";
  const directories = new Map([["/safe/tmp", new Set()]]);
  const files = new Map();
  const identities = new Map([["/safe/tmp", { dev: 1, ino: 1 }]]);
  let nextInode = 2;
  const addToParent = (path) => {
    const index = path.lastIndexOf("/");
    const parent = index === 0 ? "/" : path.slice(0, index);
    directories.get(parent)?.add(path.slice(index + 1));
  };
  const dependencies = {
    canonicalPath: async (path) => path,
    changeMode: async () => {},
    command,
    fetchBytes: async () => Buffer.alloc(0),
    hashBytes: () => KIND_PINS.kind.assets["darwin/arm64"].sha256,
    makeDirectory: async (path) => {
      directories.set(path, new Set());
      identities.set(path, { dev: 2, ino: nextInode++ });
      addToParent(path);
    },
    makeTemp: async () => {
      directories.set(root, new Set());
      identities.set(root, { dev: 2, ino: nextInode++ });
      addToParent(root);
      return root;
    },
    readDirectory: async (path) => [...(directories.get(path) ?? [])],
    readPath: async (path) => files.get(path),
    removePath: async (path) => {
      for (const candidate of [...directories.keys(), ...files.keys()]) {
        if (candidate === path || candidate.startsWith(`${path}/`)) {
          directories.delete(candidate);
          files.delete(candidate);
          identities.delete(candidate);
        }
      }
      const index = path.lastIndexOf("/");
      const parent = index === 0 ? "/" : path.slice(0, index);
      directories.get(parent)?.delete(path.slice(index + 1));
    },
    statPath: async (path) => {
      const identity = identities.get(path);
      if (!identity) {
        const error = new Error("missing");
        error.code = "ENOENT";
        throw error;
      }
      return {
        ...identity,
        isDirectory: () => directories.has(path),
        isFile: () => files.has(path),
        isSymbolicLink: () => false,
        mode: files.has(path) ? 0o100600 : 0o40700,
        size: files.get(path)?.length ?? 0,
      };
    },
    tempParent: "/safe/tmp",
    writePath: async (path, value) => {
      files.set(path, value);
      identities.set(path, { dev: 2, ino: nextInode++ });
      addToParent(path);
    },
  };
  const input = {
    home: "/Users/test",
    hostPlatform: "darwin/arm64",
    marker,
    nodePlatform: "linux/arm64",
    path: "/usr/local/bin:/usr/bin:/bin",
    repositoryRoot: "/repository",
  };
  const recordFile = (path, value = Buffer.from("binary")) => {
    files.set(path, value);
    identities.set(path, { dev: 2, ino: nextInode++ });
    addToParent(path);
  };
  return {
    dependencies, directories, files, identities, input, recordFile, root,
    system: new LocalProductSystem(input, dependencies),
  };
}

test("concrete preflight proves global absence and only explicit local tools", async () => {
  const calls = [];
  const fixture = createConcreteFixture(async (command, arguments_, options) => {
    calls.push({ arguments: arguments_, command, environment: options.environment });
    if (command === "docker" && arguments_[0] === "version") {
      return { signal: null, status: 0, stderr: "", stdout: "29.4.0\n", thrown: false, timedOut: false };
    }
    if (command === "kubectl" && arguments_[0] === "version") {
      return { signal: null, status: 0, stderr: "", stdout: '{"clientVersion":{"gitVersion":"v1.35.3"}}\n', thrown: false, timedOut: false };
    }
    return { signal: null, status: 0, stderr: "", stdout: "", thrown: false, timedOut: false };
  });
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await fixture.system.initialize(phase);
  await fixture.system.preflight(phase);
  assert.deepEqual(calls.map(({ command, arguments: arguments_ }) => [command, ...arguments_]), [
    ["docker", "ps", "--all", "--quiet", "--no-trunc", "--filter", "name=^/zasp-m1-30a-"],
    ["docker", "ps", "--all", "--quiet", "--no-trunc", "--filter", "label=zasp.dev/proof=m1-30a"],
    ["docker", "network", "ls", "--quiet", "--no-trunc", "--filter", "name=^zasp-m1-30a-"],
    ["docker", "network", "ls", "--quiet", "--no-trunc", "--filter", "label=zasp.dev/proof=m1-30a"],
    ...PRODUCTS.map((product) => [
      "docker", "image", "ls", "--quiet", "--no-trunc", "--filter", `reference=${product.image}`,
    ]),
    ["docker", "image", "ls", "--quiet", "--no-trunc", "--filter", "label=zasp.dev/proof=m1-30a"],
    ["docker", "version", "--format", "{{.Server.Version}}"],
    ["kubectl", "version", "--client=true", "--output=json"],
  ]);
  assert.ok(calls.every(({ environment }) => environment.KUBECONFIG === `${fixture.root}/kubeconfig`));
  assert.ok(calls.every(({ environment }) => environment.DOCKER_CONFIG === `${fixture.root}/docker`));
});

test("concrete runtime fences retained workspace files before provider mutation", async () => {
  const networkId = "a".repeat(64);
  let calls = 0;
  let fixture;
  fixture = createConcreteFixture(async (command, arguments_) => {
    calls += 1;
    if (command === "docker" && arguments_[0] === "network") return {
      signal: null, status: 0, stderr: "", thrown: false, timedOut: false,
      stdout: `${JSON.stringify([networkId, fixture.system.cluster, "bridge", false, {
        "zasp.dev/proof": "m1-30a", "zasp.dev/run": marker,
      }, {}, {}, { Config: [{ Gateway: "172.20.0.1", Subnet: "172.20.0.0/16" }], Driver: "default", Options: {} }])}\n`,
    };
    return { signal: null, status: 0, stderr: "", stdout: "", thrown: false, timedOut: false };
  });
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await fixture.system.initialize(phase);
  fixture.recordFile(`${fixture.root}/kind`, Buffer.from("kind"));
  fixture.recordFile(`${fixture.root}/kubeconfig`, Buffer.from(kubeconfigDocument(fixture.system.cluster)));
  await fixture.system.rememberOwnedPath(`${fixture.root}/kind`, "file", phase, "ownership");
  fixture.system.networkMayHaveApplied = true;
  fixture.system.networkIdentity = { id: networkId, name: fixture.system.cluster };
  fixture.identities.set(`${fixture.root}/kind.json`, { dev: 9, ino: 9 });
  await assert.rejects(() => fixture.system.createCluster(phase), { name: "Failure" });
  assert.equal(calls, 0, "the changed file is rejected before any provider read or mutation");

  let sameIdentityCalls = 0;
  const sameIdentity = createConcreteFixture(async () => {
    sameIdentityCalls += 1;
    return { signal: null, status: 0, stderr: "", stdout: "", thrown: false, timedOut: false };
  });
  await sameIdentity.system.initialize(phase);
  sameIdentity.recordFile(`${sameIdentity.root}/kind`, Buffer.from("kind"));
  sameIdentity.recordFile(`${sameIdentity.root}/kubeconfig`, Buffer.from(kubeconfigDocument(sameIdentity.system.cluster)));
  await sameIdentity.system.rememberOwnedPath(`${sameIdentity.root}/kind`, "file", phase, "ownership");
  sameIdentity.system.networkMayHaveApplied = true;
  sameIdentity.system.networkIdentity = { id: networkId, name: sameIdentity.system.cluster };
  sameIdentity.system.verifyNetwork = async () => {};
  const kindConfigBytes = Buffer.from(sameIdentity.files.get(`${sameIdentity.root}/kind.json`));
  kindConfigBytes[0] = kindConfigBytes[0] === 0x7b ? 0x5b : 0x7b;
  sameIdentity.files.set(`${sameIdentity.root}/kind.json`, kindConfigBytes);
  await assert.rejects(() => sameIdentity.system.createCluster(phase), { name: "Failure" });
  assert.equal(sameIdentityCalls, 0);

  sameIdentity.system.verifyCluster = async () => {};
  const manifestBytes = Buffer.from(sameIdentity.files.get(`${sameIdentity.root}/manifests.yaml`));
  manifestBytes[0] = manifestBytes[0] === 0x61 ? 0x62 : 0x61;
  sameIdentity.files.set(`${sameIdentity.root}/manifests.yaml`, manifestBytes);
  await assert.rejects(() => sameIdentity.system.applyManifests(phase), { name: "Failure" });
  assert.equal(sameIdentityCalls, 0);
});

test("concrete build downloads exact kind and retains four exact image identities", async () => {
  const calls = [];
  let fixture;
  fixture = createConcreteFixture(async (command, arguments_, options) => {
    calls.push({ arguments: arguments_, command, cwd: options.cwd, environment: options.environment });
    if (command === "go") {
      const output = arguments_[arguments_.indexOf("-o") + 1];
      fixture.recordFile(output);
      return { signal: null, status: 0, stderr: "", stdout: "", thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "build") {
      return { signal: null, status: 0, stderr: "", stdout: "", thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "image" && arguments_[1] === "inspect") {
      const product = PRODUCTS.find((entry) => entry.image === arguments_[2]);
      const index = PRODUCTS.indexOf(product);
      return {
        signal: null,
        status: 0,
        stderr: "",
        stdout: `${JSON.stringify(rawImageDocument(product, {
          Id: `sha256:${String(index + 1).repeat(64)}`,
          RootFS: { Layers: [`sha256:${String(index + 5).repeat(64)}`], Type: "layers" },
        }))}\n`,
        thrown: false,
        timedOut: false,
      };
    }
    throw new Error("unexpected command");
  });
  fixture.dependencies.fetchBytes = async (url, limit) => {
    assert.equal(url, KIND_PINS.kind.assets["darwin/arm64"].url);
    assert.equal(limit, 134_217_728);
    return Buffer.from("kind-binary");
  };
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await fixture.system.initialize(phase);
  await fixture.system.buildImages(phase);

  assert.equal(calls.filter(({ command }) => command === "go").length, 4);
  assert.equal(calls.filter(({ command, arguments: arguments_ }) =>
    command === "docker" && arguments_[0] === "build").length, 4);
  assert.equal(calls.filter(({ command, arguments: arguments_ }) =>
    command === "docker" && arguments_[0] === "image").length, 4);
  assert.deepEqual([...fixture.system.imageIdentities.keys()], PRODUCTS.map(({ name }) => name));
  assert.deepEqual([...fixture.system.imageIdentities.values()].map(({ id }) => id),
    [1, 2, 3, 4].map((value) => `sha256:${String(value).repeat(64)}`));
  assert.deepEqual(fixture.files.get(`${fixture.root}/kind`), Buffer.from("kind-binary"));
  assert.ok(calls.filter(({ command }) => command === "go").every(({ environment }) =>
    environment.CGO_ENABLED === "0" && environment.GOENV === "off" && environment.GOWORK === "off"));
});

test("concrete lifecycle creates and retains only the exact network and kind node", async () => {
  const networkId = "a".repeat(64);
  const nodeId = "b".repeat(64);
  const calls = [];
  let fixture;
  fixture = createConcreteFixture(async (command, arguments_) => {
    calls.push([command, ...arguments_]);
    if (command === "docker" && arguments_[0] === "network" && arguments_[1] === "create") {
      return { signal: null, status: 0, stderr: "", stdout: `${networkId}\n`, thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "network" && arguments_[1] === "inspect") {
      return {
        signal: null, status: 0, stderr: "", thrown: false, timedOut: false,
        stdout: `${JSON.stringify([networkId, fixture.system.cluster, "bridge", false, {
          "zasp.dev/proof": "m1-30a", "zasp.dev/run": marker,
        }, {}, {}, { Config: [{ Gateway: "172.20.0.1", Subnet: "172.20.0.0/16" }], Driver: "default", Options: {} }])}\n`,
      };
    }
    if (command === `${fixture.root}/kind`) {
      fixture.recordFile(`${fixture.root}/kubeconfig`, Buffer.from(kubeconfigDocument(fixture.system.cluster)));
      return { signal: null, status: 0, stderr: "", stdout: "created\n", thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "ps") {
      return { signal: null, status: 0, stderr: "", stdout: `${nodeId}|${fixture.system.cluster}-control-plane\n`, thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "inspect") {
      return { signal: null, status: 0, stderr: "", stdout: `${JSON.stringify(kindNodeDocument(fixture.system.cluster, networkId, nodeId))}\n`, thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "image") {
      const product = PRODUCTS.find((entry) => fixture.system.imageIdentities.get(entry.name)?.id === arguments_[2]);
      const index = PRODUCTS.indexOf(product);
      return {
        signal: null, status: 0, stderr: "", thrown: false, timedOut: false,
        stdout: `${JSON.stringify(rawImageDocument(product, {
          Id: `sha256:${String(index + 1).repeat(64)}`,
          RootFS: { Layers: [`sha256:${String(index + 5).repeat(64)}`], Type: "layers" },
        }))}\n`,
      };
    }
    throw new Error("unexpected command");
  });
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await fixture.system.initialize(phase);
  fixture.recordFile(`${fixture.root}/kind`, Buffer.from("kind"));
  await fixture.system.rememberOwnedPath(`${fixture.root}/kind`, "file", phase, "ownership");
  await fixture.system.createNetwork(phase);
  await fixture.system.createCluster(phase);

  assert.equal(fixture.system.networkIdentity.id, networkId);
  assert.equal(fixture.system.nodeIdentity.token, nodeId);
  assert.equal(fixture.system.nodeIdentity.volumeToken, "c".repeat(64));
  assert.ok(calls.some((value) => value[0] === `${fixture.root}/kind` &&
    value.includes("--image") && value.includes(KIND_PINS.node.reference)));
});

test("concrete lifecycle loads all images and proves the exact Ready Kubernetes state", async () => {
  const networkId = "a".repeat(64);
  const nodeId = "b".repeat(64);
  const state = providerKubernetesState();
  const calls = [];
  let fixture;
  fixture = createConcreteFixture(async (command, arguments_) => {
    calls.push([command, ...arguments_]);
    if (command === "docker" && arguments_[0] === "network") {
      return {
        signal: null, status: 0, stderr: "", thrown: false, timedOut: false,
        stdout: `${JSON.stringify([networkId, fixture.system.cluster, "bridge", false, {
          "zasp.dev/proof": "m1-30a", "zasp.dev/run": marker,
        }, {}, { [nodeId]: {} }, { Config: [{ Gateway: "172.20.0.1", Subnet: "172.20.0.0/16" }], Driver: "default", Options: {} }])}\n`,
      };
    }
    if (command === "docker" && arguments_[0] === "ps") {
      return { signal: null, status: 0, stderr: "", stdout: `${nodeId}|${fixture.system.cluster}-control-plane\n`, thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "inspect") {
      return { signal: null, status: 0, stderr: "", stdout: `${JSON.stringify(kindNodeDocument(fixture.system.cluster, networkId, nodeId))}\n`, thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "image") {
      const product = PRODUCTS.find((entry) => fixture.system.imageIdentities.get(entry.name)?.id === arguments_[2]);
      const index = PRODUCTS.indexOf(product);
      return {
        signal: null, status: 0, stderr: "", thrown: false, timedOut: false,
        stdout: `${JSON.stringify(rawImageDocument(product, {
          Id: `sha256:${String(index + 1).repeat(64)}`,
          RootFS: { Layers: [`sha256:${String(index + 5).repeat(64)}`], Type: "layers" },
        }))}\n`,
      };
    }
    if (command === `${fixture.root}/kind` && arguments_[0] === "load") {
      return { signal: null, status: 0, stderr: "", stdout: "loaded\n", thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "exec") {
      if (arguments_.includes("images") && arguments_.includes("list")) {
        return { signal: null, status: 0, stderr: "", stdout: containerdInventory(), thrown: false, timedOut: false };
      }
      if (arguments_.includes("content") && arguments_.includes("get")) {
        const digest = arguments_.at(-1);
        const product = PRODUCTS.find((entry) => [
          containerdImport(entry), containerdTarget(entry), `sha256:${String(PRODUCTS.indexOf(entry) + 1).repeat(64)}`,
        ].includes(digest));
        const document = digest === containerdImport(product)
          ? containerdImportIndex(product)
          : digest === containerdTarget(product)
            ? containerdTargetManifest(product)
            : containerdImageConfig(product);
        return { signal: null, status: 0, stderr: "", stdout: `${JSON.stringify(document)}\n`, thrown: false, timedOut: false };
      }
    }
    if (command === "kubectl" && arguments_.includes("apply")) {
      return { signal: null, status: 0, stderr: "", stdout: "applied\n", thrown: false, timedOut: false };
    }
    if (command === "kubectl" && arguments_.includes("wait")) {
      return { signal: null, status: 0, stderr: "", stdout: "ready\n", thrown: false, timedOut: false };
    }
    if (command === "kubectl" && arguments_.includes("namespace")) {
      return { signal: null, status: 0, stderr: "", stdout: `${JSON.stringify(state.namespace)}\n`, thrown: false, timedOut: false };
    }
    if (command === "kubectl" && arguments_.includes("deployment")) {
      return { signal: null, status: 0, stderr: "", stdout: `${JSON.stringify({ apiVersion: "v1", items: state.deployments, kind: "List", metadata: { resourceVersion: "" } })}\n`, thrown: false, timedOut: false };
    }
    if (command === "kubectl" && arguments_.includes("replicaset")) {
      return { signal: null, status: 0, stderr: "", stdout: `${JSON.stringify({ apiVersion: "v1", items: state.replicaSets, kind: "List", metadata: { resourceVersion: "" } })}\n`, thrown: false, timedOut: false };
    }
    if (command === "kubectl" && arguments_.includes("pod")) {
      return { signal: null, status: 0, stderr: "", stdout: `${JSON.stringify({ apiVersion: "v1", items: state.pods, kind: "List", metadata: { resourceVersion: "" } })}\n`, thrown: false, timedOut: false };
    }
    if (command === "kubectl" && arguments_.includes("service")) {
      return { signal: null, status: 0, stderr: "", stdout: `${JSON.stringify({ apiVersion: "v1", items: state.services, kind: "List", metadata: { resourceVersion: "" } })}\n`, thrown: false, timedOut: false };
    }
    if (command === "kubectl" && arguments_.includes("endpointslice")) {
      return { signal: null, status: 0, stderr: "", stdout: `${JSON.stringify({ apiVersion: "v1", items: state.endpointSlices, kind: "List", metadata: { resourceVersion: "" } })}\n`, thrown: false, timedOut: false };
    }
    if (command === "kubectl" && arguments_.includes("ingress")) {
      return { signal: null, status: 0, stderr: "", stdout: '{"apiVersion":"v1","items":[],"kind":"List","metadata":{"resourceVersion":""}}\n', thrown: false, timedOut: false };
    }
    throw new Error("unexpected command");
  });
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await fixture.system.initialize(phase);
  fixture.recordFile(`${fixture.root}/kind`, Buffer.from("kind"));
  fixture.recordFile(`${fixture.root}/kubeconfig`, Buffer.from(kubeconfigDocument(fixture.system.cluster)));
  await fixture.system.rememberOwnedPath(`${fixture.root}/kind`, "file", phase, "ownership");
  await fixture.system.rememberOwnedPath(`${fixture.root}/kubeconfig`, "file", phase, "ownership");
  fixture.system.networkMayHaveApplied = true;
  fixture.system.networkIdentity = { id: networkId, name: fixture.system.cluster };
  fixture.system.clusterMayHaveApplied = true;
  fixture.system.nodeIdentity = validateKindNodeInspectionForTest(
    kindNodeDocument(fixture.system.cluster, networkId, nodeId), fixture.system.cluster, networkId, nodeId,
  );
  for (const [index, product] of PRODUCTS.entries()) {
    fixture.system.imageIdentities.set(product.name, {
      architecture: "arm64", id: `sha256:${String(index + 1).repeat(64)}`,
      layers: [`sha256:${String(index + 5).repeat(64)}`], reference: product.image,
    });
  }
  await fixture.system.loadImages(phase);
  await fixture.system.applyManifests(phase);
  assert.deepEqual(await fixture.system.verifyReadiness(phase), {
    internal: true, pods: 4, ready: 4, services: 4,
  });
  assert.equal(calls.filter((value) => value[1] === "load").length, 4);
  assert.ok(calls.some((value) => value.includes("apply") && value.includes(`${fixture.root}/manifests.yaml`)));
});

function validateKindNodeInspectionForTest(document, cluster, networkId, token) {
  const node = document[0];
  const network = node.NetworkSettings.Networks[cluster];
  return {
    apiPort: "51234",
    gateway: network.Gateway,
    imageId: node.Image,
    ipAddress: network.IPAddress,
    macAddress: network.MacAddress,
    networkId,
    token,
    volumeToken: node.Mounts.find(({ Type }) => Type === "volume").Name,
  };
}

test("concrete cleanup re-proves exact identities, continues in reverse order, and audits zero", async () => {
  const networkId = "a".repeat(64);
  const nodeId = "b".repeat(64);
  const volumeId = "c".repeat(64);
  const imageIds = new Map(PRODUCTS.map((product, index) =>
    [product.name, `sha256:${String(index + 1).repeat(64)}`]));
  let nodePresent = true;
  let networkPresent = true;
  const imagesPresent = new Set(imageIds.values());
  let fixture;
  fixture = createConcreteFixture(async (command, arguments_) => {
    const ok = (stdout = "") => ({ signal: null, status: 0, stderr: "", stdout, thrown: false, timedOut: false });
    if (command === "docker" && arguments_[0] === "ps") {
      return ok(nodePresent ? `${nodeId}|${fixture.system.cluster}-control-plane\n` : "");
    }
    if (command === "docker" && arguments_[0] === "inspect") {
      return nodePresent
        ? ok(`${JSON.stringify(kindNodeDocument(fixture.system.cluster, networkId, nodeId))}\n`)
        : { signal: null, status: 1, stderr: `Error: No such object: ${nodeId}\n`, stdout: "[]\n", thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "rm") {
      nodePresent = false;
      return ok(`${nodeId}\n`);
    }
    if (command === "docker" && arguments_[0] === "volume") {
      return { signal: null, status: 1, stderr: `Error response from daemon: get ${volumeId}: no such volume\n`, stdout: "[]\n", thrown: false, timedOut: false };
    }
    if (command === "docker" && arguments_[0] === "network" && arguments_[1] === "inspect") {
      if (!networkPresent) return { signal: null, status: 1, stderr: `Error response from daemon: network ${networkId} not found\n`, stdout: "[]\n", thrown: false, timedOut: false };
      return ok(`${JSON.stringify([networkId, fixture.system.cluster, "bridge", false, {
        "zasp.dev/proof": "m1-30a", "zasp.dev/run": marker,
      }, {}, {}, { Config: [{ Gateway: "172.20.0.1", Subnet: "172.20.0.0/16" }], Driver: "default", Options: {} }])}\n`);
    }
    if (command === "docker" && arguments_[0] === "network" && arguments_[1] === "rm") {
      networkPresent = false;
      return ok(`${networkId}\n`);
    }
    if (command === "docker" && arguments_[0] === "network" && arguments_[1] === "ls") return ok();
    if (command === "docker" && arguments_[0] === "image" && arguments_[1] === "inspect") {
      const id = arguments_[2];
      if (!imagesPresent.has(id)) return { signal: null, status: 1, stderr: `Error response from daemon: No such image: ${id}\n`, stdout: "[]\n", thrown: false, timedOut: false };
      const product = PRODUCTS.find((entry) => imageIds.get(entry.name) === id);
      const index = PRODUCTS.indexOf(product);
      return ok(`${JSON.stringify(rawImageDocument(product, {
        Id: id, RootFS: { Layers: [`sha256:${String(index + 5).repeat(64)}`], Type: "layers" },
      }))}\n`);
    }
    if (command === "docker" && arguments_[0] === "image" && arguments_[1] === "rm") {
      imagesPresent.delete(arguments_[3]);
      return ok(`${arguments_[3]}\n`);
    }
    if (command === "docker" && arguments_[0] === "image" && arguments_[1] === "ls") return ok();
    throw new Error(`unexpected command ${command} ${arguments_.join(" ")}`);
  });
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await fixture.system.initialize(phase);
  fixture.recordFile(`${fixture.root}/kind`, Buffer.from("kind"));
  fixture.recordFile(`${fixture.root}/kubeconfig`, Buffer.from(kubeconfigDocument(fixture.system.cluster)));
  fixture.system.networkMayHaveApplied = true;
  fixture.system.networkIdentity = { id: networkId, name: fixture.system.cluster };
  fixture.system.clusterMayHaveApplied = true;
  fixture.system.nodeIdentity = validateKindNodeInspectionForTest(
    kindNodeDocument(fixture.system.cluster, networkId, nodeId), fixture.system.cluster, networkId, nodeId,
  );
  for (const product of PRODUCTS) fixture.system.imageIdentities.set(product.name, {
    architecture: "arm64", id: imageIds.get(product.name),
    layers: [`sha256:${String(PRODUCTS.indexOf(product) + 5).repeat(64)}`], reference: product.image,
  });

  await fixture.system.joinMutations(phase);
  await fixture.system.cleanup(phase);
  await fixture.system.auditAbsence(phase);
  assert.equal(nodePresent, false);
  assert.equal(networkPresent, false);
  assert.equal(imagesPresent.size, 0);
  assert.equal(fixture.directories.has(fixture.root), false);
});

test("concrete cleanup re-arms an ambiguous delayed network before exact removal", async () => {
  const networkId = "a".repeat(64);
  let present = true;
  let fixture;
  fixture = createConcreteFixture(async (command, arguments_) => {
    const ok = (stdout = "") => ({ signal: null, status: 0, stderr: "", stdout, thrown: false, timedOut: false });
    if (command === "docker" && arguments_[0] === "network" && arguments_[1] === "ls") {
      return ok(present ? `${networkId}|${fixture.system.cluster}\n` : "");
    }
    if (command === "docker" && arguments_[0] === "network" && arguments_[1] === "inspect") {
      if (!present) return { signal: null, status: 1, stderr: `Error response from daemon: network ${networkId} not found\n`, stdout: "[]\n", thrown: false, timedOut: false };
      return ok(`${JSON.stringify([networkId, fixture.system.cluster, "bridge", false, {
        "zasp.dev/proof": "m1-30a", "zasp.dev/run": marker,
      }, {}, {}, { Config: [{ Gateway: "172.20.0.1", Subnet: "172.20.0.0/16" }], Driver: "default", Options: {} }])}\n`);
    }
    if (command === "docker" && arguments_[0] === "network" && arguments_[1] === "rm") {
      present = false;
      return ok(`${networkId}\n`);
    }
    if (command === "docker" && arguments_[0] === "ps") return ok();
    if (command === "docker" && arguments_[0] === "image") return ok();
    throw new Error("unexpected command");
  });
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await fixture.system.initialize(phase);
  fixture.system.networkMayHaveApplied = true;
  await fixture.system.cleanup(phase);
  await fixture.system.auditAbsence(phase);
  assert.equal(present, false);
});

test("concrete cleanup re-arms an ambiguous delayed image before exact removal", async () => {
  const product = PRODUCTS[0];
  const imageId = `sha256:${"a".repeat(64)}`;
  let present = true;
  const fixture = createConcreteFixture(async (command, arguments_) => {
    const ok = (stdout = "") => ({ signal: null, status: 0, stderr: "", stdout, thrown: false, timedOut: false });
    if (command === "docker" && arguments_[0] === "image" && arguments_[1] === "ls") {
      const reference = arguments_.find((value) => value === `reference=${product.image}`);
      return ok(present && reference ? `${imageId}\n` : "");
    }
    if (command === "docker" && arguments_[0] === "image" && arguments_[1] === "inspect") {
      if (!present) return { signal: null, status: 1, stderr: `Error response from daemon: No such image: ${imageId}\n`, stdout: "[]\n", thrown: false, timedOut: false };
      return ok(`${JSON.stringify(rawImageDocument(product))}\n`);
    }
    if (command === "docker" && arguments_[0] === "image" && arguments_[1] === "rm") {
      present = false;
      return ok(`${imageId}\n`);
    }
    if (command === "docker" && arguments_[0] === "ps") return ok();
    if (command === "docker" && arguments_[0] === "network") return ok();
    throw new Error("unexpected command");
  });
  const phase = { assertActive() {}, signal: new AbortController().signal };
  await fixture.system.initialize(phase);
  fixture.system.imageMayHaveApplied.add(product.name);
  await fixture.system.cleanup(phase);
  await fixture.system.auditAbsence(phase);
  assert.equal(present, false);
});
