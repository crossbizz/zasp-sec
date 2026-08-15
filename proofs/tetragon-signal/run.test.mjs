import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  FAILURE_CATEGORIES,
  SUCCESS_LINE,
  DockerKindLifecycle,
  DockerKindRuntime,
  DockerKindSystem,
  Failure,
  buildHelmInstallArguments,
  buildEventCaptureArguments,
  buildTetragonHealthArguments,
  buildKprobeEventCaptureArguments,
  buildKindCreateArguments,
  buildNodeImagePullArguments,
  buildNetworkCreateArguments,
  buildToolEnvironment,
  classifyMutationOutcome,
  fixtureTriggerCommands,
  exactMissingDockerObject,
  exactMissingDockerVolume,
  exactMissingTetragonLog,
  fixtureSettleMilliseconds,
  orchestrate,
  runBounded,
  runMain,
  validateKindNodeInspection,
  validateOperatorPod,
  validateTetragonHealthPod,
  validateTetragonHealthResult,
} from "./run.mjs";

const marker = "0123456789abcdef";
const names = Object.freeze({
  prefix: `zasp-m0-12-${marker}`,
  cluster: `zasp-m0-12-${marker}`,
  namespace: `zasp-m0-12-${marker}`,
  sinkPod: "sink",
  sinkService: "sink",
  workloadPod: "workload",
  filePolicy: `zasp-m0-12-file-${marker}`,
  networkPolicy: `zasp-m0-12-connect-${marker}`,
});

function proofResult() {
  return {
    process: true,
    file: true,
    network: true,
    identity: true,
    capability: true,
    drops: 0,
    events: [{}, {}, {}],
    workload: { id: "org_aaaaaaaaaaaaaaaa:k8s_workload:fixture" },
    sensor: { version: "1.7.0" },
  };
}

class FakeRuntime {
  constructor(options = {}) {
    this.options = options;
    this.events = [];
    this.candidate = options.candidate ?? false;
  }

  async preflight(phase) {
    phase.assertActive();
    this.events.push("preflight");
    if (this.options.preflightError) throw this.options.preflightError;
  }

  async createCluster(phase) {
    phase.assertActive();
    this.events.push("createCluster");
    this.candidate = true;
    if (this.options.createError) throw this.options.createError;
  }

  async installTetragon(phase) {
    phase.assertActive();
    this.events.push("installTetragon");
    if (this.options.installError) throw this.options.installError;
  }

  async runFixture(phase) {
    phase.assertActive();
    this.events.push("runFixture");
    if (this.options.waitForAbort) {
      await new Promise((resolve) => phase.signal.addEventListener("abort", resolve, { once: true }));
      assert.throws(() => phase.assertActive(), Failure);
      return;
    }
    if (this.options.fixtureError) throw this.options.fixtureError;
  }

  async captureEvidence(phase) {
    phase.assertActive();
    this.events.push("captureEvidence");
    if (this.options.captureError) throw this.options.captureError;
    return proofResult();
  }

  async joinMutations() {
    this.events.push("joinMutations");
    if (this.options.joinError) throw this.options.joinError;
  }

  async cleanup(phase) {
    phase.assertActive();
    this.events.push("cleanup");
    if (this.options.cleanupError) throw this.options.cleanupError;
    this.candidate = false;
  }

  async auditAbsence(phase) {
    phase.assertActive();
    this.events.push("auditAbsence");
    if (this.options.auditError) throw this.options.auditError;
  }

  hasCandidate() {
    return this.candidate;
  }
}

function childProcess({ stdout = "", stderr = "", status = 0, signal = null, delay = 0, closeOnKill = true }) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kills = [];
  child.kill = (killSignal) => {
    child.kills.push(killSignal);
    if (closeOnKill) queueMicrotask(() => child.emit("close", null, killSignal));
    return true;
  };
  setTimeout(() => {
    if (stdout) child.stdout.write(stdout);
    if (stderr) child.stderr.write(stderr);
    child.stdout.end();
    child.stderr.end();
    child.emit("close", status, signal);
  }, delay);
  return child;
}

test("locks fixed output and failure categories", () => {
  assert.equal(SUCCESS_LINE, "Tetragon signal proof passed: process=true file=true network=true identity=true capability=true drops=0 cleanup=true.");
  assert.deepEqual(FAILURE_CATEGORIES, [
    "capability",
    "cleanup",
    "configuration",
    "normalization",
    "operation",
    "ownership",
    "provider",
  ]);
  assert.equal(fixtureSettleMilliseconds, 30_000);
});

test("builds exact network, kind, Helm, and fixture command arguments", () => {
  assert.deepEqual(buildNetworkCreateArguments(names.cluster, marker), [
    "network", "create", "--driver", "bridge",
    "--label", "zasp.dev/proof=m0-12", "--label", `zasp.dev/run=${marker}`,
    names.cluster,
  ]);
  assert.deepEqual(buildKindCreateArguments(names, {
    config: "/owned/kind.json",
    kubeconfig: "/owned/kubeconfig",
    nodeImage: "kindest/node:v1.35.5@sha256:fixture",
  }), [
    "create", "cluster", "--name", names.cluster, "--config", "/owned/kind.json",
    "--kubeconfig", "/owned/kubeconfig", "--image",
    "kindest/node:v1.35.5@sha256:fixture", "--wait", "180s",
  ]);
  assert.deepEqual(buildHelmInstallArguments({
    chart: "/owned/tetragon.tgz",
    kubeconfig: "/owned/kubeconfig",
    values: "/owned/values.json",
  }), [
    "upgrade", "--install", "tetragon", "/owned/tetragon.tgz", "--namespace",
    "kube-system", "--kubeconfig", "/owned/kubeconfig", "--values",
    "/owned/values.json", "--wait", "--timeout", "180s",
  ]);
  assert.deepEqual(fixtureTriggerCommands(names, "10.96.0.23"), [
    ["exec", "--namespace", names.namespace, names.workloadPod, "--", "/bin/echo", "zasp-m0-12-exec"],
    ["exec", "--namespace", names.namespace, names.workloadPod, "--", "/bin/sh", "-c", "printf zasp-m0-12 > /tmp/zasp-m0-12-proof.txt && cat /tmp/zasp-m0-12-proof.txt >/dev/null"],
    ["exec", "--namespace", names.namespace, names.workloadPod, "--", "/bin/nc", "-w", "2", "10.96.0.23", "18080"],
  ]);
  assert.deepEqual(buildEventCaptureArguments("tetragon-fixture"), [
    "exec", "--namespace", "kube-system", "tetragon-fixture", "--container",
    "tetragon", "--", "/bin/cat", "/var/run/cilium/tetragon/tetragon.log",
  ]);
  assert.deepEqual(buildNodeImagePullArguments("a".repeat(64), "linux/arm64", "registry.invalid/image@sha256:fixture"), [
    "exec", "a".repeat(64), "ctr", "--namespace", "k8s.io", "images", "pull",
    "--platform", "linux/arm64", "registry.invalid/image@sha256:fixture",
  ]);
  assert.deepEqual(buildKprobeEventCaptureArguments("tetragon-fixture", names), [
    "exec", "--namespace", "kube-system", "tetragon-fixture", "--container", "tetragon",
    "--", "/bin/sh", "-c",
    "set -eu\n/usr/bin/tetra getevents --server-address unix:///var/run/tetragon/tetragon.sock --event-types PROCESS_KPROBE --policy-names \"$1\" --policy-names \"$2\" --output json &\ncapture_pid=$!\n/bin/sleep 40\nstatus=0\n/bin/kill -INT \"$capture_pid\" 2>/dev/null || true\nwait \"$capture_pid\" || status=$?\ncase \"$status\" in 0|130) exit 0 ;; *) exit 1 ;; esac\n",
    "zasp-m0-12-capture", names.filePolicy, names.networkPolicy,
  ]);
});

test("validates exact pinned Tetragon/operator images and explicit gRPC health evidence", () => {
  const tetragonDigest = "sha256:" + "c".repeat(64);
  const operatorDigest = "sha256:" + "d".repeat(64);
  const tetragonImage = `quay.io/cilium/tetragon:v1.7.0@${tetragonDigest}`;
  const operatorImage = `quay.io/cilium/tetragon-operator:v1.7.0@${operatorDigest}`;
  const pod = {
    metadata: { name: "tetragon-fixture", namespace: "kube-system", labels: {
      "zasp.dev/proof": "m0-12", "zasp.dev/run": marker,
    } },
    spec: {
      nodeName: names.cluster + "-control-plane",
      containers: [{
        name: "tetragon",
        livenessProbe: {
          failureThreshold: 3,
          grpc: { port: 6789, service: "liveness" },
          periodSeconds: 10,
          successThreshold: 1,
          timeoutSeconds: 60,
        },
      }],
    },
    status: {
      phase: "Running",
      containerStatuses: [{
        name: "tetragon", ready: true, restartCount: 0,
        imageID: tetragonImage,
      }],
    },
  };
  pod.spec.containers[0].image = tetragonImage;
  assert.equal(validateTetragonHealthPod(
    pod, names.cluster + "-control-plane", tetragonImage, tetragonDigest, marker,
  ), "tetragon-fixture");
  const wrong = structuredClone(pod);
  wrong.spec.containers[0].livenessProbe.grpc.port = 2112;
  assert.throws(() => validateTetragonHealthPod(
    wrong, names.cluster + "-control-plane", tetragonImage, tetragonDigest, marker,
  ), Failure);
  assert.throws(() => validateTetragonHealthPod(
    pod, names.cluster + "-control-plane", tetragonImage, `sha256:${"e".repeat(64)}`, marker,
  ), Failure);

  const operator = {
    metadata: { name: "tetragon-operator-fixture", namespace: "kube-system", labels: {
      "zasp.dev/proof": "m0-12", "zasp.dev/run": marker,
    } },
    spec: { nodeName: names.cluster + "-control-plane", containers: [{
      name: "tetragon-operator", image: operatorImage,
    }] },
    status: { phase: "Running", containerStatuses: [{
      name: "tetragon-operator", ready: true, restartCount: 0,
      imageID: operatorImage,
    }] },
  };
  assert.equal(validateOperatorPod(
    operator, names.cluster + "-control-plane", operatorImage, operatorDigest, marker,
  ), "tetragon-operator-fixture");
  assert.throws(() => validateOperatorPod(
    operator, names.cluster + "-control-plane", operatorImage, `sha256:${"e".repeat(64)}`, marker,
  ), Failure);
  assert.deepEqual(buildTetragonHealthArguments("tetragon-fixture"), [
    "exec", "--namespace", "kube-system", "tetragon-fixture", "--container", "tetragon",
    "--", "/usr/bin/tetra", "--server-address", "unix:///var/run/tetragon/tetragon.sock", "--timeout", "5s",
    "--retries", "1", "status",
  ]);
  assert.equal(validateTetragonHealthResult({
    status: 0, signal: null, stdout: "Health Status: running\n", stderr: "",
  }), true);
  assert.equal(validateTetragonHealthResult({
    status: 0, signal: null, stdout: "", stderr: "",
  }), false);
});

test("binds the complete supported kind node fingerprint and rejects replacement metadata", () => {
  const token = "a".repeat(64);
  const imageId = `sha256:${"b".repeat(64)}`;
  const volumeToken = "c".repeat(64);
  const networkId = "d".repeat(64);
  const name = `${names.cluster}-control-plane`;
  const document = [{
    Id: token,
    Name: `/${name}`,
    Image: imageId,
    Config: {
      Image: "kindest/node:v1.35.5@sha256:fixture",
      Labels: {
        "io.x-k8s.kind.cluster": names.cluster,
        "io.x-k8s.kind.role": "control-plane",
      },
      Env: [
        "KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER",
        "KUBECONFIG=/etc/kubernetes/admin.conf",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "container=docker",
        "HTTP_PROXY=",
        "HTTPS_PROXY=",
        "NO_PROXY=",
      ],
      Entrypoint: ["/usr/local/bin/entrypoint", "/sbin/init"],
      Cmd: null,
      User: "",
      Hostname: name,
    },
    HostConfig: {
      Binds: ["/lib/modules:/lib/modules:ro", "/dev/mapper:/dev/mapper", "/proc:/procHost:ro"],
      Tmpfs: { "/run": "", "/tmp": "" },
      Privileged: true,
      CapAdd: null,
      CapDrop: null,
      Devices: [],
      DeviceRequests: null,
      PidMode: "",
      IpcMode: "private",
      UsernsMode: "",
      CgroupnsMode: "private",
      ReadonlyRootfs: false,
      SecurityOpt: ["seccomp=unconfined", "apparmor=unconfined", "label=disable"],
    },
    Mounts: [
      { Type: "bind", Source: "/lib/modules", Destination: "/lib/modules", Mode: "ro", RW: false, Propagation: "rprivate" },
      { Type: "bind", Source: "/dev/mapper", Destination: "/dev/mapper", Mode: "", RW: true, Propagation: "rprivate" },
      { Type: "bind", Source: "/proc", Destination: "/procHost", Mode: "ro", RW: false, Propagation: "rprivate" },
      { Type: "volume", Name: volumeToken, Source: `/var/lib/docker/volumes/${volumeToken}/_data`, Destination: "/var", Driver: "local", Mode: "", RW: true, Propagation: "" },
    ],
    NetworkSettings: { Networks: {
      [names.cluster]: {
        Aliases: null,
        DriverOpts: null,
        Gateway: "172.18.0.1",
        IPAddress: "172.18.0.2",
        IPPrefixLen: 24,
        MacAddress: "02:42:ac:12:00:02",
        NetworkID: networkId,
      },
    } },
  }];
  const expectedNode = {
    cluster: names.cluster,
    imageId,
    name,
    networkId,
    reference: "kindest/node:v1.35.5@sha256:fixture",
    token,
  };
  const retained = validateKindNodeInspection(document, expectedNode);
  assert.equal(retained.token, token);
  assert.equal(retained.volumeToken, volumeToken);
  assert.deepEqual(validateKindNodeInspection(structuredClone(document), expectedNode, retained), retained);

  for (const mutate of [
    (value) => { value[0].Id = "e".repeat(64); },
    (value) => { value[0].Image = `sha256:${"e".repeat(64)}`; },
    (value) => { value[0].Config.Labels.foreign = "true"; },
    (value) => { value[0].HostConfig.Privileged = false; },
    (value) => { value[0].Mounts.push({ Type: "bind", Source: "/foreign", Destination: "/foreign" }); },
    (value) => { value[0].NetworkSettings.Networks.foreign = {}; },
    (value) => { value[0].Mounts[3].Name = "e".repeat(64); },
  ]) {
    const changed = structuredClone(document);
    mutate(changed);
    assert.throws(() => validateKindNodeInspection(changed, expectedNode, retained), Failure);
  }
});

test("builds an allowlisted tool environment without ambient credential or proxy state", () => {
  const environment = buildToolEnvironment({
    path: "/fixed/bin",
    home: "/owned/home",
    dockerConfig: "/owned/docker",
    kubeconfig: "/owned/kubeconfig",
    network: names.cluster,
  });

  assert.deepEqual(environment, {
    DOCKER_CONFIG: "/owned/docker",
    HOME: "/owned/home",
    KIND_EXPERIMENTAL_DOCKER_NETWORK: names.cluster,
    KUBECONFIG: "/owned/kubeconfig",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: "/fixed/bin",
  });
  for (const key of Object.keys(environment)) {
    assert.doesNotMatch(key, /AWS|GOOGLE|AZURE|TOKEN|PASSWORD|PROXY|KUBECONFIG_PATH/i);
  }
});

test("classifies only thrown, signaled, or malformed-zero mutations as ambiguous", () => {
  const valid = (value) => /^[0-9a-f]{64}\n$/.test(value.stdout);
  assert.equal(classifyMutationOutcome({ status: 0, signal: null, stdout: `${"a".repeat(64)}\n`, stderr: "" }, valid), "success");
  assert.equal(classifyMutationOutcome({ status: 1, signal: null, stdout: "", stderr: "rejected" }, valid), "definitive");
  assert.equal(classifyMutationOutcome({ status: 0, signal: "SIGKILL", stdout: "", stderr: "" }, valid), "ambiguous");
  assert.equal(classifyMutationOutcome({ status: 0, signal: null, stdout: "invalid\n", stderr: "" }, valid), "ambiguous");
  assert.equal(classifyMutationOutcome(undefined, valid), "ambiguous");
});

test("accepts only exact Docker 29 missing container and network envelopes", () => {
  const token = "a".repeat(64);
  assert.equal(exactMissingDockerObject({
    status: 1, signal: null, stdout: "[]\n", stderr: `error: no such object: ${token}\n`,
  }, token), true);
  assert.equal(exactMissingDockerObject({
    status: 1, signal: null, stdout: "[]\n",
    stderr: `Error response from daemon: network ${token} not found\n`,
  }, token), true);
  assert.equal(exactMissingDockerObject({
    status: 1, signal: null, stdout: "", stderr: "foreign\n",
  }, token), false);
});

test("accepts only the exact Docker 29 missing volume envelope", () => {
  const token = "a".repeat(64);
  const exact = {
    status: 1, signal: null, stdout: "[]\n",
    stderr: `Error response from daemon: get ${token}: no such volume\n`,
  };
  assert.equal(exactMissingDockerVolume(exact, token), true);
  for (const changed of [
    { ...exact, status: 0 },
    { ...exact, signal: "SIGKILL" },
    { ...exact, stdout: "" },
    { ...exact, stderr: `Error response from daemon: get ${token}: permission denied\n` },
  ]) assert.equal(exactMissingDockerVolume(changed, token), false);
});

test("accepts only the exact pinned-image missing event-log envelope", () => {
  const exact = {
    status: 1,
    signal: null,
    stdout: "",
    stderr: "cat: can't open '/var/run/cilium/tetragon/tetragon.log': No such file or directory\ncommand terminated with exit code 1\n",
  };
  assert.equal(exactMissingTetragonLog(exact), true);
  for (const changed of [
    { ...exact, status: 0 },
    { ...exact, signal: "SIGKILL" },
    { ...exact, stdout: "unexpected" },
    { ...exact, stderr: exact.stderr.replace("No such file or directory", "Permission denied") },
  ]) assert.equal(exactMissingTetragonLog(changed), false);
});

test("runBounded captures a successful child within one combined byte cap", async () => {
  let invocation;
  const result = await runBounded("tool", ["arg"], {
    env: { PATH: "/fixed" },
    timeoutMs: 1000,
    maximumBytes: 8,
  }, (command, arguments_, options) => {
    invocation = { command, arguments_, options };
    return childProcess({ stdout: "abcd", stderr: "efgh" });
  });

  assert.deepEqual(invocation, {
    command: "tool",
    arguments_: ["arg"],
    options: { env: { PATH: "/fixed" }, stdio: ["ignore", "pipe", "pipe"] },
  });
  assert.deepEqual(result, { status: 0, signal: null, stdout: "abcd", stderr: "efgh" });
});

test("runBounded SIGKILLs combined overflow and deadline without leaking listeners", async () => {
  let overflowChild;
  await assert.rejects(
    runBounded("tool", [], { env: {}, timeoutMs: 1000, maximumBytes: 7 }, () => {
      overflowChild = childProcess({ stdout: "abcd", stderr: "efgh", delay: 1 });
      return overflowChild;
    }),
    Failure,
  );
  assert.deepEqual(overflowChild.kills, ["SIGKILL"]);
  assert.equal(overflowChild.stdout.listenerCount("data"), 0);
  assert.equal(overflowChild.stderr.listenerCount("data"), 0);

  let timedChild;
  await assert.rejects(
    runBounded("tool", [], { env: {}, timeoutMs: 5, maximumBytes: 8 }, () => {
      timedChild = childProcess({ delay: 1000 });
      return timedChild;
    }),
    Failure,
  );
  assert.deepEqual(timedChild.kills, ["SIGKILL"]);
});

test("runBounded contains stdout and stderr pipe errors", async () => {
  let child;
  const promise = runBounded("tool", [], { env: {}, timeoutMs: 1000, maximumBytes: 8 }, () => {
    child = childProcess({ delay: 1000 });
    return child;
  });
  child.stdout.emit("error", new Error("sensitive pipe detail"));
  await assert.rejects(promise, Failure);
  assert.deepEqual(child.kills, ["SIGKILL"]);
});

test("runBounded SIGKILLs and reaps a child when its phase signal aborts", async () => {
  const controller = new AbortController();
  const child = childProcess({ delay: 1000 });
  const execution = runBounded("tool", [], {
    env: { PATH: "/fixed/bin" },
    maximumBytes: 4096,
    timeoutMs: 5000,
    signal: controller.signal,
  }, () => child);
  controller.abort();
  await assert.rejects(execution, Failure);
  assert.deepEqual(child.kills, ["SIGKILL"]);
  assert.equal(child.listenerCount("close"), 0);
});

test("orchestrates the exact main and independent cleanup sequence", async () => {
  const runtime = new FakeRuntime();
  const result = await orchestrate(runtime, { mainTimeoutMs: 1000, cleanupTimeoutMs: 1000 });

  assert.deepEqual(runtime.events, [
    "preflight", "createCluster", "installTetragon", "runFixture",
    "captureEvidence", "joinMutations", "cleanup", "auditAbsence",
  ]);
  assert.equal(result.cleanup, true);
  assert.equal(result.drops, 0);
});

test("cleanup continues and wins precedence after a main failure", async () => {
  const runtime = new FakeRuntime({
    captureError: new Failure("normalization"),
    cleanupError: new Failure("cleanup"),
  });

  await assert.rejects(
    orchestrate(runtime, { mainTimeoutMs: 1000, cleanupTimeoutMs: 1000 }),
    (error) => error instanceof Failure && error.category === "cleanup",
  );
  assert.deepEqual(runtime.events.slice(-3), ["joinMutations", "cleanup", "auditAbsence"]);
});

test("main deadline revokes authority before independent cleanup", async () => {
  const runtime = new FakeRuntime({ waitForAbort: true });

  await assert.rejects(
    orchestrate(runtime, { mainTimeoutMs: 5, cleanupTimeoutMs: 1000 }),
    (error) => error instanceof Failure && error.category === "operation",
  );
  assert.deepEqual(runtime.events, [
    "preflight", "createCluster", "installTetragon", "runFixture",
    "joinMutations", "cleanup", "auditAbsence",
  ]);
});

test("main deadline joins the revoked operation before cleanup begins", async () => {
  const events = [];
  const runtime = new FakeRuntime();
  runtime.runFixture = async (phase) => {
    events.push("main-start");
    await new Promise((resolve) => phase.signal.addEventListener("abort", () => {
      setTimeout(() => { events.push("main-settled"); resolve(); }, 10);
    }, { once: true }));
  };
  runtime.joinMutations = async () => { events.push("cleanup-start"); };

  await assert.rejects(
    orchestrate(runtime, { mainTimeoutMs: 5, cleanupTimeoutMs: 1000 }),
    (error) => error instanceof Failure && error.category === "operation",
  );
  assert.deepEqual(events, ["main-start", "main-settled", "cleanup-start"]);
});

test("phase deadlines bound an uncooperative main and cleanup settlement", async () => {
  const mainRuntime = new FakeRuntime();
  mainRuntime.runFixture = async () => new Promise(() => {});
  const mainStarted = Date.now();
  await assert.rejects(
    orchestrate(mainRuntime, {
      mainTimeoutMs: 5,
      cleanupTimeoutMs: 100,
      settlementTimeoutMs: 5,
    }),
    (error) => error instanceof Failure && error.category === "operation",
  );
  assert.ok(Date.now() - mainStarted < 100);
  assert.deepEqual(mainRuntime.events.slice(-3), ["joinMutations", "cleanup", "auditAbsence"]);

  const cleanupRuntime = new FakeRuntime();
  cleanupRuntime.cleanup = async () => new Promise(() => {});
  const cleanupStarted = Date.now();
  await assert.rejects(
    orchestrate(cleanupRuntime, {
      mainTimeoutMs: 100,
      cleanupTimeoutMs: 5,
      settlementTimeoutMs: 5,
    }),
    (error) => error instanceof Failure && error.category === "cleanup",
  );
  assert.ok(Date.now() - cleanupStarted < 100);
});

test("mutation journal join failure still runs cleanup and absence audit", async () => {
  const runtime = new FakeRuntime({ joinError: new Failure("operation") });

  await assert.rejects(
    orchestrate(runtime, { mainTimeoutMs: 1000, cleanupTimeoutMs: 1000 }),
    (error) => error instanceof Failure && error.category === "operation",
  );
  assert.deepEqual(runtime.events.slice(-3), ["joinMutations", "cleanup", "auditAbsence"]);
});

test("runMain emits exactly one success line", async () => {
  let stdout = "";
  let stderr = "";
  let exitCode;
  const code = await runMain(new FakeRuntime(), {
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: (value) => { exitCode = value; },
  });

  assert.equal(code, 0);
  assert.equal(exitCode, 0);
  assert.equal(stdout, `${SUCCESS_LINE}\n`);
  assert.equal(stderr, "");
});

test("runMain contains construction, panic, and provider details in fixed categories", async () => {
  for (const [name, runtimeFactory, category] of [
    ["construction", () => { throw new Error("secret construction detail"); }, "operation"],
    ["panic", () => new FakeRuntime({ createError: new Error("secret panic detail") }), "operation"],
    ["provider", () => new FakeRuntime({ installError: new Failure("provider", "provider payload") }), "provider"],
  ]) {
    let stdout = "";
    let stderr = "";
    const code = await runMain(undefined, {
      runtimeFactory,
      stdout: { write: (value) => { stdout += value; } },
      stderr: { write: (value) => { stderr += value; } },
      setExitCode: () => {},
    });
    assert.equal(code, 1, name);
    assert.equal(stdout, "", name);
    assert.equal(stderr, `Tetragon signal proof failed: ${category} rejected.\n`, name);
    assert.doesNotMatch(stderr, /secret|payload/, name);
  }
});

test("DockerKindRuntime refuses ambient input and requires injected exact tooling", () => {
  assert.throws(() => new DockerKindRuntime({}), TypeError);
  assert.throws(() => new DockerKindRuntime({
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
    ambient: { HTTP_PROXY: "http://foreign" },
  }), TypeError);
});

test("DockerKindRuntime drives an injected lifecycle with retained candidate state", async () => {
  const events = [];
  let candidate = false;
  const lifecycle = {
    async preflight() { events.push("preflight"); },
    async createCluster() { events.push("createCluster"); candidate = true; },
    async installTetragon() { events.push("installTetragon"); },
    async runFixture() { events.push("runFixture"); },
    async captureEvidence() { events.push("captureEvidence"); return proofResult(); },
    async joinMutations() { events.push("joinMutations"); },
    async cleanup() { events.push("cleanup"); candidate = false; },
    async auditAbsence() { events.push("auditAbsence"); },
    hasCandidate() { return candidate; },
  };
  const runtime = new DockerKindRuntime({
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
  }, { lifecycle });
  const phase = { signal: new AbortController().signal, assertActive() {} };

  await runtime.preflight(phase);
  await runtime.createCluster(phase);
  assert.equal(runtime.hasCandidate(), true);
  await runtime.installTetragon(phase);
  await runtime.runFixture(phase);
  assert.deepEqual(await runtime.captureEvidence(phase), proofResult());
  await runtime.joinMutations(phase);
  await runtime.cleanup(phase);
  assert.equal(runtime.hasCandidate(), false);
  await runtime.auditAbsence(phase);
  assert.deepEqual(events, [
    "preflight", "createCluster", "installTetragon", "runFixture",
    "captureEvidence", "joinMutations", "cleanup", "auditAbsence",
  ]);
});

test("DockerKindLifecycle drives the concrete system in dependency order", async () => {
  const events = [];
  let candidate = false;
  const system = {
    async initialize() { events.push("initialize"); },
    async preflight() { events.push("preflight"); },
    async resolveAssets() { events.push("resolveAssets"); },
    async createNetwork() { events.push("createNetwork"); candidate = true; },
    async createCluster() { events.push("createCluster"); },
    async installTetragon() { events.push("installTetragon"); },
    async runFixture() { events.push("runFixture"); },
    async captureEvidence() { events.push("captureEvidence"); return proofResult(); },
    async joinMutations() { events.push("joinMutations"); },
    async cleanup() { events.push("cleanup"); candidate = false; },
    async auditAbsence() { events.push("auditAbsence"); },
    hasCandidate() { return candidate; },
  };
  const lifecycle = new DockerKindLifecycle({
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
  }, { system });
  const phase = { signal: new AbortController().signal, assertActive() {} };

  await lifecycle.preflight(phase);
  await lifecycle.createCluster(phase);
  assert.equal(lifecycle.hasCandidate(), true);
  await lifecycle.installTetragon(phase);
  await lifecycle.runFixture(phase);
  assert.deepEqual(await lifecycle.captureEvidence(phase), proofResult());
  await lifecycle.joinMutations(phase);
  await lifecycle.cleanup(phase);
  assert.equal(lifecycle.hasCandidate(), false);
  await lifecycle.auditAbsence(phase);
  assert.deepEqual(events, [
    "initialize", "preflight", "resolveAssets", "createNetwork", "createCluster",
    "installTetragon", "runFixture", "captureEvidence", "joinMutations",
    "cleanup", "auditAbsence",
  ]);
});

test("DockerKindSystem retains and cleans an mkdtemp candidate after invalid initial proof", async () => {
  const parent = "/safe/tmp";
  const candidate = `${parent}/zasp-m0-12-${marker}-runtime-owned`;
  const removed = [];
  let candidateStats = 0;
  let candidateRemoved = false;
  const status = (symbolic = false) => ({
    dev: 7,
    ino: 9,
    isDirectory: () => true,
    isFile: () => false,
    isSymbolicLink: () => symbolic,
  });
  const system = new DockerKindSystem({
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
  }, {
    tempParent: parent,
    canonicalPath: async (value) => value,
    statPath: async (value) => {
      if (value !== candidate || candidateRemoved) throw Object.assign(new Error("missing"), { code: "ENOENT" });
      candidateStats += 1;
      return status(candidateStats === 1);
    },
    readDirectory: async (value) => value === parent ? [] : [],
    makeTemp: async () => candidate,
    makeDirectory: async () => {},
    writePath: async () => {},
    readPath: async () => Buffer.from("fixture"),
    changeMode: async () => {},
    removePath: async (value) => { removed.push(value); candidateRemoved = true; },
    command: async () => ({ status: 0, signal: null, stdout: "ok\n", stderr: "" }),
    fetchBytes: async () => Buffer.from("fixture"),
    normalize: () => proofResult(),
    wait: async () => {},
  });
  const phase = { signal: new AbortController().signal, assertActive() {} };

  await assert.rejects(system.initialize(phase), (error) => error instanceof Failure && error.category === "configuration");
  await system.cleanupTemporary(phase);
  assert.deepEqual(removed, [candidate]);
  assert.equal(system.hasCandidate(), false);
});

test("DockerKindSystem cleans only retained full IDs and preserves the network on unproved cluster absence", async () => {
  const input = {
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
  };
  const nodeToken = "a".repeat(64);
  const volumeToken = "b".repeat(64);
  const networkToken = "c".repeat(64);
  const phase = { signal: new AbortController().signal, assertActive() {} };
  const calls = [];
  const system = new DockerKindSystem(input);
  system.paths = Object.freeze({ kubeconfig: "/owned/kubeconfig" });
  system.clusterMayHaveApplied = true;
  system.networkMayHaveApplied = true;
  system.resourcesApplied = true;
  system.chartInstalled = true;
  system.nodeToken = nodeToken;
  system.nodeIdentity = Object.freeze({ token: nodeToken, volumeToken });
  system.networkToken = networkToken;
  system.nodeCandidates = async () => [{ token: nodeToken, name: `${names.cluster}-control-plane` }];
  system.networkCandidates = async () => [{ token: networkToken, name: names.cluster }];
  system.verifyCluster = async () => { calls.push("verify-cluster"); };
  system.requireClusterAbsent = async () => { calls.push("absent-cluster-volume"); };
  system.verifyNetwork = async (_category, _phase, empty) => { calls.push(`verify-network-${empty}`); };
  system.requireNetworkAbsent = async () => { calls.push("absent-network"); };
  system.mutation = async (command, arguments_) => {
    calls.push([command, ...arguments_].join(" "));
    const token = command === "docker" && arguments_[0] === "rm" ? nodeToken : networkToken;
    return { status: 0, signal: null, stdout: `${token}\n`, stderr: "" };
  };

  await system.cleanup(phase);
  assert.deepEqual(calls, [
    "verify-cluster",
    `docker rm --force --volumes ${nodeToken}`,
    "absent-cluster-volume",
    "verify-network-true",
    `docker network rm ${networkToken}`,
    "absent-network",
  ]);
  assert.equal(system.resourcesApplied, false);
  assert.equal(system.chartInstalled, false);

  const rejected = new DockerKindSystem(input);
  rejected.paths = Object.freeze({ kubeconfig: "/owned/kubeconfig" });
  rejected.clusterMayHaveApplied = true;
  rejected.networkMayHaveApplied = true;
  rejected.nodeToken = nodeToken;
  rejected.nodeIdentity = Object.freeze({ token: nodeToken, volumeToken });
  rejected.networkToken = networkToken;
  let mutations = 0;
  rejected.verifyCluster = async () => { throw new Failure("cleanup"); };
  rejected.verifyNetwork = async () => { throw new Error("network must be retained"); };
  rejected.mutation = async () => { mutations += 1; };
  await assert.rejects(rejected.cleanup(phase), (error) => error instanceof Failure && error.category === "cleanup");
  assert.equal(mutations, 0);
  assert.equal(rejected.networkMayHaveApplied, true);

  const noOp = new DockerKindSystem(input);
  noOp.paths = Object.freeze({ kubeconfig: "/owned/kubeconfig" });
  noOp.clusterMayHaveApplied = true;
  noOp.networkMayHaveApplied = true;
  noOp.networkToken = networkToken;
  const noOpCalls = [];
  noOp.nodeCandidates = async () => [];
  noOp.networkCandidates = async () => [{ token: networkToken, name: names.cluster }];
  noOp.requireClusterAbsent = async () => { noOpCalls.push("absent-cluster"); };
  noOp.verifyNetwork = async (_category, _phase, empty) => {
    noOpCalls.push(`verify-network-${empty}`);
  };
  noOp.requireNetworkAbsent = async () => { noOpCalls.push("absent-network"); };
  noOp.mutation = async (_command, arguments_) => {
    noOpCalls.push(arguments_.join(" "));
    return { status: 0, signal: null, stdout: `${networkToken}\n`, stderr: "" };
  };
  await noOp.cleanup(phase);
  assert.deepEqual(noOpCalls, [
    "absent-cluster", "verify-network-true", `network rm ${networkToken}`, "absent-network",
  ]);
  assert.equal(noOp.hasCandidate(), false);
});

test("concrete DockerKindSystem completes an injected full lifecycle through exact ID cleanup", async () => {
  const input = {
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
  };
  const parent = await mkdtemp(join(tmpdir(), "zasp-m012-system-test-"));
  const networkToken = "a".repeat(64);
  const nodeToken = "b".repeat(64);
  const volumeToken = "c".repeat(64);
  const networkAddress = "172.19.0.1";
  const nodeAddress = "172.19.0.2";
  const nodeImageId = `sha256:${"d".repeat(64)}`;
  const workloadUid = "11111111-2222-4333-8444-555555555555";
  const containerId = `containerd://${"e".repeat(64)}`;
  const commands = [];
  let networkExists = false;
  let nodeExists = false;
  let volumeExists = false;
  let logReads = 0;
  let system;
  const ok = (stdout = "ok\n") => ({ status: 0, signal: null, stdout, stderr: "" });
  const metrics = () => Buffer.from([
    'tetragon_build_info{commit="",go_version="go1.26.2",modified="",time="",version="v1.7.0"} 1',
    'tetragon_tracingpolicy_loaded{state="enabled"} 2',
    'tetragon_tracingpolicy_loaded{state="disabled"} 0',
    'tetragon_tracingpolicy_loaded{state="error"} 0',
    'tetragon_tracingpolicy_loaded{state="load_error"} 0',
    "tetragon_observer_ringbuf_events_lost_total 0",
    "tetragon_observer_ringbuf_errors_total 0",
    "tetragon_observer_ringbuf_queue_events_lost_total 0",
    "tetragon_notify_overflowed_events_total 0",
    "tetragon_export_ratelimit_events_dropped_total 0",
    "",
  ].join("\n"));
  const nodeDocument = () => [{
    Id: nodeToken,
    Name: `/${names.cluster}-control-plane`,
    Image: nodeImageId,
    Config: {
      Image: system.fixture.pins.node.reference,
      Labels: { "io.x-k8s.kind.cluster": names.cluster, "io.x-k8s.kind.role": "control-plane" },
      Env: [
        "KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER",
        "KUBECONFIG=/etc/kubernetes/admin.conf",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "container=docker", "HTTP_PROXY=", "HTTPS_PROXY=", "NO_PROXY=",
      ],
      Entrypoint: ["/usr/local/bin/entrypoint", "/sbin/init"],
      Cmd: null, User: "", Hostname: `${names.cluster}-control-plane`,
    },
    HostConfig: {
      Binds: ["/lib/modules:/lib/modules:ro", "/dev/mapper:/dev/mapper", "/proc:/procHost:ro"],
      Tmpfs: { "/run": "", "/tmp": "" }, Privileged: true, CapAdd: null, CapDrop: null,
      Devices: [], DeviceRequests: null, PidMode: "", IpcMode: "private", UsernsMode: "",
      CgroupnsMode: "private", ReadonlyRootfs: false,
      SecurityOpt: ["seccomp=unconfined", "apparmor=unconfined", "label=disable"],
    },
    Mounts: [
      { Type: "bind", Source: "/lib/modules", Destination: "/lib/modules", Mode: "ro", RW: false, Propagation: "rprivate" },
      { Type: "bind", Source: "/dev/mapper", Destination: "/dev/mapper", Mode: "", RW: true, Propagation: "rprivate" },
      { Type: "bind", Source: "/proc", Destination: "/procHost", Mode: "ro", RW: false, Propagation: "rprivate" },
      { Type: "volume", Name: volumeToken, Source: `/var/lib/docker/volumes/${volumeToken}/_data`, Destination: "/var", Driver: "local", Mode: "", RW: true, Propagation: "" },
    ],
    NetworkSettings: { Networks: { [names.cluster]: {
      NetworkID: networkToken, Aliases: null, DriverOpts: null, Gateway: networkAddress,
      IPAddress: nodeAddress, IPPrefixLen: 24, MacAddress: "02:42:ac:13:00:02",
    } } },
  }];
  const podLabels = { "zasp.dev/proof": "m0-12", "zasp.dev/run": marker };

  try {
    system = new DockerKindSystem(input, {
      normalize: () => proofResult(),
      tempParent: parent,
      wait: async () => {},
    });
    system.resolveAssets = async () => {
      await writeFile(system.paths.kind, "kind");
      await writeFile(system.paths.chart, "chart");
      for (const [kind, id] of [["node", nodeImageId], ["tetragon", `sha256:${"f".repeat(64)}`],
        ["operator", `sha256:${"1".repeat(64)}`], ["busybox", `sha256:${"2".repeat(64)}`]]) {
        const pin = system.fixture.pins[kind];
        system.imageMetadata.set(kind, Object.freeze({
          id, platformDigest: pin.platformDigests[input.nodePlatform], reference: pin.reference,
        }));
      }
    };
    system.execute = async (command, arguments_) => {
      commands.push([command, ...arguments_]);
      const joined = arguments_.join(" ");
      if (command === "docker" && joined.startsWith("network create ")) {
        networkExists = true;
        return ok(`${networkToken}\n`);
      }
      if (command === system.paths?.kind && arguments_[0] === "create") {
        nodeExists = true;
        volumeExists = true;
        await writeFile(system.paths.kubeconfig, "fixture-kubeconfig\n");
        return ok();
      }
      if (command === "docker" && arguments_[0] === "ps") {
        return ok(nodeExists ? `${nodeToken}|${names.cluster}-control-plane\n` : "");
      }
      if (command === "docker" && joined.startsWith("network ls ")) {
        return ok(networkExists ? `${networkToken}|${names.cluster}\n` : "");
      }
      if (command === "docker" && joined.startsWith("network inspect --format")) {
        return ok(`${JSON.stringify([
          networkToken, names.cluster, "bridge", false, podLabels,
          nodeExists ? { [nodeToken]: { Name: `${names.cluster}-control-plane` } } : {}, {},
        ])}\n`);
      }
      if (command === "docker" && arguments_[0] === "inspect") {
        return nodeExists ? ok(`${JSON.stringify(nodeDocument())}\n`) : {
          status: 1, signal: null, stdout: "[]\n", stderr: `error: no such object: ${nodeToken}\n`,
        };
      }
      if (command === "docker" && joined === `volume inspect ${volumeToken}`) {
        return volumeExists ? ok("[]\n") : {
          status: 1, signal: null, stdout: "[]\n",
          stderr: `Error response from daemon: get ${volumeToken}: no such volume\n`,
        };
      }
      if (command === "docker" && joined === `network inspect ${networkToken}`) {
        return networkExists ? ok("[]\n") : {
          status: 1, signal: null, stdout: "[]\n",
          stderr: `Error response from daemon: network ${networkToken} not found\n`,
        };
      }
      if (command === "docker" && joined === `rm --force --volumes ${nodeToken}`) {
        nodeExists = false;
        volumeExists = false;
        return ok(`${nodeToken}\n`);
      }
      if (command === "docker" && joined === `network rm ${networkToken}`) {
        networkExists = false;
        return ok(`${networkToken}\n`);
      }
      if (command === "docker" && arguments_[0] === "exec" && arguments_.includes("list")) {
        return ok(`${Object.values(system.fixture.runtimeImages).join("\n")}\n`);
      }
      if (command === "docker" || command === "helm" || command === system.paths?.kind) return ok();
      if (command !== "kubectl") return ok("v1\n");
      if (joined.includes("get pod workload")) return ok(`${JSON.stringify({
        metadata: { name: "workload", namespace: names.namespace, uid: workloadUid },
        spec: { nodeName: `${names.cluster}-control-plane`, containers: [{ name: "workload" }] },
        status: { containerStatuses: [{
          name: "workload", ready: true, restartCount: 0, containerID: containerId,
          imageID: system.fixture.runtimeImages.busybox,
        }] },
      })}\n`);
      if (joined.includes("get service sink")) return ok(`${JSON.stringify({ spec: { clusterIP: "10.96.0.23" } })}\n`);
      if (joined.includes("app.kubernetes.io/name=tetragon-operator")) return ok(`${JSON.stringify({ items: [{
        metadata: { name: "tetragon-operator-fixture", namespace: "kube-system", labels: podLabels },
        spec: { nodeName: `${names.cluster}-control-plane`, containers: [{
          name: "tetragon-operator", image: system.fixture.runtimeImages.operator,
        }] },
        status: { phase: "Running", containerStatuses: [{
          name: "tetragon-operator", ready: true, restartCount: 0,
          imageID: system.fixture.runtimeImages.operator,
        }] },
      }] })}\n`);
      if (joined.includes("app.kubernetes.io/name=tetragon")) return ok(`${JSON.stringify({ items: [{
        metadata: { name: "tetragon-fixture", namespace: "kube-system", labels: podLabels },
        spec: { nodeName: `${names.cluster}-control-plane`, containers: [{
          name: "tetragon", image: system.fixture.runtimeImages.tetragon,
          livenessProbe: { grpc: { port: 6789, service: "liveness" }, timeoutSeconds: 60 },
        }] },
        status: { phase: "Running", containerStatuses: [{
          name: "tetragon", ready: true, restartCount: 0,
          imageID: system.fixture.runtimeImages.tetragon,
        }] },
      }] })}\n`);
      if (joined.includes("/usr/bin/tetra --server-address unix:///var/run/tetragon/tetragon.sock")) {
        return ok("Health Status: running\n");
      }
      if (joined.includes(" get --raw ")) return ok(metrics().toString("utf8"));
      if (joined.includes("getevents")) {
        return new Promise((resolve) => setTimeout(() => resolve(ok("{}\n")), 5));
      }
      if (arguments_.includes("/bin/cat")) {
        logReads += 1;
        return ok(logReads === 1 ? "" : "{}\n");
      }
      return ok();
    };

    const lifecycle = new DockerKindLifecycle(input, { system });
    const result = await orchestrate(lifecycle, {
      mainTimeoutMs: 5000, cleanupTimeoutMs: 5000, settlementTimeoutMs: 100,
    });
    assert.equal(result.cleanup, true);
    assert.equal(system.hasCandidate(), false);
    assert.equal(networkExists, false);
    assert.equal(nodeExists, false);
    assert.equal(volumeExists, false);
    assert.equal(commands.some(([command, ...arguments_]) =>
      command === "kubectl" && arguments_.includes("delete")), false);
    assert.equal(commands.some(([command, ...arguments_]) =>
      command === "helm" && arguments_.includes("uninstall")), false);
    assert.equal(commands.some(([command, ...arguments_]) =>
      command === "docker" && arguments_.join(" ") === `rm --force --volumes ${nodeToken}`), true);
    assert.equal(commands.some(([command, ...arguments_]) => command === "kubectl" &&
      arguments_[0] === "--kubeconfig" && arguments_.slice(2).join(" ") === [
        "wait", "--namespace", "kube-system",
        "--for=condition=Ready", "--selector=app.kubernetes.io/name=tetragon-operator",
        "pod", "--timeout", "120s",
      ].join(" ")), true);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("Helm and resource uncertainty is armed before mutation and remains contained by the owned cluster", async () => {
  const input = {
    marker,
    organizationId: "org_aaaaaaaaaaaaaaaa",
    path: "/fixed/bin",
    hostPlatform: "darwin/arm64",
    nodePlatform: "linux/arm64",
  };
  const phase = { signal: new AbortController().signal, assertActive() {} };
  const configured = () => {
    const system = new DockerKindSystem(input, { wait: async () => {} });
    system.paths = Object.freeze({
      chart: "/owned/tetragon.tgz", kubeconfig: "/owned/kubeconfig",
      resources: "/owned/resources.json", values: "/owned/values.json",
    });
    system.nodeToken = "a".repeat(64);
    system.nodeIdentity = Object.freeze({ token: system.nodeToken, volumeToken: "b".repeat(64) });
    system.networkToken = "c".repeat(64);
    system.clusterMayHaveApplied = true;
    system.verifyCluster = async () => {};
    system.readCommand = async () => ({
      status: 0, signal: null,
      stdout: [system.fixture.runtimeImages.tetragon, system.fixture.runtimeImages.operator,
        system.fixture.runtimeImages.busybox, ""].join("\n"), stderr: "",
    });
    system.readKubectl = async () => ({ status: 0, signal: null, stdout: "ok\n", stderr: "" });
    return system;
  };

  const helm = configured();
  helm.mutation = async (command) => {
    if (command === "helm") throw new Failure("operation");
    return { status: 0, signal: null, stdout: "ok\n", stderr: "" };
  };
  await assert.rejects(helm.installTetragon(phase), Failure);
  assert.equal(helm.chartInstalled, true);
  assert.equal(helm.resourcesApplied, false);

  const resources = configured();
  resources.mutation = async (command) => {
    if (command === "kubectl") throw new Failure("operation");
    return { status: 0, signal: null, stdout: "ok\n", stderr: "" };
  };
  await assert.rejects(resources.installTetragon(phase), Failure);
  assert.equal(resources.chartInstalled, true);
  assert.equal(resources.resourcesApplied, true);
});
