import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { basename } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

const api = await import("./run.mjs").catch(() => undefined);

const marker = "0123456789abcdef";
const prefix = `zasp-m0-11-${marker}`;
const networkName = `${prefix}-network`;
const localstackName = `${prefix}-localstack`;
const prowlerName = `${prefix}-prowler`;
const networkID = "a".repeat(64);
const localstackID = "b".repeat(64);
const prowlerID = "c".repeat(64);
const localstackImageID = `sha256:${"d".repeat(64)}`;
const prowlerImageID = `sha256:${"e".repeat(64)}`;
const localstackVolume = "f".repeat(64);
const proofDirectory = "/safe/proof";
const tempParent = "/safe/tmp";
const dockerConfig = `${tempParent}/${prefix}-docker-config-owned`;
const outputDirectory = `${tempParent}/${prefix}-output-owned`;
const roleArn = "arn:aws:iam::000000000000:role/shared-fixture-role";
const roleID = "AROAXXXXXXXXXXXXXXXX";

const localstackImageEnvironment = [
  "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "LANG=C.UTF-8",
  "GPG_KEY=A035C8C19219BA821E" + "CEA86B64E628F8D684696D",
  "PYTHON_VERSION=3.11.13",
  "PYTHON_SHA256=8fb5f9fbc7609fa822cb31549884575db7fd9657cbffb89510b5d7975963a83a",
  "USER=localstack",
  "PYTHONUNBUFFERED=1",
  "LOCALSTACK_BUILD_DATE=2025-07-31",
  "LOCALSTACK_BUILD_GIT_HASH=82de91e30",
  "LOCALSTACK_BUILD_VERSION=4.7.0",
];
const localstackProofEnvironment = ["SERVICES=iam,sts", "ENFORCE_IAM=1", "PERSISTENCE=0"];
const localstackImageEntrypoint = ["docker-entrypoint.sh"];
const localstackImageExposedPorts = [
  ...Array.from({ length: 50 }, (_, index) => `${4510 + index}/tcp`),
  "4566/tcp",
  "5678/tcp",
].sort();
const localstackImageVolumes = ["/var/lib/localstack"];

const prowlerImageEnvironment = [
  "PATH=/home/prowler/.local/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "LANG=C.UTF-8",
  "GPG_KEY=7169605F62C75135" + "6D054A26A821E680E5FA6305",
  "PYTHON_VERSION=3.12.13",
  "PYTHON_SHA256=c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684",
  "POWERSHELL_VERSION=7.5.9",
  "POWERSHELL_TELEMETRY_OPTOUT=1",
  "TRIVY_VERSION=0.72.0",
  "ZIZMOR_VERSION=1.24.1",
  "HOME=/home/prowler",
];
const prowlerProofEnvironment = [
  "AWS_ACCESS_KEY_ID=zasp_fixture_access",
  "AWS_SECRET_ACCESS_KEY=zasp_fixture_secret",
  "AWS_SESSION_TOKEN=zasp_fixture_session",
  "AWS_DEFAULT_REGION=us-east-1",
  "AWS_REGION=us-east-1",
  "AWS_EC2_METADATA_DISABLED=true",
  `AWS_ENDPOINT_URL=http://${localstackName}:4566`,
  "AWS_SHARED_CREDENTIALS_FILE=/nonexistent",
  "AWS_CONFIG_FILE=/nonexistent",
];
const bridgeEnvironment = [
  "PATH=/home/prowler/.local/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "LANG=C.UTF-8",
  "GPG_KEY=7169605F62C75135" + "6D054A26A821E680E5FA6305",
  "PYTHON_VERSION=3.12.13",
  "PYTHON_SHA256=c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684",
  "POWERSHELL_VERSION=7.5.9",
  "POWERSHELL_TELEMETRY_OPTOUT=1",
  "TRIVY_VERSION=0.72.0",
  "ZIZMOR_VERSION=1.24.1",
  "HOME=/tmp",
  "PYTHONUNBUFFERED=1",
  `HOSTNAME=${prowlerName}`,
];

function requireExport(name) {
  assert.notEqual(api, undefined, "run.mjs production module is absent");
  assert.equal(typeof api[name], name.endsWith("IMAGE") || name.endsWith("LINE") ? "string" : "function", `${name} production API is absent`);
  return api[name];
}

function result(status = 0, stdout = "", stderr = "", signal = null) {
  return { status, stdout, stderr, signal };
}

function identityStat(dev = 1, ino = 2, { file = false, symlink = false, size = 0 } = {}) {
  return {
    dev,
    ino,
    size,
    isDirectory: () => !file,
    isFile: () => file,
    isSymbolicLink: () => symlink,
  };
}

function imageInspection({ imageID, environment, entrypoint, command = null, exposedPorts = null, volumes = null, user = "", workingDirectory = "" }) {
  return `${JSON.stringify([
    imageID,
    environment,
    entrypoint,
    command,
    Array.isArray(exposedPorts) ? Object.fromEntries(exposedPorts.map((entry) => [entry, {}])) : exposedPorts,
    Array.isArray(volumes) ? Object.fromEntries(volumes.map((entry) => [entry, {}])) : volumes,
    user,
    workingDirectory,
  ])}\n`;
}

function networkInspection({ internal = true, driver = "bridge", scope = "local", attachable = false, ingress = false } = {}) {
  return `${networkID}|${networkName}|m0-11|${marker}|${internal}|${driver}|${scope}|${attachable}|${ingress}\n`;
}

function localstackInspection(overrides = {}) {
  const mounts = overrides.mounts ?? [{
    Type: "volume", Name: localstackVolume,
    Source: `/var/lib/docker/volumes/${localstackVolume}/_data`, Destination: "/var/lib/localstack",
    Driver: "local", Mode: "", RW: true, Propagation: "",
  }];
  return containerInspection({
    token: localstackID,
    name: localstackName,
    hostname: localstackName,
    imageID: localstackImageID,
    image: api?.LOCALSTACK_IMAGE,
    environment: [
      "ENFORCE_IAM=1", "PERSISTENCE=0", "SERVICES=iam,sts",
      ...localstackImageEnvironment,
    ],
    entrypoint: localstackImageEntrypoint,
    command: null,
    mounts,
    binds: null,
    tmpfs: null,
    readonlyRootfs: false,
    capDrop: null,
    securityOpt: null,
    pidsLimit: null,
    memory: 0,
    nanoCpus: 0,
    user: "",
    workingDirectory: "/opt/code/localstack/",
    exposedPorts: localstackImageExposedPorts,
    ...overrides,
  });
}

function prowlerInspection(overrides = {}) {
  return containerInspection({
    token: prowlerID,
    name: prowlerName,
    hostname: prowlerName,
    imageID: prowlerImageID,
    image: api?.PROWLER_IMAGE,
    environment: [...prowlerProofEnvironment, ...prowlerImageEnvironment],
    entrypoint: ["/usr/bin/env"],
    command: [
      "-i", ...bridgeEnvironment,
      "/home/prowler/.venv/bin/python",
      "/proof/fixture_runner.py", "--fixture", "/proof/fixture.json",
      "--output", "/proof/output/prowler.ocsf.json",
    ],
    mounts: [
      { Type: "bind", Source: proofDirectory, Destination: "/proof", Mode: "ro", RW: false, Propagation: "rprivate" },
      { Type: "bind", Source: outputDirectory, Destination: "/proof/output", Mode: "rw", RW: true, Propagation: "rprivate" },
    ],
    binds: [`${proofDirectory}:/proof:ro`, `${outputDirectory}:/proof/output:rw`],
    tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=33554432" },
    readonlyRootfs: true,
    capDrop: ["ALL"],
    securityOpt: ["no-new-privileges:true"],
    pidsLimit: 64,
    memory: 805306368,
    nanoCpus: 1_000_000_000,
    user: "prowler",
    workingDirectory: "/home/prowler",
    exposedPorts: [],
    ...overrides,
  });
}

function containerInspection({
  token, name, hostname, imageID, image, environment, entrypoint, command, mounts, binds, tmpfs,
  readonlyRootfs, capDrop, securityOpt, pidsLimit, memory, nanoCpus, user, workingDirectory,
  exposedPorts, attachedNetworkID = networkID,
}) {
  return `${[
    token,
    `/${name}`,
    hostname,
    imageID,
    image,
    "m0-11",
    marker,
    networkName,
    JSON.stringify({ [networkName]: { NetworkID: attachedNetworkID } }),
    JSON.stringify(environment),
    JSON.stringify({}),
    JSON.stringify(Object.fromEntries(exposedPorts.map((port) => [port, null]))),
    JSON.stringify(entrypoint),
    JSON.stringify(command),
    JSON.stringify(mounts),
    JSON.stringify(binds),
    JSON.stringify(null),
    JSON.stringify(tmpfs),
    JSON.stringify(readonlyRootfs),
    JSON.stringify(capDrop),
    JSON.stringify(securityOpt),
    JSON.stringify(pidsLimit),
    JSON.stringify(memory),
    JSON.stringify(nanoCpus),
    JSON.stringify(user),
    JSON.stringify(workingDirectory),
  ].join("|")}\n`;
}

test("pins exact images and builds an internal proof network", () => {
  assert.equal(requireExport("LOCALSTACK_IMAGE"), "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c");
  assert.equal(requireExport("PROWLER_IMAGE"), "prowlercloud/prowler:5.39.0@sha256:58c8a0eb0c947517bd89b6214cde0cc1d5f59df4eebbb99a87475ab741914959");
  assert.deepEqual(requireExport("buildNetworkCreateArguments")(networkName), [
    "network", "create", "--internal",
    "--label", "zasp.proof=m0-11", "--label", `zasp.marker=${marker}`, networkName,
  ]);
});

test("builds exact disposable LocalStack and hardened Prowler mutations", () => {
  const localstack = requireExport("buildLocalStackRunArguments")(localstackName, networkName);
  assert.deepEqual(localstack, [
    "run", "--detach", "--rm", "--name", localstackName, "--hostname", localstackName,
    "--network", networkName,
    "--env", "SERVICES=iam,sts", "--env", "ENFORCE_IAM=1", "--env", "PERSISTENCE=0",
    "--label", "zasp.proof=m0-11", "--label", `zasp.marker=${marker}`,
    api.LOCALSTACK_IMAGE,
  ]);
  assert.equal(localstack.includes("--publish"), false);

  const prowler = requireExport("buildProwlerCreateArguments")(
    prowlerName, localstackName, networkName, proofDirectory, outputDirectory,
  );
  assert.deepEqual(prowler, [
    "create", "--rm", "--name", prowlerName, "--hostname", prowlerName,
    "--network", networkName,
    ...prowlerProofEnvironment.flatMap((entry) => ["--env", entry]),
    "--label", "zasp.proof=m0-11", "--label", `zasp.marker=${marker}`,
    "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--pids-limit", "64", "--memory", "768m", "--cpus", "1",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m",
    "--volume", `${proofDirectory}:/proof:ro`,
    "--volume", `${outputDirectory}:/proof/output:rw`,
    "--entrypoint", "/usr/bin/env", api.PROWLER_IMAGE,
    "-i", ...bridgeEnvironment,
    "/home/prowler/.venv/bin/python",
    "/proof/fixture_runner.py", "--fixture", "/proof/fixture.json",
    "--output", "/proof/output/prowler.ocsf.json",
  ]);
  for (const ambient of ["AWS_PROFILE", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "DOCKER_AUTH_CONFIG", ".env"]) {
    assert.equal(prowler.some((entry) => entry.includes(ambient)), false, ambient);
  }
});

test("bounded child execution caps combined output, deadlines, and panics", async () => {
  const runBounded = requireExport("runBounded");
  for (const child of [
    fakeChild({ stdout: [Buffer.alloc(10_000)], stderr: [Buffer.alloc(6_385)], neverClose: true }),
    fakeChild({ neverClose: true }),
  ]) {
    await assert.rejects(
      runBounded("docker", [], { env: {}, timeoutMs: 10, outputLimit: 16_384, category: "provider" }, () => child.child),
      (error) => error?.category === "provider",
    );
    assert.deepEqual(child.signals, ["SIGKILL"]);
  }
});

test("bounded child pipe failures are killed, reaped, and stripped of listeners", async () => {
  const runBounded = requireExport("runBounded");
  for (const streamName of ["stdout", "stderr"]) {
    const fault = faultingChild(streamName);
    await assert.rejects(
      runBounded("docker", [], {
        env: {}, timeoutMs: 100, outputLimit: 16_384, category: "provider",
      }, () => fault.child),
      (error) => error?.category === "provider",
    );
    assert.deepEqual(fault.signals, ["SIGKILL"]);
    assert.equal(fault.reaped(), 1);
    assert.equal(fault.child.listenerCount("error"), 0);
    assert.equal(fault.child.listenerCount("close"), 0);
    assert.equal(fault.child.stdout.listenerCount("data"), 0);
    assert.equal(fault.child.stdout.listenerCount("error"), 0);
    assert.equal(fault.child.stderr.listenerCount("data"), 0);
    assert.equal(fault.child.stderr.listenerCount("error"), 0);
  }
});

test("orchestration maps either child pipe failure to one fixed line and still cleans up", async () => {
  for (const streamName of ["stdout", "stderr"]) {
    const runtime = new FakeRuntime();
    runtime.resolveImages = async () => {
      runtime.record("images");
      const fault = faultingChild(streamName);
      await api.runBounded("docker", [], {
        env: {}, timeoutMs: 100, outputLimit: 16_384, category: "provider",
      }, () => fault.child);
    };
    const proof = await api.orchestrate(runtime, fastOptions());
    assert.deepEqual(proof, { code: 1, line: "Prowler evidence proof failed: provider rejected." });
    assert.equal(proof.line.includes("secret"), false);
    assert.deepEqual(runtime.calls, [
      "initialize", "preflight", "images", "cleanup-output", "prefix-absent",
      "cleanup-config", "temp-prefix-absent",
    ]);
  }
});

test("initializes two exact empty canonical temp directories and isolates Docker CLI environment", async () => {
  const calls = [];
  const runtime = temporaryRuntime({
    command: async (command, args, options) => { calls.push({ command, args, options }); return result(); },
  });
  await runtime.initialize();
  await runtime.dockerRead(["version"]);
  assert.deepEqual(calls[0].options.env, { PATH: "/safe/bin", DOCKER_CONFIG: dockerConfig });
  for (const key of ["HOME", "AWS_PROFILE", "AWS_ACCESS_KEY_ID", "HTTPS_PROXY", "DOCKER_AUTH_CONFIG"]) {
    assert.equal(calls[0].options.env[key], undefined);
  }
  assert.equal(runtime.outputIdentity.path, outputDirectory);
});

test("rejects lexical, symlink, replacement, and nonempty temp ownership", async () => {
  for (const testCase of [
    { candidate: "relative" },
    { candidate: `${tempParent}/${prefix}-docker-config-` },
    { candidate: `/elsewhere/${prefix}-docker-config-owned` },
    { stat: identityStat(1, 2, { symlink: true }) },
    { stat: { ...identityStat(), isDirectory: () => false } },
    { real: "/elsewhere/replacement" },
    { entries: ["config.json"] },
  ]) {
    const removed = [];
    const runtime = temporaryRuntime({
      configCandidate: testCase.candidate ?? dockerConfig,
      configReal: testCase.real ?? (testCase.candidate ?? dockerConfig),
      configStat: testCase.stat ?? identityStat(),
      configEntries: testCase.entries ?? [],
      removeTemp: async (...args) => { removed.push(args); },
    });
    await assert.rejects(runtime.initialize(), (error) => error?.category === "configuration");
    assert.deepEqual(removed, []);
  }
});

test("re-proves the exact empty Docker config immediately before every Docker command", async () => {
  for (const operation of ["dockerRead", "dockerMutation"]) {
    for (const mutation of ["canonical", "identity", "contents"]) {
      let calls = 0;
      const runtime = temporaryRuntime({
        command: async () => { calls += 1; return result(); },
      });
      await runtime.initialize();
      runtime.canonicalPath = async (value) => value === dockerConfig && mutation === "canonical"
        ? `${dockerConfig}-replacement`
        : value;
      runtime.statPath = async (value) => value === dockerConfig
        ? identityStat(1, mutation === "identity" ? 99 : 2)
        : identityStat(1, 3);
      runtime.readDirectory = async (value) => value === dockerConfig && mutation === "contents"
        ? ["config.json"]
        : [];
      await assert.rejects(runtime[operation](["version"]), (error) => error?.category === "provider");
      assert.equal(calls, 0, `${operation}:${mutation}`);
    }
  }
});

test("re-proves the output directory before and after scanner creation, start, and artifact use", async () => {
  const beforeCreate = temporaryRuntime();
  await beforeCreate.initialize();
  beforeCreate.roleIdentity = { arn: roleArn, role_id: roleID };
  beforeCreate.ensureFixture = async () => {};
  beforeCreate.createContainer = async () => prowlerID;
  beforeCreate.readDirectory = async (value) => value === outputDirectory ? ["replacement"] : [];
  await assert.rejects(beforeCreate.createProwler(), (error) => error?.category === "ownership");

  let afterCreateInode = 3;
  const afterCreate = temporaryRuntime();
  await afterCreate.initialize();
  afterCreate.roleIdentity = { arn: roleArn, role_id: roleID };
  afterCreate.ensureFixture = async () => {};
  afterCreate.statPath = async (value) => value === outputDirectory
    ? identityStat(1, afterCreateInode)
    : identityStat(1, 2);
  afterCreate.readDirectory = async () => [];
  afterCreate.createContainer = async () => { afterCreateInode = 99; return prowlerID; };
  await assert.rejects(afterCreate.createProwler(), (error) => error?.category === "ownership");

  let afterStartInode = 3;
  const afterStart = temporaryRuntime();
  await afterStart.initialize();
  afterStart.verifyContainer = async () => prowlerID;
  afterStart.statPath = async (value) => value === outputDirectory
    ? identityStat(1, afterStartInode)
    : identityStat(1, 2);
  afterStart.readDirectory = async (value) => value === outputDirectory ? ["prowler.ocsf.json"] : [];
  afterStart.dockerMutation = async () => {
    afterStartInode = 99;
    return result(3, "Prowler fixture bridge produced one FAIL finding.\n");
  };
  await assert.rejects(afterStart.runProwler(), (error) => error?.category === "ownership");

  const bytes = Buffer.from("artifact");
  let afterReadInode = 3;
  const afterRead = temporaryRuntime({
    artifactBytes: bytes,
    openPath: async () => {
      let offset = 0;
      return {
        stat: async () => identityStat(1, 9, { file: true, size: bytes.length }),
        read: async (buffer, bufferOffset, length) => {
          const chunk = bytes.subarray(offset, offset + length);
          chunk.copy(buffer, bufferOffset);
          offset += chunk.length;
          return { bytesRead: chunk.length };
        },
        close: async () => { afterReadInode = 99; },
      };
    },
  });
  await afterRead.initialize();
  const originalStat = afterRead.statPath;
  afterRead.statPath = async (value) => value === outputDirectory
    ? identityStat(1, afterReadInode)
    : originalStat(value);
  await assert.rejects(afterRead.readArtifact(), (error) => error?.category === "normalization");
});

test("directory replacement restored before cleanup preserves the main failure while persistent mutation gives cleanup precedence", async () => {
  for (const restoreBeforeCleanup of [true, false]) {
    let configInode = 2;
    let phaseCount = 0;
    const guard = temporaryRuntime({ command: async () => result() });
    const runtime = new FakeRuntime();
    runtime.setAbortSignal = () => {
      phaseCount += 1;
      if (phaseCount === 2 && restoreBeforeCleanup) configInode = 2;
    };
    runtime.initialize = async () => {
      runtime.record("initialize");
      await guard.initialize();
      const originalStat = guard.statPath;
      guard.statPath = async (value) => value === dockerConfig
        ? identityStat(1, configInode)
        : originalStat(value);
    };
    runtime.resolveImages = async () => {
      runtime.record("images");
      configInode = 99;
      await guard.dockerMutation(["version"]);
    };
    runtime.requirePrefixAbsent = async () => {
      runtime.record("prefix-absent");
      await guard.dockerMutation(["version"], { category: "cleanup" });
    };
    const proof = await api.orchestrate(runtime, fastOptions());
    assert.deepEqual(proof, restoreBeforeCleanup
      ? { code: 1, line: "Prowler evidence proof failed: provider rejected." }
      : { code: 1, line: "Prowler evidence proof failed: cleanup rejected." });
    for (const call of ["cleanup-output", "prefix-absent", "cleanup-config", "temp-prefix-absent"]) {
      assert.equal(runtime.calls.includes(call), true, `${restoreBeforeCleanup}:${call}`);
    }
  }
});

test("resolves exact full image metadata with one single-attempt pull", async () => {
  const runtime = scriptedRuntime([
    missingImage(api.LOCALSTACK_IMAGE), missingImage(api.LOCALSTACK_IMAGE), result(0, "pulled\n"),
    result(0, imageInspection({
      imageID: localstackImageID,
      environment: localstackImageEnvironment,
      entrypoint: localstackImageEntrypoint,
      exposedPorts: localstackImageExposedPorts,
      volumes: localstackImageVolumes,
      user: null,
      workingDirectory: "/opt/code/localstack/",
    })),
  ]);
  assert.equal(await runtime.resolveImage(api.LOCALSTACK_IMAGE), localstackImageID);
  assert.deepEqual(runtime.calls.map((call) => call.kind), ["read", "read", "mutation", "read"]);
  assert.equal(runtime.calls.filter((call) => call.kind === "mutation").length, 1);
  assert.equal(runtime.calls[0].args[3].includes('{{json (index .Config "User")}}'), true);
  assert.equal(runtime.imageRuntimeMetadata.get(api.LOCALSTACK_IMAGE).user, "");

  for (const malformed of [
    `${localstackImageID}\n`,
    imageInspection({ imageID: localstackImageID, environment: [...localstackImageEnvironment, localstackImageEnvironment[0]], entrypoint: localstackImageEntrypoint }),
    imageInspection({ imageID: localstackImageID, environment: localstackImageEnvironment, entrypoint: null }),
  ]) {
    await assert.rejects(scriptedRuntime([result(0, malformed)]).resolveImage(api.LOCALSTACK_IMAGE));
  }
});

test("pulls only after an exact missing-image envelope and reconciles only thrown ambiguity", async () => {
  const inspection = result(0, imageInspection({
    imageID: localstackImageID,
    environment: localstackImageEnvironment,
    entrypoint: localstackImageEntrypoint,
    exposedPorts: localstackImageExposedPorts,
    volumes: localstackImageVolumes,
    user: "",
    workingDirectory: "/opt/code/localstack/",
  }));

  const generic = scriptedRuntime([result(1), result(1)]);
  await assert.rejects(generic.resolveImage(api.LOCALSTACK_IMAGE), (error) => error?.category === "provider");
  assert.equal(generic.calls.some((call) => call.kind === "mutation"), false);

  const ambiguous = scriptedRuntime([
    missingImage(api.LOCALSTACK_IMAGE), missingImage(api.LOCALSTACK_IMAGE),
    new api.Failure("provider"), inspection,
  ]);
  assert.equal(await ambiguous.resolveImage(api.LOCALSTACK_IMAGE), localstackImageID);
  assert.deepEqual(ambiguous.calls.map((call) => call.kind), ["read", "read", "mutation", "read"]);

  const definitive = scriptedRuntime([
    missingImage(api.LOCALSTACK_IMAGE), missingImage(api.LOCALSTACK_IMAGE),
    result(1, "", "pull rejected\n"), inspection,
  ]);
  await assert.rejects(definitive.resolveImage(api.LOCALSTACK_IMAGE), (error) => error?.category === "provider");
  assert.equal(definitive.calls.length, 3);
  assert.equal(definitive.imageIDs.has(api.LOCALSTACK_IMAGE), false);
});

test("preflight rejects owned container, internal-network, output, or temp prefix collisions", async () => {
  const clean = scriptedRuntime([result(), result()]);
  await clean.preflight();
  for (const responses of [
    [result(0, `${localstackID}|${localstackName}\n`), result()],
    [result(), result(0, `${networkID}|${networkName}\n`)],
  ]) {
    await assert.rejects(scriptedRuntime(responses).preflight(), (error) => error?.category === "ownership");
  }
});

test("temp prefix audits are global across markers, admit only the two current identities, and finish empty", async () => {
  const currentEntries = [basename(dockerConfig), basename(outputDirectory)];
  const staleOtherMarker = "zasp-m0-11-fedcba9876543210-output-stale";

  const clean = temporaryRuntime();
  await clean.initialize();
  clean.readDirectory = async (value) => {
    if (value === tempParent) return [...currentEntries, "unrelated"];
    return [];
  };
  await clean.preflight();

  const stale = temporaryRuntime();
  await stale.initialize();
  stale.readDirectory = async (value) => {
    if (value === tempParent) return [...currentEntries, staleOtherMarker];
    return [];
  };
  await assert.rejects(stale.preflight(), (error) => error?.category === "ownership");
  await assert.rejects(stale.requireTemporaryPrefixAbsent(), (error) => error?.category === "cleanup");

  const final = temporaryRuntime();
  await final.initialize();
  final.readDirectory = async (value) => value === tempParent ? ["unrelated"] : [];
  await final.requireTemporaryPrefixAbsent();
});

test("preflight and absence never reinterpret exhausted provider reads as empty listings", async () => {
  await assert.rejects(
    scriptedRuntime([result(1), result(1), result(1), result(1)]).preflight(),
    (error) => error?.category === "ownership",
  );

  const runtime = scriptedRuntime([
    missingContainer(prowlerID), missingContainer(prowlerID),
    result(1), result(1),
  ]);
  runtime.containerTokens.set("prowler", prowlerID);
  await assert.rejects(runtime.requireContainerAbsent("prowler"), (error) => error?.category === "cleanup");
});

test("reconciles ambiguous mutations only through one exact full-ID owned resource", async () => {
  const network = scriptedRuntime([
    new api.Failure("provider"),
    result(0, `${networkID}|${networkName}\n`),
    result(0, networkInspection()),
  ]);
  assert.equal(await network.createNetwork(), networkID);

  const localstack = scriptedRuntime([
    result(1),
    result(0, `${localstackID}|${localstackName}\n`),
    result(0, localstackInspection()),
  ]);
  localstack.networkToken = networkID;
  localstack.imageIDs.set(api.LOCALSTACK_IMAGE, localstackImageID);
  assert.equal(await localstack.startLocalStack(), localstackID);
});

test("verifies internal network and every LocalStack runtime ownership field", async () => {
  const runtime = scriptedRuntime([result(0, networkInspection()), result(0, localstackInspection())]);
  runtime.networkToken = networkID;
  runtime.containerTokens.set("localstack", localstackID);
  runtime.imageIDs.set(api.LOCALSTACK_IMAGE, localstackImageID);
  runtime.imageRuntimeMetadata.set(api.LOCALSTACK_IMAGE, localstackImageMetadata());
  assert.equal(await runtime.verifyNetwork(), networkID);
  assert.equal(await runtime.verifyContainer("localstack"), localstackID);

  for (const changed of [
    networkInspection({ internal: false }),
    networkInspection({ driver: "overlay" }),
  ]) {
    const candidate = scriptedRuntime([result(0, changed)]);
    candidate.networkToken = networkID;
    await assert.rejects(candidate.verifyNetwork(), (error) => error?.category === "ownership");
  }
  for (const changed of [
    localstackInspection({ hostname: "replacement" }),
    localstackInspection({ environment: [...localstackProofEnvironment, ...localstackImageEnvironment, "AWS_SECRET_ACCESS_KEY=ambient"] }),
    localstackInspection({ mounts: [] }),
    localstackInspection({ attachedNetworkID: "9".repeat(64) }),
  ]) {
    const candidate = scriptedRuntime([result(0, changed)]);
    candidate.networkToken = networkID;
    candidate.containerTokens.set("localstack", localstackID);
    candidate.imageIDs.set(api.LOCALSTACK_IMAGE, localstackImageID);
    candidate.imageRuntimeMetadata.set(api.LOCALSTACK_IMAGE, localstackImageMetadata());
    await assert.rejects(candidate.verifyContainer("localstack"), (error) => error?.category === "ownership");
  }
});

test("uses synthetic in-container AWS calls, exact readiness, and single-attempt IAM creation", async () => {
  const runtime = scriptedRuntime([
    result(0, `${JSON.stringify({ Account: "000000000000", Arn: "arn:aws:iam::000000000000:root", UserId: "000000000000" })}\n`),
    result(0, `${JSON.stringify({ Role: roleDocument() })}\n`),
    result(0, `${JSON.stringify({ Role: roleDocument() })}\n`),
    result(0, `${JSON.stringify({ Tags: exactTags() })}\n`),
  ]);
  runtime.containerTokens.set("localstack", localstackID);
  runtime.networkToken = networkID;
  runtime.imageIDs.set(api.LOCALSTACK_IMAGE, localstackImageID);
  runtime.imageRuntimeMetadata.set(api.LOCALSTACK_IMAGE, localstackImageMetadata());
  runtime.verifyContainer = async () => localstackID;

  assert.equal(await runtime.isLocalStackReady(), true);
  assert.deepEqual(await runtime.createAndVerifyRole(), { arn: roleArn, role_id: roleID });
  const mutations = runtime.calls.filter((call) => call.kind === "mutation");
  assert.equal(mutations.length, 1);
  const mutation = mutations[0].args;
  assert.deepEqual(mutation.slice(0, 2), ["exec", "--env"]);
  assert.equal(mutation.includes("create-role"), true);
  assert.equal(mutation.includes("--assume-role-policy-document"), true);
  assert.equal(mutation.some((value) => value.includes("AWS_PROFILE")), false);
});

test("accepts exact IAM proof tags independent of provider response order", async () => {
  const reversed = [...exactTags()].reverse();
  const role = roleDocument(reversed);
  const runtime = scriptedRuntime([
    result(0, `${JSON.stringify({ Role: role })}\n`),
    result(0, `${JSON.stringify({ Role: role })}\n`),
    result(0, `${JSON.stringify({ Tags: reversed })}\n`),
  ]);
  runtime.containerTokens.set("localstack", localstackID);
  runtime.verifyContainer = async () => localstackID;
  assert.deepEqual(await runtime.createAndVerifyRole(), { arn: roleArn, role_id: roleID });
});

test("reconciles one ambiguous IAM create only through exact role identity, trust, and tags", async () => {
  const role = roleDocument();
  const runtime = scriptedRuntime([
    new api.Failure("provider"),
    result(0, `${JSON.stringify({ Role: role })}\n`),
    result(0, `${JSON.stringify({ Tags: exactTags() })}\n`),
  ]);
  runtime.containerTokens.set("localstack", localstackID);
  runtime.verifyContainer = async () => localstackID;
  assert.deepEqual(await runtime.createAndVerifyRole(), { arn: roleArn, role_id: roleID });
  assert.equal(runtime.calls.filter((call) => call.kind === "mutation").length, 1);
});

test("rejects impossible or non-canonical role timestamps while accepting strict UTC", async () => {
  for (const createDate of [
    "2026-02-30T00:00:00+00:00",
    "Fri, 14 Aug 2026 00:00:00 GMT",
    "2026-08-14 00:00:00+00:00",
    "2026-08-14T00:00:00-07:00",
  ]) {
    const role = { ...roleDocument(), CreateDate: createDate };
    const runtime = scriptedRuntime([
      result(0, `${JSON.stringify({ Role: role })}\n`),
      result(0, `${JSON.stringify({ Role: role })}\n`),
      result(0, `${JSON.stringify({ Tags: exactTags() })}\n`),
    ]);
    runtime.containerTokens.set("localstack", localstackID);
    runtime.verifyContainer = async () => localstackID;
    await assert.rejects(runtime.createAndVerifyRole(), (error) => error?.category === "ownership");
  }

  const exactRole = { ...roleDocument(), CreateDate: "2026-08-14T00:00:00.123456Z" };
  const exact = scriptedRuntime([
    result(0, `${JSON.stringify({ Role: exactRole })}\n`),
    result(0, `${JSON.stringify({ Role: exactRole })}\n`),
    result(0, `${JSON.stringify({ Tags: exactTags() })}\n`),
  ]);
  exact.containerTokens.set("localstack", localstackID);
  exact.verifyContainer = async () => localstackID;
  assert.deepEqual(await exact.createAndVerifyRole(), { arn: roleArn, role_id: roleID });
});

test("verifies hardened scanner ownership and rejects security, mount, env, or argv drift", async () => {
  const exact = scriptedRuntime([result(0, prowlerInspection())]);
  configureProwler(exact);
  assert.equal(await exact.verifyContainer("prowler"), prowlerID);

  for (const changed of [
    prowlerInspection({ readonlyRootfs: false }),
    prowlerInspection({ capDrop: [] }),
    prowlerInspection({ securityOpt: [] }),
    prowlerInspection({ pidsLimit: 0 }),
    prowlerInspection({ memory: 0 }),
    prowlerInspection({ nanoCpus: 0 }),
    prowlerInspection({ user: "root" }),
    prowlerInspection({ environment: [...prowlerProofEnvironment, ...prowlerImageEnvironment, "HTTPS_PROXY=http://ambient.invalid"] }),
    prowlerInspection({ mounts: [] }),
    prowlerInspection({ command: ["-i", "PATH=/bad", "/bin/sh"] }),
  ]) {
    const runtime = scriptedRuntime([result(0, changed)]);
    configureProwler(runtime);
    await assert.rejects(runtime.verifyContainer("prowler"), (error) => error?.category === "ownership");
  }
});

test("container inspection rejects duplicate JSON keys without requiring object key order", async () => {
  const reorderedMounts = [
    Object.fromEntries(Object.entries({
      Type: "bind", Source: proofDirectory, Destination: "/proof", Mode: "ro", RW: false, Propagation: "rprivate",
    }).reverse()),
    Object.fromEntries(Object.entries({
      Type: "bind", Source: outputDirectory, Destination: "/proof/output", Mode: "rw", RW: true, Propagation: "rprivate",
    }).reverse()),
  ];
  const reordered = scriptedRuntime([result(0, prowlerInspection({ mounts: reorderedMounts }))]);
  configureProwler(reordered);
  assert.equal(await reordered.verifyContainer("prowler"), prowlerID);

  const duplicateNetworks = replaceInspectionField(
    prowlerInspection(), 8,
    `{${JSON.stringify(networkName)}:{"NetworkID":${JSON.stringify(networkID)}},${JSON.stringify(networkName)}:{"NetworkID":${JSON.stringify(networkID)}}}`,
  );
  const duplicateTmpfs = replaceInspectionField(
    prowlerInspection(), 17,
    `{${JSON.stringify("/tmp")}:${JSON.stringify("rw,noexec,nosuid,nodev,size=33554432")},${JSON.stringify("/tmp")}:${JSON.stringify("rw,noexec,nosuid,nodev,size=33554432")}}`,
  );
  for (const inspection of [duplicateNetworks, duplicateTmpfs]) {
    const runtime = scriptedRuntime([result(0, inspection)]);
    configureProwler(runtime);
    await assert.rejects(runtime.verifyContainer("prowler"), (error) => error?.category === "ownership");
  }
});

test("requires exact Prowler exit 3, one fixed bridge line, and one normalized artifact", async () => {
  const normalized = expectedNormalized();
  const bytes = Buffer.from("official artifact");
  let received;
  const runtime = scriptedRuntime([
    result(0, prowlerInspection()),
    result(3, "Prowler fixture bridge produced one FAIL finding.\n"),
  ], {
    artifactBytes: bytes,
    normalize: (organization, artifact, observedAt) => {
      received = { organization, artifact, observedAt };
      return normalized;
    },
  });
  configureProwler(runtime);
  assert.equal(await runtime.runProwler(), undefined);
  assert.deepEqual(await runtime.normalizeArtifact(), normalized);
  assert.deepEqual(received, {
    organization: "org_aaaaaaaaaaaaaaaa",
    artifact: bytes,
    observedAt: "2026-08-14T00:00:00.000Z",
  });

  for (const processResult of [
    result(0, "Prowler fixture bridge produced one FAIL finding.\n"),
    result(3, "unexpected\n"),
    result(3, "Prowler fixture bridge produced one FAIL finding.\n", "noise"),
  ]) {
    const rejected = scriptedRuntime([result(0, prowlerInspection()), processResult]);
    configureProwler(rejected);
    await assert.rejects(rejected.runProwler(), (error) => error?.category === "normalization");
  }
});

test("blocks persistent output replacement before scanner start and gives cleanup failure precedence", async () => {
  let outputInode = 3;
  let startCalls = 0;
  const guard = temporaryRuntime({
    command: async (command, args) => {
      if (command === "docker" && args[0] === "start") startCalls += 1;
      return result(3, "Prowler fixture bridge produced one FAIL finding.\n");
    },
  });
  const runtime = new FakeRuntime();
  runtime.initialize = async () => {
    runtime.record("initialize");
    await guard.initialize();
    const originalStat = guard.statPath;
    guard.statPath = async (value) => value === outputDirectory
      ? identityStat(1, outputInode)
      : originalStat(value);
    guard.readDirectory = async () => [];
    guard.verifyContainer = async () => { outputInode = 99; return prowlerID; };
  };
  runtime.runProwler = async () => {
    runtime.record("run-prowler");
    await guard.runProwler();
  };
  runtime.cleanupOutput = async () => {
    runtime.record("cleanup-output");
    await guard.cleanupOutput();
  };

  assert.deepEqual(await api.orchestrate(runtime, fastOptions()), {
    code: 1, line: "Prowler evidence proof failed: cleanup rejected.",
  });
  assert.equal(startCalls, 0);
  for (const call of ["cleanup-output", "prefix-absent", "cleanup-config", "temp-prefix-absent"]) {
    assert.equal(runtime.calls.includes(call), true, call);
  }
});

test("blocks output replacement restored inside scanner start before post-start reproof", async () => {
  let outputInode = 3;
  let startCalls = 0;
  const runtime = temporaryRuntime({
    command: async (command, args) => {
      if (command === "docker" && args[0] === "start") {
        startCalls += 1;
        outputInode = 3;
      }
      return result(3, "Prowler fixture bridge produced one FAIL finding.\n");
    },
  });
  await runtime.initialize();
  const originalStat = runtime.statPath;
  runtime.statPath = async (value) => value === outputDirectory
    ? identityStat(1, outputInode)
    : originalStat(value);
  runtime.readDirectory = async () => [];
  runtime.verifyContainer = async () => { outputInode = 99; return prowlerID; };

  await assert.rejects(runtime.runProwler(), (error) => error?.category === "operation");
  assert.equal(startCalls, 0);
});

test("artifact boundary accepts exactly one bounded regular non-symlink output", async () => {
  const bytes = Buffer.from("artifact");
  const runtime = temporaryRuntime({ artifactBytes: bytes });
  await runtime.initialize();
  assert.deepEqual(await runtime.readArtifact(), bytes);

  for (const testCase of [
    { outputEntries: [] },
    { outputEntries: ["prowler.ocsf.json", "extra.json"] },
    { artifactStat: identityStat(1, 9, { file: true, symlink: true, size: bytes.length }) },
    { artifactStat: identityStat(1, 9, { file: true, size: 65_537 }) },
    { artifactBytes: Buffer.alloc(65_537) },
  ]) {
    const rejected = temporaryRuntime({ artifactBytes: bytes, ...testCase });
    await rejected.initialize();
    await assert.rejects(rejected.readArtifact(), (error) => error?.category === "normalization");
  }
});

test("reads the artifact only through a bounded no-follow descriptor", async () => {
  const bytes = Buffer.from("descriptor artifact");
  const openCalls = [];
  let closed = false;
  const runtime = temporaryRuntime({
    artifactBytes: bytes,
    readPath: async (value) => {
      if (value.endsWith("prowler.ocsf.json")) throw new Error("path read must not occur");
      return Buffer.from("{}\n");
    },
    openPath: async (path, flags) => {
      openCalls.push({ path, flags });
      let offset = 0;
      return {
        stat: async () => identityStat(1, 9, { file: true, size: bytes.length }),
        read: async (buffer, bufferOffset, length) => {
          const chunk = bytes.subarray(offset, offset + length);
          chunk.copy(buffer, bufferOffset);
          offset += chunk.length;
          return { bytesRead: chunk.length };
        },
        close: async () => { closed = true; },
      };
    },
  });
  await runtime.initialize();
  assert.deepEqual(await runtime.readArtifact(), bytes);
  assert.equal(openCalls.length, 1);
  assert.equal(openCalls[0].path, `${outputDirectory}/prowler.ocsf.json`);
  assert.equal(Number.isInteger(openCalls[0].flags), true);
  assert.equal(closed, true);
});

test("read-only Docker calls retry once while every mutation is single-attempt", async () => {
  const runtime = scriptedRuntime([new api.Failure("provider"), result(0, "ok\n")]);
  assert.deepEqual(await runtime.readDocker(["version"]), result(0, "ok\n"));
  assert.equal(runtime.calls.length, 2);

  const mutation = scriptedRuntime([new api.Failure("provider"), result()]);
  await assert.rejects(mutation.dockerMutation(["network", "create"]));
  assert.equal(mutation.calls.length, 1);
});

test("generic missing envelopes fail while exact missing resources reconcile", async () => {
  const generic = scriptedRuntime([result(1), result(1), result()]);
  generic.containerTokens.set("prowler", prowlerID);
  await assert.rejects(generic.requireContainerAbsent("prowler"), (error) => error?.category === "cleanup");

  const exact = scriptedRuntime([
    missingContainer(prowlerID), missingContainer(prowlerID), result(),
  ]);
  exact.containerTokens.set("prowler", prowlerID);
  await exact.requireContainerAbsent("prowler");
});

test("orchestrates the exact lifecycle and cleanup in reverse dependency order", async () => {
  const runtime = new FakeRuntime();
  assert.deepEqual(await requireExport("orchestrate")(runtime, fastOptions()), { code: 0, line: api.SUCCESS_LINE });
  assert.deepEqual(runtime.calls, [
    "initialize", "preflight", "images", "network", "localstack", "ready",
    "role", "prowler", "run-prowler", "normalize",
    "remove-prowler", "absent-prowler", "remove-localstack", "absent-localstack",
    "remove-network", "absent-network", "cleanup-output", "prefix-absent",
    "cleanup-config", "temp-prefix-absent",
  ]);
});

test("cleanup continues independently, has precedence, and preserves network until containers are absent", async () => {
  const runtime = new FakeRuntime({ failAt: "normalize", cleanupFailures: new Set(["remove-prowler", "absent-localstack", "cleanup-output"]) });
  const deadlines = [];
  const proof = await api.orchestrate(runtime, {
    ...fastOptions(),
    withDeadline: async (operation, timeoutMs) => { deadlines.push(timeoutMs); return operation(); },
  });
  assert.deepEqual(proof, { code: 1, line: "Prowler evidence proof failed: cleanup rejected." });
  assert.deepEqual(deadlines, [300_000, 60_000]);
  assert.equal(runtime.calls.includes("remove-network"), false);
  for (const call of ["absent-network", "cleanup-output", "cleanup-config", "prefix-absent", "temp-prefix-absent"]) {
    assert.equal(runtime.calls.includes(call), true, call);
  }
});

test("joins delayed temp creation into cleanup and fences late main-phase mutations", async () => {
  const creation = deferred();
  const started = deferred();
  let removed = false;
  const runtime = temporaryRuntime({
    makeTemp: async (prefix_) => {
      if (prefix_.includes("docker-config")) { started.resolve(); return creation.promise; }
      return outputDirectory;
    },
    removeTemp: async (path) => { if (path === dockerConfig) removed = true; },
  });
  let phase = 0;
  const proof = await api.orchestrate(runtime, {
    readinessAttempts: 1,
    wait: async () => {},
    withDeadline: async (operation) => {
      phase += 1;
      const controller = new AbortController();
      if (phase === 1) {
        const pending = operation(controller.signal);
        pending.catch(() => {});
        await started.promise;
        controller.abort();
        queueMicrotask(() => creation.resolve(dockerConfig));
        throw new api.Failure("operation");
      }
      return operation(controller.signal);
    },
  });
  await creation.promise;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(removed, true);
  assert.deepEqual(proof, { code: 1, line: "Prowler evidence proof failed: operation rejected." });
});

test("deadline, panic, output overflow, and stream failure expose one fixed line only", async () => {
  for (const runtime of [
    new FakeRuntime({ failAt: "images", failure: new Error("secret panic") }),
    new FakeRuntime({ failAt: "run-prowler", failure: new api.Failure("normalization") }),
  ]) {
    const proof = await api.orchestrate(runtime, fastOptions());
    assert.match(proof.line, /^Prowler evidence proof failed: (operation|normalization) rejected\.$/);
    assert.equal(proof.line.includes("secret"), false);
  }

  let stdout = "";
  let stderr = "";
  let exitCode;
  const code = await requireExport("runMain")(undefined, {
    runtimeFactory: () => { throw new Error("secret factory panic"); },
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: (value) => { exitCode = value; },
  });
  assert.equal(code, 1);
  assert.equal(stdout, "");
  assert.equal(stderr, "Prowler evidence proof failed: operation rejected.\n");
  assert.equal(exitCode, 1);
});

class FakeRuntime {
  constructor({ failAt, failure = new Error("detail"), cleanupFailures = new Set() } = {}) {
    this.failAt = failAt;
    this.failure = failure;
    this.cleanupFailures = cleanupFailures;
    this.calls = [];
  }
  setAbortSignal() {}
  record(name, value) {
    this.calls.push(name);
    if (this.failAt === name || this.cleanupFailures.has(name)) throw this.failure;
    return value;
  }
  hasTemporaryCreationStarted() { return true; }
  async initialize() { this.record("initialize"); }
  async preflight() { this.record("preflight"); }
  async resolveImages() { this.record("images"); }
  async createNetwork() { return this.record("network", networkID); }
  async startLocalStack() { return this.record("localstack", localstackID); }
  async isLocalStackReady() { return this.record("ready", true); }
  async createAndVerifyRole() { return this.record("role", { arn: roleArn, role_id: roleID }); }
  async createProwler() { return this.record("prowler", prowlerID); }
  async runProwler() { this.record("run-prowler"); }
  async normalizeArtifact() { return this.record("normalize", expectedNormalized()); }
  async removeContainer(kind) { this.record(`remove-${kind}`); }
  async requireContainerAbsent(kind) { this.record(`absent-${kind}`); }
  async removeNetwork() { this.record("remove-network"); }
  async requireNetworkAbsent() { this.record("absent-network"); }
  async cleanupOutput() { this.record("cleanup-output"); }
  async cleanupDockerConfig() { this.record("cleanup-config"); }
  async requirePrefixAbsent() { this.record("prefix-absent"); }
  async requireTemporaryPrefixAbsent() { this.record("temp-prefix-absent"); }
}

class ScriptedRuntime extends (api?.DockerRuntime ?? class {}) {
  constructor(responses, options = {}) {
    super({
      path: "/safe/bin", marker, proofDirectory, tempParent,
      makeTemp: async (value) => value.includes("docker-config") ? dockerConfig : outputDirectory,
      chmodPath: async () => {},
      removeTemp: async () => {},
      canonicalPath: async (value) => value,
      statPath: async (value) => value.endsWith("fixture.json")
        ? identityStat(1, 8, { file: true, size: 1 })
        : identityStat(1, value === dockerConfig ? 2 : 3),
      readDirectory: async (value) => value === tempParent
        ? [basename(dockerConfig), basename(outputDirectory)]
        : [],
      readPath: async () => Buffer.from("{}\n"),
      wait: async () => {},
      normalize: options.normalize,
    });
    this.responses = [...responses];
    this.calls = [];
    this.dockerConfigIdentity = { path: dockerConfig, dev: 1, ino: 2 };
    this.outputIdentity = { path: outputDirectory, dev: 1, ino: 3 };
    this.imageRuntimeMetadata.set(api.LOCALSTACK_IMAGE, localstackImageMetadata());
    this.imageRuntimeMetadata.set(api.PROWLER_IMAGE, prowlerImageMetadata());
    if (options.artifactBytes !== undefined) {
      this.readArtifact = async () => options.artifactBytes;
    }
  }
  async dockerRead(args, options = {}) { return this.next("read", args, options); }
  async dockerMutation(args, options = {}) { return this.next("mutation", args, options); }
  next(kind, args, options) {
    this.calls.push({ kind, args, options });
    const response = this.responses.shift() ?? result(1);
    if (response instanceof Error) throw response;
    return response;
  }
}

function scriptedRuntime(responses, options) {
  return new ScriptedRuntime(responses, options);
}

function temporaryRuntime({
  configCandidate = dockerConfig,
  outputCandidate = outputDirectory,
  configReal = configCandidate,
  outputReal = outputCandidate,
  configStat = identityStat(1, 2),
  outputStat = identityStat(1, 3),
  artifactStat,
  configEntries = [],
  outputEntries = ["prowler.ocsf.json"],
  artifactBytes = Buffer.from("artifact"),
  readPath,
  openPath,
  makeTemp,
  removeTemp = async () => {},
  command = async () => result(),
} = {}) {
  const statForArtifact = artifactStat ?? identityStat(1, 9, { file: true, size: artifactBytes.length });
  const removedPaths = new Set();
  const createdPaths = new Set();
  let outputDirectoryReads = 0;
  return new (requireExport("DockerRuntime"))({
    path: "/safe/bin", marker, proofDirectory, tempParent,
    makeTemp: async (value) => {
      const candidate = await (makeTemp ?? (async (prefix_) => prefix_.includes("docker-config")
        ? configCandidate
        : outputCandidate))(value);
      createdPaths.add(candidate);
      return candidate;
    },
    chmodPath: async () => {},
    removeTemp: async (...arguments_) => {
      await removeTemp(...arguments_);
      removedPaths.add(arguments_[0]);
    },
    canonicalPath: async (value) => {
      if (value === configCandidate) return configReal;
      if (value === outputCandidate) return outputReal;
      return value;
    },
    statPath: async (value) => {
      if (removedPaths.has(value)) throw Object.assign(new Error("missing"), { code: "ENOENT" });
      if (value === configCandidate) return configStat;
      if (value === outputCandidate) return outputStat;
      if (value.endsWith("prowler.ocsf.json")) return statForArtifact;
      if (value.endsWith("fixture.json")) return identityStat(1, 8, { file: true, size: 3 });
      return identityStat(1, 7);
    },
    readDirectory: async (value) => {
      if (value === configCandidate) return configEntries;
      if (value === outputCandidate) {
        outputDirectoryReads += 1;
        return outputDirectoryReads <= 2 ? [] : outputEntries;
      }
      if (value === tempParent) {
        return [...createdPaths]
          .filter((candidate) => !removedPaths.has(candidate))
          .map((candidate) => basename(candidate));
      }
      return [];
    },
    readPath: readPath ?? (async (value) => value.endsWith("prowler.ocsf.json") ? artifactBytes : Buffer.from("{}\n")),
    openPath: openPath ?? (async () => {
      let offset = 0;
      return {
        stat: async () => statForArtifact,
        read: async (buffer, bufferOffset, length) => {
          const chunk = artifactBytes.subarray(offset, offset + length);
          chunk.copy(buffer, bufferOffset);
          offset += chunk.length;
          return { bytesRead: chunk.length };
        },
        close: async () => {},
      };
    }),
    command,
    wait: async () => {},
  });
}

function localstackImageMetadata() {
  return {
    environment: localstackImageEnvironment,
    entrypoint: localstackImageEntrypoint,
    command: null,
    exposedPorts: localstackImageExposedPorts,
    volumes: localstackImageVolumes,
    user: "",
    workingDirectory: "/opt/code/localstack/",
  };
}

function prowlerImageMetadata() {
  return {
    environment: prowlerImageEnvironment,
    entrypoint: ["/home/prowler/.venv/bin/prowler"],
    command: null,
    exposedPorts: [],
    volumes: [],
    user: "prowler",
    workingDirectory: "/home/prowler",
  };
}

function configureProwler(runtime) {
  runtime.networkToken = networkID;
  runtime.containerTokens.set("prowler", prowlerID);
  runtime.imageIDs.set(api.PROWLER_IMAGE, prowlerImageID);
  runtime.imageRuntimeMetadata.set(api.PROWLER_IMAGE, prowlerImageMetadata());
}

function roleDocument(tags = exactTags()) {
  return {
    Path: "/",
    RoleName: "shared-fixture-role",
    RoleId: roleID,
    Arn: roleArn,
    CreateDate: "2026-08-14T00:00:00+00:00",
    AssumeRolePolicyDocument: {
      Version: "2012-10-17",
      Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }],
    },
    MaxSessionDuration: 3600,
    Tags: tags,
  };
}

function exactTags() {
  return [
    { Key: "zasp.marker", Value: marker },
    { Key: "zasp.proof", Value: "m0-11" },
  ];
}

function expectedNormalized() {
  const resourceID = "org_aaaaaaaaaaaaaaaa:aws:identity_role:81eeba69c5c0887f4083a0e195a431b852d750fd3ee41ad276c1142285d1b77b";
  return {
    organization_id: "org_aaaaaaaaaaaaaaaa",
    resources: [{ id: resourceID, organization_id: "org_aaaaaaaaaaaaaaaa", provider: "aws", kind: "identity_role", source_id: roleArn }],
    findings: [{ organization_id: "org_aaaaaaaaaaaaaaaa", resource_id: resourceID }],
    evidence: [{ organization_id: "org_aaaaaaaaaaaaaaaa", resource_id: resourceID }],
  };
}

function missingContainer(token) {
  return result(1, "\n", `error: no such object: ${token}\n`);
}

function missingImage(image) {
  return result(1, "\n", `Error response from daemon: No such image: ${image}\n`);
}

function replaceInspectionField(inspection, index, replacement) {
  const fields = inspection.slice(0, -1).split("|");
  assert.equal(fields.length, 26);
  fields[index] = replacement;
  return `${fields.join("|")}\n`;
}

function fakeChild({ stdout = [], stderr = [], code = 0, signal = null, neverClose = false } = {}) {
  const child = new EventEmitter();
  const signals = [];
  let closed = false;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = (value) => {
    signals.push(value);
    if (!closed) queueMicrotask(() => { closed = true; child.emit("close", null, value); });
    return true;
  };
  queueMicrotask(() => {
    for (const chunk of stdout) child.stdout.write(chunk);
    for (const chunk of stderr) child.stderr.write(chunk);
    if (!neverClose && !closed) {
      closed = true;
      child.stdout.end(); child.stderr.end(); child.emit("close", code, signal);
    }
  });
  return { child, signals };
}

function faultingChild(streamName) {
  const child = new EventEmitter();
  const signals = [];
  let closeCount = 0;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = (value) => {
    signals.push(value);
    queueMicrotask(() => { closeCount += 1; child.emit("close", null, "SIGKILL"); });
    return true;
  };
  queueMicrotask(() => child[streamName].emit("error", new Error(`secret ${streamName} failure`)));
  return { child, signals, reaped: () => closeCount };
}

function deferred() {
  let resolve;
  const promise = new Promise((resolve_) => { resolve = resolve_; });
  return { promise, resolve };
}

function fastOptions() {
  return { readinessAttempts: 1, wait: async () => {}, withDeadline: async (operation) => operation() };
}
