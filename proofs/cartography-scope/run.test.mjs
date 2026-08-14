import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  CARTOGRAPHY_IMAGE,
  CARTOGRAPHY_BOOTSTRAP,
  NEO4J_IMAGE,
  DockerRuntime,
  Failure,
  SUCCESS_LINE,
  buildCartographyCreateArguments,
  buildNeo4jRunArguments,
  buildNetworkCreateArguments,
  orchestrate,
  runBounded,
  runMain,
} from "./run.mjs";

const marker = "0123456789abcdef";
const prefix = `zasp-m0-10-${marker}`;
const networkName = `${prefix}-network`;
const networkID = "c".repeat(64);
const neo4jID = "a".repeat(64);
const cartographyID = "b".repeat(64);
const neo4jImageID = `sha256:${"d".repeat(64)}`;
const cartographyImageID = `sha256:${"e".repeat(64)}`;
const proofDirectory = "/safe/proof";
const dockerConfig = `/safe/tmp/${prefix}-docker-config-owned`;
const baseContainerEnvironment = [
  "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "HOME=/tmp",
  "LANG=C.UTF-8",
  "PYTHONUNBUFFERED=1",
];
const expectedBootstrap = 'import os,re,runpy,sys;h=os.environ.get("HOSTNAME","");e=sys.argv[1];(h==e and re.fullmatch(r"zasp-m0-10-[0-9a-f]{16}-cartography-[ab]",h)) or sys.exit(1);os.environ.clear();os.environ.update({"PATH":"/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOME":"/tmp","LANG":"C.UTF-8","PYTHONUNBUFFERED":"1","HOSTNAME":h});sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name="__main__")';

const rawGraph = {
  schema_version: 1,
  nodes: [
    { labels: ["AWSAccount"], properties: { id: "000000000000" } },
    { labels: ["AWSRole"], properties: { arn: "arn:aws:iam::000000000000:role/shared-fixture-role" } },
    { labels: ["GitHubOrganization"], properties: { url: "https://api.github.test/orgs/shared-fixture" } },
    { labels: ["GitHubRepository"], properties: { id: "424242" } },
  ],
  relationships: [
    {
      type: "RESOURCE",
      source: { label: "AWSAccount", id: "000000000000" },
      target: { label: "AWSRole", id: "arn:aws:iam::000000000000:role/shared-fixture-role" },
    },
    {
      type: "OWNER",
      source: { label: "GitHubRepository", id: "424242" },
      target: { label: "GitHubOrganization", id: "https://api.github.test/orgs/shared-fixture" },
    },
  ],
};

test("pins both exact images and builds exact network and Neo4j mutations", () => {
  assert.equal(CARTOGRAPHY_IMAGE, "ghcr.io/cartography-cncf/cartography:0.139.1@sha256:f1d7c1f46a8a2137b9a955327d3cd47e8340c7d537d0447467d2e952af8bb8f0");
  assert.equal(NEO4J_IMAGE, "neo4j:5.26-community@sha256:d9dd3dc7d1c78fa959191ff02dbdcbefadceaf83eee23428fb92a58cac8ad3fe");
  assert.deepEqual(buildNetworkCreateArguments(networkName), [
    "network", "create", "--label", "zasp.proof=m0-10", "--label", `zasp.marker=${marker}`, networkName,
  ]);
  assert.deepEqual(buildNeo4jRunArguments(`${prefix}-neo4j-a`, networkName), [
    "run", "--detach", "--rm", "--name", `${prefix}-neo4j-a`,
    "--network", networkName,
    "--env", "NEO4J_AUTH=none",
    "--label", "zasp.proof=m0-10", "--label", `zasp.marker=${marker}`,
    "--publish", "127.0.0.1::7687", NEO4J_IMAGE,
  ]);
  assert.notDeepEqual(
    buildNeo4jRunArguments(`${prefix}-neo4j-a`, networkName),
    buildNeo4jRunArguments(`${prefix}-neo4j-b`, networkName),
  );
});

test("builds two exact one-shot Cartography creates with a read-only proof mount and no provider environment", () => {
  for (const slot of ["a", "b"]) {
    const args = buildCartographyCreateArguments(
      `${prefix}-cartography-${slot}`,
      `${prefix}-neo4j-${slot}`,
      networkName,
      proofDirectory,
      slot,
    );
    assert.deepEqual(args, [
      "create", "--rm", "--name", `${prefix}-cartography-${slot}`,
      "--hostname", `${prefix}-cartography-${slot}`,
      "--network", networkName,
      "--label", "zasp.proof=m0-10", "--label", `zasp.marker=${marker}`,
      "--entrypoint", "python",
      "--volume", `${proofDirectory}:/proof:ro`,
      CARTOGRAPHY_IMAGE,
      "-I", "-c", expectedBootstrap,
      `${prefix}-cartography-${slot}`,
      "/proof/fixture_runner.py",
      "--fixture", `/proof/fixtures/org-${slot}.json`,
      "--neo4j-uri", `bolt://${prefix}-neo4j-${slot}:7687`,
    ]);
    assert.equal(args.includes("--env"), false);
  }
  assert.equal(CARTOGRAPHY_BOOTSTRAP, expectedBootstrap);
});

test("Cartography bootstrap erases image environment and passes only exact bridge argv", () => {
  const directory = mkdtempSync(join(tmpdir(), "zasp-m0-10-bootstrap-test-"));
  const probe = join(directory, "probe.py");
  writeFileSync(probe, "import json,os,sys\nprint(json.dumps({'env':dict(os.environ),'argv':sys.argv},sort_keys=True,separators=(',',':')))\n");
  const hostname = `${prefix}-cartography-a`;
  const runnerArguments = [probe, "--fixture", "/proof/fixtures/org-a.json", "--neo4j-uri", `bolt://${prefix}-neo4j-a:7687`];
  try {
    const process = spawnSync("/opt/homebrew/bin/python3.13", ["-I", "-c", CARTOGRAPHY_BOOTSTRAP, hostname, ...runnerArguments], {
      encoding: "utf8",
      env: {
        HOSTNAME: hostname,
        AWS_SECRET_ACCESS_KEY: "must-disappear",
        GITHUB_TOKEN: "must-disappear",
        HTTPS_PROXY: "http://must-disappear.invalid",
        PYTHONPATH: "/must/disappear",
        IMAGE_METADATA: "must-disappear",
      },
    });
    assert.equal(process.status, 0);
    assert.equal(process.stderr, "");
    assert.deepEqual(JSON.parse(process.stdout), {
      env: Object.fromEntries([...baseContainerEnvironment, `HOSTNAME=${hostname}`].map((entry) => entry.split(/=(.*)/s).slice(0, 2))),
      argv: runnerArguments,
    });

    const rejected = spawnSync("/opt/homebrew/bin/python3.13", ["-I", "-c", CARTOGRAPHY_BOOTSTRAP, hostname, ...runnerArguments], {
      encoding: "utf8",
      env: { HOSTNAME: `${prefix}-cartography-b` },
    });
    assert.equal(rejected.status, 1);
    assert.equal(rejected.stdout, "");
    assert.equal(rejected.stderr, "");
  } finally {
    rmSync(directory, { recursive: true, force: false, maxRetries: 0 });
  }
});

test("bounded spawn enforces one combined 16 KiB cap, absolute deadlines, and SIGKILL", async () => {
  for (const child of [
    fakeChild({ stdout: [Buffer.alloc(10_000)], stderr: [Buffer.alloc(6_385)], neverClose: true }),
    fakeChild({ neverClose: true }),
  ]) {
    await assert.rejects(
      runBounded("docker", [], { env: {}, timeoutMs: 15, outputLimit: 16_384 }, () => child.child),
      (error) => error instanceof Failure && error.category === "operation",
    );
    assert.deepEqual(child.signals, ["SIGKILL"]);
  }
});

test("admits only an empty canonical Docker-config directory and passes only PATH plus DOCKER_CONFIG", async () => {
  const calls = [];
  const runtime = temporaryRuntime({
    command: (command, args, options) => {
      calls.push({ command, args, options });
      return Promise.resolve(result(0));
    },
  });
  await runtime.initialize();
  await runtime.dockerRead(["version"]);
  assert.deepEqual(calls[0], {
    command: "docker",
    args: ["version"],
    options: {
      env: { PATH: "/safe/bin", DOCKER_CONFIG: dockerConfig },
      timeoutMs: 30_000,
      outputLimit: 16_384,
      category: "provider",
    },
  });
  assert.equal(calls[0].options.env.HOME, undefined);
  assert.equal(calls[0].options.env.HTTPS_PROXY, undefined);
  assert.equal(calls[0].options.env.DOCKER_AUTH_CONFIG, undefined);
});

test("never removes a malformed or nonempty temporary candidate", async () => {
  const cases = [
    { name: "relative", value: "relative" },
    { name: "bare-prefix", value: `/safe/tmp/${prefix}-docker-config-` },
    { name: "wrong-parent", value: `/elsewhere/${prefix}-docker-config-owned` },
    { name: "symlink", stat: identityStat(1, 2, true) },
    { name: "not-directory", stat: { ...identityStat(1, 2), isDirectory: () => false } },
    { name: "canonical-escape", real: `/elsewhere/${prefix}-docker-config-owned` },
    { name: "nonempty", entries: ["config.json"] },
  ];
  for (const testCase of cases) {
    const removed = [];
    const runtime = temporaryRuntime({
      candidate: testCase.value ?? dockerConfig,
      candidateReal: testCase.real ?? (testCase.value ?? dockerConfig),
      stat: testCase.stat ?? identityStat(1, 2),
      entries: testCase.entries ?? [],
      removeTemp: (...args) => { removed.push(args); },
    });
    await assert.rejects(runtime.initialize(), (error) => error?.category === "configuration", testCase.name);
    assert.deepEqual(removed, [], testCase.name);
  }
});

test("re-proves canonical path, device, inode, type, and emptiness immediately before recursive config removal", async () => {
  const mutations = [
    { name: "inode", stat: identityStat(1, 3) },
    { name: "device", stat: identityStat(2, 2) },
    { name: "symlink", stat: identityStat(1, 2, true) },
    { name: "escape", real: "/elsewhere/replacement" },
    { name: "nonempty", entries: ["credentials.json"] },
  ];
  for (const mutation of mutations) {
    const removed = [];
    const runtime = temporaryRuntime({
      statPath: sequence(identityStat(1, 2), mutation.stat ?? identityStat(1, 2)),
      canonicalPath: pathAwareSequence(mutation.real ?? dockerConfig),
      readDirectory: sequence([], mutation.entries ?? []),
      removeTemp: (...args) => { removed.push(args); },
    });
    await runtime.initialize();
    await assert.rejects(runtime.cleanupDockerConfig(), (error) => error?.category === "cleanup", mutation.name);
    assert.deepEqual(removed, [], mutation.name);
  }

  const removed = [];
  let removedDirectory = false;
  const unchanged = temporaryRuntime({
    statPath: async () => {
      if (removedDirectory) throw Object.assign(new Error("missing"), { code: "ENOENT" });
      return identityStat(1, 2);
    },
    canonicalPath: async (value) => {
      if (value === dockerConfig && removedDirectory) throw Object.assign(new Error("missing"), { code: "ENOENT" });
      return value;
    },
    readDirectory: async (value) => {
      if (value === dockerConfig && removedDirectory) throw Object.assign(new Error("missing"), { code: "ENOENT" });
      return [];
    },
    removeTemp: (...args) => { removed.push(args); removedDirectory = true; },
  });
  await unchanged.initialize();
  await unchanged.cleanupDockerConfig();
  assert.deepEqual(removed, [[dockerConfig, { recursive: true, force: false, maxRetries: 0 }]]);
});

test("requires exact Docker-config and proof-prefix absence after recursive removal", async () => {
  const runtime = temporaryRuntime({ removeTemp: async () => {} });
  await runtime.initialize();
  await assert.rejects(runtime.cleanupDockerConfig(), (error) => error?.category === "cleanup");
});

test("resolves exact images through inspect, one pull mutation, and a fresh full-ID inspect", async () => {
  const runtime = new ScriptedRuntime([
    result(1), result(1),
    result(0, "pulled\n"),
    result(0, `${neo4jImageID}\n`),
  ]);
  assert.equal(await runtime.resolveImage(NEO4J_IMAGE), neo4jImageID);
  assert.deepEqual(runtime.calls.map((call) => call.args[0]), ["image", "image", "pull", "image"]);
  assert.equal(runtime.calls.filter((call) => call.kind === "mutation").length, 1);

  const missing = new ScriptedRuntime([result(1), result(1), result(1)]);
  await assert.rejects(missing.resolveImage(CARTOGRAPHY_IMAGE), (error) => error?.category === "provider");
});

test("preflight rejects every owned prefix collision while preserving an unrelated shared container", async () => {
  const shared = `${"f".repeat(64)}|shared-non-proof`;
  const clean = new ScriptedRuntime([
    result(0, `${shared}\n`),
    result(0),
  ]);
  await clean.requirePrefixAbsent();

  for (const responses of [
    [result(0, `${shared}\n${neo4jID}|${prefix}-neo4j-a\n`), result(0)],
    [result(0, `${shared}\n`), result(0, `${networkID}|${prefix}-network\n`)],
  ]) {
    const runtime = new ScriptedRuntime(responses);
    await assert.rejects(runtime.requirePrefixAbsent(), (error) => error?.category === "ownership");
  }
});

test("a preflight ownership collision is preserved and never promoted to cleanup authority", async () => {
  const runtime = new FakeRuntime({
    failAt: "preflight",
    failure: new Failure("ownership"),
    candidate: false,
  });
  assert.deepEqual(await orchestrate(runtime, fastOptions()), {
    code: 1,
    line: "Cartography scope proof failed: ownership rejected.",
  });
  assert.equal(runtime.calls.some((call) => call.startsWith("remove-")), false);
  assert.equal(runtime.calls.includes("prefix-absent"), false);
  assert.equal(runtime.calls.includes("cleanup-config"), true);
});

test("reconciles ambiguous network creation only through exact full ownership", async () => {
  const expected = `${networkID}|${networkName}|m0-10|${marker}`;
  const runtime = new ScriptedRuntime([
    result(1),
    result(0, `${networkID}|${networkName}\n`),
    result(0, `${expected}\n`),
  ]);
  assert.equal(await runtime.createNetwork(), networkID);

  for (const wrong of [
    expected.replace(networkID, "abc"),
    expected.replace(networkName, `${networkName}-replacement`),
    expected.replace("m0-10", "wrong"),
    expected.replace(marker, "fedcba9876543210"),
  ]) {
    const candidate = new ScriptedRuntime([result(0, `${wrong}\n`)]);
    candidate.networkToken = networkID;
    await assert.rejects(candidate.verifyNetwork(), (error) => error?.category === "ownership");
  }
});

test("rejects truncated IDs and wrong container image, name, labels, marker, network, auth, or port", async () => {
  const expected = containerInspection({
    token: neo4jID,
    name: `${prefix}-neo4j-a`,
    imageID: neo4jImageID,
    image: NEO4J_IMAGE,
    environment: ["NEO4J_AUTH=none"],
    ports: { "7687/tcp": [{ HostIp: "127.0.0.1", HostPort: "49152" }] },
  });
  const wrongValues = [
    replaceInspectionField(expected, 0, neo4jID.slice(0, 12)),
    replaceInspectionField(expected, 1, "/wrong"),
    replaceInspectionField(expected, 2, "wrong-hostname"),
    replaceInspectionField(expected, 3, cartographyImageID),
    replaceInspectionField(expected, 4, "neo4j:latest"),
    replaceInspectionField(expected, 5, "wrong"),
    replaceInspectionField(expected, 6, "fedcba9876543210"),
    replaceInspectionField(expected, 7, "bridge"),
    expected.replace("NEO4J_AUTH=none", "NEO4J_AUTH=password"),
    expected.replace("127.0.0.1", "0.0.0.0"),
  ];
  for (const value of wrongValues) {
    const runtime = new ScriptedRuntime([result(0, `${value}\n`)]);
    runtime.networkToken = networkID;
    runtime.imageIDs.set(NEO4J_IMAGE, neo4jImageID);
    runtime.containerTokens.set("neo4j-a", neo4jID);
    await assert.rejects(runtime.verifyContainer("neo4j-a"), (error) => error?.category === "ownership");
  }
});

test("allows pinned-image Neo4j metadata and unbound exposed ports but only one loopback Bolt binding", async () => {
  const runtime = new ScriptedRuntime([result(0, `${containerInspection({
    token: neo4jID,
    name: `${prefix}-neo4j-a`,
    imageID: neo4jImageID,
    image: NEO4J_IMAGE,
    environment: ["PATH=/opt/java/bin", "NEO4J_EDITION=community", "NEO4J_AUTH=none"],
    ports: {
      "7473/tcp": null,
      "7474/tcp": null,
      "7687/tcp": [{ HostIp: "127.0.0.1", HostPort: "49152" }],
    },
  })}\n`)]);
  runtime.networkToken = networkID;
  runtime.imageIDs.set(NEO4J_IMAGE, neo4jImageID);
  runtime.containerTokens.set("neo4j-a", neo4jID);
  assert.equal(await runtime.verifyContainer("neo4j-a"), neo4jID);
});

test("rejects credential or proxy settings in a Cartography container even though the bootstrap clears image metadata", async () => {
  const runtime = new ScriptedRuntime([result(0, `${containerInspection({
    token: cartographyID,
    name: `${prefix}-cartography-a`,
    imageID: cartographyImageID,
    image: CARTOGRAPHY_IMAGE,
    environment: [...baseContainerEnvironment, "PYTHON_VERSION=3.13", "HTTPS_PROXY=http://ambient.invalid"],
  })}\n`)]);
  runtime.networkToken = networkID;
  runtime.imageIDs.set(CARTOGRAPHY_IMAGE, cartographyImageID);
  runtime.containerTokens.set("cartography-a", cartographyID);
  await assert.rejects(runtime.verifyContainer("cartography-a"), (error) => error?.category === "ownership");
});

test("rejects a replacement Cartography hostname, entrypoint, bootstrap argv, or read-only mount", async () => {
  const expected = containerInspection({
    token: cartographyID,
    name: `${prefix}-cartography-a`,
    imageID: cartographyImageID,
    image: CARTOGRAPHY_IMAGE,
    environment: ["PYTHON_VERSION=3.13"],
  });
  const wrongValues = [
    replaceInspectionField(expected, 2, `${prefix}-cartography-b`),
    replaceInspectionField(expected, 11, JSON.stringify(["sh"])),
    replaceInspectionField(expected, 12, JSON.stringify(["/proof/fixture_runner.py"])),
    replaceInspectionField(expected, 13, JSON.stringify([{ Type: "bind", Source: proofDirectory, Destination: "/proof", RW: true }])),
  ];
  for (const value of wrongValues) {
    const runtime = new ScriptedRuntime([result(0, `${value}\n`)]);
    runtime.networkToken = networkID;
    runtime.imageIDs.set(CARTOGRAPHY_IMAGE, cartographyImageID);
    runtime.containerTokens.set("cartography-a", cartographyID);
    await assert.rejects(runtime.verifyContainer("cartography-a"), (error) => error?.category === "ownership");
  }
});

test("reconciles ambiguous creates and removes only the same freshly re-proven container", async () => {
  const inspection = containerInspection({
    token: neo4jID,
    name: `${prefix}-neo4j-a`,
    imageID: neo4jImageID,
    image: NEO4J_IMAGE,
    environment: ["NEO4J_AUTH=none"],
    ports: { "7687/tcp": [{ HostIp: "127.0.0.1", HostPort: "49152" }] },
  });
  const runtime = new ScriptedRuntime([
    result(1),
    result(0, `${neo4jID}|${prefix}-neo4j-a\n`),
    result(0, `${inspection}\n`),
  ]);
  runtime.networkToken = networkID;
  runtime.imageIDs.set(NEO4J_IMAGE, neo4jImageID);
  assert.equal(await runtime.startNeo4j("a"), neo4jID);

  const removal = new ScriptedRuntime([
    result(0, `${inspection}\n`),
    result(1),
    result(1), result(1),
    result(0), result(0),
  ]);
  removal.networkToken = networkID;
  removal.imageIDs.set(NEO4J_IMAGE, neo4jImageID);
  removal.containerTokens.set("neo4j-a", neo4jID);
  await removal.removeContainer("neo4j-a");
  assert.equal(removal.calls.filter((call) => call.args[0] === "rm").length, 1);

  const replacement = new ScriptedRuntime([
    result(1), result(1),
    result(0, `${"f".repeat(64)}|${prefix}-neo4j-a\n`),
  ]);
  replacement.containerTokens.set("neo4j-a", neo4jID);
  await assert.rejects(replacement.removeContainer("neo4j-a"), (error) => error?.category === "cleanup");
  assert.equal(replacement.calls.some((call) => call.args[0] === "rm"), false);
});

test("readiness and bridge calls use exact finite deadlines and reject malformed or overflowing output", async () => {
  const runtime = new ScriptedRuntime([
    result(0, `${containerInspection({ token: neo4jID, name: `${prefix}-neo4j-a`, imageID: neo4jImageID, image: NEO4J_IMAGE, environment: ["NEO4J_AUTH=none"], ports: { "7687/tcp": [{ HostIp: "127.0.0.1", HostPort: "49152" }] } })}\n`),
    result(0, "ready\n1\n"),
  ]);
  runtime.networkToken = networkID;
  runtime.imageIDs.set(NEO4J_IMAGE, neo4jImageID);
  runtime.containerTokens.set("neo4j-a", neo4jID);
  assert.equal(await runtime.isNeo4jReady("a"), true);
  assert.equal(runtime.calls.at(-1).options.timeoutMs, 500);
  assert.equal(runtime.calls.at(-1).options.outputLimit, 16_384);

  for (const output of ["not-json\n", `${"x".repeat(16_385)}\n`]) {
    const bridge = new ScriptedRuntime([result(0, output)]);
    bridge.containerTokens.set("cartography-a", cartographyID);
    await assert.rejects(bridge.attachCartography("a"), (error) => error?.category === "normalization");
    assert.equal(bridge.calls[0].options.timeoutMs, 45_000);
    assert.equal(bridge.calls[0].options.outputLimit, 16_384);
  }
});

test("orchestrates two isolated graphs, normalizes exact fixtures, and cleans in reverse dependency order", async () => {
  const runtime = new FakeRuntime();
  assert.deepEqual(await orchestrate(runtime, fastOptions()), { code: 0, line: SUCCESS_LINE });
  assert.deepEqual(runtime.calls, [
    "initialize", "preflight", "images", "network",
    "neo4j-a", "verify-neo4j-a", "port-neo4j-a",
    "neo4j-b", "verify-neo4j-b", "port-neo4j-b",
    "ready-a", "ready-b", "cartography-a", "verify-cartography-a",
    "cartography-b", "verify-cartography-b", "bridge-a", "bridge-b",
    "remove-cartography-b", "absent-cartography-b",
    "remove-cartography-a", "absent-cartography-a",
    "remove-neo4j-b", "absent-neo4j-b",
    "remove-neo4j-a", "absent-neo4j-a",
    "remove-network", "absent-network", "prefix-absent", "cleanup-config", "temp-prefix-absent",
  ]);
});

test("maps malformed bridge JSON, exact graph mismatch, panic, cancellation, and construction failures to fixed categories", async () => {
  const mismatchedGraph = structuredClone(rawGraph);
  mismatchedGraph.nodes[0].properties.id = "111111111111";
  mismatchedGraph.nodes[1].properties.arn = "arn:aws:iam::111111111111:role/shared-fixture-role";
  mismatchedGraph.relationships[0].source.id = "111111111111";
  mismatchedGraph.relationships[0].target.id = "arn:aws:iam::111111111111:role/shared-fixture-role";
  const cases = [
    { runtime: new FakeRuntime({ bridge: "{" }), category: "normalization" },
    { runtime: new FakeRuntime({ bridge: JSON.stringify(mismatchedGraph) }), category: "normalization" },
    { runtime: new FakeRuntime({ failAt: "images", failure: new Failure("provider") }), category: "provider" },
    { runtime: new FakeRuntime({ failAt: "network", failure: new Error("panic detail") }), category: "operation" },
    { runtime: new FakeRuntime({ failAt: "ready-a", failure: new Failure("operation") }), category: "operation" },
  ];
  for (const testCase of cases) {
    const result = await orchestrate(testCase.runtime, fastOptions());
    assert.deepEqual(result, { code: 1, line: `Cartography scope proof failed: ${testCase.category} rejected.` });
    assert.equal(result.line.includes("detail"), false);
  }

  let stderr = "";
  const code = await runMain(undefined, {
    runtimeFactory: () => { throw new Failure("configuration"); },
    stdout: { write: () => { throw new Error("must not write success"); } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: () => {},
  });
  assert.equal(code, 1);
  assert.equal(stderr, "Cartography scope proof failed: configuration rejected.\n");
});

test("cleanup continues across every resource, has an independent budget, and cleanup failure wins", async () => {
  const runtime = new FakeRuntime({ failAt: "bridge-a", failure: new Failure("normalization"), cleanupFailures: new Set(["remove-cartography-b", "remove-neo4j-a", "cleanup-config"]) });
  const deadlines = [];
  const result = await orchestrate(runtime, {
    ...fastOptions(),
    withDeadline: async (operation, timeoutMs) => {
      deadlines.push(timeoutMs);
      return operation();
    },
  });
  assert.deepEqual(result, { code: 1, line: "Cartography scope proof failed: cleanup rejected." });
  assert.deepEqual(deadlines, [300_000, 60_000]);
  for (const call of ["remove-cartography-b", "remove-cartography-a", "remove-neo4j-b", "remove-neo4j-a", "remove-network", "prefix-absent", "cleanup-config", "temp-prefix-absent"]) {
    assert.ok(runtime.calls.includes(call), call);
  }
});

test("outer cancellation is fixed-output operation failure and cleanup gets its own fresh deadline", async () => {
  const runtime = new FakeRuntime({ candidate: false });
  const deadlines = [];
  let call = 0;
  const result = await orchestrate(runtime, {
    readinessAttempts: 1,
    wait: async () => {},
    withDeadline: async (operation, timeoutMs) => {
      deadlines.push(timeoutMs);
      call += 1;
      if (call === 1) throw new Failure("operation");
      return operation();
    },
  });
  assert.deepEqual(result, { code: 1, line: "Cartography scope proof failed: operation rejected." });
  assert.deepEqual(deadlines, [300_000, 60_000]);
  assert.deepEqual(runtime.calls, ["cleanup-config"]);
});

test("runMain emits exactly one fixed success or failure line and contains factory and stream panics", async () => {
  for (const { runtime, expected, code } of [
    { runtime: new FakeRuntime(), expected: `${SUCCESS_LINE}\n`, code: 0 },
    { runtime: new FakeRuntime({ failAt: "preflight", failure: new Failure("ownership") }), expected: "Cartography scope proof failed: ownership rejected.\n", code: 1 },
  ]) {
    let stdout = "", stderr = "", exitCode;
    const actual = await runMain(runtime, {
      orchestrateOptions: fastOptions(),
      stdout: { write: (value) => { stdout += value; } },
      stderr: { write: (value) => { stderr += value; } },
      setExitCode: (value) => { exitCode = value; },
    });
    assert.equal(actual, code);
    assert.equal(stdout + stderr, expected);
    assert.equal(exitCode, code);
    assert.equal((stdout + stderr).trimEnd().split("\n").length, 1);
  }
});

class FakeRuntime {
  constructor({ bridge = JSON.stringify(rawGraph), failAt, failure = new Error("detail"), cleanupFailures = new Set(), candidate = true } = {}) {
    this.bridge = bridge;
    this.failAt = failAt;
    this.failure = failure;
    this.cleanupFailures = cleanupFailures;
    this.candidate = candidate;
    this.calls = [];
  }

  record(name, value) {
    this.calls.push(name);
    if (this.failAt === name || this.cleanupFailures.has(name)) throw this.failure;
    return value;
  }

  async initialize() { this.record("initialize"); }
  async preflight() { this.record("preflight"); }
  async resolveImages() { this.record("images"); }
  async createNetwork() { return this.record("network", networkID); }
  async startNeo4j(slot) { return this.record(`neo4j-${slot}`, neo4jID); }
  async verifyContainer(kind) { this.record(`verify-${kind}`); }
  async neo4jPort(slot) { return this.record(`port-neo4j-${slot}`, 49152); }
  async isNeo4jReady(slot) { return this.record(`ready-${slot}`, true); }
  async createCartography(slot) { return this.record(`cartography-${slot}`, cartographyID); }
  async attachCartography(slot) { return this.record(`bridge-${slot}`, this.bridge); }
  hasCandidate() { return this.candidate; }
  async removeContainer(kind) { this.record(`remove-${kind}`); }
  async requireContainerAbsent(kind) { this.record(`absent-${kind}`); }
  async removeNetwork() { this.record("remove-network"); }
  async requireNetworkAbsent() { this.record("absent-network"); }
  async requirePrefixAbsent() { this.record("prefix-absent"); }
  async cleanupDockerConfig() { this.record("cleanup-config"); }
  async requireTemporaryPrefixAbsent() { this.record("temp-prefix-absent"); }
}

class ScriptedRuntime extends DockerRuntime {
  constructor(responses) {
    super({
      path: "/safe/bin", marker, proofDirectory, tempParent: "/safe/tmp",
      makeTemp: async () => dockerConfig,
      removeTemp: async () => {},
      canonicalPath: async (value) => value,
      statPath: async () => identityStat(1, 2),
      readDirectory: async () => [],
      wait: async () => {},
    });
    this.responses = responses;
    this.calls = [];
    this.dockerConfigIdentity = { path: dockerConfig, dev: 1, ino: 2 };
    this.proofIdentity = { path: proofDirectory, dev: 1, ino: 3 };
  }

  async dockerRead(args, options = {}) {
    this.calls.push({ kind: "read", args, options: this.commandOptions(options) });
    return this.responses.shift() ?? result(1);
  }

  async dockerMutation(args, options = {}) {
    this.calls.push({ kind: "mutation", args, options: this.commandOptions(options) });
    return this.responses.shift() ?? result(1);
  }

  commandOptions(options) {
    return {
      timeoutMs: options.timeoutMs ?? 30_000,
      outputLimit: options.outputLimit ?? 16_384,
      category: options.category ?? "provider",
    };
  }
}

function temporaryRuntime({
  candidate = dockerConfig,
  candidateReal = candidate,
  stat = identityStat(1, 2),
  entries = [],
  statPath = async () => stat,
  canonicalPath = async (value) => value === "/safe/tmp" || value === proofDirectory ? value : candidateReal,
  readDirectory = async () => entries,
  removeTemp = async () => {},
  command = async () => result(0),
} = {}) {
  return new DockerRuntime({
    path: "/safe/bin", marker, proofDirectory, tempParent: "/safe/tmp",
    makeTemp: async () => candidate, removeTemp, canonicalPath, statPath, readDirectory,
    command,
  });
}

function containerInspection({
  token,
  name,
  hostname = name.includes("-neo4j-") ? token.slice(0, 12) : name,
  imageID,
  image,
  environment,
  ports = {},
  entrypoint = name.includes("-cartography-") ? ["python"] : null,
  command = name.includes("-cartography-") ? [
    "-I", "-c", expectedBootstrap, name, "/proof/fixture_runner.py",
    "--fixture", `/proof/fixtures/org-${name.at(-1)}.json`,
    "--neo4j-uri", `bolt://${prefix}-neo4j-${name.at(-1)}:7687`,
  ] : null,
  mounts = name.includes("-cartography-") ? [{ Type: "bind", Source: proofDirectory, Destination: "/proof", RW: false }] : [],
}) {
  return [
    token,
    `/${name}`,
    hostname,
    imageID,
    image,
    "m0-10",
    marker,
    networkName,
    JSON.stringify({ [networkName]: { NetworkID: networkID } }),
    JSON.stringify(environment),
    JSON.stringify(ports),
    JSON.stringify(entrypoint),
    JSON.stringify(command),
    JSON.stringify(mounts),
  ].join("|");
}

function result(status = 0, stdout = "", stderr = "", signal = null) {
  return { status, stdout, stderr, signal };
}

function replaceInspectionField(value, index, replacement) {
  const fields = value.split("|");
  fields[index] = replacement;
  return fields.join("|");
}

function identityStat(dev, ino, link = false) {
  return { dev, ino, isDirectory: () => true, isSymbolicLink: () => link };
}

function sequence(...values) {
  return async () => {
    const value = values.shift();
    if (value instanceof Error) throw value;
    return value;
  };
}

function pathAwareSequence(finalCandidate) {
  const candidates = [dockerConfig, finalCandidate];
  return async (value) => {
    if (value === "/safe/tmp" || value === proofDirectory) return value;
    return candidates.shift();
  };
}

function fakeChild({ stdout = [], stderr = [], code = 0, signal = null, neverClose = false } = {}) {
  const child = new EventEmitter();
  const signals = [];
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = (value) => { signals.push(value); return true; };
  queueMicrotask(() => {
    for (const chunk of stdout) child.stdout.write(chunk);
    for (const chunk of stderr) child.stderr.write(chunk);
    if (!neverClose) {
      child.stdout.end();
      child.stderr.end();
      child.emit("close", code, signal);
    }
  });
  return { child, signals };
}

function fastOptions() {
  return {
    readinessAttempts: 1,
    wait: async () => {},
    withDeadline: async (operation) => operation(),
  };
}
