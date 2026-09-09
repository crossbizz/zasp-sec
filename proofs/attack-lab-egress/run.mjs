import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const directory = dirname(fileURLToPath(import.meta.url));
const root = resolve(directory, "../..");
const image = "alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412";
const contract = join(root, "deploy/staging/attack-lab-egress-contract.json");

export function validateReceipt(before, receipt, after) {
  assert.equal(before?.reachable, true);
  assert.equal(after?.reachable, true);
  for (const name of ["proxy_allowed", "infra_allowed", "direct_denied", "wrong_port_denied"]) assert.equal(receipt?.[name], true);
  assert.equal(receipt.uid, 65532);
  assert.equal(receipt.capabilities, 0);
  assert.match(receipt.kernel_dropped_packets, /^[1-9][0-9]*$/);
  assert.equal(receipt.proof_boundary, "owned Linux network namespace; not live AWS security-group attachment");
  return true;
}

// Names are recorded before create. A lost CLI response cannot hide a daemon-
// created object. Never remove a namesake without its exact ownership label.
export async function createOwned(intents, owner, kind, create) {
  assert.match(owner, /^zasp-m521-[a-f0-9]{32}$/);
  assert.ok(["container", "network"].includes(kind));
  const name = `${owner}-${kind}-${intents.length}`;
  intents.push({ kind, name });
  return create(name);
}

export async function cleanupOwned(intents, owner, run) {
  assert.match(owner, /^zasp-m521-[a-f0-9]{32}$/);
  const failures = [];
  for (const intent of [...intents].reverse()) {
    try {
      assert.ok(intent.name.startsWith(owner + "-"));
      assert.ok(["container", "network"].includes(intent.kind));
      const prefix = intent.kind === "network" ? ["network"] : [];
      const observed = JSON.parse(await run([...prefix, "inspect", intent.name]));
      assert.equal(observed.length, 1);
      const value = observed[0];
      assert.equal(value.Name, intent.kind === "network" ? intent.name : "/" + intent.name);
      assert.equal((intent.kind === "network" ? value.Labels : value.Config?.Labels)?.["zasp.fixture.owner"], owner);
      assert.match(value.Id, /^[a-f0-9]{64}$/);
      await run([...prefix, "rm", ...(intent.kind === "container" ? ["--force"] : []), value.Id]);
    } catch { failures.push(intent.name); }
  }
  assert.deepEqual(failures, [], "owned fixture cleanup could not be verified");
}

export async function runProof({ interruptAfterAllocation = false } = {}) {
  const abort = new AbortController();
  const interrupted = () => abort.abort();
  process.once("SIGTERM", interrupted);
  process.once("SIGINT", interrupted);
  const temporary = await mkdtemp(join(tmpdir(), "zasp-m521-egress-"));
  const nonce = randomBytes(16).toString("hex");
  const owner = `zasp-m521-${nonce}`;
  const intents = [];
  let network;
  let receipt;
  const run = async (command, args, options = {}) => (await exec(command, args, { cwd: root, timeout: 120_000, maxBuffer: 2 * 1024 * 1024, signal: abort.signal, ...options })).stdout.trim();
  const docker = (args, options) => run("docker", args, options);
  try {
    const architecture = await docker(["info", "--format", "{{.Architecture}}"]);
    const goarch = ({ aarch64: "arm64", arm64: "arm64", x86_64: "amd64", amd64: "amd64" })[architecture];
    assert.ok(goarch, "supported Docker Linux architecture required");
    const binary = join(temporary, "proof");
    await run("go", ["build", "-mod=readonly", "-trimpath", "-o", binary, "."], { cwd: directory, env: { ...process.env, CGO_ENABLED: "0", GOOS: "linux", GOARCH: goarch } });
    await chmod(temporary, 0o755);
    await chmod(binary, 0o755);
    await docker(["pull", image]);
    abort.signal.throwIfAborted();
    network = await createOwned(intents, owner, "network", (name) => docker(["network", "create", "--internal", "--label", `zasp.fixture.owner=${owner}`, name]));
    assert.match(network, /^[a-f0-9]{64}$/);
    const create = async (mode, environment = {}, enforce = false) => {
      abort.signal.throwIfAborted();
      const id = await createOwned(intents, owner, "container", (name) => docker(["create", "--name", name, "--network", network, "--label", `zasp.fixture.owner=${owner}`, "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=128m", "--cpus=0.5",
        ...(enforce ? ["--cap-add=NET_ADMIN", "--cap-add=SETUID", "--cap-add=SETGID"] : ["--user=65532:65532", "--sysctl=net.ipv4.ip_unprivileged_port_start=0"]),
        "--mount", `type=bind,src=${binary},dst=/proof,readonly`, "--mount", `type=bind,src=${contract},dst=/contract.json,readonly`,
        "--env", `PROOF_NONCE=${nonce}`, ...Object.entries(environment).flatMap(([key, value]) => ["--env", `${key}=${value}`]),
        "--entrypoint=/proof", image, mode]));
      assert.match(id, /^[a-f0-9]{64}$/);
      return id;
    };
    const server = async (environment = {}) => {
      const id = await create("serve", environment);
      await docker(["start", id]);
      const detail = JSON.parse(await docker(["inspect", id]))[0];
      const ip = Object.values(detail.NetworkSettings.Networks)[0]?.IPAddress;
      assert.match(ip, /^\d+\.\d+\.\d+\.\d+$/);
      return { id, ip };
    };
    const target = await server();
    const proxy = await server({ PROOF_FORWARD: target.ip });
    const infrastructure = await server();
    if (interruptAfterAllocation) {
      console.error(`Interrupting owned fixture: ${owner}`);
      process.kill(process.pid, "SIGTERM");
      await new Promise((done) => setImmediate(done));
      abort.signal.throwIfAborted();
    }
    // exec runs this independent positive control in the proxy namespace, not
    // the namespace whose OUTPUT chain is about to be restricted.
    const control = async () => JSON.parse(await docker(["exec", "--env", `PROOF_TARGET=${target.ip}`, proxy.id, "/proof", "control"]));
    let before;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { before = await control(); break; } catch (error) { if (attempt === 29 || abort.signal.aborted) throw error; }
      await new Promise((done) => setTimeout(done, 100));
    }
    const runner = await create("enforce", { PROOF_TARGET: target.ip, PROOF_PROXY: proxy.ip, PROOF_INFRA: infrastructure.ip }, true);
    const output = await docker(["start", "--attach", runner], { timeout: 30_000 });
    const state = JSON.parse(await docker(["inspect", runner]))[0].State;
    assert.equal(state.ExitCode, 0, "kernel enforcement fixture failed");
    receipt = JSON.parse(output);
    const after = await control();
    validateReceipt(before, receipt, after);
    receipt.contract_sha256 = createHash("sha256").update(await readFile(contract)).digest("hex");
    receipt.control_before = before.reachable;
    receipt.control_after = after.reachable;
  } finally {
    try {
      await cleanupOwned(intents, owner, async (args) => (await exec("docker", args, { timeout: 20_000, maxBuffer: 2 * 1024 * 1024 })).stdout.trim());
    } finally {
      // This path was created by mkdtemp above. No shared workspace is removed.
      await rm(temporary, { recursive: true, force: true });
      process.removeListener("SIGTERM", interrupted);
      process.removeListener("SIGINT", interrupted);
    }
  }
  receipt.cleanup = true;
  return receipt;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runProof({ interruptAfterAllocation: process.argv.includes("--interrupt-after-allocation") }).then((receipt) => console.log(JSON.stringify(receipt))).catch((error) => { console.error(error.message); process.exitCode = 1; });
}
