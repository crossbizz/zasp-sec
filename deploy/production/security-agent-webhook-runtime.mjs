import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnOwnedCommand } from "../../scripts/owned-command.mjs";
import { createOwnedBrowserPostgres } from "../../scripts/owned-browser-postgres.mjs";
import { goTestRuntime, requireGoTestVersion } from "./go-test-runtime.mjs";

export function validateWebhookTestEvents(raw, names) {
  const events = raw.trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
  assert.ok(events.length > 0, "no Go test events");
  assert.ok(!events.some(e => e.Action === "skip"), "unexpected Go test skip");
  for (const name of names) {
    assert.equal(events.filter(e => e.Test === name && e.Action === "run").length, 1, `missing or repeated test ${name}`);
    assert.equal(events.filter(e => e.Test === name && e.Action === "pass").length, 1, `test failed: ${name}`);
  }
  assert.ok(!events.some(e => e.Action === "fail"), "Go tests failed");
  return events;
}

export async function runWebhookRuntime(args = process.argv.slice(2)) {
  assert.deepEqual(args, ["--group", "authority"], "select --group authority");
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const platform = path.join(root, "services/platform");
  const output = await mkdtemp(path.join(tmpdir(), "zasp-webhook-authority-"));
  const runtime = goTestRuntime();
  const active = new Set();
  let postgres;
  async function command(executable, argv, env = runtime.env, cwd = platform, timeout = 120000) {
    const owned = spawnOwnedCommand(executable, argv, { cwd, env });
    active.add(owned);
    const timer = setTimeout(() => void owned.stop(), timeout);
    try {
      const result = await owned.completed;
      assert.equal(result.status, 0, `${executable} failed: ${result.stderr || result.stdout}`);
      return result.stdout;
    } finally { clearTimeout(timer); active.delete(owned); }
  }
  const stop = async () => {
    await Promise.all([...active].map(p => p.stop()));
    if (postgres) await postgres.stop();
  };
  const interrupted = () => { void stop().finally(() => { process.exitCode = 1; }); };
  process.once("SIGINT", interrupted); process.once("SIGTERM", interrupted);
  console.log(`WEBHOOK_EVIDENCE ${output}`);
  try {
    requireGoTestVersion(await command(runtime.executable, ["env", "GOVERSION"]));
    const architecture = (await command("docker", ["image", "inspect", "postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba", "--format", "{{.Architecture}}"])).trim();
    assert.ok(["amd64", "arm64"].includes(architecture));
    const relay = path.join(output, "postgres-relay"), binary = path.join(output, "apiserver.test");
    await command(runtime.executable, ["build", "-o", relay, "./internal/ownedpgrelay"], { ...runtime.env, GOOS: "linux", GOARCH: architecture, CGO_ENABLED: "0" });
    await command(runtime.executable, ["test", "-c", "-o", binary, "./apiserver"]);
    const tests = ["TestSecurityAgentWebhookReleaseCyclePostgres", "TestSecurityAgentWebhookAuthorityPostgres", "TestSecurityAgentWebhookApprovalPostgres", "TestSecurityAgentWebhookIdempotencyPostgres", "TestSecurityAgentWebhookLeasePostgres", "TestSecurityAgentWebhookPrior57ExistingTestPostgres", "TestSecurityAgentWebhookPrior57AttackLabPostgres", "TestSecurityAgentWebhookPrior58ExistingTestPostgres", "TestSecurityAgentWebhookPrior58AttackLabPostgres", "TestSecurityAgentWebhookCandidate59ExistingTestPostgres", "TestSecurityAgentWebhookCandidate59AttackLabPostgres"];
    for (const name of tests) {
      const listener = net.createServer();
      await new Promise((resolve, reject) => { listener.once("error", reject); listener.listen(0, "127.0.0.1", resolve); });
      const port = listener.address().port;
      await new Promise(resolve => listener.close(resolve));
      postgres = createOwnedBrowserPostgres({ port, isolatedRelay: relay });
      await postgres.start();
      console.log(`WEBHOOK_CONTAINER ${postgres.containerID} network=none test=${name}`);
      const owned = spawnOwnedCommand(runtime.executable, ["tool", "test2json", "-t", "-p", "apiserver", binary, `-test.run=^${name}$`, "-test.v", "-test.timeout=180s"], {
        cwd: path.join(platform, "apiserver"), env: { ...runtime.env, ZASP_WEBHOOK_TEST_PORT: String(port), ZASP_WEBHOOK_TEST_CONTAINER: postgres.containerID },
      });
      active.add(owned);
      const result = await owned.completed;
      active.delete(owned);
      await writeFile(path.join(output, `${name}.jsonl`), result.stdout, { mode: 0o600 });
      await writeFile(path.join(output, `${name}.stderr`), result.stderr, { mode: 0o600 });
      process.stdout.write(result.stdout);
      validateWebhookTestEvents(result.stdout, [name]);
      assert.equal(result.status, 0);
      await postgres.stop(); postgres = undefined;
    }
  } finally {
    await stop();
    process.removeListener("SIGINT", interrupted); process.removeListener("SIGTERM", interrupted);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runWebhookRuntime().catch(error => { console.error(error); process.exitCode = 1; });
}
