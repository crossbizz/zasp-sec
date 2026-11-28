// Run with node --test deploy/zasp/vps-cli.test.mjs. The real CLI and its
// component handlers run with a private HOME and no live infrastructure tools.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../../zasp", import.meta.url));
const canary = "test-private-material-keep-off-terminal";
const prerequisites = ["bash", "cat", "dirname", "ln", "mktemp", "python3", "rm", "sed"];
const external = ["aws", "docker", "helm", "kubectl", "skopeo", "terraform", "stack"];

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "zasp-vps-cli-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const bin = join(root, "bin");
  const config = join(root, "installation.env");
  const calls = join(root, "external-calls");
  const state = join(root, "state");
  mkdirSync(bin);
  mkdirSync(state);
  for (const command of prerequisites) {
    const found = spawnSync("bash", ["-c", 'type -P "$1"', "locate", command], { encoding: "utf8" });
    assert.equal(found.status, 0, "required test tool: " + command);
    symlinkSync(found.stdout.trim(), join(bin, command));
  }
  for (const command of external) {
    writeFileSync(join(bin, command), '#!/bin/sh\nprintf "%s\\n" "${0##*/}" >> "$CALLS"\nexit 71\n', { mode: 0o700 });
  }
  function run(args, env = {}) {
    const result = spawnSync(join(bin, "bash"), [cli, "--config", config, ...args], {
      cwd: root, encoding: "utf8", timeout: 15000,
      env: {
        PATH: bin, HOME: root, CALLS: calls, ZASP_STATE_DIR: state, ZASP_LOCAL_STACK_SCRIPT: join(bin, "stack"),
        PYTHONDONTWRITEBYTECODE: "1", ...env,
      },
    });
    assert.ifError(result.error);
    const output = result.stdout + result.stderr;
    assert.equal(output.includes(canary), false, "CLI exposed a test credential");
    return { status: result.status, output };
  }
  return {
    root, config, calls, state, run,
    writeConfig(contents) { writeFileSync(config, contents, { mode: 0o600 }); },
    noExternalCalls() { assert.equal(existsSync(calls), false, "an infrastructure command ran"); },
  };
}

function expect(result, status, message) {
  assert.equal(result.status, status, result.output);
  assert.match(result.output, message);
}

test("a fresh config explicitly selects the supported VPS provider defaults and is private", t => {
  const f = fixture(t);
  expect(f.run(["config", "init", "--dry-run"]), 0, /private vps configuration/i);
  assert.equal(existsSync(f.config), false);
  expect(f.run(["config", "init"]), 0, /vps/);
  assert.equal(statSync(f.config).mode & 0o777, 0o600);
  const settings = Object.fromEntries(readFileSync(f.config, "utf8").split("\n")
    .filter(line => line && !line.startsWith("#")).map(line => line.split("=")));
  for (const [key, value] of Object.entries({
    ZASP_PROFILE: "vps", ZASP_CONNECTOR_SECRETS_PROVIDER: "openbao", ZASP_RECOVERY_SIGNING_PROVIDER: "openbao",
    ZASP_EVIDENCE_PROVIDER: "s3", ZASP_EVIDENCE_ENCRYPTION: "provider-managed", ZASP_QUEUE_PROVIDER: "sqs",
    ZASP_AUDIT_EXPORT_QUEUE_ENCRYPTION: "provider-managed", ZASP_BACKUP_PROVIDER: "r2",
  })) assert.equal(settings[key], value, key);
  f.noExternalCalls();
});

for (const [profile, stop] of [
  ["local", /stack down/],
  ["kubernetes", /kubectl .*scale statefulset\/zasp --replicas=0/],
  ["aws", /kubectl .*scale deployment --all --replicas=0/],
]) {
  test("explicit " + profile + " installs keep their profile, provider settings and keys", t => {
    const f = fixture(t);
    expect(f.run(["--profile", profile, "config", "init"]), 0, new RegExp(profile));
    const generated = readFileSync(f.config, "utf8");
    assert.match(generated, new RegExp("^ZASP_PROFILE=" + profile + "$", "m"));
    const original = generated + "\nZASP_BACKUP_PROVIDER=s3\nSTYTCH_SECRET=" + canary + "\n";
    f.writeConfig(original);
    const key = join(f.state, "forward.seed");
    writeFileSync(key, canary, { mode: 0o600 });
    expect(f.run(["--profile", "vps", "config", "init"]), 0, /already exists/);
    expect(f.run(["--dry-run", "stop"]), 0, stop);
    assert.equal(readFileSync(f.config, "utf8"), original);
    assert.equal(readFileSync(key, "utf8"), canary);
    f.noExternalCalls();
  });
}

test("destructive commands cannot silently select an installation", t => {
  const f = fixture(t);
  const operations = [["stop"], ["restore", "archive"], ["uninstall"], ["upgrade"], ["backup"]];
  for (const op of operations) expect(f.run([...op, "--yes"]), 1, /no selected installation/i);
  f.writeConfig("ZASP_BACKUP_PROVIDER=local\nSTYTCH_SECRET=" + canary + "\n");
  for (const op of operations) expect(f.run([...op, "--yes"]), 1, /ambiguous/i);
  expect(f.run(["--profile", "local", "--dry-run", "stop"]), 0, /stack down/);
  f.writeConfig("export ZASP_PROFILE='local'\n");
  for (const op of operations) {
    expect(f.run(["--profile", "aws", ...op, "--yes"]), 1, /conflicts with the installation/i);
    expect(f.run([...op, "--yes"], { ZASP_PROFILE: "kubernetes" }), 1, /conflicts with the installation/i);
  }
  f.writeConfig("ZASP_PROFILE=vps\nZASP_PROFILE=local\n");
  expect(f.run(["--yes", "uninstall"]), 1, /conflicting ZASP_PROFILE/i);
  f.noExternalCalls();
});

test("unsupported providers fail closed before dispatching component operations", t => {
  const f = fixture(t);
  f.writeConfig("ZASP_PROFILE=vps\n");
  for (const [key, value, diagnostic] of [
    ["ZASP_SECRETS_PROVIDER", "openbao", /general platform secrets/],
    ["ZASP_RECOVERY_SIGNING_PROVIDER", "unknown", /RECOVERY_SIGNING_PROVIDER/],
    ["ZASP_EVIDENCE_PROVIDER", "r2", /version-addressed S3/],
    ["ZASP_QUEUE_PROVIDER", "cloudflare", /renewable visibility/],
    ["ZASP_QUEUE_ENCRYPTION", "provider-managed", /AUDIT_EXPORT_QUEUE_ENCRYPTION/],
    ["ZASP_BACKUP_PROVIDER", "", /backup provider/],
  ]) expect(f.run(["install", "nango"], { [key]: value }), 1, diagnostic);
  f.noExternalCalls();
});

test("untargeted VPS operations require an explicit component", t => {
  const f = fixture(t);
  f.writeConfig("ZASP_PROFILE=vps\n");
  for (const args of [["install"], ["up"], ["start"], ["stop"], ["upgrade"], ["bootstrap-admin"], ["uninstall", "--yes"]]) {
    expect(f.run(args), 1, /Select a VPS operation/i);
  }
  f.noExternalCalls();
});

test("explicit production setup uses the namespace initializer and signed first-install path", t => {
  const f = fixture(t);
  f.writeConfig("ZASP_PROFILE=vps\n");
  expect(f.run(["--dry-run", "install", "namespaces"]), 0, /vps_production.py namespaces/);
  expect(f.run(["--dry-run", "install", "application"]), 0, /release-security\/deploy.mjs install-vps-production/);
  expect(f.run(["--dry-run", "status", "application"]), 0, /vps_production.py status/);
  f.noExternalCalls();
});

test("VPS dry runs dispatch the selected component and leave local and external state untouched", t => {
  const f = fixture(t);
  const key = join(f.state, "status.token");
  writeFileSync(key, canary, { mode: 0o600 });
  const original = [
    "ZASP_PROFILE=vps", "ZASP_VPS_KUBE_CONTEXT=private-pilot", "ZASP_VPS_INSTALLATION_ID=pilot-one",
    "ZASP_VPS_CLUSTER_UID=a6938916-f27e-4d98-a821-23064f98ac31",
    "ZASP_VPS_POSTGRES_IMAGE=registry.example/postgres@sha256:" + "1".repeat(64),
    "ZASP_VPS_OPENBAO_STATUS_TOKEN_FILE=" + key, "ZASP_VPS_NANGO_SERVICE_KEY_FILE=" + key,
    "STYTCH_SECRET=" + canary, "",
  ].join("\n");
  f.writeConfig(original);
  const before = readdirSync(f.root).sort();
  for (const [args, pattern] of [
    [["install", "dependencies"], /three PVC-backed PostgreSQL clusters/],
    [["status", "dependencies"], /dry-run status/i],
    [["install", "openbao"], /openbao: dry run; install/],
    [["install", "nango"], /nango: dry run; install/],
    [["secrets", "init", "openbao"], /openbao: dry run; init/],
    [["secrets", "unseal", "openbao"], /openbao: dry run; unseal/],
    [["upgrade", "openbao"], /openbao: dry run; upgrade/],
    [["stop", "nango"], /nango: dry run; stop/],
  ]) expect(f.run(["--dry-run", ...args]), 0, pattern);
  expect(f.run(["--dry-run", "doctor"]), 1, /signed application install/i);
  expect(f.run(["--dry-run", "status"]), 0, /vps_production.py status/i);
  assert.deepEqual(readdirSync(f.root).sort(), before);
  assert.deepEqual(readdirSync(f.state), ["status.token"]);
  assert.equal(readFileSync(f.config, "utf8"), original);
  assert.equal(readFileSync(key, "utf8"), canary);
  f.noExternalCalls();
});
