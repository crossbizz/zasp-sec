// stack.sh refuses a second state directory: the containers and the secrets
// inside them are shared by the machine, so a command run with another state
// directory would replace the first stack's secrets.
//
//   node --test deploy/local/real-stack/stack-owner.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const script = join(dirname(fileURLToPath(import.meta.url)), "stack.sh");

function sandbox(mount = "") {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "zasp-stack-owner-")));
  const bin = join(root, "bin");
  mkdirSync(bin);
  // A docker that reports the given Neo4j mount and does nothing else.
  writeFileSync(join(bin, "docker"), `#!/bin/sh\n[ "$1" = inspect ] && [ -n "${mount}" ] && { echo "${mount}"; exit 0; }\nexit 1\n`);
  chmodSync(join(bin, "docker"), 0o755);
  const run = (state, extra = {}) => spawnSync("bash", [script, "bootstrap", "Example", "example.test", "admin@example.test"], {
    encoding: "utf8",
    env: { PATH: `${bin}:${process.env.PATH}`, HOME: root, ZASP_REAL_STACK_STATE: join(root, state), ZASP_REAL_STACK_OWNER_FILE: join(root, "owner"), ...extra },
  });
  return { root, run, owner: () => (existsSync(join(root, "owner")) ? readFileSync(join(root, "owner"), "utf8").trim() : "") };
}
// 'bootstrap' claims the machine and then stops at the missing identity
// provider credentials, before it touches anything.
const claimed = result => result.status !== 0 && /STYTCH_PROJECT_ID is required/.test(result.stderr);
const refused = result => result.status !== 0 && /belongs to the state directory/.test(result.stderr) && !/STYTCH/.test(result.stderr);

test("the first state directory claims the machine and keeps it", () => {
  const box = sandbox();
  try {
    assert.ok(claimed(box.run("a")));
    assert.equal(box.owner(), join(box.root, "a"));
    assert.ok(claimed(box.run("a")));
  } finally { rmSync(box.root, { recursive: true, force: true }); }
});

test("a second state directory is refused while the first exists", () => {
  const box = sandbox();
  try {
    assert.ok(claimed(box.run("a")));
    mkdirSync(join(box.root, "a", "secrets"));
    const second = box.run("b");
    assert.ok(refused(second), second.stderr);
    assert.match(second.stderr, new RegExp(join(box.root, "a")));
    assert.equal(box.owner(), join(box.root, "a"));
    assert.equal(existsSync(join(box.root, "b", "secrets")), false);
  } finally { rmSync(box.root, { recursive: true, force: true }); }
});

test("taking over is explicit, and a holder whose state is gone holds nothing", () => {
  const box = sandbox();
  try {
    assert.ok(claimed(box.run("a")));
    mkdirSync(join(box.root, "a", "secrets"));
    assert.ok(claimed(box.run("b", { ZASP_REAL_STACK_TAKE_OVER: "1" })));
    assert.equal(box.owner(), join(box.root, "b"));
    // b never created secrets: c may claim.
    assert.ok(claimed(box.run("c")));
    assert.equal(box.owner(), join(box.root, "c"));
  } finally { rmSync(box.root, { recursive: true, force: true }); }
});

test("without a record the holder is the state that created the Neo4j container", () => {
  const box = sandbox("$HOME/a/tls/neo4j");
  try {
    mkdirSync(join(box.root, "a", "secrets"), { recursive: true });
    assert.ok(refused(box.run("b")));
    assert.equal(box.owner(), "");
    assert.ok(claimed(box.run("a")));
    assert.equal(box.owner(), join(box.root, "a"));
  } finally { rmSync(box.root, { recursive: true, force: true }); }
});

// 'reset' deletes the state directory and everything in the containers. The
// stand-ins: a docker that accepts every command and records it, and a curl
// that finds nothing listening.
function resetSandbox() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "zasp-stack-reset-")));
  const bin = join(root, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, "docker"), `#!/bin/sh\necho "$*" >> "${root}/docker.log"\n[ "$1" = inspect ] && exit 1\nexit 0\n`);
  writeFileSync(join(bin, "curl"), "#!/bin/sh\nexit 7\n");
  chmodSync(join(bin, "docker"), 0o755);
  chmodSync(join(bin, "curl"), 0o755);
  const run = (state, ...args) => spawnSync("bash", [script, "reset", ...args], {
    encoding: "utf8",
    env: { PATH: `${bin}:${process.env.PATH}`, HOME: root, ZASP_REAL_STACK_STATE: join(root, state), ZASP_REAL_STACK_OWNER_FILE: join(root, "owner") },
  });
  const docker = () => (existsSync(join(root, "docker.log")) ? readFileSync(join(root, "docker.log"), "utf8") : "");
  return { root, run, docker };
}

test("reset needs --yes and deletes nothing without it", () => {
  const box = resetSandbox();
  try {
    mkdirSync(join(box.root, "a", "secrets"), { recursive: true });
    const result = box.run("a");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /reset --yes/);
    assert.ok(existsSync(join(box.root, "a", "secrets")));
    assert.equal(box.docker(), "");
  } finally { rmSync(box.root, { recursive: true, force: true }); }
});

test("reset removes the containers, the service volumes and the state, and keeps provider.env", () => {
  const box = resetSandbox();
  try {
    mkdirSync(join(box.root, "a", "secrets"), { recursive: true });
    writeFileSync(join(box.root, "a", "provider.env"), "STYTCH_PROJECT_ID=project-test-kept\n");
    writeFileSync(join(box.root, "a", "organization.env"), "ZASP_STYTCH_ORGANIZATION_ID=organization-test-gone\n");
    writeFileSync(join(box.root, "owner"), `${join(box.root, "a")}\n`);
    const result = box.run("a", "--yes");
    assert.equal(result.status, 0, result.stderr);
    assert.match(box.docker(), /^rm -f -v zasp-real-stack-pg zasp-real-stack-neo4j zasp-real-stack-opensearch zasp-real-stack-localstack$/m);
    assert.match(box.docker(), /^compose -f .*temporal-openfga\.compose\.yaml down --volumes --remove-orphans$/m);
    assert.equal(readFileSync(join(box.root, "a", "provider.env"), "utf8"), "STYTCH_PROJECT_ID=project-test-kept\n");
    assert.equal(existsSync(join(box.root, "a", "secrets")), false);
    assert.equal(existsSync(join(box.root, "a", "organization.env")), false);
    assert.equal(existsSync(join(box.root, "owner")), false);
  } finally { rmSync(box.root, { recursive: true, force: true }); }
});

test("reset refuses a state directory that does not hold the machine", () => {
  const box = resetSandbox();
  try {
    mkdirSync(join(box.root, "a", "secrets"), { recursive: true });
    writeFileSync(join(box.root, "owner"), `${join(box.root, "a")}\n`);
    const result = box.run("b", "--yes");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /belongs to the state directory/);
    assert.ok(existsSync(join(box.root, "a", "secrets")));
    assert.doesNotMatch(box.docker(), /rm -f|down/);
  } finally { rmSync(box.root, { recursive: true, force: true }); }
});
