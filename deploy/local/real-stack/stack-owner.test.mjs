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
