import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";

import {
  createOAuthWorkspace,
  removeOAuthWorkspace,
  reproveOAuthWorkspace,
  validateOAuthTemporaryPrefixEntries,
} from "./boundary.mjs";

const marker = "0123456789abcdef";

function deterministicRandom(length) {
  return Buffer.alloc(length, length);
}

async function withParent(callback) {
  const parent = await mkdtemp(join(tmpdir(), "zasp-m0-14b-boundary-parent-"));
  try { return await callback(parent); }
  finally { await rm(parent, { recursive: true, force: true }); }
}

async function fakeOpenSSL(command, arguments_) {
  assert.equal(command, "openssl");
  const outputIndex = arguments_.indexOf("-out");
  if (outputIndex >= 0) await writeFile(arguments_[outputIndex + 1], `generated:${arguments_.join(" ")}`);
  if (arguments_.includes("-CAcreateserial")) {
    const caIndex = arguments_.indexOf("-CA");
    await writeFile(`${arguments_[caIndex + 1].replace(/\.crt$/, "")}.srl`, "serial");
  }
  return { status: 0, signal: null, stdout: "", stderr: "" };
}

test("creates a canonical workspace with unique synthetic values and generated TLS", async () => {
  await withParent(async (parent) => {
    const commands = [];
    const workspace = await createOAuthWorkspace({
      marker,
      tempParent: parent,
      proofSourcePath: join(process.cwd(), "proofs"),
      randomSource: deterministicRandom,
      runCommand: async (...args) => { commands.push(args); return fakeOpenSSL(...args); },
    });
    assert.match(basename(workspace.root.path), /^zasp-m0-14b-0123456789abcdef-[A-Za-z0-9]{6}$/);
    assert.equal(workspace.root.canonical, await realpath(workspace.root.path));
    assert.deepEqual(await readdir(workspace.dockerConfig.path), []);
    assert.equal(commands.length, 5);
    assert.equal(commands.every(([command]) => command === "openssl"), true);
    assert.equal((await readFile(workspace.tls.san.path, "utf8")), "subjectAltName=DNS:github.com\n");
    assert.equal((await lstat(workspace.tls.caCertificate.path)).isSymbolicLink(), false);
    assert.equal((await lstat(workspace.tls.fixtureCertificate.path)).isFile(), true);
    assert.deepEqual(workspace.runtimeInput.organizationId, `org_${marker}`);
    assert.deepEqual(await reproveOAuthWorkspace(workspace), workspace);
    await removeOAuthWorkspace(workspace);
    await assert.rejects(() => lstat(workspace.root.path), { code: "ENOENT" });
  });
});

test("rejects certificate content, identity, mode, and Docker-config drift", async () => {
  await withParent(async (parent) => {
    const workspace = await createOAuthWorkspace({ marker, tempParent: parent, proofSourcePath: join(process.cwd(), "proofs"), randomSource: deterministicRandom, runCommand: fakeOpenSSL });
    await chmod(workspace.tls.caCertificate.path, 0o600);
    await writeFile(workspace.tls.caCertificate.path, "changed");
    await assert.rejects(() => reproveOAuthWorkspace(workspace));
  });
  await withParent(async (parent) => {
    const workspace = await createOAuthWorkspace({ marker, tempParent: parent, proofSourcePath: join(process.cwd(), "proofs"), randomSource: deterministicRandom, runCommand: fakeOpenSSL });
    await chmod(workspace.tls.fixtureKey.path, 0o644);
    await assert.rejects(() => reproveOAuthWorkspace(workspace));
  });
});

test("cleans an exact retained candidate when TLS generation fails", async () => {
  await withParent(async (parent) => {
    await assert.rejects(() => createOAuthWorkspace({
      marker,
      tempParent: parent,
      proofSourcePath: join(process.cwd(), "proofs"),
      randomSource: deterministicRandom,
      runCommand: async () => ({ status: 1, signal: null, stdout: "", stderr: "" }),
    }));
    assert.deepEqual((await readdir(parent)).filter((name) => name.startsWith("zasp-m0-14b-")), []);
  });
});

test("skips destructive cleanup after workspace replacement", async () => {
  await withParent(async (parent) => {
    const workspace = await createOAuthWorkspace({ marker, tempParent: parent, proofSourcePath: join(process.cwd(), "proofs"), randomSource: deterministicRandom, runCommand: fakeOpenSSL });
    await rm(workspace.root.path, { recursive: true, force: false });
    await import("node:fs/promises").then(({ mkdir }) => mkdir(workspace.root.path, { mode: 0o700 }));
    await assert.rejects(() => removeOAuthWorkspace(workspace));
    assert.equal((await lstat(workspace.root.path)).isDirectory(), true);
  });
});

test("rejects stale OAuth roots across every marker", () => {
  assert.equal(validateOAuthTemporaryPrefixEntries(["unrelated"]), true);
  for (const entries of [["zasp-m0-14b-ffffffffffffffff-ABC123"], ["zasp-m0-14b-invalid"], "bad", [1]]) {
    assert.throws(() => validateOAuthTemporaryPrefixEntries(entries));
  }
});
