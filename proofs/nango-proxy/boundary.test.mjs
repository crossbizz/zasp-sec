import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";

import {
  createProxyWorkspace,
  removeProxyWorkspace,
  reproveProxyWorkspace,
  validateProxyMarker,
  validateProxyTemporaryPrefixEntries,
} from "./boundary.mjs";

const marker = "0123456789abcdef";

function deterministicRandom(length) {
  return Buffer.alloc(length, length);
}

async function withParent(callback) {
  const parent = await mkdtemp(join(tmpdir(), "zasp-m0-15-boundary-parent-"));
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

test("creates an exact owned workspace with one synthetic provider key and TLS SAN", async () => {
  await withParent(async (parent) => {
    const workspace = await createProxyWorkspace({
      marker,
      tempParent: parent,
      proofSourcePath: join(process.cwd(), "proofs"),
      randomSource: deterministicRandom,
      runCommand: fakeOpenSSL,
    });
    assert.match(basename(workspace.root.path), /^zasp-m0-15-0123456789abcdef-[A-Za-z0-9]{6}$/);
    assert.equal(workspace.root.canonical, await realpath(workspace.root.path));
    assert.deepEqual(await readdir(workspace.dockerConfig.path), []);
    assert.equal(await readFile(workspace.tls.san.path, "utf8"), "subjectAltName=DNS:events.1password.com\n");
    assert.equal((await lstat(workspace.tls.fixtureCertificate.path)).isFile(), true);
    assert.match(workspace.providerKey, /^eyJ[A-Za-z0-9_-]{16}\.ey[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{32}$/);
    assert.equal(workspace.runtimeInput.providerKey, workspace.providerKey);
    assert.deepEqual(await reproveProxyWorkspace(workspace), workspace);
    await removeProxyWorkspace(workspace);
    await assert.rejects(() => lstat(workspace.root.path), { code: "ENOENT" });
  });
});

test("accepts real bounded OpenSSL output and binds every generated file", async () => {
  await withParent(async (parent) => {
    const workspace = await createProxyWorkspace({ marker, tempParent: parent, proofSourcePath: join(process.cwd(), "proofs") });
    assert.deepEqual(await reproveProxyWorkspace(workspace), workspace);
    await writeFile(join(workspace.tls.directory.path, "unexpected"), "foreign");
    await assert.rejects(() => reproveProxyWorkspace(workspace));
  });
});

test("rejects TLS content, mode, Docker-config, and root identity drift", async () => {
  await withParent(async (parent) => {
    const workspace = await createProxyWorkspace({ marker, tempParent: parent, proofSourcePath: join(process.cwd(), "proofs"), randomSource: deterministicRandom, runCommand: fakeOpenSSL });
    await chmod(workspace.tls.fixtureKey.path, 0o644);
    await assert.rejects(() => reproveProxyWorkspace(workspace));
  });
  await withParent(async (parent) => {
    const workspace = await createProxyWorkspace({ marker, tempParent: parent, proofSourcePath: join(process.cwd(), "proofs"), randomSource: deterministicRandom, runCommand: fakeOpenSSL });
    await writeFile(join(workspace.dockerConfig.path, "config.json"), "{}");
    await assert.rejects(() => reproveProxyWorkspace(workspace));
  });
});

test("cleans only an exact retained candidate after creation failure", async () => {
  await withParent(async (parent) => {
    await assert.rejects(() => createProxyWorkspace({
      marker,
      tempParent: parent,
      proofSourcePath: join(process.cwd(), "proofs"),
      randomSource: deterministicRandom,
      runCommand: async () => ({ status: 1, signal: null, stdout: "", stderr: "" }),
    }));
    assert.deepEqual((await readdir(parent)).filter((name) => name.startsWith("zasp-m0-15-")), []);
  });
});

test("skips destructive cleanup after workspace replacement", async () => {
  await withParent(async (parent) => {
    const workspace = await createProxyWorkspace({ marker, tempParent: parent, proofSourcePath: join(process.cwd(), "proofs"), randomSource: deterministicRandom, runCommand: fakeOpenSSL });
    await rm(workspace.root.path, { recursive: true, force: false });
    await import("node:fs/promises").then(({ mkdir }) => mkdir(workspace.root.path, { mode: 0o700 }));
    await assert.rejects(() => removeProxyWorkspace(workspace));
    assert.equal((await lstat(workspace.root.path)).isDirectory(), true);
  });
});

test("rejects stale Proxy roots across markers and invalid marker grammar", () => {
  assert.equal(validateProxyMarker(marker), marker);
  assert.equal(validateProxyTemporaryPrefixEntries(["unrelated"]), true);
  for (const entries of [["zasp-m0-15-ffffffffffffffff-ABC123"], ["zasp-m0-15-invalid"], "bad", [1]]) {
    assert.throws(() => validateProxyTemporaryPrefixEntries(entries));
  }
  for (const value of ["", "A".repeat(16), "a".repeat(15), "a".repeat(17), 1]) {
    assert.throws(() => validateProxyMarker(value));
  }
});
