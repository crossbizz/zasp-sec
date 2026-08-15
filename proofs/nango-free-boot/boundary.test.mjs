import assert from "node:assert/strict";
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";

import {
  createOwnedWorkspace,
  removeOwnedWorkspace,
  reproveOwnedWorkspace,
  validateOwnedDirectory,
  validateTemporaryPrefixEntries,
} from "./boundary.mjs";

const marker = "0123456789abcdef";

function deterministicRandom(length) {
  if (length === 24) return Buffer.alloc(length, 1);
  if (length === 32) return Buffer.alloc(length, 2);
  throw new Error("unexpected random request");
}

async function withParent(callback) {
  const parent = await mkdtemp(join(tmpdir(), "zasp-m0-14a-boundary-parent-"));
  try {
    return await callback(parent);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
}

test("creates one canonical owned workspace with fresh synthetic values", async () => {
  await withParent(async (parent) => {
    const workspace = await createOwnedWorkspace({
      marker,
      tempParent: parent,
      randomSource: deterministicRandom,
    });

    assert.match(basename(workspace.root.path), /^zasp-m0-14a-0123456789abcdef-[A-Za-z0-9]{6}$/);
    assert.equal(workspace.root.canonical, await realpath(workspace.root.path));
    assert.equal(workspace.dockerConfig.path, join(workspace.root.path, "docker-config"));
    assert.deepEqual(await readdir(workspace.dockerConfig.path), []);
    assert.equal(workspace.password, Buffer.alloc(24, 1).toString("base64url"));
    assert.equal(workspace.password.length, 32);
    assert.equal(workspace.encryptionKey, Buffer.alloc(32, 2).toString("base64"));
    assert.deepEqual(workspace.runtimeInput, {
      marker,
      password: workspace.password,
      encryptionKey: workspace.encryptionKey,
    });
    assert.equal(Object.isFrozen(workspace), true);
    assert.equal(Object.isFrozen(workspace.root), true);

    await removeOwnedWorkspace(workspace);
    await assert.rejects(() => lstat(workspace.root.path), { code: "ENOENT" });
  });
});

test("re-proves unchanged directory and empty Docker config identities", async () => {
  await withParent(async (parent) => {
    const workspace = await createOwnedWorkspace({ marker, tempParent: parent, randomSource: deterministicRandom });
    const reproved = await reproveOwnedWorkspace(workspace);

    assert.deepEqual(reproved, workspace);
    await writeFile(join(workspace.dockerConfig.path, "config.json"), "{}");
    await assert.rejects(() => reproveOwnedWorkspace(workspace));
    await rm(join(workspace.dockerConfig.path, "config.json"));
    await removeOwnedWorkspace(workspace);
  });
});

test("rejects symlink, non-directory, traversal, and bare-prefix candidates", async () => {
  await withParent(async (parent) => {
    const target = await mkdtemp(join(parent, "target-"));
    const link = join(parent, `zasp-m0-14a-${marker}-ABC123`);
    const file = join(parent, `zasp-m0-14a-${marker}-DEF456`);
    await symlink(target, link);
    await writeFile(file, "not a directory");

    await assert.rejects(() => validateOwnedDirectory(link, parent, `zasp-m0-14a-${marker}-`));
    await assert.rejects(() => validateOwnedDirectory(file, parent, `zasp-m0-14a-${marker}-`));
    await assert.rejects(() => validateOwnedDirectory(parent, parent, `zasp-m0-14a-${marker}-`));
    await assert.rejects(() => validateOwnedDirectory(join(parent, "..", basename(parent), basename(link)), parent, `zasp-m0-14a-${marker}-`));
  });
});

test("cleanup skips a replaced root and never recursively removes it", async () => {
  await withParent(async (parent) => {
    const workspace = await createOwnedWorkspace({ marker, tempParent: parent, randomSource: deterministicRandom });
    const original = `${workspace.root.path}-original`;
    await import("node:fs/promises").then(({ rename }) => rename(workspace.root.path, original));
    await mkdir(workspace.root.path, { mode: 0o700 });
    await mkdir(join(workspace.root.path, "docker-config"), { mode: 0o700 });

    await assert.rejects(() => removeOwnedWorkspace(workspace));
    assert.equal((await lstat(workspace.root.path)).isDirectory(), true);
    assert.equal((await lstat(original)).isDirectory(), true);
  });
});

test("cleanup failure wins when an operation and exact removal both fail", async () => {
  await withParent(async (parent) => {
    const calls = [];
    const workspace = await createOwnedWorkspace({ marker, tempParent: parent, randomSource: deterministicRandom });
    const io = {
      lstat,
      realpath,
      readdir,
      remove: async () => {
        calls.push("remove");
        throw new Error("synthetic cleanup detail");
      },
    };

    await assert.rejects(() => removeOwnedWorkspace(workspace, io), /workspace cleanup failed/);
    assert.deepEqual(calls, ["remove"]);
  });
});

test("rejects stale temporary roots across every run marker", () => {
  assert.equal(validateTemporaryPrefixEntries(["unrelated", "other-proof"]), true);
  for (const entries of [
    [`zasp-m0-14a-${marker}-ABC123`],
    ["zasp-m0-14a-ffffffffffffffff-ZYX987"],
    ["safe", "zasp-m0-14a-not-even-valid"],
    "not-an-array",
    [1],
  ]) {
    assert.throws(() => validateTemporaryPrefixEntries(entries));
  }
});

test("rejects malformed randomness and never reads ambient secret files", async () => {
  await withParent(async (parent) => {
    for (const randomSource of [
      () => "not bytes",
      (length) => Buffer.alloc(length - 1),
      () => { throw new Error("random unavailable"); },
    ]) {
      await assert.rejects(() => createOwnedWorkspace({ marker, tempParent: parent, randomSource }));
    }
    assert.equal(await readFile(join(process.cwd(), "package.json"), "utf8").then(Boolean), true);
    assert.deepEqual((await readdir(parent)).filter((entry) => entry.startsWith("zasp-m0-14a-")), []);
  });
});

test("retains and removes an exact root when setup fails immediately after mkdtemp", async () => {
  await withParent(async (parent) => {
    await assert.rejects(() => createOwnedWorkspace({
      marker,
      tempParent: parent,
      randomSource: deterministicRandom,
      io: {
        chmod: async () => { throw new Error("synthetic chmod failure"); },
      },
    }));
    assert.deepEqual((await readdir(parent)).filter((entry) => entry.startsWith("zasp-m0-14a-")), []);
  });
});
