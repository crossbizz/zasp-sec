import assert from "node:assert/strict";
import { lstat, mkdtemp, readFile, readdir, realpath, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { test } from "node:test";

import {
  admitPromptfooOutput,
  createPromptfooWorkspace,
  removePromptfooOutput,
  removePromptfooWorkspace,
  reprovePromptfooWorkspace,
  validatePromptfooMarker,
  validatePromptfooTemporaryPrefixEntries,
} from "./boundary.mjs";

const marker = "0123456789abcdef";
const configuration = "prompts:\n  - \"{{prompt}}\"\n";

async function withParent(callback) {
  const parent = await mkdtemp(join(tmpdir(), "zasp-m0-16-boundary-parent-"));
  try { return await callback(parent); }
  finally { await rm(parent, { recursive: true, force: true }); }
}

test("creates and re-proves one exact direct-child workspace", async () => {
  await withParent(async (parent) => {
    const workspace = await createPromptfooWorkspace({
      marker,
      configuration,
      proofSourcePath: join(process.cwd(), "proofs", "promptfoo-redteam"),
      tempParent: parent,
    });
    assert.match(basename(workspace.root.path), /^zasp-m0-16-0123456789abcdef-[A-Za-z0-9]{6}$/);
    assert.equal(workspace.root.canonical, await realpath(workspace.root.path));
    assert.deepEqual(await readdir(workspace.dockerConfig.path), []);
    assert.deepEqual(await readdir(workspace.output.path), []);
    assert.equal(await readFile(workspace.configuration.path, "utf8"), configuration);
    assert.equal(workspace.fakeAgent.path, join(process.cwd(), "proofs", "promptfoo-redteam", "fake_agent.mjs"));
    assert.deepEqual(await reprovePromptfooWorkspace(workspace), workspace);
    await removePromptfooWorkspace(workspace);
    await assert.rejects(lstat(workspace.root.path), { code: "ENOENT" });
  });
});

test("retains and cleans an exact candidate when setup fails after mkdtemp", async () => {
  await withParent(async (parent) => {
    const created = [];
    await assert.rejects(createPromptfooWorkspace({
      marker,
      configuration,
      proofSourcePath: join(process.cwd(), "proofs", "promptfoo-redteam"),
      tempParent: parent,
      io: {
        makeTemp: async (prefix) => {
          const path = await mkdtemp(prefix);
          created.push(path);
          return path;
        },
        mkdir: async () => { throw new Error("sensitive"); },
      },
    }), TypeError);
    assert.equal(created.length, 1);
    await assert.rejects(lstat(created[0]), { code: "ENOENT" });
  });
});

test("fails closed on file, directory, and cleanup-time identity replacement", async () => {
  await withParent(async (parent) => {
    const workspace = await createPromptfooWorkspace({ marker, configuration, proofSourcePath: join(process.cwd(), "proofs", "promptfoo-redteam"), tempParent: parent });
    const replacement = join(workspace.root.path, "replacement.yaml");
    await writeFile(replacement, `${configuration}extra: true\n`);
    await rename(replacement, workspace.configuration.path);
    await assert.rejects(reprovePromptfooWorkspace(workspace), TypeError);
  });
  await withParent(async (parent) => {
    const workspace = await createPromptfooWorkspace({ marker, configuration, proofSourcePath: join(process.cwd(), "proofs", "promptfoo-redteam"), tempParent: parent });
    const moved = `${workspace.output.path}-old`;
    await rename(workspace.output.path, moved);
    await import("node:fs/promises").then(({ mkdir }) => mkdir(workspace.output.path, { mode: 0o777 }));
    await assert.rejects(removePromptfooWorkspace(workspace), TypeError);
    assert.equal((await lstat(workspace.output.path)).isDirectory(), true);
  });
});

test("admits and removes only one exact bounded output identity", async () => {
  await withParent(async (parent) => {
    const workspace = await createPromptfooWorkspace({ marker, configuration, proofSourcePath: join(process.cwd(), "proofs", "promptfoo-redteam"), tempParent: parent });
    const outputPath = join(workspace.output.path, "promptfoo.json");
    await writeFile(outputPath, '{"exact":true}', { mode: 0o600 });
    const artifact = await admitPromptfooOutput(workspace);
    assert.equal(artifact.path, outputPath);
    assert.equal(artifact.parent, workspace.output.path);
    await removePromptfooOutput(workspace, artifact);
    assert.deepEqual(await readdir(workspace.output.path), []);
    await removePromptfooWorkspace(workspace);
  });
  await withParent(async (parent) => {
    const workspace = await createPromptfooWorkspace({ marker, configuration, proofSourcePath: join(process.cwd(), "proofs", "promptfoo-redteam"), tempParent: parent });
    const outputPath = join(workspace.output.path, "promptfoo.json");
    await writeFile(outputPath, '{"exact":true}', { mode: 0o600 });
    const artifact = await admitPromptfooOutput(workspace);
    await writeFile(outputPath, '{"changed":true}');
    await assert.rejects(removePromptfooOutput(workspace, artifact), TypeError);
    assert.equal((await lstat(outputPath)).isFile(), true);
  });
});

test("rejects stale roots across markers and malformed boundaries", () => {
  assert.equal(validatePromptfooMarker(marker), marker);
  assert.equal(validatePromptfooTemporaryPrefixEntries(["unrelated"]), true);
  for (const entries of [["zasp-m0-16-ffffffffffffffff-ABC123"], ["zasp-m0-16-invalid"], "bad", [1]]) {
    assert.throws(() => validatePromptfooTemporaryPrefixEntries(entries));
  }
  for (const value of ["", "A".repeat(16), "a".repeat(15), "a".repeat(17), 1]) {
    assert.throws(() => validatePromptfooMarker(value));
  }
});
