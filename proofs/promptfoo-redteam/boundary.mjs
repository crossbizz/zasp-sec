import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

const globalPrefix = "zasp-m0-16-";
const markerPattern = /^[0-9a-f]{16}$/;
const suffixPattern = /^[A-Za-z0-9]{6}$/;
const defaultIo = Object.freeze({ chmod, lstat, makeTemp: mkdtemp, mkdir, open, readFile, readdir, realpath, remove: rm, writeFile });

export function validatePromptfooMarker(value) {
  if (typeof value !== "string" || !markerPattern.test(value)) throw new TypeError("Promptfoo marker is invalid");
  return value;
}

export async function createPromptfooWorkspace({
  marker,
  configuration,
  proofSourcePath,
  tempParent = tmpdir(),
  io: overrides = {},
} = {}) {
  const validatedMarker = validatePromptfooMarker(marker);
  if (
    typeof configuration !== "string" ||
    configuration.length === 0 ||
    Buffer.byteLength(configuration) > 16_384 ||
    configuration.includes("\0") ||
    !canonicalAbsolute(tempParent) ||
    !canonicalAbsolute(proofSourcePath)
  ) throw new TypeError("Promptfoo workspace input is invalid");
  const io = buildIo(overrides);
  const prefix = `${globalPrefix}${validatedMarker}-`;
  await inspectParent(tempParent, io);
  const fakeAgent = await inspectFile(join(proofSourcePath, "fake_agent.mjs"), proofSourcePath, "fake_agent.mjs", undefined, 65_536, io);
  let candidate;
  let root;
  try {
    candidate = await io.makeTemp(join(tempParent, prefix));
    root = await inspectOwnedRoot(candidate, tempParent, prefix, io);
    await io.chmod(candidate, 0o700);
    root = await inspectOwnedRoot(candidate, tempParent, prefix, io);
    requireMode(root.mode, 0o700);

    const dockerConfigPath = join(root.path, "docker-config");
    const outputPath = join(root.path, "output");
    const configurationPath = join(root.path, "promptfooconfig.yaml");
    await io.mkdir(dockerConfigPath, { mode: 0o700 });
    await io.mkdir(outputPath, { mode: 0o777 });
    await io.chmod(dockerConfigPath, 0o700);
    await io.chmod(outputPath, 0o777);
    await io.writeFile(configurationPath, configuration, { mode: 0o600, flag: "wx" });
    await io.chmod(configurationPath, 0o444);

    const dockerConfig = await inspectDirectory(dockerConfigPath, root.path, "docker-config", io);
    const output = await inspectDirectory(outputPath, root.path, "output", io);
    const configurationFile = await inspectFile(configurationPath, root.path, "promptfooconfig.yaml", 0o444, 16_384, io);
    requireMode(dockerConfig.mode, 0o700);
    requireMode(output.mode, 0o777);
    await requireEmpty(dockerConfig.path, io);
    await requireEmpty(output.path, io);
    await requireExactEntries(root.path, ["docker-config", "output", "promptfooconfig.yaml"], io);

    return deepFreeze({
      marker: validatedMarker,
      prefix,
      root,
      dockerConfig,
      output,
      configuration: configurationFile,
      fakeAgent,
      runtimeInput: {
        marker: validatedMarker,
        workspaceRoot: root.path,
        dockerConfigPath: dockerConfig.path,
        configurationPath: configurationFile.path,
        outputPath: output.path,
        fakeAgentPath: fakeAgent.path,
      },
    });
  } catch (error) {
    if (candidate !== undefined) {
      try {
        const retained = root ?? await inspectOwnedRoot(candidate, tempParent, prefix, io);
        const current = await inspectOwnedRoot(candidate, tempParent, prefix, io);
        if (!sameIdentity(current, retained, false)) throw new TypeError("Promptfoo workspace identity changed");
        await io.remove(candidate, { recursive: true, force: false, maxRetries: 0 });
        await requireMissing(candidate, io);
      } catch (cleanupError) {
        throw new TypeError("Promptfoo workspace creation cleanup failed", { cause: cleanupError });
      }
    }
    throw new TypeError("Promptfoo workspace creation failed", { cause: error });
  }
}

export async function reprovePromptfooWorkspace(workspace, overrides = {}) {
  expectWorkspace(workspace);
  const io = buildIo(overrides);
  const root = await inspectOwnedRoot(workspace.root.path, workspace.root.parent, workspace.prefix, io);
  requireSame(root, workspace.root, 0o700);
  const dockerConfig = await inspectDirectory(workspace.dockerConfig.path, root.path, "docker-config", io);
  const output = await inspectDirectory(workspace.output.path, root.path, "output", io);
  const configuration = await inspectFile(workspace.configuration.path, root.path, "promptfooconfig.yaml", 0o444, 16_384, io);
  const fakeAgent = await inspectFile(workspace.fakeAgent.path, workspace.fakeAgent.parent, "fake_agent.mjs", workspace.fakeAgent.mode & 0o777, 65_536, io);
  requireSame(dockerConfig, workspace.dockerConfig, 0o700);
  requireSame(output, workspace.output, 0o777);
  if (!sameFileIdentity(configuration, workspace.configuration) || !sameFileIdentity(fakeAgent, workspace.fakeAgent)) {
    throw new TypeError("Promptfoo workspace file identity changed");
  }
  await requireEmpty(dockerConfig.path, io);
  await requireEmpty(output.path, io);
  await requireExactEntries(root.path, ["docker-config", "output", "promptfooconfig.yaml"], io);
  return workspace;
}

export async function removePromptfooWorkspace(workspace, overrides = {}) {
  const io = buildIo(overrides);
  try {
    await reprovePromptfooWorkspace(workspace, io);
    await io.remove(workspace.root.path, { recursive: true, force: false, maxRetries: 0 });
    await requireMissing(workspace.root.path, io);
  } catch (error) {
    throw new TypeError("Promptfoo workspace cleanup failed", { cause: error });
  }
}

export async function admitPromptfooOutput(workspace, overrides = {}) {
  expectWorkspace(workspace);
  const io = buildIo(overrides);
  await reproveWorkspaceWithOutput(workspace, ["promptfoo.json"], io);
  return inspectOutputFile(join(workspace.output.path, "promptfoo.json"), workspace.output.path, io);
}

export async function removePromptfooOutput(workspace, artifact, overrides = {}) {
  expectWorkspace(workspace);
  const io = buildIo(overrides);
  try {
    await reproveWorkspaceWithOutput(workspace, ["promptfoo.json"], io);
    const current = await inspectOutputFile(join(workspace.output.path, "promptfoo.json"), workspace.output.path, io);
    if (!sameOutputIdentity(current, artifact)) throw new TypeError("Promptfoo output identity changed");
    await io.remove(current.path, { force: false, maxRetries: 0 });
    await requireMissing(current.path, io);
    await requireEmpty(workspace.output.path, io);
  } catch (error) {
    throw new TypeError("Promptfoo output cleanup failed", { cause: error });
  }
}

export function validatePromptfooTemporaryPrefixEntries(entries) {
  if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string")) throw new TypeError("Promptfoo temporary entries are invalid");
  if (entries.some((entry) => entry.startsWith(globalPrefix))) throw new TypeError("stale Promptfoo temporary root exists");
  return true;
}

async function inspectOwnedRoot(candidate, parent, prefix, io) {
  if (!canonicalAbsolute(candidate) || !canonicalAbsolute(parent)) throw new TypeError("Promptfoo root path is invalid");
  const name = basename(candidate);
  if (dirname(candidate) !== parent || !name.startsWith(prefix) || !suffixPattern.test(name.slice(prefix.length))) throw new TypeError("Promptfoo root name is invalid");
  return inspectDirectory(candidate, parent, name, io);
}

async function inspectDirectory(path, parent, name, io) {
  await inspectParent(parent, io);
  const state = await io.lstat(path);
  if (!state.isDirectory() || state.isSymbolicLink()) throw new TypeError("Promptfoo directory type is invalid");
  const [parentCanonical, canonical] = await Promise.all([io.realpath(parent), io.realpath(path)]);
  if (dirname(path) !== parent || basename(path) !== name || dirname(canonical) !== parentCanonical || basename(canonical) !== name) {
    throw new TypeError("Promptfoo directory boundary is invalid");
  }
  return deepFreeze({ path, parent, canonical, parentCanonical, dev: integer(state.dev), ino: integer(state.ino), mode: integer(state.mode) });
}

async function inspectFile(path, parent, name, mode, maximumBytes, io) {
  await inspectParent(parent, io);
  const state = await io.lstat(path);
  if (!state.isFile() || state.isSymbolicLink() || dirname(path) !== parent || basename(path) !== name) throw new TypeError("Promptfoo file type is invalid");
  const [parentCanonical, canonical, content] = await Promise.all([io.realpath(parent), io.realpath(path), io.readFile(path)]);
  if (dirname(canonical) !== parentCanonical || basename(canonical) !== name || !Buffer.isBuffer(content) || content.byteLength === 0 || content.byteLength > maximumBytes) {
    throw new TypeError("Promptfoo file boundary is invalid");
  }
  if (mode !== undefined) requireMode(state.mode, mode);
  return deepFreeze({ path, parent, canonical, parentCanonical, dev: integer(state.dev), ino: integer(state.ino), mode: integer(state.mode), size: integer(state.size), sha256: createHash("sha256").update(content).digest("hex") });
}

async function inspectOutputFile(path, parent, io) {
  const state = await io.lstat(path);
  if (!state.isFile() || state.isSymbolicLink() || dirname(path) !== parent || basename(path) !== "promptfoo.json" || state.size <= 0 || state.size > 262_144) {
    throw new TypeError("Promptfoo output type is invalid");
  }
  const [parentCanonical, canonical] = await Promise.all([io.realpath(parent), io.realpath(path)]);
  if (dirname(canonical) !== parentCanonical || basename(canonical) !== "promptfoo.json") throw new TypeError("Promptfoo output boundary is invalid");
  let handle;
  try {
    handle = await io.open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = await handle.stat();
    if (!before.isFile() || before.dev !== state.dev || before.ino !== state.ino || before.size !== state.size) throw new TypeError("Promptfoo output identity changed");
    const bytes = Buffer.alloc(before.size + 1);
    const { bytesRead } = await handle.read(bytes, 0, bytes.byteLength, 0);
    const after = await handle.stat();
    if (bytesRead !== before.size || after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size || after.mtimeMs !== before.mtimeMs) {
      throw new TypeError("Promptfoo output identity changed");
    }
    return deepFreeze({ path, parent, canonical, parentCanonical, dev: integer(before.dev), ino: integer(before.ino), mode: integer(before.mode), size: integer(before.size), mtimeMs: before.mtimeMs, sha256: createHash("sha256").update(bytes.subarray(0, bytesRead)).digest("hex") });
  } finally {
    try { await handle?.close(); } catch { /* caller reports boundary failure */ }
  }
}

async function reproveWorkspaceWithOutput(workspace, outputEntries, io) {
  const root = await inspectOwnedRoot(workspace.root.path, workspace.root.parent, workspace.prefix, io);
  requireSame(root, workspace.root, 0o700);
  const dockerConfig = await inspectDirectory(workspace.dockerConfig.path, root.path, "docker-config", io);
  const output = await inspectDirectory(workspace.output.path, root.path, "output", io);
  const configuration = await inspectFile(workspace.configuration.path, root.path, "promptfooconfig.yaml", 0o444, 16_384, io);
  const fakeAgent = await inspectFile(workspace.fakeAgent.path, workspace.fakeAgent.parent, "fake_agent.mjs", workspace.fakeAgent.mode & 0o777, 65_536, io);
  requireSame(dockerConfig, workspace.dockerConfig, 0o700);
  requireSame(output, workspace.output, 0o777);
  if (!sameFileIdentity(configuration, workspace.configuration) || !sameFileIdentity(fakeAgent, workspace.fakeAgent)) throw new TypeError("Promptfoo workspace file identity changed");
  await requireEmpty(dockerConfig.path, io);
  await requireExactEntries(output.path, outputEntries, io);
  await requireExactEntries(root.path, ["docker-config", "output", "promptfooconfig.yaml"], io);
}

async function inspectParent(parent, io) {
  const state = await io.lstat(parent);
  if (!state.isDirectory() || state.isSymbolicLink()) throw new TypeError("Promptfoo parent is invalid");
  return io.realpath(parent);
}

function requireSame(current, expected, mode) {
  if (!sameIdentity(current, expected, true)) throw new TypeError("Promptfoo directory identity changed");
  requireMode(current.mode, mode);
}

function sameIdentity(left, right, includeMode) {
  return left.path === right.path && left.parent === right.parent && left.canonical === right.canonical && left.parentCanonical === right.parentCanonical && left.dev === right.dev && left.ino === right.ino && (!includeMode || left.mode === right.mode);
}

function sameFileIdentity(left, right) {
  return sameIdentity(left, right, true) && left.size === right.size && left.sha256 === right.sha256;
}

function sameOutputIdentity(left, right) {
  return plainObject(right) && sameIdentity(left, right, true) && left.size === right.size && left.mtimeMs === right.mtimeMs && left.sha256 === right.sha256;
}

async function requireEmpty(path, io) {
  const entries = await io.readdir(path);
  if (!Array.isArray(entries) || entries.length !== 0) throw new TypeError("Promptfoo directory is not empty");
}

async function requireExactEntries(path, expected, io) {
  const entries = await io.readdir(path);
  if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string") || !sameEntries(entries, expected)) throw new TypeError("Promptfoo entries are invalid");
}

async function requireMissing(path, io) {
  try { await io.lstat(path); }
  catch (error) { if (error?.code === "ENOENT") return; throw error; }
  throw new TypeError("Promptfoo workspace still exists");
}

function expectWorkspace(value) {
  if (!plainObject(value) || !plainObject(value.root) || !plainObject(value.dockerConfig) || !plainObject(value.output) || !plainObject(value.configuration) || !plainObject(value.fakeAgent) || value.prefix !== `${globalPrefix}${value.marker}-`) {
    throw new TypeError("Promptfoo workspace is invalid");
  }
  validatePromptfooMarker(value.marker);
}

function sameEntries(left, right) { const actual = [...left].sort(); const wanted = [...right].sort(); return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]); }
function requireMode(mode, expected) { if ((mode & 0o777) !== expected) throw new TypeError("Promptfoo mode is invalid"); }
function integer(value) { if (!Number.isInteger(value)) throw new TypeError("Promptfoo identity is invalid"); return value; }
function canonicalAbsolute(value) { return typeof value === "string" && isAbsolute(value) && resolve(value) === value && !value.includes("\0"); }

function buildIo(overrides) {
  if (!plainObject(overrides)) throw new TypeError("Promptfoo I/O is invalid");
  const io = { ...defaultIo, ...overrides };
  for (const key of ["chmod", "lstat", "makeTemp", "mkdir", "open", "readFile", "readdir", "realpath", "remove", "writeFile"]) {
    if (typeof io[key] !== "function") throw new TypeError("Promptfoo I/O is invalid");
  }
  return io;
}

function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function deepFreeze(value) { if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value; for (const child of Object.values(value)) deepFreeze(child); return Object.freeze(value); }
