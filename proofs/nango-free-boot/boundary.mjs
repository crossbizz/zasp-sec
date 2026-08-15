import { randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readdir, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

import { validateMarker } from "./manifest.mjs";

const globalPrefix = "zasp-m0-14a-";
const suffixPattern = /^[A-Za-z0-9]{6}$/;
const passwordPattern = /^[A-Za-z0-9_-]{32}$/;
const encryptionKeyPattern = /^[A-Za-z0-9+/]{43}=$/;

const defaultIo = Object.freeze({
  chmod,
  lstat,
  makeTemp: mkdtemp,
  mkdir,
  randomSource: randomBytes,
  readdir,
  realpath,
  remove: rm,
});

export async function createOwnedWorkspace({
  marker,
  tempParent = tmpdir(),
  randomSource = defaultIo.randomSource,
  io: overrides = {},
} = {}) {
  const validatedMarker = validateMarker(marker);
  if (typeof tempParent !== "string" || !isAbsolute(tempParent) || resolve(tempParent) !== tempParent) {
    throw new TypeError("temporary parent is invalid");
  }
  if (typeof randomSource !== "function" || !isPlainObject(overrides)) {
    throw new TypeError("workspace dependency is invalid");
  }
  const io = buildIo({ ...overrides, randomSource });
  const password = exactRandom(io.randomSource, 24).toString("base64url");
  const encryptionKey = exactRandom(io.randomSource, 32).toString("base64");
  if (!passwordPattern.test(password) || !validEncryptionKey(encryptionKey)) {
    throw new TypeError("synthetic workspace secret is invalid");
  }

  await validateParent(tempParent, io);
  const prefix = `${globalPrefix}${validatedMarker}-`;
  let root;
  try {
    const candidate = await io.makeTemp(join(tempParent, prefix));
    root = await validateOwnedDirectory(candidate, tempParent, prefix, io);
    await io.chmod(candidate, 0o700);
    const securedRoot = await validateOwnedDirectory(candidate, tempParent, prefix, io);
    if (!sameDirectoryIdentityExceptMode(securedRoot, root)) {
      throw new TypeError("workspace identity changed during setup");
    }
    root = securedRoot;
    requireMode(root.mode, 0o700, "workspace");

    const dockerConfigPath = join(root.path, "docker-config");
    await io.mkdir(dockerConfigPath, { mode: 0o700 });
    await io.chmod(dockerConfigPath, 0o700);
    const dockerConfig = await validateExactChildDirectory(
      dockerConfigPath,
      root.path,
      "docker-config",
      io,
    );
    requireMode(dockerConfig.mode, 0o700, "Docker config");
    await requireEmptyDirectory(dockerConfig.path, io);

    return deepFreeze({
      marker: validatedMarker,
      prefix,
      root,
      dockerConfig,
      password,
      encryptionKey,
      runtimeInput: {
        marker: validatedMarker,
        password,
        encryptionKey,
      },
    });
  } catch (error) {
    if (root !== undefined) {
      try {
        await removeRetainedRoot(root, prefix, io);
      } catch (cleanupError) {
        throw new TypeError("workspace creation cleanup failed", { cause: cleanupError });
      }
    }
    throw error;
  }
}

export async function validateOwnedDirectory(candidate, parent, prefix, overrides = {}) {
  const io = buildIo(overrides);
  if (
    typeof candidate !== "string" || !isAbsolute(candidate) || resolve(candidate) !== candidate ||
    typeof parent !== "string" || !isAbsolute(parent) || resolve(parent) !== parent ||
    typeof prefix !== "string" || prefix.length === 0
  ) {
    throw new TypeError("owned directory input is invalid");
  }
  const name = basename(candidate);
  if (!name.startsWith(prefix) || !suffixPattern.test(name.slice(prefix.length))) {
    throw new TypeError("owned directory name is invalid");
  }
  return inspectDirectDirectory(candidate, parent, name, io);
}

export async function reproveOwnedWorkspace(workspace, overrides = {}) {
  expectWorkspace(workspace);
  const io = buildIo(overrides);
  const root = await validateOwnedDirectory(
    workspace.root.path,
    workspace.root.parent,
    workspace.prefix,
    io,
  );
  if (!sameDirectoryIdentity(root, workspace.root)) {
    throw new TypeError("workspace identity changed");
  }
  requireMode(root.mode, 0o700, "workspace");

  const dockerConfig = await validateExactChildDirectory(
    workspace.dockerConfig.path,
    workspace.root.path,
    "docker-config",
    io,
  );
  if (!sameDirectoryIdentity(dockerConfig, workspace.dockerConfig)) {
    throw new TypeError("Docker config identity changed");
  }
  requireMode(dockerConfig.mode, 0o700, "Docker config");
  await requireEmptyDirectory(dockerConfig.path, io);
  return workspace;
}

export async function removeOwnedWorkspace(workspace, overrides = {}) {
  const io = buildIo(overrides);
  try {
    await reproveOwnedWorkspace(workspace, io);
    await io.remove(workspace.root.path, { recursive: true, force: false, maxRetries: 0 });
    await requireMissing(workspace.root.path, io);
  } catch (error) {
    throw new TypeError("workspace cleanup failed", { cause: error });
  }
}

export function validateTemporaryPrefixEntries(entries) {
  if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string")) {
    throw new TypeError("temporary prefix entries are invalid");
  }
  if (entries.some((entry) => entry.startsWith(globalPrefix))) {
    throw new TypeError("stale M0-14a temporary root exists");
  }
  return true;
}

async function validateExactChildDirectory(candidate, parent, name, io) {
  if (basename(candidate) !== name || dirname(candidate) !== parent) {
    throw new TypeError("owned child path is invalid");
  }
  return inspectDirectDirectory(candidate, parent, name, io);
}

async function inspectDirectDirectory(candidate, parent, expectedName, io) {
  await validateParent(parent, io);
  const stat = await io.lstat(candidate);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError("owned directory type is invalid");
  }
  const [parentCanonical, candidateCanonical] = await Promise.all([
    io.realpath(parent),
    io.realpath(candidate),
  ]);
  if (
    dirname(candidate) !== parent || basename(candidate) !== expectedName ||
    dirname(candidateCanonical) !== parentCanonical ||
    basename(candidateCanonical) !== expectedName
  ) {
    throw new TypeError("owned directory boundary is invalid");
  }
  if (!Number.isInteger(stat.dev) || !Number.isInteger(stat.ino) || !Number.isInteger(stat.mode)) {
    throw new TypeError("owned directory identity is invalid");
  }
  return deepFreeze({
    path: candidate,
    parent,
    canonical: candidateCanonical,
    parentCanonical,
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
  });
}

async function validateParent(parent, io) {
  const stat = await io.lstat(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError("temporary parent type is invalid");
  }
  return io.realpath(parent);
}

async function requireEmptyDirectory(path, io) {
  const entries = await io.readdir(path);
  if (!Array.isArray(entries) || entries.length !== 0) {
    throw new TypeError("Docker config is not empty");
  }
}

async function removeRetainedRoot(identity, prefix, io) {
  const current = await validateOwnedDirectory(identity.path, identity.parent, prefix, io);
  if (!sameDirectoryIdentityExceptMode(current, identity)) throw new TypeError("workspace identity changed");
  await io.remove(identity.path, { recursive: true, force: false, maxRetries: 0 });
  await requireMissing(identity.path, io);
}

async function requireMissing(path, io) {
  try {
    await io.lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new TypeError("workspace still exists");
}

function expectWorkspace(value) {
  if (!isPlainObject(value) || !isPlainObject(value.root) || !isPlainObject(value.dockerConfig)) {
    throw new TypeError("workspace is invalid");
  }
  validateMarker(value.marker);
  if (
    value.prefix !== `${globalPrefix}${value.marker}-` ||
    !passwordPattern.test(value.password) || !validEncryptionKey(value.encryptionKey) ||
    !isPlainObject(value.runtimeInput) ||
    value.runtimeInput.marker !== value.marker ||
    value.runtimeInput.password !== value.password ||
    value.runtimeInput.encryptionKey !== value.encryptionKey
  ) {
    throw new TypeError("workspace value is invalid");
  }
}

function sameDirectoryIdentity(left, right) {
  return left.path === right.path && left.parent === right.parent &&
    left.canonical === right.canonical && left.parentCanonical === right.parentCanonical &&
    left.dev === right.dev && left.ino === right.ino && left.mode === right.mode;
}

function sameDirectoryIdentityExceptMode(left, right) {
  return left.path === right.path && left.parent === right.parent &&
    left.canonical === right.canonical && left.parentCanonical === right.parentCanonical &&
    left.dev === right.dev && left.ino === right.ino;
}

function exactRandom(randomSource, length) {
  const value = randomSource(length);
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new TypeError("random source result is invalid");
  }
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function validEncryptionKey(value) {
  if (typeof value !== "string" || !encryptionKeyPattern.test(value)) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.byteLength === 32 && decoded.toString("base64") === value;
}

function requireMode(mode, expected, label) {
  if ((mode & 0o777) !== expected) throw new TypeError(`${label} permissions are invalid`);
}

function buildIo(overrides) {
  if (!isPlainObject(overrides)) throw new TypeError("workspace I/O is invalid");
  const io = { ...defaultIo, ...overrides };
  for (const key of ["chmod", "lstat", "makeTemp", "mkdir", "randomSource", "readdir", "realpath", "remove"]) {
    if (typeof io[key] !== "function") throw new TypeError("workspace I/O is invalid");
  }
  return io;
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
