import { createHash, randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

import { runBounded } from "../nango-free-boot/run.mjs";

const globalPrefix = "zasp-m0-14c-";
const markerPattern = /^[0-9a-f]{16}$/;
const suffixPattern = /^[A-Za-z0-9]{6}$/;
const passwordPattern = /^[A-Za-z0-9_-]{32}$/;
const encryptionKeyPattern = /^[A-Za-z0-9+/]{43}=$/;
const providerKeyPattern = /^eyJ[A-Za-z0-9_-]{16}\.ey[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{32}$/;
const tlsEntries = ["ca.crt", "ca.key", "ca.srl", "san.cnf", "server.crt", "server.csr", "server.key"];

const defaultIo = Object.freeze({ chmod, lstat, makeTemp: mkdtemp, mkdir, readFile, readdir, realpath, remove: rm, writeFile });

export function validateApiKeyMarker(value) {
  if (typeof value !== "string" || !markerPattern.test(value)) throw new TypeError("API-key marker is invalid");
  return value;
}

export async function createApiKeyWorkspace({
  marker,
  tempParent = tmpdir(),
  proofSourcePath,
  randomSource = randomBytes,
  runCommand = defaultRunCommand,
  io: overrides = {},
} = {}) {
  const validatedMarker = validateApiKeyMarker(marker);
  if (!canonicalAbsolute(tempParent) || !canonicalAbsolute(proofSourcePath) || typeof randomSource !== "function" || typeof runCommand !== "function" || !plainObject(overrides)) {
    throw new TypeError("API-key workspace input is invalid");
  }
  const io = buildIo(overrides);
  const prefix = `${globalPrefix}${validatedMarker}-`;
  const password = exactRandom(randomSource, 24).toString("base64url");
  const encryptionKey = exactRandom(randomSource, 32).toString("base64");
  const providerKey = `eyJ${exactRandom(randomSource, 12).toString("base64url")}.ey${exactRandom(randomSource, 12).toString("base64url")}.${exactRandom(randomSource, 24).toString("base64url")}`;
  if (!passwordPattern.test(password) || !validEncryptionKey(encryptionKey) || !providerKeyPattern.test(providerKey)) {
    throw new TypeError("API-key workspace secret is invalid");
  }

  await inspectParent(tempParent, io);
  const proofSource = await inspectDirectory(proofSourcePath, dirname(proofSourcePath), basename(proofSourcePath), io);
  let candidate;
  let root;
  try {
    candidate = await io.makeTemp(join(tempParent, prefix));
    root = await inspectOwnedRoot(candidate, tempParent, prefix, io);
    await io.chmod(candidate, 0o700);
    root = await recheckIdentity(root, () => inspectOwnedRoot(candidate, tempParent, prefix, io), 0o700);

    const dockerConfigPath = join(root.path, "docker-config");
    const tlsPath = join(root.path, "tls");
    await io.mkdir(dockerConfigPath, { mode: 0o700 });
    await io.mkdir(tlsPath, { mode: 0o700 });
    await io.chmod(dockerConfigPath, 0o700);
    await io.chmod(tlsPath, 0o700);
    const dockerConfig = await inspectDirectory(dockerConfigPath, root.path, "docker-config", io);
    const tlsDirectory = await inspectDirectory(tlsPath, root.path, "tls", io);
    requireMode(dockerConfig.mode, 0o700);
    requireMode(tlsDirectory.mode, 0o700);
    await requireEmpty(dockerConfig.path, io);

    const paths = {
      caKey: join(tlsPath, "ca.key"),
      caCertificate: join(tlsPath, "ca.crt"),
      fixtureKey: join(tlsPath, "server.key"),
      fixtureRequest: join(tlsPath, "server.csr"),
      fixtureCertificate: join(tlsPath, "server.crt"),
      san: join(tlsPath, "san.cnf"),
      caSerial: join(tlsPath, "ca.srl"),
    };
    await io.writeFile(paths.san, "subjectAltName=DNS:events.1password.com\n", { mode: 0o600, flag: "wx" });
    for (const arguments_ of tlsCommands(paths, validatedMarker)) {
      const result = await runCommand("openssl", arguments_);
      if (!boundedCommandSuccess(result)) throw new TypeError("OpenSSL command failed");
    }
    await Promise.all([
      io.chmod(paths.caKey, 0o400),
      io.chmod(paths.fixtureKey, 0o400),
      io.chmod(paths.caCertificate, 0o444),
      io.chmod(paths.fixtureCertificate, 0o444),
      io.chmod(paths.fixtureRequest, 0o444),
      io.chmod(paths.caSerial, 0o444),
      io.chmod(paths.san, 0o444),
    ]);
    const [caKey, caCertificate, caSerial, fixtureCertificate, fixtureKey, fixtureRequest, san] = await Promise.all([
      inspectFile(paths.caKey, tlsPath, "ca.key", 0o400, io),
      inspectFile(paths.caCertificate, tlsPath, "ca.crt", 0o444, io),
      inspectFile(paths.caSerial, tlsPath, "ca.srl", 0o444, io),
      inspectFile(paths.fixtureCertificate, tlsPath, "server.crt", 0o444, io),
      inspectFile(paths.fixtureKey, tlsPath, "server.key", 0o400, io),
      inspectFile(paths.fixtureRequest, tlsPath, "server.csr", 0o444, io),
      inspectFile(paths.san, tlsPath, "san.cnf", 0o444, io),
    ]);
    await requireExactEntries(tlsPath, tlsEntries, io);

    return deepFreeze({
      marker: validatedMarker,
      prefix,
      root,
      dockerConfig,
      proofSource,
      tls: { directory: tlsDirectory, caKey, caCertificate, caSerial, fixtureCertificate, fixtureKey, fixtureRequest, san },
      password,
      encryptionKey,
      providerKey,
      runtimeInput: {
        marker: validatedMarker,
        password,
        encryptionKey,
        providerKey,
        workspaceRoot: root.path,
        dockerConfigPath: dockerConfig.path,
        caCertificatePath: caCertificate.path,
        fixtureCertificatePath: fixtureCertificate.path,
        fixtureKeyPath: fixtureKey.path,
        proofSourcePath: proofSource.path,
      },
    });
  } catch (error) {
    if (candidate !== undefined) {
      try {
        const retained = root ?? await inspectOwnedRoot(candidate, tempParent, prefix, io);
        const current = await inspectOwnedRoot(candidate, tempParent, prefix, io);
        if (!sameIdentityExceptMode(current, retained)) throw new TypeError("API-key workspace identity changed");
        await io.remove(candidate, { recursive: true, force: false, maxRetries: 0 });
        await requireMissing(candidate, io);
      } catch (cleanupError) {
        throw new TypeError("API-key workspace creation cleanup failed", { cause: cleanupError });
      }
    }
    throw error;
  }
}

export async function reproveApiKeyWorkspace(workspace, overrides = {}) {
  expectWorkspace(workspace);
  const io = buildIo(overrides);
  const root = await inspectOwnedRoot(workspace.root.path, workspace.root.parent, workspace.prefix, io);
  requireSame(root, workspace.root, 0o700);
  const dockerConfig = await inspectDirectory(workspace.dockerConfig.path, root.path, "docker-config", io);
  requireSame(dockerConfig, workspace.dockerConfig, 0o700);
  await requireEmpty(dockerConfig.path, io);
  const tlsDirectory = await inspectDirectory(workspace.tls.directory.path, root.path, "tls", io);
  requireSame(tlsDirectory, workspace.tls.directory, 0o700);
  const proofSource = await inspectDirectory(workspace.proofSource.path, workspace.proofSource.parent, basename(workspace.proofSource.path), io);
  requireSame(proofSource, workspace.proofSource, workspace.proofSource.mode & 0o777);
  for (const [name, mode] of [["caKey", 0o400], ["caCertificate", 0o444], ["caSerial", 0o444], ["fixtureCertificate", 0o444], ["fixtureKey", 0o400], ["fixtureRequest", 0o444], ["san", 0o444]]) {
    const expected = workspace.tls[name];
    const current = await inspectFile(expected.path, tlsDirectory.path, basename(expected.path), mode, io);
    if (!sameFileIdentity(current, expected)) throw new TypeError("API-key TLS identity changed");
  }
  await requireExactEntries(tlsDirectory.path, tlsEntries, io);
  return workspace;
}

export async function removeApiKeyWorkspace(workspace, overrides = {}) {
  const io = buildIo(overrides);
  try {
    await reproveApiKeyWorkspace(workspace, io);
    await io.remove(workspace.root.path, { recursive: true, force: false, maxRetries: 0 });
    await requireMissing(workspace.root.path, io);
  } catch (error) {
    throw new TypeError("API-key workspace cleanup failed", { cause: error });
  }
}

export function validateApiKeyTemporaryPrefixEntries(entries) {
  if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string")) throw new TypeError("API-key temporary entries are invalid");
  if (entries.some((entry) => entry.startsWith(globalPrefix))) throw new TypeError("stale API-key temporary root exists");
  return true;
}

function tlsCommands(paths, marker) {
  return [
    ["genrsa", "-out", paths.caKey, "2048"],
    ["req", "-x509", "-new", "-nodes", "-key", paths.caKey, "-sha256", "-days", "1", "-subj", `/CN=zasp-m0-14c-ca-${marker}`, "-out", paths.caCertificate],
    ["genrsa", "-out", paths.fixtureKey, "2048"],
    ["req", "-new", "-key", paths.fixtureKey, "-subj", "/CN=events.1password.com", "-out", paths.fixtureRequest],
    ["x509", "-req", "-in", paths.fixtureRequest, "-CA", paths.caCertificate, "-CAkey", paths.caKey, "-CAcreateserial", "-out", paths.fixtureCertificate, "-days", "1", "-sha256", "-extfile", paths.san],
  ];
}

async function defaultRunCommand(command, arguments_) {
  const path = process.env.PATH;
  if (typeof path !== "string" || path.length === 0) throw new TypeError("PATH is unavailable");
  return runBounded(command, arguments_, { timeoutMs: 10_000, outputLimit: 4_096, env: { PATH: path } });
}

async function inspectOwnedRoot(candidate, parent, prefix, io) {
  if (!canonicalAbsolute(candidate) || !canonicalAbsolute(parent)) throw new TypeError("API-key root path is invalid");
  const name = basename(candidate);
  if (dirname(candidate) !== parent || !name.startsWith(prefix) || !suffixPattern.test(name.slice(prefix.length))) throw new TypeError("API-key root name is invalid");
  return inspectDirectory(candidate, parent, name, io);
}

async function inspectDirectory(path, parent, name, io) {
  await inspectParent(parent, io);
  const stat = await io.lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new TypeError("API-key directory type is invalid");
  const [parentCanonical, canonical] = await Promise.all([io.realpath(parent), io.realpath(path)]);
  if (dirname(path) !== parent || basename(path) !== name || dirname(canonical) !== parentCanonical || basename(canonical) !== name) throw new TypeError("API-key directory boundary is invalid");
  return deepFreeze({ path, parent, canonical, parentCanonical, dev: integer(stat.dev), ino: integer(stat.ino), mode: integer(stat.mode) });
}

async function inspectFile(path, parent, name, mode, io) {
  const stat = await io.lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || dirname(path) !== parent || basename(path) !== name) throw new TypeError("API-key TLS file boundary is invalid");
  const canonical = await io.realpath(path);
  const parentCanonical = await io.realpath(parent);
  if (dirname(canonical) !== parentCanonical || basename(canonical) !== name) throw new TypeError("API-key TLS canonical boundary is invalid");
  requireMode(stat.mode, mode);
  const content = await io.readFile(path);
  if (!Buffer.isBuffer(content) || content.byteLength === 0 || content.byteLength > 32_768) throw new TypeError("API-key TLS file is invalid");
  return deepFreeze({ path, parent, canonical, parentCanonical, dev: integer(stat.dev), ino: integer(stat.ino), mode: integer(stat.mode), size: integer(stat.size), sha256: createHash("sha256").update(content).digest("hex") });
}

async function inspectParent(parent, io) {
  const stat = await io.lstat(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new TypeError("API-key parent is invalid");
  return io.realpath(parent);
}

async function recheckIdentity(expected, inspect, mode) {
  const current = await inspect();
  if (!sameIdentityExceptMode(current, expected)) throw new TypeError("API-key directory identity changed");
  requireMode(current.mode, mode);
  return current;
}

function requireSame(current, expected, mode) {
  if (!sameDirectoryIdentity(current, expected)) throw new TypeError("API-key directory identity changed");
  requireMode(current.mode, mode);
}

function sameDirectoryIdentity(left, right) { return sameIdentityExceptMode(left, right) && left.mode === right.mode; }
function sameIdentityExceptMode(left, right) { return left.path === right.path && left.parent === right.parent && left.canonical === right.canonical && left.parentCanonical === right.parentCanonical && left.dev === right.dev && left.ino === right.ino; }
function sameFileIdentity(left, right) { return sameDirectoryIdentity(left, right) && left.size === right.size && left.sha256 === right.sha256; }

async function requireEmpty(path, io) {
  const entries = await io.readdir(path);
  if (!Array.isArray(entries) || entries.length !== 0) throw new TypeError("Docker config is not empty");
}

async function requireExactEntries(path, expected, io) {
  const entries = await io.readdir(path);
  if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string") || !sameEntries(entries, expected)) throw new TypeError("API-key directory entries are invalid");
}

function sameEntries(left, right) {
  const actual = [...left].sort();
  const expected = [...right].sort();
  return actual.length === expected.length && actual.every((entry, index) => entry === expected[index]);
}

async function requireMissing(path, io) {
  try { await io.lstat(path); }
  catch (error) { if (error?.code === "ENOENT") return; throw error; }
  throw new TypeError("API-key workspace still exists");
}

function expectWorkspace(value) {
  if (!plainObject(value) || !plainObject(value.root) || !plainObject(value.dockerConfig) || !plainObject(value.tls) || value.prefix !== `${globalPrefix}${value.marker}-` || !providerKeyPattern.test(value.providerKey ?? "")) throw new TypeError("API-key workspace is invalid");
  validateApiKeyMarker(value.marker);
}

function boundedCommandSuccess(value) { return plainObject(value) && value.status === 0 && value.signal === null && typeof value.stdout === "string" && typeof value.stderr === "string" && value.stdout.length + value.stderr.length <= 4_096; }
function exactRandom(randomSource, length) { const value = randomSource(length); if (!(value instanceof Uint8Array) || value.byteLength !== length) throw new TypeError("random source result is invalid"); return Buffer.from(value.buffer, value.byteOffset, value.byteLength); }
function validEncryptionKey(value) { if (!encryptionKeyPattern.test(value)) return false; const decoded = Buffer.from(value, "base64"); return decoded.byteLength === 32 && decoded.toString("base64") === value; }
function requireMode(mode, expected) { if ((mode & 0o777) !== expected) throw new TypeError("API-key file mode is invalid"); }
function integer(value) { if (!Number.isInteger(value)) throw new TypeError("API-key identity is invalid"); return value; }
function canonicalAbsolute(value) { return typeof value === "string" && isAbsolute(value) && resolve(value) === value && !value.includes("\0"); }

function buildIo(overrides) {
  if (!plainObject(overrides)) throw new TypeError("API-key workspace I/O is invalid");
  const io = { ...defaultIo, ...overrides };
  for (const key of ["chmod", "lstat", "makeTemp", "mkdir", "readFile", "readdir", "realpath", "remove", "writeFile"]) if (typeof io[key] !== "function") throw new TypeError("API-key workspace I/O is invalid");
  return io;
}

function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function deepFreeze(value) { if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value; for (const child of Object.values(value)) deepFreeze(child); return Object.freeze(value); }
