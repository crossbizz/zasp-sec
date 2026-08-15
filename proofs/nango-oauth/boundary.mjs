import { createHash, randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

import { runBounded } from "../nango-free-boot/run.mjs";
import { validateOAuthMarker } from "./manifest.mjs";

const globalPrefix = "zasp-m0-14b-";
const suffixPattern = /^[A-Za-z0-9]{6}$/;
const passwordPattern = /^[A-Za-z0-9_-]{32}$/;
const encryptionKeyPattern = /^[A-Za-z0-9+/]{43}=$/;

const defaultIo = Object.freeze({ chmod, lstat, makeTemp: mkdtemp, mkdir, readFile, readdir, realpath, remove: rm, writeFile });

export async function createOAuthWorkspace({
  marker,
  tempParent = tmpdir(),
  proofSourcePath,
  randomSource = randomBytes,
  runCommand = defaultRunCommand,
  io: overrides = {},
} = {}) {
  const validatedMarker = validateOAuthMarker(marker);
  if (!canonicalAbsolute(tempParent) || !canonicalAbsolute(proofSourcePath) || typeof randomSource !== "function" || typeof runCommand !== "function" || !plainObject(overrides)) {
    throw new TypeError("OAuth workspace input is invalid");
  }
  const io = buildIo(overrides);
  const prefix = `${globalPrefix}${validatedMarker}-`;
  const password = exactRandom(randomSource, 24).toString("base64url");
  const encryptionKey = exactRandom(randomSource, 32).toString("base64");
  const clientId = `client_${exactRandom(randomSource, 12).toString("hex")}`;
  const clientSecret = `secret_${exactRandom(randomSource, 24).toString("base64url")}`;
  const code = `code_${exactRandom(randomSource, 24).toString("base64url")}`;
  const accessToken = `token_${exactRandom(randomSource, 24).toString("base64url")}`;
  if (!passwordPattern.test(password) || !validEncryptionKey(encryptionKey)) throw new TypeError("OAuth workspace secret is invalid");

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
    };
    await io.writeFile(paths.san, "subjectAltName=DNS:github.com\n", { mode: 0o600, flag: "wx" });
    const commands = tlsCommands(paths, validatedMarker);
    for (const arguments_ of commands) {
      const result = await runCommand("openssl", arguments_);
      if (!exactQuietSuccess(result)) throw new TypeError("OpenSSL command failed");
    }
    await Promise.all([
      io.chmod(paths.caKey, 0o400),
      io.chmod(paths.fixtureKey, 0o400),
      io.chmod(paths.caCertificate, 0o444),
      io.chmod(paths.fixtureCertificate, 0o444),
      io.chmod(paths.san, 0o444),
    ]);
    const [caCertificate, fixtureCertificate, fixtureKey, san] = await Promise.all([
      inspectFile(paths.caCertificate, tlsPath, "ca.crt", 0o444, io),
      inspectFile(paths.fixtureCertificate, tlsPath, "server.crt", 0o444, io),
      inspectFile(paths.fixtureKey, tlsPath, "server.key", 0o400, io),
      inspectFile(paths.san, tlsPath, "san.cnf", 0o444, io),
    ]);

    return deepFreeze({
      marker: validatedMarker,
      prefix,
      root,
      dockerConfig,
      proofSource,
      tls: { directory: tlsDirectory, caCertificate, fixtureCertificate, fixtureKey, san },
      password,
      encryptionKey,
      clientId,
      clientSecret,
      code,
      accessToken,
      runtimeInput: {
        marker: validatedMarker,
        password,
        encryptionKey,
        clientId,
        clientSecret,
        code,
        accessToken,
        organizationId: `org_${validatedMarker}`,
        endUserId: `user_${validatedMarker}`,
        integrationKey: `zasp-m0-14b-${validatedMarker}-github`,
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
        if (!sameIdentityExceptMode(current, retained)) throw new TypeError("OAuth workspace identity changed");
        await io.remove(candidate, { recursive: true, force: false, maxRetries: 0 });
        await requireMissing(candidate, io);
      } catch (cleanupError) {
        throw new TypeError("OAuth workspace creation cleanup failed", { cause: cleanupError });
      }
    }
    throw error;
  }
}

export async function reproveOAuthWorkspace(workspace, overrides = {}) {
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
  for (const [name, mode] of [["caCertificate", 0o444], ["fixtureCertificate", 0o444], ["fixtureKey", 0o400], ["san", 0o444]]) {
    const expected = workspace.tls[name];
    const current = await inspectFile(expected.path, tlsDirectory.path, basename(expected.path), mode, io);
    if (!sameFileIdentity(current, expected)) throw new TypeError("OAuth TLS identity changed");
  }
  return workspace;
}

export async function removeOAuthWorkspace(workspace, overrides = {}) {
  const io = buildIo(overrides);
  try {
    await reproveOAuthWorkspace(workspace, io);
    await io.remove(workspace.root.path, { recursive: true, force: false, maxRetries: 0 });
    await requireMissing(workspace.root.path, io);
  } catch (error) {
    throw new TypeError("OAuth workspace cleanup failed", { cause: error });
  }
}

export function validateOAuthTemporaryPrefixEntries(entries) {
  if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string")) throw new TypeError("OAuth temporary entries are invalid");
  if (entries.some((entry) => entry.startsWith(globalPrefix))) throw new TypeError("stale OAuth temporary root exists");
  return true;
}

function tlsCommands(paths, marker) {
  return [
    ["genrsa", "-out", paths.caKey, "2048"],
    ["req", "-x509", "-new", "-nodes", "-key", paths.caKey, "-sha256", "-days", "1", "-subj", `/CN=zasp-m0-14b-ca-${marker}`, "-out", paths.caCertificate],
    ["genrsa", "-out", paths.fixtureKey, "2048"],
    ["req", "-new", "-key", paths.fixtureKey, "-subj", "/CN=github.com", "-out", paths.fixtureRequest],
    ["x509", "-req", "-in", paths.fixtureRequest, "-CA", paths.caCertificate, "-CAkey", paths.caKey, "-CAcreateserial", "-out", paths.fixtureCertificate, "-days", "1", "-sha256", "-extfile", paths.san],
  ];
}

async function defaultRunCommand(command, arguments_) {
  const path = process.env.PATH;
  if (typeof path !== "string" || path.length === 0) throw new TypeError("PATH is unavailable");
  return runBounded(command, arguments_, { timeoutMs: 10_000, outputLimit: 4_096, env: { PATH: path } });
}

async function inspectOwnedRoot(candidate, parent, prefix, io) {
  if (!canonicalAbsolute(candidate) || !canonicalAbsolute(parent)) throw new TypeError("OAuth root path is invalid");
  const name = basename(candidate);
  if (dirname(candidate) !== parent || !name.startsWith(prefix) || !suffixPattern.test(name.slice(prefix.length))) throw new TypeError("OAuth root name is invalid");
  return inspectDirectory(candidate, parent, name, io);
}

async function inspectDirectory(path, parent, name, io) {
  await inspectParent(parent, io);
  const stat = await io.lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new TypeError("OAuth directory type is invalid");
  const [parentCanonical, canonical] = await Promise.all([io.realpath(parent), io.realpath(path)]);
  if (dirname(path) !== parent || basename(path) !== name || dirname(canonical) !== parentCanonical || basename(canonical) !== name) throw new TypeError("OAuth directory boundary is invalid");
  return deepFreeze({ path, parent, canonical, parentCanonical, dev: integer(stat.dev), ino: integer(stat.ino), mode: integer(stat.mode) });
}

async function inspectFile(path, parent, name, mode, io) {
  const stat = await io.lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || dirname(path) !== parent || basename(path) !== name) throw new TypeError("OAuth TLS file boundary is invalid");
  const canonical = await io.realpath(path);
  const parentCanonical = await io.realpath(parent);
  if (dirname(canonical) !== parentCanonical || basename(canonical) !== name) throw new TypeError("OAuth TLS file canonical boundary is invalid");
  requireMode(stat.mode, mode);
  const content = await io.readFile(path);
  if (!Buffer.isBuffer(content) || content.byteLength === 0 || content.byteLength > 32_768) throw new TypeError("OAuth TLS file is invalid");
  return deepFreeze({ path, parent, canonical, parentCanonical, dev: integer(stat.dev), ino: integer(stat.ino), mode: integer(stat.mode), size: integer(stat.size), sha256: createHash("sha256").update(content).digest("hex") });
}

async function inspectParent(parent, io) {
  const stat = await io.lstat(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new TypeError("OAuth parent is invalid");
  return io.realpath(parent);
}

async function recheckIdentity(expected, inspect, mode) {
  const current = await inspect();
  if (!sameIdentityExceptMode(current, expected)) throw new TypeError("OAuth directory identity changed");
  requireMode(current.mode, mode);
  return current;
}

function requireSame(current, expected, mode) {
  if (!sameDirectoryIdentity(current, expected)) throw new TypeError("OAuth directory identity changed");
  requireMode(current.mode, mode);
}

function sameDirectoryIdentity(left, right) {
  return sameIdentityExceptMode(left, right) && left.mode === right.mode;
}

function sameIdentityExceptMode(left, right) {
  return left.path === right.path && left.parent === right.parent && left.canonical === right.canonical && left.parentCanonical === right.parentCanonical && left.dev === right.dev && left.ino === right.ino;
}

function sameFileIdentity(left, right) {
  return sameDirectoryIdentity(left, right) && left.size === right.size && left.sha256 === right.sha256;
}

async function requireEmpty(path, io) {
  const entries = await io.readdir(path);
  if (!Array.isArray(entries) || entries.length !== 0) throw new TypeError("Docker config is not empty");
}

async function requireMissing(path, io) {
  try { await io.lstat(path); }
  catch (error) { if (error?.code === "ENOENT") return; throw error; }
  throw new TypeError("OAuth workspace still exists");
}

function expectWorkspace(value) {
  if (!plainObject(value) || !plainObject(value.root) || !plainObject(value.dockerConfig) || !plainObject(value.tls) || value.prefix !== `${globalPrefix}${value.marker}-`) throw new TypeError("OAuth workspace is invalid");
  validateOAuthMarker(value.marker);
}

function exactQuietSuccess(value) {
  return plainObject(value) && value.status === 0 && value.signal === null && value.stdout === "" && value.stderr === "";
}

function exactRandom(randomSource, length) {
  const value = randomSource(length);
  if (!(value instanceof Uint8Array) || value.byteLength !== length) throw new TypeError("random source result is invalid");
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function validEncryptionKey(value) {
  if (!encryptionKeyPattern.test(value)) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.byteLength === 32 && decoded.toString("base64") === value;
}

function requireMode(mode, expected) {
  if ((mode & 0o777) !== expected) throw new TypeError("OAuth file mode is invalid");
}

function integer(value) {
  if (!Number.isInteger(value)) throw new TypeError("OAuth identity is invalid");
  return value;
}

function canonicalAbsolute(value) {
  return typeof value === "string" && isAbsolute(value) && resolve(value) === value && !value.includes("\0");
}

function buildIo(overrides) {
  if (!plainObject(overrides)) throw new TypeError("OAuth workspace I/O is invalid");
  const io = { ...defaultIo, ...overrides };
  for (const key of ["chmod", "lstat", "makeTemp", "mkdir", "readFile", "readdir", "realpath", "remove", "writeFile"]) {
    if (typeof io[key] !== "function") throw new TypeError("OAuth workspace I/O is invalid");
  }
  return io;
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
