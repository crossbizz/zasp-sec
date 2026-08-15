import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";

export const ARTIFACT_NAME = "traces.json";
const maximumArtifactBytes = 65_536;
const ownedSuffixPattern = /^[0-9a-f]{16}$/;

const collectorConfiguration = `receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 64
    spike_limit_mib: 16
  batch:
    timeout: 100ms
    send_batch_size: 1
    send_batch_max_size: 1
exporters:
  file:
    path: /proof/output/traces.json
    format: json
    append: false
    flush_interval: 100ms
service:
  telemetry:
    logs:
      level: error
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [file]
`;

const defaultIo = Object.freeze({ lstat, open, realpath });

export function buildCollectorConfig() {
  return Buffer.from(collectorConfiguration);
}

export async function validateOwnedDirectory(candidate, parent, prefix, io = defaultIo) {
  if (
    typeof candidate !== "string" || !isAbsolute(candidate) ||
    typeof parent !== "string" || !isAbsolute(parent) ||
    typeof prefix !== "string" || prefix.length === 0
  ) {
    throw new TypeError("owned directory input is invalid");
  }
  const name = basename(candidate);
  if (!name.startsWith(prefix) || !ownedSuffixPattern.test(name.slice(prefix.length))) {
    throw new TypeError("owned directory name is invalid");
  }
  const [parentCanonical, candidateStat] = await Promise.all([
    io.realpath(parent),
    io.lstat(candidate),
  ]);
  if (!candidateStat.isDirectory() || candidateStat.isSymbolicLink()) {
    throw new TypeError("owned directory type is invalid");
  }
  const candidateCanonical = await io.realpath(candidate);
  if (
    dirname(candidateCanonical) !== parentCanonical ||
    dirname(candidate) !== parent ||
    basename(candidateCanonical) !== name
  ) {
    throw new TypeError("owned directory boundary is invalid");
  }
  return Object.freeze({
    path: candidate,
    parent: parentCanonical,
    canonical: candidateCanonical,
    dev: candidateStat.dev,
    ino: candidateStat.ino,
  });
}

export async function readStableArtifact(identity, io = defaultIo) {
  const admitted = validateIdentity(identity);
  const current = await validateOwnedDirectory(
    admitted.path,
    dirname(admitted.path),
    basename(admitted.path).slice(0, -16),
    io,
  );
  if (!sameIdentity(admitted, current)) throw new TypeError("owned directory identity changed");

  const artifactPath = join(admitted.path, ARTIFACT_NAME);
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const nonblocking = constants.O_NONBLOCK ?? 0;
  const handle = await io.open(artifactPath, constants.O_RDONLY | noFollow | nonblocking);
  let result;
  let operationError;
  try {
    const before = await handle.stat();
    validateArtifactStat(before);
    const buffer = Buffer.alloc(maximumArtifactBytes + 1);
    const read = await handle.read(buffer, 0, buffer.byteLength, 0);
    const after = await handle.stat();
    if (
      !sameArtifactStat(before, after) ||
      read.bytesRead !== before.size ||
      read.bytesRead <= 0 ||
      read.bytesRead > maximumArtifactBytes
    ) {
      throw new TypeError("artifact changed while reading");
    }
    const resultLength = read.bytesRead - (buffer[read.bytesRead - 1] === 0x0a ? 1 : 0);
    result = Buffer.from(buffer.subarray(0, resultLength));
    if (result.byteLength === 0) throw new TypeError("artifact is empty");
  } catch (error) {
    operationError = error;
  }

  let closeError;
  try {
    await handle.close();
  } catch (error) {
    closeError = error;
  }
  if (closeError !== undefined) throw new TypeError("artifact close failed", { cause: closeError });
  if (operationError !== undefined) throw operationError;
  return result;
}

function validateIdentity(value) {
  if (!isPlainObject(value)) throw new TypeError("owned directory identity is invalid");
  const keys = Object.keys(value).sort();
  const expected = ["canonical", "dev", "ino", "parent", "path"];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new TypeError("owned directory identity keys are invalid");
  }
  if (
    typeof value.path !== "string" || typeof value.parent !== "string" ||
    typeof value.canonical !== "string" || !Number.isInteger(value.dev) ||
    !Number.isInteger(value.ino)
  ) {
    throw new TypeError("owned directory identity values are invalid");
  }
  return value;
}

function validateArtifactStat(stat) {
  if (
    typeof stat?.isFile !== "function" || !stat.isFile() ||
    typeof stat.isSymbolicLink !== "function" || stat.isSymbolicLink() ||
    !Number.isInteger(stat.dev) || !Number.isInteger(stat.ino) ||
    !Number.isInteger(stat.size) || stat.size <= 0 || stat.size > maximumArtifactBytes
  ) {
    throw new TypeError("artifact type or size is invalid");
  }
}

function sameArtifactStat(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mode === right.mode && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function sameIdentity(left, right) {
  return left.path === right.path && left.parent === right.parent &&
    left.canonical === right.canonical && left.dev === right.dev && left.ino === right.ino;
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
