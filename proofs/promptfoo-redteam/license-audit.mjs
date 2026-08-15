import { createHash } from "node:crypto";
import { lstat, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { PROMPTFOO_PINS } from "./manifest.mjs";
import { dockerEnvironment, runBounded } from "./run.mjs";

const proofDirectory = dirname(fileURLToPath(import.meta.url));
const inventoryPath = join(proofDirectory, "adapter-license.json");
const sourceCommit = "1ede17aaed940e6dff04f71d24e4ecc011809dae";
const sourceTree = "8c8043c046e3ad5d09f456dcf0db9ae4344521be";
const environmentSha256 = "19fdd905361d9fe8fe431007549a928e0e5bca43b8ce4e74d2972364235673c0";
const sha256Pattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const outputLimit = 128 * 1024;
const timeoutMs = 30_000;

function reject() { throw new Error("Promptfoo adapter license audit rejected"); }
function exactKeys(value, keys) { return value !== null && typeof value === "object" && !Array.isArray(value) && isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort()); }
function exactStrings(value) { return Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === "string" && item.length > 0) && new Set(value).size === value.length; }
function exactStringMap(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length > 0 && Object.entries(value).every(([key, item]) => key.length > 0 && typeof item === "string" && item.length > 0); }

function validateInventory(inventory) {
  if (!exactKeys(inventory, ["schema_version", "allowed_licenses", "images", "components"]) || inventory.schema_version !== 1 || !isDeepStrictEqual(inventory.allowed_licenses, ["MIT"])) reject();
  if (!Array.isArray(inventory.images) || inventory.images.length !== 1 || !Array.isArray(inventory.components) || inventory.components.length !== 1) reject();
  const component = inventory.components[0];
  if (!exactKeys(component, ["name", "version", "license", "source_repository", "source_tag", "source_tag_object", "source_commit", "source_tree", "npm_integrity", "boundary", "artifacts"])) reject();
  if (
    component.name !== "promptfoo" || component.version !== PROMPTFOO_PINS.version || component.license !== "MIT" ||
    component.source_repository !== "https://github.com/promptfoo/promptfoo" || component.source_tag !== "0.121.19" ||
    component.source_tag_object !== sourceCommit || component.source_commit !== sourceCommit || component.source_tree !== sourceTree ||
    component.npm_integrity !== PROMPTFOO_PINS.npmIntegrity || !commitPattern.test(component.source_commit) ||
    typeof component.boundary !== "string" || component.boundary.length === 0 || !Array.isArray(component.artifacts) || component.artifacts.length !== 2
  ) reject();
  const kinds = new Set();
  for (const artifact of component.artifacts) {
    if (!exactKeys(artifact, ["kind", "url", "sha256"]) || !["license", "manifest"].includes(artifact.kind) || kinds.has(artifact.kind) || !sha256Pattern.test(artifact.sha256)) reject();
    const expectedUrl = artifact.kind === "license"
      ? `https://raw.githubusercontent.com/promptfoo/promptfoo/${sourceCommit}/LICENSE`
      : `https://raw.githubusercontent.com/promptfoo/promptfoo/${sourceCommit}/package.json`;
    const expectedHash = artifact.kind === "license" ? PROMPTFOO_PINS.licenseSha256 : "bfb2bfb839147deb9320d7828b0a4cc2a43aadba95d9e3f6f69c7ce40e0cf798";
    if (artifact.url !== expectedUrl || artifact.sha256 !== expectedHash) reject();
    kinds.add(artifact.kind);
  }
  const image = inventory.images[0];
  if (!exactKeys(image, ["component", "reference", "repo_digests", "environment_sha256", "environment_count", "entrypoint", "command", "user", "working_directory", "labels"])) reject();
  if (
    image.component !== "promptfoo" || image.reference !== PROMPTFOO_PINS.image ||
    !isDeepStrictEqual(image.repo_digests, [`ghcr.io/promptfoo/promptfoo@${PROMPTFOO_PINS.image.split("@")[1]}`]) ||
    image.environment_sha256 !== environmentSha256 || image.environment_count !== 8 ||
    !isDeepStrictEqual(image.entrypoint, ["docker-entrypoint.sh"]) || !isDeepStrictEqual(image.command, ["node", "dist/src/server/index.js"]) ||
    image.user !== "promptfoo" || image.working_directory !== "/app" || !exactStringMap(image.labels) ||
    image.labels["org.opencontainers.image.revision"] !== sourceCommit || image.labels["org.opencontainers.image.licenses"] !== "MIT"
  ) reject();
  return true;
}

export async function loadLicenseInventory() {
  let value;
  try { value = JSON.parse(await readFile(inventoryPath, "utf8")); } catch { reject(); }
  validateInventory(value);
  return value;
}

export async function auditAdapterLicense(inventory, dependencies) {
  validateInventory(inventory);
  if (typeof dependencies?.inspectImage !== "function" || typeof dependencies?.fingerprintUrl !== "function") reject();
  const image = inventory.images[0];
  const inspected = await dependencies.inspectImage(image.reference).catch(reject);
  if (!exactKeys(inspected, ["identifier", "repo_digests", "environment_sha256", "environment_count", "entrypoint", "command", "user", "working_directory", "labels"]) || !/^sha256:[a-f0-9]{64}$/.test(inspected.identifier)) reject();
  const expected = { ...image, identifier: inspected.identifier };
  delete expected.component;
  delete expected.reference;
  if (!isDeepStrictEqual(inspected, expected)) reject();
  for (const artifact of inventory.components[0].artifacts) {
    if (await dependencies.fingerprintUrl(artifact.url).catch(reject) !== artifact.sha256) reject();
  }
  return { images: 1, components: 1, artifacts: 2, prohibited: 0 };
}

export function buildImageInspectArguments(reference) {
  return ["image", "inspect", reference, "--format", '[{{json .Id}},{{json .RepoDigests}},{{json .Config.Env}},{{json .Config.Entrypoint}},{{json (index .Config "Cmd")}},{{json (index .Config "User")}},{{json .Config.WorkingDir}},{{json .Config.Labels}}]'];
}

export function parseImageInspectResult(result) {
  if (!exactKeys(result, ["status", "signal", "stdout", "stderr", "overflow", "timedOut", "thrown"]) || result.status !== 0 || result.signal !== null || result.stderr !== "" || result.overflow || result.timedOut || result.thrown) reject();
  let tuple;
  try { tuple = JSON.parse(result.stdout.trim()); } catch { reject(); }
  if (!Array.isArray(tuple) || tuple.length !== 8 || !exactStrings(tuple[1]) || !exactStrings(tuple[2]) || !exactStrings(tuple[3]) || !exactStrings(tuple[4]) || typeof tuple[5] !== "string" || typeof tuple[6] !== "string" || !exactStringMap(tuple[7])) reject();
  return {
    identifier: tuple[0],
    repo_digests: tuple[1],
    environment_sha256: createHash("sha256").update(JSON.stringify(tuple[2])).digest("hex"),
    environment_count: tuple[2].length,
    entrypoint: tuple[3],
    command: tuple[4],
    user: tuple[5],
    working_directory: tuple[6],
    labels: tuple[7],
  };
}

export async function fingerprintUrl(url, options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const limit = options.limit ?? outputLimit;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMilliseconds ?? timeoutMs);
  let reader;
  try {
    const response = await fetchImpl(url, { signal: controller.signal, redirect: "error", headers: { Accept: "application/octet-stream", "Accept-Encoding": "identity", "User-Agent": "zasp-promptfoo-license-audit/1" } });
    if (!response?.ok) reject();
    reader = response.body?.getReader?.();
    if (!reader) reject();
    const digest = createHash("sha256");
    let bytes = 0;
    while (true) {
      const chunk = await reader.read();
      if (chunk?.done === true) break;
      if (chunk?.done !== false || !(chunk.value instanceof Uint8Array) || chunk.value.byteLength === 0) reject();
      bytes += chunk.value.byteLength;
      if (bytes > limit) reject();
      digest.update(chunk.value);
    }
    if (bytes === 0) reject();
    return digest.digest("hex");
  } catch { reject(); }
  finally { clearTimeout(timer); try { reader?.releaseLock?.(); } catch { /* fixed failure */ } }
}

async function inspectImage(reference, dockerConfig) {
  const result = await runBounded("docker", buildImageInspectArguments(reference), {
    timeoutMs,
    outputLimit,
    env: dockerEnvironment(process.env.PATH, dockerConfig),
  });
  return parseImageInspectResult(result);
}

export async function runMain(output = process.stdout, error = process.stderr) {
  let root;
  let identity;
  try {
    root = await mkdtemp(join(tmpdir(), "zasp-m0-16-license-"));
    const state = await lstat(root);
    identity = { dev: state.dev, ino: state.ino, canonical: await realpath(root) };
    const inventory = await loadLicenseInventory();
    const result = await auditAdapterLicense(inventory, { inspectImage: (reference) => inspectImage(reference, root), fingerprintUrl });
    output.write(`Promptfoo adapter license audit passed: images=${result.images} components=${result.components} artifacts=${result.artifacts} prohibited=${result.prohibited}.\n`);
    return 0;
  } catch {
    error.write("Promptfoo adapter license audit failed.\n");
    return 1;
  } finally {
    if (root !== undefined && identity !== undefined) {
      try {
        const state = await lstat(root);
        if (state.dev === identity.dev && state.ino === identity.ino && await realpath(root) === identity.canonical) await rm(root, { recursive: true, force: false, maxRetries: 0 });
      } catch { /* fixed boundary already selected */ }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await runMain();
