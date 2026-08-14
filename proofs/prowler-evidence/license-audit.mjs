import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { LOCALSTACK_IMAGE, PROWLER_IMAGE } from "./run.mjs";

const proofDirectory = dirname(fileURLToPath(import.meta.url));
const inventoryPath = join(proofDirectory, "adapter-licenses.json");
const expectedComponents = new Set(["localstack-community", "prowler", "py-ocsf-models"]);
const expectedImages = new Set(["localstack-community", "prowler"]);
const expectedImageReferences = new Map([
  ["localstack-community", LOCALSTACK_IMAGE],
  ["prowler", PROWLER_IMAGE],
]);
const expectedImageEnvironments = new Map([
  ["localstack-community", { count: 10, sha256: "1e4fe2995cc9b2339761b690070d16ababb619a51bf41a49d5148ddac7517092" }],
  ["prowler", { count: 10, sha256: "ad772f6f73ba34935ac3d0565005ef8571e039f3505b62065378906473609f7d" }],
]);
const expectedComponentIdentities = new Map([
  ["prowler", {
    version: "5.39.0", repository: "https://github.com/prowler-cloud/prowler", tag: "5.39.0",
    tagObject: "1bb6b3cb39e9bc603e89e9c8a9023582ad6e90d5", commit: "1bb6b3cb39e9bc603e89e9c8a9023582ad6e90d5",
  }],
  ["py-ocsf-models", {
    version: "0.10.0", repository: "https://github.com/prowler-cloud/py-ocsf-models", tag: "0.10.0",
    tagObject: "8c12c2fc73e09c9fc103f5dec2e0d2762aa1a78b", commit: "8c12c2fc73e09c9fc103f5dec2e0d2762aa1a78b",
  }],
  ["localstack-community", {
    version: "4.7.0", repository: "https://github.com/localstack/localstack", tag: "v4.7.0",
    tagObject: "dff59755581d7c1832e4e9e985362b6062b88a08", commit: "82de91e30b0185a6792dd5047168b29d69bbb1f9",
  }],
]);
const allowedArtifactKinds = new Set(["license", "manifest", "supplemental-terms"]);
const sha256Pattern = /^[a-f0-9]{64}$/;
const imageIDPattern = /^sha256:[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const outputLimit = 128 * 1024;
const timeoutMs = 30_000;

function reject() {
  throw new Error("adapter license audit rejected");
}

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort());
}

function exactStrings(value, { allowEmpty = false } = {}) {
  return Array.isArray(value) && (allowEmpty || value.length > 0) &&
    value.every((item) => typeof item === "string" && item.length > 0) &&
    new Set(value).size === value.length;
}

function exactStringMap(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length > 0 &&
    Object.entries(value).every(([key, item]) => key.length > 0 && typeof item === "string" && item.length > 0);
}

function validateInventory(inventory) {
  if (!exactKeys(inventory, ["schema_version", "allowed_licenses", "images", "components"])) reject();
  if (inventory.schema_version !== 1 || !isDeepStrictEqual(inventory.allowed_licenses, ["Apache-2.0"])) reject();
  if (!Array.isArray(inventory.images) || inventory.images.length !== 2) reject();
  if (!Array.isArray(inventory.components) || inventory.components.length !== 3) reject();

  const components = new Map();
  let artifactCount = 0;
  const artifactUrls = new Set();
  for (const component of inventory.components) {
    if (!exactKeys(component, [
      "name", "version", "license", "source_repository", "source_tag", "source_tag_object",
      "source_commit", "boundary", "artifacts",
    ])) reject();
    if (!expectedComponents.has(component.name) || components.has(component.name)) reject();
    const identity = expectedComponentIdentities.get(component.name);
    if (
      component.version !== identity?.version || component.source_repository !== identity.repository ||
      component.source_tag !== identity.tag || component.source_tag_object !== identity.tagObject ||
      component.source_commit !== identity.commit ||
      component.license !== "Apache-2.0" || !inventory.allowed_licenses.includes(component.license) ||
      !commitPattern.test(component.source_tag_object) || !commitPattern.test(component.source_commit) ||
      typeof component.boundary !== "string" || component.boundary.length === 0 ||
      !Array.isArray(component.artifacts) || component.artifacts.length < 2
    ) reject();
    if (component.name !== "localstack-community" && component.source_tag_object !== component.source_commit) reject();
    const kinds = new Set();
    for (const artifact of component.artifacts) {
      if (!exactKeys(artifact, ["kind", "url", "sha256"])) reject();
      const prefix = `https://raw.githubusercontent.com/${new URL(component.source_repository).pathname.slice(1)}/${component.source_commit}/`;
      if (
        !allowedArtifactKinds.has(artifact.kind) || kinds.has(artifact.kind) ||
        typeof artifact.url !== "string" || !artifact.url.startsWith(prefix) || artifactUrls.has(artifact.url) ||
        !sha256Pattern.test(artifact.sha256)
      ) reject();
      kinds.add(artifact.kind);
      artifactUrls.add(artifact.url);
      artifactCount += 1;
    }
    if (!kinds.has("license") || !kinds.has("manifest")) reject();
    if (component.name === "localstack-community" && !kinds.has("supplemental-terms")) reject();
    components.set(component.name, component);
  }
  if (!isDeepStrictEqual(new Set(components.keys()), expectedComponents) || artifactCount !== 7) reject();

  const images = new Set();
  for (const image of inventory.images) {
    if (!exactKeys(image, [
      "component", "reference", "repo_digests", "environment_sha256", "environment_count", "entrypoint", "command",
      "user", "working_directory", "labels",
    ])) reject();
    if (!expectedImages.has(image.component) || images.has(image.component) || !components.has(image.component)) reject();
    if (
      image.reference !== expectedImageReferences.get(image.component) ||
      !exactStrings(image.repo_digests) || image.environment_sha256 !== expectedImageEnvironments.get(image.component)?.sha256 ||
      image.environment_count !== expectedImageEnvironments.get(image.component)?.count ||
      !exactStrings(image.entrypoint) ||
      image.command !== null || typeof image.user !== "string" || typeof image.working_directory !== "string" ||
      !exactStringMap(image.labels)
    ) reject();
    images.add(image.component);
  }
  if (!isDeepStrictEqual(images, expectedImages)) reject();

  const prowler = components.get("prowler");
  const prowlerImage = inventory.images.find((image) => image.component === "prowler");
  if (
    prowlerImage.labels["org.opencontainers.image.revision"] !== prowler.source_commit ||
    prowlerImage.labels["org.opencontainers.image.version"] !== prowler.version ||
    prowlerImage.labels["org.opencontainers.image.source"] !== prowler.source_repository
  ) reject();
  return artifactCount;
}

export async function loadLicenseInventory() {
  let parsed;
  try { parsed = JSON.parse(await readFile(inventoryPath, "utf8")); }
  catch { reject(); }
  validateInventory(parsed);
  return parsed;
}

export async function auditAdapterLicenses(inventory, dependencies) {
  const artifacts = validateInventory(inventory);
  if (typeof dependencies?.inspectImage !== "function" || typeof dependencies?.fingerprintUrl !== "function") reject();
  for (const image of inventory.images) {
    const inspected = await dependencies.inspectImage(image.reference).catch(reject);
    if (!exactKeys(inspected, [
      "identifier", "repo_digests", "environment_sha256", "environment_count", "entrypoint", "command", "user",
      "working_directory", "labels",
    ]) || !imageIDPattern.test(inspected.identifier)) reject();
    const expected = { ...image, identifier: inspected.identifier };
    delete expected.component;
    delete expected.reference;
    if (!isDeepStrictEqual(inspected, expected)) reject();
  }
  for (const component of inventory.components) {
    for (const artifact of component.artifacts) {
      const actual = await dependencies.fingerprintUrl(artifact.url).catch(reject);
      if (actual !== artifact.sha256) reject();
    }
  }
  return { images: inventory.images.length, components: inventory.components.length, artifacts, prohibited: 0 };
}

export function buildImageInspectArguments(reference) {
  return [
    "image", "inspect", reference, "--format",
    "[{{json .Id}},{{json .RepoDigests}},{{json .Config.Env}},{{json .Config.Entrypoint}},{{json (index .Config \"Cmd\")}},{{json (index .Config \"User\")}},{{json .Config.WorkingDir}},{{json .Config.Labels}}]",
  ];
}

export function parseImageInspectResult(result) {
  if (result?.status !== 0 || result?.signal !== null || result?.stderr !== "") reject();
  let parsed;
  try { parsed = JSON.parse(result.stdout.trim()); }
  catch { reject(); }
  if (!Array.isArray(parsed) || parsed.length !== 8) reject();
  if (!exactStrings(parsed[2])) reject();
  return {
    identifier: parsed[0], repo_digests: parsed[1],
    environment_sha256: createHash("sha256").update(JSON.stringify(parsed[2])).digest("hex"),
    environment_count: parsed[2].length, entrypoint: parsed[3],
    command: parsed[4], user: parsed[5] ?? "", working_directory: parsed[6] ?? "", labels: parsed[7],
  };
}

function runDockerInspect(reference, dockerConfig) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn("docker", buildImageInspectArguments(reference), {
      env: { PATH: process.env.PATH, DOCKER_CONFIG: dockerConfig },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let bytes = 0;
    let stderrBytes = 0;
    const stdout = [];
    let settled = false;
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    const rejectSafely = () => { if (!settled) child.kill("SIGKILL"); };
    child.once("error", rejectSafely);
    child.stdout.on("error", rejectSafely);
    child.stderr.on("error", rejectSafely);
    child.stdout.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > outputLimit) rejectSafely(); else stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      bytes += chunk.length;
      stderrBytes += chunk.length;
      if (bytes > outputLimit) rejectSafely();
    });
    child.once("close", (status, signal) => {
      settled = true;
      clearTimeout(timer);
      if (status !== 0 || signal !== null || bytes > outputLimit) { rejectPromise(new Error("inspect rejected")); return; }
      try {
        resolvePromise(parseImageInspectResult({
          status, signal, stderr: stderrBytes === 0 ? "" : "present", stdout: Buffer.concat(stdout).toString("utf8"),
        }));
      } catch { rejectPromise(new Error("inspect rejected")); }
    });
  });
}

export async function fingerprintUrl(url, options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const limit = options.limit ?? outputLimit;
  const timeoutMilliseconds = options.timeoutMilliseconds ?? timeoutMs;
  if (
    typeof fetchImpl !== "function" || !Number.isInteger(limit) || limit < 1 || limit > outputLimit ||
    !Number.isInteger(timeoutMilliseconds) || timeoutMilliseconds < 1 || timeoutMilliseconds > timeoutMs
  ) reject();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMilliseconds);
  let reader;
  try {
    const response = await fetchImpl(url, {
      signal: controller.signal,
      redirect: "error",
      headers: {
        Accept: "application/octet-stream",
        "Accept-Encoding": "identity",
        "User-Agent": "zasp-adapter-license-audit/1",
      },
    });
    const declared = response?.headers?.get?.("content-length") ?? null;
    if (!response?.ok || (declared !== null && !/^(?:0|[1-9][0-9]*)$/.test(declared))) reject();
    const declaredLength = declared === null ? undefined : Number(declared);
    if (declaredLength !== undefined && (!Number.isSafeInteger(declaredLength) || declaredLength < 1 || declaredLength > limit)) reject();
    reader = response?.body?.getReader?.();
    if (reader === undefined || typeof reader.read !== "function") reject();
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
    if (bytes === 0 || (declaredLength !== undefined && bytes !== declaredLength)) reject();
    return digest.digest("hex");
  } catch {
    controller.abort();
    try { await reader?.cancel?.(); } catch { /* rejection remains fixed */ }
    reject();
  } finally {
    clearTimeout(timer);
    try { reader?.releaseLock?.(); } catch { /* best effort */ }
  }
}

export async function runMain(output = process.stdout, error = process.stderr) {
  let dockerConfig;
  try {
    dockerConfig = await mkdtemp(join(tmpdir(), "zasp-adapter-license-"));
    const inventory = await loadLicenseInventory();
    const result = await auditAdapterLicenses(inventory, {
      inspectImage: (reference) => runDockerInspect(reference, dockerConfig),
      fingerprintUrl,
    });
    output.write(`Prowler adapter license audit passed: images=${result.images} components=${result.components} artifacts=${result.artifacts} prohibited=${result.prohibited}.\n`);
    return 0;
  } catch {
    error.write("Prowler adapter license audit failed.\n");
    return 1;
  } finally {
    if (dockerConfig !== undefined) await rm(dockerConfig, { recursive: true, force: true }).catch(() => undefined);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  process.exitCode = await runMain();
}
