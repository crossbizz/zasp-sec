import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { runBounded } from "./run.mjs";

const proofDirectory = dirname(fileURLToPath(import.meta.url));
const inventoryPath = join(proofDirectory, "adapter-license.json");
const maximumInventoryBytes = 16 * 1024;
const maximumArtifactBytes = 8 * 1024 * 1024;
const digestPattern = /^sha256:[a-f0-9]{64}$/u;

function reject() { throw new Error("Fargate adapter license audit rejected"); }

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort());
}

export function parseLicenseInventory(source) {
  if (typeof source !== "string" || Buffer.byteLength(source) === 0 || Buffer.byteLength(source) > maximumInventoryBytes) reject();
  let value;
  try { value = parseUniqueJSON(source); } catch { reject(); }
  validateInventory(value);
  return value;
}

function validateInventory(inventory) {
  if (!exactKeys(inventory, ["schema_version", "allowed_licenses", "image", "components", "boundary"]) ||
      inventory.schema_version !== 1 || !isDeepStrictEqual(inventory.allowed_licenses, ["Apache-2.0", "GPL-2.0-only"]) ||
      typeof inventory.boundary !== "string" || !inventory.boundary.includes("not relicensed") ||
      !Array.isArray(inventory.components) || inventory.components.length !== 2) reject();
  const image = inventory.image;
  if (!exactKeys(image, ["reference", "index_digest", "version", "source_commit", "platforms"]) ||
      image.reference !== CanaryImageReference || image.index_digest !== CanaryIndexDigest || image.version !== "1.36.1-1" ||
      image.source_commit !== KubernetesSourceCommit || !exactKeys(image.platforms, ["linux/amd64", "linux/arm64"])) reject();
	for (const [platform, expected] of Object.entries(ExpectedPlatforms)) {
		if (!exactKeys(image.platforms[platform], ["manifest_digest", "config_digest"]) ||
			!isDeepStrictEqual({ ...image.platforms[platform] }, { ...expected })) reject();
  }
  const expectedComponents = [
    {
      name: "Kubernetes e2e BusyBox image packaging", version: "1.36.1-1", license: "Apache-2.0",
      source_repository: "https://github.com/kubernetes/kubernetes", source_commit: KubernetesSourceCommit,
      source_path: "test/images/busybox/Dockerfile",
      source_url: `https://raw.githubusercontent.com/kubernetes/kubernetes/${KubernetesSourceCommit}/test/images/busybox/Dockerfile`,
      source_sha256: "b1a06c7718262b6de2aebb822093dbc4215f980500024ca65d2206341a7a3838",
      license_url: `https://raw.githubusercontent.com/kubernetes/kubernetes/${KubernetesSourceCommit}/LICENSE`,
      license_sha256: "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    },
    {
      name: "BusyBox runtime", version: "1.36.1", license: "GPL-2.0-only", source_repository: "https://busybox.net",
      source_commit: "release-tarball-busybox-1.36.1", source_path: "busybox-1.36.1.tar.bz2",
      source_url: "https://busybox.net/downloads/busybox-1.36.1.tar.bz2",
      source_sha256: "b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314",
      license_url: "https://raw.githubusercontent.com/mirror/busybox/1_36_1/LICENSE",
      license_sha256: "bbfc9843646d483c334664f651c208b9839626891d8f17604db2146962f43548",
    },
  ];
  const componentKeys = ["name", "version", "license", "source_repository", "source_commit", "source_path", "source_url", "source_sha256", "license_url", "license_sha256"];
  for (let index = 0; index < expectedComponents.length; index += 1) {
		if (!exactKeys(inventory.components[index], componentKeys) || !isDeepStrictEqual({ ...inventory.components[index] }, expectedComponents[index])) reject();
  }
}

export const CanaryImageReference = "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9";
export const CanaryIndexDigest = "sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9";
export const KubernetesSourceCommit = "22d90ebde235edec3541f728b37a01285bdd8b1b";
export const ExpectedPlatforms = Object.freeze({
  "linux/amd64": Object.freeze({ manifest_digest: "sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb", config_digest: "sha256:3e0d9138669908f438c06993e9a6815bbd8c05411b8e9acfc297b3c8b017c28c" }),
  "linux/arm64": Object.freeze({ manifest_digest: "sha256:55c89c6d9404d6668eb237dda92f28a99eb14e640f1c177a55cc9d738c53c303", config_digest: "sha256:6d0099de92b2a095017ed32499154f16eec2df38f0d2e9192bcf6ae7d241ac75" }),
});

export async function auditAdapterLicense(inventory, dependencies) {
  validateInventory(inventory);
  for (const name of ["inspectImage", "inspectIndex", "fingerprintUrl"]) if (typeof dependencies?.[name] !== "function") reject();
  const [image, index] = await Promise.all([
    dependencies.inspectImage(inventory.image.reference).catch(reject),
    dependencies.inspectIndex(inventory.image.reference).catch(reject),
  ]);
  if (!exactKeys(image, ["repo_digest", "architecture", "os", "image_id", "labels"]) ||
      image.repo_digest !== `registry.k8s.io/e2e-test-images/busybox@${CanaryIndexDigest}` || image.os !== "linux" ||
      !["amd64", "arm64"].includes(image.architecture) || image.image_id !== ExpectedPlatforms[`linux/${image.architecture}`].config_digest ||
      !exactKeys(image.labels, ["commit_id", "git_url", "image_version"]) || image.labels.commit_id !== KubernetesSourceCommit ||
      image.labels.git_url !== `https://github.com/kubernetes/kubernetes/tree/${KubernetesSourceCommit}/test/images/busybox` || image.labels.image_version !== "1.36.1-1") reject();
  if (!exactKeys(index, ["digest", "platforms"]) || index.digest !== CanaryIndexDigest || !Array.isArray(index.platforms) || index.platforms.length !== 2) reject();
  const sortedPlatforms = [...index.platforms].sort((left, right) => left.platform.localeCompare(right.platform));
  const expectedDescriptors = Object.entries(ExpectedPlatforms).map(([platform, value]) => ({ platform, digest: value.manifest_digest })).sort((left, right) => left.platform.localeCompare(right.platform));
  if (!isDeepStrictEqual(sortedPlatforms, expectedDescriptors)) reject();
  for (const component of inventory.components) {
    if (await dependencies.fingerprintUrl(component.source_url).catch(reject) !== component.source_sha256 ||
        await dependencies.fingerprintUrl(component.license_url).catch(reject) !== component.license_sha256) reject();
  }
  return { components: 2, artifacts: 7, prohibited: 0 };
}

async function dockerJSON(arguments_) {
  const result = await runBounded("docker", arguments_, {
    cwd: proofDirectory,
    env: { PATH: process.env.PATH ?? "" },
    outputLimit: 64 * 1024,
    timeoutMs: 30_000,
  });
  if (result.code !== 0 || result.signal !== null || result.stderr !== "" || result.stdout === "") reject();
  try { return parseUniqueJSON(result.stdout); } catch { reject(); }
}

export async function inspectLocalImage(reference) {
  if (reference !== CanaryImageReference) reject();
  const value = await dockerJSON(["image", "inspect", reference, "--format", "{{json .}}"]) ;
  if (value === null || typeof value !== "object" || Array.isArray(value) || !Array.isArray(value.RepoDigests) || value.RepoDigests.length !== 1 ||
      typeof value.Architecture !== "string" || value.Os !== "linux" || !digestPattern.test(value.Id ?? "") || value.Config === null || typeof value.Config !== "object") reject();
  return { repo_digest: value.RepoDigests[0], architecture: value.Architecture, os: value.Os, image_id: value.Id, labels: value.Config.Labels };
}

export async function inspectRemoteIndex(reference) {
  if (reference !== CanaryImageReference) reject();
  const value = await dockerJSON(["buildx", "imagetools", "inspect", reference, "--format", "{{json .Manifest}}"]) ;
  if (value === null || typeof value !== "object" || Array.isArray(value) || value.digest !== CanaryIndexDigest || !Array.isArray(value.manifests)) reject();
  const platforms = value.manifests
    .filter((entry) => entry?.platform?.os === "linux" && ["amd64", "arm64"].includes(entry?.platform?.architecture) && entry.platform.variant === undefined)
    .map((entry) => ({ platform: `${entry.platform.os}/${entry.platform.architecture}`, digest: entry.digest }));
  return { digest: value.digest, platforms };
}

export async function fingerprintURL(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);
  let reader;
  try {
    const response = await (options.fetchImpl ?? fetch)(url, { signal: controller.signal, redirect: "error", headers: { Accept: "application/octet-stream", "Accept-Encoding": "identity", "User-Agent": "zasp-fargate-license-audit/1" } });
    if (!response?.ok || response.status !== 200 || response.redirected) reject();
    reader = response.body?.getReader?.();
    if (reader === undefined) reject();
    const hash = createHash("sha256");
    let bytes = 0;
    while (true) {
      const chunk = await reader.read();
      if (chunk?.done === true) break;
      if (chunk?.done !== false || !(chunk.value instanceof Uint8Array) || chunk.value.byteLength === 0) reject();
      bytes += chunk.value.byteLength;
      if (bytes > maximumArtifactBytes) reject();
      hash.update(chunk.value);
    }
    if (bytes === 0) reject();
    return hash.digest("hex");
  } catch { reject(); }
  finally {
    clearTimeout(timer);
    try { reader?.releaseLock?.(); } catch { /* fixed failure */ }
  }
}

export async function runMain(output = process.stdout, error = process.stderr, dependencies = {}) {
  try {
    const source = await (dependencies.readInventory ?? (() => readFile(inventoryPath, "utf8")))();
    const inventory = parseLicenseInventory(source);
    const result = await auditAdapterLicense(inventory, {
      inspectImage: dependencies.inspectImage ?? inspectLocalImage,
      inspectIndex: dependencies.inspectIndex ?? inspectRemoteIndex,
      fingerprintUrl: dependencies.fingerprintUrl ?? fingerprintURL,
    });
    output.write(`EKS Fargate adapter license audit passed: components=${result.components} artifacts=${result.artifacts} prohibited=${result.prohibited}.\n`);
    return 0;
  } catch {
    error.write("EKS Fargate adapter license audit failed.\n");
    return 1;
  }
}

function parseUniqueJSON(source) {
  let index = 0;
  const whitespace = () => { while (index < source.length && /[\t\n\r ]/u.test(source[index])) index += 1; };
  const parseString = () => {
    if (source[index] !== '"') throw new SyntaxError();
    const start = index++;
    while (index < source.length) {
      if (source[index] === '"') return JSON.parse(source.slice(start, ++index));
      if (source.charCodeAt(index) <= 0x1f) throw new SyntaxError();
      if (source[index] !== "\\") { index += 1; continue; }
      index += 1;
      if ('"\\/bfnrt'.includes(source[index] ?? "")) index += 1;
      else if (source[index] === "u" && /^[a-fA-F0-9]{4}$/u.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError();
    }
    throw new SyntaxError();
  };
  const parseValue = (depth) => {
    if (depth > 16) throw new SyntaxError();
    whitespace();
    if (source[index] === "{") {
      index += 1; whitespace();
      const value = Object.create(null); const keys = new Set();
      if (source[index] === "}") { index += 1; return value; }
      while (true) {
        const key = parseString();
        if (keys.has(key) || keys.size >= 64) throw new SyntaxError();
        keys.add(key); whitespace();
        if (source[index++] !== ":") throw new SyntaxError();
        value[key] = parseValue(depth + 1); whitespace();
        if (source[index] === "}") { index += 1; return value; }
        if (source[index++] !== ",") throw new SyntaxError();
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1; whitespace(); const value = [];
      if (source[index] === "]") { index += 1; return value; }
      while (true) {
        if (value.length >= 64) throw new SyntaxError();
        value.push(parseValue(depth + 1)); whitespace();
        if (source[index] === "]") { index += 1; return value; }
        if (source[index++] !== ",") throw new SyntaxError();
        whitespace();
      }
    }
    const remaining = source.slice(index);
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(remaining);
    if (match === null) return parseString();
    index += match[0].length;
    return JSON.parse(match[0]);
  };
  const value = parseValue(0);
  whitespace();
  if (index !== source.length) throw new SyntaxError();
  return value;
}

if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await runMain();
}
