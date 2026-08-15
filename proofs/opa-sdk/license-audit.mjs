import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

const proofDirectory = dirname(fileURLToPath(import.meta.url));
const inventoryPath = join(proofDirectory, "adapter-license.json");
const goModPath = join(proofDirectory, "go.mod");
const goSumPath = join(proofDirectory, "go.sum");
const expectedCommit = "64a3625d33bc6ad8e7c40df03b76ce2fb3ab4d21";
const expectedModuleSum = "h1:TMm6bCyb3CEL4wjXsXn1d/kBSBbjF+5sEIyzQvbJiEw=";
const expectedGoModSum = "h1:lcuZYSlqQpXFzsA6EJCELmfR5+nNOpZYX+eo7xaIIlk=";
const expectedLicenseSha256 = "c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08";
const maximumInventoryBytes = 8_192;
const maximumResponseBytes = 128 * 1024;
const fetchTimeoutMilliseconds = 15_000;

function reject() {
  throw new Error("OPA SDK license audit rejected");
}

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort());
}

function validateInventory(inventory) {
  if (!exactKeys(inventory, ["schema_version", "allowed_licenses", "component"]) ||
      inventory.schema_version !== 1 || !isDeepStrictEqual(inventory.allowed_licenses, ["Apache-2.0"])) reject();
  const component = inventory.component;
  if (!exactKeys(component, [
    "name", "module", "version", "license", "source_repository", "source_tag",
    "source_commit", "module_sum", "go_mod_sum", "module_time", "license_url",
    "license_sha256", "boundary",
  ])) reject();
  if (component.name !== "Open Policy Agent" || component.module !== "github.com/open-policy-agent/opa" ||
      component.version !== "v1.17.0" || component.license !== "Apache-2.0" ||
      component.source_repository !== "https://github.com/open-policy-agent/opa" ||
      component.source_tag !== "v1.17.0" || component.source_commit !== expectedCommit ||
      component.module_sum !== expectedModuleSum || component.go_mod_sum !== expectedGoModSum ||
      component.module_time !== "2026-05-28T14:48:35Z" ||
      component.license_url !== `https://raw.githubusercontent.com/open-policy-agent/opa/${expectedCommit}/LICENSE` ||
      component.license_sha256 !== expectedLicenseSha256 ||
      component.boundary !== "Prepared in-process Rego query used only by the local OPA SDK proof.") reject();
  return component;
}

export function parseLicenseInventory(source) {
  if (typeof source !== "string" || Buffer.byteLength(source) === 0 || Buffer.byteLength(source) > maximumInventoryBytes) reject();
  let parsed;
  try { parsed = parseUniqueJSON(source); } catch { reject(); }
  validateInventory(parsed);
  return parsed;
}

export async function loadLicenseInventory() {
  let source;
  try { source = await readFile(inventoryPath, "utf8"); } catch { reject(); }
  return parseLicenseInventory(source);
}

function validateGoModule(goMod, goSum, component) {
  if (typeof goMod !== "string" || typeof goSum !== "string") reject();
  if (!/^module github\.com\/zasp-ai\/zasp-sec\/proofs\/opa-sdk$/m.test(goMod) ||
      !/^go 1\.25\.0$/m.test(goMod) || !/^toolchain go1\.26\.5$/m.test(goMod) ||
      (goMod.match(/^require github\.com\/open-policy-agent\/opa v1\.17\.0$/gm) ?? []).length !== 1 ||
      /^(replace|exclude|retract)\b/m.test(goMod)) reject();
  const opaLines = goSum.split("\n").filter((line) => line.startsWith("github.com/open-policy-agent/opa "));
  if (!isDeepStrictEqual(opaLines, [
    `github.com/open-policy-agent/opa ${component.version} ${component.module_sum}`,
    `github.com/open-policy-agent/opa ${component.version}/go.mod ${component.go_mod_sum}`,
  ])) reject();
}

export async function auditAdapterLicense(inventory, dependencies) {
  const component = validateInventory(inventory);
  for (const name of ["readGoMod", "readGoSum", "resolveTag", "moduleInfo", "fingerprintUrl"]) {
    if (typeof dependencies?.[name] !== "function") reject();
  }
  const [goMod, goSum] = await Promise.all([
    dependencies.readGoMod().catch(reject),
    dependencies.readGoSum().catch(reject),
  ]);
  validateGoModule(goMod, goSum, component);
  const tagCommit = await dependencies.resolveTag(component.source_repository, component.source_tag).catch(reject);
  if (tagCommit !== component.source_commit) reject();
  const metadata = await dependencies.moduleInfo(component.module, component.version).catch(reject);
  if (!exactKeys(metadata, ["Version", "Time", "Origin"]) ||
      metadata.Version !== component.version || metadata.Time !== component.module_time ||
      !exactKeys(metadata.Origin, ["VCS", "URL", "Hash", "Ref"]) || metadata.Origin.VCS !== "git" ||
      metadata.Origin.URL !== component.source_repository || metadata.Origin.Hash !== component.source_commit ||
      metadata.Origin.Ref !== `refs/tags/${component.source_tag}`) reject();
  if (await dependencies.fingerprintUrl(component.license_url).catch(reject) !== component.license_sha256) reject();
  return { components: 1, artifacts: 3, prohibited: 0 };
}

async function readBoundedURL(url, options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const limit = options.limit ?? maximumResponseBytes;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMilliseconds ?? fetchTimeoutMilliseconds);
  let reader;
  try {
    const response = await fetchImpl(url, {
      signal: controller.signal,
      redirect: "error",
      headers: { Accept: options.accept ?? "application/octet-stream", "Accept-Encoding": "identity", "User-Agent": "zasp-opa-sdk-license-audit/1" },
    });
    if (!response?.ok || response.status !== 200 || response.redirected) reject();
    reader = response.body?.getReader?.();
    if (!reader) reject();
    const chunks = [];
    let bytes = 0;
    while (true) {
      const chunk = await reader.read();
      if (chunk?.done === true) break;
      if (chunk?.done !== false || !(chunk.value instanceof Uint8Array) || chunk.value.byteLength === 0) reject();
      bytes += chunk.value.byteLength;
      if (bytes > limit) reject();
      chunks.push(chunk.value);
    }
    if (bytes === 0) reject();
    return Buffer.concat(chunks, bytes);
  } catch { reject(); }
  finally {
    clearTimeout(timer);
    try { reader?.releaseLock?.(); } catch { /* fixed failure */ }
  }
}

export async function resolveSourceTag(repository, tag) {
  if (repository !== "https://github.com/open-policy-agent/opa" || tag !== "v1.17.0") reject();
  const body = await readBoundedURL(`https://api.github.com/repos/open-policy-agent/opa/git/ref/tags/${tag}`, { accept: "application/vnd.github+json" });
  let value;
  try { value = parseUniqueJSON(new TextDecoder("utf-8", { fatal: true }).decode(body)); } catch { reject(); }
  if (!exactKeys(value, ["ref", "node_id", "url", "object"]) || value.ref !== `refs/tags/${tag}` ||
      !exactKeys(value.object, ["sha", "type", "url"]) || value.object.type !== "commit" ||
      value.object.sha !== expectedCommit) reject();
  return value.object.sha;
}

export async function fetchModuleInfo(moduleName, version) {
  if (moduleName !== "github.com/open-policy-agent/opa" || version !== "v1.17.0") reject();
  const body = await readBoundedURL(`https://proxy.golang.org/${moduleName}/@v/${version}.info`, { accept: "application/json" });
  try { return parseUniqueJSON(new TextDecoder("utf-8", { fatal: true }).decode(body)); } catch { reject(); }
}

export async function fingerprintURL(url, options = {}) {
  const body = await readBoundedURL(url, options);
  return createHash("sha256").update(body).digest("hex");
}

export async function runMain(output = process.stdout, error = process.stderr, dependencies = {}) {
  try {
    const inventory = await (dependencies.loadInventory ?? loadLicenseInventory)();
    const result = await (dependencies.audit ?? auditAdapterLicense)(inventory, {
      readGoMod: dependencies.readGoMod ?? (() => readFile(goModPath, "utf8")),
      readGoSum: dependencies.readGoSum ?? (() => readFile(goSumPath, "utf8")),
      resolveTag: dependencies.resolveTag ?? resolveSourceTag,
      moduleInfo: dependencies.moduleInfo ?? fetchModuleInfo,
      fingerprintUrl: dependencies.fingerprintUrl ?? fingerprintURL,
    });
    output.write(`OPA SDK license audit passed: components=${result.components} artifacts=${result.artifacts} prohibited=${result.prohibited}.\n`);
    return 0;
  } catch {
    error.write("OPA SDK license audit failed.\n");
    return 1;
  }
}

function parseUniqueJSON(source) {
  let index = 0;
  const whitespace = () => { while (index < source.length && /[\t\n\r ]/.test(source[index])) index += 1; };
  const string = () => {
    if (source[index] !== '"') throw new SyntaxError();
    const start = index++;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') return JSON.parse(source.slice(start, ++index));
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError();
      if (character !== "\\") { index += 1; continue; }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) index += 1;
      else if (escape === "u" && /^[a-fA-F0-9]{4}$/.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError();
    }
    throw new SyntaxError();
  };
  const value = (depth) => {
    if (depth > 12) throw new SyntaxError();
    whitespace();
    if (source[index] === "{") {
      index += 1; whitespace();
      const output = {}; const keys = new Set();
      if (source[index] === "}") { index += 1; return output; }
      while (true) {
        const key = string();
        if (keys.has(key) || keys.size >= 32) throw new SyntaxError();
        keys.add(key); whitespace();
        if (source[index++] !== ":") throw new SyntaxError();
        Object.defineProperty(output, key, { value: value(depth + 1), enumerable: true, configurable: true, writable: true }); whitespace();
        if (source[index] === "}") { index += 1; return output; }
        if (source[index++] !== ",") throw new SyntaxError();
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1; whitespace(); const output = [];
      if (source[index] === "]") { index += 1; return output; }
      while (true) {
        if (output.length >= 32) throw new SyntaxError();
        output.push(value(depth + 1)); whitespace();
        if (source[index] === "]") { index += 1; return output; }
        if (source[index++] !== ",") throw new SyntaxError();
        whitespace();
      }
    }
    if (source[index] === '"') return string();
    for (const [literal, parsed] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, index)) { index += literal.length; return parsed; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
    if (!number) throw new SyntaxError();
    index += number[0].length;
    const parsed = Number(number[0]);
    if (!Number.isFinite(parsed)) throw new SyntaxError();
    return parsed;
  };
  const output = value(0); whitespace();
  if (index !== source.length) throw new SyntaxError();
  return output;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await runMain();
