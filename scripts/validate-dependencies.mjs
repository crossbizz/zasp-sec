import { constants } from "node:fs";
import { open, readdir } from "node:fs/promises";
import { basename, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { JSON_SCHEMA, load } from "js-yaml";

export const successLine = "Dependency lock valid";
export const failureLine = "Dependency lock rejected";

const lockPath = "build/dependencies.lock.yaml";
const packageLockPath = "package-lock.json";
const lockByteLimit = 64 * 1024;
const manifestByteLimit = 256 * 1024;
const packageLockByteLimit = 2 * 1024 * 1024;
const productRoots = ["apps", "cmd", "services", "workers"];
const manifestNames = new Set(["go.mod", "package.json", "pyproject.toml"]);
const ignoredProductDirectories = new Set([
  "__pycache__",
  ".next",
  ".turbo",
  ".venv",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "venv",
  "vendor",
]);
const discoveryEntryLimit = 4096;
const internalHealthModule = "github.com/zasp-ai/zasp-sec/services/health";
const internalHealthVersion = "v0.0.0";
const internalHealthConsumer = "services/platform/go.mod";
const internalHealthTarget = "services/health/go.mod";
const internalHealthReplacement = `replace ${internalHealthModule} => ../health`;

const approvedOwners = ["identity-platform", "platform-data", "web-platform"];
const allowedLicenses = ["Apache-2.0", "ISC", "MIT"];
const prohibitedLicenses = [
  "AGPL-3.0-only",
  "GPL-2.0-only",
  "GPL-3.0-only",
  "LGPL-2.1-only",
  "LGPL-3.0-only",
  "SSPL-1.0",
];
const requiredManifests = [
  { ecosystem: "npm", path: "apps/web/package.json" },
  { ecosystem: "go", path: "cmd/agentsecctl/go.mod" },
  { ecosystem: "npm", path: "package.json" },
  { ecosystem: "go", path: "services/event-ingest/go.mod" },
  { ecosystem: "go", path: "services/health/go.mod" },
  { ecosystem: "go", path: "services/platform/go.mod" },
  { ecosystem: "go", path: "services/runtime-gateway/go.mod" },
  { ecosystem: "npm", path: "workers/redteam-node/package.json" },
  { ecosystem: "python", path: "workers/security-python/pyproject.toml" },
];

function invalid() {
  return new Error("dependency lock invalid");
}

function assert(condition) {
  if (!condition) {
    throw invalid();
  }
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys) {
  assert(isObject(value));
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  assert(actual.length === expected.length && actual.every((key, index) => key === expected[index]));
}

function exactStringArray(value, expected) {
  assert(Array.isArray(value));
  assert(value.length === expected.length);
  assert(value.every((entry, index) => typeof entry === "string" && entry === expected[index]));
}

function parseYaml(text, byteLimit) {
  assert(typeof text === "string" && Buffer.byteLength(text, "utf8") <= byteLimit);
  assert(!/[&*][A-Za-z0-9_-]+/.test(text));
  assert(!/(?:^|\n)\s*<<\s*:/.test(text));
  try {
    return load(text, { schema: JSON_SCHEMA, json: false });
  } catch {
    throw invalid();
  }
}

function parseJson(text, byteLimit) {
  assert(typeof text === "string" && Buffer.byteLength(text, "utf8") <= byteLimit);
  assert(text.trimStart().startsWith("{") && text.trimEnd().endsWith("}"));
  let value;
  try {
    value = JSON.parse(text);
    parseYaml(text, byteLimit);
  } catch {
    throw invalid();
  }
  assert(isObject(value));
  return value;
}

export function parseDependencyLock(text) {
  const lock = parseYaml(text, lockByteLimit);
  exactKeys(lock, ["schema_version", "policy", "manifests", "dependencies"]);
  assert(lock.schema_version === 1);

  exactKeys(lock.policy, ["approved_owners", "allowed_licenses", "prohibited_licenses"]);
  exactStringArray(lock.policy.approved_owners, approvedOwners);
  exactStringArray(lock.policy.allowed_licenses, allowedLicenses);
  exactStringArray(lock.policy.prohibited_licenses, prohibitedLicenses);

  assert(Array.isArray(lock.manifests) && lock.manifests.length === requiredManifests.length);
  for (const [index, manifest] of lock.manifests.entries()) {
    exactKeys(manifest, ["ecosystem", "path"]);
    assert(manifest.ecosystem === requiredManifests[index].ecosystem);
    assert(manifest.path === requiredManifests[index].path);
  }

  assert(Array.isArray(lock.dependencies));
  let previousKey = "";
  const seen = new Set();
  for (const dependency of lock.dependencies) {
    exactKeys(dependency, ["ecosystem", "manifest", "name", "version", "license", "owner", "scope", "review"]);
    assert(["go", "npm", "python"].includes(dependency.ecosystem));
    assert(typeof dependency.manifest === "string");
    assert(typeof dependency.name === "string" && /^[A-Za-z0-9@][A-Za-z0-9@/._-]*$/.test(dependency.name));
    assert(typeof dependency.version === "string" && exactVersion(dependency.ecosystem, dependency.version));
    assert(typeof dependency.license === "string" && allowedLicenses.includes(dependency.license));
    assert(!prohibitedLicenses.includes(dependency.license));
    assert(approvedOwners.includes(dependency.owner));
    assert(dependency.scope === "runtime");
    assert(dependency.review === "approved");
    assert(lock.manifests.some((manifest) => manifest.path === dependency.manifest && manifest.ecosystem === dependency.ecosystem));

    const key = `${dependency.manifest}:${dependency.name}`;
    assert(key > previousKey && !seen.has(key));
    previousKey = key;
    seen.add(key);
  }
  return lock;
}

function exactVersion(ecosystem, version) {
  if (ecosystem === "npm") {
    return /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version);
  }
  if (ecosystem === "go") {
    return /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/.test(version);
  }
  return /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:[0-9A-Za-z.-]+)?$/.test(version);
}

function collectNpmDependencies(path, text, packageLock) {
  const manifest = parseJson(text, manifestByteLimit);
  const dependencies = manifest.dependencies ?? {};
  assert(isObject(dependencies));
  assert(Object.values(dependencies).every((value) => typeof value === "string"));

  if (path !== "package.json") {
    assert(Object.keys(dependencies).length === 0);
    return [];
  }

  assert(packageLock.lockfileVersion === 3 && isObject(packageLock.packages));
  const lockedRoot = packageLock.packages[""];
  assert(isObject(lockedRoot) && isObject(lockedRoot.dependencies));
  const names = Object.keys(dependencies).sort();
  const lockedNames = Object.keys(lockedRoot.dependencies).sort();
  assert(names.length === lockedNames.length && names.every((name, index) => name === lockedNames[index]));
  for (const name of names) {
    assert(lockedRoot.dependencies[name] === dependencies[name]);
  }

  return names.map((name) => {
    const resolvedPackage = packageLock.packages[`node_modules/${name}`];
    assert(isObject(resolvedPackage));
    assert(typeof resolvedPackage.version === "string" && exactVersion("npm", resolvedPackage.version));
    assert(typeof resolvedPackage.license === "string");
    return {
      ecosystem: "npm",
      manifest: path,
      name,
      version: resolvedPackage.version,
      license: resolvedPackage.license,
    };
  });
}

function parseGoRequirement(line) {
  const indirect = /\/\/\s*indirect\s*$/.test(line);
  const withoutComment = line.replace(/\/\/.*$/, "").trim();
  const match = withoutComment.match(/^([^\s]+)\s+(v[^\s]+)$/);
  assert(match !== null);
  assert(exactVersion("go", match[2]));
  return { name: match[1], version: match[2], indirect };
}

function goModulePath(text) {
  const matches = [...text.matchAll(/^module ([^\s]+)$/gm)];
  assert(matches.length === 1);
  return matches[0][1];
}

function collectGoDependencies(path, text, files) {
  assert(typeof text === "string" && Buffer.byteLength(text, "utf8") <= manifestByteLimit);
  const dependencies = [];
  let inRequireBlock = false;
  let internalReplacementSeen = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("//")) {
      continue;
    }
    if (/^replace\b/.test(line)) {
      assert(path === internalHealthConsumer);
      assert(line === internalHealthReplacement && !internalReplacementSeen);
      internalReplacementSeen = true;
      continue;
    }
    if (/^require\s*\($/.test(line)) {
      assert(!inRequireBlock);
      inRequireBlock = true;
      continue;
    }
    if (line === ")") {
      assert(inRequireBlock);
      inRequireBlock = false;
      continue;
    }
    if (inRequireBlock) {
      const requirement = parseGoRequirement(line);
      dependencies.push(requirement);
      continue;
    }
    if (/^require\b/.test(line)) {
      const requirementText = line.replace(/^require\s+/, "");
      assert(requirementText !== line);
      const requirement = parseGoRequirement(requirementText);
      dependencies.push(requirement);
    }
  }
  assert(!inRequireBlock);
  let internalRequirementSeen = false;
  const external = dependencies.filter(({ name, version, indirect }) => {
    if (name !== internalHealthModule) return !indirect;
    assert(path === internalHealthConsumer && version === internalHealthVersion && !indirect && !internalRequirementSeen);
    internalRequirementSeen = true;
    return false;
  });
  assert(internalReplacementSeen === internalRequirementSeen);
  if (internalRequirementSeen) {
    assert(typeof files[internalHealthTarget] === "string");
    assert(goModulePath(files[internalHealthTarget]) === internalHealthModule);
  }
  return external.map(({ name, version }) => ({ ecosystem: "go", manifest: path, name, version }));
}

function collectPythonDependencies(path, text) {
  assert(typeof text === "string" && Buffer.byteLength(text, "utf8") <= manifestByteLimit);
  const projectHeaders = [...text.matchAll(/^\[project\]\s*$/gm)];
  assert(projectHeaders.length === 1);
  const sectionStart = projectHeaders[0].index + projectHeaders[0][0].length;
  const remainder = text.slice(sectionStart);
  const nextSection = remainder.search(/^\[/m);
  const section = nextSection === -1 ? remainder : remainder.slice(0, nextSection);
  const matches = [...section.matchAll(/^dependencies\s*=\s*\[([\s\S]*?)\]\s*$/gm)];
  const assignments = [...section.matchAll(/^dependencies\s*=/gm)];
  assert(assignments.length === matches.length);
  assert(matches.length <= 1);
  if (matches.length === 0) {
    return [];
  }
  let values;
  try {
    values = JSON.parse(`[${matches[0][1]}]`);
  } catch {
    throw invalid();
  }
  assert(Array.isArray(values));
  return values.map((value) => {
    assert(typeof value === "string");
    const match = value.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)$/);
    assert(match !== null && exactVersion("python", match[2]));
    return { ecosystem: "python", manifest: path, name: match[1], version: match[2] };
  });
}

export function validateDependencyState({ lockText, files }) {
  const lock = parseDependencyLock(lockText);
  assert(isObject(files));
  const suppliedManifests = Object.keys(files)
    .filter((path) => manifestNames.has(basename(path)))
    .sort();
  const expectedManifests = requiredManifests.map(({ path }) => path).sort();
  assert(
    suppliedManifests.length === expectedManifests.length
      && suppliedManifests.every((path, index) => path === expectedManifests[index]),
  );
  const packageLock = parseJson(files[packageLockPath], packageLockByteLimit);
  const actual = [];
  for (const manifest of requiredManifests) {
    const text = files[manifest.path];
    assert(typeof text === "string");
    if (manifest.ecosystem === "npm") {
      actual.push(...collectNpmDependencies(manifest.path, text, packageLock));
    } else if (manifest.ecosystem === "go") {
      actual.push(...collectGoDependencies(manifest.path, text, files));
    } else {
      actual.push(...collectPythonDependencies(manifest.path, text));
    }
  }

  actual.sort((left, right) => `${left.manifest}:${left.name}`.localeCompare(`${right.manifest}:${right.name}`));
  assert(actual.length === lock.dependencies.length);
  for (const [index, observed] of actual.entries()) {
    const reviewed = lock.dependencies[index];
    assert(observed.ecosystem === reviewed.ecosystem);
    assert(observed.manifest === reviewed.manifest);
    assert(observed.name === reviewed.name);
    assert(observed.version === reviewed.version);
    if (observed.license !== undefined) {
      assert(observed.license === reviewed.license);
    }
  }

  return { manifests: requiredManifests.length, dependencies: actual.length };
}

export async function readBoundedFile(path, byteLimit) {
  assert(typeof path === "string" && path !== "");
  assert(Number.isSafeInteger(byteLimit) && byteLimit >= 0);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    assert(before.isFile() && before.size <= BigInt(byteLimit));

    const value = Buffer.alloc(byteLimit + 1);
    let total = 0;
    while (total < value.byteLength) {
      const { bytesRead } = await handle.read(value, total, value.byteLength - total, total);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    assert(total <= byteLimit);

    const after = await handle.stat({ bigint: true });
    assert(after.isFile());
    assert(before.dev === after.dev && before.ino === after.ino);
    assert(before.size === after.size && after.size === BigInt(total));
    assert(before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs);
    return new TextDecoder("utf-8", { fatal: true }).decode(value.subarray(0, total));
  } catch {
    throw invalid();
  } finally {
    await handle.close();
  }
}

async function discoverProductManifests(root) {
  const discovered = ["package.json"];
  const pending = productRoots.map((path) => resolve(root, path));
  let entriesSeen = 0;
  while (pending.length > 0) {
    const directory = pending.pop();
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      entriesSeen += 1;
      assert(entriesSeen <= discoveryEntryLimit);
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredProductDirectories.has(entry.name)) pending.push(path);
      } else if (manifestNames.has(entry.name)) {
        assert(entry.isFile());
        discovered.push(relative(root, path).split(sep).join("/"));
      }
    }
  }
  discovered.sort();
  const expected = requiredManifests.map(({ path }) => path).sort();
  assert(discovered.length === expected.length && discovered.every((path, index) => path === expected[index]));
  return discovered;
}

export async function validateRepository(root = process.cwd()) {
  const files = {};
  for (const manifest of await discoverProductManifests(root)) {
    files[manifest] = await readBoundedFile(resolve(root, manifest), manifestByteLimit);
  }
  files[packageLockPath] = await readBoundedFile(resolve(root, packageLockPath), packageLockByteLimit);
  const lockText = await readBoundedFile(resolve(root, lockPath), lockByteLimit);
  return validateDependencyState({ lockText, files });
}

function writeLine(stream, value) {
  const result = stream.write(`${value}\n`);
  assert(result !== false);
}

export async function runMain(args = process.argv.slice(2), dependencies = {}) {
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  const setExitCode = dependencies.setExitCode ?? ((value) => { process.exitCode = value; });
  const validate = dependencies.validateRepository ?? validateRepository;
  try {
    assert(Array.isArray(args) && args.length === 0);
    await validate();
    writeLine(stdout, successLine);
    setExitCode(0);
    return 0;
  } catch {
    try {
      writeLine(stderr, failureLine);
    } catch {
      // The fixed failure boundary has no safe secondary output channel.
    }
    setExitCode(1);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await runMain();
}
