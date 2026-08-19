import { access, readFile } from "node:fs/promises";
import { dirname, extname, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const productionEntries = ["app/page.tsx", "app/[...path]/page.tsx"];
const sourceExtensions = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const forbiddenExactSources = new Set([
  "app/domain/store.tsx",
  "app/domain/seed.ts",
  "app/components/ZaspDemoApp.tsx",
  "app/features/agents/AgentSecurityView.tsx",
  "app/features/connectors/ConnectorViews.tsx",
  "app/features/policies/PoliciesView.tsx",
]);
const forbiddenSourcePrefixes = [
  "app/features/discovery/",
  "app/features/governance/",
  "app/features/guardrails/",
  "app/features/overview/",
  "app/features/redteam/",
  "app/features/sensors/",
  "app/features/tools/",
];
const forbiddenCompiledSentinels = [
  "zasp-demo-state",
  "fixtureAgentSecurityAPI",
  "Demo environment",
  "Red Team",
  "Attack Lab",
  "Guardrail dashboard",
  "Create guardrail",
  "Zasp security report",
  "Schedule report",
  "Generate report",
  "Report templates",
];
const browserStoragePattern = /\b(?:localStorage|sessionStorage|indexedDB)\b|\bcaches\s*\./;

function repositoryPath(root, path) {
  return relative(root, path).split(sep).join("/");
}

function sourceViolation(path) {
  if (forbiddenExactSources.has(path) || forbiddenSourcePrefixes.some((prefix) => path.startsWith(prefix))) {
    return "demo module";
  }
  if (/(?:^|\/)fixtures?(?:[./-]|$)/i.test(path)) return "fixture module";
  return null;
}

function importSpecifiers(source) {
  const result = [];
  const staticImport = /\b(?:import|export)\s+(?:type\s+)?(?:[^'";]*?\s+from\s*)?["']([^"']+)["']/g;
  const dynamicImport = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
  for (const pattern of [staticImport, dynamicImport]) {
    for (const match of source.matchAll(pattern)) result.push(match[1]);
  }
  return result;
}

async function exists(path) {
  try { await access(path); return true; } catch { return false; }
}

async function resolveSourceImport(importer, specifier) {
  if (!specifier.startsWith(".")) return null;
  const base = resolve(dirname(importer), specifier);
  const candidates = sourceExtensions.flatMap((extension) => [base + extension, resolve(base, `index${extension}`)]);
  for (const candidate of candidates) {
    if (extname(candidate) === ".json") continue;
    if (await exists(candidate)) return candidate;
  }
  throw new Error(`unresolved production import: ${specifier}`);
}

export async function checkSourceGraph({ root = repositoryRoot, entries = productionEntries } = {}) {
  const pending = entries.map((entry) => resolve(root, entry));
  const visited = new Set();
  while (pending.length) {
    const file = pending.pop();
    if (visited.has(file)) continue;
    visited.add(file);
    const path = repositoryPath(root, file);
    const violation = sourceViolation(path);
    if (violation) throw new Error(`${violation} is reachable from production: ${path}`);
    const source = await readFile(file, "utf8");
    if (browserStoragePattern.test(source)) throw new Error(`browser storage is reachable from production: ${path}`);
    for (const specifier of importSpecifiers(source)) {
      const imported = await resolveSourceImport(file, specifier);
      if (imported) pending.push(imported);
    }
  }
  return { files: [...visited].map((file) => repositoryPath(root, file)).sort() };
}

function manifestClosure(manifest, starts) {
  const pending = [...starts];
  const visited = new Set();
  while (pending.length) {
    const key = pending.pop();
    if (visited.has(key)) continue;
    const entry = manifest[key];
    if (!entry) throw new Error(`compiled manifest reference is missing: ${key}`);
    visited.add(key);
    for (const imported of [...(entry.imports ?? []), ...(entry.dynamicImports ?? [])]) pending.push(imported);
  }
  return visited;
}

async function chunkPath(buildRoot, file) {
  for (const candidate of [resolve(buildRoot, file), resolve(buildRoot, "ssr", file)]) {
    if (await exists(candidate)) return candidate;
  }
  throw new Error(`compiled chunk is missing: ${file}`);
}

async function checkManifest({ root, kind, starts }) {
  const buildRoot = resolve(root, "dist", kind);
  const manifest = JSON.parse(await readFile(resolve(buildRoot, ".vite/manifest.json"), "utf8"));
  const closure = manifestClosure(manifest, starts(manifest));
  for (const key of closure) {
    const entry = manifest[key];
    const source = entry.src ?? key;
    const violation = sourceViolation(source);
    if (violation) throw new Error(`forbidden source in production ${kind} closure: ${source}`);
    const contents = await readFile(await chunkPath(buildRoot, entry.file), "utf8");
    const sentinel = forbiddenCompiledSentinels.find((value) => contents.includes(value));
    if (sentinel) throw new Error(`forbidden sentinel in production ${kind} closure: ${sentinel}`);
  }
  return closure.size;
}

export async function checkCompiledBuild({ root = repositoryRoot } = {}) {
  const clientChunks = await checkManifest({
    root,
    kind: "client",
    starts: (manifest) => {
      if (!manifest["virtual:vinext-app-browser-entry"]) throw new Error("production client entry is missing");
      return ["virtual:vinext-app-browser-entry"];
    },
  });
  const serverChunks = await checkManifest({
    root,
    kind: "server",
    starts: (manifest) => productionEntries.map((entry) => {
      if (!manifest[entry]) throw new Error(`production server entry is missing: ${entry}`);
      return entry;
    }),
  });
  return { clientChunks, serverChunks };
}

export async function runMain({ args = process.argv.slice(2), stdout = process.stdout, stderr = process.stderr, root = repositoryRoot } = {}) {
  try {
    if (args.length !== 1 || !["--source", "--compiled"].includes(args[0])) throw new Error("expected --source or --compiled");
    const result = args[0] === "--source" ? await checkSourceGraph({ root }) : await checkCompiledBuild({ root });
    stdout.write(args[0] === "--source"
      ? `Production source graph passed: files=${result.files.length}.\n`
      : `Production compiled graph passed: client_chunks=${result.clientChunks} server_chunks=${result.serverChunks}.\n`);
    return 0;
  } catch (error) {
    stderr.write(`Production import graph rejected: ${error instanceof Error ? error.message : "invalid input"}.\n`);
    return 1;
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  process.exitCode = await runMain();
}
