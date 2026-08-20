import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { inspectContainerBuilds } from "./release-contract.mjs";

const exec = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const requiredHeaders = Object.freeze(["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"]);
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const traceparent = /^00-([0-9a-f]{32})-([0-9a-f]{16})-(?:00|01)$/;

export async function loadReleasePolicy() {
  return deepFreeze({
    performance: { webP95Milliseconds: 2000, apiReadP95Milliseconds: 500, apiMutationP95Milliseconds: 1000, errorRatePercent: 1 },
    resilience: ["replica_restart", "provider_timeout", "queue_redrive", "stale_read_revalidation"],
    supplyChain: ["npm_spdx_sbom", "go_spdx_sbom", "license_allowlist", "offline_dependency_audit", "digest_pinned_container_definition", "full_tracked_gitleaks", "required_ci_gate"],
    proof: { ownedPrefix: "zasp-production-e2e-", ambientMutation: false },
  });
}

export async function runReadOnlySynthetic({ origin, token, allowHTTPLoopback = false }) {
  const parsed = new URL(origin);
  const loopback = net.isIP(parsed.hostname) !== 0 && (parsed.hostname === "127.0.0.1" || parsed.hostname === "::1");
  if ((parsed.protocol !== "https:" && !(allowHTTPLoopback && parsed.protocol === "http:" && loopback)) || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || token.length < 32 || token.length > 4096 || token.trim() !== token) throw new Error("synthetic rejected");

  const webStarted = performance.now();
  const web = await fetch(new URL("/sign-in", parsed), { redirect: "manual", signal: AbortSignal.timeout(5000) });
  await web.arrayBuffer();
  const webMilliseconds = Math.ceil(performance.now() - webStarted);
  if (web.status !== 200 || requiredHeaders.some((name) => !web.headers.has(name)) || webMilliseconds > 2000) throw new Error("synthetic rejected");

  const apiStarted = performance.now();
  const api = await fetch(new URL("/api/v1/home/summary", parsed), { headers: { Authorization: `Bearer ${token}` }, redirect: "manual", signal: AbortSignal.timeout(5000) });
  await api.arrayBuffer();
  const apiMilliseconds = Math.ceil(performance.now() - apiStarted);
  const correlationID = api.headers.get("x-correlation-id") ?? "";
  const trace = traceparent.exec(api.headers.get("traceparent") ?? "");
  if (api.status !== 200 || !productID.test(correlationID) || !trace || /^0+$/.test(trace[1]) || apiMilliseconds > 500) throw new Error("synthetic rejected");
  return deepFreeze({ apiMilliseconds, correlationID, traceID: trace[1], webMilliseconds });
}

export async function verifyReleaseSources() {
  const builds = await inspectContainerBuilds();
  if (builds.length !== 3 || builds.some((build) => !build.readOnlyCompatible || build.containsSecret)) throw new Error("container gate rejected");

  const canary = await source("deploy/staging/product/templates/canary.yaml");
  const monitoring = await source("deploy/staging/product/templates/monitoring.yaml");
  if (!canary.includes("production-readonly-canary") || !canary.includes("/api/v1/home/summary") || !canary.includes("ZASP_CANARY_READ_TOKEN") || !monitoring.includes("ZaspAPIErrorBudgetBurn") || !monitoring.includes("> 0.01")) throw new Error("canary gate rejected");

  const requiredDocs = ["production-deployment.md", "backup-restore-rollback.md", "observability-and-canaries.md", "authentication-and-support.md", "supported-workflows.md"];
  const docs = await Promise.all(requiredDocs.map((name) => source(`docs/operations/${name}`)));
  for (const phrase of ["schema v13", "Do not run `agentsec-migrate down`", "correlation ID", "must not ask", "not supported production workflows"]) {
    if (!docs.some((document) => document.includes(phrase))) throw new Error("documentation gate rejected");
  }

  const { stdout } = await exec("npm", ["sbom", "--omit=dev", "--sbom-format", "spdx", "--json"], { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  const sbom = JSON.parse(stdout);
  if (sbom.spdxVersion !== "SPDX-2.3" || !Array.isArray(sbom.packages) || sbom.packages.length < 2) throw new Error("SBOM gate rejected");
  const allowed = new Set(["0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT", "MPL-2.0"]);
  for (const entry of sbom.packages) {
    const license = entry.licenseConcluded ?? entry.licenseDeclared;
    if (entry.name === "zasp-agent-security-console" && license === "NOASSERTION") continue;
    if (!allowed.has(license)) throw new Error(`license gate rejected: ${entry.name}`);
  }

  const goSpdx = await goSourceSBOM();
  validateGoSpdxDocument(goSpdx);
  if (goSpdx.packages.length < 20) throw new Error("Go SBOM gate rejected");
  for (const entry of goSpdx.packages) {
    if (entry.licenseConcluded !== "NOASSERTION" && !allowed.has(entry.licenseConcluded)) throw new Error(`Go license gate rejected: ${entry.name}`);
    if (entry.licenseConcluded === "NOASSERTION" && !entry.name.startsWith("github.com/zasp-ai/zasp-sec/")) throw new Error(`Go license gate rejected: ${entry.name}`);
  }

  const sensitiveSources = await Promise.all([
    source(".dockerignore"), source("deploy/production/api.Dockerfile"), source("deploy/production/web.Dockerfile"), source("deploy/production/worker.Dockerfile"),
    source("deploy/staging/product/values.yaml"), source("deploy/staging/product/templates/secrets.yaml"), source("deploy/staging/product/templates/workloads.yaml"),
  ]);
  const combined = sensitiveSources.join("\n");
  if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{16,}/.test(combined) || !sensitiveSources[0].includes(".env") || !sensitiveSources[5].includes("secretsmanager") || !sensitiveSources[6].includes("/var/run/secrets/zasp")) throw new Error("secret gate rejected");
  const terraform = await source("deploy/staging/main.tf");
  for (const contract of ["system:serviceaccount:agentsec:agentsec-api", "system:serviceaccount:agentsec:zasp-discovery-worker", "system:serviceaccount:agentsec:zasp-discovery-scheduler", "system:serviceaccount:agentsec:zasp-outbox-publisher", "system:serviceaccount:agentsec:zasp-projection-risk", "system:serviceaccount:agentsec:zasp-projection-graph", "system:serviceaccount:agentsec:zasp-projection-search", "system:serviceaccount:agentsec:agentsec-projection-graph-init", "system:serviceaccount:agentsec:agentsec-projection-search-init", "system:serviceaccount:agentsec:agentsec-migration", "system:serviceaccount:agentsec:agentsec-canary-secret-sync", "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "sqs:SendMessage", "sqs:ReceiveMessage", "s3:PutObject", "discovery-jobs", "zasp-inventory-v1/_mapping", "_zasp_schema_v1", "neo4j/auth/runtime", "neo4j/auth/schema", "canary-read-token", "token-reveal-key", "stytch-secret", "postgres-api-dsn", "postgres-worker-dsn", "postgres-outbox-worker-dsn", "postgres-scheduler-dsn", "postgres-projection-risk-dsn", "postgres-projection-graph-dsn", "postgres-projection-search-dsn", "postgres-migration-dsn"]) {
    if (!terraform.includes(contract)) throw new Error("secret identity gate rejected");
  }
  const [workloads, projectionInit, resilience] = await Promise.all([
    source("deploy/staging/product/templates/workloads.yaml"), source("deploy/staging/product/templates/projection-init.yaml"), source("deploy/staging/product/templates/resilience.yaml"),
  ]);
  for (const contract of ["ZASP_WORKER_MODE", "projection-risk", "projection-graph", "projection-search", "ZASP_NEO4J_EXPECTED_PRINCIPAL", "ZASP_NEO4J_EXPECTED_ROLE"]) if (!workloads.includes(contract)) throw new Error("worker deployment gate rejected");
  for (const contract of ["projection-search-init", "projection-graph-init", "ZASP_PROJECTION_INIT_ROLE_ARN", "ZASP_PROJECTION_INIT_WEB_IDENTITY_TOKEN_FILE", "ZASP_PROJECTION_INIT_TIMEOUT", "ZASP_NEO4J_SCHEMA_CREDENTIAL_REFERENCE", "ZASP_OPENSEARCH_INDEX", 'helm.sh/hook-weight: "-7"']) if (!projectionInit.includes(contract)) throw new Error("projection init gate rejected");
  for (const contract of ["agentsec-discovery-worker", "agentsec-projection-risk", "agentsec-projection-graph", "agentsec-projection-search", "HorizontalPodAutoscaler", "PodDisruptionBudget", "default-deny"]) if (!resilience.includes(contract)) throw new Error("worker resilience gate rejected");
  for (const contract of ["ZaspDiscoveryWorkerUnavailable", "ZaspProjectionWorkersUnavailable", "ZaspTask4ControlWorkersUnavailable", "ZaspTask4WorkerDependencyNotReady", "ZaspTask4WorkerCapacityExhausted"]) if (!monitoring.includes(contract)) throw new Error("worker monitoring gate rejected");

  await exec("gitleaks", ["git", "--no-banner", "--redact", "--log-opts=HEAD"], { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  const workflow = await source(".github/workflows/runnable-ui.yml");
  if (!workflow.includes("fetch-depth: 0") || !workflow.includes("github.com/zricethezav/gitleaks/v8@v8.30.1") || !workflow.includes("npm run production:release:gate")) throw new Error("required CI gate rejected");

  const definitions = [await source("deploy/production/web.Dockerfile"), await source("deploy/production/api.Dockerfile"), await source("deploy/production/worker.Dockerfile")];
  const imageReferences = new Set(definitions.flatMap((definition) => [...definition.matchAll(/^FROM\s+(\S+)/gm)].map((match) => match[1])));
  if (imageReferences.size !== 3 || [...imageReferences].some((reference) => !/@sha256:[0-9a-f]{64}$/.test(reference))) throw new Error("image definition gate rejected");

  return deepFreeze({ canary: true, documentation: true, imageDefinitions: imageReferences.size, licensePolicy: true, trackedSecretScan: true, npmSpdxPackages: sbom.packages.length, goSpdxPackages: goSpdx.packages.length, goSpdx, requiredCI: true, task4Deployment: true });
}

async function goSourceSBOM() {
  const template = "{{with .Module}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}";
  const { stdout } = await exec("go", ["list", "-deps", "-f", template, "./agentsec-api", "./agentsec-migrate", "./agentsec-worker", "./cmd/zasp-healthcheck"], { cwd: path.join(root, "services/platform"), encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  const modules = new Map();
  for (const line of stdout.split("\n")) {
    if (!line) continue;
    const [name, version, directory] = line.split("\t");
    if (!name || !directory || modules.has(name)) continue;
    modules.set(name, { name, version: version || "0.0.0-local", directory });
  }
  const packages = [];
  for (const dependency of [...modules.values()].sort((left, right) => left.name.localeCompare(right.name))) {
    const license = await moduleLicense(dependency);
    const packageID = createHash("sha256").update(`${dependency.name}\0${dependency.version}`).digest("hex").slice(0, 24);
    packages.push({ SPDXID: `SPDXRef-Package-${packageID}`, name: dependency.name, versionInfo: dependency.version, downloadLocation: "NOASSERTION", filesAnalyzed: false, licenseConcluded: license, licenseDeclared: license, copyrightText: "NOASSERTION" });
  }
  const created = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const documentNamespace = goDocumentNamespace(packages, created);
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "zasp-production-go-source",
    documentNamespace,
    creationInfo: { created, creators: ["Tool: zasp-production-release-gate"] },
    packages,
    relationships: packages.map((entry) => ({ spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: entry.SPDXID })),
  };
}

export function validateGoSpdxDocument(document) {
  const created = document?.creationInfo?.created;
  if (!document || document.spdxVersion !== "SPDX-2.3" || document.dataLicense !== "CC0-1.0" || document.SPDXID !== "SPDXRef-DOCUMENT" || document.name !== "zasp-production-go-source" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(created) || Number.isNaN(Date.parse(created)) || new Date(created).toISOString().replace(/\.000Z$/, "Z") !== created || !document.creationInfo?.creators?.includes("Tool: zasp-production-release-gate") || !Array.isArray(document.packages) || !Array.isArray(document.relationships) || document.documentNamespace !== goDocumentNamespace(document.packages, created)) throw new Error("Go SBOM gate rejected");
  const packageIDs = new Set();
  for (const entry of document.packages) {
    if (!entry || !/^SPDXRef-Package-[A-Za-z0-9.-]+$/.test(entry.SPDXID) || packageIDs.has(entry.SPDXID) || typeof entry.name !== "string" || !entry.name || typeof entry.versionInfo !== "string" || !entry.versionInfo || entry.downloadLocation !== "NOASSERTION" || entry.filesAnalyzed !== false || typeof entry.licenseConcluded !== "string" || entry.licenseDeclared !== entry.licenseConcluded || entry.copyrightText !== "NOASSERTION") throw new Error("Go SBOM gate rejected");
    packageIDs.add(entry.SPDXID);
  }
  if (document.relationships.length !== packageIDs.size) throw new Error("Go SBOM gate rejected");
  const described = new Set();
  for (const relationship of document.relationships) {
    if (!relationship || relationship.spdxElementId !== "SPDXRef-DOCUMENT" || relationship.relationshipType !== "DESCRIBES" || !packageIDs.has(relationship.relatedSpdxElement) || described.has(relationship.relatedSpdxElement)) throw new Error("Go SBOM gate rejected");
    described.add(relationship.relatedSpdxElement);
  }
  return true;
}

function goDocumentNamespace(packages, created) {
  const namespaceID = createHash("sha256").update(JSON.stringify({ created, packages })).digest("hex");
  return `https://zasp.example/spdx/go-source/${namespaceID}`;
}

async function moduleLicense(dependency) {
  if (dependency.name.startsWith("github.com/zasp-ai/zasp-sec/")) return "NOASSERTION";
  const names = (await readdir(dependency.directory)).filter((name) => /^(?:licen[cs]e|copying)(?:[._-].*)?$/i.test(name)).sort();
  if (names.length === 0) return "NOASSERTION";
  const texts = await Promise.all(names.map((name) => readFile(path.join(dependency.directory, name), "utf8")));
  const text = texts.join("\n").toLowerCase();
  if (text.includes("apache license") && text.includes("version 2.0")) return "Apache-2.0";
  if (text.includes("permission is hereby granted, free of charge") || text.includes("the mit license")) return "MIT";
  if (text.includes("permission to use, copy, modify, and/or distribute")) return "ISC";
  if (text.includes("redistribution and use in source and binary forms")) return text.includes("neither the name") ? "BSD-3-Clause" : "BSD-2-Clause";
  if (text.includes("mozilla public license") && text.includes("version 2.0")) return "MPL-2.0";
  return "NOASSERTION";
}

async function source(relative) { return readFile(path.join(root, relative), "utf8"); }
function deepFreeze(value) { if (value && typeof value === "object") { for (const child of Object.values(value)) deepFreeze(child); Object.freeze(value); } return value; }
