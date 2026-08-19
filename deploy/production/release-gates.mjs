import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
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
    supplyChain: ["spdx_sbom", "license_allowlist", "offline_dependency_audit", "container_definition", "tracked_secret_scan"],
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
  if (builds.length !== 2 || builds.some((build) => !build.readOnlyCompatible || build.containsSecret)) throw new Error("container gate rejected");

  const canary = await source("deploy/staging/product/templates/canary.yaml");
  const monitoring = await source("deploy/staging/product/templates/monitoring.yaml");
  if (!canary.includes("production-readonly-canary") || !canary.includes("/api/v1/home/summary") || !canary.includes("ZASP_CANARY_READ_TOKEN") || !monitoring.includes("ZaspAPIErrorBudgetBurn") || !monitoring.includes("> 0.01")) throw new Error("canary gate rejected");

  const requiredDocs = ["production-deployment.md", "backup-restore-rollback.md", "observability-and-canaries.md", "authentication-and-support.md", "supported-workflows.md"];
  const docs = await Promise.all(requiredDocs.map((name) => source(`docs/operations/${name}`)));
  for (const phrase of ["schema v9", "Do not run `agentsec-migrate down`", "correlation ID", "must not ask", "not supported production workflows"]) {
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

  const sensitiveSources = await Promise.all([
    source(".dockerignore"), source("deploy/production/api.Dockerfile"), source("deploy/production/web.Dockerfile"),
    source("deploy/staging/product/values.yaml"), source("deploy/staging/product/templates/secrets.yaml"), source("deploy/staging/product/templates/workloads.yaml"),
  ]);
  const combined = sensitiveSources.join("\n");
  if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{16,}/.test(combined) || !sensitiveSources[0].includes(".env") || !sensitiveSources[4].includes("secretsmanager") || !sensitiveSources[5].includes("secretKeyRef")) throw new Error("secret gate rejected");
  const terraform = await source("deploy/staging/main.tf");
  for (const contract of ["system:serviceaccount:agentsec:agentsec-product", "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "canary-read-token", "token-reveal-key", "stytch-secret", "postgres-dsn"]) {
    if (!terraform.includes(contract)) throw new Error("secret identity gate rejected");
  }

  return deepFreeze({ canary: true, documentation: true, imageDefinitions: true, licensePolicy: true, secretScan: true, spdx: true });
}

async function source(relative) { return readFile(path.join(root, relative), "utf8"); }
function deepFreeze(value) { if (value && typeof value === "object") { for (const child of Object.values(value)) deepFreeze(child); Object.freeze(value); } return value; }
