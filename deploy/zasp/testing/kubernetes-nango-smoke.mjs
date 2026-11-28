import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { appendFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";
import { rendered, release, namespace, origin } from "./kubernetes-nango.mjs";

// Fail before allocating the private kubeconfig when local tools are missing.
for (const [tool, args] of [["kind", ["version"]], ["kubectl", ["version", "--client"]], ["helm", ["version", "--short"]]]) {
  execFileSync(tool, args, { stdio: "inherit", timeout: 10000 });
}

const cluster = "zasp-nango-" + randomBytes(4).toString("hex");
const temp = mkdtempSync(join(tmpdir(), "zasp-nango-"));
const kubeconfig = join(temp, "kubeconfig");
const kubeArgs = ["--kubeconfig", kubeconfig, "--context", "kind-" + cluster, "-n", namespace];
const kubectl = (args, opts = {}) => execFileSync("kubectl", [...kubeArgs, ...args], { encoding: "utf8", timeout: 360_000, ...opts });
const dashboard = "http://127.0.0.1:3003";

function workload() {
  const secrets = {
    nangoServiceKey: randomUUID(),
    nangoAdminKey: randomBytes(32).toString("hex"),
    nangoEncryptionKey: randomBytes(32).toString("base64"),
  };
  const docs = rendered({ enabled: true }, { secrets, persistence: false });
  const stateful = docs.find(doc => doc.kind === "StatefulSet");
  const pod = stateful.spec.template.spec;
  // Exercise the production chart's init order, probes, DNS, secret mounts and
  // filesystem permissions without pulling the unrelated product services.
  const api = pod.containers.find(container => container.name === "api");
  const server = pod.initContainers.find(container => container.name === "nango");
  const client = {
    name: "client", image: server.image, securityContext: server.securityContext,
    command: ["node", "-e", "setInterval(() => {}, 60000)"],
    env: api.env, volumeMounts: api.volumeMounts.filter(mount => mount.name === "nango-client"),
  };
  pod.initContainers = pod.initContainers.filter(container => ["postgres", "database-init", "nango-migrate", "nango"].includes(container.name));
  pod.containers = [client];
  const mounts = new Set([...pod.initContainers, client].flatMap(c => (c.volumeMounts || []).map(mount => mount.name)));
  pod.volumes = pod.volumes.filter(volume => mounts.has(volume.name));
  return docs.filter(doc => ["ConfigMap", "Secret", "NetworkPolicy", "Service", "StatefulSet"].includes(doc.kind));
}

let phase = "create kind cluster";

async function dashboardRequest(path, options = {}) {
  phase = (options.method ?? "GET") + " " + path;
  const response = await fetch(dashboard + path, { signal: AbortSignal.timeout(10000), redirect: "error", ...options });
  phase += " HTTP " + response.status;
  assert.equal(response.status, 200, `${options.method ?? "GET"} ${path} returned ${response.status}`);
  return response;
}

async function dashboardSetup() {
  const html = await (await dashboardRequest("/")).text();
  assert.match(html, /<script[^>]+src=["']\/env\.js(?:\?[^"']*)?["']/);
  const script = await (await dashboardRequest("/env.js")).text();
  const config = JSON.parse(script.trim().replace(/^window\._env\s*=\s*/, "").replace(/;$/, ""));
  assert.equal(config.apiUrl, dashboard);
  assert.equal(config.publicUrl, dashboard);
  assert.equal(config.features.auth, true);

  const json = { "Content-Type": "application/json", Origin: dashboard };
  const signup = await dashboardRequest("/api/v1/account/signup", {
    method: "POST", headers: json,
    body: JSON.stringify({ name: "Smoke Operator", email: "operator@example.test", password: "Ci1!" + randomBytes(16).toString("hex") }),
  });
  assert.equal((await signup.json()).data.verified, false);
  // This isolated installation has no SMTP. Read the private verification
  // message into memory, exactly as an operator with local pod access would.
  phase = "read local verification email";
  const logs = kubectl(["logs", release + "-0", "-c", "nango", "--tail=200"]);
  const token = logs.match(/http:\/\/127\.0\.0\.1:3003\/signup\/verification\/([A-Za-z0-9_-]+)/)?.[1];
  assert.ok(token, "the dashboard generated a loopback verification link");
  const verified = await dashboardRequest("/api/v1/account/verify/code", {
    method: "POST", headers: json, body: JSON.stringify({ token }),
  });
  const cookie = verified.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
  assert.ok(cookie, "dashboard verification opened a browser session");
  const callback = origin + "/api/v1/integrations/oauth/callback";
  const environment = await dashboardRequest("/api/v1/environments?env=prod", {
    method: "PATCH", headers: { ...json, Cookie: cookie }, body: JSON.stringify({ callback_url: callback }),
  });
  assert.equal((await environment.json()).data.callback_url, callback);
}

const inventoryProbe = `
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const key = readFileSync("/var/run/secrets/zasp-nango/service-key", "utf8");
const url = process.env.ZASP_NANGO_BASE_URL + "/integrations";
const request = headers => fetch(url, { headers, signal: AbortSignal.timeout(10000) });
const anonymous = await request({});
assert.ok([401,403].includes(anonymous.status), "anonymous inventory access must be denied");
const response = await request({ Authorization: "Bearer " + key });
assert.equal(response.status, 200, "product service key must authorize the integration inventory");
assert.deepEqual((await response.json()).data, []);
`;

let tunnel;
try {
  execFileSync("kind", ["create", "cluster", "--name", cluster, "--kubeconfig", kubeconfig, "--wait", "120s"], { stdio: "inherit", timeout: 300_000 });
  phase = "create disposable namespace";
  kubectl(["create", "namespace", namespace]);
  phase = "render and apply chart resources";
  kubectl(["apply", "-f", "-"], { input: JSON.stringify({ apiVersion: "v1", kind: "List", items: workload() }) });
  phase = "wait for PostgreSQL and Nango readiness";
  kubectl(["rollout", "status", "statefulset/" + release, "--timeout=300s"]);
  phase = "open dashboard port-forward";
  tunnel = spawn("kubectl", [...kubeArgs, "port-forward", "--address=127.0.0.1", "service/" + release + "-nango", "3003:3003"], { stdio: ["ignore", "pipe", "inherit"] });
  const lines = createInterface({ input: tunnel.stdout });
  const timer = new AbortController();
  try {
    const ready = (async () => {
      for await (const line of lines) if (line.startsWith("Forwarding from 127.0.0.1:3003")) return;
      throw new Error("dashboard port-forward exited before listening");
    })();
    await Promise.race([ready, delay(15000, null, { signal: timer.signal }).then(() => { throw new Error("dashboard port-forward timed out"); })]);
  } finally {
    timer.abort();
    lines.close();
  }
  await dashboardSetup();
  phase = "authenticated product inventory";
  kubectl(["exec", release + "-0", "-c", "client", "--", "node", "--input-type=module", "-e", inventoryProbe]);
  console.log("Nango migration, private dashboard, callback and authenticated integration inventory passed.");
} catch (err) {
  // Phases are assigned from static paths and HTTP status only. Credentials,
  // signup messages, and the signed-in dashboard response stay out of summaries.
  console.error("::error title=Nango Kubernetes smoke::" + phase);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, "failure=" + phase + "\n");
  // Pod status and Kubernetes events identify pull, mount and readiness errors;
  // Nango logs can contain account verification links.
  try { kubectl(["get", "pods", "-o", "wide"], { stdio: "inherit", timeout: 10000 }); } catch { /* Cluster may not have started. */ }
  try { kubectl(["get", "events", "--sort-by=.metadata.creationTimestamp"], { stdio: "inherit", timeout: 10000 }); } catch { /* Cluster may not have started. */ }
  throw err;
} finally {
  tunnel?.kill();
  try {
    execFileSync("kind", ["delete", "cluster", "--name", cluster, "--kubeconfig", kubeconfig], { stdio: "inherit", timeout: 60000 });
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}
