import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { installBoundedSignalCleanup } from "./bounded-signal-cleanup.mjs";

const FIXED_NODE_VERSION = "v22.23.1";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const platform = path.join(root, "services", "platform");
const postgresBin = "/opt/homebrew/bin";
const chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

if (process.version !== FIXED_NODE_VERSION) throw new Error(`production combined E2E requires Node ${FIXED_NODE_VERSION}`);

const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "zasp-production-e2e-"));
const children = [];
let proxy;
let identity;
let api;
let postgres;
let web;
let browser;
let observedSessionCookie = false;
const cleanupController = installBoundedSignalCleanup(cleanupOwnedResources);

try {
  const ports = await Promise.all(Array.from({ length: 7 }, reservePort));
  const [postgresPort, identityPort, apiPort, healthPort, webPort, proxyPort, chromePort] = ports;
  const dsn = `postgres://zasp_e2e@127.0.0.1:${postgresPort}/postgres?sslmode=disable`;
  postgres = await startPostgres(postgresPort);
  console.log("combined E2E: disposable PostgreSQL ready");

  const migrate = path.join(temporaryRoot, "agentsec-migrate");
  const apiBinary = path.join(temporaryRoot, "agentsec-api");
  await command("go", ["build", "-o", migrate, "./agentsec-migrate"], { cwd: platform });
  await command("go", ["build", "-o", apiBinary, "./agentsec-api"], { cwd: platform });
  await command(migrate, ["up"], { env: { ...process.env, ZASP_POSTGRES_DSN: dsn, ZASP_MIGRATION_TIMEOUT: "20s" } });
  await seedPostgres(dsn);
  console.log("combined E2E: migrations and durable seed ready");

  const publicOrigin = `https://127.0.0.1:${proxyPort}`;
  identity = await startIdentityServer(identityPort, publicOrigin);
  const apiEnvironment = {
    ...process.env,
    ZASP_ENVIRONMENT: "test",
    ZASP_PRODUCT_LISTEN_ADDRESS: `127.0.0.1:${apiPort}`,
    ZASP_INTERNAL_LISTEN_ADDRESS: `127.0.0.1:${healthPort}`,
    ZASP_PUBLIC_ORIGIN: publicOrigin,
    ZASP_COOKIE_SECURE: "true",
    ZASP_PROVIDER_TIMEOUT: "5s",
    ZASP_SHUTDOWN_TIMEOUT: "5s",
    ZASP_READINESS_INTERVAL: "100ms",
    ZASP_READINESS_MAX_INTERVAL: "1s",
    ZASP_POSTGRES_DSN: dsn,
    ZASP_STYTCH_BASE_URL: `http://127.0.0.1:${identityPort}`,
    ZASP_STYTCH_AUTHORIZE_URL: `http://127.0.0.1:${identityPort}/v1/b2b/public/oauth/google/start`,
    ZASP_STYTCH_PROJECT_ID: "project-test-local",
    ZASP_STYTCH_SECRET: "secret-test-local",
    ZASP_STYTCH_PUBLIC_TOKEN: "public-token-test-local",
    ZASP_STYTCH_ORGANIZATION_ID: "organization-test-local",
  };
  api = startChild(apiBinary, [], { env: apiEnvironment });
	try {
		await waitForHTTP(`http://127.0.0.1:${healthPort}/readyz`, 200);
	} catch (error) {
		throw new Error(`${error instanceof Error ? error.message : "API readiness failed"}: ${api.output()}`);
	}
  console.log("combined E2E: Go product and internal listeners ready");

  await command("npm", ["run", "build"], { cwd: root, timeout: 120_000 });
  web = startChild(path.join(root, "node_modules", ".bin", "vinext"), ["start", "--port", String(webPort), "--hostname", "127.0.0.1"], { cwd: root });
  await waitForHTTP(`http://127.0.0.1:${webPort}/sign-in`, 200);
  console.log("combined E2E: built web server ready");

  const key = path.join(temporaryRoot, "tls.key");
  const certificate = path.join(temporaryRoot, "tls.crt");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", certificate]);
  proxy = await startProxy(proxyPort, apiPort, webPort, key, certificate);
  await waitForHTTP(`${publicOrigin}/sign-in`, 200, true);

  const profile = path.join(temporaryRoot, "chrome-profile");
  browser = await startBrowser(profile, chromePort, `${publicOrigin}/api/v1/session/start?return_to=%2Fdiscovery%2Fassets`);
  const signedIn = await waitForBrowserText(browser.cdp, /Support agent/);
  assert.equal(observedSessionCookie, true, "__Host-zasp_session was not issued through the combined origin");
  assert.match(signedIn, /Agents/);
  assert.match(signedIn, /Support agent/);
  assert.doesNotMatch(signedIn, /Product API unavailable|Sign-in failed/);
  console.log("combined E2E: browser callback, cookie, bootstrap, and durable data proven");

  await stopChild(api);
  api = startChild(apiBinary, [], { env: apiEnvironment });
  await waitForHTTP(`http://127.0.0.1:${healthPort}/readyz`, 200);
  await browser.cdp.send("Page.reload", { ignoreCache: true });
  const reloaded = await waitForBrowserText(browser.cdp, /Support agent/);
  assert.match(reloaded, /Support agent/);
  assert.doesNotMatch(reloaded, /Sign in to Zasp|Product API unavailable/);
  console.log("combined E2E: API restart and browser reload proven");

  await browser.cdp.send("Page.navigate", { url: `${publicOrigin}/api/v1/agents/pid_90000001-0000-4000-8000-000000000001` });
  const denied = await waitForBrowserText(browser.cdp, /not_found/);
  assert.match(denied, /not_found/);
  assert.doesNotMatch(denied, /Foreign tenant agent/);

  console.log("production combined E2E passed: callback/cookie/bootstrap, durable data, restart/reload, tenant denial");
} finally {
	await cleanupController.run();
	cleanupController.dispose();
}

async function cleanupOwnedResources() {
  console.log("combined E2E: cleanup browser");
  if (browser) {
    browser.cdp.close();
    await stopChild(browser.child);
  }
  console.log("combined E2E: cleanup api");
  if (api) await stopChild(api);
  console.log("combined E2E: cleanup proxy");
  if (proxy) await closeServer(proxy);
  console.log("combined E2E: cleanup identity");
  if (identity) await closeServer(identity);
  console.log("combined E2E: cleanup web");
  if (web) await stopChild(web);
  console.log("combined E2E: cleanup postgres");
  if (postgres) await stopPostgres(postgres);
  console.log("combined E2E: cleanup remaining processes");
  for (const child of children.reverse()) await stopChild(child);
  console.log("combined E2E: cleanup files");
  await rm(temporaryRoot, { recursive: true, force: true });
}

async function startPostgres(port) {
  const data = path.join(temporaryRoot, "postgres-data");
  await command(path.join(postgresBin, "initdb"), ["--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username=zasp_e2e", "-D", data]);
  const child = startChild(path.join(postgresBin, "postgres"), ["-D", data, "-h", "127.0.0.1", "-p", String(port), "-k", ""]);
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const ready = await command(path.join(postgresBin, "pg_isready"), ["-h", "127.0.0.1", "-p", String(port), "-U", "zasp_e2e", "-d", "postgres"], { reject: false });
    if (ready.status === 0) return { child, data };
    await delay(25);
  }
  throw new Error(`disposable PostgreSQL did not become ready: ${child.output()}`);
}

async function stopPostgres(value) {
  await command(path.join(postgresBin, "pg_ctl"), ["-D", value.data, "-m", "fast", "-w", "stop"], { reject: false, timeout: 10_000 });
  await stopChild(value.child);
}

async function seedPostgres(dsn) {
  const sql = `
INSERT INTO zasp_authorized_scopes (principal_id, organization_id, workspace_id, environment_id, label, permissions, is_default) VALUES
('pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','Production','["view"]'::jsonb,true),
('pid_90000004-0000-4000-8000-000000000004','pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','pid_90000003-0000-4000-8000-000000000003','Foreign','["view"]'::jsonb,true);
INSERT INTO zasp_identity_memberships (principal_id, organization_id, organization_reference, member_reference, role) VALUES
('pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','organization-test-local','member-test-local','security_admin');
INSERT INTO zasp_core_payloads (organization_id, workspace_id, environment_id, operation, payload) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','session_bootstrap:pid_10000004-0000-4000-8000-000000000004','{"principal":{"id":"pid_10000004-0000-4000-8000-000000000004","organization_id":"pid_10000001-0000-4000-8000-000000000001","organization_reference":"organization-local","member_reference":"member-local","role":"security_admin","active":true},"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","permissions":["view"],"capabilities":["inventory.read","scope.switch"],"csrf_token":"cccccccccccccccccccccccccccccccc","correlation_id":"pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}'::jsonb),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','agents','{"items":[{"id":"pid_20000001-0000-4000-8000-000000000001","name":"Support agent","kind":"agent","owner":"security","team":"platform","tags":["production"],"evidence_id":"pid_20000006-0000-4000-8000-000000000006","first_seen":"2026-08-18T09:00:00Z","last_seen":"2026-08-18T10:00:00Z"}]}'::jsonb),
('pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','pid_90000003-0000-4000-8000-000000000003','agent:pid_90000001-0000-4000-8000-000000000001','{"id":"pid_90000001-0000-4000-8000-000000000001","name":"Foreign tenant agent","kind":"agent","owner":"foreign","team":"foreign","tags":[],"evidence_id":"pid_90000006-0000-4000-8000-000000000006","first_seen":"2026-08-18T09:00:00Z","last_seen":"2026-08-18T10:00:00Z"}'::jsonb);
`;
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1"], { input: sql });
}

async function startIdentityServer(port, publicOrigin) {
  const server = http.createServer(async (request, response) => {
    const target = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
    if (request.method === "GET" && target.pathname === "/v1/b2b/public/oauth/google/start") {
      assert.equal(target.searchParams.get("public_token"), "public-token-test-local");
      assert.equal(target.searchParams.get("organization_id"), "organization-test-local");
      const callback = new URL(target.searchParams.get("login_redirect_url"));
      assert.equal(callback.origin, publicOrigin);
      assert.equal(callback.pathname, "/auth/callback");
      assert.equal(target.searchParams.get("signup_redirect_url"), callback.toString());
      assert.ok((callback.searchParams.get("state") ?? "").length >= 32);
      callback.searchParams.set("token", "local-oauth-token");
      response.writeHead(302, { location: callback.toString() });
      response.end();
      return;
    }
    if (request.method === "POST" && target.pathname === "/v1/b2b/oauth/authenticate") {
      assert.equal(request.headers.authorization, `Basic ${Buffer.from("project-test-local:secret-test-local").toString("base64")}`);
      assert.deepEqual(JSON.parse(await readBody(request)), { oauth_token: "local-oauth-token", session_duration_minutes: 60 });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ status_code: 200, request_id: "request-id-test-oauth", member_id: "member-test-local", organization_id: "organization-test-local", session_jwt: "header.payload.signature" }));
      return;
    }
    if (request.method === "POST" && target.pathname === "/v1/b2b/sessions/authenticate") {
      assert.equal(request.headers.authorization, `Basic ${Buffer.from("project-test-local:secret-test-local").toString("base64")}`);
      assert.deepEqual(JSON.parse(await readBody(request)), { session_jwt: "header.payload.signature" });
      const now = new Date();
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ status_code: 200, request_id: "request-id-test-session", session_jwt: "header.payload.signature", member_session: { member_session_id: "member-session-test-local", member_id: "member-test-local", organization_id: "organization-test-local", started_at: now.toISOString(), last_accessed_at: now.toISOString(), expires_at: new Date(now.getTime() + 3_600_000).toISOString() } }));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  return server;
}

async function startProxy(port, apiPort, webPort, keyPath, certificatePath) {
  const server = https.createServer({ key: await readFile(keyPath), cert: await readFile(certificatePath) }, (request, response) => {
    const upstreamPort = request.url?.startsWith("/api/v1/") ? apiPort : webPort;
    const upstream = http.request({ hostname: "127.0.0.1", port: upstreamPort, method: request.method, path: request.url, headers: { ...request.headers, host: `127.0.0.1:${port}` } }, (upstreamResponse) => {
      if ((upstreamResponse.headers["set-cookie"] ?? []).some((value) => value.startsWith("__Host-zasp_session="))) observedSessionCookie = true;
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    });
    upstream.on("error", () => { response.writeHead(502); response.end("upstream unavailable"); });
    request.pipe(upstream);
  });
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  return server;
}

async function startBrowser(profile, port, target) {
  const child = startChild(chrome, ["--headless=new", "--no-first-run", "--disable-background-networking", "--disable-component-update", "--ignore-certificate-errors", `--user-data-dir=${profile}`, `--remote-debugging-port=${port}`, target]);
  let page;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      const pages = await fetch(`http://127.0.0.1:${port}/json/list`).then((response) => response.json());
      page = pages.find((value) => value.type === "page" && value.webSocketDebuggerUrl);
      if (page) break;
    } catch {
      page = undefined;
    }
    await delay(50);
  }
  if (!page) throw new Error(`browser debugging endpoint unavailable: ${child.output()}`);
  const cdp = await connectCDP(page.webSocketDebuggerUrl);
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  return { child, cdp };
}

async function waitForBrowserText(cdp, pattern) {
  let last = "";
  for (let attempt = 0; attempt < 300; attempt += 1) {
    const evaluated = await cdp.send("Runtime.evaluate", { expression: "document.body ? document.body.innerText : ''", returnByValue: true });
    last = evaluated.result?.value ?? "";
    if (pattern.test(last)) return last;
    await delay(50);
  }
  throw new Error(`browser text did not match ${pattern}: ${last}`);
}

async function connectCDP(target) {
  const socket = new WebSocket(target);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser debugging connection rejected")), { once: true });
  });
  let nextID = 0;
  const pending = new Map();
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (!message.id || !pending.has(message.id)) return;
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(message.error.message)); else resolve(message.result);
  });
  return {
    send(method, params = {}) {
      const id = ++nextID;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
    close() { socket.close(); },
  };
}

function startChild(executable, args, options = {}) {
  const child = spawn(executable, args, { cwd: options.cwd ?? root, env: options.env ?? process.env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (value) => { output += value; });
  child.stderr.on("data", (value) => { output += value; });
  child.output = () => output.slice(-16_384);
  children.push(child);
  return child;
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([once(child, "exit"), delay(5_000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await Promise.race([once(child, "exit"), delay(2_000)]);
  }
}

async function command(executable, args, options = {}) {
  const child = spawn(executable, args, { cwd: options.cwd ?? root, env: options.env ?? process.env, stdio: ["pipe", "pipe", "pipe"] });
	children.push(child);
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (value) => { stdout += value; });
  child.stderr.on("data", (value) => { stderr += value; });
  if (options.input) child.stdin.end(options.input); else child.stdin.end();
  const deadline = setTimeout(() => child.kill("SIGKILL"), options.timeout ?? 30_000);
  const [status] = await once(child, "exit");
  clearTimeout(deadline);
  const result = { status, stdout, stderr };
  if (status !== 0 && options.reject !== false) throw new Error(`${path.basename(executable)} failed (${status}): ${stderr || stdout}`);
  return result;
}

async function reservePort() {
  const server = net.createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await closeServer(server);
  return port;
}

async function waitForHTTP(target, expected, insecure = false) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const status = await new Promise((resolve) => {
      const transport = target.startsWith("https:") ? https : http;
      const request = transport.get(target, { rejectUnauthorized: !insecure }, (response) => { response.resume(); resolve(response.statusCode); });
      request.on("error", () => resolve(0));
    });
    if (status === expected) return;
    await delay(50);
  }
  throw new Error(`endpoint did not become ready: ${target}`);
}

async function readBody(request) {
  let body = "";
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 16_384) throw new Error("identity request too large");
  }
  return body;
}

async function closeServer(server) {
  server.closeAllConnections?.();
  server.close();
  if (server.listening) await Promise.race([once(server, "close"), delay(2_000)]);
}

function delay(milliseconds) { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }
