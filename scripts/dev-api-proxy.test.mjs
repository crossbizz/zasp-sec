import assert from "node:assert/strict";
import { createServer as createHTTPServer } from "node:http";
import { once } from "node:events";
import test from "node:test";
import { createServer as createViteServer } from "vite";
import { createDevAPIProxy } from "./dev-api-proxy.mjs";

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return `http://127.0.0.1:${server.address().port}`;
}

// Actual owned HTTP/Vite requests, rather than an assertion that config contains
// a target. The tokens below are synthetic fixture values, never printed.
test("development API routing preserves browser security headers, cookies and product errors", { timeout: 15_000 }, async () => {
  const received = [];
  const backend = createHTTPServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received.push({ method: request.method, body: Buffer.concat(chunks).toString(), url: request.url, origin: request.headers.origin, host: request.headers.host, cookie: request.headers.cookie, csrf: request.headers["x-csrf-token"] });
    response.writeHead(401, { "Content-Type": "application/json", "Set-Cookie": "fixture-session=revoked; HttpOnly; Path=/; SameSite=Lax" });
    response.end(JSON.stringify({ code: "unauthorized" }));
  });
  let vite;
  try {
    const target = await listen(backend);
    vite = await createViteServer({ configFile: false, root: process.cwd(), server: { host: "127.0.0.1", port: 0, proxy: createDevAPIProxy(target) }, logLevel: "silent" });
    await vite.listen();
    const origin = `http://127.0.0.1:${vite.httpServer.address().port}`;
    const response = await fetch(`${origin}/api/v1/session/bootstrap?source=login`, { headers: { Origin: origin, Cookie: "fixture-session=synthetic", "X-CSRF-Token": "fixture-csrf" } });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { code: "unauthorized" });
    assert.equal(response.headers.get("set-cookie"), "fixture-session=revoked; HttpOnly; Path=/; SameSite=Lax");
    assert.deepEqual(received, [{ method: "GET", body: "", url: "/api/v1/session/bootstrap?source=login", origin, host: new URL(origin).host, cookie: "fixture-session=synthetic", csrf: "fixture-csrf" }]);
    const mutation = await fetch(`${origin}/api/v1/session/scope`, { method: "PUT", headers: { Origin: origin, Cookie: "fixture-session=synthetic", "X-CSRF-Token": "fixture-csrf", "Content-Type": "application/json" }, body: JSON.stringify({ workspace_id: "fixture-workspace" }) });
    assert.equal(mutation.status, 401);
    await mutation.text();
    assert.deepEqual(received[1], { method: "PUT", body: '{"workspace_id":"fixture-workspace"}', url: "/api/v1/session/scope", origin, host: new URL(origin).host, cookie: "fixture-session=synthetic", csrf: "fixture-csrf" });
    await fetch(`${origin}/api-other`);
    assert.equal(received.length, 2, "non-API routes must stay on the web server");
  } finally {
    if (vite) await vite.close();
    backend.closeAllConnections();
    if (backend.listening) await new Promise((resolve, reject) => backend.close(error => error ? reject(error) : resolve()));
  }
});

test("absent development authority leaves API routing unconfigured", () => {
  assert.equal(createDevAPIProxy(undefined), undefined);
  assert.equal(createDevAPIProxy(""), undefined);
});

test("development authority rejects credentials, ambiguous URL components and insecure remote origins", () => {
  for (const origin of ["http://api.example.test", "https://user:secret@api.example.test", "http://@localhost:8080", "https://api.example.test/path", "https://api.example.test/../", "https://api.example.test?token=x", "https://api.example.test#fragment", " https://api.example.test", "//api.example.test", "file:///tmp/api", "http://localhost.evil.test", "http://0.0.0.0:8080"]) {
    assert.throws(() => createDevAPIProxy(origin), /Invalid ZASP_DEV_API_ORIGIN/, "invalid authority must refuse startup without including its value");
  }
});

test("development authority accepts HTTPS and explicit loopback without changing TLS or cookie authority", () => {
  for (const origin of ["https://api.example.test", "http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"]) {
    const proxy = createDevAPIProxy(origin);
    assert.equal(proxy["^/api(?:/|$)"].target, origin);
    assert.equal(proxy["^/api(?:/|$)"].secure, true);
    assert.equal(proxy["^/api(?:/|$)"].changeOrigin, false);
    assert.equal(proxy["^/api(?:/|$)"].cookieDomainRewrite, undefined);
    assert.equal(proxy["^/api(?:/|$)"].rewrite, undefined);
  }
});
