#!/usr/bin/env node
// The local stack's TLS front. It terminates HTTPS on the public origin,
// serves the built web application, and forwards /api to the product API with
// exactly the headers the production ingress sends. It has no dependencies
// beyond Node. On a developer machine it listens on loopback only. The
// evaluation Helm chart (deploy/kubernetes/zasp) runs the same file in a pod,
// where it must accept connections from the pod network.
//
// Settings (set by stack.sh, or by the chart's entrypoint):
//   ZASP_FRONT_ORIGIN    public origin, for example https://zasp.local-stack.test:8443
//   ZASP_FRONT_API       product API listener, for example http://127.0.0.1:4000
//   ZASP_FRONT_WEB_DIR   the built standalone web application (dist/standalone)
//   ZASP_FRONT_WEB_PORT  loopback port the web application is started on
//   ZASP_FRONT_CERT, ZASP_FRONT_KEY  the server certificate chain and its key
//   ZASP_FRONT_LISTEN       optional address to listen on; default 127.0.0.1
//   ZASP_FRONT_LISTEN_PORT  optional port to listen on; default the origin's port
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";

const setting = (name) => {
  const value = process.env[name];
  if (!value) {
    console.error(`front: ${name} is required`);
    process.exit(2);
  }
  return value;
};

const origin = new URL(setting("ZASP_FRONT_ORIGIN"));
const api = new URL(setting("ZASP_FRONT_API"));
const webDirectory = setting("ZASP_FRONT_WEB_DIR");
const webPort = Number.parseInt(setting("ZASP_FRONT_WEB_PORT"), 10);
if (origin.protocol !== "https:" || api.protocol !== "http:" || !(webPort > 0 && webPort < 65536)) {
  console.error("front: the origin must be https, the API http, and the web port a port number");
  process.exit(2);
}
const publicPort = origin.port || "443";
// The port this process binds may differ from the origin's: behind a port
// forward or a load balancer the origin is on 443 and the pod on 8443.
const listenAddress = process.env.ZASP_FRONT_LISTEN || "127.0.0.1";
const listenPort = Number.parseInt(process.env.ZASP_FRONT_LISTEN_PORT || publicPort, 10);
if (!(listenPort > 0 && listenPort < 65536)) {
  console.error("front: ZASP_FRONT_LISTEN_PORT must be a port number");
  process.exit(2);
}

// Headers that describe one connection and are never forwarded.
const hopByHop = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]);

// The API accepts a request only when Host and the X-Forwarded-* headers name
// the public origin, each exactly once, and no Forwarded header is present.
// Anything the browser sent under those names is dropped and replaced.
function upstreamHeaders(incoming, remoteAddress) {
  const headers = {};
  for (const [name, value] of Object.entries(incoming)) {
    if (hopByHop.has(name) || name === "forwarded" || name.startsWith("x-forwarded-") || name === "host") continue;
    headers[name] = value;
  }
  headers.host = origin.host;
  headers["x-forwarded-proto"] = "https";
  headers["x-forwarded-host"] = origin.host;
  headers["x-forwarded-port"] = publicPort;
  headers["x-forwarded-for"] = (remoteAddress ?? "127.0.0.1").replace(/^::ffff:/, "").replace(/^::1$/, "127.0.0.1");
  return headers;
}

function refuse(response, status, message) {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
  response.end(`${message}\n`);
}

function forward(request, response, target, forApi) {
  const upstream = http.request({
    host: target.hostname,
    port: target.port,
    method: request.method,
    path: request.url,
    headers: upstreamHeaders(request.headers, request.socket.remoteAddress),
  }, (answer) => {
    const headers = {};
    for (const [name, value] of Object.entries(answer.headers)) {
      if (!hopByHop.has(name)) headers[name] = value;
    }
    // The production ingress sets this on every response. The sign-in callback
    // carries a single-use token in its address.
    headers["referrer-policy"] = "no-referrer";
    response.writeHead(answer.statusCode ?? 502, headers);
    answer.pipe(response);
  });
  upstream.on("error", () => {
    refuse(response, 502, forApi
      ? "The product API is not answering on " + api.host + ". Check 'stack.sh status'."
      : "The web application is not answering yet. Try again in a few seconds.");
  });
  response.on("close", () => upstream.destroy());
  request.pipe(upstream);
}

const web = spawn(process.execPath, [path.join(webDirectory, "server.js")], {
  cwd: webDirectory,
  env: { ...process.env, NODE_ENV: "production", HOST: "127.0.0.1", PORT: String(webPort) },
  stdio: ["ignore", "inherit", "inherit"],
});
let stopping = false;
web.on("exit", (code, signal) => {
  if (stopping) return;
  console.error(`front: the web application stopped (${signal ?? code}); is port ${webPort} in use?`);
  process.exit(1);
});
web.on("error", (error) => {
  console.error(`front: the web application did not start: ${error.message}`);
  process.exit(1);
});

const server = https.createServer({
  cert: readFileSync(setting("ZASP_FRONT_CERT")),
  key: readFileSync(setting("ZASP_FRONT_KEY")),
}, (request, response) => {
  // The session cookie and the sign-in redirect are bound to the public
  // origin. Any other name for this listener would sign nobody in.
  if (request.headers.host !== origin.host) {
    refuse(response, 421, `This is the Zasp local stack. Open ${origin.origin}/ (it needs '127.0.0.1 ${origin.hostname}' in /etc/hosts).`);
    return;
  }
  const pathname = (request.url ?? "/").split("?")[0];
  if (pathname === "/api" || pathname.startsWith("/api/")) forward(request, response, api, true);
  else forward(request, response, new URL(`http://127.0.0.1:${webPort}`), false);
});
server.on("error", (error) => {
  console.error(`front: cannot listen on ${listenAddress}:${listenPort}: ${error.message}`);
  stopping = true;
  web.kill("SIGTERM");
  process.exit(1);
});
server.listen(listenPort, listenAddress, () => {
  console.log(`front: ${origin.origin}/ -> web application on 127.0.0.1:${webPort}, /api -> ${api.origin}`);
});

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    stopping = true;
    web.kill("SIGTERM");
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  });
}
