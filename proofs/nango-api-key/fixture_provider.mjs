import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer as createHttpsServer } from "node:https";
import { pathToFileURL } from "node:url";

const maximumRequestBytes = 16_384;
const providerKeyPattern = /^eyJ[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const fixedFailureBody = Buffer.from('{"error":"invalid_request"}');
const fixedSuccessBody = Buffer.from('{"features":[],"items":[]}');

export function createFixtureProvider(configuration, dependencies = {}) {
  const validated = validateConfiguration(configuration);
  let verificationUsed = false;
  let server;

  const handle = async (request) => {
    try {
      if (!plainObject(request) || typeof request.method !== "string" || typeof request.host !== "string" || typeof request.url !== "string" || !plainObject(request.headers) || !Buffer.isBuffer(request.body) || request.bodyComplete !== true || request.body.byteLength > maximumRequestBytes) return rejected();
      if (verificationUsed || request.host !== validated.hostname || request.method !== "GET" || request.url !== "/api/v2/auth/introspect" || request.body.byteLength !== 0) return rejected();
      if (!exactHeader(request.headers, "accept", "application/json, text/plain, */*") || !exactHeader(request.headers, "authorization", `Bearer ${validated.providerKey}`)) return rejected();
      verificationUsed = true;
      return {
        status: 200,
        headers: { "content-type": "application/json", "cache-control": "no-store" },
        body: Buffer.from(fixedSuccessBody),
      };
    } catch {
      return rejected();
    }
  };

  const listener = (request, response) => {
    const chunks = [];
    let size = 0;
    let complete = false;
    let responded = false;
    const finish = async () => {
      if (responded) return;
      responded = true;
      const result = await handle({
        method: request.method,
        host: singleHeader(request.headers?.host),
        url: request.url,
        headers: normalizeHeaders(request.headers),
        body: Buffer.concat(chunks),
        bodyComplete: complete,
      });
      response.writeHead(result.status, result.headers);
      response.end(result.body);
    };
    request.on("data", (chunk) => {
      if (responded) return;
      let value;
      try { value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); }
      catch { void finish(); return; }
      size += value.byteLength;
      if (size > maximumRequestBytes) { request.destroy?.(); void finish(); }
      else chunks.push(value);
    });
    request.once("end", () => { complete = true; void finish(); });
    request.once("aborted", () => { void finish(); });
    request.once("error", () => { void finish(); });
  };

  const ensureServer = () => {
    if (server) return server;
    const createServer = dependencies.createServer ?? createHttpsServer;
    if (typeof createServer !== "function") throw new TypeError("HTTPS server factory is invalid");
    const key = dependencies.key ?? readBoundedTlsFile(validated.tlsKeyPath);
    const certificate = dependencies.certificate ?? readBoundedTlsFile(validated.tlsCertificatePath);
    if (!Buffer.isBuffer(key) || !Buffer.isBuffer(certificate) || key.byteLength === 0 || certificate.byteLength === 0 || key.byteLength > 32_768 || certificate.byteLength > 32_768) throw new TypeError("TLS material is invalid");
    server = createServer({ key, cert: certificate }, listener);
    if (!server || typeof server.listen !== "function" || typeof server.close !== "function") throw new TypeError("HTTPS server is invalid");
    return server;
  };

  if (dependencies.createServer !== undefined || dependencies.key !== undefined || dependencies.certificate !== undefined) ensureServer();

  return Object.freeze({
    handle,
    state: () => ({ verificationUsed }),
    listen: (port, host) => new Promise((resolve, reject) => {
      if (!Number.isInteger(port) || port < 1 || port > 65_535 || host !== "0.0.0.0") { reject(new TypeError("listen boundary is invalid")); return; }
      let target;
      try { target = ensureServer(); } catch (error) { reject(error); return; }
      const onError = () => reject(new TypeError("HTTPS listen failed"));
      target.once?.("error", onError);
      try { target.listen(port, host, () => { target.removeListener?.("error", onError); resolve(); }); }
      catch (error) { target.removeListener?.("error", onError); reject(error); }
    }),
    close: () => new Promise((resolve, reject) => {
      if (!server) { resolve(); return; }
      try { server.close((error) => error ? reject(new TypeError("HTTPS close failed")) : resolve()); }
      catch (error) { reject(error); }
    }),
  });
}

export async function runMain(configuration, dependencies = {}) {
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  try {
    if (typeof stdout?.write !== "function" || typeof stderr?.write !== "function") return 1;
    const fixture = createFixtureProvider(configuration, dependencies);
    await fixture.listen(443, "0.0.0.0");
    stdout.write("Nango API-key fixture ready.\n");
    return 0;
  } catch {
    try { stderr?.write?.("Nango API-key fixture failed.\n"); } catch { /* fixed boundary */ }
    return 1;
  }
}

export function configurationFromEnvironment(environment) {
  if (!environmentRecord(environment)) throw new TypeError("environment is invalid");
  return {
    hostname: environment.NANGO_API_KEY_HOSTNAME,
    providerKey: environment.NANGO_API_KEY_PROVIDER_KEY,
    tlsKeyPath: environment.NANGO_API_KEY_TLS_KEY_PATH,
    tlsCertificatePath: environment.NANGO_API_KEY_TLS_CERTIFICATE_PATH,
  };
}

function validateConfiguration(value) {
  if (!plainObject(value)) throw new TypeError("fixture configuration is invalid");
  const keys = Object.keys(value).sort();
  const baseKeys = ["hostname", "providerKey"].sort();
  const tlsKeys = [...baseKeys, "tlsKeyPath", "tlsCertificatePath"].sort();
  if (!sameArray(keys, baseKeys) && !sameArray(keys, tlsKeys)) throw new TypeError("fixture configuration is invalid");
  if (value.hostname !== "events.1password.com" || !providerKeyPattern.test(value.providerKey ?? "")) throw new TypeError("fixture configuration is invalid");
  if (keys.length === tlsKeys.length && (!absolutePath(value.tlsKeyPath) || !absolutePath(value.tlsCertificatePath))) throw new TypeError("fixture configuration is invalid");
  return Object.freeze({ ...value });
}

function readBoundedTlsFile(path) {
  if (!absolutePath(path)) throw new TypeError("TLS path is invalid");
  let value;
  try { value = readFileSync(path); } catch { throw new TypeError("TLS material is unavailable"); }
  if (!Buffer.isBuffer(value) || value.byteLength === 0 || value.byteLength > 32_768) throw new TypeError("TLS material is invalid");
  return value;
}

function normalizeHeaders(headers) {
  if (!plainObject(headers)) return {};
  const output = {};
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === "string") output[key.toLowerCase()] = value;
    else if (Array.isArray(value) && value.length === 1 && typeof value[0] === "string") output[key.toLowerCase()] = value[0];
  }
  return output;
}

function exactHeader(headers, name, expected) {
  const matches = Object.entries(headers).filter(([key]) => key.toLowerCase() === name);
  if (matches.length !== 1 || typeof matches[0][1] !== "string") return false;
  return safeEqual(matches[0][1], expected);
}

function rejected() { return { status: 400, headers: { "content-type": "application/json", "cache-control": "no-store" }, body: Buffer.from(fixedFailureBody) }; }
function safeEqual(left, right) { if (typeof left !== "string" || typeof right !== "string") return false; const a = Buffer.from(left); const b = Buffer.from(right); return a.byteLength === b.byteLength && timingSafeEqual(a, b); }
function singleHeader(value) { return typeof value === "string" ? value : ""; }
function sameArray(left, right) { return left.length === right.length && left.every((value, index) => value === right[index]); }
function absolutePath(value) { return typeof value === "string" && value.startsWith("/") && value.length <= 4_096 && !value.includes("\0"); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function environmentRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.exitCode = await runMain(configurationFromEnvironment(process.env)); }
  catch { process.stderr.write("Nango API-key fixture failed.\n"); process.exitCode = 1; }
}
