import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer as createHttpsServer } from "node:https";
import { pathToFileURL } from "node:url";

const maximumRequestBytes = 16_384;
const tokenContentType = "application/x-www-form-urlencoded";
const statePattern = /^[A-Za-z0-9_-]{16,128}$/;
const challengePattern = /^[A-Za-z0-9_-]{43,128}$/;
const secretPattern = /^[A-Za-z0-9._~-]{1,4096}$/;
const fixedFailureBody = Buffer.from('{"error":"invalid_request"}');

export function createFixtureProvider(configuration, dependencies = {}) {
  const validated = validateConfiguration(configuration);
  let authorizationUsed = false;
  let codeUsed = false;
  let retainedChallenge;
  let server;

  const handle = async (request) => {
    try {
      if (!plainObject(request) || typeof request.method !== "string" || typeof request.host !== "string" || typeof request.url !== "string" || !plainObject(request.headers) || !Buffer.isBuffer(request.body) || request.bodyComplete !== true || request.body.byteLength > maximumRequestBytes) {
        return rejected();
      }
      if (request.host !== validated.hostname) return rejected();
      if (request.method === "GET") {
        if (request.body.byteLength !== 0) return rejected();
        const result = validateAuthorizationRequest(request.url, validated);
        if (!result || authorizationUsed) return rejected();
        authorizationUsed = true;
        retainedChallenge = result.challenge;
        const separator = validated.callbackUrl.includes("?") ? "&" : "?";
        return {
          status: 302,
          headers: {
            location: `${validated.callbackUrl}${separator}code=${encodeURIComponent(validated.code)}&state=${encodeURIComponent(result.state)}`,
            "content-length": "0",
          },
          body: Buffer.alloc(0),
        };
      }
      if (request.method === "POST") {
        if (!authorizationUsed || codeUsed || request.url !== "/login/oauth/access_token") return rejected();
        if (!exactContentType(request.headers, tokenContentType)) return rejected();
        const form = parseUniqueForm(request.body);
        if (!form || !validTokenForm(form, validated, retainedChallenge)) return rejected();
        codeUsed = true;
        return {
          status: 200,
          headers: {
            "content-type": "application/json",
            "cache-control": "no-store",
            pragma: "no-cache",
          },
          body: Buffer.from(JSON.stringify({
            access_token: validated.accessToken,
            token_type: "bearer",
            scope: "",
          })),
        };
      }
      return rejected();
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
      const host = singleHeader(request.headers?.host);
      const result = await handle({
        method: request.method,
        host,
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
      if (size > maximumRequestBytes) {
        request.destroy?.();
        void finish();
      } else {
        chunks.push(value);
      }
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
    if (!Buffer.isBuffer(key) || !Buffer.isBuffer(certificate) || key.byteLength === 0 || certificate.byteLength === 0) {
      throw new TypeError("TLS material is invalid");
    }
    server = createServer({ key, cert: certificate }, listener);
    if (!server || typeof server.listen !== "function" || typeof server.close !== "function") {
      throw new TypeError("HTTPS server is invalid");
    }
    return server;
  };

  if (dependencies.createServer !== undefined || dependencies.key !== undefined || dependencies.certificate !== undefined) {
    ensureServer();
  }

  return Object.freeze({
    handle,
    state: () => ({ authorizationUsed, codeUsed }),
    listen: (port, host) => new Promise((resolve, reject) => {
      if (!Number.isInteger(port) || port < 1 || port > 65_535 || host !== "0.0.0.0") {
        reject(new TypeError("listen boundary is invalid"));
        return;
      }
      let target;
      try { target = ensureServer(); } catch (error) { reject(error); return; }
      const onError = () => reject(new TypeError("HTTPS listen failed"));
      target.once?.("error", onError);
      try {
        target.listen(port, host, () => {
          target.removeListener?.("error", onError);
          resolve();
        });
      } catch (error) {
        target.removeListener?.("error", onError);
        reject(error);
      }
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
    stdout.write("Nango OAuth fixture ready.\n");
    return 0;
  } catch {
    try { stderr?.write?.("Nango OAuth fixture failed.\n"); } catch { /* fixed boundary */ }
    return 1;
  }
}

export function configurationFromEnvironment(environment) {
  if (!plainObject(environment)) throw new TypeError("environment is invalid");
  return {
    clientId: environment.NANGO_OAUTH_CLIENT_ID,
    clientSecret: environment.NANGO_OAUTH_CLIENT_SECRET,
    code: environment.NANGO_OAUTH_CODE,
    accessToken: environment.NANGO_OAUTH_ACCESS_TOKEN,
    callbackUrl: environment.NANGO_OAUTH_CALLBACK_URL,
    hostname: environment.NANGO_OAUTH_HOSTNAME,
    tlsKeyPath: environment.NANGO_OAUTH_TLS_KEY_PATH,
    tlsCertificatePath: environment.NANGO_OAUTH_TLS_CERTIFICATE_PATH,
  };
}

function validateAuthorizationRequest(source, configuration) {
  let url;
  try { url = new URL(source, `https://${configuration.hostname}`); } catch { return undefined; }
  if (url.origin !== `https://${configuration.hostname}` || url.pathname !== "/login/oauth/authorize" || url.hash !== "") return undefined;
  const query = uniqueParameters(url.searchParams);
  if (!query) return undefined;
  const keys = [...query.keys()].sort();
  const required = ["client_id", "code_challenge", "code_challenge_method", "redirect_uri", "response_type", "state"];
  const withScope = [...required, "scope"].sort();
  if (!sameArray(keys, required.sort()) && !sameArray(keys, withScope)) return undefined;
  if (query.has("scope") && query.get("scope") !== "") return undefined;
  const state = query.get("state");
  const challenge = query.get("code_challenge");
  if (
    !safeEqual(query.get("client_id"), configuration.clientId) ||
    !safeEqual(query.get("redirect_uri"), configuration.callbackUrl) ||
    query.get("response_type") !== "code" || query.get("code_challenge_method") !== "S256" ||
    !statePattern.test(state ?? "") || !challengePattern.test(challenge ?? "")
  ) return undefined;
  return { state, challenge };
}

function validTokenForm(form, configuration, retainedChallenge) {
  const expectedKeys = ["grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"].sort();
  if (!sameArray([...form.keys()].sort(), expectedKeys)) return false;
  const verifier = form.get("code_verifier");
  if (!secretPattern.test(verifier ?? "") || !challengePattern.test(retainedChallenge ?? "")) return false;
  const derived = createHash("sha256").update(verifier).digest("base64url");
  return form.get("grant_type") === "authorization_code" &&
    safeEqual(form.get("code"), configuration.code) &&
    safeEqual(form.get("redirect_uri"), configuration.callbackUrl) &&
    safeEqual(form.get("client_id"), configuration.clientId) &&
    safeEqual(form.get("client_secret"), configuration.clientSecret) &&
    safeEqual(derived, retainedChallenge);
}

function parseUniqueForm(body) {
  if (!Buffer.isBuffer(body) || body.byteLength === 0 || body.byteLength > maximumRequestBytes) return undefined;
  let source;
  try { source = new TextDecoder("utf-8", { fatal: true }).decode(body); } catch { return undefined; }
  if (!/^(?:[A-Za-z0-9_.~-]|%[0-9A-F]{2}|[=&])+$/.test(source)) return undefined;
  const parameters = new URLSearchParams(source);
  return uniqueParameters(parameters);
}

function uniqueParameters(parameters) {
  const result = new Map();
  for (const [key, value] of parameters.entries()) {
    if (result.has(key)) return undefined;
    result.set(key, value);
  }
  return result;
}

function exactContentType(headers, expected) {
  const matches = Object.entries(headers).filter(([key]) => key.toLowerCase() === "content-type");
  return matches.length === 1 && matches[0][1] === expected;
}

function validateConfiguration(value) {
  if (!plainObject(value)) throw new TypeError("fixture configuration is invalid");
  const keys = Object.keys(value).sort();
  const baseKeys = ["clientId", "clientSecret", "code", "accessToken", "callbackUrl", "hostname"].sort();
  const tlsKeys = [...baseKeys, "tlsKeyPath", "tlsCertificatePath"].sort();
  if (!sameArray(keys, baseKeys) && !sameArray(keys, tlsKeys)) throw new TypeError("fixture configuration is invalid");
  if (
    value.hostname !== "github.com" || !boundedString(value.clientId, 1, 255) ||
    !secretPattern.test(value.clientSecret ?? "") || !secretPattern.test(value.code ?? "") ||
    !secretPattern.test(value.accessToken ?? "")
  ) throw new TypeError("fixture configuration is invalid");
  let callback;
  try { callback = new URL(value.callbackUrl); } catch { throw new TypeError("fixture configuration is invalid"); }
  if (
    callback.protocol !== "http:" || callback.port !== "3003" ||
    !/^zasp-m0-14b-[0-9a-f]{16}-server$/.test(callback.hostname) ||
    callback.pathname !== "/oauth/callback" || callback.search !== "" || callback.hash !== "" ||
    callback.username !== "" || callback.password !== ""
  ) throw new TypeError("fixture configuration is invalid");
  if (keys.length === tlsKeys.length && (!absolutePath(value.tlsKeyPath) || !absolutePath(value.tlsCertificatePath))) {
    throw new TypeError("fixture configuration is invalid");
  }
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

function singleHeader(value) {
  return typeof value === "string" ? value : "";
}

function rejected() {
  return {
    status: 400,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: Buffer.from(fixedFailureBody),
  };
}

function safeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.byteLength === b.byteLength && timingSafeEqual(a, b);
}

function sameArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function boundedString(value, minimum, maximum) {
  return typeof value === "string" && value.length >= minimum && value.length <= maximum && !value.includes("\0");
}

function absolutePath(value) {
  return typeof value === "string" && value.startsWith("/") && value.length <= 4_096 && !value.includes("\0");
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const code = await runMain(configurationFromEnvironment(process.env));
  process.exitCode = code;
}
