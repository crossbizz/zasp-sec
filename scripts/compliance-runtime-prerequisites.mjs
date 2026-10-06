import path from "node:path";

const required = Object.freeze([
  "ZASP_RUNTIME_SERVICES_ENABLED", "ZASP_RUNTIME_SERVICES_TIMEOUT",
  "ZASP_TEMPORAL_ADDRESS", "ZASP_TEMPORAL_NAMESPACE", "ZASP_TEMPORAL_TASK_QUEUE",
  "ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE", "ZASP_OPENFGA_URL", "ZASP_OPENFGA_STORE_ID",
  "ZASP_OPENFGA_MODEL_ID", "ZASP_OPENFGA_TOKEN_FILE",
]);
const optional = Object.freeze([
  "ZASP_TEMPORAL_TLS_CA_FILE", "ZASP_TEMPORAL_TLS_CERT_FILE", "ZASP_TEMPORAL_TLS_KEY_FILE",
  "ZASP_OPENFGA_TLS_CA_FILE",
]);
const name = /^[a-z][a-z0-9._-]{1,127}$/;
const ulid = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const unsafeText = /[\r\n\t\0]/;

function refuse(fields) {
  const error = new Error(`compliance browser runtime prerequisites refused: ${[...new Set(fields)].sort().join(", ")}; owned Temporal/OpenFGA and current authorization schema bootstrap/readiness remain required`);
  error.code = "ZASP_COMPLIANCE_RUNTIME_PREREQUISITE_REFUSED";
  throw error;
}
function absolute(value) {
  return typeof value === "string" && path.isAbsolute(value) && !unsafeText.test(value) && !value.split(path.sep).includes("..");
}

// Configuration validation only. No service, model, namespace, token contents,
// database schema, production readiness or provider authority is established.
export function complianceRuntimeBindings(environment) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) refuse(["runtime environment"]);
  const missing = required.filter(key => typeof environment[key] !== "string" || environment[key] === "" || unsafeText.test(environment[key]));
  if (missing.length) refuse(missing);
  const bad = [];
  if (environment.ZASP_RUNTIME_SERVICES_ENABLED !== "true") bad.push("ZASP_RUNTIME_SERVICES_ENABLED");
  const timeout = /^(\d+(?:\.\d+)?)(ms|s)$/.exec(environment.ZASP_RUNTIME_SERVICES_TIMEOUT);
  // Match Go time.ParseDuration's truncation to whole nanoseconds for ms/s.
  // A positive decimal below 1ns is zero to the production runtime.
  let timeoutNanoseconds = 0;
  if (timeout) {
    const precision = timeout[2] === "s" ? 9 : 6;
    const [whole, fraction = ""] = timeout[1].split(".");
    timeoutNanoseconds = Number(whole) * 10 ** precision + Number(fraction.slice(0, precision).padEnd(precision, "0"));
  }
  if (!timeout || timeoutNanoseconds < 1 || timeoutNanoseconds > 30_000_000_000) bad.push("ZASP_RUNTIME_SERVICES_TIMEOUT");
  for (const key of ["ZASP_TEMPORAL_NAMESPACE", "ZASP_TEMPORAL_TASK_QUEUE", "ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE"]) if (!name.test(environment[key])) bad.push(key);
  if (environment.ZASP_TEMPORAL_TASK_QUEUE === environment.ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE) bad.push("ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE");
  const address = /^(127\.0\.0\.1|localhost|\[::1\]):([1-9]\d{0,4})$/.exec(environment.ZASP_TEMPORAL_ADDRESS);
  if (!address || Number(address[2]) > 65535) bad.push("ZASP_TEMPORAL_ADDRESS");
  try {
    const url = new URL(environment.ZASP_OPENFGA_URL);
    if (!/^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::[1-9]\d{0,4})?$/.test(environment.ZASP_OPENFGA_URL) || !["http:", "https:"].includes(url.protocol) || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) bad.push("ZASP_OPENFGA_URL");
  } catch { bad.push("ZASP_OPENFGA_URL"); }
  for (const key of ["ZASP_OPENFGA_STORE_ID", "ZASP_OPENFGA_MODEL_ID"]) if (!ulid.test(environment[key])) bad.push(key);
  if (!absolute(environment.ZASP_OPENFGA_TOKEN_FILE)) bad.push("ZASP_OPENFGA_TOKEN_FILE");
  for (const key of optional) if (environment[key] && !absolute(environment[key])) bad.push(key);
  const tls = optional.slice(0, 3);
  if (tls.some(key => environment[key]) && !tls.every(key => absolute(environment[key]))) bad.push(...tls.filter(key => !absolute(environment[key])));
  if (bad.length) refuse(bad);
  const bindings = Object.fromEntries([...required, ...optional].filter(key => environment[key] !== undefined).map(key => [key, environment[key]]));
  return Object.freeze({ status: "CONFIG_VALIDATED_ONLY", runtimeReadiness: "NOT_CHECKED", schemaReadiness: "NOT_CHECKED", environment: Object.freeze(bindings) });
}


export function complianceOwnedRuntimeInputs(environment) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) refuse(["runtime environment"]);
  const keys = ["ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT", "ZASP_BROWSER_RUNTIME_RAW_ROOT"];
  const invalid = keys.filter(key => !absolute(environment[key]));
  if (environment[keys[0]] === environment[keys[1]]) invalid.push(...keys);
  if (invalid.length) refuse(invalid);
  return Object.freeze({ status:"CONFIG_VALIDATED_ONLY", runtimeReadiness:"NOT_CHECKED", schemaReadiness:"NOT_CHECKED" });
}
