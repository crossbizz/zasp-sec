import { isDeepStrictEqual } from "node:util";

export const PROOF_LABEL = "m0-14a";

const markerPattern = /^[0-9a-f]{16}$/;
const passwordPattern = /^[A-Za-z0-9_-]{32}$/;
const encryptionKeyPattern = /^[A-Za-z0-9+/]{43}=$/;
const supportedPlatforms = new Set(["linux/amd64", "linux/arm64"]);
const maximumJsonBytes = 65_536;
const maximumJsonDepth = 16;
const maximumCollectionSize = 256;
const maximumStringLength = 8_192;

export const PINS = deepFreeze({
  nango: {
    version: "v0.70.5",
    sourceCommit: "7faf2c303bbb0322333f526e9ca31c0fe95ef58e",
    sourceTagObject: "bf8ea10293c20c6d8affff754205851011023285",
    reference: "nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed",
    platform: "linux/amd64",
    manifestDigest: "sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed",
    configDigest: "sha256:41de4cc7a0061baefb846306d6666f74ddd4ca46d0b51b7bd24ffa2581a482d9",
  },
  postgres: {
    version: "16.0-alpine",
    reference: "postgres:16.0-alpine@sha256:acf5271bbecd4b8733f4e93959a8d2b536a57aeee6cc4b6a71890aaf646425b8",
  },
  probe: {
    version: "1.36.1-1",
    reference: "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
  },
});

export function validateMarker(value) {
  if (typeof value !== "string" || !markerPattern.test(value)) {
    throw new TypeError("proof marker is invalid");
  }
  return value;
}

export function buildRuntimeSpec(input) {
  expectPlainObject(input, "runtime input");
  const marker = validateMarker(input.marker);
  if (typeof input.platform !== "string" || !supportedPlatforms.has(input.platform)) {
    throw new TypeError("runtime platform is unsupported");
  }
  if (typeof input.password !== "string" || !passwordPattern.test(input.password)) {
    throw new TypeError("database password is invalid");
  }
  if (!validEncryptionKey(input.encryptionKey)) {
    throw new TypeError("Nango encryption key is invalid");
  }

  const prefix = `zasp-m0-14a-${marker}`;
  const networkName = `${prefix}-network`;
  const databaseContainerName = `${prefix}-db`;
  const nangoContainerName = `${prefix}-server`;
  const databaseName = `nango_${marker}`;
  // v0.70.5 contains a migration that explicitly targets nango._nango_sync_jobs.
  // Isolation comes from the per-run database/container, so retain that pinned
  // schema name instead of pretending the upstream migration is configurable.
  const databaseSchema = "nango";
  // The same pinned migration set explicitly targets nango_records.* indexes.
  // Both fixed upstream schema names remain isolated by the per-run database.
  const recordsSchema = "nango_records";
  const databaseUser = `proof_${marker}`;
  const connectionUrl = `postgresql://${databaseUser}:${encodeURIComponent(input.password)}@${databaseContainerName}:5432/${databaseName}`;
  const commonLabels = {
    "zasp.dev/proof": PROOF_LABEL,
    "zasp.dev/run": marker,
  };
  const roleLabels = (role) => ({ ...commonLabels, "zasp.dev/role": role });
  const endpoint = `http://${nangoContainerName}:3003/ready`;

  return deepFreeze({
    marker,
    prefix,
    platform: input.platform,
    serviceRoles: ["database", "nango"],
    network: {
      name: networkName,
      internal: true,
      labels: roleLabels("network"),
    },
    database: {
      role: "database",
      name: databaseContainerName,
      network: networkName,
      networkAlias: databaseContainerName,
      labels: roleLabels("database"),
      image: PINS.postgres.reference,
      platform: input.platform,
      databaseName,
      schema: databaseSchema,
      recordsSchema,
      user: databaseUser,
      environment: {
        PGDATA: "/var/lib/postgresql/data/pgdata",
        POSTGRES_DB: databaseName,
        POSTGRES_PASSWORD: input.password,
        POSTGRES_USER: databaseUser,
      },
      publishedPorts: {},
      tmpfs: {
        "/var/lib/postgresql/data": "rw,nosuid,nodev,size=256m",
        "/tmp": "rw,noexec,nosuid,nodev,size=16m",
      },
    },
    nango: {
      role: "nango",
      name: nangoContainerName,
      network: networkName,
      networkAlias: nangoContainerName,
      labels: roleLabels("nango"),
      image: PINS.nango.reference,
      platform: PINS.nango.platform,
      internalPort: 3003,
      environment: {
        CSP_REPORT_ONLY: "true",
        FLAG_AUTH_ROLES_ENABLED: "false",
        FLAG_SERVE_CONNECT_UI: "false",
        NANGO_CLOUD: "false",
        NANGO_DATABASE_URL: connectionUrl,
        NANGO_DB_APPLICATION_NAME: "zasp-m0-14a-proof",
        NANGO_DB_NAME: databaseName,
        NANGO_DB_POOL_MAX: "4",
        NANGO_DB_POOL_MIN: "0",
        NANGO_DB_SCHEMA: databaseSchema,
        NANGO_DB_SSL: "false",
        NANGO_ENCRYPTION_KEY: input.encryptionKey,
        NANGO_ENTERPRISE: "false",
        NANGO_LOGS_ENABLED: "false",
        NANGO_MIGRATE_AT_START: "true",
        NANGO_PUBLIC_SERVER_URL: `http://${nangoContainerName}:3003`,
        NANGO_SERVER_URL: `http://${nangoContainerName}:3003`,
        NANGO_TELEMETRY_SDK: "false",
        RECORDS_DATABASE_POOL_MAX: "4",
        RECORDS_DATABASE_POOL_MIN: "0",
        RECORDS_DATABASE_SCHEMA: recordsSchema,
        RECORDS_DATABASE_URL: connectionUrl,
        SERVER_PORT: "3003",
      },
      publishedPorts: {},
      readOnlyRootfs: true,
      tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=32m" },
    },
    probe: {
      role: "probe",
      name: `${prefix}-probe`,
      network: networkName,
      networkAlias: `${prefix}-probe`,
      labels: roleLabels("probe"),
      image: PINS.probe.reference,
      platform: input.platform,
      endpoint,
      expectedOutput: '{"result":"ok"}',
      environment: {},
      publishedPorts: {},
      readOnlyRootfs: true,
      tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=8m" },
      command: [
        "sh",
        "-ec",
        `expected=/tmp/zasp-ready.expected; response=/tmp/zasp-ready.response; header=/tmp/zasp-ready.header; body=/tmp/zasp-ready.body; separator=/tmp/zasp-ready.separator; printf '%s' '{"result":"ok"}' > "$expected"; printf '\r\n\r\n' > "$separator"; for attempt in $(seq 1 240); do rm -f "$response" "$header" "$body"; if printf 'GET /ready HTTP/1.1\r\nHost: ${nangoContainerName}:3003\r\nConnection: close\r\n\r\n' | nc -w 2 ${nangoContainerName} 3003 > "$response" 2>/dev/null; then size=$(wc -c < "$response"); header_size=$(awk '{ total += length($0) + 1; if ($0 == "\\r") { print total; exit } }' "$response"); if [ -n "$header_size" ] && [ "$size" -eq $((header_size + 15)) ]; then head -c "$header_size" "$response" > "$header"; tail -c 15 "$response" > "$body"; status=$(head -n 1 "$header"); if [ "$status" = "$(printf 'HTTP/1.1 200 OK\r')" ] && tail -c 4 "$header" | cmp -s "$separator" - && cmp -s "$expected" "$body"; then cat "$body"; exit 0; fi; fi; fi; sleep 1; done; exit 1`,
      ],
    },
  });
}

export function parseBoundedUniqueJson(input) {
  const source = decodeBoundedUtf8(input);
  let index = 0;
  const whitespace = () => {
    while (index < source.length && /[\t\n\r ]/.test(source[index])) index += 1;
  };
  const parseString = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid JSON string");
    const start = index;
    index += 1;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') {
        index += 1;
        const value = JSON.parse(source.slice(start, index));
        if (value.length > maximumStringLength || hasUnpairedSurrogate(value)) {
          throw new SyntaxError("invalid JSON string");
        }
        return value;
      }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid JSON string");
      if (character !== "\\") {
        index += 1;
        continue;
      }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) index += 1;
      else if (escape === "u" && /^[a-fA-F0-9]{4}$/.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError("invalid JSON escape");
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const parseValue = (depth) => {
    if (depth > maximumJsonDepth) throw new SyntaxError("JSON nesting is excessive");
    whitespace();
    if (source[index] === "{") {
      index += 1;
      whitespace();
      const entries = [];
      const keys = new Set();
      if (source[index] === "}") { index += 1; return {}; }
      while (true) {
        const key = parseString();
        if (keys.has(key) || keys.size >= maximumCollectionSize) {
          throw new SyntaxError("duplicate or excessive JSON object");
        }
        keys.add(key);
        whitespace();
        if (source[index] !== ":") throw new SyntaxError("invalid JSON object");
        index += 1;
        entries.push([key, parseValue(depth + 1)]);
        whitespace();
        if (source[index] === "}") { index += 1; return Object.fromEntries(entries); }
        if (source[index] !== ",") throw new SyntaxError("invalid JSON object");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1;
      whitespace();
      const output = [];
      if (source[index] === "]") { index += 1; return output; }
      while (true) {
        output.push(parseValue(depth + 1));
        if (output.length > maximumCollectionSize) throw new SyntaxError("JSON array is excessive");
        whitespace();
        if (source[index] === "]") { index += 1; return output; }
        if (source[index] !== ",") throw new SyntaxError("invalid JSON array");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === '"') return parseString();
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, index)) { index += literal.length; return value; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
    if (number === null) throw new SyntaxError("invalid JSON value");
    index += number[0].length;
    const parsed = Number(number[0]);
    if (!Number.isFinite(parsed)) throw new SyntaxError("invalid JSON number");
    return parsed;
  };
  const output = parseValue(0);
  whitespace();
  if (index !== source.length) throw new SyntaxError("trailing JSON data");
  return output;
}

export function parseReadyOutput(input) {
  const source = exactBytes(input);
  const output = parseBoundedUniqueJson(source);
  if (
    Buffer.compare(source, Buffer.from('{"result":"ok"}')) !== 0 ||
    !isPlainObject(output) ||
    !isDeepStrictEqual(Object.keys(output), ["result"]) ||
    output.result !== "ok"
  ) {
    throw new TypeError("Nango readiness output is invalid");
  }
  return output;
}

function validEncryptionKey(value) {
  if (typeof value !== "string" || !encryptionKeyPattern.test(value)) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.byteLength === 32 && decoded.toString("base64") === value;
}

function exactBytes(value) {
  if (typeof value === "string") {
    if (hasUnpairedSurrogate(value)) throw new SyntaxError("invalid UTF-8 input");
    return Buffer.from(value, "utf8");
  }
  if (!(value instanceof Uint8Array)) throw new TypeError("JSON input is invalid");
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function decodeBoundedUtf8(value) {
  const bytes = exactBytes(value);
  if (bytes.byteLength === 0 || bytes.byteLength > maximumJsonBytes) {
    throw new SyntaxError("JSON byte size is invalid");
  }
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new SyntaxError("JSON is not valid UTF-8");
  }
  if (source.charCodeAt(0) === 0xfeff) throw new SyntaxError("JSON BOM is invalid");
  return source;
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return true;
  }
  return false;
}

function expectPlainObject(value, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} is invalid`);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
