import { basename, isAbsolute, join, resolve } from "node:path";

import { PINS } from "../nango-free-boot/manifest.mjs";
import { validateApiKeyMarker } from "./boundary.mjs";

export { validateApiKeyMarker };

export const API_KEY_PROOF_LABEL = "m0-14c";
export const API_KEY_PINS = PINS;

const passwordPattern = /^[A-Za-z0-9_-]{32}$/;
const encryptionKeyPattern = /^[A-Za-z0-9+/]{43}=$/;
const providerKeyPattern = /^eyJ[A-Za-z0-9_-]{16}\.ey[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{32}$/;
const supportedPlatforms = new Set(["linux/amd64", "linux/arm64"]);

export function buildApiKeyRuntimeSpec(input) {
  validateInput(input);
  const marker = validateApiKeyMarker(input.marker);
  const prefix = `zasp-m0-14c-${marker}`;
  const expectedRootPrefix = `${prefix}-`;
  const rootName = basename(input.workspaceRoot);
  if (!rootName.startsWith(expectedRootPrefix) || !/^[A-Za-z0-9]{6}$/.test(rootName.slice(expectedRootPrefix.length))) throw new TypeError("API-key workspace root is invalid");
  if (input.dockerConfigPath !== join(input.workspaceRoot, "docker-config")) throw new TypeError("Docker config path is invalid");
  if (input.caCertificatePath !== join(input.workspaceRoot, "tls", "ca.crt")) throw new TypeError("CA path is invalid");
  if (input.fixtureCertificatePath !== join(input.workspaceRoot, "tls", "server.crt")) throw new TypeError("fixture certificate path is invalid");
  if (input.fixtureKeyPath !== join(input.workspaceRoot, "tls", "server.key")) throw new TypeError("fixture key path is invalid");

  const networkName = `${prefix}-network`;
  const databaseName = `nango_${marker}`;
  const databaseUser = `proof_${marker}`;
  const databaseContainerName = `${prefix}-db`;
  const nangoContainerName = `${prefix}-server`;
  const fixtureContainerName = `${prefix}-fixture`;
  const wrapperContainerName = `${prefix}-wrapper`;
  const connectionUrl = `postgresql://${databaseUser}:${encodeURIComponent(input.password)}@${databaseContainerName}:5432/${databaseName}`;
  const labels = (role) => ({ "zasp.dev/proof": API_KEY_PROOF_LABEL, "zasp.dev/run": marker, "zasp.dev/role": role });
  const common = (role, name, image, platform) => ({ role, name, network: networkName, labels: labels(role), image, platform, publishedPorts: {} });

  return deepFreeze({
    marker,
    prefix,
    platform: input.platform,
    roles: ["database", "nango", "fixture", "wrapper"],
    dockerConfigPath: input.dockerConfigPath,
    network: { name: networkName, internal: true, labels: labels("network") },
    database: {
      ...common("database", databaseContainerName, PINS.postgres.reference, input.platform),
      networkAlias: databaseContainerName,
      databaseName,
      schema: "nango",
      recordsSchema: "nango_records",
      user: databaseUser,
      environment: { PGDATA: "/var/lib/postgresql/data/pgdata", POSTGRES_DB: databaseName, POSTGRES_PASSWORD: input.password, POSTGRES_USER: databaseUser },
      readOnlyRootfs: true,
      tmpfs: { "/var/lib/postgresql/data": "rw,nosuid,nodev,size=256m", "/var/run/postgresql": "rw,nosuid,nodev,size=16m", "/tmp": "rw,noexec,nosuid,nodev,size=16m" },
      mounts: [],
    },
    nango: {
      ...common("nango", nangoContainerName, PINS.nango.reference, PINS.nango.platform),
      networkAlias: nangoContainerName,
      environment: {
        CSP_REPORT_ONLY: "true",
        FLAG_AUTH_ENABLED: "false",
        FLAG_AUTH_ROLES_ENABLED: "false",
        FLAG_SERVE_CONNECT_UI: "false",
        NANGO_CLOUD: "false",
        NANGO_DATABASE_URL: connectionUrl,
        NANGO_DB_APPLICATION_NAME: "zasp-m0-14c-proof",
        NANGO_DB_NAME: databaseName,
        NANGO_DB_POOL_MAX: "4",
        NANGO_DB_POOL_MIN: "0",
        NANGO_DB_SCHEMA: "nango",
        NANGO_DB_SSL: "false",
        NANGO_ENCRYPTION_KEY: input.encryptionKey,
        NANGO_ENTERPRISE: "false",
        NANGO_LOGS_ENABLED: "false",
        NANGO_MIGRATE_AT_START: "true",
        NANGO_PUBLIC_CONNECT_URL: `http://${nangoContainerName}:3003/connect`,
        NANGO_PUBLIC_SERVER_URL: `http://${nangoContainerName}:3003`,
        NANGO_SERVER_URL: `http://${nangoContainerName}:3003`,
        NANGO_TELEMETRY_SDK: "false",
        NODE_EXTRA_CA_CERTS: "/proof/tls/ca.crt",
        RECORDS_DATABASE_POOL_MAX: "4",
        RECORDS_DATABASE_POOL_MIN: "0",
        RECORDS_DATABASE_SCHEMA: "nango_records",
        RECORDS_DATABASE_URL: connectionUrl,
        SERVER_PORT: "3003",
      },
      readOnlyRootfs: true,
      tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=32m" },
      mounts: [{ source: input.caCertificatePath, target: "/proof/tls/ca.crt", readOnly: true }],
    },
    fixture: {
      ...common("fixture", fixtureContainerName, PINS.nango.reference, PINS.nango.platform),
      networkAlias: "events.1password.com",
      environment: {
        NANGO_API_KEY_HOSTNAME: "events.1password.com",
        NANGO_API_KEY_PROVIDER_KEY: input.providerKey,
        NANGO_API_KEY_TLS_CERTIFICATE_PATH: "/proof/tls/server.crt",
        NANGO_API_KEY_TLS_KEY_PATH: "/proof/tls/server.key",
      },
      entrypoint: ["/usr/local/bin/node"],
      command: ["/proofs/nango-api-key/fixture_provider.mjs"],
      readOnlyRootfs: true,
      tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=16m" },
      mounts: [
        { source: input.proofSourcePath, target: "/proofs", readOnly: true },
        { source: input.fixtureCertificatePath, target: "/proof/tls/server.crt", readOnly: true },
        { source: input.fixtureKeyPath, target: "/proof/tls/server.key", readOnly: true },
      ],
    },
    wrapper: {
      ...common("wrapper", wrapperContainerName, PINS.nango.reference, PINS.nango.platform),
      networkAlias: wrapperContainerName,
      environment: {
        NODE_EXTRA_CA_CERTS: "/proof/tls/ca.crt",
        NANGO_API_KEY_BASE_URL: `http://${nangoContainerName}:3003`,
        NANGO_API_KEY_END_USER_ID: `user_${marker}`,
        NANGO_API_KEY_ENVIRONMENT: "dev",
        NANGO_API_KEY_FORBIDDEN_VALUES: [input.password, input.encryptionKey].join(","),
        NANGO_API_KEY_INTEGRATION_KEY: `${prefix}-1password-events`,
        NANGO_API_KEY_ORGANIZATION_ID: `org_${marker}`,
        NANGO_API_KEY_PROVIDER_KEY: input.providerKey,
      },
      entrypoint: ["/usr/local/bin/node"],
      command: ["/proofs/nango-api-key/product_wrapper.mjs"],
      readOnlyRootfs: true,
      tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=16m" },
      mounts: [
        { source: input.proofSourcePath, target: "/proofs", readOnly: true },
        { source: input.caCertificatePath, target: "/proof/tls/ca.crt", readOnly: true },
      ],
    },
  });
}

function validateInput(input) {
  if (!plainObject(input)) throw new TypeError("API-key runtime input is invalid");
  const expected = ["marker", "platform", "password", "encryptionKey", "providerKey", "workspaceRoot", "dockerConfigPath", "caCertificatePath", "fixtureCertificatePath", "fixtureKeyPath", "proofSourcePath"].sort();
  const actual = Object.keys(input).sort();
  if (!sameArray(actual, expected)) throw new TypeError("API-key runtime input is invalid");
  validateApiKeyMarker(input.marker);
  if (!supportedPlatforms.has(input.platform) || !passwordPattern.test(input.password) || !validEncryptionKey(input.encryptionKey) || !providerKeyPattern.test(input.providerKey)) throw new TypeError("API-key runtime secret is invalid");
  for (const path of [input.workspaceRoot, input.dockerConfigPath, input.caCertificatePath, input.fixtureCertificatePath, input.fixtureKeyPath, input.proofSourcePath]) {
    if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path || path.includes("\0")) throw new TypeError("API-key runtime path is invalid");
  }
}

function validEncryptionKey(value) { if (typeof value !== "string" || !encryptionKeyPattern.test(value)) return false; const decoded = Buffer.from(value, "base64"); return decoded.byteLength === 32 && decoded.toString("base64") === value; }
function sameArray(left, right) { return left.length === right.length && left.every((value, index) => value === right[index]); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function deepFreeze(value) { if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value; for (const child of Object.values(value)) deepFreeze(child); return Object.freeze(value); }
