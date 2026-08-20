import { execFile } from "node:child_process";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const exec = promisify(execFile);
const entrypoint = "packages/server/dist/migrate.js";
const proofError = "Nango image proof rejected";

export const nangoImage = "nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed";

export async function runNangoImageProof() {
  let proofDirectory;
  try {
    await ensureImage();
    const boundary = ["--user", "1000:1000", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864"];
    await exec("docker", ["run", "--rm", "--platform", "linux/amd64", ...boundary, "--entrypoint", "node", nangoImage, "--check", entrypoint], commandOptions());
    await exec("docker", ["run", "--rm", "--platform", "linux/amd64", ...boundary, "--entrypoint", "/bin/sh", nangoImage, "-c", `test -f ${entrypoint} && test -f packages/server/lib/migrate.ts && test ! -e packages/server/lib/migrate.js`], commandOptions());
    await exec("docker", ["run", "--rm", "--platform", "linux/amd64", ...boundary, "--entrypoint", "node", nangoImage, "--input-type=module", "--eval", shutdownProofScript], commandOptions());
    proofDirectory = await createTLSProofDirectory();
    const proofDatabaseURL = new URL("postgres://db.nango.test:5432/nango?sslmode=verify-full");
    proofDatabaseURL.username = "nango";
    proofDatabaseURL.password = "fixture-only";
    await exec("docker", [
      "run", "--rm", "--platform", "linux/amd64", ...boundary,
      "--volume", `${proofDirectory}:/proof:ro`,
      "--env", "NODE_EXTRA_CA_CERTS=/proof/server.crt",
      "--env", `NANGO_DATABASE_URL=${proofDatabaseURL.href}`,
      "--env", "NANGO_DB_SSL=true",
      "--env", `RECORDS_DATABASE_URL=${proofDatabaseURL.href}`,
      "--env", "RECORDS_DATABASE_SSL=true",
      "--entrypoint", "node", nangoImage, "--input-type=module", "--eval", tlsProofScript,
    ], { ...commandOptions(), timeout: 30_000 });
    return Object.freeze({ image: nangoImage, migrationEntrypoint: entrypoint, databaseTLS: "verify-full", authEnabled: true, gracefulShutdown: true, readOnlyRoot: true, runtimeUser: "1000:1000", verified: true });
  } catch {
    throw new Error(proofError);
  } finally {
    if (proofDirectory) await rm(proofDirectory, { force: true, recursive: true });
  }
}

async function createTLSProofDirectory() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "zasp-nango-tls-proof-"));
  const openssl = async (arguments_) => exec("openssl", arguments_, { ...commandOptions(), cwd: directory });
  await openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=db.nango.test", "-addext", "subjectAltName=DNS:db.nango.test", "-keyout", "server.key", "-out", "server.crt"]);
  await openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=db.nango.test", "-addext", "subjectAltName=DNS:db.nango.test", "-keyout", "untrusted.key", "-out", "untrusted.crt"]);
  await Promise.all(["server.key", "server.crt", "untrusted.key", "untrusted.crt"].map((name) => chmod(path.join(directory, name), 0o644)));
  return directory;
}

const tlsProofScript = String.raw`
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import tls from "node:tls";

const require = createRequire(import.meta.url);
const ConnectionParameters = require("/app/nango/node_modules/pg/lib/connection-parameters.js");
const { getDbConfig } = await import("file:///app/nango/packages/database/dist/getConfig.js");
const { config: recordsConfig } = await import("file:///app/nango/packages/records/dist/db/config.js");
const { flagHasAuth } = await import("file:///app/nango/packages/utils/dist/environment/detection.js");

if (!flagHasAuth) throw new Error("auth disabled");
const connections = [getDbConfig({ timeoutMs: 5000 }).connection, recordsConfig.connection]
  .map((value) => new ConnectionParameters(value));
for (const connection of connections) {
  if (connection.host !== "db.nango.test" || typeof connection.ssl !== "object" || connection.ssl === null || connection.ssl.rejectUnauthorized === false) {
    throw new Error("database TLS not verified");
  }
}

const trusted = { key: await readFile("/proof/server.key"), cert: await readFile("/proof/server.crt") };
const untrusted = { key: await readFile("/proof/untrusted.key"), cert: await readFile("/proof/untrusted.crt") };

async function proveTLS(serverCredentials, servername, shouldPass) {
  const server = tls.createServer(serverCredentials, (socket) => socket.end());
  server.on("tlsClientError", () => {});
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  let passed = false;
  try {
    await new Promise((resolve, reject) => {
      const client = tls.connect({ host: "127.0.0.1", port, servername, ...connections[0].ssl }, () => {
        if (!client.authorized) reject(client.authorizationError ?? new Error("unauthorized"));
        else resolve();
        client.end();
      });
      client.once("error", reject);
    });
    passed = true;
  } catch {
    passed = false;
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
  if (passed !== shouldPass) throw new Error("unexpected TLS result");
}

await proveTLS(trusted, "db.nango.test", true);
await proveTLS(trusted, "wrong.nango.test", false);
await proveTLS(untrusted, "db.nango.test", false);
`;

const shutdownProofScript = String.raw`
import { readFile } from "node:fs/promises";
const source = await readFile("packages/server/dist/server.js", "utf8");
for (const contract of ["server.close(async () =>", "process.on('SIGTERM'", "beginShutdown();", "await db.destroy();", "await destroyRecords();"]) {
  if (!source.includes(contract)) process.exit(1);
}
`;

async function ensureImage() {
  try {
    await exec("docker", ["image", "inspect", nangoImage], commandOptions());
  } catch {
    await exec("docker", ["pull", "--platform", "linux/amd64", nangoImage], { ...commandOptions(), timeout: 120_000 });
  }
}

function commandOptions() {
  return { encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 15_000, env: { PATH: process.env.PATH ?? "" } };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runNangoImageProof().then(() => {
    process.stdout.write("Nango image proof passed.\n");
  }).catch(() => {
    process.stdout.write("Nango image proof failed.\n");
    process.exitCode = 1;
  });
}
