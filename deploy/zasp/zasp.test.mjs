// Tests of the ./zasp entry point: argument handling, the configuration file,
// doctor against missing and present prerequisites, the commands each profile
// runs (against stand-ins for docker, helm, kubectl, terraform and the local
// stack script), and the evaluation Helm chart.
//
//   node --test deploy/zasp/zasp.test.mjs
//
// The chart is rendered when a `helm` program is on PATH (or named by
// ZASP_TEST_HELM); without one those tests are skipped and say so.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { loadAll } from "js-yaml";

import { createFakeIdentityProvider } from "./testing/fake-identity-provider.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const zasp = join(root, "zasp");
const chart = join(root, "deploy", "kubernetes", "zasp");
const stack = join(root, "deploy", "local", "real-stack", "stack.sh");

const which = name => {
  const found = spawnSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8" });
  return found.status === 0 ? found.stdout.trim() : "";
};
const bash = which("bash");
const helm = process.env.ZASP_TEST_HELM || which("helm");
// The programs the scripts themselves need. A sandbox PATH holds only these,
// plus whatever stand-ins a test adds, so "not installed" can be tested.
const basics = ["bash", "sh", "env", "sed", "grep", "dirname", "basename", "cat", "head", "tail", "tr", "stat", "find", "sort", "mktemp",
  "chmod", "mkdir", "ln", "rm", "cp", "mv", "date", "tar", "gzip", "cmp", "id", "wc", "ls", "sleep", "tee", "touch", "seq", "git"];

function sandbox({ tools = {}, real = [], config = "", profile = "local" } = {}) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "zasp-test-")));
  const bin = join(base, "bin");
  mkdirSync(bin);
  for (const name of [...basics, ...real]) {
    const path = which(name);
    if (path) symlinkSync(path, join(bin, name));
  }
  const calls = join(base, "calls.log");
  for (const [name, body] of Object.entries(tools)) {
    writeFileSync(join(bin, name), `#!${bash}\nprintf '%s' "${name}" >> "${calls}"; printf ' %s' "$@" >> "${calls}"; printf '\\n' >> "${calls}"\n${body}\n`);
    chmodSync(join(bin, name), 0o755);
  }
  const file = join(base, "zasp.env");
  writeFileSync(file, `ZASP_PROFILE=${profile}\n${config}`, { mode: 0o600 });
  const hosts = join(base, "hosts");
  writeFileSync(hosts, "127.0.0.1 localhost\n");
  const run = (args, extra = {}) => spawnSync(bash, [zasp, "--config", file, ...args], {
    encoding: "utf8",
    cwd: base,
    env: { PATH: bin, HOME: base, ZASP_HOSTS_FILE: hosts, ZASP_STATE_DIR: join(base, "state"), ZASP_REAL_STACK_OWNER_FILE: join(base, "owner"), ...extra },
  });
  return {
    base, bin, file, hosts, run, state: join(base, "state"),
    calls: () => (existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").filter(Boolean) : []),
    done: () => rmSync(base, { recursive: true, force: true }),
  };
}
const output = result => `${result.stdout}\n${result.stderr}`;

// --- arguments and configuration ---------------------------------------------

test("without a command the usage is printed and the exit status is 2", () => {
  const box = sandbox();
  try {
    const result = box.run([]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /usage: zasp/);
    for (const command of ["doctor", "secrets init", "install", "bootstrap-admin", "up", "start", "stop", "status", "logs", "upgrade", "backup", "restore", "uninstall"]) {
      assert.match(result.stderr, new RegExp(`\\b${command}\\b`), command);
    }
  } finally { box.done(); }
});

test("an unknown command and an unknown profile are refused", () => {
  const box = sandbox();
  try {
    const command = box.run(["explode"]);
    assert.equal(command.status, 1);
    assert.match(command.stderr, /unknown command 'explode'/);
    const profile = box.run(["--profile", "mainframe", "status"]);
    assert.equal(profile.status, 1);
    assert.match(profile.stderr, /unknown profile 'mainframe'/);
  } finally { box.done(); }
});

test("the configuration file is data: nothing in it is executed, quotes are removed, the environment wins", () => {
  const marker = join(tmpdir(), `zasp-test-marker-${process.pid}`);
  const box = sandbox({
    tools: { stack: 'echo "name=$ZASP_ORGANIZATION_NAME domain=$ZASP_ORGANIZATION_DOMAIN email=$ZASP_ADMIN_EMAIL"' },
    config: `ZASP_ORGANIZATION_NAME="Example $(touch ${marker}) Security"\nexport ZASP_ORGANIZATION_DOMAIN='example.test'\n  ZASP_ADMIN_EMAIL=admin@example.test   \n# a comment\n\n`,
  });
  try {
    const result = box.run(["bootstrap-admin"], { ZASP_LOCAL_STACK_SCRIPT: join(box.bin, "stack"), ZASP_ADMIN_EMAIL: "owner@example.test" });
    assert.equal(result.status, 0, output(result));
    assert.equal(existsSync(marker), false, "a command substitution in the configuration file ran");
    assert.deepEqual(box.calls(), [`stack bootstrap Example $(touch ${marker}) Security example.test owner@example.test`]);
  } finally { box.done(); rmSync(marker, { force: true }); }
});

test("a configuration line that is not KEY=VALUE is refused with its line number", () => {
  const box = sandbox({ config: "this is not a setting\n" });
  try {
    const result = box.run(["status"]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /line 2 is not KEY=VALUE/);
  } finally { box.done(); }
});

test("config init writes a private file from the example and never replaces one", () => {
  const box = sandbox();
  try {
    const target = join(box.base, "fresh.env");
    const first = spawnSync(bash, [zasp, "--config", target, "--profile", "kubernetes", "config", "init"], { encoding: "utf8", env: { PATH: box.bin, HOME: box.base } });
    assert.equal(first.status, 0, output(first));
    assert.equal(statSync(target).mode & 0o777, 0o600);
    assert.match(readFileSync(target, "utf8"), /^ZASP_PROFILE=kubernetes$/m);
    writeFileSync(target, "ZASP_PROFILE=local\n");
    const second = spawnSync(bash, [zasp, "--config", target, "config", "init"], { encoding: "utf8", env: { PATH: box.bin, HOME: box.base } });
    assert.equal(second.status, 0);
    assert.match(second.stdout, /already exists/);
    assert.equal(readFileSync(target, "utf8"), "ZASP_PROFILE=local\n");
  } finally { box.done(); }
});

test("the example configuration parses and names every profile's settings", () => {
  const example = readFileSync(join(here, "zasp.env.example"), "utf8");
  for (const line of example.split("\n")) {
    if (line === "" || line.startsWith("#")) continue;
    assert.match(line, /^[A-Z][A-Z0-9_]*=/, line);
  }
  for (const name of ["ZASP_PROFILE", "STYTCH_PROJECT_ID", "STYTCH_SECRET", "STYTCH_PUBLIC_TOKEN", "ZASP_ADMIN_EMAIL", "OPENROUTER_API_KEY", "ZASP_ORIGIN",
    "ZASP_DEPENDENCIES", "ZASP_KUBE_VALUES", "ZASP_IMAGE_REGISTRY", "ZASP_AWS_TFVARS", "ZASP_AWS_VALUES", "ZASP_AWS_OPERATOR_DSN_FILE"]) {
    assert.match(example, new RegExp(`^#?${name}=`, "m"), name);
  }
});

// --- doctor --------------------------------------------------------------------

test("local doctor lists every missing prerequisite and exits 1", () => {
  const box = sandbox();
  try {
    const result = box.run(["doctor"]);
    assert.equal(result.status, 1, output(result));
    for (const expected of [
      /MISSING {2}curl is not installed/, /MISSING {2}openssl is not installed/, /MISSING {2}go is not installed/, /MISSING {2}node is not installed/,
      /MISSING {2}docker is not installed/, /MISSING {2}zasp\.local-stack\.test is not mapped to this machine/,
      /run: echo '127\.0\.0\.1 zasp\.local-stack\.test' \| sudo tee -a \/etc\/hosts/,
      /MISSING {2}STYTCH_PROJECT_ID is not set/, /MISSING {2}STYTCH_SECRET is not set/, /MISSING {2}STYTCH_PUBLIC_TOKEN is not set/,
      /warn {5}ZASP_ADMIN_EMAIL is not set/, /warn {5}OPENROUTER_API_KEY is not set/, /Fix every MISSING line/,
    ]) assert.match(result.stdout, expected);
  } finally { box.done(); }
});

test("local doctor passes when the prerequisites are present, and never prints a setting's value", () => {
  const secret = "secret-test-do-not-print-0123456789";
  const box = sandbox({
    tools: { curl: "", openssl: "", go: "", node: "echo v0.0.0", npm: "", docker: "exit 0" },
    config: `STYTCH_PROJECT_ID=project-test-example\nSTYTCH_SECRET=${secret}\nSTYTCH_PUBLIC_TOKEN=public-token-test-example\n` +
      "ZASP_ORGANIZATION_NAME=Example\nZASP_ORGANIZATION_DOMAIN=example.test\nZASP_ADMIN_EMAIL=admin@example.test\nOPENROUTER_API_KEY=placeholder-model-key\n",
  });
  try {
    writeFileSync(box.hosts, "127.0.0.1 localhost\n127.0.0.1   zasp.local-stack.test # zasp\n");
    const result = box.run(["doctor"]);
    assert.equal(output(result).includes(secret), false);
    // The key files live in the state directory: nothing needs root.
    const missing = result.stdout.split("\n").filter(line => line.startsWith("  MISSING  "));
    assert.deepEqual(missing, [], result.stdout);
    assert.match(result.stdout, /ok {7}.*\/state\/runtime is writable \(key files and analyzers; no root needed\)/);
    assert.equal(result.stdout.includes("sudo mkdir"), false, result.stdout);
    // 'system' asks for the paths a pod has; where those cannot be written,
    // doctor says how to create them and how to go back.
    const system = box.run(["doctor"], { ZASP_RUNTIME_DIR: "system" });
    assert.equal(system.stdout.includes("/state/runtime"), false, system.stdout);
    const systemMissing = system.stdout.split("\n").filter(line => line.startsWith("  MISSING  "));
    for (const line of systemMissing) assert.match(line, /\/var\/run\//);
    assert.equal(system.status, systemMissing.length ? 1 : 0, system.stdout);
    if (systemMissing.length) assert.match(system.stdout, /Fix every MISSING line/);
    assert.match(box.run(["doctor"], { ZASP_RUNTIME_DIR: "relative" }).stdout, /MISSING.*ZASP_RUNTIME_DIR must be an absolute directory or 'system'/);
    for (const expected of [/ok {7}docker \(/, /ok {7}the Docker daemon answers/, /ok {7}docker compose/, /ok {7}zasp\.local-stack\.test resolves to this machine/,
      /ok {7}STYTCH_SECRET is set/, /ok {7}public origin https:\/\/zasp\.local-stack\.test:8443/]) assert.match(result.stdout, expected);
  } finally { box.done(); }
});

test("local doctor refuses an origin the product would refuse", () => {
  for (const [origin, message] of [["http://zasp.example.test", /must start with https/], ["https://localhost:8443", /refused by the connector sign-in callbacks/],
    ["https://192.0.2.10:8443", /is an IP address/], ["https://zasp.local", /refused by the connector sign-in callbacks/]]) {
    const box = sandbox({ config: `ZASP_ORIGIN=${origin}\n` });
    try {
      const result = box.run(["doctor"]);
      assert.equal(result.status, 1);
      assert.match(result.stdout, message, origin);
    } finally { box.done(); }
  }
});

test("local doctor in native mode asks for the native programs instead of Docker", () => {
  const box = sandbox({ config: "ZASP_DEPENDENCIES=native\n", tools: { pg_ctl: "", initdb: "" } });
  try {
    // An explicit bin directory controls native startup even on a host with PostgreSQL on PATH.
    const result = box.run(["doctor"], { ZASP_POSTGRES_BIN: join(box.base, "missing-postgres") });
    assert.doesNotMatch(result.stdout, /docker is not installed|Docker daemon/);
    for (const expected of [/MISSING {2}PostgreSQL 18 server programs/, /MISSING {2}openfga is not installed/, /MISSING {2}temporal is not installed/,
      /MISSING {2}moto_server is not installed/, /MISSING {2}aws is not installed/, /warn {5}native dependencies are a reduced stack/]) assert.match(result.stdout, expected);
    const installed = box.run(["doctor"], { ZASP_POSTGRES_BIN: box.bin });
    assert.match(installed.stdout, /ok {7}PostgreSQL server programs/);
    rmSync(join(box.bin, "initdb"));
    const incomplete = box.run(["doctor"], { ZASP_POSTGRES_BIN: box.bin });
    assert.match(incomplete.stdout, /MISSING {2}PostgreSQL 18 server programs/);
  } finally { box.done(); }
});

// --- profile local ---------------------------------------------------------------

const localTools = { curl: "", openssl: 'if [ "$1" = dgst ]; then cat >/dev/null; echo "SHA2-256(stdin)= abc"; fi', go: "", node: "echo v0.0.0", npm: "", docker: "exit 0" };
const localConfig = "STYTCH_PROJECT_ID=project-test-example\nSTYTCH_SECRET=secret-test-example\nSTYTCH_PUBLIC_TOKEN=public-token-test-example\n";
// A stand-in for stack.sh that behaves like it where zasp depends on it.
const stackStub = state => `
case "$1" in
  up) mkdir -p "${state}" && : > "${state}/up.done" ;;
  bootstrap) echo 'ZASP_STYTCH_ORGANIZATION_ID=organization-test-1' > "${state}/organization.env"; echo '{"organization_reference":"organization-test-1"}' ;;
  verify) [ ! -f "${state}/stale" ] || exit 1; echo '{"sealed":true,"intact":true,"artifact":"x","current":true}' ;;
  dump) echo '-- dump' > "$2/postgres.sql" ;;
esac`;

function localBox(config = "") {
  const box = sandbox({ tools: localTools, config: localConfig + config });
  writeFileSync(box.hosts, "127.0.0.1 zasp.local-stack.test\n");
  writeFileSync(join(box.bin, "stack"), `#!${bash}\nprintf 'stack' >> "${box.base}/calls.log"; printf ' %s' "$@" >> "${box.base}/calls.log"; printf '\\n' >> "${box.base}/calls.log"\n${stackStub(box.state)}\n`);
  chmodSync(join(box.bin, "stack"), 0o755);
  const run = (args, extra = {}) => box.run(args, { ZASP_LOCAL_STACK_SCRIPT: join(box.bin, "stack"), ...extra });
  return { ...box, run, stackCalls: () => box.calls().filter(line => line.startsWith("stack ")) };
}
test("up installs, creates the first administrator from the configuration and starts, in that order", () => {
  const box = localBox("ZASP_ORGANIZATION_NAME=Example Security\nZASP_ORGANIZATION_DOMAIN=example.test\nZASP_ADMIN_EMAIL=admin@example.test\n");
  try {
    const result = box.run(["up"]);
    assert.equal(result.status, 0, output(result));
    assert.deepEqual(box.stackCalls(), ["stack up", "stack bootstrap Example Security example.test admin@example.test", "stack start"]);
    assert.match(result.stdout, /Open {7}https:\/\/zasp\.local-stack\.test:8443\//);
    assert.match(result.stdout, /Sign in/);
    // A second run does not bootstrap again.
    assert.equal(box.run(["up"]).status, 0);
    assert.deepEqual(box.stackCalls().slice(3), ["stack up", "stack start"]);
  } finally { box.done(); }
});

test("up without the first administrator's settings stops after the schema and says what to run", () => {
  const box = localBox();
  try {
    const result = box.run(["up"]);
    assert.equal(result.status, 1);
    assert.deepEqual(box.stackCalls(), ["stack up"]);
    assert.match(result.stderr, /\.\/zasp bootstrap-admin '<organization name>' <email domain> <administrator email>/);
  } finally { box.done(); }
});

test("install refuses to start when doctor finds something missing", () => {
  const box = sandbox();
  try {
    const result = box.run(["install"], { ZASP_LOCAL_STACK_SCRIPT: "/nonexistent" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /prerequisites are missing/);
  } finally { box.done(); }
});

test("stop, status and bootstrap-admin map to the stack script; destructive commands need --yes", () => {
  const box = localBox();
  try {
    assert.equal(box.run(["stop"]).status, 0);
    assert.equal(box.run(["status"]).status, 0);
    assert.equal(box.run(["bootstrap-admin", "Example", "example.test", "admin@example.test"]).status, 0);
    const refused = box.run(["uninstall"]);
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /--yes/);
    assert.equal(box.run(["uninstall", "--yes"]).status, 0);
    assert.deepEqual(box.stackCalls(), ["stack down", "stack status", "stack bootstrap Example example.test admin@example.test", "stack reset --yes"]);
    const partial = box.run(["bootstrap-admin", "Example"]);
    assert.equal(partial.status, 1);
    assert.match(partial.stderr, /usage: zasp bootstrap-admin/);
  } finally { box.done(); }
});

test("upgrade rebuilds and restarts, and explains a schema that cannot be upgraded in place", () => {
  const box = localBox();
  try {
    const early = box.run(["upgrade"]);
    assert.equal(early.status, 1);
    assert.match(early.stderr, /nothing is installed yet/);
    mkdirSync(box.state, { recursive: true });
    writeFileSync(join(box.state, "up.done"), "");
    const result = box.run(["upgrade"]);
    assert.equal(result.status, 0, output(result));
    assert.deepEqual(box.stackCalls(), ["stack stop", "stack build", "stack verify", "stack start"]);
    assert.equal(existsSync(join(box.state, "up.done")), false, "'start' must repeat the installation steps");
    writeFileSync(join(box.state, "up.done"), "");
    writeFileSync(join(box.state, "stale"), "");
    const stale = box.run(["upgrade"]);
    assert.equal(stale.status, 1);
    assert.match(stale.stderr, /no in-place schema upgrade/);
    assert.match(stale.stderr, /\.\/zasp uninstall --yes/);
    assert.equal(box.stackCalls().at(-1), "stack verify");
  } finally { box.done(); }
});

test("backup writes one private archive with the dump, the keys and a manifest; restore checks what it is given", () => {
  const box = localBox();
  try {
    assert.equal(box.run(["backup"]).status, 1, "nothing installed, nothing to back up");
    mkdirSync(join(box.state, "secrets"), { recursive: true });
    writeFileSync(join(box.state, "up.done"), "");
    writeFileSync(join(box.state, "secrets", "keys.env"), "ZASP_WORKFLOW_SIGNING_KEY=not-a-real-key\n");
    writeFileSync(join(box.state, "fga.env"), "ZASP_OPENFGA_STORE_ID=x\n");
    const archive = join(box.base, "backup.tar.gz");
    const result = box.run(["backup", archive]);
    assert.equal(result.status, 0, output(result));
    assert.equal(statSync(archive).mode & 0o777, 0o600);
    const listing = spawnSync("tar", ["-tzf", archive], { encoding: "utf8" }).stdout;
    for (const entry of ["manifest", "dump/postgres.sql", "state/secrets/keys.env", "state/fga.env"]) assert.match(listing, new RegExp(`^${entry}$`, "m"), entry);
    assert.equal(box.run(["backup", archive]).status, 1, "an existing archive is not overwritten");

    const refused = box.run(["restore", archive]);
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /--yes/);
    writeFileSync(join(box.base, "junk.tar.gz"), "not an archive");
    assert.match(box.run(["restore", join(box.base, "junk.tar.gz"), "--yes"]).stderr, /not a readable archive/);
    rmSync(join(box.state, "secrets"), { recursive: true });
    const restored = box.run(["restore", archive, "--yes"]);
    assert.equal(restored.status, 0, output(restored));
    assert.equal(readFileSync(join(box.state, "secrets", "keys.env"), "utf8"), "ZASP_WORKFLOW_SIGNING_KEY=not-a-real-key\n");
    assert.match(box.stackCalls().at(-1), /^stack load .*\/dump$/);
    const other = box.run(["restore", archive, "--yes"], { ZASP_DEPENDENCIES: "native" });
    assert.equal(other.status, 1);
    assert.match(other.stderr, /dependencies=docker/);
  } finally { box.done(); }
});

test("the web dependencies are never reinstalled through a symbolic link", () => {
  // 'npm ci' empties the directory a node_modules link points to.
  const source = readFileSync(join(here, "lib", "local.sh"), "utf8");
  const guard = source.indexOf('[ ! -L "$ZASP_ROOT/node_modules" ]');
  const install = source.indexOf('run npm ci');
  assert.ok(guard > 0 && install > guard, "the symbolic link check must come before npm ci");
});

// --- the local stack script ------------------------------------------------------

test("stack.sh refuses an unknown dependency mode, and native mode names the missing PostgreSQL programs", () => {
  const box = sandbox();
  try {
    const env = { PATH: box.bin, HOME: box.base, ZASP_REAL_STACK_STATE: box.state, ZASP_REAL_STACK_OWNER_FILE: join(box.base, "owner") };
    const unknown = spawnSync(bash, [stack, "status"], { encoding: "utf8", env: { ...env, ZASP_REAL_STACK_DEPENDENCIES: "podman" } });
    assert.equal(unknown.status, 1);
    assert.match(unknown.stderr, /must be 'docker' or 'native'/);
    const native = spawnSync(bash, [stack, "up"], { encoding: "utf8", env: {
      ...env, ZASP_REAL_STACK_DEPENDENCIES: "native", ZASP_REAL_STACK_PG_BIN: join(box.base, "missing-postgres"),
    } });
    assert.equal(native.status, 1);
    assert.match(native.stderr, /PostgreSQL 18 programs \(initdb, pg_ctl\) were not found; set ZASP_REAL_STACK_PG_BIN/);
  } finally { box.done(); }
});

test("stack.sh native mode leaves out the workers it cannot serve", () => {
  const box = sandbox({ real: ["curl", "ps"] });
  try {
    const env = { PATH: box.bin, HOME: box.base, ZASP_REAL_STACK_STATE: box.state, ZASP_REAL_STACK_OWNER_FILE: join(box.base, "owner"), ZASP_REAL_STACK_PG_PORT: "1" };
    const status = spawnSync(bash, [stack, "status"], { encoding: "utf8", env: { ...env, ZASP_REAL_STACK_DEPENDENCIES: "native" } });
    assert.equal(status.status, 0, status.stderr);
    const names = status.stdout.split("\n").map(line => line.split(/\s+/)[0]).filter(Boolean);
    assert.deepEqual(names, ["postgres", "aws-emulator", "temporal", "openfga", "api", "worker-scheduler", "worker-projection-risk", "worker-security-agent-action", "projector", "ui", "hosts"]);
  } finally { box.done(); }
});

// --- profile kubernetes ------------------------------------------------------------

const kubeConfig = values => "ZASP_ORIGIN=https://zasp.example.test:8443\nSTYTCH_PROJECT_ID=project-test-example\nSTYTCH_SECRET=secret-test-do-not-print-abcdef\n" +
  "STYTCH_PUBLIC_TOKEN=public-token-test-example\nZASP_ORGANIZATION_NAME=Example Security\nZASP_ORGANIZATION_DOMAIN=example.test\nZASP_ADMIN_EMAIL=admin@example.test\n" +
  "ZASP_IMAGE_API=registry.example.test/zasp/zasp-api:1\nZASP_IMAGE_WORKER=registry.example.test/zasp/zasp-worker:1\nZASP_IMAGE_WEB=registry.example.test/zasp/zasp-web:1\n" +
  `ZASP_KUBE_VALUES=${values}\n`;
const hasOpenssl = which("openssl") !== "";
const needsOpenssl = hasOpenssl ? {} : { skip: "openssl is not installed" };

function kubeBox(tools = {}) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "zasp-kube-")));
  const values = join(base, "zasp-values.yaml");
  const box = sandbox({ profile: "kubernetes", real: ["openssl"], tools, config: kubeConfig(values) });
  return { ...box, values, done: () => { box.done(); rmSync(base, { recursive: true, force: true }); } };
}

test("kubernetes secrets init writes a private values file, prints no value, and keeps an existing file", needsOpenssl, () => {
  const box = kubeBox();
  try {
    const first = box.run(["secrets", "init"]);
    assert.equal(first.status, 0, output(first));
    assert.equal(statSync(box.values).mode & 0o777, 0o600);
    const written = readFileSync(box.values, "utf8");
    assert.equal(output(first).includes("secret-test-do-not-print-abcdef"), false);
    const [document] = loadAll(written);
    for (const [key, pattern] of Object.entries({
      workflowSigningKey: /^[0-9a-f]{64}$/, tokenRevealKey: /^[A-Za-z0-9_-]{43}$/, stytchWebhookSecret: /^whsec_[A-Za-z0-9+/]{43}=$/,
      openfgaToken: /^[0-9a-f]{64}$/, awsExternalId: /^[0-9a-f]{48}$/, gatewaySigningKey: /^[A-Za-z0-9_-]{86}$/,
      neo4jAdminPassword: /^[0-9a-f]{48}$/, frontTlsCertificate: /BEGIN CERTIFICATE/, frontTlsKey: /BEGIN (RSA )?PRIVATE KEY/, neo4jTlsCa: /BEGIN CERTIFICATE/,
    })) {
      assert.match(document.secrets[key], pattern, key);
      assert.equal(output(first).includes(document.secrets[key].trim().split("\n")[1] ?? document.secrets[key]), false, `${key} was printed`);
    }
    assert.equal(Buffer.from(document.secrets.forwardSeedBase64, "base64").length, 64);
    assert.equal(Buffer.from(document.secrets.approvalDeliveryKeyBase64, "base64").length, 32);
    // The verifier document holds the public half of the signing key.
    const signing = Buffer.from(document.secrets.gatewaySigningKey, "base64url");
    const verifier = JSON.parse(document.secrets.gatewayPolicyKeysJson);
    assert.deepEqual(verifier, { keys: [{ key_id: "zasp-gateway", public_key: signing.subarray(32).toString("base64url") }] });
    assert.equal(document.secrets.stytchSecret, "secret-test-do-not-print-abcdef");
    assert.equal(document.bootstrap.adminEmail, "admin@example.test");
    assert.ok(existsSync(box.values.replace(/\.yaml$/, ".ca.crt")));
    const second = box.run(["secrets", "init"]);
    assert.equal(second.status, 0);
    assert.match(second.stdout, /already exists; its keys were kept/);
    assert.equal(readFileSync(box.values, "utf8"), written);
  } finally { box.done(); }
});

test("kubernetes doctor names a missing values file and missing programs", () => {
  const box = kubeBox();
  try {
    const result = box.run(["doctor"]);
    assert.equal(result.status, 1);
    for (const expected of [/MISSING {2}helm is not installed/, /MISSING {2}kubectl is not installed/, /MISSING {2}no values file at/, /run: \.\/zasp --profile kubernetes secrets init/]) {
      assert.match(result.stdout, expected);
    }
  } finally { box.done(); }
});

const kubectlStub = `case "$*" in *"version -o json"*) printf '{"serverVersion": {\\n "major": "1",\\n "minor": "31"\\n}}\\n' ;; *"get storageclass"*) echo "standard (default)" ;; esac`;

test("kubernetes commands run helm and kubectl against the release; --dry-run runs nothing", needsOpenssl, () => {
  const box = kubeBox({ helm: "", kubectl: kubectlStub });
  try {
    assert.equal(box.run(["secrets", "init"]).status, 0);
    const dry = box.run(["--dry-run", "up"]);
    assert.equal(dry.status, 0, output(dry));
    assert.match(dry.stdout, new RegExp(`would run: helm -n zasp upgrade --install zasp \\S+/deploy/kubernetes/zasp --create-namespace -f ${box.values}`));
    assert.match(dry.stdout, /would run: kubectl -n zasp rollout status statefulset\/zasp --timeout=30m/);
    assert.equal(box.calls().some(line => line.includes("upgrade --install")), false);
    const before = box.calls().length;
    assert.equal(box.run(["up"]).status, 0);
    assert.equal(box.run(["stop"]).status, 0);
    assert.equal(box.run(["bootstrap-admin", "Example", "example.test", "admin@example.test"]).status, 0);
    assert.equal(box.run(["uninstall"]).status, 1);
    assert.equal(box.run(["uninstall", "--yes"]).status, 0);
    const calls = box.calls().slice(before).filter(line => !/ version | get storageclass| template /.test(line));
    assert.deepEqual(calls, [
      `helm -n zasp upgrade --install zasp ${chart} --create-namespace -f ${box.values}`,
      "kubectl -n zasp rollout status statefulset/zasp --timeout=30m",
      "kubectl -n zasp scale statefulset/zasp --replicas=0",
      "kubectl -n zasp exec zasp-0 -c toolbox -- /bin/sh /zasp/config/entrypoint.sh bootstrap Example example.test admin@example.test",
      "helm -n zasp uninstall zasp",
      "kubectl -n zasp delete pvc -l app.kubernetes.io/instance=zasp",
    ]);
  } finally { box.done(); }
});

test("kubernetes doctor refuses a cluster older than 1.29", needsOpenssl, () => {
  const box = kubeBox({ helm: "", kubectl: kubectlStub.replace('"31"', '"27"') });
  try {
    assert.equal(box.run(["secrets", "init"]).status, 0);
    const result = box.run(["doctor"]);
    assert.equal(result.status, 1);
    assert.match(result.stdout, /MISSING {2}the cluster runs Kubernetes 1\.27/);
  } finally { box.done(); }
});

// --- the evaluation chart ------------------------------------------------------------

test("the chart carries exact copies of the files it shares with the local stack", () => {
  assert.equal(readFileSync(join(chart, "files", "front.mjs"), "utf8"), readFileSync(join(root, "deploy", "local", "real-stack", "front.mjs"), "utf8"));
  assert.equal(readFileSync(join(chart, "files", "authorization-model.json"), "utf8"), readFileSync(join(root, "services", "platform", "authorization", "model.json"), "utf8"));
});

test("the chart's scripts parse, and its entrypoint names the same database logins as the local stack", () => {
  assert.equal(spawnSync("sh", ["-n", join(chart, "files", "entrypoint.sh")]).status, 0);
  assert.equal(spawnSync(bash, ["-n", join(chart, "files", "provision-cloud.sh")]).status, 0);
  const logins = text => [...text.matchAll(/^\s*(ZASP_[A-Z_]+_DB_PRINCIPAL)=(zasp_svc_[a-z_]+)$/gm)].map(match => `${match[1]}=${match[2]}`).sort();
  const local = logins(readFileSync(stack, "utf8"));
  assert.equal(local.length, 30);
  assert.deepEqual(logins(readFileSync(join(chart, "files", "entrypoint.sh"), "utf8")), local);
});

const needsHelm = helm && hasOpenssl ? {} : { skip: "helm (or openssl) is not installed: the chart was not rendered" };
function render(box, extra = []) {
  const result = spawnSync(helm, ["template", "zasp", chart, "--kube-version", "1.29.0", "-f", box.values, ...extra], { encoding: "utf8" });
  return { ...result, documents: result.status === 0 ? loadAll(result.stdout).filter(Boolean) : [] };
}
const pod = documents => documents.find(document => document.kind === "StatefulSet").spec.template.spec;

test("the chart renders one pod with every dependency ordered before the product", needsHelm, () => {
  const box = kubeBox();
  try {
    assert.equal(box.run(["secrets", "init"]).status, 0);
    const rendered = render(box);
    assert.equal(rendered.status, 0, rendered.stderr);
    assert.deepEqual(rendered.documents.map(document => document.kind).sort(), ["ConfigMap", "ConfigMap", "NetworkPolicy", "Secret", "Service", "StatefulSet"]);
    const spec = pod(rendered.documents);
    assert.deepEqual(spec.initContainers.map(container => container.name), ["postgres", "database-init", "prepare", "openfga-migrate", "openfga",
      "temporal", "localstack", "opensearch", "neo4j", "fga-model", "graph-user", "schema", "search-init", "graph-init"]);
    assert.deepEqual(spec.initContainers.filter(container => container.restartPolicy === "Always").map(container => container.name),
      ["postgres", "openfga", "temporal", "localstack", "opensearch", "neo4j"]);
    assert.deepEqual(spec.containers.map(container => container.name), ["api", "worker-scheduler", "worker-discovery", "worker-outbox", "worker-projection-graph",
      "worker-projection-search", "worker-projection-risk", "worker-security-agent-action", "projector", "front", "toolbox"]);
    // Nothing runs as root unless the root volume step is asked for.
    const everyContainer = podSpec => [...podSpec.initContainers, ...podSpec.containers];
    assert.deepEqual(everyContainer(spec).filter(container => container.securityContext?.runAsUser === 0).map(container => container.name), []);
    assert.equal(spec.securityContext.fsGroup, 65532);
    const database = spec.initContainers.find(container => container.name === "postgres");
    assert.equal(database.securityContext.runAsNonRoot, true);
    assert.equal(database.securityContext.runAsUser, 999);
    const rooted = pod(render(box, ["--set", "volumePermissions.enabled=true"]).documents);
    assert.equal(rooted.initContainers[0].name, "volume-permissions");
    assert.deepEqual(everyContainer(rooted).filter(container => container.securityContext?.runAsUser === 0).map(container => container.name), ["volume-permissions"]);
    assert.equal(spec.automountServiceAccountToken, false);
    // Only the front is reachable from outside the pod.
    const policy = rendered.documents.find(document => document.kind === "NetworkPolicy");
    assert.deepEqual(policy.spec.ingress, [{ ports: [{ protocol: "TCP", port: 8443 }] }]);
    const service = rendered.documents.find(document => document.kind === "Service");
    assert.deepEqual(service.spec.ports, [{ name: "https", port: 8443, targetPort: "https" }]);
    // No secret value is passed as a plain environment value.
    const secret = rendered.documents.find(document => document.kind === "Secret");
    // Compared by their longest line: a certificate spans lines, and a raw key may contain a line break.
    const longestLine = value => value.split("\n").reduce((longest, line) => (line.length > longest.length ? line : longest), "");
    const values = Object.values(secret.data).map(value => longestLine(Buffer.from(value, "base64").toString("latin1"))).filter(value => value.length >= 16);
    const statefulSet = rendered.stdout.slice(rendered.stdout.indexOf("kind: StatefulSet"));
    assert.ok(values.length >= 20);
    for (const value of values) assert.equal(statefulSet.includes(value), false);
    const settings = rendered.documents.find(document => document.metadata.name === "zasp-settings").data;
    assert.equal(settings.ZASP_PUBLIC_ORIGIN, "https://zasp.example.test:8443");
    assert.equal(settings.ZASP_BOOTSTRAP_ADMIN_EMAIL, "admin@example.test");
  } finally { box.done(); }
});

test("the chart refuses what the product would refuse, with the setting's name", needsHelm, () => {
  const box = kubeBox();
  try {
    assert.equal(box.run(["secrets", "init"]).status, 0);
    for (const [set, message] of [
      ["publicOrigin=https://localhost:8443", /publicOrigin must not be localhost/], ["publicOrigin=https://192.0.2.7", /publicOrigin must not be localhost/],
      ["publicOrigin=http://zasp.example.test", /publicOrigin must be https/], ["images.api=", /images\.api is required/],
      ["secrets.stytchSecret=", /secrets\.stytchSecret is required/], ["secrets.workflowSigningKey=", /secrets\.workflowSigningKey is required/],
      ["secrets.awsExternalId=short", /exactly 48 characters/], ["bootstrap.adminEmail=", /must be set together/],
      ["securityAgent.planner=true", /securityAgent\.planner needs secrets\.plannerApiKey/], ["database.external.enabled=true", /database\.external\.host is required/],
      ["identity.oauthProvider=facebook", /identity\.oauthProvider must be/], ["ingress.enabled=true", /ingress\.tlsSecretName is required/],
    ]) {
      const rendered = render(box, ["--set", set]);
      assert.notEqual(rendered.status, 0, set);
      assert.match(rendered.stderr, message, set);
    }
  } finally { box.done(); }
});

test("the chart's switches: planner, maintenance mode, external database, no persistence, ingress", needsHelm, () => {
  const box = kubeBox();
  try {
    assert.equal(box.run(["secrets", "init"]).status, 0);
    const planner = pod(render(box, ["--set", "securityAgent.planner=true", "--set", "secrets.plannerApiKey=placeholder-model-key"]).documents);
    assert.ok(planner.containers.some(container => container.name === "worker-security-agent"));
    assert.deepEqual(planner.initContainers.map(container => container.name).filter(name => name.startsWith("selector")), ["selector-count", "selector-configure"]);

    const maintenance = pod(render(box, ["--set", "product.enabled=false"]).documents);
    assert.deepEqual(maintenance.initContainers.map(container => container.name), ["postgres", "database-init"]);

    assert.deepEqual(maintenance.containers.map(container => container.name), ["toolbox"]);

    const external = render(box, ["--set", "database.external.enabled=true", "--set", "database.external.host=db.example.internal:5432",
      "--set", "secrets.operatorDsn=postgres://zasp_operator:placeholder@db.example.internal/zasp?sslmode=require", "--set", "secrets.servicePassword=placeholder"]);
    assert.equal(external.status, 0, external.stderr);
    assert.equal(external.documents.find(document => document.metadata.name === "zasp-settings").data.ZASP_DATABASE_MODE, "external");
    const init = pod(external.documents).initContainers.find(container => container.name === "database-init").args[0];
    assert.doesNotMatch(init, /CREATE ROLE zasp_operator/);
    assert.match(init, /CREATE DATABASE openfga/);

    const ephemeral = render(box, ["--set", "persistence.enabled=false"]).documents.find(document => document.kind === "StatefulSet");
    assert.equal(ephemeral.spec.volumeClaimTemplates, undefined);
    assert.ok(ephemeral.spec.template.spec.volumes.some(volume => volume.name === "data" && volume.emptyDir));

    const ingress = render(box, ["--set", "ingress.enabled=true", "--set", "ingress.tlsSecretName=zasp-tls"]).documents.find(document => document.kind === "Ingress");
    assert.equal(ingress.spec.rules[0].host, "zasp.example.test");
    assert.equal(ingress.spec.tls[0].secretName, "zasp-tls");
  } finally { box.done(); }
});

test("helm lint accepts the chart", needsHelm, () => {
  const box = kubeBox();
  try {
    assert.equal(box.run(["secrets", "init"]).status, 0);
    const result = spawnSync(helm, ["lint", chart, "--kube-version", "1.29.0", "-f", box.values], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stdout + result.stderr);
  } finally { box.done(); }
});

// --- profile aws -----------------------------------------------------------------------

function awsBox(tools = {}, config = "") {
  const box = sandbox({ profile: "aws", tools, config: "ZASP_AWS_REGION=us-west-2\nZASP_AWS_ACCOUNT_ID=000000000000\nZASP_AWS_HOST=app.example.test\n" + config });
  const tfvars = join(box.base, "production.tfvars");
  const values = join(box.base, "values-production.yaml");
  writeFileSync(tfvars, 'account_id = "000000000000"\n');
  writeFileSync(values, "global:\n  publicOrigin: https://app.example.test\n");
  const run = (args, extra = {}) => box.run(args, { ZASP_AWS_TFVARS: tfvars, ZASP_AWS_VALUES: values, ZASP_AWS_WORK: join(box.base, "work"), ...extra });
  return { ...box, run, tfvars, values };
}

test("aws install without a step prints the procedure and runs nothing", () => {
  const box = awsBox({ terraform: "", helm: "", kubectl: "" });
  try {
    const result = box.run(["install"]);
    assert.equal(result.status, 0);
    for (const expected of [/\.\/zasp install infrastructure --yes/, /\.\/zasp install images/, /\.\/zasp secrets init/, /\.\/zasp install dsns/, /manual, runbook step 6/]) assert.match(result.stdout, expected);
    assert.deepEqual(box.calls(), []);
  } finally { box.done(); }
});

test("aws infrastructure plans first and applies only with --yes", () => {
  const box = awsBox({ terraform: 'case "$*" in *"output -json helm_values"*) echo "{}" ;; esac' });
  try {
    const planned = box.run(["install", "infrastructure"]);
    assert.equal(planned.status, 0, output(planned));
    assert.match(planned.stdout, /Review it, then apply it with: \.\/zasp install infrastructure --yes/);
    const staging = join(root, "deploy", "staging");
    assert.deepEqual(box.calls(), [`terraform -chdir=${staging} init -input=false -lockfile=readonly`,
      `terraform -chdir=${staging} plan -input=false -var-file=${box.tfvars} -out=${join(box.base, "work", "zasp.plan")}`]);
    assert.equal(box.run(["install", "infrastructure", "--yes"]).status, 0);
    assert.deepEqual(box.calls().slice(4), [`terraform -chdir=${staging} apply -input=false ${join(box.base, "work", "zasp.plan")}`, `terraform -chdir=${staging} output -json helm_values`]);
    assert.equal(readFileSync(join(box.base, "work", "values-terraform.json"), "utf8"), "{}\n");
  } finally { box.done(); }
});

test("aws release passes the Terraform values, then the operator's values, and does not wait", () => {
  const box = awsBox({ terraform: 'echo "{}"', helm: "", kubectl: "" });
  try {
    const result = box.run(["--dry-run", "up"]);
    assert.equal(result.status, 0, output(result));
    assert.match(result.stdout, new RegExp(`would run: helm -n agentsec upgrade --install zasp \\S+/deploy/staging/product --create-namespace -f \\S+/values-terraform.json -f ${box.values} --timeout 20m`));
    assert.doesNotMatch(result.stdout, /--wait|--atomic/);
  } finally { box.done(); }
});

test("aws restore is refused with the procedure, and uninstall keeps the infrastructure unless asked", () => {
  const box = awsBox({ terraform: "", helm: "", kubectl: "" });
  try {
    const restore = box.run(["restore", "anything", "--yes"]);
    assert.equal(restore.status, 1);
    assert.match(restore.stderr, /production restore is not automated/);
    assert.equal(box.run(["uninstall"]).status, 1);
    const kept = box.run(["uninstall", "--yes"]);
    assert.equal(kept.status, 0);
    assert.match(kept.stdout, /still exist and cost money/);
    assert.deepEqual(box.calls(), ["helm -n agentsec uninstall zasp"]);
    assert.equal(box.run(["uninstall", "--yes", "--destroy-infrastructure"]).status, 0);
    assert.match(box.calls().at(-1), /^terraform -chdir=\S+ destroy -var-file=/);
  } finally { box.done(); }
});

test("aws doctor checks the Terraform version, unfinished files and the account", () => {
  const box = awsBox({ terraform: 'echo "Terraform v1.9.0"', aws: 'echo 111111111111', helm: "", kubectl: "exit 1" });
  try {
    writeFileSync(box.tfvars, 'account_id = "000000000000" # REPLACE: the account\n');
    writeFileSync(box.values, 'global:\n  publicOrigin: ""              # REQUIRED: the origin\n');
    const result = box.run(["doctor"]);
    assert.equal(result.status, 1);
    for (const expected of [/terraform is 1\.9\.0; deploy\/staging\/versions\.tf requires 1\.15\.8 exactly/, /still has 1 lines marked REPLACE/, /still has 1 empty values marked REQUIRED/,
      /AWS credentials are for account 111111111111, not 000000000000/, /MISSING {2}ZASP_AWS_OPERATOR_DSN_FILE does not name a file/, /warn {5}the cluster does not answer/]) {
      assert.match(result.stdout, expected);
    }
  } finally { box.done(); }
});

test("the Terraform version zasp asks for is the one the root pins", () => {
  const versions = readFileSync(join(root, "deploy", "staging", "versions.tf"), "utf8");
  const asked = readFileSync(join(here, "lib", "aws.sh"), "utf8").match(/^AWS_TERRAFORM_VERSION=(\S+)$/m)[1];
  assert.ok(versions.includes(asked), `deploy/staging/versions.tf does not mention ${asked}`);
});

// --- the guides ---------------------------------------------------------------------------

// GitHub's heading anchors: lower case, punctuation removed, spaces to hyphens.
const anchors = text => new Set([...text.matchAll(/^#{1,6} +(.+)$/gm)].map(match => match[1].trim().toLowerCase().replace(/[^\p{L}\p{N} _-]/gu, "").replace(/ /g, "-")));

test("the front page and the administrator guide link only to files and headings that exist", () => {
  // The user guide is written separately; its link is expected to dangle until it lands.
  const pending = new Set([join(root, "docs", "getting-started", "user.md")]);
  for (const page of [join(root, "README.md"), join(root, "docs", "getting-started", "administrator.md")]) {
    const text = readFileSync(page, "utf8");
    for (const match of text.matchAll(/\]\(([^)\s]+)\)/g)) {
      const [target, fragment] = match[1].split("#");
      if (/^[a-z]+:/.test(target)) continue;
      const file = target === "" ? page : join(dirname(page), target);
      if (pending.has(file)) continue;
      assert.ok(existsSync(file), `${page} links to ${match[1]}, which does not exist`);
      if (fragment && file.endsWith(".md")) assert.ok(anchors(readFileSync(file, "utf8")).has(fragment), `${page} links to ${match[1]}: no such heading`);
    }
  }
});

// --- demo data ---------------------------------------------------------------------------

test("local demo commands map to the stack script, pass their options on, and need an installed stack", () => {
  const box = localBox();
  try {
    const early = box.run(["demo", "status"]);
    assert.equal(early.status, 1);
    assert.match(early.stderr, /nothing is installed yet; run \.\/zasp up/);
    // The preview of a seeding needs no stack.
    assert.equal(box.run(["--dry-run", "demo", "seed", "--email", "person@example.test"]).status, 0);
    mkdirSync(box.state, { recursive: true });
    writeFileSync(join(box.state, "up.done"), "");
    assert.equal(box.run(["demo", "seed", "--email", "person@example.test", "--into-existing-organization", "pid_00000000-0000-4000-8000-000000000001"]).status, 0);
    assert.equal(box.run(["demo", "status"]).status, 0);
    assert.equal(box.run(["demo", "remove"]).status, 0);
    assert.equal(box.run(["demo", "remove", "--yes"]).status, 0);
    assert.equal(box.run(["--dry-run", "demo", "remove", "--yes"]).status, 0);
    assert.deepEqual(box.stackCalls(), [
      "stack demo seed --email person@example.test --dry-run",
      "stack demo seed --email person@example.test --into-existing-organization pid_00000000-0000-4000-8000-000000000001",
      "stack demo status",
      // Without --yes the command itself lists what it would remove and refuses.
      "stack demo remove",
      "stack demo remove --yes",
      "stack demo remove --yes --dry-run",
    ]);
    for (const wrong of [["demo"], ["demo", "reset"]]) {
      const refused = box.run(wrong);
      assert.equal(refused.status, 1);
      assert.match(refused.stderr, /usage: zasp demo seed --email <address> \| status \| remove --yes \| help/);
    }
  } finally { box.done(); }
});

test("kubernetes and aws demo commands run the seeder of the API image as the operator", needsOpenssl, () => {
  const kube = kubeBox({ helm: "", kubectl: kubectlStub });
  try {
    assert.equal(kube.run(["secrets", "init"]).status, 0);
    const before = kube.calls().length;
    assert.equal(kube.run(["demo", "seed", "--email", "person@example.test"]).status, 0);
    assert.equal(kube.run(["demo", "remove", "--yes"]).status, 0);
    const dry = kube.run(["--dry-run", "demo", "status"]);
    assert.match(dry.stdout, /would run: kubectl -n zasp exec zasp-0 -c toolbox -- \/bin\/sh \/zasp\/config\/entrypoint\.sh demo status/);
    assert.deepEqual(kube.calls().slice(before), [
      "kubectl -n zasp exec zasp-0 -c toolbox -- /bin/sh /zasp/config/entrypoint.sh demo seed --email person@example.test",
      "kubectl -n zasp exec zasp-0 -c toolbox -- /bin/sh /zasp/config/entrypoint.sh demo remove --yes",
    ]);
  } finally { kube.done(); }
  const aws = awsBox({ docker: "" }, "ZASP_AWS_API_IMAGE=registry.example.test/zasp/api@sha256:" + "0".repeat(64) + "\n");
  try {
    const dry = aws.run(["--dry-run", "demo", "seed", "--email", "person@example.test"]);
    assert.equal(dry.status, 0, output(dry));
    assert.match(dry.stdout, /would run: docker run --rm --entrypoint \/app\/zasp-demo --env-file <private file> \S+ seed --email person@example\.test/);
    // Without the operator's database access nothing is started.
    const refused = aws.run(["demo", "status"]);
    assert.equal(refused.status, 1);
    assert.equal(aws.calls().some(line => line.startsWith("docker run")), false);
  } finally { aws.done(); }
});

test("the API image carries the demo seeder next to the bootstrap command", () => {
  const dockerfile = readFileSync(join(root, "deploy", "production", "api.Dockerfile"), "utf8");
  assert.match(dockerfile, /-o \/out\/zasp-demo \.\/cmd\/zasp-demo/);
  assert.match(dockerfile, /COPY --from=build .*\/out\/zasp-bootstrap \/out\/zasp-demo /);
  for (const script of [stack, join(chart, "files", "entrypoint.sh")]) {
    assert.match(readFileSync(script, "utf8"), /^ {2}demo\) shift; cmd_demo "\$@" ;;$/m, script);
  }
});

test("the guides name only commands the entry point has", () => {
  const usage = spawnSync(bash, [zasp, "--help"], { encoding: "utf8" }).stdout;
  const known = new Set(["doctor", "config", "secrets", "install", "bootstrap-admin", "up", "demo", "start", "stop", "status", "logs", "upgrade", "backup", "restore", "uninstall"]);
  for (const command of known) assert.match(usage, new RegExp(`^  ${command}\\b`, "m"), command);
  for (const page of [join(root, "README.md"), join(root, "docs", "getting-started", "administrator.md")]) {
    for (const match of readFileSync(page, "utf8").matchAll(/\.\/zasp(?: --[a-z-]+(?: (?:local|kubernetes|aws))?)* ([a-z-]+)/g)) {
      assert.ok(known.has(match[1]), `${page} mentions './zasp ${match[1]}', which is not a command`);
    }
  }
});

// --- the identity provider stand-in -----------------------------------------------------

test("the identity provider stand-in answers the four directory requests bootstrap makes, and nothing else", async () => {
  const server = createFakeIdentityProvider();
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const call = async (path, body) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, { method: "POST", body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  try {
    const search = { limit: 2, query: { operator: "AND", operands: [{ filter_name: "organization_slugs", filter_value: ["example-test"] }] } };
    assert.deepEqual((await call("/v1/b2b/organizations/search", search)).body.organizations, []);
    const created = (await call("/v1/b2b/organizations", { organization_name: "Example", organization_slug: "example-test", email_allowed_domains: ["example.test"], trusted_metadata: { zasp_bootstrap: "v1" } })).body.organization;
    assert.match(created.organization_id, /^organization-test-/);
    assert.equal((await call("/v1/b2b/organizations/search", search)).body.organizations.length, 1);
    const invited = (await call("/v1/b2b/magic_links/email/invite", { organization_id: created.organization_id, email_address: "admin@example.test" })).body.member;
    assert.equal(invited.status, "invited");
    const members = { organization_ids: [created.organization_id], query: { operands: [{ filter_name: "member_emails", filter_value: ["admin@example.test"] }] } };
    assert.equal((await call("/v1/b2b/organizations/members/search", members)).body.members[0].member_id, invited.member_id);
    assert.equal((await call("/v1/b2b/oauth/authenticate", {})).status, 404, "it must not issue sessions");
  } finally { server.close(); }
});

test("unapproved AWS promotion never calls Helm upgrade", () => {
  const box = awsBox({terraform:'echo "{}"',helm:'exit 12',kubectl:'exit 12',node:'exec "'+process.execPath+'" "$@"'});
  try {
    const result=box.run(["install","release"], {ZASP_RELEASE_EVIDENCE_DIR:""});
    assert.notEqual(result.status,0);
    assert.match(result.stderr,/verified production release failed/);
    assert.equal(box.calls().some(line=>line.includes("upgrade --install")),false);
  } finally {box.done();}
});
