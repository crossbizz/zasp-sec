import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

// A missing implementation is the first RED, not an import-time test crash.
const implementation = await import("./browser-prerequisites.mjs").catch(error => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});

function fixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), "zasp-browser-prerequisites-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const executable = (relative, body = "exit 0") => {
    const file = path.join(root, relative);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
    return file;
  };
  return { root, executable };
}

test("macOS preserves the existing application default", () => {
  assert.equal(typeof implementation.selectBrowserExecutable, "function");
  const visited = [];
  const chosen = implementation.selectBrowserExecutable({ platform: "darwin", env: {}, validate: file => { visited.push(file); return file; } });
  assert.equal(chosen, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
  assert.deepEqual(visited, [chosen]);
});

test("explicit Linux executable with spaces and shell metacharacters is passed literally", t => {
  assert.equal(typeof implementation.selectBrowserExecutable, "function");
  const { executable } = fixture(t);
  const chrome = executable("chrome space;$(false)", "printf '%s' \"$1\"");
  const chosen = implementation.selectBrowserExecutable({ platform: "linux", env: { ZASP_COMBINED_E2E_CHROME: chrome } });
  assert.equal(chosen, chrome);
  const result = spawnSync(chosen, ["literal argument"], { encoding: "utf8", timeout: 2000 });
  assert.equal(result.status, 0);
  assert.equal(result.stdout, "literal argument");
});

for (const [label, supplied] of [["relative", "./chrome"], ["newline", "/tmp/chrome\n"], ["NUL", "/tmp/chrome\0"], ["tab", "/tmp/chrome\t"], ["DEL", "/tmp/chrome\x7f"], ["C1", "/tmp/chrome\u0085"], ["empty", ""]]) {
  test(`explicit ${label} browser path fails without fallback`, () => {
    assert.equal(typeof implementation.selectBrowserExecutable, "function");
    assert.throws(() => implementation.selectBrowserExecutable({ platform: "linux", env: { ZASP_COMBINED_E2E_CHROME: supplied } }), /browser.*(absolute|control|empty)/i);
  });
}

for (const kind of ["nonexistent", "nonexecutable", "directory"]) {
  test(`explicit ${kind} path fails despite a valid PATH fallback`, t => {
    assert.equal(typeof implementation.selectBrowserExecutable, "function");
    const { root, executable } = fixture(t);
    executable("google-chrome");
    const invalid = path.join(root, "invalid");
    if (kind === "directory") mkdirSync(invalid);
    if (kind === "nonexecutable") { writeFileSync(invalid, "not executable"); chmodSync(invalid, 0o600); }
    assert.throws(() => implementation.selectBrowserExecutable({ platform: "linux", env: { PATH: root, ZASP_COMBINED_E2E_CHROME: invalid } }), /browser.*executable regular file/i);
  });
}

test("Linux resolves installed Chrome from PATH and refuses missing defaults", t => {
  assert.equal(typeof implementation.selectBrowserExecutable, "function");
  const { root, executable } = fixture(t);
  const chrome = executable("google-chrome-stable");
  assert.equal(implementation.selectBrowserExecutable({ platform: "linux", env: { PATH: root } }), chrome);
  assert.throws(() => implementation.selectBrowserExecutable({ platform: "linux", env: { PATH: "/does-not-exist" } }), /browser.*not found/i);
});

function prerequisites(t) {
  const { root, executable } = fixture(t);
  const chrome = executable("chrome");
  executable("go"); executable("docker"); executable("openssl");
  executable("pg_config", `printf '%s' '${root}/pg'`);
  executable("pg/psql"); executable("node_modules/.bin/vinext");
  mkdirSync(path.join(root, "dist/server"), { recursive: true });
  writeFileSync(path.join(root, "dist/server/index.js"), "compiled fixture");
  return { root, env: { PATH: root, ZASP_COMBINED_E2E_CHROME: chrome } };
}

test("checked prerequisites reach setup once with resolved browser and PostgreSQL paths", async t => {
  assert.equal(typeof implementation.withBrowserPrerequisites, "function");
  const options = prerequisites(t);
  const result = await implementation.withBrowserPrerequisites(options, checked => {
    writeFileSync(path.join(options.root, "setup"), "setup reached");
    return checked;
  });
  assert.equal(readFileSync(path.join(options.root, "setup"), "utf8"), "setup reached");
  assert.deepEqual(result, { chrome: options.env.ZASP_COMBINED_E2E_CHROME, postgresBin: path.join(options.root, "pg") });
});

for (const missing of ["chrome", "go", "docker", "openssl", "pg_config", "pg/psql", "node_modules/.bin/vinext", "dist/server/index.js"]) {
  test(`missing ${missing} prevents setup and identifies the prerequisite`, async t => {
    assert.equal(typeof implementation.withBrowserPrerequisites, "function");
    const options = prerequisites(t);
    rmSync(path.join(options.root, missing));
    let setup = false;
    await assert.rejects(() => implementation.withBrowserPrerequisites(options, () => { setup = true; }), missing === "chrome" ? /browser/i : new RegExp(missing.replaceAll("/", "\\/")));
    assert.equal(setup, false, "database/compilation setup must not run");
  });
}

test("the actual harness exits nonzero before setup for an invalid explicit browser", t => {
  const { root } = fixture(t);
  const result = spawnSync(process.execPath, [new URL("./production-combined-e2e.mjs", import.meta.url).pathname], {
    encoding: "utf8", timeout: 5000,
    env: { ...process.env, PATH: root, TMPDIR: root, ZASP_COMBINED_E2E_CHROME: "./invalid-browser", ZASP_COMBINED_E2E_COMPLIANCE: "true" },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /browser.*absolute/i);
  assert.deepEqual(readdirSync(root), [], "failed prerequisites must not allocate the harness temporary root");
});

for (const [label, output] of [["relative", "relative/pg"], ["embedded control", "/tmp/pg\t/bin"], ["empty", ""]]) {
  test(`invalid ${label} pg_config output prevents setup`, async t => {
    const options = prerequisites(t);
    writeFileSync(path.join(options.root, "pg_config"), `#!/bin/sh\nprintf '%s' '${output}'\n`);
    let setup = false;
    await assert.rejects(() => implementation.withBrowserPrerequisites(options, () => { setup = true; }), /PostgreSQL.*absolute.*control/i);
    assert.equal(setup, false);
  });
}

test("failed pg_config command identifies the tool and prevents setup", async t => {
  const options = prerequisites(t);
  writeFileSync(path.join(options.root, "pg_config"), "#!/bin/sh\nexit 19\n");
  let setup = false;
  await assert.rejects(() => implementation.withBrowserPrerequisites(options, () => { setup = true; }), /pg_config --bindir failed/);
  assert.equal(setup, false);
});
