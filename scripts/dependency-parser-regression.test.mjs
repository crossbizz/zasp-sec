import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
const childPath = fileURLToPath(new URL("./fixtures/dependency-parser-regression-child.mjs", import.meta.url));

function parseInOwnedChild(name) {
  // spawnSync owns the child until wait completes, including timeout SIGKILL.
  // Empty ambient environment keeps NODE_OPTIONS, proxies and credentials out.
  const result = spawnSync(process.execPath, [
    "--max-old-space-size=32",
    "--experimental-import-meta-resolve",
    childPath,
    name,
  ], {
    cwd: root,
    env: { PATH: dirname(process.execPath), TZ: "UTC" },
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    timeout: 2_000,
    maxBuffer: 16 * 1024,
    killSignal: "SIGKILL",
  });
  const diagnostic = `${name}: status=${result.status} signal=${result.signal} error=${result.error?.code ?? "none"} stderr=${result.stderr}`;
  assert.equal(result.error, undefined, diagnostic);
  assert.equal(result.signal, null, diagnostic);
  assert.equal(result.status, 0, diagnostic);
  assert.equal(result.stderr, "", diagnostic);
  const value = JSON.parse(result.stdout);
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), "child must return one object");
  assert.equal(new URL(value.parser).protocol, "file:", "parser must resolve locally from vinext");
  return value;
}

// Wrong valid dimensions, a skipped parser call, or a malformed "success" must
// fail. These literal dimensions do not come from the parser being checked.
for (const [fixture, width, height, type] of [
  ["icns-valid", 32, 32, "icns"],
  ["jxl-valid", 8, 8, "jxl"],
  ["heif-valid", 16, 24, "heic"],
]) {
  test(`vinext's actual image parser preserves ${fixture} dimensions`, () => {
    const result = parseInOwnedChild(fixture);
    assert.deepEqual(Object.keys(result).sort(), ["dimensions", "disposition", "parser"]);
    assert.equal(result.disposition, "dimensions");
    assert.deepEqual(result.dimensions, { width, height, type });
  });
}

// A zero-size box must throw inside the real parser. A timeout, OOM, crash,
// import error, empty output, or successful bogus dimensions does not pass.
for (const fixture of ["icns-zero-entry", "jxl-zero-partial", "heif-zero-ispe"]) {
  test(`vinext's actual image parser rejects ${fixture} without hanging`, () => {
    const result = parseInOwnedChild(fixture);
    assert.deepEqual(Object.keys(result).sort(), ["disposition", "error", "parser"]);
    assert.equal(result.disposition, "rejected");
    assert.deepEqual(Object.keys(result.error).sort(), ["message", "name"]);
    assert.equal(result.error.name, "TypeError");
    assert.equal(typeof result.error.message, "string");
    assert.ok(result.error.message.length > 0 && result.error.message.length <= 512);
  });
}
