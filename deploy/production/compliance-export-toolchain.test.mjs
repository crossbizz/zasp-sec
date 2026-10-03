import assert from "node:assert/strict";
import test from "node:test";

const runtime = await import("./go-test-runtime.mjs").catch(error => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});

test("Go test launch preserves setup-go PATH and configured cache without ambient credentials", () => {
  assert.equal(typeof runtime.goTestRuntime, "function", "portable Go launch selection is required");
  const launch = runtime.goTestRuntime({ PATH: "/opt/hostedtoolcache/go/1.26.8/x64/bin:/usr/bin", HOME: "/home/runner", GOCACHE: "/tmp/runner-go-cache", AWS_SECRET_ACCESS_KEY: "must-not-forward", ZASP_POSTGRES_DSN: "must-not-forward", GOPROXY: "https://unapproved.example", GOTOOLCHAIN: "auto" });
  assert.equal(launch.executable, "go");
  assert.deepEqual(launch.env, { PATH: "/opt/hostedtoolcache/go/1.26.8/x64/bin:/usr/bin", HOME: "/home/runner", GOCACHE: "/tmp/runner-go-cache", GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off", GOENV: "off" });
});

test("Go test launch accepts an explicit executable outside Homebrew and leaves default cache portable", () => {
  assert.equal(typeof runtime.goTestRuntime, "function", "portable Go launch selection is required");
  const launch = runtime.goTestRuntime({ ZASP_GO_BIN: "/opt/toolchains/go/bin/go", PATH: "/usr/bin", HOME: "/home/runner" });
  assert.equal(launch.executable, "/opt/toolchains/go/bin/go");
  assert.equal(Object.hasOwn(launch.env, "GOCACHE"), false);
  for (const value of ["", " go", "go\n"]) assert.throws(() => runtime.goTestRuntime({ ZASP_GO_BIN: value }), /Go executable/);
});

test("Go test launch refuses an unpinned or malformed toolchain version", () => {
  assert.equal(typeof runtime.requireGoTestVersion, "function", "Go version gate is required");
  for (const version of ["go1.26.8\n", "go1.26.8\r\n"]) assert.doesNotThrow(() => runtime.requireGoTestVersion(version));
  for (const version of ["go1.25.13\n", "go1.26.0\n", "go1.26.4\n", "go1.26.5\n", "go1.26.7\n", "go1.26.9\n", "devel go1.26\n", "go1.26.8\nextra", ""]) assert.throws(() => runtime.requireGoTestVersion(version), /Go 1.26.8/);
});
