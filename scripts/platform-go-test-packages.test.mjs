import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { migrationTestCensus, migrationTestCommands } from "./migration-test-partition.mjs";

import {
  apiserverFeatureRun,
  apiserverFeatureTestFiles,
  coveredBy,
  fullyRunPatterns,
  goTestNames,
  main,
  platformGoTestCommands,
  reachableScripts,
  uncoveredPackages,
  verifiedMigrationCoverage,
} from "./platform-go-test-packages.mjs";

const repositoryRoot = resolve(import.meta.dirname, "..");
const workflowPath = resolve(repositoryRoot, ".github/workflows/runnable-ui-acceptance.yml");
const apiserverDirectory = resolve(repositoryRoot, "services/platform/apiserver");

test("finds only platform go test commands, split at shell operators", () => {
  const commands = platformGoTestCommands([
    "go test -C services/platform -race -count=1 ./audit && go test -C services/health ./...",
    "cd x; go test -C services/platform ./a ./b || true",
    "echo go test -C services/platform ./not-a-command",
    "npm test",
  ].join("\n"));
  assert.deepEqual(commands, [
    "go test -C services/platform -race -count=1 ./audit",
    "go test -C services/platform ./a ./b",
  ]);
});

test("a filtered, list-only or compile-only command covers no package", () => {
  const patterns = fullyRunPatterns([
    "go test -C services/platform -race ./full ./tree/...",
    "go test -C services/platform -race ./filtered -run '^TestX$'",
    "go test -C services/platform -run=^TestY$ ./filtered2",
    "go test -C services/platform -race -c -o bin ./compiled",
    "go test -C services/platform ./skipped -skip TestExpensive",
    "go test -C services/platform -skip=Test ./filtered",
    "go test -C services/platform -test.skip=Test ./also-filtered",
    "go test -C services/platform -list Test ./inventory",
  ]);
  assert.deepEqual([...patterns].sort(), ["full", "tree/..."]);
});

test("migration filters partition the current long cases, future tests and ordinary Go examples and fuzz seeds", () => {
  const prefix = "^TestTemporalDiscovery";
  const long = prefix + "(Continuation|ShippedRuntime|TenantIsolation)Postgres$";
  const suffix = ["./agentsec-migrate"];
  assert.deepEqual(migrationTestCommands.continuation.slice(6), ["-timeout=70m", "-run", prefix + "ContinuationPostgres$", ...suffix]);
  assert.deepEqual(migrationTestCommands["discovery-long"].slice(6), ["-timeout=45m", "-run", prefix + "(ShippedRuntime|TenantIsolation)Postgres$", ...suffix]);
  assert.deepEqual(migrationTestCommands.discovery.slice(6), ["-timeout=65m", "-run", prefix, "-skip", long, ...suffix]);
  assert.deepEqual(migrationTestCommands.remaining.slice(6), ["-timeout=90m", "-skip", prefix, ...suffix]);
  const cases = ["TestTemporalDiscoveryContinuationPostgres", "TestTemporalDiscoveryShippedRuntimePostgres",
    "TestTemporalDiscoveryTenantIsolationPostgres", "TestTemporalDiscoveryContinuationPostgresFuture", "TestTemporalDiscoveryNew",
    "TestNew", "FuzzMigration", "ExampleMigration", "ok  github.com/zasp-ai/zasp-sec/services/platform/agentsec-migrate 0.1s"];
  assert.deepEqual(migrationTestCensus(cases.join("\n")), {continuation: 1, "discovery-long": 2, discovery: 2, remaining: 3});
  assert.throws(() => migrationTestCensus(cases.slice(1).join("\n")));
  assert.throws(() => migrationTestCensus([cases[0], ...cases].join("\n")));
  assert.throws(() => migrationTestCensus(cases.slice(0, -1).join("\n")));
});

test("only the checked acceptance migration matrix covers the complete package", () => {
  const yaml = readFileSync(workflowPath, "utf8");
  assert.equal(verifiedMigrationCoverage(yaml), "agentsec-migrate");
  for (const change of [
    ["lane: [continuation, discovery-long, discovery, remaining]", "lane: [discovery-long, discovery, remaining]"],
    ["-run '^TestTemporalDiscoveryContinuationPostgres$'", "-run '^TestTemporalDiscovery'"],
    ["-run '^TestTemporalDiscovery(ShippedRuntime|TenantIsolation)Postgres$'", "-run '^TestTemporalDiscovery(Continuation|ShippedRuntime|TenantIsolation)Postgres$'"],
    ["if: matrix.lane == 'discovery-long'", "if: false"],
    ["-skip '^TestTemporalDiscovery' ./agentsec-migrate", "-skip '^Test' ./agentsec-migrate"],
  ]) {
    assert.notEqual(yaml.replace(...change), yaml);
    assert.throws(() => verifiedMigrationCoverage(yaml.replace(...change)));
  }
});

test("a dir/... pattern covers the directory and everything below it only", () => {
  const patterns = new Set(["graphstore/...", "audit"]);
  assert.equal(coveredBy(patterns, "graphstore"), true);
  assert.equal(coveredBy(patterns, "graphstore/neo4jstore"), true);
  assert.equal(coveredBy(patterns, "graphstorex"), false);
  assert.equal(coveredBy(patterns, "audit"), true);
  assert.equal(coveredBy(patterns, "audit/sub"), false);
  assert.equal(coveredBy(new Set(["..."]), "anything/at/all"), true);
});

test("only npm scripts reachable from verify count, cycles included", () => {
  const scripts = {
    verify: "npm run a && npm run b",
    a: "go test -C services/platform ./alpha && npm run a",
    b: "npm run c",
    c: "go test -C services/platform ./gamma",
    orphan: "go test -C services/platform ./orphan",
  };
  const texts = reachableScripts(scripts, "verify");
  assert.equal(texts.length, 4);
  assert.deepEqual(uncoveredPackages(["alpha", "gamma", "orphan", "apiserver"], texts), ["orphan"]);
});

test("apiserver is never listed as a whole package", () => {
  assert.deepEqual(uncoveredPackages(["apiserver", "z", "a"], []), ["a", "z"]);
});

test("reads top-level test functions only", () => {
  const source = [
    "func TestOne(t *testing.T) {}",
    "func TestTwo(tb *testing.T) {",
    "\tfunc TestNested(t *testing.T) {}",
    "func BenchmarkX(b *testing.B) {}",
    "func FuzzY(f *testing.F) {}",
    "func helperTest(t *testing.T) {}",
    "func Test(t *testing.T) {}",
  ].join("\n");
  assert.deepEqual(goTestNames(source), ["TestOne", "TestTwo", "Test"]);
});

test("the apiserver feature slice selects exactly the tests of the feature files", () => {
  const expected = new Set();
  for (const file of apiserverFeatureTestFiles) {
    assert.ok(existsSync(resolve(apiserverDirectory, file)), `${file} no longer exists`);
    const names = goTestNames(readFileSync(resolve(apiserverDirectory, file), "utf8"));
    assert.ok(names.length > 0, `${file} declares no test`);
    for (const name of names) expected.add(name);
  }
  assert.equal(new Set(apiserverFeatureTestFiles).size, apiserverFeatureTestFiles.length, "a feature file is listed twice");
  const run = new RegExp(apiserverFeatureRun());
  const all = readdirSync(apiserverDirectory).filter((name) => name.endsWith("_test.go"))
    .flatMap((name) => goTestNames(readFileSync(resolve(apiserverDirectory, name), "utf8")));
  assert.ok(all.length > 1000, `found only ${all.length} apiserver tests`);
  const selected = new Set(all.filter((name) => run.test(name)));
  assert.deepEqual([...selected].sort(), [...expected].sort());
  // Anchored: a longer name that starts with a feature test is not selected.
  const [first] = [...expected];
  assert.equal(run.test(first + "Extra"), false);
  assert.equal(run.test("X" + first), false);
});

test("the CLI prints the feature slice", () => {
  assert.equal(main(["--apiserver-features"]), apiserverFeatureRun());
});

test("the workflow runs the listed packages and the apiserver feature tests", () => {
  const source = readFileSync(workflowPath, "utf8");
  const start = source.indexOf("\n  platform-go:\n");
  assert.ok(start >= 0, "runnable-ui-acceptance.yml has no platform-go job");
  const rest = source.slice(start + 1);
  const next = rest.slice(1).search(/\n {2}[A-Za-z0-9_-]+:\n/);
  const job = next < 0 ? rest : rest.slice(0, next + 1);
  assert.match(job, /GOTOOLCHAIN: local/);
  assert.match(job, /postgresql-18/);
  assert.match(job, /node --test scripts\/platform-go-test-packages\.test\.mjs/);
  assert.match(job, /mapfile -t packages < <\(node scripts\/platform-go-test-packages\.mjs\)/);
  assert.match(job, /go test -C services\/platform -race -count=1 [^\n]*"\$\{packages\[@\]\}"/);
  assert.match(job, /go test -C services\/platform -count=1 -run 'IsFast\$' \.\/guardrail/);
  assert.match(job, /go test -C services\/platform -race -count=1 [^\n]*-run "\$\(node scripts\/platform-go-test-packages\.mjs --apiserver-features\)" \.\/apiserver/);
});
