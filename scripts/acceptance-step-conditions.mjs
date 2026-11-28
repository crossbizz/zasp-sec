// Test helpers for the reusable acceptance workflow. Only these newly assigned
// IDs are scheduling metadata. Existing audit IDs are part of the release contract.
import assert from "node:assert/strict";
import { migrationTestCommands } from "./migration-test-partition.mjs";

const prerequisiteSteps = {
  verify: {
    dependencies: "Install locked dependencies",
    postgres: "Install PostgreSQL 18 reference fixture tools",
    secret_scanner: "Install pinned secret scanner",
    platform_metadata: "Prime platform full-MVS metadata for offline release contracts",
    ui_verify: "Verify runnable UI",
    migration_cache: "Prime native migration compilation cache for compliance browser",
    browser_prerequisites: "Provision isolated compliance browser prerequisites",
    authorization_tools: "Provision pinned owned authorization runtime tools",
  },
  "platform-go": { selection: "Verify the platform package selection" },
};

export function requiredStepOutcomes(condition) {
  assert.equal(typeof condition, "string", "expected a required acceptance condition");
  const pattern = /^\$\{\{ !cancelled\(\)((?: && steps\.[a-z][a-z0-9_]*\.outcome == 'success')+) \}\}$/;
  const match = pattern.exec(condition);
  assert.ok(match, `unsupported acceptance condition: ${condition}`);
  return [...match[1].matchAll(/steps\.([a-z][a-z0-9_]*)\.outcome/g)].map(([, id]) => id);
}

export function assertAcceptanceStepConditions(steps, job = "verify") {
  const names = prerequisiteSteps[job];
  assert.ok(names);
  const seen = new Set();
  for (const step of steps) {
    const guarded = job === "verify"
      ? seen.has("dependencies") && step.name !== "Verify production release sources"
      : step.name === "Verify the apiserver feature tests";
    if (guarded) {
      for (const id of requiredStepOutcomes(step.if)) {
        assert.ok(seen.has(id), `${step.name} references missing or later prerequisite ${id}`);
      }
    } else {
      assert.equal(step.if, undefined, `${step.name} must use the default success condition`);
    }
    if (step.id) {
      assert.ok(!seen.has(step.id), `duplicate step id ${step.id}`);
      if (Object.hasOwn(names, step.id)) assert.equal(step.name, names[step.id]);
      seen.add(step.id);
    }
  }
  for (const id of Object.keys(names)) assert.ok(seen.has(id), `missing setup step ${id}`);
}

// Existing tests also pin commands, timeout, environments and step order.
// Validate scheduling first so that normalization cannot conceal a skipped gate.
export function stepsWithoutAcceptanceScheduling(steps, job = "verify") {
  assertAcceptanceStepConditions(steps, job);
  return steps.map(step => {
    const copy = { ...step };
    delete copy.if;
    if (Object.hasOwn(prerequisiteSteps[job], copy.id)) delete copy.id;
    return copy;
  });
}

const fullSizeLaneIDs = ["audit_composition", "audit_race", "audit_controls", "audit_normal", "audit_orderly", "audit_orderly_race"];
const primeAuditChildrenCommand = `task_build_dir=$(mktemp -d "\${RUNNER_TEMP}/zasp-audit-build.XXXXXX")
trap 'rm -rf -- "$task_build_dir"' EXIT
flags=()
if [[ "$AUDIT_CHILD_MODE" == race ]]; then flags=(-race); fi
for package in apiserver agentsec-worker; do
  GOENV=off GOTOOLCHAIN=local GOGC=100 GOMEMLIMIT=off GOMAXPROCS=2 go test -C services/platform "\${flags[@]}" -c -o "$task_build_dir/$package.test" "./$package"
done
`;

const durableGroups = [
  "Verify migrations and runtime infrastructure packages",
  "Verify API and worker packages",
  "Verify runtime metadata, lineage and search packages",
];
const goTest = "go test -C services/platform -race -count=1 ";

function requiredFixtureSetup(main) {
  const pg = main.find(step => step.name === "Install PostgreSQL 18 reference fixture tools");
  assert.ok(pg);
  return [
    {name: "Check out repository", uses: "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"},
    {name: "Set up Node", uses: "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020", with: {"node-version": "22.23.1"}},
    {name: "Set up Go", uses: "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16", with: {"go-version": "1.26.8", cache: true, "cache-dependency-path": "services/platform/go.sum"}},
    pg,
  ];
}

const primeMigrationChildrenCommand = `task_build_dir=$(mktemp -d "\${RUNNER_TEMP}/zasp-migration-build.XXXXXX")
trap 'rm -rf -- "$task_build_dir"' EXIT
for package in agentsec-worker apiserver authorization; do
  go test -C services/platform -c -o "$task_build_dir/$package.test" "./$package"
done
go build -C services/platform -o "$task_build_dir/migrate" ./agentsec-migrate
go build -C services/platform -race -o "$task_build_dir/migrate-race" ./agentsec-migrate
`;

export function assertMigrationScheduling(jobs, pinnedSetup = requiredFixtureSetup(stepsWithoutAcceptanceScheduling(jobs.verify.steps))) {
  const {steps, ...settings} = jobs["migration-tests"];
  assert.deepEqual(settings, {
    name: "Migration commands (${{ matrix.lane }})", "runs-on": "ubuntu-24.04",
    "timeout-minutes": 170, env: {GOTOOLCHAIN: "local"},
    strategy: {"fail-fast": false, matrix: {lane: ["continuation", "discovery-long", "discovery", "remaining"]}},
  });
  const lanes = Object.entries(migrationTestCommands).map(([lane, args]) => {
    const command = args.map(arg => arg.startsWith("^") ? "'" + arg + "'" : arg).join(" ");
    const minutes = Number(/^-timeout=(\d+)m$/.exec(args[6])[1]);
    return {
      name: `Run ${lane} migration tests`, if: `matrix.lane == '${lane}'`, "timeout-minutes": minutes + 10,
      run: ["node scripts/owned-migration-tests.mjs -- \\", "  " + command, ""].join("\n"),
    };
  });
  assert.deepEqual(steps, [
    ...pinnedSetup,
    {name: "Prime compilation for migration fixture subprocesses", "timeout-minutes": 30, run: primeMigrationChildrenCommand},
    {name: "Provision pinned owned authorization runtime tools", "timeout-minutes": 5,
      run: "node scripts/hosted-runtime-tool-intake.mjs"},
    {name: "Verify migration test partition", if: "matrix.lane == 'remaining'", "timeout-minutes": 20,
      run: "node --test scripts/owned-migration-tests.test.mjs\nnode scripts/migration-test-partition.mjs\n"},
    ...lanes,
  ]);
  return steps.at(-1).run.trimEnd().split(" ").at(-1);
}

// The predecessor digest covers one shell block. Validate the required jobs,
// then use their real commands and real -list selector to recover its inventory.
function foldDurableGroups(jobs, main, pinnedSetup) {
  const isolatedPackage = assertMigrationScheduling(jobs, pinnedSetup);
  const {steps, ...settings} = jobs["durable-apiserver"];
  assert.deepEqual(settings, {
    name: "Durable API server (${{ matrix.shard }})", "runs-on": "ubuntu-24.04",
    "timeout-minutes": 90, env: {GOTOOLCHAIN: "local"},
    strategy: {"fail-fast": false, matrix: {shard: [0, 1, 2, 3, 4, 5, 6, 7]}},
  });
  const {run, ...stage} = steps.at(-1);
  assert.deepEqual(steps.slice(0, -1), [
    ...pinnedSetup,
    {name: "Test durable API server partition", if: "matrix.shard == 0", run: "node --test scripts/durable-apiserver-shard.test.mjs"},
  ]);
  assert.deepEqual(stage, {
    name: "Verify runtime sessions, enrollment pairing and candidate authority", "timeout-minutes": 70,
    env: {DURABLE_SHARD: "${{ matrix.shard }}"},
  });
  const [temp, build, binary, settlementBinary, list, select, test, end] = run.split("\n");
  assert.equal(settlementBinary, 'export ZASP_ATTACK_LAB_TASK2_WORKER_BINARY="$ZASP_RECONCILE_CLIENT_BINARY"');
  assert.equal(end, "");
  assert.equal(run.split("\n").length, 8);
  const inventory = /^go test -C services\/platform -race -count=1 \.\/apiserver -list ('[^']+') > "\$task_reconciler_dir\/tests"$/.exec(list);
  assert.ok(inventory, "missing complete durable API test inventory");
  assert.equal(select, 'selection=$(node scripts/durable-apiserver-shard.mjs "$task_reconciler_dir/tests" "$DURABLE_SHARD")');
  assert.equal(test, goTest + '-timeout=60m ./apiserver -run "$selection"');
  const originalApiRun = [temp, build, binary, goTest + "-timeout=30m ./apiserver -run " + inventory[1], ""].join("\n");

  const index = jobs.verify.steps.findIndex(step => step.name === durableGroups[0]);
  assert.ok(index >= 0);
  const groups = jobs.verify.steps.slice(index, index + durableGroups.length);
  assert.deepEqual(groups.map(step => step.name), durableGroups);
  assert.deepEqual(groups.map(step => step.run.trimEnd().split("\n").length), [2, 1, 1]);
  for (const {name, run, ...guard} of groups) {
    assert.equal(typeof run, "string", name);
    assert.deepEqual(guard, {if: "${{ !cancelled() && steps.postgres.outcome == 'success' }}"});
  }
  const [check, packages] = groups[0].run.trimEnd().split("\n");
  assert.ok(packages.startsWith(goTest));
  const joined = [check, goTest + isolatedPackage + " " + packages.slice(goTest.length), ""].join("\n");
  main.splice(index, groups.length, {
    name: "Verify durable runtime sessions, enrollment pairing and candidate authority",
    run: joined + groups.slice(1).map(group => group.run).join("") + originalApiRun,
  });
}

// Rebuild the predecessor command inventory only after proving that GitHub will
// run every full-size lane independently on the same checkout. The callers pin
// every returned command, environment, timeout and the original step digest.
export function requiredAcceptanceSteps(jobs) {
  const main = stepsWithoutAcceptanceScheduling(jobs.verify.steps);
  const {steps, ...settings} = jobs["audit-full-size"];
  assert.deepEqual(settings, {
    name: "Full-size audit (${{ matrix.lane }})", "runs-on": "ubuntu-24.04", "timeout-minutes": 90,
    strategy: {"fail-fast": false, matrix: {lane: fullSizeLaneIDs}}, env: {GOTOOLCHAIN: "local"},
  });
  const pinnedSetup = requiredFixtureSetup(main);
  foldDurableGroups(jobs, main, pinnedSetup);
  assert.deepEqual(steps.slice(0, 5), [
    ...pinnedSetup,
    {name: "Prime audit child compilation", "timeout-minutes": 30, env: {
      AUDIT_CHILD_MODE: "${{ (matrix.lane == 'audit_composition' || matrix.lane == 'audit_race' || matrix.lane == 'audit_orderly_race') && 'race' || 'normal' }}",
    }, run: primeAuditChildrenCommand},
  ]);
  const lanes = steps.slice(5);
  assert.deepEqual(lanes.map(step => step.id), fullSizeLaneIDs);
  const selected = lanes.map(({if: condition, ...step}) => {
    assert.equal(condition, `matrix.lane == '${step.id}'`);
    assert.equal(step["continue-on-error"], undefined);
    return step;
  });
  const index = main.findIndex(step => step.name === "Verify sensor lineage and authenticated replay");
  assert.ok(index > 0 && main[index - 1].id === "audit_helpers");
  main.splice(index, 0, ...selected);
  return main;
}
