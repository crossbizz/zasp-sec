import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { JSON_SCHEMA, load } from "js-yaml";
import { describe, expect, it } from "vitest";

type WorkflowStep = {
  "timeout-minutes"?: number;
  if?: unknown;
  "continue-on-error"?: unknown;
  run?: string;
  uses?: string;
  with?: Record<string, unknown>;
};

type WorkflowJob = {
  "runs-on"?: string;
  if?: unknown;
  "continue-on-error"?: unknown;
  steps?: WorkflowStep[];
};

type Workflow = {
  on?: Record<string, unknown>;
  permissions?: Record<string, unknown>;
  jobs?: Record<string, WorkflowJob>;
};

type PackageManifest = {
  scripts?: Record<string, string>;
};

const repositoryRoot = process.cwd();
const checkoutAction = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1";
const setupNodeAction = "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020";
const setupGoAction = "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16";
const postgresFixtureCommand = `fixture_pg_dir=$(mktemp -d "\${RUNNER_TEMP}/zasp-pgdg.XXXXXX")
curl --fail --location --retry 3 --max-time 60 --output "$fixture_pg_dir/pgdg.asc" https://www.postgresql.org/media/keys/ACCC4CF8.asc
printf '%s  %s\\n' 0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76 "$fixture_pg_dir/pgdg.asc" | sha256sum --check -
sudo install -m 0644 "$fixture_pg_dir/pgdg.asc" /usr/share/keyrings/zasp-ci-pgdg.asc
printf '%s\\n' 'deb [arch=amd64 signed-by=/usr/share/keyrings/zasp-ci-pgdg.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main' | sudo tee /etc/apt/sources.list.d/zasp-ci-pgdg.list > /dev/null
sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends postgresql-18 postgresql-client-18
fixture_pg_bin=/usr/lib/postgresql/18/bin
for fixture_tool in initdb postgres pg_isready pg_ctl pg_config; do
  test -x "$fixture_pg_bin/$fixture_tool"
done
case "$("$fixture_pg_bin/postgres" --version)" in
  "postgres (PostgreSQL) 18."*) ;;
  *) exit 1 ;;
esac
"$fixture_pg_bin/postgres" --version
printf '%s\\n' "$fixture_pg_bin" >> "$GITHUB_PATH"
`;
const sensorAcceptanceCommand = `export PATH="$(pg_config --bindir):$PATH"
test -x "$(pg_config --bindir)/initdb"
go test -C services/sensor-agent -race -count=1 ./...
go test -C services/platform -race -count=1 ./apiserver -run '^(TestRuntimeAcceptance|TestProductionRuntimeIngestHTTPPersistsTransactionalOutboxBeforeAcceptance)'
`;
const daemonReplayCommand = "node --test scripts/sensor-daemon-replay.test.mjs\nnode scripts/sensor-daemon-replay.mjs\n";
const maintenanceAlertCommand = `task_prom_dir=$(mktemp -d "\${RUNNER_TEMP}/zasp-promtool.XXXXXX")
curl --fail --location --retry 3 --max-time 120 --output "$task_prom_dir/prometheus.tar.gz" https://github.com/prometheus/prometheus/releases/download/v3.14.0/prometheus-3.14.0.linux-amd64.tar.gz
printf '%s  %s\\n' f665c6da19eb7ba399c915d30c7d9793c9b417bf8a749b504bc470678631478d "$task_prom_dir/prometheus.tar.gz" | sha256sum --check -
tar -xzf "$task_prom_dir/prometheus.tar.gz" -C "$task_prom_dir" prometheus-3.14.0.linux-amd64/promtool
ZASP_PROMTOOL_BIN="$task_prom_dir/prometheus-3.14.0.linux-amd64/promtool" node --test deploy/production/reconciliation-maintenance-alerts.test.mjs
ZASP_PROMTOOL_BIN="$task_prom_dir/prometheus-3.14.0.linux-amd64/promtool" go test -C services/platform -race -count=1 ./agentsec-api -run '^TestReconciliationMaintenancePrometheusExposition$'
`;

async function readWorkflow(): Promise<Workflow> {
  const source = await readFile(
    resolve(repositoryRoot, ".github/workflows/runnable-ui.yml"),
    "utf8",
  );

  return load(source, { schema: JSON_SCHEMA }) as Workflow;
}

async function readPackageManifest(): Promise<PackageManifest> {
  const source = await readFile(resolve(repositoryRoot, "package.json"), "utf8");
  return JSON.parse(source) as PackageManifest;
}

function isUnrestrictedEvent(event: unknown): boolean {
  return event === null || (
    typeof event === "object" &&
    event !== null &&
    Object.keys(event).length === 0
  );
}

function assertRunnableUiWorkflow(
  workflow: Workflow,
  packageManifest: PackageManifest,
) {
  const verificationCommands = packageManifest.scripts?.verify
    .split("&&")
    .map((command) => command.trim());

  expect(workflow.on).toHaveProperty("push");
  expect(workflow.on).toHaveProperty("pull_request");
  expect(isUnrestrictedEvent(workflow.on?.push)).toBe(true);
  expect(isUnrestrictedEvent(workflow.on?.pull_request)).toBe(true);
  expect(workflow.permissions).toEqual({ contents: "read" });
  expect(verificationCommands).toEqual([
    "npm run dependencies:check",
    "npm run health:contract:test",
    "npm run openapi:test",
    "npm run openapi:lint",
    "npm run openapi:check",
    "npm run ui-api:test",
    "npm run ui-api:check",
    "npm run raw-fetch:test",
    "npm run saas:tenancy:test",
    "npm run graph:neo4j:test",
    "npm run db:tenant-rls:test",
    "npm test",
    "npm run typecheck",
    "npm run lint",
    "npm run production:imports:test",
    "npm run production:imports:source",
    "npm run staging:gate:test",
    "npm run production:release:test",
    "npm run build",
    "npm run production:imports:compiled",
    "npm run implementation:status:check",
  ]);

  const verificationJobs = Object.values(workflow.jobs ?? {}).filter((job) =>
    job.steps?.some((step) => step.run === "npm run verify"),
  );
  expect(verificationJobs).toHaveLength(1);

  const verificationJob = verificationJobs[0];
  if (!verificationJob) return;

  expect(verificationJob.if).toBeUndefined();
  expect(verificationJob["runs-on"]).toBe("ubuntu-24.04");
  expect(verificationJob["continue-on-error"]).toBeUndefined();

  const verificationSteps = verificationJob.steps ?? [];
  expect(verificationSteps).toHaveLength(16);
  expect(verificationSteps.map((step) => step.uses ?? step.run)).toEqual([
    checkoutAction,
    setupNodeAction,
    setupGoAction,
    "npm install --global npm@10.9.8",
    "SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm ci",
    postgresFixtureCommand,
    "go install github.com/zricethezav/gitleaks/v8@v8.30.1",
    "npm run implementation:status:check",
    "npm run verify",
    "node --test scripts/red-team-runtime-proof.test.mjs scripts/production-combined-e2e.test.mjs scripts/owned-command.test.mjs scripts/implementation-status-check.test.mjs workers/redteam-node/runner.test.mjs workers/redteam-node/artifact.test.mjs\ngo test -C services/platform -race -count=1 ./apiserver -run '^TestProductionRedTeamHandlerOperationAcceptance$'\n",
    "npm run production:release:gate",
    maintenanceAlertCommand,
    "test -x \"$(pg_config --bindir)/initdb\"\ngo test -C services/platform -race -count=1 ./agentsec-migrate ./migrations ./runtimeevent\ngo test -C services/platform -race -count=1 ./runtimemetadata ./sensoradapter ./sessionsearch ./runtimeprojection ./runtimecorrelation ./runtimeindex/...\ngo test -C services/platform -race -count=1 ./apiserver -run '^(TestRuntime(Session|EnrollmentPairing|CandidateAuthority|CorrelationRouting)|TestSensor|TestReconciliationLanePlan|TestReconciliationMaintenance|TestConnectorAuthorizationPostgresReconciliationIndexes)'\n",
    sensorAcceptanceCommand,
    daemonReplayCommand,
    "go test -C proofs/attack-lab-egress -race -count=1 ./...\ngo test -C services/platform -race -count=1 ./attack-lab-runner ./attacklabrunner ./attack-lab-proxy ./attacklabproxy ./attacklab\nnode --test proofs/attack-lab-egress/run.test.mjs\nnode proofs/attack-lab-egress/run.mjs\nZASP_ATTACK_LAB_EGRESS_DOCKER=true node --test proofs/attack-lab-egress/interruption.test.mjs\n",
  ]);
  expect(verificationSteps[0]?.with).toEqual({ "fetch-depth": 0 });
  expect(verificationSteps[1]?.with).toMatchObject({
    "node-version": "22.23.1",
    cache: "npm",
  });
  expect(verificationSteps[2]?.with).toMatchObject({
    "go-version": "1.25.6",
    cache: true,
    "cache-dependency-path": "services/platform/go.sum",
  });
  expect(verificationSteps[14]?.["timeout-minutes"]).toBe(15);
  for (const step of verificationSteps) {
    expect(step.if).toBeUndefined();
    expect(step["continue-on-error"]).toBeUndefined();
  }
}

function validWorkflow(): Workflow {
  return {
    on: { push: null, pull_request: null },
    permissions: { contents: "read" },
    jobs: {
      verify: {
        "runs-on": "ubuntu-24.04",
        steps: [
          { uses: checkoutAction, with: { "fetch-depth": 0 } },
          {
            uses: setupNodeAction,
            with: { "node-version": "22.23.1", cache: "npm" },
          },
          { uses: setupGoAction, with: { "go-version": "1.25.6", cache: true, "cache-dependency-path": "services/platform/go.sum" } },
          { run: "npm install --global npm@10.9.8" },
          { run: "SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm ci" },
          { run: postgresFixtureCommand },
          { run: "go install github.com/zricethezav/gitleaks/v8@v8.30.1" },
          { run: "npm run implementation:status:check" },
          { run: "npm run verify" },
          { run: "node --test scripts/red-team-runtime-proof.test.mjs scripts/production-combined-e2e.test.mjs scripts/owned-command.test.mjs scripts/implementation-status-check.test.mjs workers/redteam-node/runner.test.mjs workers/redteam-node/artifact.test.mjs\ngo test -C services/platform -race -count=1 ./apiserver -run '^TestProductionRedTeamHandlerOperationAcceptance$'\n" },
          { run: "npm run production:release:gate" },
          { run: maintenanceAlertCommand },
          { run: "test -x \"$(pg_config --bindir)/initdb\"\ngo test -C services/platform -race -count=1 ./agentsec-migrate ./migrations ./runtimeevent\ngo test -C services/platform -race -count=1 ./runtimemetadata ./sensoradapter ./sessionsearch ./runtimeprojection ./runtimecorrelation ./runtimeindex/...\ngo test -C services/platform -race -count=1 ./apiserver -run '^(TestRuntime(Session|EnrollmentPairing|CandidateAuthority|CorrelationRouting)|TestSensor|TestReconciliationLanePlan|TestReconciliationMaintenance|TestConnectorAuthorizationPostgresReconciliationIndexes)'\n" },
          { run: sensorAcceptanceCommand },
          { run: daemonReplayCommand, "timeout-minutes": 15 },
          { run: "go test -C proofs/attack-lab-egress -race -count=1 ./...\ngo test -C services/platform -race -count=1 ./attack-lab-runner ./attacklabrunner ./attack-lab-proxy ./attacklabproxy ./attacklab\nnode --test proofs/attack-lab-egress/run.test.mjs\nnode proofs/attack-lab-egress/run.mjs\nZASP_ATTACK_LAB_EGRESS_DOCKER=true node --test proofs/attack-lab-egress/interruption.test.mjs\n" },
        ],
      },
    },
  };
}

describe("runnable UI GitHub Actions gate", () => {
  it.each(["omitted", "skipped", "unbounded", "allowed-failure"])("rejects %s actual daemon proof", async (condition) => {
    const workflow = validWorkflow();
    const steps = workflow.jobs?.verify?.steps;
    const step = steps?.find(value => value.run === daemonReplayCommand);
    if (!steps || !step) throw new Error("daemon proof fixture is missing");
    if (condition === "omitted") steps.splice(steps.indexOf(step), 1);
    if (condition === "skipped") step.if = false;
    if (condition === "unbounded") delete step["timeout-minutes"];
    if (condition === "allowed-failure") step["continue-on-error"] = true;
    const manifest = await readPackageManifest();
    expect(() => assertRunnableUiWorkflow(workflow, manifest)).toThrow();
  });
  it("accepts the baseline before testing hostile workflow mutations", async () => {
    assertRunnableUiWorkflow(validWorkflow(), await readPackageManifest());
  });
  const invalidWorkflowCases: Array<{
    description: string;
    workflow: Workflow;
  }> = [
    {
      description: "a filtered push trigger",
      workflow: {
        ...validWorkflow(),
        on: { push: { branches: ["main"] }, pull_request: null },
      },
    },
    {
      description: "a filtered pull-request trigger",
      workflow: {
        ...validWorkflow(),
        on: { push: null, pull_request: { paths: ["app/**"] } },
      },
    },
    {
      description: "quality steps split across jobs",
      workflow: {
        ...validWorkflow(),
        jobs: {
          setup: {
            steps: validWorkflow().jobs?.verify?.steps?.slice(0, 4),
          },
          verify: { steps: [{ run: "npm run verify" }] },
        },
      },
    },
    {
      description: "quality steps in the wrong order",
      workflow: {
        ...validWorkflow(),
        jobs: {
          verify: {
            steps: [
              { uses: setupNodeAction, with: { "node-version": "22.23.1", cache: "npm" } },
              { uses: checkoutAction, with: { "fetch-depth": 0 } },
              { run: "npm install --global npm@10.9.8" },
              { run: "SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm ci" },
              { run: "npm run verify" },
            ],
          },
        },
      },
    },
    {
      description: "a conditional verification job",
      workflow: {
        ...validWorkflow(),
        jobs: { verify: { ...validWorkflow().jobs?.verify, if: false } },
      },
    },
    {
      description: "a continue-on-error verification job",
      workflow: {
        ...validWorkflow(),
        jobs: {
          verify: {
            ...validWorkflow().jobs?.verify,
            "continue-on-error": true,
          },
        },
      },
    },
    {
      description: "a continue-on-error quality step",
      workflow: {
        ...validWorkflow(),
        jobs: {
          verify: {
            steps: [
              { uses: checkoutAction },
              {
                uses: setupNodeAction,
                with: { "node-version": "22.23.1", cache: "npm" },
              },
              { run: "npm install --global npm@10.9.8" },
              { run: "SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm ci" },
              { run: "npm run verify", "continue-on-error": true },
            ],
          },
        },
      },
    },
  ];

  it.each(invalidWorkflowCases)("rejects $description", async ({ workflow }) => {
    const packageManifest = await readPackageManifest();
    expect(() => assertRunnableUiWorkflow(workflow, packageManifest)).toThrow();
  });

  it.each(["./runtimemetadata", "./sensoradapter", "./sessionsearch", "./runtimeprojection", "./runtimecorrelation", "./runtimeindex/..."])("rejects omission of runtime search verification for %s", async (target) => {
    const workflow = validWorkflow();
    const step = workflow.jobs?.verify?.steps?.find((value) => value.run?.includes("./sessionsearch"));
    expect(step?.run).toContain(target);
    if (!step?.run) throw new Error("runtime verification fixture is missing");
    step.run = step.run.replace(` ${target}`, "");
    const packageManifest = await readPackageManifest();
    expect(() => assertRunnableUiWorkflow(workflow, packageManifest)).toThrow();
  });

  it.each([
    ["wrong PostgreSQL major", "postgresql-18", "postgresql-16"],
    ["ambient PostgreSQL selection", "fixture_pg_bin=/usr/lib/postgresql/18/bin", 'fixture_pg_bin="$(pg_config --bindir)"'],
    ["missing key verification", " | sha256sum --check -", ""],
    ["missing server version check", '  *) exit 1 ;;', '  *) ;;'],
  ])("rejects %s in reference database setup", async (_name, before, after) => {
    const workflow = validWorkflow();
    const step = workflow.jobs?.verify?.steps?.find((value) => value.run === postgresFixtureCommand);
    if (!step?.run) throw new Error("PostgreSQL setup fixture is missing");
    step.run = step.run.replace(before, after);
    const packageManifest = await readPackageManifest();
    expect(() => assertRunnableUiWorkflow(workflow, packageManifest)).toThrow();
  });

  it("runs the locked runnable-UI verification on every push and pull request", async () => {
    const [workflow, packageManifest] = await Promise.all([
      readWorkflow(),
      readPackageManifest(),
    ]);

    assertRunnableUiWorkflow(workflow, packageManifest);
  });
});
