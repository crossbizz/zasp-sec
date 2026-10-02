import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { JSON_SCHEMA, load } from "js-yaml";
import { describe, expect, it } from "vitest";
import { assertAuditSourceCoverage, readAuditSources, type AuditLane } from "./audit-ci-source-contract";

type WorkflowStep = {
  name?: string;
  id?: string;
  env?: Record<string, string>;
  shell?: unknown;
  "working-directory"?: unknown;
  "timeout-minutes"?: number;
  if?: unknown;
  "continue-on-error"?: unknown;
  run?: string;
  uses?: string;
  with?: Record<string, unknown>;
};

type WorkflowJob = {
  env?: unknown;
  defaults?: unknown;
  "timeout-minutes"?: number;
  "runs-on"?: string;
  if?: unknown;
  "continue-on-error"?: unknown;
  steps?: WorkflowStep[];
};

type Workflow = {
  env?: unknown;
  defaults?: unknown;
  on?: Record<string, unknown>;
  permissions?: Record<string, unknown>;
  jobs?: Record<string, WorkflowJob>;
};

type PackageManifest = {
  scripts?: Record<string, string>;
};

const repositoryRoot = process.cwd();
const sessionIAMCommand = "task_tf_dir=$(mktemp -d \"${RUNNER_TEMP}/zasp-terraform.XXXXXX\")\ncurl --fail --location --retry 3 --max-time 120 --output \"$task_tf_dir/terraform.zip\" https://releases.hashicorp.com/terraform/1.15.8/terraform_1.15.8_linux_amd64.zip\nprintf '%s  %s\\n' d25ce7b6902013ad905db3d2eab0be4cd905887fe88b81a6171b8d5503c31f3d \"$task_tf_dir/terraform.zip\" | sha256sum --check -\nunzip -q \"$task_tf_dir/terraform.zip\" -d \"$task_tf_dir\"\nexport TF_DATA_DIR=\"$task_tf_dir/data\"\n\"$task_tf_dir/terraform\" -chdir=deploy/staging init -backend=false -input=false -lockfile=readonly\n\"$task_tf_dir/terraform\" -chdir=deploy/staging test -filter=tests/session_search_iam.tftest.hcl -filter=tests/test_reconciler_iam.tftest.hcl -var-file=release.tfvars -no-color\n";
const checkoutAction = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1";
const setupNodeAction = "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020";
const setupGoAction = "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16";
const compliancePrerequisitesCommand = `# This populates the exact cache entry consumed with --pull=never.
compliance_postgres_image=postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba
docker pull "$compliance_postgres_image"
docker image inspect "$compliance_postgres_image" --format '{{json .RepoDigests}}' | node --input-type=module -e 'import assert from "node:assert/strict"; import { readFileSync } from "node:fs"; assert.ok(JSON.parse(readFileSync(0,"utf8")).includes(process.argv[1]), "pinned browser PostgreSQL digest absent");' "$compliance_postgres_image"
node --input-type=module <<'NODE'
import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { selectBrowserExecutable } from "./scripts/browser-prerequisites.mjs";
const chrome = selectBrowserExecutable();
console.log(\`Hosted compliance browser: \${chrome}\`);
console.log(execFileSync(chrome, ["--version"], { encoding: "utf8", timeout: 5000, killSignal: "SIGKILL" }).trim());
appendFileSync(process.env.GITHUB_ENV, \`ZASP_COMBINED_E2E_CHROME=\${chrome}\\n\`);
NODE
`;
const complianceAcceptanceCommand = "node --test scripts/browser-prerequisites.test.mjs scripts/browser-e2e-helpers.test.mjs scripts/owned-browser-postgres.test.mjs scripts/compliance-browser-bytes.test.mjs\nnode scripts/production-combined-e2e.mjs\n";
const complianceSteps: WorkflowStep[] = [
  { name: "Provision isolated compliance browser prerequisites", "timeout-minutes": 10, run: compliancePrerequisitesCommand },
  { name: "Verify current compliance browser acceptance", "timeout-minutes": 15, env: { ZASP_COMBINED_E2E_COMPLIANCE: "true" }, run: complianceAcceptanceCommand },
];
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
const auditExportCommand = `export PATH="$(pg_config --bindir):$PATH"
test -x "$(pg_config --bindir)/initdb"
go test -C services/platform -race -count=1 -timeout=30m ./audit ./auditexportconfig ./artifactstore/...
`;
const auditPrerequisitesCommand = `test "$(node --version)" = v22.23.1
test "$(go env GOVERSION)" = go1.25.13
export PATH="$(pg_config --bindir):$PATH"
for fixture_tool in initdb postgres pg_ctl pg_isready cc docker; do
  command -v "$fixture_tool"
done
test "$(id -u)" -ne 0
cc --version
docker info --format '{{.ServerVersion}}'
docker pull localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c
`;
const auditLanes: Array<{ id: string; pattern: string; minutes: number; env?: Record<string, string> }> = [
  { id: "audit_a1", pattern: "^TestAuditExportPostgres[A-M]", minutes: 30 },
  { id: "audit_a2", pattern: "^TestAuditExportPostgres[N-Z]", minutes: 30 },
  { id: "audit_a3", pattern: "^TestAuditExport(Public|Identity|Worker|RunContext|s)", minutes: 30, env: { ZASP_AUDIT_EXPORT_LOCALSTACK_REQUIRED: "true" } },
  { id: "audit_a4", pattern: "^TestAuditExport(Artifact|Composition|Contents|Cursor|Descriptor|HTTP(Create|Get|PostWorker|Rejects)|Localstack|LocalStack|Policy|Process|Production|Read|Recovery|Repository)", minutes: 30 },
  { id: "audit_helpers", pattern: "^(TestAuditHTTP(Size(Expected|Memory|Oracle|PostgresStop|Process(Inputs|Protocol|TerminalTail|PrivateFiles|Environment|StartFailure|BackgroundOwnership)|Provider|Shutdown)|Fixture)|TestDisposablePostgresCleanup)", minutes: 30 },
  { id: "audit_composition", pattern: "^TestAuditHTTPSizeProcessCompositionPostgres$", minutes: 32 },
  { id: "audit_race", pattern: "^TestAuditExportHTTPSizeProcessPostgres$", minutes: 32, env: { ZASP_AUDIT_HTTP_SIZE_BUILD: "race" } },
  { id: "audit_controls", pattern: "^TestAuditExportHTTPSizeMemorySensitivityPostgres$", minutes: 40, env: { ZASP_AUDIT_HTTP_SIZE_BUILD: "" } },
  { id: "audit_normal", pattern: "^TestAuditExportHTTPSizeProcessPostgres$", minutes: 40, env: { ZASP_AUDIT_HTTP_SIZE_BUILD: "" } },
  { id: "audit_orderly", pattern: "^TestAuditExportHTTPOrderlyRestartPostgres$", minutes: 20, env: { ZASP_AUDIT_HTTP_SIZE_BUILD: "" } },
  { id: "audit_orderly_race", pattern: "^TestAuditExportHTTPOrderlyRestartPostgres$", minutes: 20, env: { ZASP_AUDIT_HTTP_SIZE_BUILD: "race" } },
];
const auditSteps: WorkflowStep[] = [
  { id: "audit_prerequisites", run: auditPrerequisitesCommand, "timeout-minutes": 35 },
  { id: "audit_packages", run: auditExportCommand, "timeout-minutes": 35 },
  ...auditLanes.map(lane => ({ id: lane.id, env: lane.env, "timeout-minutes": lane.minutes + 5,
    run: `export PATH="$(pg_config --bindir):$PATH"\ntest -x "$(pg_config --bindir)/initdb"\ngo test -C services/platform -race -count=1 -v -timeout=${lane.minutes}m ./apiserver -run '${lane.pattern}'\n` })),
];

function actualAuditLanes(workflow: Workflow): AuditLane[] {
  const localstackImage = workflow.jobs?.verify?.steps?.find(step => step.id === "audit_prerequisites")?.run?.match(/^docker pull (\S+)$/m)?.[1];
  return (workflow.jobs?.verify?.steps ?? []).filter(step => step.id?.startsWith("audit_") && step.run?.includes("./apiserver"))
    .map(step => {
      const matches = [...(step.run ?? "").matchAll(/^go test -C services\/platform -race -count=1 -v -timeout=\d+m \.\/apiserver -run '([^']+)'$/gm)];
      expect(matches, `${step.id}: exact bounded command, no filters/bypasses`).toHaveLength(1);
      return { id: step.id!, pattern: matches[0][1], mode: step.env?.ZASP_AUDIT_HTTP_SIZE_BUILD,
        localstackImage, localstackRequired: step.env?.ZASP_AUDIT_EXPORT_LOCALSTACK_REQUIRED,
        repeat: step.id === "audit_race" || step.id === "audit_orderly_race" };
    });
}
const daemonReplayCommand = "node --test scripts/sensor-daemon-replay.test.mjs\nnode scripts/sensor-daemon-replay.mjs\n";
const maintenanceAlertCommand = `task_prom_dir=$(mktemp -d "\${RUNNER_TEMP}/zasp-promtool.XXXXXX")
curl --fail --location --retry 3 --max-time 120 --output "$task_prom_dir/prometheus.tar.gz" https://github.com/prometheus/prometheus/releases/download/v3.14.0/prometheus-3.14.0.linux-amd64.tar.gz
printf '%s  %s\\n' f665c6da19eb7ba399c915d30c7d9793c9b417bf8a749b504bc470678631478d "$task_prom_dir/prometheus.tar.gz" | sha256sum --check -
tar -xzf "$task_prom_dir/prometheus.tar.gz" -C "$task_prom_dir" prometheus-3.14.0.linux-amd64/promtool
ZASP_PROMTOOL_BIN="$task_prom_dir/prometheus-3.14.0.linux-amd64/promtool" node --test deploy/production/reconciliation-maintenance-alerts.test.mjs deploy/production/audit-export-alerts.test.mjs deploy/production/test-reconciler-alerts.test.mjs
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
  expect(workflow.env).toBeUndefined();
  expect(workflow.defaults).toBeUndefined();
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
  expect(verificationJob.env).toBeUndefined();
  expect(verificationJob.defaults).toBeUndefined();
  expect(verificationJob["timeout-minutes"]).toBeUndefined();

  const verificationSteps = verificationJob.steps ?? [];
  expect(verificationSteps).toHaveLength(32);
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
    ...complianceSteps.map(step => step.run),
    "node --test scripts/red-team-runtime-proof.test.mjs scripts/production-combined-e2e.test.mjs scripts/audit-export-browser-proof.test.mjs scripts/audit-export-volume-proof.test.mjs scripts/runtime-precision-browser-proof.test.mjs scripts/owned-command.test.mjs scripts/implementation-status-check.test.mjs workers/redteam-node/runner.test.mjs workers/redteam-node/artifact.test.mjs\ngo test -C services/platform -race -count=1 ./apiserver -run '^TestProductionRedTeamHandlerOperationAcceptance$'\n",
    "npm run production:release:gate",
    sessionIAMCommand,
    maintenanceAlertCommand,
    "test -x \"$(pg_config --bindir)/initdb\"\ngo test -C services/platform -race -count=1 ./agentsec-migrate ./migrations ./runtimeevent ./internal/testprocess ./internal/sandboxcutover\ngo test -C services/platform -race -count=1 ./agentsec-api ./agentsec-worker\ngo test -C services/platform -race -count=1 ./runtimemetadata ./runtimelineage ./sensoradapter ./sessionsearch ./runtimeprojection ./runtimecorrelation ./runtimeindex/...\ntask_reconciler_dir=$(mktemp -d \"${RUNNER_TEMP}/zasp-reconciler.XXXXXX\")\ngo test -C services/platform -race -c -o \"$task_reconciler_dir/worker-tests\" ./agentsec-worker\nexport ZASP_RECONCILE_CLIENT_BINARY=\"$task_reconciler_dir/worker-tests\"\ngo test -C services/platform -race -count=1 -timeout=30m ./apiserver -run '^(TestRuntime(Session|EnrollmentPairing|CandidateAuthority|CorrelationRouting|Sandbox|Precision)|TestSensor|TestReconciliationLanePlan|TestReconciliationMaintenance|TestConnectorAuthorizationPostgresReconciliationIndexes|Test.*SecurityAgent)'\n",
    ...auditSteps.map(step => step.run),
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
    "go-version": "1.25.13",
    cache: true,
    "cache-dependency-path": "services/platform/go.sum",
  });
  expect(verificationSteps.find(step => step.run === sessionIAMCommand)?.["timeout-minutes"]).toBe(10);
  for (const expected of complianceSteps) {
    expect(verificationSteps.find(step => step.name === expected.name)).toEqual(expected);
  }
  for (const expected of auditSteps) {
    const actual = verificationSteps.find(step => step.id === expected.id);
    expect(actual).toMatchObject({ id: expected.id, "timeout-minutes": expected["timeout-minutes"] });
    expect(actual?.env).toEqual(expected.env);
  }
  expect(verificationSteps.find(step => step.run === daemonReplayCommand)?.["timeout-minutes"]).toBe(15);
  for (const step of verificationSteps) {
    expect(step.if).toBeUndefined();
    expect(step["continue-on-error"]).toBeUndefined();
    expect(step.shell).toBeUndefined();
    expect(step["working-directory"]).toBeUndefined();
    if (!step.id?.startsWith("audit_") && step.name !== complianceSteps[1].name) expect(step.env).toBeUndefined();
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
          { uses: setupGoAction, with: { "go-version": "1.25.13", cache: true, "cache-dependency-path": "services/platform/go.sum" } },
          { run: "npm install --global npm@10.9.8" },
          { run: "SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm ci" },
          { run: postgresFixtureCommand },
          { run: "go install github.com/zricethezav/gitleaks/v8@v8.30.1" },
          { run: "npm run implementation:status:check" },
          { run: "npm run verify" },
          ...structuredClone(complianceSteps),
          { run: "node --test scripts/red-team-runtime-proof.test.mjs scripts/production-combined-e2e.test.mjs scripts/audit-export-browser-proof.test.mjs scripts/audit-export-volume-proof.test.mjs scripts/runtime-precision-browser-proof.test.mjs scripts/owned-command.test.mjs scripts/implementation-status-check.test.mjs workers/redteam-node/runner.test.mjs workers/redteam-node/artifact.test.mjs\ngo test -C services/platform -race -count=1 ./apiserver -run '^TestProductionRedTeamHandlerOperationAcceptance$'\n" },
          { run: "npm run production:release:gate" },
          { run: sessionIAMCommand, "timeout-minutes": 10 },
          { run: maintenanceAlertCommand },
          { run: "test -x \"$(pg_config --bindir)/initdb\"\ngo test -C services/platform -race -count=1 ./agentsec-migrate ./migrations ./runtimeevent ./internal/testprocess ./internal/sandboxcutover\ngo test -C services/platform -race -count=1 ./agentsec-api ./agentsec-worker\ngo test -C services/platform -race -count=1 ./runtimemetadata ./runtimelineage ./sensoradapter ./sessionsearch ./runtimeprojection ./runtimecorrelation ./runtimeindex/...\ntask_reconciler_dir=$(mktemp -d \"${RUNNER_TEMP}/zasp-reconciler.XXXXXX\")\ngo test -C services/platform -race -c -o \"$task_reconciler_dir/worker-tests\" ./agentsec-worker\nexport ZASP_RECONCILE_CLIENT_BINARY=\"$task_reconciler_dir/worker-tests\"\ngo test -C services/platform -race -count=1 -timeout=30m ./apiserver -run '^(TestRuntime(Session|EnrollmentPairing|CandidateAuthority|CorrelationRouting|Sandbox|Precision)|TestSensor|TestReconciliationLanePlan|TestReconciliationMaintenance|TestConnectorAuthorizationPostgresReconciliationIndexes|Test.*SecurityAgent)'\n" },
          ...structuredClone(auditSteps),
          { run: sensorAcceptanceCommand },
          { run: daemonReplayCommand, "timeout-minutes": 15 },
          { run: "go test -C proofs/attack-lab-egress -race -count=1 ./...\ngo test -C services/platform -race -count=1 ./attack-lab-runner ./attacklabrunner ./attack-lab-proxy ./attacklabproxy ./attacklab\nnode --test proofs/attack-lab-egress/run.test.mjs\nnode proofs/attack-lab-egress/run.mjs\nZASP_ATTACK_LAB_EGRESS_DOCKER=true node --test proofs/attack-lab-egress/interruption.test.mjs\n" },
        ],
      },
    },
  };
}

describe("runnable UI GitHub Actions gate", () => {
  it.each(complianceSteps.flatMap(step => ["omitted", "skipped", "allowed failure", "timeout", "command", "environment", "order"].map(condition => [step.name!, condition] as const)))("rejects compliance step %s with %s", async (name, condition) => {
    const workflow = await readWorkflow();
    const manifest = await readPackageManifest();
    assertRunnableUiWorkflow(workflow, manifest);
    const steps = workflow.jobs!.verify.steps!;
    const step = steps.find(value => value.name === name)!;
    if (condition === "omitted") steps.splice(steps.indexOf(step), 1);
    if (condition === "skipped") step.if = false;
    if (condition === "allowed failure") step["continue-on-error"] = true;
    if (condition === "timeout") delete step["timeout-minutes"];
    if (condition === "command") step.run = "true";
    if (condition === "environment") step.env = { ZASP_COMBINED_E2E_COMPLIANCE: "false" };
    if (condition === "order") steps.unshift(steps.splice(steps.indexOf(step), 1)[0]);
    expect(() => assertRunnableUiWorkflow(workflow, manifest)).toThrow();
  });
  it("assigns every current audit declaration and parent-owned full-size mode to CI", async () => {
    const workflow = await readWorkflow();
    assertAuditSourceCoverage(await readAuditSources(repositoryRoot), actualAuditLanes(workflow));
  });
  it.each([
    "omitted", "skipped", "allowed-failure", "unbounded step", "changed step timeout",
    "unbounded test", "changed test timeout", "missing audit codec", "missing policy parser", "missing artifact store",
  ])("rejects %s audit export acceptance in the actual parsed workflow", async (condition) => {
    const workflow = await readWorkflow();
    const manifest = await readPackageManifest();
    assertRunnableUiWorkflow(workflow, manifest);
    const steps = workflow.jobs?.verify?.steps;
    const step = steps?.find(value => value.run === auditExportCommand);
    if (!steps || !step?.run) throw new Error("audit export acceptance step is missing");
    if (condition === "omitted") steps.splice(steps.indexOf(step), 1);
    if (condition === "skipped") step.if = false;
    if (condition === "allowed-failure") step["continue-on-error"] = true;
    if (condition === "unbounded step") delete step["timeout-minutes"];
    if (condition === "changed step timeout") step["timeout-minutes"] = 20;
    if (condition === "unbounded test") step.run = step.run.replace(" -timeout=30m", "");
    if (condition === "changed test timeout") step.run = step.run.replace("-timeout=30m", "-timeout=15m");
    if (condition === "missing audit codec") step.run = step.run.replace(" ./audit", "");
    if (condition === "missing policy parser") step.run = step.run.replace(" ./auditexportconfig", "");
    if (condition === "missing artifact store") step.run = step.run.replace(" ./artifactstore/...", "");
    expect(() => assertRunnableUiWorkflow(workflow, manifest)).toThrow();
  });
  it("accepts the source-inventory fixture before testing hostile source mutations", async () => {
    const inventory = assertAuditSourceCoverage(await readAuditSources(repositoryRoot), actualAuditLanes(validWorkflow()));
    expect(inventory.declarations).toHaveLength(229);
    expect(Object.keys(inventory.assignments)).toHaveLength(228);
    expect(inventory.assignments.TestAuditExportRunContextConsumersPostgres).toBe("audit_a3");
    for (const name of [
      "TestAuditHTTPSizeExpectedMixedActualProducersPostgres",
      "TestAuditHTTPSizeExpectedMixedDuplicatePostgres",
      "TestAuditHTTPSizeExpectedMixedScopeLifetimePostgres",
      "TestAuditHTTPSizeExpectedMixedMalformedPostgres",
      "TestAuditHTTPSizeExpectedMixedFamiliesScopePostgres",
      "TestAuditHTTPSizeExpectedMixedRawValidation",
      "TestAuditHTTPSizeProviderBrowserReaderSTSSelection",
      "TestAuditHTTPSizeProviderBrowserRejectsSizeReaderFallback",
      "TestAuditHTTPSizeProviderBrowserControlRejectsMalformedCommands",
      "TestAuditHTTPSizeProviderBrowserSavedVerifierRejectsUnaccountedFiles",
    ]) {
      expect(inventory.assignments[name], name).toBe("audit_helpers");
    }
  });
  it.each(auditSteps.flatMap(step => ["omitted", "skipped", "allowed failure", "unbounded", "changed cap", "ignored error", "short", "skip", "missing race", "cached", "subcase filter"].map(condition => [step.id!, condition])))("rejects %s lane with %s", async (id, condition) => {
      const workflow = await readWorkflow();
      const manifest = await readPackageManifest();
      assertRunnableUiWorkflow(workflow, manifest);
      const steps = workflow.jobs!.verify.steps!;
      const step = steps.find(value => value.id === id)!;
      if (condition === "omitted") steps.splice(steps.indexOf(step), 1);
      if (condition === "skipped") step.if = false;
      if (condition === "allowed failure") step["continue-on-error"] = true;
      if (condition === "unbounded") delete step["timeout-minutes"];
      if (condition === "changed cap") step["timeout-minutes"] = 1;
      if (condition === "ignored error") step.run += "true\n";
      if (condition === "short") step.run += "go test -short ./apiserver\n";
      if (condition === "skip") step.run += "go test -skip . ./apiserver\n";
      if (condition === "missing race") step.run = step.run!.replace(/-race|docker pull/, "echo");
      if (condition === "cached") step.run = step.run!.replace(/-count=1|docker pull/, "echo");
      if (condition === "subcase filter") step.run = step.run!.replace(/'?\n$/, "/N1-off'\n");
      expect(() => assertRunnableUiWorkflow(workflow, manifest)).toThrow();
    });
  it.each([
    ["audit_a3", "|s)", ")"], ["audit_a4", "|LocalStack", ""], ["audit_a4", "|Recovery", ""],
    ...["Expected", "Memory", "Oracle", "Provider", "PrivateFiles", "Fixture", "TestDisposablePostgresCleanup"].map(name => ["audit_helpers", name, "NeverMatch"]),
  ])("rejects lost source family %s/%s independently of copied workflow strings", async (id, before, after) => {
    const sources = await readAuditSources(repositoryRoot);
    const lanes = actualAuditLanes(validWorkflow());
    assertAuditSourceCoverage(sources, lanes);
    const lane = lanes.find(value => value.id === id)!;
    lane.pattern = lane.pattern.replace(before, after);
    expect(() => assertAuditSourceCoverage(sources, lanes)).toThrow(/base assignment/);
  });
  it.each([
    ["unmatched declaration", "apiserver/synthetic_test.go", "", "func TestAuditExportUnassigned(t *testing.T) {}\n"],
    ["new child", "agentsec-worker/synthetic_test.go", "", 'func TestAuditExportUnknownChild(t *testing.T) { t.Skip("parent owned") }\n'],
    ["lost API ownership", "apiserver/audit_export_http_size_postgres_test.go", "api, err = startAuditHTTPSizeAPI(", "api, err = missingAPI("],
    ["lost worker ownership", "apiserver/audit_export_http_size_postgres_test.go", "runAuditHTTPSizeWorker(", "missingWorker("],
    ["lost recovery child", "apiserver/audit_export_recovery_process_postgres_test.go", "launcher.startRecovery(", "launcher.noRecovery("],
    ["lost LocalStack restart owner", "apiserver/audit_export_localstack_postgres_test.go", "exerciseAuditExportLocalStackRestart(t, release.version)", "missingLocalStackRestart(t, release.version)"],
    ["lost LocalStack child", "apiserver/audit_export_localstack_postgres_test.go", "owner.launch(", "owner.noLaunch("],
    ["lost child launch", "apiserver/audit_export_http_size_process_test.go", "-test.run=^TestAuditHTTPSizeAPIProcess$", "-test.run=^TestUnrelated$"],
    ["single control", "apiserver/audit_export_http_size_memory_test.go", '"api-retain", "worker-retain"', '"api-retain"'],
    ["N1 only", "apiserver/audit_export_http_size_memory_test.go", '"N1-off", "N2-off", "N3-on"', '"N1-off"'],
    ["missing race subcase", "apiserver/audit_export_http_size_memory_test.go", 't.Run("functional-race"', 't.Run("unrelated"'],
    ["reduced pair rows", "apiserver/audit_export_http_size_memory_test.go", "rows = 100001", "rows = 1000"],
    ["reduced orderly rows", "apiserver/audit_export_http_orderly_restart_test.go", "Rows: 100001", "Rows: 1000"],
    ["missing controlled zero", "apiserver/audit_export_http_size_postgres_test.go", "range []bool{false, true}", "range []bool{false}"],
    ["one recovery phase", "apiserver/audit_export_recovery_process_postgres_test.go", '"capture", "receipt", "stale", "manifest", "finish"', '"capture"'],
    ["ambient build mode", "apiserver/audit_export_http_orderly_restart_test.go", 'os.Getenv("ZASP_AUDIT_HTTP_SIZE_BUILD")', '""'],
    ["changed source provider pin", "apiserver/audit_export_localstack_owner_test.go", "localstack/localstack:4.7.0@sha256:", "localstack/localstack:latest@sha256:"],
    ["changed source provider flag", "apiserver/audit_export_localstack_postgres_test.go", 'os.Getenv("ZASP_AUDIT_EXPORT_LOCALSTACK_REQUIRED")', 'os.Getenv("WRONG_PROVIDER_FLAG")'],
    ["lost worker mode", "apiserver/audit_export_http_size_postgres_test.go", 'range []string{"audit-export-outbox", "audit-export"}', 'range []string{"audit-export"}'],
  ])("rejects %s in actual Go source", async (_description, file, before, after) => {
    const sources = await readAuditSources(repositoryRoot);
    const lanes = actualAuditLanes(validWorkflow());
    assertAuditSourceCoverage(sources, lanes);
    if (before) {
      expect(sources[file]).toContain(before);
      sources[file] = sources[file].replaceAll(before, after);
    } else sources[file] = after;
    expect(() => assertAuditSourceCoverage(sources, lanes)).toThrow();
  });
  it.each([
    ["single-line", 'func TestAuditExportUnknownChild(t *testing.T) { t.Skip("parent owned") }'],
    ["multiline", 'func TestAuditExportUnknownChild(\n t *testing.T,\n) { t.Skip("parent owned") }'],
  ])("rejects an unmapped %s worker declaration", async (_syntax, declaration) => {
    const sources = await readAuditSources(repositoryRoot);
    const lanes = actualAuditLanes(validWorkflow());
    assertAuditSourceCoverage(sources, lanes);
    sources["agentsec-worker/synthetic_test.go"] = declaration;
    expect(() => assertAuditSourceCoverage(sources, lanes)).toThrow(/unmapped skipping worker entrypoint|unsupported or missing worker audit declaration syntax/);
  });
  it("refuses unsupported worker declaration syntax that silently reduces the inventory", async () => {
    const sources = await readAuditSources(repositoryRoot);
    const lanes = actualAuditLanes(validWorkflow());
    assertAuditSourceCoverage(sources, lanes);
    const signature = "func TestAuditHTTPSizeWorkerRetention(t *testing.T)";
    const file = Object.keys(sources).find(file => file.startsWith("agentsec-worker/") && sources[file].includes(signature));
    expect(file).toBeDefined();
    sources[file!] = sources[file!].replace(signature, "func TestAuditHTTPSizeWorkerRetention(\n t *testing.T,\n)");
    expect(() => assertAuditSourceCoverage(sources, lanes)).toThrow(/unsupported or missing worker audit declaration syntax/);
  });
  it.each(["duplicate base", "standalone API child", "lost parent", "missing race", "numeric raced", "controls raced", "extra repetition", "N1 filter", "one control filter"])("rejects %s in source-derived coverage", async condition => {
      const sources = await readAuditSources(repositoryRoot);
      const lanes = actualAuditLanes(validWorkflow());
      assertAuditSourceCoverage(sources, lanes);
      if (condition === "duplicate base") lanes.push({ ...lanes[0], id: "duplicate" });
      if (condition === "standalone API child") lanes.push({ id: "standalone", pattern: "^TestAuditHTTPSizeAPIProcess$" });
      if (condition === "lost parent") lanes.splice(lanes.findIndex(lane => lane.id === "audit_orderly"), 1);
      if (condition === "missing race") delete lanes.find(lane => lane.id === "audit_race")!.mode;
      if (condition === "numeric raced") lanes.find(lane => lane.id === "audit_normal")!.mode = "race";
      if (condition === "controls raced") lanes.find(lane => lane.id === "audit_controls")!.mode = "race";
      if (condition === "extra repetition") lanes.push({ ...lanes[0], id: "extra", repeat: true });
      if (condition === "N1 filter") lanes.find(lane => lane.id === "audit_normal")!.pattern += "/N1-off$";
      if (condition === "one control filter") lanes.find(lane => lane.id === "audit_controls")!.pattern += "/api-retain$";
      expect(() => assertAuditSourceCoverage(sources, lanes)).toThrow();
    });
  it.each([
    ["missing provider flag", "audit_a3", "env"], ["wrong provider flag", "audit_a3", "false"],
    ["missing race env", "audit_race", "env"], ["raced controls", "audit_controls", "race"],
    ["raced normals", "audit_normal", "race"], ["lost orderly mode", "audit_orderly", "env"],
    ["lost orderly race", "audit_orderly_race", "env"],
  ])("rejects %s on parsed workflow", async (_description, id, mutation) => {
    const workflow = await readWorkflow();
    const manifest = await readPackageManifest();
    assertRunnableUiWorkflow(workflow, manifest);
    const step = workflow.jobs!.verify.steps!.find(step => step.id === id)!;
    if (mutation === "env") delete step.env;
    else step.env = { [id === "audit_a3" ? "ZASP_AUDIT_EXPORT_LOCALSTACK_REQUIRED" : "ZASP_AUDIT_HTTP_SIZE_BUILD"]: mutation };
    expect(() => assertRunnableUiWorkflow(workflow, manifest)).toThrow();
  });
  it.each(["node", "go", "pg_config", "cc", "docker info", "docker pull", "4.7.0@sha256:"])("rejects disabled %s prerequisite", async token => {
    const workflow = await readWorkflow();
    const manifest = await readPackageManifest();
    assertRunnableUiWorkflow(workflow, manifest);
    const step = workflow.jobs!.verify.steps!.find(step => step.id === "audit_prerequisites")!;
    expect(step.run).toContain(token);
    step.run = step.run!.replace(token, "disabled");
    expect(() => assertRunnableUiWorkflow(workflow, manifest)).toThrow();
  });
  it.each(["Node setup", "Go setup", "PG setup", "checkout pin", "Node pin", "Go pin", "npm pin", "lock install", "worker package", "migration package", "testprocess package", "lane before setup"])("rejects lost %s", async condition => {
    const workflow = await readWorkflow();
    const manifest = await readPackageManifest();
    assertRunnableUiWorkflow(workflow, manifest);
    const steps = workflow.jobs!.verify.steps!;
    const setupIndices: Record<string, number> = { "Node setup": 1, "Go setup": 2, "PG setup": 5, "lock install": 4 };
    const remove = setupIndices[condition];
    if (remove !== undefined) steps.splice(remove, 1);
    if (condition === "checkout pin") steps[0].uses = "actions/checkout@main";
    if (condition === "Node pin") steps[1].with!["node-version"] = "22";
    if (condition === "Go pin") steps[2].with!["go-version"] = "1.25";
    if (condition === "npm pin") steps[3].run = "npm install --global npm";
    const packages: Record<string, string> = { "worker package": " ./agentsec-worker", "migration package": " ./agentsec-migrate", "testprocess package": " ./internal/testprocess" };
    const target = packages[condition];
    if (target) {
      const runtime = steps.find(step => step.run?.startsWith('test -x "$(pg_config --bindir)/initdb"'))!;
      expect(runtime.run).toContain(target);
      runtime.run = runtime.run!.replace(target, "");
    }
    if (condition === "lane before setup") steps.unshift(steps.splice(steps.findIndex(step => step.id === "audit_a1"), 1)[0]);
    expect(() => assertRunnableUiWorkflow(workflow, manifest)).toThrow();
  });
  it("runs the precise browser checkpoint tests in CI and the combined acceptance command", async () => {
    const workflow = await readFile(resolve(repositoryRoot, ".github/workflows/runnable-ui.yml"), "utf8");
    const manifest = await readPackageManifest();
    expect(workflow).toContain("scripts/runtime-precision-browser-proof.test.mjs");
    expect(manifest.scripts?.["production:combined-e2e:test"]).toContain("scripts/runtime-precision-browser-proof.test.mjs");
  });
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

  it.each(["./runtimemetadata", "./runtimelineage", "./sensoradapter", "./sessionsearch", "./runtimeprojection", "./runtimecorrelation", "./runtimeindex/..."])("rejects omission of runtime search verification for %s", async (target) => {
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

  it("selects the registered precision PostgreSQL tests in required CI", async () => {
    const workflow = await readWorkflow();
    const command = workflow.jobs?.verify?.steps?.flatMap(step => (step.run ?? "").split("\n")).find(line => line.includes("./apiserver -run '^(TestRuntime("));
    const pattern = command?.match(/-run '([^']+)'/)?.[1];
    expect(command).toContain("-timeout=30m");
    expect(pattern).toBeDefined();
    const selection = new RegExp(pattern!);
    for (const name of ["TestRuntimePrecisionRepositoryRegisteredCompletion", "TestRuntimePrecisionRegisteredCompletionRejectsAlteredAuthorityAtomically", "TestRuntimePrecisionMigrationRoundTrip", "TestRuntimePrecisionUpgradeKeepsExistingAPIAndV1Intake"]) {
      expect(selection.test(name), `${name} must run in CI`).toBe(true);
    }
  });

  it("runs the cutover executor package tests, not only importing its implementation", async () => {
    const workflow = await readWorkflow();
    const command = workflow.jobs?.verify?.steps?.flatMap(step => (step.run ?? "").split("\n")).find(line => line.startsWith("go test ") && line.includes("./agentsec-migrate"));
    expect(command?.split(/\s+/)).toContain("./internal/sandboxcutover");
  });

  it("includes the read-only cutover observation bridge in required release verification", async () => {
    const manifest = await readPackageManifest();
    expect(manifest.scripts?.verify).toContain("npm run production:release:test");
    expect(manifest.scripts?.["production:release:test"]?.split(/\s+/)).toContain("deploy/production/sandbox-query-observation.test.mjs");
  });
});
