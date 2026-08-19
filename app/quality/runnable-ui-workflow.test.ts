import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { JSON_SCHEMA, load } from "js-yaml";
import { describe, expect, it } from "vitest";

type WorkflowStep = {
  if?: unknown;
  "continue-on-error"?: unknown;
  run?: string;
  uses?: string;
  with?: Record<string, unknown>;
};

type WorkflowJob = {
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
    "npm run db:tenant-rls:test",
    "npm test",
    "npm run typecheck",
    "npm run lint",
    "npm run production:imports:test",
    "npm run production:imports:source",
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
  expect(verificationJob["continue-on-error"]).toBeUndefined();

  const verificationSteps = verificationJob.steps ?? [];
  expect(verificationSteps).toHaveLength(9);
  expect(verificationSteps.map((step) => step.uses ?? step.run)).toEqual([
    checkoutAction,
    setupNodeAction,
    setupGoAction,
    "npm install --global npm@10.9.8",
    "SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm ci",
    "go install github.com/zricethezav/gitleaks/v8@v8.30.1",
    "npm run implementation:status:check",
    "npm run verify",
    "npm run production:release:gate",
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
        steps: [
          { uses: checkoutAction, with: { "fetch-depth": 0 } },
          {
            uses: setupNodeAction,
            with: { "node-version": "22.23.1", cache: "npm" },
          },
          { uses: setupGoAction, with: { "go-version": "1.25.6", cache: true, "cache-dependency-path": "services/platform/go.sum" } },
          { run: "npm install --global npm@10.9.8" },
          { run: "SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm ci" },
          { run: "go install github.com/zricethezav/gitleaks/v8@v8.30.1" },
          { run: "npm run implementation:status:check" },
          { run: "npm run verify" },
          { run: "npm run production:release:gate" },
        ],
      },
    },
  };
}

describe("runnable UI GitHub Actions gate", () => {
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

  it("runs the locked runnable-UI verification on every push and pull request", async () => {
    const [workflow, packageManifest] = await Promise.all([
      readWorkflow(),
      readPackageManifest(),
    ]);

    assertRunnableUiWorkflow(workflow, packageManifest);
  });
});
