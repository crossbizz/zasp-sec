import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { JSON_SCHEMA, load } from "js-yaml";
import { describe, expect, it } from "vitest";

type WorkflowStep = {
  run?: string;
  uses?: string;
  with?: Record<string, unknown>;
};

type Workflow = {
  on?: Record<string, unknown>;
  jobs?: Record<string, { steps?: WorkflowStep[] }>;
};

type PackageManifest = {
  scripts?: Record<string, string>;
};

const repositoryRoot = process.cwd();

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

describe("runnable UI GitHub Actions gate", () => {
  it("runs the locked runnable-UI verification on every push and pull request", async () => {
    const [workflow, packageManifest] = await Promise.all([
      readWorkflow(),
      readPackageManifest(),
    ]);
    const verificationCommands = packageManifest.scripts?.verify
      .split("&&")
      .map((command) => command.trim());

    expect(Object.keys(workflow.on ?? {})).toEqual(
      expect.arrayContaining(["push", "pull_request"]),
    );
    expect(verificationCommands).toEqual([
      "npm test",
      "npm run typecheck",
      "npm run lint",
      "npm run build",
    ]);

    const workflowSteps = Object.values(workflow.jobs ?? {}).flatMap(
      (job) => job.steps ?? [],
    );
    const setupNode = workflowSteps.find(
      (step) => step.uses?.startsWith("actions/setup-node@"),
    );

    expect(workflowSteps.some((step) => step.uses?.startsWith("actions/checkout@"))).toBe(true);
    expect(setupNode?.with).toMatchObject({
      "node-version": "22.23.1",
      cache: "npm",
    });
    expect(workflowSteps.map((step) => step.run)).toEqual(
      expect.arrayContaining([
        "npm install --global npm@10.9.8",
        "SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm ci",
        "npm run verify",
      ]),
    );
  });
});
