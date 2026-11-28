import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { load } from "js-yaml";
import { describe, expect, it } from "vitest";
import { assertAcceptanceStepConditions, requiredStepOutcomes } from "../../scripts/acceptance-step-conditions.mjs";

type Step = { name: string; id?: string; if?: string; "continue-on-error"?: boolean };
type Job = { steps: Step[]; if?: string; needs?: string | string[]; uses?: string; "continue-on-error"?: boolean };
type Outcome = "success" | "failure" | "skipped";
function jobs(name: string) {
  return (load(readFileSync(resolve(process.cwd(), ".github/workflows", name + ".yml"), "utf8")) as { jobs: Record<string, Job> }).jobs;
}
const acceptance = jobs("runnable-ui-acceptance");
const cd = jobs("production-cd");
const browser = "Verify current compliance browser acceptance";
const audit = "Verify audit PostgreSQL authority A-M";
const sensor = "Verify sensor lineage and authenticated replay";
const regression = "Verify Red Team runtime and ledger regressions";
const evidence = "Verify production release sources";

// Evaluate the two step conditions allowed by the source contract. GitHub keeps
// the step outcome on a tolerated failure and the job failure on a required one.
function run(job: string, failed?: string, cancelAfter?: string) {
  const steps = acceptance[job].steps;
  assertAcceptanceStepConditions(steps, job);
  const outcomes = new Map<string, Outcome>();
  let failedJob = false;
  let cancelled = false;
  for (const step of steps) {
    const ready = !cancelled && (step.if
      ? requiredStepOutcomes(step.if).every((id: string) => outcomes.get(id) === "success")
      : !failedJob);
    const outcome = ready ? (step.name === failed ? "failure" : "success") : "skipped";
    outcomes.set(step.name, outcome);
    if (step.id) outcomes.set(step.id, outcome);
    if (outcome === "failure" && !step["continue-on-error"]) failedJob = true;
    if (step.name === cancelAfter) cancelled = true;
  }
  return { outcomes, failedJob };
}

describe("production acceptance failure reporting", () => {
  it("runs every required check on a healthy checkout and keeps the release evidence advisory", () => {
    for (const job of ["verify", "platform-go"]) {
      expect(acceptance[job]["continue-on-error"]).toBeUndefined();
      const result = run(job);
      expect(new Set(result.outcomes.values())).toEqual(new Set(["success"]));
      expect(acceptance[job].steps.filter(step => step["continue-on-error"]).map(step => step.name))
        .toEqual(job === "verify" ? [evidence] : []);
    }
    expect(run("verify", evidence).failedJob).toBe(false);
  });

  it.each([browser, audit, "Verify approval maintenance signed notification delivery"])(
    "continues independent checks after %s and keeps the job failed", failed => {
      const { outcomes, failedJob } = run("verify", failed);
      expect(failedJob).toBe(true);
      expect(outcomes.get(failed)).toBe("failure");
      for (const independent of [sensor, "Verify actual daemon lost-success replay", "Verify bounded Attack Lab network enforcement"])
        expect(outcomes.get(independent)).toBe("success");
      if (failed !== audit) expect(outcomes.get(audit)).toBe("success");
      if (failed === browser) {
        expect(outcomes.get(regression)).toBe("success");
        expect(outcomes.get(evidence)).toBe("skipped");
      }
    },
  );

  it.each(["Verify runnable UI", "Provision isolated compliance browser prerequisites"])(
    "requires %s for both consumers of the compiled UI and pinned browser image", failed => {
      const { outcomes, failedJob } = run("verify", failed);
      expect(failedJob).toBe(true);
      expect(outcomes.get(browser)).toBe("skipped");
      expect(outcomes.get(regression)).toBe("skipped");
      expect(outcomes.get(audit)).toBe("success");
      expect(outcomes.get(sensor)).toBe("success");
    },
  );

  it("honors tool prerequisites, including LocalStack only for its consumers", () => {
    const pg = run("verify", "Install PostgreSQL 18 reference fixture tools");
    for (const name of [browser, audit, sensor, "audit_prerequisites"])
      expect(pg.outcomes.get(name)).toBe("skipped");
    expect(pg.outcomes.get("Verify session search IAM policies")).toBe("success");
    const image = run("verify", "Require audit fixture toolchains and pinned LocalStack image");
    expect(image.failedJob).toBe(true);
    for (const id of ["audit_a3", "audit_a4"]) expect(image.outcomes.get(id)).toBe("skipped");
    for (const name of [audit, "audit_helpers", sensor]) expect(image.outcomes.get(name)).toBe("success");
    const tools = run("verify", "Provision pinned owned authorization runtime tools");
    expect(tools.outcomes.get(browser)).toBe("skipped");
    expect(tools.outcomes.get(regression)).toBe("success");
  });

  it("skips dependent checks after shared setup failure or cancellation", () => {
    const setup = run("verify", "Install locked dependencies");
    expect(setup.failedJob).toBe(true);
    for (const name of [browser, audit, sensor]) expect(setup.outcomes.get(name)).toBe("skipped");
    const canceled = run("verify", undefined, browser);
    expect(canceled.outcomes.get(browser)).toBe("success");
    for (const name of [audit, sensor]) expect(canceled.outcomes.get(name)).toBe("skipped");
    const feature = "Verify the apiserver feature tests";
    expect(run("platform-go", "Verify the platform package selection").outcomes.get(feature)).toBe("skipped");
    expect(run("platform-go", "Verify platform packages no other step runs").outcomes.get(feature)).toBe("success");
  });

  it("requires successful main acceptance before the protected production promotion and upgrade", () => {
    expect(cd.acceptance.uses).toBe("./.github/workflows/runnable-ui-acceptance.yml");
    expect(cd.promotion.needs).toEqual(expect.arrayContaining(["tested-main", "acceptance"]));
    expect(cd.upgrade.needs).toBe("promotion");
    for (const job of [cd.acceptance, cd.promotion, cd.upgrade]) {
      expect(job["continue-on-error"]).toBeUndefined();
      // With no status-function override, GitHub applies its implicit success() to needs.
      expect(job.if).not.toMatch(/\b(always|cancelled|failure|success)\s*\(/i);
    }
  });
});
