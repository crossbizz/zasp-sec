// Test helpers for the reusable acceptance workflow. Only these newly assigned
// IDs are scheduling metadata. Existing audit IDs are part of the release contract.
import assert from "node:assert/strict";

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
