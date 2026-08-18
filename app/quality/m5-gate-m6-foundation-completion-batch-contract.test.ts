import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const selected = [
  "M5-31", "M5-32", "M5-33a", "M5-33b", "M5-33c", "M5-33", "M5-34", "M5-35",
  ...Array.from({ length: 17 }, (_, index) => `M6-${String(index + 1).padStart(2, "0")}`),
];

describe("M5 gate and M6 policy-foundation completion batch", () => {
  it("keeps all policy operations in the generated product contract", async () => {
    const [openapi, generated] = await Promise.all([
      readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(root, "apps/web/api/generated.ts"), "utf8"),
    ]);
    for (const operation of ["listPolicies", "createPolicy", "getPolicy", "updatePolicy", "deletePolicy", "simulatePolicy", "rolloutPolicy", "disablePolicy", "listPolicyDecisions"]) {
      expect(openapi).toContain(`operationId: ${operation}`);
      expect(generated).toContain(operation);
    }
  });

  it("uses real OPA, artifact, restart, token, and history adapter boundaries", async () => {
    const [module, integration] = await Promise.all([
      readFile(resolve(root, "services/platform/policy/policy.go"), "utf8"),
      readFile(resolve(root, "services/platform/policy/integration.go"), "utf8"),
    ]);
    expect(module).toContain("github.com/open-policy-agent/opa/v1/rego");
    for (const symbol of ["WriteBundleArtifact", "RestoreBundleCache", "NewBundleHTTPHandler", "SimulateOpenSearch"]) expect(integration).toContain(` ${symbol}`);
  });

  it("records exactly 25 reviewed tasks as Complete", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(selected).toHaveLength(25);
    for (const value of ["| Pending | 0 |", "| In progress | 168 |", "| Complete | 557 |", "| Blocked | 3 |", "`0/168/557/3`", "| M5 | 42 | 0 | 0 | 42 | 0 |", "| M6 | 36 | 0 | 0 | 36 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (const task of selected) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(1);
    }
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M5-01 through M5-35 are Complete");
    expect(prose).toContain("M6-01 through M6-31 are Complete");
  });
});
