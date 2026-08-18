import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const selected = [
  ...Array.from({ length: 14 }, (_, index) => `M6-${String(index + 18).padStart(2, "0")}`),
  "M6-31a", "M6-31b", "M6-31c", "M6-31d", "M6-31e",
  ...Array.from({ length: 6 }, (_, index) => `M7-${String(index + 1).padStart(2, "0")}`),
];

describe("M6 gate and M7 session-foundation completion batch", () => {
  it("retains the runtime, UI, and session implementation boundaries", async () => {
    const [runtime, sessions, policiesView, sessionsView] = await Promise.all([
      readFile(resolve(root, "services/platform/policy/runtime.go"), "utf8"),
      readFile(resolve(root, "services/platform/sessioncontrol/sessioncontrol.go"), "utf8"),
      readFile(resolve(root, "app/features/policies/PoliciesView.tsx"), "utf8"),
      readFile(resolve(root, "app/features/sessions/SessionsComplianceView.tsx"), "utf8"),
    ]);
    for (const symbol of ["Rollout", "RuntimeProxy", "ParseMCPAction", "NormalizeActionContext", "EvaluateBundleFallback", "MeasureDecisionP95", "EvaluateM6Gate"]) expect(runtime).toContain(` ${symbol}`);
    for (const symbol of ["Project", "BuildSessionFilter"]) expect(sessions).toContain(` ${symbol}`);
    for (const label of ["Monitor", "Enforce", "Disabled", "Simulate policy"]) expect(policiesView).toContain(label);
    for (const label of ["Agent", "Principal", "Credential", "Decision", "Exact"]) expect(sessionsView).toContain(label);
  });

  it("keeps all session operations in the generated product contract", async () => {
    const [openapi, generated] = await Promise.all([
      readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(root, "apps/web/api/generated.ts"), "utf8"),
    ]);
    for (const operation of ["listSessions", "getSession", "listSessionEvents"]) {
      expect(openapi).toContain(`operationId: ${operation}`);
      expect(generated).toContain(operation);
    }
  });

  it("records exactly 25 reviewed tasks as Complete", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(selected).toHaveLength(25);
    for (const value of ["| Pending | 0 |", "| In progress | 47 |", "| Complete | 655 |", "| Blocked | 26 |", "`0/47/655/26`", "| M6 | 36 | 0 | 0 | 36 | 0 |", "| M7 | 62 | 0 | 0 | 62 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (const task of selected) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(1);
    }
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M6-01 through M6-31 are Complete");
    expect(prose).toContain("M7-01 through M7-40 are Complete");
    expect(prose).toContain("Provider-backed staging and live outage injection are not claimed");
  });
});
