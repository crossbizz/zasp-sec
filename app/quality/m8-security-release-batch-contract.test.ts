import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M8-40a through M8-51d security release batch", () => {
  it("adds tenant, leakage, supply-chain, compliance, and golden-stage gates", () => {
    const source = read("cmd/agentsecctl/security_release.go");
    for (const symbol of ["EvaluateTenantIsolation", "EvaluateConnectorSSRF", "EvaluateSecretLeakage", "EvaluatePolicyBypass", "EvaluateAttackLabSafety", "GenerateSBOM", "EvaluateImageSignatures", "EvaluateVulnerabilities", "ValidateSupplyChainInventory", "EvaluateHIPAAProfile", "ValidateSOC2Checklist", "EvaluateGoldenStage"]) expect(source).toContain(`func ${symbol}`);
  });

  it("binds every required leakage sink and managed dependency", () => {
    const source = read("cmd/agentsecctl/security_release.go");
    for (const value of ["logs", "posthog", "ai", "otlp", "support_bundle", "evidence_store"]) expect(source).toContain(`"${value}"`);
    for (const value of ["nango", "neo4j", "stytch", "neon", "posthog", "openrouter", "otlp"]) expect(source).toContain(`"${value}"`);
  });

  it("classifies all 25 tasks without claiming absent release artifacts or live golden stages", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] || "";
    const blocked = tracker.match(/## Blocked[\s\S]*/)?.[0] || "";
    const completed = ["M8-40a", "M8-40b", "M8-40c", "M8-40d", "M8-40", "M8-41", "M8-42a", "M8-42b", "M8-42c", "M8-42d", "M8-42e", "M8-42f", "M8-42", "M8-43", "M8-44", "M8-47", "M8-48", "M8-49", "M8-50"];
    const externallyBlocked = ["M8-45", "M8-46", "M8-51a", "M8-51b", "M8-51c", "M8-51d"];
    for (const id of [...completed, ...externallyBlocked]) expect(active.match(new RegExp(`^\\| ${id} \\|`, "gm")) ?? []).toHaveLength(0);
    for (const id of completed) expect(complete.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const id of externallyBlocked) expect(blocked.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 22 |", "| Complete | 667 |", "| Blocked | 39 |", "`0/22/667/39`", "| M8 | 141 | 0 | 16 | 89 | 36 |"]) expect(tracker).toContain(value);
  });
});
