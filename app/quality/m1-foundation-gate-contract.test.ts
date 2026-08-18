import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

function rows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .slice(2)
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

describe("M1-36 foundation gate", () => {
  it("binds the source dependency and PASS-only rule", async () => {
    const source = await readFile(
      resolve(root, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const section = source.match(/\*\*M1-36 - M1 gate\*\*[\s\S]*?### M1A/)?.[0] ?? "";
    expect(section).toContain("Depends on: `M1-36e, M1-44, M1-45`");
    expect(section).toContain("five independent checks");
    expect(section).toContain("PASS only when all check artifacts passed");
  });

  it("records exactly five passed checks and both passed tenant prerequisites", async () => {
    const gate = await readFile(resolve(root, "docs/decisions/m1-foundation-gate.md"), "utf8");
    const checkSection = gate.match(/## Independent checks[\s\S]*?## Tenant prerequisites/)?.[0] ?? "";
    const prerequisiteSection = gate.match(/## Tenant prerequisites[\s\S]*?## Decision/)?.[0] ?? "";
    const checks = rows(checkSection);
    const prerequisites = rows(prerequisiteSection);
    const prose = gate.replace(/\s+/g, " ");

    expect(checks.map(([task]) => task)).toEqual(["M1-36a", "M1-36b", "M1-36c", "M1-36d", "M1-36e"]);
    expect(checks.every((row) => row.length === 4 && row[1] === "PASS" && row[2] !== "" && row[3] !== "")).toBe(true);
    expect(prerequisites.map(([task]) => task)).toEqual(["M1-44", "M1-45"]);
    expect(prerequisites.every((row) => row.length === 4 && row[1] === "PASS")).toBe(true);
    expect(gate).toContain("# M1 foundation gate: PASS");
    expect(prose).toContain("M1A and M2 may begin");
    expect(prose).toContain("does not waive M0-09, M0-18, or M0-19");
  });
});
