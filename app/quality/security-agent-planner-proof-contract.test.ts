import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");

function markdownRows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function section(markdown: string, heading: "In progress" | "Complete" | "Blocked") {
  const end = heading === "In progress" ? "Complete" : heading === "Complete" ? "Blocked" : "Review findings";
  return markdownRows(markdown.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "").slice(2);
}

describe("Security Agent planner boundary repository contract", () => {
  it("binds M0-21a and R-14 to a fixed two-action catalog proof", async () => {
    const [source, prd, risk, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-21a-security-agent-planner-proof-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-21a-security-agent-planner-proof-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M0-21a - Security Agent planner boundary proof\*\*[\s\S]*?\*\*M0-22 -/)?.[0];
    const riskRows = markdownRows(risk).filter(([id]) => id === "R-14");

    expect(sourceSection).toContain("Depends on: `M0-21`");
    expect(sourceSection).toContain("untrusted injection text");
    expect(sourceSection).toContain("fixed two-action catalog");
    expect(sourceSection).toContain("arbitrary URL/shell/action output is rejected");
    expect(prd).toContain("The planner cannot invent actions or action parameters outside these schemas");
    expect(prd).toContain("Evidence is treated as untrusted data, not instructions");
    expect(riskRows).toHaveLength(1);
    expect(riskRows[0]?.[5]).toBe(
      "PASS — M0-21/M0-21a — .superpowers/sdd/2026-08-15-m0-21-openrouter-privacy-proof-implementation-plan/task-5-report.md; .superpowers/sdd/2026-08-15-m0-21a-security-agent-planner-proof-implementation-plan/task-5-report.md; proof head 6f4ed10198495b8f0b6019cb6d82221d7cac91c1",
    );
    expect(design).toContain("numeric loopback");
    expect(design).toContain("two-action catalog");
    expect(design).toContain("no general shell");
    expect(plan).toContain("Every behavior change follows a witnessed tests-only RED");
  });

  it("retains M0-21a completion and the combined R-14 evidence", async () => {
    const [tracker, readme, risk] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
    ]);
    const active = section(tracker, "In progress");
    const blocked = section(tracker, "Blocked");

    expect(readme).toContain("M0-21a is Complete");
    expect(tracker).toContain("| Pending | 656 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 69 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`656/0/69/3`");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(section(tracker, "Complete").filter(([task]) => task === "M0-21a")).toHaveLength(1);
    expect(section(tracker, "Complete").filter(([task]) => task === "M0-22")).toHaveLength(1);
    expect(blocked.filter(([task]) => ["M0-09", "M0-18", "M0-19"].includes(task))).toHaveLength(3);
    expect(risk).toContain("PASS — M0-21/M0-21a");
    expect(tracker).toContain("M0-23 is\n  Complete");
  });

  it("exposes hermetic root test and run commands only after the proof exists", async () => {
    const [packageJson, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const scripts = JSON.parse(packageJson).scripts;
    expect(scripts["proof:planner:test"]).toBe("node --test proofs/security-agent-planner/*.test.mjs");
    expect(scripts["proof:planner:run"]).toBe("node proofs/security-agent-planner/run.mjs");
    expect(readme).toContain("npm run proof:planner:test");
    expect(readme).toContain("npm run proof:planner:run");
  });
});
