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

describe("OpenRouter privacy proof repository contract", () => {
  it("binds M0-21 to redacted structured local-only explanation", async () => {
    const [source, prd, risk, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-21-openrouter-privacy-proof-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-21-openrouter-privacy-proof-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M0-21 - OpenRouter privacy proof\*\*[\s\S]*?\*\*M0-21a -/)?.[0];
    const riskRows = markdownRows(risk).filter(([id]) => id === "R-14");

    expect(sourceSection).toContain("Depends on: `M0-20`");
    expect(sourceSection).toContain("fake OpenRouter-compatible endpoint");
    expect(sourceSection).toContain("secret/PII fields are absent");
    expect(sourceSection).toContain("structured result validates");
    expect(prd).toContain("OpenRouter for bounded Security Agent planning plus optional AI explanations");
    expect(riskRows).toHaveLength(1);
    expect(riskRows[0]?.[5]).toContain("PASS — M0-21/M0-21a —");
    expect(design).toContain("numeric loopback");
    expect(design).toContain("no OpenRouter credential");
    expect(design).toContain("closed structured result schema");
    expect(plan).toContain("Every behavior change follows a witnessed tests-only RED");
  });

  it("retains M0-21 while combined M0-21a evidence advances R-14", async () => {
    const [tracker, readme, risk] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
    ]);
    const active = section(tracker, "In progress");
    const blocked = section(tracker, "Blocked");

    const complete = section(tracker, "Complete");
    expect(readme).toContain("M0-21 is Complete");
    expect(tracker).toContain("| Pending | 679 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 46 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`679/0/46/3`");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M0-21")).toHaveLength(1);
    expect(blocked.filter(([task]) => ["M0-09", "M0-18", "M0-19"].includes(task))).toHaveLength(3);
    expect(risk).toContain("PASS — M0-21/M0-21a —");
  });

  it("exposes exact hermetic and local commands with fixed output", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const manifest = JSON.parse(packageText) as { scripts?: Record<string, string> };
    const proofSection = readme.match(/## OpenRouter privacy proof[\s\S]*?## EKS Fargate egress proof/)?.[0] ?? "";

    expect(manifest.scripts?.["proof:openrouter:test"]).toBe("node --test proofs/openrouter-privacy/*.test.mjs");
    expect(manifest.scripts?.["proof:openrouter:run"]).toBe("node proofs/openrouter-privacy/run.mjs");
    expect(proofSection).toContain("npm run proof:openrouter:test");
    expect(proofSection).toContain("npm run proof:openrouter:run");
    expect(proofSection).toContain(
      "OpenRouter privacy proof passed: explanation=true secret=false pii=false structured=true cleanup=true.",
    );
    expect(proofSection).toContain("R-14 is PASS");
  });
});
