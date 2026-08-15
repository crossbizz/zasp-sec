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

describe("OTLP export proof repository contract", () => {
  it("binds M0-22 and R-12 to bounded export and nonblocking failure", async () => {
    const [source, prd, risk, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-22-otlp-export-proof-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-22-otlp-export-proof-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M0-22 - OTLP export proof\*\*[\s\S]*?\*\*M0-23 -/)?.[0];
    const riskRows = markdownRows(risk).filter(([id]) => id === "R-12");

    expect(sourceSection).toContain("Depends on: `M0-21a`");
    expect(sourceSection).toContain("bounded operational telemetry");
    expect(sourceSection).toContain("Exporter failure does not block");
    expect(prd).toContain("OpenTelemetry to an in-cluster Collector, optionally exporting to Grafana Cloud or New Relic");
    expect(riskRows).toHaveLength(1);
    expect(riskRows[0]?.[5]).toBe("Not run — M0-13/M0-22");
    expect(design).toContain("private internal network");
    expect(design).toContain("bounded sending queue");
    expect(design).toContain("nonblocking application operation");
    expect(plan).toContain("Every behavior change follows a witnessed tests-only RED");
  });

  it("starts only M0-22 without advancing R-12", async () => {
    const [tracker, readme, risk, packageSource] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageSource) as { scripts?: Record<string, string> };
    const active = section(tracker, "In progress");
    const blocked = section(tracker, "Blocked");

    expect(readme).toContain("M0-22 is In progress");
    expect(readme).toContain("npm run proof:otlp-export:test");
    expect(readme).toContain("npm run proof:otlp-export:run");
    expect(readme).toContain("OTLP export proof passed: delivered=true bounded=true exporter_failed=true application_unblocked=true cleanup=true.");
    expect(packageJson.scripts?.["proof:otlp-export:test"]).toBe("node --test proofs/otlp-export/*.test.mjs");
    expect(packageJson.scripts?.["proof:otlp-export:run"]).toBe("node proofs/otlp-export/run.mjs");
    expect(tracker).toContain("| Pending | 701 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 22 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`701/1/22/3`");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 1 \| 22 \| 3 \|/);
    expect(active.filter(([task]) => task === "M0-22")).toHaveLength(1);
    expect(blocked.filter(([task]) => ["M0-09", "M0-18", "M0-19"].includes(task))).toHaveLength(3);
    expect(risk).toContain("Not run — M0-13/M0-22");
  });
});
