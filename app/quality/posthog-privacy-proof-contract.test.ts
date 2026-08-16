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

describe("PostHog privacy proof repository contract", () => {
  it("binds M0-20 and R-13 to a local allowlist-only proof", async () => {
    const [source, prd, risk, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-20-posthog-privacy-proof-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-20-posthog-privacy-proof-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M0-20 - PostHog privacy proof\*\*[\s\S]*?\*\*M0-21 -/)?.[0];
    const riskRows = markdownRows(risk).filter(([id]) => id === "R-13");

    expect(sourceSection).toContain("Depends on: `M0-19`");
    expect(sourceSection).toContain("fake PostHog endpoint");
    expect(sourceSection).toContain("prompt, secret, IP and raw evidence");
    expect(prd).toContain("PostHog for allowlisted usage analytics and non-critical feature flags");
    expect(riskRows).toHaveLength(1);
    expect(riskRows[0]?.[5]).toContain("PASS — M0-20 —");
    expect(design).toContain("random loopback port");
    expect(design).toContain("no PostHog credential");
    expect(design).toContain("fail closed on every unknown property");
    expect(plan).toContain("Every behavior change follows a witnessed tests-only RED");
  });

  it("completes only M0-20 and advances only R-13", async () => {
    const [tracker, readme, risk] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
    ]);
    const active = section(tracker, "In progress");
    const blocked = section(tracker, "Blocked");

    const complete = section(tracker, "Complete");
    expect(readme).toContain("M0-20 is Complete");
    expect(readme).toContain("fake PostHog endpoint");
    expect(tracker).toContain("| Pending | 688 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 36 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`688/1/36/3`");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    expect(active).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M0-20")).toHaveLength(1);
    expect(blocked.filter(([task]) => ["M0-09", "M0-18", "M0-19"].includes(task))).toHaveLength(3);
    expect(risk).toContain("PASS — M0-20 —");
    expect(risk).toContain("task-5-report.md; proof head e99edb0");
  });

  it("exposes exact hermetic and local proof commands with fixed output", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const manifest = JSON.parse(packageText) as { scripts?: Record<string, string> };
    const proofSection = readme.match(/## PostHog privacy proof[\s\S]*?## EKS Fargate egress proof/)?.[0] ?? "";

    expect(manifest.scripts?.["proof:posthog:test"]).toBe("node --test proofs/posthog-privacy/*.test.mjs");
    expect(manifest.scripts?.["proof:posthog:run"]).toBe("node proofs/posthog-privacy/run.mjs");
    expect(proofSection).toContain("npm run proof:posthog:test");
    expect(proofSection).toContain("npm run proof:posthog:run");
    expect(proofSection).toContain(
      "PostHog privacy proof passed: event=true prompt=false secret=false ip=false evidence=false cleanup=true.",
    );
    expect(proofSection).toContain("does not claim hosted PostHog availability");
  });
});
