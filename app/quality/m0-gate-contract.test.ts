import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const expectedRiskIds = Array.from({ length: 14 }, (_, index) => `R-${String(index + 1).padStart(2, "0")}`);
const requiredUpdatedEvidence = new Map([
  [
    "R-01",
    "PASS — M0-02/M0-03 — .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-02-report.md; proof head da1323050a9875bde17190e6d84afa7fa4651a13; .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-03-report.md; proof head 5ddf9b23b9b781499281610da2ac153663ff42b8",
  ],
  [
    "R-02",
    "PASS — M0-04/M0-05 — .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-04-report.md; proof head e8a8f5fc56ace9570a23476771c8c48377cd4db3; .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-05-report.md; proof head 37d638f22d8e9e5b8075cc9aab755b6589084b07",
  ],
  [
    "R-04",
    "PASS — M0-06/M0-08 — .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-06-report.md; proof head ba02323b83618e096c67cb2380f5a4cbaf9c9086; .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-08-report.md; proof head 959f033c9f6b5d26e0c57b0e01dbb539358c7a09",
  ],
  [
    "R-05",
    "PASS — M0-10 — .superpowers/sdd/2026-08-14-m0-10-cartography-proof-implementation-plan/task-6-report.md; proof head 23b759b793e02aba91c24b846651ed64018a9a03",
  ],
]);

function markdownRows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function taskRows(tracker: string, heading: "In progress" | "Complete") {
  const end = heading === "In progress" ? "Complete" : "Blocked";
  const body = tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return markdownRows(body).slice(2);
}

function riskStatusRows(riskRegister: string) {
  return new Map(
    markdownRows(riskRegister)
      .filter(([id]) => /^R-\d{2}$/.test(id ?? ""))
      .map((row) => [row[0], row[5]]),
  );
}

function assertGate(gate: string) {
  const rows = markdownRows(gate).filter(([id]) => /^R-\d{2}$/.test(id ?? ""));
  expect(markdownRows(gate).find(([first]) => first === "Risk")).toEqual([
    "Risk",
    "Outcome",
    "Proofs",
    "Evidence",
    "Architecture decision",
  ]);
  expect(rows.map(([id]) => id)).toEqual(expectedRiskIds);
  expect(new Set(rows.map(([id]) => id)).size).toBe(14);
  expect(rows.filter(([, outcome]) => outcome === "PASS")).toHaveLength(12);
  expect(rows.filter(([, outcome]) => outcome === "BLOCKED").map(([id]) => id)).toEqual(["R-03", "R-11"]);
  expect(rows.every(([, outcome]) => outcome === "PASS" || outcome === "BLOCKED")).toBe(true);
  for (const [id, outcome, proofs, evidence, decision] of rows) {
    expect(proofs).toMatch(/^M0-/);
    expect(decision.length).toBeGreaterThan(40);
    if (outcome === "PASS") {
      expect(evidence).toContain(".superpowers/sdd/");
      expect(evidence).toMatch(/proof head [0-9a-f]{7,40}/);
    }
    if (id === "R-03") {
      expect(proofs).toBe("M0-06/M0-07/M0-09");
      expect(evidence).toContain("0/9 isolated real-AWS inputs");
      expect(evidence).toContain("LocalStack cannot substitute");
      expect(decision).toContain("block real-AWS IAM parity and dependent M1A/M3 claims");
      expect(decision).toContain("Resume only when M0-09 passes");
    }
    if (id === "R-11") {
      expect(proofs).toBe("M0-18/M0-19");
      expect(evidence).toContain("0/11 and 0/19 real-EKS inputs");
      expect(evidence).toContain("LocalStack cannot substitute");
      expect(decision).toContain("block EKS Fargate strong-isolation and egress claims");
      expect(decision).toContain("Resume only when M0-18 and M0-19 pass");
    }
  }
  expect(gate).toContain("12 PASS / 2 BLOCKED / 0 FAIL / 0 unclassified");
  expect(gate).toContain("PROCEED WITH BLOCKED PATHS");
}

describe("M0 technical proof gate repository contract", () => {
  it("binds the source gate to the evidence-only blocked-path design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-23-gate-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-23-gate-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M0-23 - M0 gate\*\*[\s\S]*?### M1 -/)?.[0];

    expect(sourceSection).toContain("Depends on: `M0-22`");
    expect(sourceSection).toContain("Record pass/fail and resulting architecture decision for every proof");
    expect(sourceSection).toContain("No unresolved proof is marked passed and blockers are explicit");
    expect(design).toContain("PROCEED WITH BLOCKED PATHS");
    expect(design).toContain("R-03 continues to block real-AWS IAM parity");
    expect(design).toContain("R-11 continues to block EKS Fargate strong-");
    expect(plan).toContain("Every behavior or status change follows a witnessed tests-only RED");
  });

  it("retains the completed M0 gate after M1-01d completes", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const summary = markdownRows(
      tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "",
    ).slice(2);
    const m0 = markdownRows(
      tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "",
    ).find(([milestone]) => milestone === "M0");

    expect(readme).toContain("M0-23 is Complete");
    expect(readme).toContain("PROCEED WITH BLOCKED PATHS");
    expect(tracker).toContain("| Pending | 692 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 32 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`692/1/32/3`");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(m0?.slice(2).reduce((sum, count) => sum + Number(count), 0)).toBe(Number(m0?.[1]));
    expect(active).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M0-23")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-01d")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-01e")).toHaveLength(1);
    expect(tracker).toContain("| M1 | 68 | 59 | 1 | 8 | 0 |");
    expect(tracker).toContain("M0-09");
    expect(tracker).toContain("M0-18");
    expect(tracker).toContain("M0-19");
  });

  it("records exactly fourteen evidence-backed decisions without passing blockers", async () => {
    const [gate, riskRegister] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/decisions/m0-technical-proof-gate.md"), "utf8").catch(() => ""),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
    ]);
    const statuses = riskStatusRows(riskRegister);

    assertGate(gate);
    for (const [id, evidence] of requiredUpdatedEvidence) {
      expect(statuses.get(id)).toBe(evidence);
    }
    expect(statuses.get("R-03")).toBe("Not run — M0-06/M0-07/M0-09");
    expect(statuses.get("R-11")).toBe("Not run — M0-18/M0-19");
  });

  it("rejects decision, evidence, blocker, ordering, and summary drift", async () => {
    const gate = await readFile(resolve(repositoryRoot, "docs/decisions/m0-technical-proof-gate.md"), "utf8").catch(
      () => "",
    );
    const row = gate.match(/^\| R-01 \|.*\|$/m)?.[0] ?? "";
    const r01 = gate.match(/^\| R-01 \|.*\|$/m)?.[0] ?? "";
    const r02 = gate.match(/^\| R-02 \|.*\|$/m)?.[0] ?? "";

    expect(() => assertGate(gate)).not.toThrow();
    expect(() => assertGate(gate.replace(row, `${row}\n${row}`))).toThrow();
    expect(() => assertGate(gate.replace(/^\| R-14 \|.*\|\n/m, ""))).toThrow();
    expect(() => assertGate(gate.replace(`${r01}\n${r02}`, `${r02}\n${r01}`))).toThrow();
    expect(() => assertGate(gate.replace("| R-03 | BLOCKED |", "| R-03 | PASS |"))).toThrow();
    expect(() => assertGate(gate.replace("| R-01 | PASS |", "| R-01 | BLOCKED |"))).toThrow();
    expect(() => assertGate(gate.replaceAll("proof head ", "review head "))).toThrow();
    expect(() => assertGate(gate.replace("LocalStack cannot substitute", "LocalStack is equivalent"))).toThrow();
    expect(() => assertGate(gate.replace("12 PASS / 2 BLOCKED / 0 FAIL / 0 unclassified", "13 PASS / 1 BLOCKED"))).toThrow();
  });
});
