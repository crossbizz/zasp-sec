import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { expectValidTrackerSnapshot } from "./tracker-contract";

const repositoryRoot = resolve(import.meta.dirname, "../..");

function markdownRows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function taskRows(tracker: string, heading: "In progress" | "Complete" | "Blocked") {
  const end = heading === "In progress" ? "Complete" : heading === "Complete" ? "Blocked" : "Review findings";
  const section = tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return markdownRows(section).slice(2);
}

function assertM018Blocked(tracker: string, readme: string, riskRegister: string) {
  expectValidTrackerSnapshot(tracker);
  const section = readme.match(/## EKS Fargate verification proof[\s\S]*?## OPA SDK proof/)?.[0];
  const activeRows = taskRows(tracker, "In progress");
  const completeRows = taskRows(tracker, "Complete");
  const blockedRows = taskRows(tracker, "Blocked");
  const riskRows = markdownRows(riskRegister).filter(([id]) => id === "R-11");

  expect(section).toBeDefined();
  expect(section).toContain("M0-18 is Blocked");
  expect(section).toContain("real EKS Fargate");
  expect(section).toContain("LocalStack");
  expect(section).toMatch(/cannot\s+(prove|satisfy)\s+(the\s+)?Fargate/i);
  expect(section).toContain("R-11 remains Not run");

  expect(section).toContain("0/11 required inputs");
  expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
  expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
  expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
  expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
  expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
  expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
  expect(activeRows).toHaveLength(0);
  expect(blockedRows.filter(([task]) => task === "M0-18")).toHaveLength(1);
  expect(blockedRows.find(([task]) => task === "M0-18")?.[1]).toBe("August 15, 2026");
  expect(blockedRows.find(([task]) => task === "M0-18")?.[2]).toContain("0/11");
  expect(blockedRows.filter(([task]) => task === "M0-19")).toHaveLength(1);
  expect(blockedRows.find(([task]) => task === "M0-19")?.[2]).toContain("0/19");
  expect(completeRows.filter(([task]) => task === "M0-17")).toHaveLength(1);
  expect([...activeRows, ...completeRows, ...blockedRows].filter(([task]) => task === "M0-19")).toHaveLength(1);
  expect(blockedRows.filter(([task]) => task === "M0-09")).toHaveLength(1);
  expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
  expect(tracker).toContain("R-03 remains incomplete");

  expect(riskRows).toHaveLength(1);
  expect(riskRows[0]?.[5]).toBe("Not run — M0-18/M0-19");
}

describe("EKS Fargate verification proof repository contract", () => {
  it("binds the source task, R-11, and the real-provider authority", async () => {
    const sourcePlan = await readFile(
      resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-18-fargate-verification-proof-design.md"),
      "utf8",
    );
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-18-fargate-verification-proof-implementation-plan.md"),
      "utf8",
    );
    const sourceSection = sourcePlan.match(/\*\*M0-18 - Fargate verification proof\*\*[\s\S]*?\*\*M0-19 -/)?.[0];

    expect(sourceSection).toBeDefined();
    expect(sourceSection).toContain("Depends on: `M0-17`");
    expect(sourceSection).toContain("existing disposable EKS Fargate test profile");
    expect(sourceSection).toContain("Pod is Fargate-scheduled");
    expect(sourceSection).toContain("run resources are deleted");
    expect(sourceSection).toContain("Timebox: <=15 minutes");
    expect(riskRegister).toContain("agentsec-attack-lab-canary-v1");
    expect(riskRegister).toContain("eks.amazonaws.com/compute-type: fargate");
    expect(design).toContain("embedded k3s/k3d or self-managed nodes");
    expect(design).toMatch(/cannot make M0-18\s+Complete or advance R-11/);
    expect(plan).toContain("LocalStack/k3s can test no more than generic compatibility");
    expect(plan).toContain("Every behavior change follows a witnessed tests-only RED");
  });

  it("blocks M0-18 without advancing R-11", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    assertM018Blocked(tracker, readme, riskRegister);
  });

  it("records the exact inert capability boundary", async () => {
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-18-fargate-verification-proof-design.md"),
      "utf8",
    );

    expect(design).toContain("AWS_M018_ISOLATED_TEST=I_UNDERSTAND_THIS_MUTATES_A_DISPOSABLE_EKS_PROFILE");
    expect(design).toContain("AWS_M018_KUBECONFIG");
    expect(design).toContain("AWS_M018_FARGATE_PROFILE");
    expect(design).toContain("AWS_M018_PROXY_URL");
    expect(design).toContain("AWS_M018_CANARY_TOKEN");
    expect(design).toContain("fails at configuration before any cluster request");
    expect(design).toContain("EKS Fargate proof passed: scheduled=true canary=true cleanup=true.");
  });

  it("exposes the hermetic test live runner and immutable license audit", async () => {
	const packageSource = await readFile(resolve(repositoryRoot, "package.json"), "utf8");
	const packageJson = JSON.parse(packageSource) as { scripts?: Record<string, string> };
	const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
	const section = readme.match(/## EKS Fargate verification proof[\s\S]*?## OPA SDK proof/)?.[0];

	expect(packageJson.scripts?.["proof:fargate:test"]).toBe(
	  "cd proofs/fargate-verification && go test -race -count=1 ./... && node --test run.test.mjs license-audit.test.mjs",
	);
	expect(packageJson.scripts?.["proof:fargate:run"]).toBe("node proofs/fargate-verification/run.mjs");
	expect(packageJson.scripts?.["proof:fargate:license"]).toBe("node proofs/fargate-verification/license-audit.mjs");
	expect(section).toContain("npm run proof:fargate:test");
	expect(section).toContain("npm run proof:fargate:run");
	expect(section).toContain("npm run proof:fargate:license");
	expect(section).toContain("GPL-2.0-only");
	expect(section).toContain("EKS Fargate proof passed: scheduled=true canary=true cleanup=true.");
  });

  it("rejects duplicate, concurrent, premature-risk, local-authority, and aggregate drift", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    const blockedRow = taskRows(tracker, "Blocked").find(([task]) => task === "M0-18")?.join(" | ");

    expect(blockedRow).toBeDefined();
    expect(() => assertM018Blocked(tracker, readme, riskRegister)).not.toThrow();
    expect(() =>
      assertM018Blocked(
        tracker.replace(`| ${blockedRow} |\n`, `| ${blockedRow} |\n| ${blockedRow} |\n`),
        readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM018Blocked(
        tracker.replace("## Complete\n", "| M0-19 | August 15, 2026 | Concurrent work. |\n\n## Complete\n"),
        readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM018Blocked(
        tracker,
        readme,
        riskRegister.replace("Not run — M0-18/M0-19", "PASS — M0-18 — local fixture"),
      ),
    ).toThrow();
    expect(() =>
      assertM018Blocked(
        tracker,
        readme.replace(/cannot\s+prove\s+Fargate/, "proves Fargate"),
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM018Blocked(tracker.replace(/^\| Pending \| \d+ \|/m, "| Pending | 686 |"), readme, riskRegister),
    ).toThrow();
  });
});
