import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");

function rows(markdown: string, heading: "In progress" | "Complete" | "Blocked") {
  const end = heading === "In progress" ? "Complete" : heading === "Complete" ? "Blocked" : "Review findings";
  const section = markdown.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return section
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .slice(2)
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

describe("EKS Fargate egress proof repository contract", () => {
  it("binds the source task and exact R-11 egress authority", async () => {
    const source = await readFile(
      resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const risk = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    const section = source.match(/\*\*M0-19 - Fargate egress proof\*\*[\s\S]*?\*\*M0-20 -/)?.[0];

    expect(section).toContain("Depends on: `M0-18`");
    expect(section).toContain("SecurityGroupPolicy");
    expect(section).toContain("Direct undeclared egress fails and allowed proxy egress succeeds");
    expect(risk).toContain("Security Groups for Pods");
    expect(risk).toContain("UDP/TCP 53");
    expect(risk).toContain("direct TCP 443 connection to the fixed undeclared-egress fixture fails");
  });

  it("records a fail-closed real-provider design and executable plan", async () => {
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-19-fargate-egress-proof-design.md"),
      "utf8",
    );
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-19-fargate-egress-proof-implementation-plan.md"),
      "utf8",
    );

    expect(design).toContain("LocalStack cannot authorize success");
    expect(design).toContain("vpcresources.k8s.aws/v1beta1");
    expect(design).toContain("single-attempt mutations");
    expect(design).toContain("direct=false proxy=true");
    expect(plan).toContain("Every behavior change follows a witnessed tests-only RED");
    expect(plan).toContain("transition M0-19 to Blocked");
  });

  it("keeps M0-19 blocked while M0-20 proceeds without advancing R-11", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const risk = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    const active = rows(tracker, "In progress");
    const blocked = rows(tracker, "Blocked");

    expect(readme).toContain("M0-19 is Blocked");
    expect(readme).toContain("0/19 required inputs");
    expect(readme).toContain("real EKS Security Groups for Pods");
    expect(tracker).toContain("| Pending | 678 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 47 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`678/0/47/3`");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(blocked.filter(([task]) => task === "M0-19")).toHaveLength(1);
    expect(blocked.find(([task]) => task === "M0-19")?.[2]).toContain("0/19 required inputs");
    expect(blocked.filter(([task]) => task === "M0-18")).toHaveLength(1);
    expect([...active, ...rows(tracker, "Complete"), ...blocked].filter(([task]) => task === "M0-20")).toHaveLength(1);
    expect(risk).toContain("Not run — M0-18/M0-19");
  });

  it("exposes the hermetic, live, and license boundaries from the root", async () => {
	const packageJson = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as { scripts?: Record<string, string> };
	const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
	const section = readme.match(/## EKS Fargate egress proof[\s\S]*?## EKS Fargate verification proof/)?.[0];
	expect(packageJson.scripts?.["proof:fargate-egress:test"]).toBe(
	  "cd proofs/fargate-egress && go test -race -count=1 ./... && node --test run.test.mjs license-audit.test.mjs",
	);
	expect(packageJson.scripts?.["proof:fargate-egress:run"]).toBe("node proofs/fargate-egress/run.mjs");
	expect(packageJson.scripts?.["proof:fargate-egress:license"]).toBe("node proofs/fargate-egress/license-audit.mjs");
	expect(section).toContain("npm run proof:fargate-egress:test");
	expect(section).toContain("npm run proof:fargate-egress:run");
	expect(section).toContain("npm run proof:fargate-egress:license");
	expect(section).toContain("EKS Fargate egress proof passed: direct_denied=true proxy_allowed=true eni_attached=true cleanup=true.");
	expect(section).toContain("EKS Fargate egress proof failed: <category> rejected.");
  });
});
