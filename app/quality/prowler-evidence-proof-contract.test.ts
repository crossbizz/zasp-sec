import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = process.cwd();
const prowlerImage = "prowlercloud/prowler:5.39.0@sha256:58c8a0eb0c947517bd89b6214cde0cc1d5f59df4eebbb99a87475ab741914959";
const checkId = "iam_role_cross_service_confused_deputy_prevention";
const fixtureArn = "arn:aws:iam::000000000000:role/shared-fixture-role";
const canonicalResourceId = "org_aaaaaaaaaaaaaaaa:aws:identity_role:81eeba69c5c0887f4083a0e195a431b852d750fd3ee41ad276c1142285d1b77b";

describe("Prowler evidence proof start contract", () => {
  it("locks the approved fixture-only image, built-in check, and normalization boundary", async () => {
    const [design, sourcePlan, riskRegister] = await Promise.all([
      readFile(
        resolve(repositoryRoot, "docs/internal/2026-08-14-m0-11-prowler-proof-design.md"),
        "utf8",
      ),
      readFile(
        resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
        "utf8",
      ),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
    ]);

    expect(sourcePlan).toContain("**M0-11 - Prowler proof**");
    expect(sourcePlan).toContain("Run a minimal Prowler AWS fixture and parse one relevant finding.");
    expect(sourcePlan).toContain("Finding maps to a canonical resource ID and normalized evidence.");
    expect(design).toContain(prowlerImage);
    expect(design).toContain(checkId);
    expect(design).toMatch(/filters to `FAIL`,\s+and writes only JSON-OCSF/);
    expect(design).toContain(fixtureArn);
    expect(design).toContain(canonicalResourceId);
    expect(riskRegister).toContain("| R-06 | **Prowler evidence normalization.**");
    expect(riskRegister).toContain("| Not run — M0-11 |");
  });

  it("starts exactly one source-plan task without completing M0-11", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    const inProgressSection = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0];
    const completeSection = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0];

    expect(tracker).toContain("| Pending | 717 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 9 |");
    expect(tracker).toContain("| Blocked | 1 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 16 \| 1 \| 9 \| 1 \|/);
    expect(inProgressSection).toContain("| M0-11 | August 14, 2026 |");
    expect(inProgressSection).toContain("exact-pinned Prowler fixture-only evidence proof");
    expect(inProgressSection).toContain("without claiming real-AWS parity");
    expect(completeSection).not.toContain("| M0-11 |");
    expect(completeSection).toContain("| M0-10 | August 14, 2026 |");
  });

  it("documents the exact start boundary without weakening blocked provider work", async () => {
    const [readme, tracker, design] = await Promise.all([
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(
        resolve(repositoryRoot, "docs/internal/2026-08-14-m0-11-prowler-proof-design.md"),
        "utf8",
      ),
    ]);
    const section = readme.match(/## Prowler evidence proof[\s\S]*?## Real AWS cross-account IAM proof/)?.[0];

    expect(section).toBeDefined();
    expect(section ?? "").toContain("M0-11 is In progress");
    expect(section ?? "").toContain(prowlerImage);
    expect(section ?? "").toContain(checkId);
    expect(section ?? "").toContain("one synthetic IAM role");
    expect(section ?? "").toContain("JSON-OCSF");
    expect(section ?? "").toContain("canonical Organization-scoped resource");
    expect(section ?? "").toContain("does not prove real-AWS authorization or parity");
    expect(tracker).toMatch(/## Blocked[\s\S]*?\| M0-09 \| August 13, 2026 \|/);
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
    expect(design).toMatch(/M0-09 and PROV-01 remain\s+Blocked/);
    expect(design).toMatch(/R-03\s+remains incomplete/);
  });
});
