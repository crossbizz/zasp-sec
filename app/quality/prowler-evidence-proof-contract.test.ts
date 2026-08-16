import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type PackageManifest = { scripts?: Record<string, string> };

const repositoryRoot = process.cwd();
const proofDirectory = "proofs/prowler-evidence";
const prowlerImage = "prowlercloud/prowler:5.39.0@sha256:58c8a0eb0c947517bd89b6214cde0cc1d5f59df4eebbb99a87475ab741914959";
const localStackImage = "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c";
const checkId = "iam_role_cross_service_confused_deputy_prevention";
const fixtureArn = "arn:aws:iam::000000000000:role/shared-fixture-role";
const canonicalResourceId = "org_aaaaaaaaaaaaaaaa:aws:identity_role:81eeba69c5c0887f4083a0e195a431b852d750fd3ee41ad276c1142285d1b77b";
const successLine = "Prowler evidence proof passed: findings=1 resources=1 evidence=1 linked=true cleanup=true.";
const failureLine = "Prowler evidence proof failed: operation rejected.";
const pythonTests = [
  "fixture_runner_test.FixtureParsingTests",
  "fixture_runner_test.ArtifactBoundaryTests",
  "fixture_runner_test.RuntimeTests",
  "fixture_runner_test.FileBoundaryTests",
  "fixture_runner_test.MainBoundaryTests",
].join(" ");
const testCommand = `cd ${proofDirectory} && node --test normalizer.test.mjs run.test.mjs license-audit.test.mjs && PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3.13 -m unittest -v ${pythonTests}`;
const runCommand = `node ${proofDirectory}/run.mjs`;
const licenseCommand = `node ${proofDirectory}/license-audit.mjs`;
const expectedR06Row = [
  "R-06",
  "**Prowler evidence normalization.** A relevant cloud-posture finding must map to product evidence.",
  "A minimal AWS fixture produces one relevant Prowler finding that maps to a canonical resource ID and normalized evidence.",
  "No relevant finding is produced, or it cannot map to both a canonical resource ID and normalized evidence.",
  "Discovery owner: block Prowler-derived MVP findings; revise the adapter or choose another evidence source.",
  "PASS — M0-11",
];

function parseMarkdownRows(markdown: string) {
  return markdown
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function assertR06Pass(riskRegister: string) {
  const r06Rows = parseMarkdownRows(riskRegister).filter(([id]) => id === "R-06");

  expect(r06Rows).toHaveLength(1);
  expect(r06Rows[0]).toEqual(expectedR06Row);
}

function assertM011Complete(tracker: string) {
  const inProgressSection = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0];
  const inProgressRows = parseMarkdownRows(inProgressSection ?? "");
  const [header, separator, ...dataRows] = inProgressRows;
  const completeSection = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0];
  const completeRows = parseMarkdownRows(completeSection ?? "").slice(2);
  const m011Rows = completeRows.filter(([task]) => task === "M0-11");

  expect(inProgressSection).toBeDefined();
  expect(header).toEqual(["Task", "Started", "Current work"]);
  expect(separator).toHaveLength(3);
  expect(separator?.every((cell) => /^:?-{3,}:?$/.test(cell))).toBe(true);
  expect(dataRows).toHaveLength(1);
  expect([...dataRows, ...completeRows].filter(([task]) => task === "M0-15")).toHaveLength(1);
  expect(completeSection).toBeDefined();
  expect(m011Rows).toHaveLength(1);
  expect(m011Rows[0]).toHaveLength(3);
  expect(m011Rows[0]?.[1]).toBe("August 14, 2026");
  expect(m011Rows[0]?.[2]).toContain("exact-pinned Prowler fixture-only evidence proof");
  expect(m011Rows[0]?.[2]).toContain("without claiming real-AWS parity");
}

describe("Prowler evidence proof contract", () => {
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
    assertR06Pass(riskRegister);
  });

  it("exposes an exact hermetic root test command and the disposable live runner", async () => {
    const manifest = JSON.parse(
      await readFile(resolve(repositoryRoot, "package.json"), "utf8"),
    ) as PackageManifest;

    expect(manifest.scripts?.["proof:prowler:test"]).toBe(testCommand);
    expect(manifest.scripts?.["proof:prowler:run"]).toBe(runCommand);
    expect(manifest.scripts?.["proof:prowler:license"]).toBe(licenseCommand);
    expect(manifest.scripts?.["proof:prowler:test"]).not.toMatch(
      /docker|PinnedImageCompatibilityTests|env-file|source|credential|proxy/i,
    );
    expect(manifest.scripts?.["proof:prowler:run"]).not.toMatch(
      /env-file|source|credential|proxy/i,
    );
  });

  it("binds repository documentation to the executable runtime boundary", async () => {
    const runtime = await import("../../proofs/prowler-evidence/run.mjs");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(
      /## Prowler evidence proof[\s\S]*?## Real AWS cross-account IAM proof/,
    )?.[0];

    expect(runtime.PROWLER_IMAGE).toBe(prowlerImage);
    expect(runtime.LOCALSTACK_IMAGE).toBe(localStackImage);
    expect(runtime.SUCCESS_LINE).toBe(successLine);
    expect(section).toBeDefined();
    expect(section).toContain(prowlerImage);
    expect(section).toContain(localStackImage);
    expect(section).toContain(successLine);
    expect(section).toContain("Prowler evidence proof failed: <category> rejected.");
    expect(section).toContain("Node.js `22.23.1` and npm `10.9.8`");
    expect(section).toContain("Python `3.13.11`");
    expect(section).toContain("Docker");
    expect(section).toContain("fixture-only");
    expect(section).toContain("does not prove real-AWS authorization or parity");
    expect(section).toContain("proof-owned containers, network, output, and temporary directories");
    expect(section).toContain("M0-11 is Complete");
    expect(section).toContain("npm run proof:prowler:license");
    expect(section).toContain("LocalStack Community image");
    expect(section).toContain("Apache-2.0 plus its tagged community EULA");

    const commands = section?.match(/```bash\n([\s\S]*?)\n```/)?.[1];
    expect(commands?.split("\n")).toEqual([
      "npm run proof:prowler:test",
      "npm run proof:prowler:license",
      "npm run proof:prowler:run",
    ]);
  });

  it("keeps runtime failures fixed and free of thrown details", async () => {
    const runtime = await import("../../proofs/prowler-evidence/run.mjs");
    let stdout = "";
    let stderr = "";
    let exitCode: number | undefined;

    const code = await runtime.runMain(undefined, {
      runtimeFactory: () => {
        throw new Error("sensitive runtime detail");
      },
      stdout: { write: (value: string) => { stdout += value; } },
      stderr: { write: (value: string) => { stderr += value; } },
      setExitCode: (value: number) => { exitCode = value; },
    });

    expect(code).toBe(1);
    expect(exitCode).toBe(1);
    expect(stdout).toBe("");
    expect(stderr).toBe(`${failureLine}\n`);
    expect(stderr).not.toContain("sensitive runtime detail");
  });

  it("completes exactly one source-plan task after reviewed live evidence", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    expect(tracker).toContain("| Pending | 685 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 39 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    assertM011Complete(tracker);
  });

  it("rejects a duplicate M0-11 Complete data row even when the aggregate remains twenty-four", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    const m011Row = tracker.split("\n").find((line) => line.startsWith("| M0-11 |"));

    expect(m011Row).toBeDefined();
    const mutatedTracker = tracker.replace(`${m011Row}\n`, `${m011Row}\n${m011Row}\n`);
    expect(mutatedTracker).toContain("| Complete | 39 |");
    expect(() => assertM011Complete(mutatedTracker)).toThrow();
  });

  it("rejects an extra In progress data row when the aggregate remains one", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    const extraRow = "| M0-15 | August 15, 2026 | Unexpected concurrent work. |";
    const completeHeading = "## Complete\n";

    const mutatedTracker = tracker.replace(completeHeading, `${extraRow}\n\n${completeHeading}`);
    expect(mutatedTracker).toContain("| In progress | 1 |");
    expect(() => assertM011Complete(mutatedTracker)).toThrow();
  });

  it("binds the exact PASS state to the parsed R-06 row", async () => {
    const riskRegister = await readFile(
      resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"),
      "utf8",
    );
    const r06Row = riskRegister.split("\n").find((line) => line.startsWith("| R-06 |"));

    expect(r06Row).toBeDefined();
    const changedR06Row = (r06Row ?? "").replace(
      "| PASS — M0-11 |",
      "| PASS — M0-11 — invalid-review-mutation |",
    );
    const mutatedRiskRegister = `${riskRegister.replace(r06Row ?? "", changedR06Row)}\n| PASS — M0-11 |\n`;

    expect(changedR06Row).not.toBe(r06Row);
    expect(() => assertR06Pass(mutatedRiskRegister)).toThrow();
  });

  it("documents the exact completion boundary without weakening blocked provider work", async () => {
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
    expect(section ?? "").toContain("M0-11 is Complete");
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
