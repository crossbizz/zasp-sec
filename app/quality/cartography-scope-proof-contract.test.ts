import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type PackageManifest = { scripts?: Record<string, string> };

const repositoryRoot = process.cwd();
const proofDirectory = "proofs/cartography-scope";
const testCommand = `cd ${proofDirectory} && node --test normalizer.test.mjs run.test.mjs && /opt/homebrew/bin/python3.13 -m unittest -v fixture_runner_test.py`;
const runCommand = `node ${proofDirectory}/run.mjs`;
const fixedSuccessLine = "Cartography scope proof passed: fixtures=2 nodes=8 relationships=4 isolated=true labels_safe=true cleanup=true.";

describe("Cartography scope proof delivery-waiver status contract", () => {
  it("keeps the exact hermetic root commands without dotenv, credential, or proxy input", async () => {
    const manifest = JSON.parse(
      await readFile(resolve(repositoryRoot, "package.json"), "utf8"),
    ) as PackageManifest;

    expect(manifest.scripts?.["proof:cartography:test"]).toBe(testCommand);
    expect(manifest.scripts?.["proof:cartography:run"]).toBe(runCommand);
    expect(manifest.scripts?.["proof:cartography:test"]).not.toMatch(/env-file|source|\.\s+\.env|credential|proxy/i);
    expect(manifest.scripts?.["proof:cartography:run"]).not.toMatch(/env-file|source|\.\s+\.env|credential|proxy/i);
  });

  it("keeps the exact disposable image pins and fixed success result", async () => {
    const runner = await readFile(resolve(repositoryRoot, proofDirectory, "run.mjs"), "utf8");

    expect(runner).toContain("ghcr.io/cartography-cncf/cartography:0.139.1@sha256:f1d7c1f46a8a2137b9a955327d3cd47e8340c7d537d0447467d2e952af8bb8f0");
    expect(runner).toContain("neo4j:5.26-community@sha256:d9dd3dc7d1c78fa959191ff02dbdcbefadceaf83eee23428fb92a58cac8ad3fe");
    expect(runner).toContain(fixedSuccessLine);
  });

  it("documents the runnable two-Organization fixture boundary and blocked provider work", async () => {
    const [readme, tracker] = await Promise.all([
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
    ]);
    const section = readme.match(/## Cartography Organization-scope proof[\s\S]*?```bash\n([\s\S]*?)\n```/);

    expect(section?.[1]?.split("\n")).toEqual([
      "npm run proof:cartography:test",
      "npm run proof:cartography:run",
    ]);
    expect(readme).toContain("Docker and Python 3.13.11");
    expect(readme).toContain("two-Organization fixture-only");
    expect(readme).toContain("no dotenv, credential, or proxy input");
    expect(readme).toContain("no AWS or GitHub calls");
    expect(readme).toContain("customer-label normalization");
    expect(readme).toContain("cleanup");
    expect(readme).toContain("does not prove AWS/GitHub authorization parity");
    expect(tracker).toContain("M0-10 is Complete");
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
  });

  it("completes M0-10 without changing the blocked provider dependencies", async () => {
    const [waiver, tracker, readme, sourcePlan] = await Promise.all([
      readFile(
        resolve(repositoryRoot, "docs/internal/2026-08-14-m0-10-cartography-delivery-waiver-design.md"),
        "utf8",
      ),
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(
        resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
        "utf8",
      ),
    ]);

    expect(tracker).toContain("| Pending | 694 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 30 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    expect(tracker.match(/## In progress[\s\S]*?## Complete/)?.[0]).not.toContain("| M0-14a |");
    expect(tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0]).toContain("| M0-14a |");
    expect(tracker).toContain(
      "| M0-10 | August 14, 2026 | Two exact-pinned disposable Cartography/Neo4j fixture runs loaded two synthetic Organizations and proved eight normalized nodes, four relationships, collision isolation, customer-label safety, exact cleanup, pinned gates/scans, two consecutive live passes, and zero-finding independent review under the fixture-only waiver; no AWS/GitHub authorization-parity claim. |",
    );
    expect(tracker.match(/## In progress[\s\S]*?## Complete/)?.[0]).not.toContain("| M0-10 |");
    expect(tracker).toMatch(/## Blocked[\s\S]*?\| M0-09 \| August 13, 2026 \|/);
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
    expect(readme).toContain("M0-10 is Complete under the Cartography delivery waiver");
    expect(waiver).toContain("M0-10 may prove only the Cartography adapter");
    expect(waiver).toContain("It may not claim cross-account IAM");
    expect(sourcePlan).toContain("**M0-10 - Cartography proof**");
  });
});
