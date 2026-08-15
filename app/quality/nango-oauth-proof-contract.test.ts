import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const nangoImage =
  "nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed";
const postgresImage =
  "postgres:16.0-alpine@sha256:acf5271bbecd4b8733f4e93959a8d2b536a57aeee6cc4b6a71890aaf646425b8";

function markdownRows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function assertM014bComplete(tracker: string) {
  const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
  const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
  const activeRows = markdownRows(active).slice(2);
  const completeRows = markdownRows(complete).slice(2);
  const completedM014b = completeRows.filter(([task]) => task === "M0-14b");

  expect(activeRows).toHaveLength(1);
  expect([...activeRows, ...completeRows].filter(([task]) => task === "M0-15")).toHaveLength(1);
  expect(completedM014b).toHaveLength(1);
  expect(completedM014b[0]?.[1]).toBe("August 15, 2026");
  expect(completedM014b[0]?.[2]).toContain("OAuth");
}

describe("Nango OAuth proof contract", () => {
  it("exposes exact hermetic and live commands with the fixed private boundary", async () => {
    const packageJson = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as {
      scripts?: Record<string, string>;
    };
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Nango OAuth proof[\s\S]*?## Nango free boot proof/)?.[0];

    expect(packageJson.scripts?.["proof:nango:oauth:test"]).toBe("node --test proofs/nango-oauth/*.test.mjs");
    expect(packageJson.scripts?.["proof:nango:oauth:run"]).toBe("node proofs/nango-oauth/run.mjs");
    expect(section).toBeDefined();
    expect(section).toContain("npm run proof:nango:oauth:test");
    expect(section).toContain("npm run proof:nango:oauth:run");
    expect(section).toContain("Nango OAuth proof passed: oauth=true reference=true product_state_safe=true cleanup=true.");
    expect(section).toContain("no host port");
    expect(section).toContain("durable connection reference");
    expect(section).toContain("R-08 is PASS");
    expect(section).toContain("M0-14b is Complete");
  });

  it("binds the source-plan dependency, deliverable, and verification boundary", async () => {
    const sourcePlan = await readFile(
      resolve(
        repositoryRoot,
        "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md",
      ),
      "utf8",
    );
    const section = sourcePlan.match(/\*\*M0-14b - Nango OAuth proof\*\*[\s\S]*?\*\*M0-14c/)?.[0];

    expect(section).toBeDefined();
    expect(section).toContain("Depends on: `M0-14a`");
    expect(section).toContain("Complete one OAuth connection against a fixture provider");
    expect(section).toContain("Product receives a durable connection reference");
    expect(section).toContain("Timebox: <=15 minutes");
  });

  it("records the exact private OAuth runtime and reference-only boundary", async () => {
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-14-m0-14b-nango-oauth-proof-design.md"),
      "utf8",
    );

    expect(design).toContain("v0.70.5");
    expect(design).toContain("7faf2c303bbb0322333f526e9ca31c0fe95ef58e");
    expect(design).toContain(nangoImage);
    expect(design).toContain(postgresImage);
    expect(design).toContain("private TLS fixture provider");
    expect(design).toContain("github.com");
    expect(design).toContain("no host publication");
    expect(design).toContain("connectionId");
    expect(design).toContain("never written to product output");
    expect(design).toContain("R-08");
    expect(design).toContain("Not run through M0-15");
  });

  it("locks the exact-owned tests-first implementation boundary", async () => {
    const plan = await readFile(
      resolve(
        repositoryRoot,
        "docs/internal/2026-08-14-m0-14b-nango-oauth-proof-implementation-plan.md",
      ),
      "utf8",
    );

    expect(plan).toContain("strict product-wrapper boundary");
    expect(plan).toContain("single-use TLS fixture provider");
    expect(plan).toContain("single mutation settlement journal");
    expect(plan).toContain("global prefix/label/marker absence");
    expect(plan).toContain("two consecutive final-code live passes");
    expect(plan).toContain("independent read-only review");
  });

  it("completes exactly M0-14b without changing blocked or future boundaries", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );

    expect(tracker).toContain("| Pending | 690 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 34 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    assertM014bComplete(tracker);
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
  });

  it("rejects duplicate completion or a concurrent active task row", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    const duplicate = tracker.replace(
      "## Blocked\n",
      "| M0-14b | August 15, 2026 | Duplicate OAuth completion. |\n\n## Blocked\n",
    );
    const concurrent = tracker.replace(
      "## Complete\n",
      "| M0-15 | August 15, 2026 | Concurrent future work. |\n\n## Complete\n",
    );

    expect(() => assertM014bComplete(duplicate)).toThrow();
    expect(() => assertM014bComplete(concurrent)).toThrow();
  });
});
