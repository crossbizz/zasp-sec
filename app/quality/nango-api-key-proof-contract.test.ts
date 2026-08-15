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

function assertM014cComplete(tracker: string) {
  const inProgress = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
  const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
  const activeRows = markdownRows(inProgress).slice(2);
  const allCompleteRows = markdownRows(complete).slice(2);
  const completeRows = allCompleteRows.filter(([task]) => task === "M0-14c");
  expect(activeRows).toHaveLength(1);
  expect([...activeRows, ...allCompleteRows].filter(([task]) => task === "M0-15")).toHaveLength(1);
  expect(completeRows).toHaveLength(1);
  expect(completeRows[0]?.[1]).toBe("August 15, 2026");
  expect(completeRows[0]?.[2]).toContain("API-key connection");
}

describe("Nango API-key proof completion contract", () => {
  it("exposes exact hermetic and live commands with the fixed private boundary", async () => {
    const packageJson = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as {
      scripts?: Record<string, string>;
    };
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Nango API-key proof[\s\S]*?## Nango OAuth proof/)?.[0];

    expect(packageJson.scripts?.["proof:nango:api-key:test"]).toBe("node --test proofs/nango-api-key/*.test.mjs");
    expect(packageJson.scripts?.["proof:nango:api-key:run"]).toBe("node proofs/nango-api-key/run.mjs");
    expect(packageJson.scripts?.["proof:nango:api-key:test"]).not.toMatch(/docker|env-file|credential|proxy/i);
    expect(section).toBeDefined();
    expect(section).toContain("npm run proof:nango:api-key:test");
    expect(section).toContain("npm run proof:nango:api-key:run");
    expect(section).toContain("Nango API key proof passed: api_key=true reference=true product_state_safe=true cleanup=true.");
    expect(section).toContain("events.1password.com");
    expect(section).toContain("durable connection reference");
    expect(section).toContain("never enters product state");
    expect(section).toContain("no host port");
    expect(section).toMatch(/R-08 is\s+PASS/);
    expect(section).toContain("M0-14c is Complete");
  });

  it("binds the exact source-plan dependency, deliverable, and verification boundary", async () => {
    const sourcePlan = await readFile(
      resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const section = sourcePlan.match(/\*\*M0-14c - Nango API key proof\*\*[\s\S]*?\*\*M0-14 -/)?.[0];

    expect(section).toBeDefined();
    expect(section).toContain("Depends on: `M0-14b`");
    expect(section).toContain("Complete one API-key connection against a fixture provider through the product wrapper");
    expect(section).toContain("Product receives a connection reference without storing the raw provider key in product state");
    expect(section).toContain("Timebox: <=15 minutes");
  });

  it("records the exact private API-key fixture and reference-only design", async () => {
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-14c-nango-api-key-proof-design.md"),
      "utf8",
    );

    expect(design).toContain("v0.70.5");
    expect(design).toContain("7faf2c303bbb0322333f526e9ca31c0fe95ef58e");
    expect(design).toContain(nangoImage);
    expect(design).toContain(postgresImage);
    expect(design).toContain("1password-events");
    expect(design).toContain("events.1password.com");
    expect(design).toContain("/api/v2/auth/introspect");
    expect(design).toContain("/api-auth/api-key/:providerConfigKey");
    expect(design).toContain("raw provider key");
    expect(design).toContain("R-08 remains Not run through M0-15");
  });

  it("locks tests-first exact-owned implementation and completion gates", async () => {
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-14c-nango-api-key-proof-implementation-plan.md"),
      "utf8",
    );

    expect(plan).toContain("Tests-first RED");
    expect(plan).toMatch(/strict API-key product wrapper/i);
    expect(plan).toContain("single-use private TLS fixture");
    expect(plan).toContain("single mutation settlement journal");
    expect(plan).toMatch(/global\s+prefix\/label\/marker absence/);
    expect(plan).toContain("two consecutive final-code live passes");
    expect(plan).toContain("independent read-only review");
  });

  it("completes exactly M0-14c while preserving blocked and risk boundaries", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );

    expect(tracker).toContain("| Pending | 701 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 22 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 1 \| 22 \| 3 \|/);
    assertM014cComplete(tracker);
    expect(tracker).toMatch(/## Complete[\s\S]*?\| M0-14b \| August 15, 2026 \|/);
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-08 is PASS");
  });

  it("rejects duplicate completion or concurrent active rows", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    const m014cRow = markdownRows(tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "").find(([task]) => task === "M0-14c")?.join(" | ");
    expect(m014cRow).toBeDefined();
    const duplicate = tracker.replace("## Blocked\n", `| ${m014cRow} |\n\n## Blocked\n`);
    const concurrent = tracker.replace(
      "## Complete\n",
      "| M0-15 | August 15, 2026 | Concurrent proxy work. |\n\n## Complete\n",
    );

    expect(() => assertM014cComplete(duplicate)).toThrow();
    expect(() => assertM014cComplete(concurrent)).toThrow();
  });
});
