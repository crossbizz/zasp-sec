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

function assertM014aComplete(tracker: string) {
  const inProgress = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
  const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
  const activeRows = markdownRows(inProgress).slice(2);
  const completeRows = markdownRows(complete).slice(2);
  const rows = completeRows.filter(([task]) => task === "M0-14a");

  expect(activeRows).toHaveLength(1);
  expect([...activeRows, ...completeRows].filter(([task]) => task === "M0-15")).toHaveLength(1);
  expect(rows).toHaveLength(1);
  expect(rows[0]?.[0]).toBe("M0-14a");
  expect(rows[0]?.[1]).toBe("August 14, 2026");
  expect(rows[0]?.[2]).toContain("two consecutive final-code");
  expect(rows[0]?.[2]).toContain("zero-finding independent review");
}

describe("Nango free boot proof contract", () => {
  it("exposes exact hermetic and live root commands with the documented fixed boundary", async () => {
    const [manifestSource, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const manifest = JSON.parse(manifestSource) as { scripts?: Record<string, string> };
    const section = readme.match(/## Nango free boot proof[\s\S]*?## Tetragon signal proof/)?.[0];

    expect(manifest.scripts?.["proof:nango:test"]).toBe(
      "node --test proofs/nango-free-boot/*.test.mjs",
    );
    expect(manifest.scripts?.["proof:nango:run"]).toBe(
      "node proofs/nango-free-boot/run.mjs",
    );
    expect(manifest.scripts?.["proof:nango:test"]).not.toMatch(/docker|env-file|credential|proxy/i);
    expect(manifest.scripts?.["proof:nango:run"]).not.toMatch(/env-file|credential|proxy/i);
    expect(section).toBeDefined();
    expect(section).toContain("npm run proof:nango:test");
    expect(section).toContain("npm run proof:nango:run");
    expect(section).toContain(
      "Nango free boot proof passed: services=2 ready=true product_network=true cleanup=true.",
    );
    expect(section).toContain("M0-14a is Complete");
    expect(section).toContain("R-08 is PASS");
    expect(section).toContain("does not read `.env`");
  });

  it("binds the source-plan dependency, deliverable, and verification boundary", async () => {
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const section = plan.match(/\*\*M0-14a - Nango free boot proof\*\*[\s\S]*?\*\*M0-14b/)?.[0];

    expect(section).toBeDefined();
    expect(section).toContain("Depends on: `M0-13`");
    expect(section).toContain("free self-hosted Nango build");
    expect(section).toContain("only required Auth/Proxy dependencies");
    expect(section).toContain("Health endpoint is reachable from the product test network");
    expect(section).toContain("Timebox: <=15 minutes");
  });

  it("records exact current self-hosted and database image pins", async () => {
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-14-m0-14a-nango-free-boot-proof-design.md"),
      "utf8",
    );

    expect(design).toContain("v0.70.5");
    expect(design).toContain("7faf2c303bbb0322333f526e9ca31c0fe95ef58e");
    expect(design).toContain(nangoImage);
    expect(design).toContain(postgresImage);
    expect(design).toContain("Elastic License");
  });

  it("limits the runtime to free Auth/Proxy boot dependencies", async () => {
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-14-m0-14a-nango-free-boot-proof-design.md"),
      "utf8",
    );
    const prose = design.replace(/\s+/g, " ");

    expect(prose).toContain("exactly two long-running containers");
    expect(prose).toContain("Nango server and PostgreSQL");
    expect(prose).toContain("Redis is optional");
    expect(prose).toContain("Connect UI is disabled");
    expect(prose).toContain("Functions, Webhooks, MCP server, RBAC, and Enterprise-only runtime");
    expect(prose).toContain("separate database");
    expect(prose).toContain("separate schema");
    expect(prose).toContain("per-run encryption key");
  });

  it("requires database-backed readiness from a private product test network", async () => {
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-14-m0-14a-nango-free-boot-proof-design.md"),
      "utf8",
    );
    const prose = design.replace(/\s+/g, " ");

    expect(prose).toContain("/ready");
    expect(prose).toContain('{"result":"ok"}');
    expect(prose).toContain("private internal Docker network");
    expect(prose).toContain("one-shot product probe");
    expect(prose).toContain("Neither PostgreSQL nor Nango publishes a host port");
    expect(prose).toContain("prefix-wide zero-resource audit");
  });

  it("locks tests-first exact-owned orchestration and cleanup", async () => {
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-14-m0-14a-nango-free-boot-proof-implementation-plan.md"),
      "utf8",
    );

    expect(plan).toContain("Tests-first RED");
    expect(plan).toContain("mutation settlement");
    expect(plan).toContain("exact full container ID");
    expect(plan).toContain("private internal network");
    expect(plan).toContain("database-backed `/ready`");
    expect(plan).toContain("independent cleanup");
    expect(plan).toContain("two consecutive live runs");
    expect(plan).toContain("independent review");
  });

  it("completes exactly M0-14a without changing blocked boundaries", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );

    expect(tracker).toContain("| Pending | 699 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 25 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    assertM014aComplete(tracker);
    expect(tracker).toContain("M0-13");
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
  });

  it("rejects duplicate M0-14a and any concurrent in-progress row", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    const duplicateRow = "| M0-14a | August 14, 2026 | Duplicate. |";
    const concurrentRow = "| M0-15 | August 15, 2026 | Decoy concurrent work. |";
    const duplicate = tracker.replace("## Complete\n", `${duplicateRow}\n\n## Complete\n`);
    const concurrent = tracker.replace("## Complete\n", `${concurrentRow}\n\n## Complete\n`);

    expect(() => assertM014aComplete(duplicate)).toThrow();
    expect(() => assertM014aComplete(concurrent)).toThrow();
  });

  it("keeps the broader Nango risk gate Not run", async () => {
    const riskRegister = await readFile(
      resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"),
      "utf8",
    );
    const rows = markdownRows(riskRegister).filter(([id]) => id === "R-08");

    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveLength(6);
    expect(rows[0]?.[5]).toMatch(/^PASS — M0-15 — /);
  });
});
