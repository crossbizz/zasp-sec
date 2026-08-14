import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type PackageManifest = { scripts?: Record<string, string> };
const repositoryRoot = process.cwd();
const proofDirectory = "proofs/opensearch-event";

describe("OpenSearch event projection proof repository contract", () => {
  it("keeps the exact toolchain and official OpenSearch image pin", async () => {
    const goModule = await readFile(resolve(repositoryRoot, proofDirectory, "go.mod"), "utf8");
    const runner = await readFile(resolve(repositoryRoot, proofDirectory, "run.mjs"), "utf8");
    expect(goModule).toMatch(/^go 1\.25\.0$/m);
    expect(goModule).toMatch(/^toolchain go1\.26\.5$/m);
    expect(runner).toMatch(/opensearchproject\/opensearch:3\.8\.0@sha256:[a-f0-9]{64}/);
  });

  it("keeps stable root test and disposable live commands without dotenv", async () => {
    const manifest = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as PackageManifest;
    expect(manifest.scripts?.["proof:opensearch:event:test"]).toBe(
      `cd ${proofDirectory} && go test -race -count=1 ./... && node --test run.test.mjs`,
    );
    expect(manifest.scripts?.["proof:opensearch:event:run"]).toBe(`node ${proofDirectory}/run.mjs`);
    expect(manifest.scripts?.["proof:opensearch:event:run"]).not.toMatch(/env-file|source|\.\s+\.env/);
  });

  it("documents the scoped EventStore contract and the local-only evidence boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## OpenSearch event projection proof[\s\S]*?```bash\n([\s\S]*?)\n```/);
    expect(section?.[1]?.split("\n")).toEqual([
      "npm run proof:opensearch:event:test",
      "npm run proof:opensearch:event:run",
    ]);
    expect(readme).toContain("Organization A");
    expect(readme).toContain("Organization B");
    expect(readme).toContain("narrow scoped `EventStore`");
    expect(readme).toContain("not AWS OpenSearch Service, IAM, durability, recovery, or release-parity evidence");
  });

  it("keeps the durable event metadata-only and the query API structured", async () => {
    const source = await readFile(resolve(repositoryRoot, proofDirectory, "proof.go"), "utf8");
    expect(source).toMatch(/type EventStore interface \{\s*IndexSessionEvent\([^\n]+\) error\s*QuerySession\([^\n]+SessionFilter\)/m);
    expect(source).not.toMatch(/json:"(?:prompt|response|content|body|secret)/);
  });
});
