import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type PackageManifest = { scripts?: Record<string, string> };
const repositoryRoot = process.cwd();
const proofDirectory = "proofs/localstack-storage";

describe("LocalStack storage proof repository contract", () => {
  it("keeps exact toolchain and current official AWS SDK v2 pins", async () => {
    const goModule = await readFile(resolve(repositoryRoot, proofDirectory, "go.mod"), "utf8");
    expect(goModule).toMatch(/^go 1\.25\.0$/m);
    expect(goModule).toMatch(/^toolchain go1\.26\.5$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2 v1\.43\.6$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2\/service\/s3 v1\.107\.2$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2\/service\/kms v1\.55\.6$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2\/service\/secretsmanager v1\.44\.6$/m);
  });

  it("keeps stable root test and disposable live commands without dotenv evaluation", async () => {
    const manifest = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as PackageManifest;
    expect(manifest.scripts?.["proof:localstack:storage:test"]).toBe(
      `cd ${proofDirectory} && go test -race -count=1 ./... && node --test run.test.mjs`,
    );
    expect(manifest.scripts?.["proof:localstack:storage:run"]).toBe(
      `node ${proofDirectory}/run.mjs`,
    );
    expect(manifest.scripts?.["proof:localstack:storage:run"]).not.toMatch(/env-file|source|\.\s+\.env/);
  });

  it("documents the runnable sequence and the LocalStack-only proof boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## LocalStack storage proof[\s\S]*?```bash\n([\s\S]*?)\n```/);
    expect(section?.[1]?.split("\n")).toEqual([
      "npm run proof:localstack:storage:test",
      "npm run proof:localstack:storage:run",
    ]);
    expect(readme).toContain("proof-owned disposable LocalStack 4.7.0 container");
    expect(readme).toContain("Organization-scoped object key");
    expect(readme).toContain("not real-AWS encryption, IAM, durability, recovery, or release-parity evidence");
    expect(readme).toContain("R-03 remains open until M0-09");
  });
});
