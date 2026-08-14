import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type PackageManifest = { scripts?: Record<string, string> };
const repositoryRoot = process.cwd();
const proofDirectory = "proofs/localstack-sqs";

describe("LocalStack SQS proof repository contract", () => {
  it("keeps exact toolchain and current official AWS SDK v2 pins", async () => {
    const goModule = await readFile(resolve(repositoryRoot, proofDirectory, "go.mod"), "utf8");
    expect(goModule).toMatch(/^go 1\.25\.0$/m);
    expect(goModule).toMatch(/^toolchain go1\.26\.5$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2 v1\.43\.5$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2\/service\/sqs v1\.46\.5$/m);
  });

  it("keeps stable root test and dotenv-safe live commands", async () => {
    const manifest = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as PackageManifest;
    expect(manifest.scripts?.["proof:localstack:sqs:test"]).toBe(
      `cd ${proofDirectory} && go test -race -count=1 ./...`,
    );
    expect(manifest.scripts?.["proof:localstack:sqs:run"]).toBe(
      "node --env-file=.env proofs/localstack-sqs/run.mjs",
    );
  });

  it("documents the runnable root sequence and supported proof boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## LocalStack SQS proof[\s\S]*?```bash\n([\s\S]*?)\n```/);
    expect(section?.[1]?.split("\n")).toEqual([
      "npm run proof:localstack:sqs:test",
      "npm run proof:localstack:sqs:run",
    ]);
    expect(readme).toContain("AWS_ENDPOINT_URL");
    expect(readme).toContain("one batched message");
    expect(readme).toContain("not real-AWS IAM or release-parity evidence");
  });
});
