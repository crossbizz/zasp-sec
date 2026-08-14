import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type PackageManifest = { scripts?: Record<string, string> };
const repositoryRoot = process.cwd();
const proofDirectory = "proofs/aws-cross-account-iam";

describe("real AWS cross-account IAM proof repository contract", () => {
  it("keeps the exact toolchain and current official AWS SDK pins", async () => {
    const goModule = await readFile(resolve(repositoryRoot, proofDirectory, "go.mod"), "utf8");
    expect(goModule).toMatch(/^go 1\.25\.0$/m);
    expect(goModule).toMatch(/^toolchain go1\.26\.5$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2 v1\.43\.5$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2\/service\/sts v1\.45\.5$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2\/service\/iam v1\.59\.0$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/smithy-go v1\.27\.7$/m);
  });

  it("keeps stable root test and explicitly gated dotenv live commands", async () => {
    const manifest = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as PackageManifest;
    expect(manifest.scripts?.["proof:aws:iam:test"]).toBe(
      `cd ${proofDirectory} && go test -race -count=1 ./... && node --test run.test.mjs`,
    );
    expect(manifest.scripts?.["proof:aws:iam:run"]).toBe(`node --env-file=.env ${proofDirectory}/run.mjs`);
  });

  it("documents every explicit live prerequisite and the incomplete real-AWS gate", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Real AWS cross-account IAM proof[\s\S]*?```bash\n([\s\S]*?)\n```/);
    expect(section?.[1]?.split("\n")).toEqual([
      "npm run proof:aws:iam:test",
      "npm run proof:aws:iam:run",
    ]);
    for (const name of [
      "AWS_M009_ISOLATED_TEST",
      "AWS_M009_SOURCE_ACCOUNT_ID",
      "AWS_M009_TARGET_ACCOUNT_ID",
      "AWS_M009_SOURCE_PRINCIPAL_ARN",
      "AWS_M009_SOURCE_ACCESS_KEY_ID",
      "AWS_M009_SOURCE_SECRET_ACCESS_KEY",
      "AWS_M009_TARGET_ADMIN_ACCESS_KEY_ID",
      "AWS_M009_TARGET_ADMIN_SECRET_ACCESS_KEY",
    ]) {
      expect(readme).toContain(name);
    }
    expect(readme).toContain("LocalStack cannot satisfy this release-parity authorization gate");
    expect(readme).toContain("M0-09 and R-03 remain In progress");
    expect(readme).toContain("No shared, staging, customer, or production AWS account may be used");
  });

  it("keeps exact STS trust, narrow allow, explicit deny, and one-attempt mutation boundaries", async () => {
    const proof = await readFile(resolve(repositoryRoot, proofDirectory, "proof.go"), "utf8");
    const sdk = await readFile(resolve(repositoryRoot, proofDirectory, "sdk.go"), "utf8");
    expect(proof).toContain('"sts:ExternalId"');
    expect(proof).toContain('"sts:RoleSessionName"');
    expect(proof).toContain('"sts:SourceIdentity"');
    expect(proof).toContain('"sts:TagSession"');
    expect(proof).toContain('"iam:GetRole"');
    expect(proof).toContain('"iam:ListRoles"');
    expect(proof).toContain('"Effect": "Deny"');
    expect(sdk).toMatch(/mutationSTSOptions[\s\S]*RetryMaxAttempts = 1/);
    expect(sdk).toMatch(/mutationIAMOptions[\s\S]*RetryMaxAttempts = 1/);
    expect(sdk).not.toContain("LoadDefaultConfig");
    expect(sdk).not.toContain("EndpointResolver");
  });
});
