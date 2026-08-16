import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type PackageManifest = { scripts?: Record<string, string> };
const repositoryRoot = process.cwd();
const proofDirectory = "proofs/localstack-iam-compat";

describe("provisional LocalStack IAM compatibility proof repository contract", () => {
  it("keeps the exact Go, SDK, and LocalStack image pins", async () => {
    const [goModule, runner] = await Promise.all([
      readFile(resolve(repositoryRoot, proofDirectory, "go.mod"), "utf8"),
      readFile(resolve(repositoryRoot, proofDirectory, "run.mjs"), "utf8"),
    ]);
    expect(goModule).toMatch(/^go 1\.25\.0$/m);
    expect(goModule).toMatch(/^toolchain go1\.26\.5$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2 v1\.43\.5$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2\/service\/iam v1\.59\.0$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/aws-sdk-go-v2\/service\/sts v1\.45\.5$/m);
    expect(goModule).toMatch(/^\s*github\.com\/aws\/smithy-go v1\.27\.7$/m);
    expect(runner).toContain("localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c");
  });

  it("keeps IAM and STS enforcement and root commands free of dotenv input", async () => {
    const [manifestText, runner] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, proofDirectory, "run.mjs"), "utf8"),
    ]);
    const manifest = JSON.parse(manifestText) as PackageManifest;
    expect(manifest.scripts?.["proof:localstack:iam:test"]).toBe(
      `cd ${proofDirectory} && go test -race -count=1 ./... && node --test run.test.mjs`,
    );
    expect(manifest.scripts?.["proof:localstack:iam:run"]).toBe(`node ${proofDirectory}/run.mjs`);
    expect(manifest.scripts?.["proof:localstack:iam:run"]).not.toMatch(/env-file|source|\.\s+\.env/);
    expect(runner).toContain('"SERVICES=iam,sts"');
    expect(runner).toContain('"ENFORCE_IAM=1"');
  });

  it("documents the executable provisional boundary and leaves real AWS work incomplete", async () => {
    const [readme, tracker, plan, cli] = await Promise.all([
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-13-localstack-iam-provisional-implementation-plan.md"), "utf8"),
      readFile(resolve(repositoryRoot, proofDirectory, "main.go"), "utf8"),
    ]);
    const section = readme.match(/## Provisional LocalStack IAM compatibility proof[\s\S]*?```bash\n([\s\S]*?)\n```/);
    expect(section?.[1]?.split("\n")).toEqual([
      "npm run proof:localstack:iam:test",
      "npm run proof:localstack:iam:run",
    ]);
    expect(readme).toContain("Docker and Go are required");
    expect(readme).toContain("No credentials are accepted");
    expect(readme).toContain("IAM enforcement is mandatory");
    expect(readme).toContain("emulator namespaces");
    expect(readme).toContain("not real-AWS parity");
    expect(readme).toContain("PROV-01 cannot complete M0-09 or R-03");
    expect(readme).toContain("PROV-01 is Blocked on LocalStack 4.7.0");
    expect(readme).toContain("M0-10 is Complete under the Cartography delivery waiver");
    expect(cli).toContain("LocalStack IAM compatibility proof passed: namespaces=true assumed=true allowed_read=true explicit_deny=true cleanup=true audit=true container_cleanup=true.");
    expect(tracker).toContain("| PROV-01 | Blocked |");
    expect(tracker).toContain("Exact-pinned LocalStack 4.7.0 does not forward SourceIdentity");
    expect(tracker).toMatch(/Official LocalStack\s+v4\.14\.0 source retains the same unsupported forwarding path; this was source\s+review only, not live testing\./);
    expect(tracker).toContain("| Pending | 663 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 62 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("| M0-09 | August 13, 2026 |");
    expect(tracker).toContain("| M0-14a | August 14, 2026 |");
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toMatch(/\| M0-10 \| August 14, 2026 \|/);
    expect(plan).toContain("mark PROV-01 Blocked");
    expect(plan).not.toContain("mark PROV-01 Complete");
  });
});
