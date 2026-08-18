import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(resolve(process.cwd(), path), "utf8");

const completedTasks = [
  "M2-08", "M2-09", "M2-10", "M2-11", "M2-12", "M2-13", "M2-14", "M2-15", "M2-16", "M2-17", "M2-18", "M2-19",
  "M2-20", "M2-21", "M2-22", "M2-23", "M2-24", "M2-25", "M2-26", "M2-27", "M2-28", "M2-29", "M2-30",
];

describe("M2 identity and administration API batch", () => {
  it("moves exactly the 23 implemented tasks to Complete with truthful arithmetic", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const section = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    const complete = section.split("\n")
      .filter((line) => /^\| M[^ |]+ \|/.test(line))
      .map((line) => line.split("|")[1].trim());

    expect(tracker).toContain("| Pending | 517 |");
    expect(tracker).toContain("| In progress | 24 |");
    expect(tracker).toContain("| Complete | 184 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("| M2 | 72 | 0 | 0 | 72 | 0 |");
    expect(tracker).toContain("`517/24/184/3`");
    expect(complete).toHaveLength(184);
    expect(new Set(complete).size).toBe(184);
    for (const task of completedTasks) expect(complete).toContain(task);
  });

  it("binds every public operation, provider service, webhook, and deprovision boundary", () => {
    const openapi = read("openapi/openapi.yaml");
    const handler = read("services/platform/identity/http.go");
    const connections = read("services/platform/identity/connections.go");
    const webhook = read("services/platform/identity/webhook.go");
    for (const operation of [
      "getOrganization", "listWorkspaces", "createWorkspace", "getWorkspace", "updateWorkspace", "listEnvironments", "createEnvironment",
      "getEnvironment", "updateEnvironment", "getCurrentPrincipal", "listMembers", "listBuiltInRoles", "listSSOConnections", "createSSOConnection",
      "deleteSSOConnection", "testSSOConnection", "listSCIMConnections", "createSCIMConnection", "deleteSCIMConnection",
    ]) expect(openapi).toContain(`operationId: ${operation}`);
    expect(handler).toContain("WithConnectionService");
    expect(connections).toContain("type ConnectionService struct");
    expect(webhook).toContain("Svix-Signature");
    expect(webhook).toContain("deprovisionMember");
  });

  it("preserves this batch inside the current M2 completion boundary", () => {
    const readme = read("README.md");
    expect(readme).toContain("M2-01 through M2-50 and the M2-47 gate are Complete");
    expect(readme).toContain("M3-01 through M3-13 are Complete");
  });
});
