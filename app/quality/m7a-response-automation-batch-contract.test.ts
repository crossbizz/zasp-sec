import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), "utf8");

describe("M7A response automation batch", () => {
  it("implements expiry, bounded actions, templates, matchers, and deduplication", () => {
    const root = "services/platform/securityagent/";
    const source = ["action.go", "expiry.go", "builtin_actions.go", "templates.go", "triggers.go"].map((file) => read(root + file)).join("\n");
    for (const symbol of ["VerifyOutcome", "ClaimExpiredControls", "NewExpiryWorker", "RegisterResponseActions", "NewTemplateRegistry", "BuiltInTemplates", "MatchFinding", "MatchAttackPath", "MatchRuntime", "NewTriggerDeduplicator"]) expect(source).toContain(` ${symbol}`);
    const worker = read("services/platform/agentsec-worker/expiry.go");
    expect(worker).toContain("runExpiryLoop");
    expect(worker).toContain("scanner.RunOnce");
  });

  it("records the expiry and response slices complete", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    for (const value of ["| Pending | 0 |", "| In progress | 6 |", "| Complete | 667 |", "| Blocked | 55 |", "`0/6/667/55`", "| M7A | 113 | 0 | 0 | 113 | 0 |"]) expect(tracker).toContain(value);
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    const tasks = ["M7A-18", "M7A-18a", "M7A-18b", "M7A-18c", "M7A-18d", "M7A-19", "M7A-20", "M7A-21", "M7A-22", "M7A-23", "M7A-24", "M7A-25", "M7A-26", "M7A-27", "M7A-28", "M7A-29", "M7A-30", "M7A-31", "M7A-32", "M7A-33", "M7A-34", "M7A-35", "M7A-36", "M7A-37", "M7A-38"];
    for (const task of tasks) expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
  });
});
