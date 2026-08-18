import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M3 UI/E2E and M4 reconciliation completion batch", () => {
  it("binds the selected tasks to reviewed product boundaries", () => {
    const connector = read("app/features/connectors/ConnectorViews.tsx");
    const sensor = read("app/features/sensors/SensorView.tsx");
    for (const value of ["Connected integrations", "Collected data", "Sync history", "Sync now", "Delete connection"]) expect(connector).toContain(value);
    for (const value of ["Enroll sensor", "Rotate enrollment token", "Delete sensor", "Coverage"]) expect(sensor).toContain(value);
    const reconciliation = read("services/platform/reconciliation/reconciliation.go") + read("services/platform/reconciliation/http.go");
    expect(reconciliation).toContain(") Reconcile(");
    const openapi = read("openapi/openapi.yaml");
    for (const operation of ["listAgents", "getAgent", "updateAgent", "getAgentCapabilities", "getAgentRelationships", "listAgentSessions", "listTools", "getTool"]) expect(openapi).toContain(`operationId: ${operation}`);
  });

  it("completes exactly 25 locally verified tasks while the M3 gate stays active", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] || "";
    expect(active.match(/^\| M3-52 \|/gm)).toHaveLength(1);
    const selected = ["M3-48", "M3-49", "M3-50", "M3-51", "M3-52a", "M3-52b", "M3-52c", "M3-52d", "M3-52e", "M4-01a", "M4-01b", "M4-01c", "M4-01d", "M4-01e", "M4-01f", "M4-01", "M4-02", "M4-03", "M4-04", "M4-05", "M4-06", "M4-07", "M4-08", "M4-09", "M4-10"];
    for (const id of selected) expect(complete.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 168 |", "| Complete | 557 |", "`0/168/557/3`", "| M3 | 75 | 0 | 2 | 73 | 0 |", "| M4 | 82 | 0 | 0 | 82 | 0 |"]) expect(tracker).toContain(value);
  });
});
