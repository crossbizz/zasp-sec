import { describe, expect, it } from "vitest";

import type { InventorySummary } from "../../../apps/web/api/generated";
import { aiBillOfMaterials } from "./ai-bom";

describe("AI bill of materials", () => {
  it("lists frameworks, services and applications from discovery signals", () => {
    const agent = { id: "pid_50000001-0000-4000-8000-000000000001", name: "shop/support-bot", provider: "kubernetes", source_kind: "kubernetes_inferred_agent", observed_at: "2026-11-14T10:00:00Z", discovery: { method: "inferred", platform: "kubernetes_workload", signals: ["egress:anthropic", "env:anthropic", "package:langgraph", "manifest:mcp_config", "unknown:x", "broken"] } } as unknown as InventorySummary;
    const bom = aiBillOfMaterials(agent, new Date("2026-11-14T12:00:00Z")) as { bomFormat: string; specVersion: string; metadata: { timestamp: string; component: { name: string } }; components: { type: string; name: string; "bom-ref": string; properties: { value: string }[] }[]; dependencies: { ref: string; dependsOn: string[] }[] };
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.6");
    expect(bom.metadata.timestamp).toBe("2026-11-14T12:00:00.000Z");
    expect(bom.metadata.component.name).toBe("shop/support-bot");
    expect(bom.components.map((component) => component["bom-ref"])).toEqual(["framework:langgraph", "framework:mcp_config", "service:anthropic"]);
    // Two signals for the same service are one component with both recorded.
    expect(bom.components[2].properties.map((property) => property.value)).toEqual(["egress:anthropic", "env:anthropic"]);
    expect(bom.dependencies).toEqual([{ ref: agent.id, dependsOn: ["framework:langgraph", "framework:mcp_config", "service:anthropic"] }]);
  });

  it("is an empty component list for an agent without signals", () => {
    const agent = { id: "pid_50000001-0000-4000-8000-000000000002", name: "Declared", provider: "kubernetes", source_kind: "kubernetes_agent", observed_at: "2026-11-14T10:00:00Z", discovery: { method: "declared", platform: "kubernetes_agent", signals: [] } } as unknown as InventorySummary;
    expect((aiBillOfMaterials(agent, new Date(0)) as { components: unknown[] }).components).toEqual([]);
  });
});
