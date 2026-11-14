import type { InventorySummary } from "../../../apps/web/api/generated";

// An AI bill of materials for one discovered agent, in CycloneDX 1.6 JSON.
// It is built from the agent's discovery signals, which name what the agent
// is made of and what it calls (frameworks, model services, MCP servers).
// The signals are catalog tokens, so the document has no versions: discovery
// does not record them. It lists what was observed, not everything the agent
// contains.

type Component = Readonly<{ type: "framework" | "service" | "application"; name: string; "bom-ref": string; description: string; properties: readonly Readonly<{ name: string; value: string }>[] }>;

const signalClasses: Readonly<Record<string, Readonly<{ type: Component["type"]; description: string }>>> = {
  package: { type: "framework", description: "Declared as a package dependency" },
  image: { type: "framework", description: "Named by the container image" },
  process: { type: "framework", description: "Named by the container command" },
  manifest: { type: "framework", description: "Declared by a manifest file in the repository" },
  port: { type: "framework", description: "Suggested by a default listening port" },
  env: { type: "service", description: "Credential or endpoint configured by environment variable name" },
  iam: { type: "service", description: "Invocation allowed by the execution role's policy" },
  invoke: { type: "service", description: "Invocation recorded in the provider's audit log" },
  egress: { type: "service", description: "Service the workload resolved and connected to at run time" },
  app: { type: "application", description: "Third-party AI application connected to the tenant" },
};

export function aiBillOfMaterials(agent: InventorySummary, generatedAt: Date): Readonly<Record<string, unknown>> {
  const components = new Map<string, Component>();
  for (const signal of agent.discovery.signals) {
    const separator = signal.indexOf(":");
    const signalClass = signal.slice(0, separator), token = signal.slice(separator + 1);
    const known = separator > 0 && Object.hasOwn(signalClasses, signalClass) ? signalClasses[signalClass] : undefined;
    if (!known || token === "") continue;
    const reference = `${known.type}:${token}`;
    const prior = components.get(reference);
    const properties = [...(prior?.properties ?? []), { name: "zasp:signal", value: signal }];
    components.set(reference, { type: known.type, name: token, "bom-ref": reference, description: prior ? prior.description : known.description, properties });
  }
  const list = [...components.values()].sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"]));
  return {
    bomFormat: "CycloneDX", specVersion: "1.6", version: 1,
    metadata: {
      timestamp: generatedAt.toISOString(),
      component: { type: "application", name: agent.name, "bom-ref": agent.id },
      properties: [
        { name: "zasp:provider", value: agent.provider }, { name: "zasp:source_kind", value: agent.source_kind },
        { name: "zasp:discovery_method", value: agent.discovery.method }, { name: "zasp:observed_at", value: agent.observed_at },
        { name: "zasp:completeness", value: "observed signals only; versions are not recorded" },
      ],
    },
    components: list,
    dependencies: [{ ref: agent.id, dependsOn: list.map((component) => component["bom-ref"]) }],
  };
}
