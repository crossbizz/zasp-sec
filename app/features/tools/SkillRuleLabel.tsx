import type { components } from "../../../apps/web/api/generated";

type Rule = components["schemas"]["AddonFindingCount"]["rule_id"];

const labels = {
  "dependency.unpinned": "Dependency version is unpinned",
  "instruction.hidden_text": "Instructions contain hidden text or markup",
  "instruction.override": "Instructions contain an override directive",
  "mcp.remote_endpoint": "MCP configuration references a remote service",
  "mcp.unpinned_exec": "MCP launcher or connection needs review",
  "mcp.unpinned_launcher": "MCP package launcher has no pinned version",
  "script.credential_path_access": "Script references a credential location",
  "script.network_access": "Script references a network client",
  "script.remote_exec_pipe": "Script passes downloaded or decoded data to an interpreter",
  "script.shell_execution": "Script references a process execution API",
} satisfies Record<Rule, string>;

export function SkillRuleLabel({ rule }: { rule: string }) {
  return <>{Object.hasOwn(labels, rule) && <span>{labels[rule as Rule]} </span>}<code>{rule}</code></>;
}
