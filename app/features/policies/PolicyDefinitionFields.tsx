"use client";

import type { Policy } from "../../../apps/web/api/generated";
import { Button, Field, Select } from "../../components/ui";

export type PolicyDefinition = Pick<Policy, "trigger" | "conditions" | "action" | "failure_mode">;
export const defaultPolicyDefinition: PolicyDefinition = {
  trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }],
  action: "monitor", failure_mode: "open",
};
const triggers = ["tool", "runtime", "network", "file", "credential"] as const;
const fields = ["action", "resource", "principal_id", "agent_id", "session_id", "environment_id"] as const;
const toolOrigins = ["platform", "application", "third_party", "client", "mixed", "unknown"] as const;

export function validDefinition(value: PolicyDefinition): boolean {
  return value.conditions.length > 0 && value.conditions.length <= 32 &&
    value.conditions.every(condition => condition.operator === "equals" && condition.value.trim().length > 0 &&
      condition.value === condition.value.trim() && !/[\r\n]/.test(condition.value) && !condition.value.includes(String.fromCharCode(0)) && new TextEncoder().encode(condition.value).length <= 256);
}

export function PolicyDefinitionFields({ value, onChange, disabled, label, templates = false }: {
  value: PolicyDefinition; onChange(value: PolicyDefinition): void; disabled: boolean; label: string; templates?: boolean;
}) {
  const change = (patch: Partial<PolicyDefinition>) => onChange({ trigger: value.trigger, conditions: value.conditions, action: value.action, failure_mode: value.failure_mode, ...patch });
  const setCondition = (index: number, patch: Partial<Policy["conditions"][number]>) =>
    change({ conditions: value.conditions.map((condition, i) => i === index ? { ...condition, ...patch } : condition) });
  function selectTemplate(template: string) {
    if (template === "prompt") {
      change({ trigger: "runtime", conditions: [{ field: "action", operator: "equals", value: "claude.prompt" }] });
    } else if (template === "tool" || toolOrigins.some(origin => template === origin)) {
      const conditions = [{ field: "action", operator: "equals" as const, value: "claude.tool_frame" }];
      if (template !== "tool") conditions.push({ field: "resource", operator: "equals", value: `claude.tool_frame.${template}` });
      change({ trigger: "tool", conditions });
    }
  }

  return <fieldset disabled={disabled}><legend>{label} match and action</legend>
    {templates && <Select label="Fill conditions from a provider template" value="" onChange={event => selectTemplate(event.target.value)}>
      <option value="">Choose a template</option>
      <option value="prompt">Claude Enterprise · prompt</option><option value="tool">Claude Enterprise · any tool frame</option>
      {toolOrigins.map(origin => <option key={origin} value={origin}>Claude Enterprise · {origin.replace("_", " ")} tools</option>)}
    </Select>}
    <Select label={label + " trigger"} value={value.trigger} onChange={event => change({ trigger: event.target.value })}>
      {triggers.map(trigger => <option key={trigger}>{trigger}</option>)}
    </Select>
    <p>All conditions must match.</p>
    {value.conditions.map((condition, index) => <div className="form-grid" key={index}>
      <Select label={`${label} condition ${index + 1} field`} value={condition.field} onChange={event => setCondition(index, { field: event.target.value })}>
        {fields.map(field => <option key={field}>{field}</option>)}
      </Select>
      <Field label={`${label} condition ${index + 1} equals`} value={condition.value} maxLength={256}
        onChange={event => setCondition(index, { value: event.target.value })} />
      {value.conditions.length > 1 && <Button aria-label={`Remove ${label.toLowerCase()} condition ${index + 1}`} onClick={() => change({ conditions: value.conditions.filter((_, i) => i !== index) })}>Remove condition</Button>}
    </div>)}
    <Button disabled={value.conditions.length >= 32} onClick={() => change({ conditions: [...value.conditions, { field: "resource", operator: "equals", value: "" }] })}>Add {label.toLowerCase()} condition</Button>
    <Select label={label + " action"} value={value.action} onChange={event => change({ action: event.target.value as Policy["action"] })}>
      <option value="monitor">Monitor match</option><option value="block">Block when enforced</option>
    </Select>
    <Select label={label + " failure mode"} value={value.failure_mode} onChange={event => change({ failure_mode: event.target.value as Policy["failure_mode"] })}>
      <option value="open">Open</option><option value="closed">Closed</option>
    </Select>
  </fieldset>;
}
