export type SecurityAgentTriggerRules =
  | { readonly version: 1; readonly mode: "manual" }
  | { readonly version: 1; readonly mode: "automatic"; readonly cooldown_seconds: number } & (
    | { readonly finding: { readonly family: string; readonly minimum_severity: "low" | "medium" | "high" | "critical" } }
    | { readonly attack_path: { readonly state: "potential" | "observed" | "verified" } }
    | { readonly runtime: { readonly decision: "allow" | "monitor" | "block"; readonly action: string; readonly count: number; readonly window_seconds: number; readonly risk?: "low" | "medium" | "high" | "critical" } }
  );

const fail = (): never => { throw new TypeError("schema mismatch"); };
const levels = ["low", "medium", "high", "critical"];
function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return fail();
  const record = value as Record<string, unknown>;
  if (required.some(key => !Object.hasOwn(record, key)) || Object.keys(record).some(key => !required.includes(key) && !optional.includes(key))) fail();
  return record;
}
function integer(value: unknown, maximum: number): void { if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum) fail(); }
function text(value: unknown): asserts value is string { if (typeof value !== "string" || value.trim() !== value || !value.length || new TextEncoder().encode(value).length > 64 || /[\u0000-\u001f\u007f-\u009f]/.test(value)) fail(); }

export function decodeSecurityAgentTriggerRules(value: unknown, kind: string, source: string): SecurityAgentTriggerRules {
  const record = object(value, ["version", "mode"], ["cooldown_seconds", "finding", "attack_path", "runtime"]);
  if (record.version !== 1) fail();
  if (record.mode === "manual") { object(value, ["version", "mode"]); return value as SecurityAgentTriggerRules; }
  if (record.mode !== "automatic") fail();
  const key = kind === "runtime_decision" ? "runtime" : kind;
  object(record, ["version", "mode", "cooldown_seconds", key]);
  integer(record.cooldown_seconds, 86400);
  if (kind === "finding") {
    const rule = object(record.finding, ["family", "minimum_severity"]);
    text(rule.family); if (rule.family !== source || !levels.includes(rule.minimum_severity as string)) fail();
  } else if (kind === "attack_path") {
    const rule = object(record.attack_path, ["state"]);
    if (!["potential", "observed", "verified"].includes(rule.state as string) || rule.state !== source) fail();
  } else if (kind === "runtime_decision") {
    const rule = object(record.runtime, ["decision", "action", "count", "window_seconds"], ["risk"]);
    if (!["allow", "monitor", "block"].includes(rule.decision as string)) fail();
    text(rule.action); integer(rule.count, 100); integer(rule.window_seconds, 86400);
    if (Object.hasOwn(rule, "risk") && !levels.includes(rule.risk as string)) fail();
  } else fail();
  return value as SecurityAgentTriggerRules;
}
