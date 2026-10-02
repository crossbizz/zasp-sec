import { Field, Select } from "../../components/ui";
import { decodeSecurityAgentTriggerRules, type SecurityAgentTriggerRules } from "../../../apps/web/api/security-agent-trigger-rules";

export type TriggerRuleDraft = { mode: string; family: string; severity: string; state: string; decision: string; action: string; risk: string; count: string; window: string; cooldown: string };
export function triggerRuleDraft(source: string, rules?: SecurityAgentTriggerRules): TriggerRuleDraft {
  const automatic = rules?.mode === "automatic" ? rules : undefined;
  const finding = automatic && "finding" in automatic ? automatic.finding : undefined;
  const path = automatic && "attack_path" in automatic ? automatic.attack_path : undefined;
  const runtime = automatic && "runtime" in automatic ? automatic.runtime : undefined;
  return { mode: rules?.mode ?? "legacy", family: finding?.family ?? source, severity: finding?.minimum_severity ?? "low", state: path?.state ?? "verified", decision: runtime?.decision ?? "block", action: runtime?.action ?? "http_request", risk: runtime?.risk ?? "", count: String(runtime?.count ?? 1), window: String(runtime?.window_seconds ?? 300), cooldown: String(automatic?.cooldown_seconds ?? 600) };
}
export function triggerRuleSource(draft: TriggerRuleDraft, kind: string, legacy: string): string {
  if (draft.mode !== "automatic") return legacy;
  return kind === "finding" ? draft.family : kind === "attack_path" ? draft.state : legacy;
}
export function triggerRuleValue(draft: TriggerRuleDraft, kind: string, source: string): SecurityAgentTriggerRules | null | undefined {
  if (draft.mode === "legacy") return undefined;
  const value = draft.mode === "manual" ? { version: 1, mode: "manual" } : {
    version: 1, mode: "automatic", cooldown_seconds: Number(draft.cooldown),
    ...(kind === "finding" ? { finding: { family: draft.family, minimum_severity: draft.severity } } : kind === "attack_path" ? { attack_path: { state: draft.state } } : { runtime: { decision: draft.decision, action: draft.action, count: Number(draft.count), window_seconds: Number(draft.window), ...(draft.risk ? { risk: draft.risk } : {}) } }),
  };
  try { return decodeSecurityAgentTriggerRules(value, kind, source); } catch { return null; }
}
export function TriggerRuleFields({ value, kind, disabled, onChange }: { value: TriggerRuleDraft; kind: string; disabled: boolean; onChange(value: TriggerRuleDraft): void }) {
  const set = (key: keyof TriggerRuleDraft, next: string) => onChange({ ...value, [key]: next });
  return <section aria-label="Trigger rules">
    <Select label="Trigger mode" value={value.mode} disabled={disabled} onChange={event => set("mode", event.target.value)}><option value="legacy">Existing template behavior</option><option value="manual">Manual only</option><option value="automatic">Configured automatic trigger</option></Select>
    {value.mode === "manual" && <p>Automatic sources cannot start this responder. Authorized manual runs remain available.</p>}
    {value.mode === "automatic" && <>
      {kind === "finding" && <><Field label="Finding family" value={value.family} disabled={disabled} maxLength={64} onChange={event => set("family", event.target.value)} /><Select label="Minimum finding severity" value={value.severity} disabled={disabled} onChange={event => set("severity", event.target.value)}>{["low", "medium", "high", "critical"].map(level => <option key={level}>{level}</option>)}</Select></>}
      {kind === "attack_path" && <Select label="Path evidence state" value={value.state} disabled={disabled} onChange={event => set("state", event.target.value)}>{["potential", "observed", "verified"].map(state => <option key={state}>{state}</option>)}</Select>}
      {kind === "runtime_decision" && <><Select label="Runtime decision" value={value.decision} disabled={disabled} onChange={event => set("decision", event.target.value)}>{["allow", "monitor", "block"].map(decision => <option key={decision}>{decision}</option>)}</Select><Field label="Evaluated action" value={value.action} maxLength={64} disabled={disabled} onChange={event => set("action", event.target.value)} /><Select label="Policy risk" value={value.risk} disabled={disabled} onChange={event => set("risk", event.target.value)}><option value="">Any risk, including unknown</option>{["low", "medium", "high", "critical"].map(level => <option key={level}>{level}</option>)}</Select><Field label="Distinct decision count" type="number" min={1} max={100} value={value.count} disabled={disabled} onChange={event => set("count", event.target.value)} /><Field label="Decision window seconds" type="number" min={1} max={86400} value={value.window} disabled={disabled} onChange={event => set("window", event.target.value)} /></>}
      <Field label="Trigger cooldown seconds" type="number" min={1} max={86400} value={value.cooldown} disabled={disabled} onChange={event => set("cooldown", event.target.value)} />
      <p>Rules take effect after validation and activation. Unsupported action and source combinations are rejected before activation.</p>
    </>}
  </section>;
}
