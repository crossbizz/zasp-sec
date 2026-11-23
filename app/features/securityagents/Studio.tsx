"use client";

import { useCallback, useRef, useState } from "react";
import { decodeEnvironmentAIControls, decodeQualifications } from "../../../apps/web/api/ai-controls";
import { useOptionalSession } from "../../auth/SessionProvider";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card, Field, Select } from "../../components/ui";
import { EvidenceGraph } from "../../components/EvidenceGraph";
import { requireAPIData } from "../../../apps/web/api/client";
import type { CustomSecurityAgent, CustomSecurityAgentDefinition } from "../../../apps/web/api/generated";
import { workflowIdempotencyKey } from "../workflows/api";
import { SessionInvestigation } from "./SessionInvestigation";
import "./studio.css";

type Definition = CustomSecurityAgentDefinition;
type Tool = Definition["read_tools"][number];
const labels: Record<Tool, string> = {
  list_agents: "Agent inventory", get_posture_summary: "Agent posture", inspect_session: "Session evidence", get_addon_drift: "Add-on drift",
};
const tools = Object.keys(labels) as Tool[];
const defaultDefinition: Definition = { name: "", mission: "", trigger: "manual", read_tools: ["inspect_session"], proposal: "none", require_approval: true, max_steps: 3, budget_nano_credits: 0, model_pin: "" };
const idPattern = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function decodeAgent(value: unknown): CustomSecurityAgent {
  if (!value || typeof value !== "object" || !("id" in value) || typeof value.id !== "string" || !idPattern.test(value.id) ||
    !("revision" in value) || !Number.isSafeInteger(value.revision) || !("definition" in value) || !value.definition || typeof value.definition !== "object") throw Error("Invalid definition");
  const d = value.definition as Partial<Definition>;
  if (typeof d.name !== "string" || typeof d.mission !== "string" || !["manual","finding_opened"].includes(String(d.trigger)) ||
    !Array.isArray(d.read_tools) || !d.read_tools.length || !d.read_tools.every(t => tools.includes(t)) || d.require_approval !== true ||
    !["none","propose_policy","request_containment"].includes(String(d.proposal)) || !Number.isSafeInteger(d.max_steps) ||
    !Number.isSafeInteger(d.budget_nano_credits) || typeof d.model_pin !== "string"
    || (d.approval_required_tools !== undefined && (!Array.isArray(d.approval_required_tools)
      || !d.approval_required_tools.every(tool => d.read_tools!.includes(tool))))
    || (d.minimum_evidence_confidence !== undefined && !["strong", "exact"].includes(d.minimum_evidence_confidence))) throw Error("Invalid definition settings");
  return value as CustomSecurityAgent;
}
const stageNames = { trigger: "Trigger", tools: "Read tools", approval: "Approval", bounds: "Run limits" } as const;
type Stage = keyof typeof stageNames;

function StudioEditor({ saved, canWrite, fresh, reauthenticate, onSaved, onClose }: {
  saved?: CustomSecurityAgent; canWrite: boolean; fresh: boolean; reauthenticate?: () => void; onSaved: (agent: CustomSecurityAgent) => void; onClose: () => void;
}) {
  const { client } = useAPI();
  const session = useOptionalSession();
  const canViewModels = session?.status === "authenticated" && session.hasCapability("compliance.read");
  const modelOptions = useAPIQuery("studio:qualified-models", useCallback(async (signal?: AbortSignal) => {
    const [controlsResponse, qualificationsResponse] = await Promise.all([
      client.GET("/api/v1/settings/ai-controls", { signal }),
      client.GET("/api/v1/ai/qualifications", { signal }),
    ]);
    const controls = requireAPIData(controlsResponse, decodeEnvironmentAIControls);
    const qualifications = requireAPIData(qualificationsResponse, decodeQualifications);
    if (session?.status !== "authenticated" || controls.environment_id !== session.environmentID) throw Error("Environment changed");
    return [...new Set(qualifications.items.filter(row => row.qualified && row.purpose === "security_agent_triage"
      && row.provider === controls.effective_mode && row.model === controls.tier3_model_pin).map(row => row.model))];
  }, [client, session]), Boolean(canViewModels));
  const [draft, setDraft] = useState<Definition>(saved?.definition ?? defaultDefinition);
  const [stage, setStage] = useState<Stage>("trigger");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [sessionID, setSessionID] = useState("");
  const attempt = useRef<{ body: string; key: string } | null>(null);
  const change = (patch: Partial<Definition>) => setDraft(value => ({ ...value, ...patch }));
  function toggleReadTool(tool: Tool, enabled: boolean) {
    if (enabled) { change({ read_tools: [...draft.read_tools, tool] }); return; }
    change({
      read_tools: draft.read_tools.filter(value => value !== tool),
      approval_required_tools: draft.approval_required_tools?.filter(value => value !== tool),
    });
  }
  function toggleApproval(tool: Tool, required: boolean) {
    const approvals = draft.approval_required_tools ?? [];
    change({ approval_required_tools: required ? [...approvals, tool] : approvals.filter(value => value !== tool) });
  }
  const stages = Object.entries(stageNames).map(([id, label]) => ({ id, label }));
  const valid = draft.name.trim() && draft.mission.trim() && draft.read_tools.length && draft.max_steps >= 1 && draft.max_steps <= 6 &&
    Number.isSafeInteger(draft.budget_nano_credits) && draft.budget_nano_credits >= 0 && draft.budget_nano_credits <= 1e12;
  const editable = canWrite && !busy;
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved?.definition);
  async function save() {
    if (!valid || busy || !canWrite || !fresh) return;
    setBusy(true); setError("");
    try {
      const body = { ...draft, name: draft.name.trim(), mission: draft.mission.trim(), read_tools: [...draft.read_tools].sort() };
      const serialized = JSON.stringify(body);
      if (attempt.current?.body !== serialized) attempt.current = { body: serialized, key: workflowIdempotencyKey() };
      const header = { "X-CSRF-Token": "", "X-Zasp-Fresh-Auth": "confirmed" as const, "Idempotency-Key": attempt.current.key };
      const result = saved ? await client.PUT("/api/v1/security-agents/custom/{id}", { params: { path: { id: saved.id }, header: { ...header, "If-Match": `"${saved.revision}"` } }, body })
        : await client.POST("/api/v1/security-agents/custom", { params: { header }, body });
      const agent = requireAPIData(result, decodeAgent);
      if (saved && (agent.id !== saved.id || agent.revision !== saved.revision + 1)) throw Error();
      onSaved(agent);
    } catch { setError("Could not confirm this revision. Check access and model qualification, or reopen the definition to load its current revision."); }
    finally { setBusy(false); }
  }
  return <Card title={<h2>{saved ? saved.definition.name : "New investigation workflow"}</h2>} action={<Button onClick={onClose} disabled={busy}>Close editor</Button>}>
    <fieldset disabled={!editable} className="studio-fields"><Field label="Name" maxLength={80} value={draft.name} onChange={e => change({name:e.target.value})} />
      <Field label="Mission" maxLength={512} value={draft.mission} onChange={e => change({mission:e.target.value})} /></fieldset>
    <EvidenceGraph label="Investigation workflow" nodes={stages} edges={stages.slice(1).map((s, i) => ({ source: stages[i].id, target: s.id, kind: "configured" }))} selectedID={stage} onSelect={id => setStage(id as Stage)} />
    <fieldset disabled={!editable} className="studio-fields"><legend>{stageNames[stage]}</legend>
      {stage === "trigger" && <Select label="Start this workflow" value={draft.trigger} onChange={e => change({trigger:e.target.value as Definition["trigger"]})}><option value="manual">Manually</option><option value="finding_opened">When a finding opens</option></Select>}
      {stage === "tools" && tools.map(tool => <div key={tool}>
        <label><input type="checkbox" checked={draft.read_tools.includes(tool)} onChange={event => toggleReadTool(tool, event.target.checked)} /> {labels[tool]}</label>
        {draft.read_tools.includes(tool) && <label><input type="checkbox" checked={draft.approval_required_tools?.includes(tool) ?? false} onChange={event => toggleApproval(tool, event.target.checked)} /> Require approval for {labels[tool].toLowerCase()}</label>}
      </div>)}
      {stage === "approval" && <><Select label="Proposal allowed" value={draft.proposal} onChange={e => change({proposal:e.target.value as Definition["proposal"]})}><option value="none">Read-only investigation</option><option value="propose_policy">Propose a policy</option><option value="request_containment">Request containment</option></Select><p>Each proposed change requires an authorized reviewer.</p></>}
      {stage === "bounds" && <><Select label="Minimum evidence confidence" value={draft.minimum_evidence_confidence ?? ""} onChange={event => change({ minimum_evidence_confidence: event.target.value === "" ? undefined : event.target.value as Definition["minimum_evidence_confidence"] })}>
        <option value="">Use the existing evidence policy</option><option value="strong">Strong or exact attribution</option><option value="exact">Exact attribution only</option>
        </Select><Field label="Maximum steps" type="number" min={1} max={6} value={draft.max_steps} onChange={e => change({max_steps:e.target.valueAsNumber})} />
        <Field label="Budget in nano-credits" type="number" min={0} max={1e12} value={draft.budget_nano_credits} onChange={e => change({budget_nano_credits:e.target.valueAsNumber})} />
        <Select label="Investigation model" value={draft.model_pin} onChange={e => change({ model_pin: e.target.value })}>
          <option value="">Deterministic handling</option>
          {draft.model_pin && !modelOptions.data?.includes(draft.model_pin) && <option value={draft.model_pin} disabled>{draft.model_pin} (saved pin)</option>}
          {modelOptions.data?.map(model => <option key={model} value={model}>{model}</option>)}
        </Select>
        {canViewModels && modelOptions.status === "error" && <p role="status">Could not load model qualifications. <Button onClick={() => void modelOptions.retry()}>Retry</Button></p>}</>}
    </fieldset>
    {error && <p role="alert">{error}</p>}
    {canWrite && (fresh ? <Button variant="primary" disabled={!valid || busy || !dirty} onClick={() => void save()}>{busy ? "Saving…" : "Save revision"}</Button> : <Button onClick={reauthenticate}>Reauthenticate to save</Button>)}
    {saved && saved.definition.trigger === "manual" && saved.definition.read_tools.includes("inspect_session") && <div className="studio-run">
      <Field label="Runtime session ID" value={sessionID} onChange={e => setSessionID(e.target.value)} hint="Use the ID shown in a runtime session’s detail page." />
      {idPattern.test(sessionID) && <SessionInvestigation sessionID={sessionID} studio={{ id: saved.id, revision: saved.revision }} />}
    </div>}
  </Card>;
}
export function SecurityAgentStudio({ canWrite, fresh, reauthenticate }: { canWrite: boolean; fresh: boolean; reauthenticate?: () => void }) {
  const { client } = useAPI();
  const [cursor, setCursor] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const list = useAPIQuery("studio:list:"+(cursor ?? ""), useCallback(async (signal?: AbortSignal) =>
    requireAPIData(await client.GET("/api/v1/security-agents/custom", { params: { query: { limit: 25, cursor: cursor ?? undefined } }, signal }), value => {
      if (!value || typeof value !== "object" || !("items" in value) || !Array.isArray(value.items) || !("next_cursor" in value) || (value.next_cursor !== null && typeof value.next_cursor !== "string")) throw Error("Invalid workflow page");
      return { items: value.items.map(decodeAgent), next: value.next_cursor };
    }), [cursor, client]));
  const detail = useAPIQuery("studio:definition:"+selected, useCallback(async (signal?: AbortSignal) =>
    requireAPIData(await client.GET("/api/v1/security-agents/custom/{id}", { params: { path: {id: selected ?? ""} }, signal }), value => {
      const agent=decodeAgent(value); if (agent.id !== selected) throw Error("Wrong definition"); return agent;
    }), [client,selected]), !!selected && selected !== "new");
  return <div className="studio"><Card title={<h2>Investigation workflows</h2>} action={canWrite && <Button onClick={() => {setNotice("");setSelected("new");}}>New workflow</Button>}>
    {notice && <p role="status">{notice}</p>}
    {list.data ? <>{list.data.items.length ? <ul>{list.data.items.map(a => <li key={a.id}><button className="row-title" onClick={() => {setNotice("");setSelected(a.id);}}>{a.definition.name}</button> · Revision {a.revision}</li>)}</ul> : <p>No investigation workflows in this environment.</p>}
      {(cursor || list.data.next) && <div className="row-actions"><Button disabled={!cursor} onClick={() => setCursor(null)}>First page</Button><Button disabled={!list.data.next} onClick={() => setCursor(list.data?.next ?? null)}>Next page</Button></div>}</>
      : list.status === "loading" ? <p role="status">Loading workflows…</p> : <p role="status">Workflows are unavailable. <Button onClick={() => void list.retry()}>Retry</Button></p>}
  </Card>
  {selected && (selected === "new" || detail.data ? <StudioEditor key={selected + "/" + detail.data?.revision} saved={selected === "new" ? undefined : detail.data} canWrite={canWrite} fresh={fresh} reauthenticate={reauthenticate} onClose={() => setSelected(null)} onSaved={a => {setNotice("Saved revision "+a.revision+" of "+a.definition.name+".");setSelected(null);void list.retry();}} />
    : <p role="status">{detail.status === "loading" ? "Loading definition…" : "Definition is unavailable."}</p>)}
  </div>;
}
