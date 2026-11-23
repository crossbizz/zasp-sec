"use client";

import { useEffect, useRef, useState } from "react";
import { APIProductError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { Button, Card, Field } from "../../components/ui";

const types = {
  mcp_tool_policy: "MCP tool",
  destination_domain_policy: "Destination domain",
  shell_command_policy: "Shell command",
  file_path_policy: "Sensitive file",
} as const;
const shell = ["shell_pipe", "secret_transfer", "reverse_shell", "privileged_mode", "encoded_execution"];
const files = ["ssh", "aws", "gcloud", "dotenv", "pem", "identity_key"];
const cohortID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ruleID = /^[a-z][a-z0-9._-]{0,63}$/;
const mcp = /^mcp__[A-Za-z0-9_-]{1,64}__(?:[A-Za-z0-9_-]{1,80}|\*)$/;
const hostLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
type Kind = keyof typeof types;
type Mode = "monitor" | "enforce";
type Failure = "open" | "closed";
type Match = "allowlist" | "denylist";
type Rule = { id: string; type: Kind; match?: Match; values: string[]; allowed_destinations?: string[] };
type Template = { cohort: string; revision: number; mode: Mode; failure_mode: Failure; rules: Rule[] };
type DraftRule = { key: number; id: string; type: Kind; match: Match; values: string; destinations: string };

function host(value: string) {
  const hostname = value.replace(/^\*\./, "");
  return value.length <= 253 && (!value.startsWith("*.") || hostname.includes(".")) && hostname.split(".").every(part => hostLabel.test(part));
}

function split(value: string) { return value.split(/[\s,]+/).filter(Boolean); }
function list(values: string[], ok: (value: string) => boolean) {
  return values.length > 0 && values.length <= 32 && new Set(values).size === values.length && values.every(ok);
}
function supportedRule(input: Rule) {
  if (!input || typeof input.id !== "string" || !ruleID.test(input.id) || !Object.hasOwn(types, input.type) || !Array.isArray(input.values) ||
      !input.values.every(v => typeof v === "string") || (input.type !== "mcp_tool_policy" && input.allowed_destinations !== undefined)) return false;
  if (input.type === "mcp_tool_policy" || input.type === "destination_domain_policy") {
    if (input.match !== "allowlist" && input.match !== "denylist") return false;
    return input.type === "destination_domain_policy" ? list(input.values, host) :
      list(input.values, v => mcp.test(v)) && (input.allowed_destinations === undefined ||
        Array.isArray(input.allowed_destinations) && list(input.allowed_destinations, v => typeof v === "string" && host(v)));
  }
  return input.match === undefined && list(input.values, v => (input.type === "shell_command_policy" ? shell : files).includes(v));
}
function readTemplate(value: unknown, cohort: string): Template {
  const t = value as Template;
  if (!t || t.cohort !== cohort || !Number.isSafeInteger(t.revision) || t.revision < 0 ||
      !["monitor", "enforce"].includes(t.mode) || !["open", "closed"].includes(t.failure_mode) || !Array.isArray(t.rules) ||
      t.rules.length > 32 || !t.rules.every(supportedRule) || new Set(t.rules.map(r => r.id)).size !== t.rules.length ||
      (t.revision === 0 ? t.rules.length !== 0 || t.mode !== "monitor" || t.failure_mode !== "open" : t.rules.length === 0)) throw Error("Invalid policy template");
  return t;
}
function ruleDraft(rule: Rule, key: number): DraftRule {
  return { key, id: rule.id, type: rule.type, match: rule.match ?? "denylist", values: rule.values.join("\n"), destinations: rule.allowed_destinations?.join("\n") ?? "" };
}
function fromDraft(d: DraftRule): Rule {
  const listRule = d.type === "mcp_tool_policy" || d.type === "destination_domain_policy";
  return { id: d.id, type: d.type, values: split(d.values), ...(listRule ? { match: d.match } : {}),
    ...(d.type === "mcp_tool_policy" && d.destinations.trim() ? { allowed_destinations: split(d.destinations) } : {}) };
}

export function EndpointPolicyCohort({ client, canManage, fresh, reauthenticate }: {
  client: APIClient; canManage: boolean; fresh: boolean; reauthenticate(): void;
}) {
  const [cohort, setCohort] = useState(""), [view, setView] = useState<Template>();
  const [notice, setNotice] = useState(""), [busy, setBusy] = useState(false);
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  const load = async () => {
    if (active.current || !cohortID.test(cohort)) return;
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setNotice(""); setView(undefined);
    try {
      const result = requireAPIData(await client.GET("/api/v1/device-cohorts/{cohort}/pretool-policy", { signal: controller.signal, params: { path: { cohort } } }), v => readTemplate(v,cohort));
      if (!controller.signal.aborted) setView(result);
    } catch { if (!controller.signal.aborted) setNotice("Template unavailable. Check your scope and permissions, then reload."); }
    finally { if (!controller.signal.aborted) { setBusy(false); active.current = null; } }
  };
  return <Card title="Endpoint policy template">
    <p>Prepare pre-tool rules for a managed cohort. Each device needs its own signed policy and acknowledgment.</p>
    <form className="framework-control-filter" onSubmit={e => { e.preventDefault(); void load(); }}>
      <Field label="Endpoint policy cohort" value={cohort} maxLength={64} disabled={busy} onChange={e => { setCohort(e.target.value); setView(undefined); setNotice(""); }} />
      <Button type="submit" disabled={busy || !cohortID.test(cohort)}>Load template</Button>
    </form>
    {notice && <p role="alert">{notice}</p>}
    {view && <RuleEditor key={view.cohort + "/" + view.revision} client={client} view={view} canManage={canManage} fresh={fresh} reauthenticate={reauthenticate} onSaved={next => {
      setView(next); setNotice("Template saved. Issue the signed revision separately to each intended device.");
    }} />}
  </Card>;
}

function RuleEditor({ client, view, canManage, fresh, reauthenticate, onSaved }: {
  client: APIClient; view: Template; canManage: boolean; fresh: boolean; reauthenticate(): void; onSaved(next: Template): void;
}) {
  const [mode, setMode] = useState(view.mode), [failure, setFailure] = useState(view.failure_mode);
  const [rules, setRules] = useState(() => view.rules.map(ruleDraft)), [notice,setNotice] = useState("");
  const sequence = useRef(rules.length), active = useRef<AbortController | null>(null);
  const retry = useRef<{ body: string; key: string } | null>(null);
  const [busy,setBusy] = useState(false), [conflict,setConflict] = useState(false);
  useEffect(() => () => active.current?.abort(), []);
  function change(key: number, patch: Partial<DraftRule>) {
    setRules(old => old.map(rule => rule.key === key ? { ...rule,...patch } : rule));
  }
  const outgoing = rules.map(fromDraft);
  const valid = outgoing.length > 0 && outgoing.length <= 32 && outgoing.every(supportedRule) && new Set(outgoing.map(r => r.id)).size === outgoing.length;
  const save = async () => {
    if (!valid || !canManage || !fresh || conflict || active.current) return;
    const body = { expected_revision:view.revision,mode,failure_mode:failure,rules:outgoing };
    const encoded = JSON.stringify(body);
    if (!retry.current || retry.current.body !== encoded) retry.current = { body:encoded,key:"endpoint-template-"+crypto.randomUUID() };
    const controller = new AbortController(); active.current=controller;
    setBusy(true); setNotice("");
    try {
      const result = requireAPIData(await client.PUT("/api/v1/device-cohorts/{cohort}/pretool-policy", { signal:controller.signal, params:{ path:{cohort:view.cohort},header:{"X-CSRF-Token":"","Idempotency-Key":retry.current.key} },body }), v => readTemplate(v,view.cohort));
      if (result.revision <= view.revision) throw Error("Invalid revision");
      if (!controller.signal.aborted) onSaved(result);
    } catch (error) {
      if (controller.signal.aborted) return;
      if (error instanceof APIProductError && [409,412].includes(error.status)) {
        setConflict(true); setNotice("Template revision changed. Load the latest template before editing it again.");
      } else { setNotice("Save could not be confirmed. Retry this template or load the latest revision."); }
    } finally { if (!controller.signal.aborted) {setBusy(false);active.current=null;} }
  };
  return <section aria-label="Cohort template rules">
    <p>{view.revision === 0 ? "No saved template." : "Saved template revision "+view.revision+"."}</p>
    {view.revision > 0 && <details><summary>Issue this template to a device</summary>
      <p>On the authorized issuer, use the endpoint policy signer with the saved rules and the enrolled device binding. Open the intended device in <strong>Devices</strong>, choose <strong>Publish signed policy</strong>, and select its signed envelope. In Devices, compare the assigned and reported revisions to confirm acknowledgment.</p>
    </details>}
    <fieldset disabled={!canManage || busy || conflict}><legend>Pre-tool policy</legend>
      <div className="form-grid">
        <label className="field">Policy mode <select value={mode} onChange={e => setMode(e.target.value as Mode)}><option value="monitor">Monitor</option><option value="enforce">Enforce</option></select></label>
        <label className="field">Adapter failure <select value={failure} onChange={e => setFailure(e.target.value as Failure)}><option value="open">Allow and record the gap</option><option value="closed">Stop the governed action</option></select></label>
      </div>
      {rules.map((r, index) => <fieldset key={r.key}><legend>Rule {index+1}</legend>
        <div className="form-grid"><Field label="Rule ID" value={r.id} maxLength={64} onChange={e => change(r.key,{id:e.target.value})} />
          <label className="field">Rule type <select value={r.type} onChange={e => change(r.key,{type:e.target.value as Kind,values:"",destinations:""})}>
            {Object.entries(types).map(([id,name]) => <option key={id} value={id}>{name}</option>)}</select></label></div>
        {["mcp_tool_policy","destination_domain_policy"].includes(r.type) ? <>
          <label className="field">Match <select value={r.match} onChange={e => change(r.key,{match:e.target.value as Match})}><option value="denylist">Deny listed values</option><option value="allowlist">Allow only listed values</option></select></label>
          <label className="field">{r.type === "mcp_tool_policy" ? "Tool names" : "Destination domains"} <textarea value={r.values} rows={2} maxLength={8192} placeholder={r.type === "mcp_tool_policy" ? "mcp__support__create_ticket" : "support.example.com"} onChange={e => change(r.key,{values:e.target.value})}/></label>
          {r.type === "mcp_tool_policy" && <label className="field">Allowed destinations (optional) <textarea value={r.destinations} rows={2} maxLength={8192} onChange={e => change(r.key,{destinations:e.target.value})}/></label>}
        </> : <fieldset><legend>Classifications</legend>{(r.type === "shell_command_policy" ? shell : files).map(v => <label key={v}><input type="checkbox" checked={split(r.values).includes(v)} onChange={e => {
          const values = new Set(split(r.values)); if(e.target.checked) values.add(v);else values.delete(v);
          change(r.key,{values:[...values].join("\n")});
        }}/> {v.replaceAll("_"," ")} </label>)}</fieldset>}
        {canManage && <Button type="button" onClick={() => setRules(old => old.filter(rule => rule.key !== r.key))}>Remove rule {index+1}</Button>}
      </fieldset>)}
      {canManage && <Button disabled={rules.length>=32} onClick={() => setRules([...rules,ruleDraft({id:"",type:"mcp_tool_policy",match:"denylist",values:[]},sequence.current++)])}>Add rule</Button>}
    </fieldset>
    {!fresh && canManage && <p>Fresh authentication required to save. <Button onClick={reauthenticate}>Reauthenticate to save</Button></p>}
    {notice && <p role="alert">{notice}</p>}
    {canManage && <Button disabled={!fresh || !valid || conflict || busy} onClick={() => void save()}>Save cohort template</Button>}
  </section>;
}
