"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { APIProductError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { modeLabels, type AISettings } from "../../../apps/web/api/ai-controls";
import { Button, Select } from "../../components/ui";
import { workflowIdempotencyKey } from "../workflows/api";

const localJobs = ["indirect_injection_screen", "purpose_alignment_check", "heuristic_fp_verify"] as const;
const managedJobs = ["agent_discovery_verify", "agent_purpose_draft", "addon_semantic_audit", "security_agent_triage", "security_agent_remediate"] as const;
type Purpose = typeof localJobs[number] | typeof managedJobs[number];
type Status = "queued" | "running" | "passed" | "failed";
type Run = { id: string; environment_id: string; purpose: string; provider: string; model: string; status: Status; requested_at: string; finished_at: string | null };
type Job = Pick<Run, "environment_id" | "provider" | "model" | "purpose">;
function decodedRun(value: unknown, job: Job, id?: string): Run {
  if (!value || typeof value !== "object") throw Error("Invalid qualification result");
  const r = value as Partial<Run>;
  if (!r.id || !/^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(r.id) || (id && r.id !== id)
    || r.environment_id !== job.environment_id || r.provider !== job.provider || r.model !== job.model || r.purpose !== job.purpose
    || !["queued","running","passed","failed"].includes(String(r.status)) || !Number.isFinite(Date.parse(String(r.requested_at)))
    || (r.finished_at !== null && !Number.isFinite(Date.parse(String(r.finished_at))))) throw Error("Qualification run did not match the selected job");
  return r as Run;
}
function availableJobs(environment: AISettings["environment"]) {
  const mode = environment.effective_mode;
  if (mode === "zasp_vpc_slm" || mode === "byoc_self_hosted") return { provider: mode, purposes: localJobs, model: environment.tier2_profile };
  if (mode === "privatelink_bedrock" || mode === "privatelink_vertex") {
    const model = environment.tier3_provider === mode ? environment.tier3_model_pin : "";
    const remediationPin = mode === "privatelink_bedrock" ? "anthropic.claude-sonnet-4-6" : "gemini-2.5-pro";
    return { provider: mode, model, purposes: managedJobs.filter(job => job !== "security_agent_remediate" || model === remediationPin) };
  }
  return null;
}
const terminal = (run: Run) => run.status === "passed" || run.status === "failed";

export function QualificationRunner(props: {
  client: APIClient; expectedScope: string; environment: AISettings["environment"]; canEdit: boolean; fresh: boolean; refreshQualifications(): Promise<void>;
}) {
  const { client, expectedScope, environment, canEdit, fresh, refreshQualifications } = props;
  const selection = availableJobs(environment);
  const [choice, setChoice] = useState<Purpose | "">("");
  const [run, setRun] = useState<Run | null>(null);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const pending = useRef<AbortController | null>(null);
  const attempt = useRef<{ body: string; key: string } | null>(null);
  useEffect(() => () => pending.current?.abort(), []);
  useEffect(() => {
    if (!run || terminal(run) || error) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const response = await client.GET("/api/v1/ai/qualifications/runs/{id}", { params: { path: { id: run.id } }, headers: { "X-Zasp-Expected-Scope": expectedScope }, signal: controller.signal });
        const next = requireAPIData(response, raw => decodedRun(raw, run, run.id));
        if (!controller.signal.aborted) { setRun(next); if (next.status === "passed") await refreshQualifications(); }
      } catch { if (!controller.signal.aborted) setError("Could not refresh this run. Check its status again."); }
    }, 2500);
    return () => { controller.abort(); clearTimeout(timer); };
  }, [client, expectedScope, run, error, refreshQualifications]);

  async function start(event: FormEvent) {
    event.preventDefault();
    if (!selection?.model || environment.monthly_budget_nano_credits <= 0 || !fresh || !canEdit || pending.current || (run && !terminal(run))) return;
    const purpose: Purpose = choice || selection.purposes[0];
    const body = { purpose, provider: selection.provider, model: selection.model };
    const serialized = JSON.stringify(body);
    if (attempt.current?.body !== serialized) attempt.current = { body: serialized, key: workflowIdempotencyKey() };
    const controller = new AbortController(); pending.current = controller; setSaving(true); setError("");
    try {
      const response = await client.POST("/api/v1/ai/qualifications/run", { params: { header: { "Idempotency-Key": attempt.current.key, "X-CSRF-Token": "", "X-Zasp-Fresh-Auth": "confirmed" } },
        headers: { "X-Zasp-Expected-Scope": expectedScope }, body, signal: controller.signal });
      const next = requireAPIData(response, raw => decodedRun(raw, { ...body, environment_id: environment.environment_id }));
      if (!controller.signal.aborted) { attempt.current = null; setRun(next); if (next.status === "passed") await refreshQualifications(); }
    } catch (cause) { if (!controller.signal.aborted) setError(cause instanceof APIProductError ? cause.product.message : "Could not confirm the qualification request. Retry to check the same request."); }
    finally { if (!controller.signal.aborted) setSaving(false); pending.current = null; }
  }
  if (!canEdit) return null;
  if (!selection || !selection.model) return <p>{selection ? "Bind a private model profile or reasoning model in Environment AI controls to run a qualification." : "Qualification runs require an approved private hosting mode."}</p>;
  const busy = saving || Boolean(run && !terminal(run));
  return <form className="ai-qualification" onSubmit={event => void start(event)}>
    <p>{modeLabels[environment.effective_mode]} · {selection.model}</p>
    <Select label="Qualification job" value={choice || selection.purposes[0]} disabled={busy || !fresh} onChange={e => setChoice(e.target.value as Purpose)}>
      {selection.purposes.map(purpose => <option value={purpose} key={purpose}>{purpose.replaceAll("_", " ")}</option>)}
    </Select>
    <Button type="submit" disabled={!fresh || busy || environment.monthly_budget_nano_credits <= 0}>{saving ? "Requesting qualification…" : "Run qualification"}</Button>
    {environment.monthly_budget_nano_credits <= 0 && <p>Save a positive monthly budget in Environment AI controls to run a qualification.</p>}
    {run && <p role="status">Qualification {run.status} · {run.purpose.replaceAll("_", " ")}</p>}
    {error && <p role="alert">{error} {run && !terminal(run) && <Button type="button" onClick={() => setError("")}>Check status</Button>}</p>}
  </form>;
}
