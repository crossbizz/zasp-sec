"use client";

import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";

import type { InventorySummary, TestDefinition, TestDefinitionInput, TestRun, TestRunDetail } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Badge, Button, Card, Drawer, Field, Modal, PageHeader, Select } from "../../components/ui";
import { createProductionRedTeamAPI, redTeamProductID, type ProductionRedTeamAPI } from "./api";
import { createRedTeamMutationRecovery, type RecoveryStorage, type RedTeamIntent } from "./redTeamMutationRecovery";

const categoryOptions = [
  ["prompt_injection", "Prompt injection"], ["tool_abuse", "Tool abuse"], ["data_leakage", "Data leakage"], ["authorization_bypass", "Authorization bypass"], ["excessive_agency", "Excessive agency"], ["sensitive_information", "Sensitive information"],
] as const;

type RedTeamData = Readonly<{ definitions: readonly TestDefinition[]; runs: readonly TestRun[]; targets: readonly InventorySummary[] }>;

type RedTeamViewProps = { scopeKey: string; canWrite: boolean; api?: ProductionRedTeamAPI; storage?: RecoveryStorage; onNavigate(path: string): void };
export function ProductionRedTeamView(props: RedTeamViewProps) { return <RedTeamSurface key={props.scopeKey} {...props} />; }

function RedTeamSurface({ scopeKey, canWrite, api: suppliedAPI, storage: suppliedStorage, onNavigate }: RedTeamViewProps) {
  const { client, getSessionInvalidationGeneration, getScopeStaleGeneration } = useAPI();
  const expectedScope = scopeKey.split("/").slice(1).join("/");
  const api = useMemo(() => suppliedAPI ?? createProductionRedTeamAPI(client, expectedScope), [client, expectedScope, suppliedAPI]);
  const storage = useMemo(() => suppliedStorage ?? browserRecoveryStorage(), [suppliedStorage]);
  const recovery = useMemo(() => {
    const session = getSessionInvalidationGeneration(), scope = getScopeStaleGeneration();
    return createRedTeamMutationRecovery(scopeKey, storage, api, () => getSessionInvalidationGeneration() === session && getScopeStaleGeneration() === scope);
  }, [scopeKey, storage, api, getSessionInvalidationGeneration, getScopeStaleGeneration]);
  const mutation = useSyncExternalStore(recovery.subscribe, recovery.getSnapshot, recovery.getSnapshot);
  useEffect(() => { recovery.activate(); return () => recovery.dispose(); }, [recovery]);
  useEffect(() => { if (!canWrite) recovery.abort(); }, [canWrite, recovery]);
  const load = useCallback(async (signal?: AbortSignal): Promise<RedTeamData> => { const [definitions, runs, targets] = await Promise.all([api.listDefinitions(signal), api.listRuns(signal), api.listTargets(signal)]); return { definitions, runs, targets }; }, [api]);
  const query = useAPIQuery("red-team:surface", load); const [createOpen, setCreateOpen] = useState(false); const [selectedDefinition, setSelectedDefinition] = useState<TestDefinition | null>(null); const [selectedRun, setSelectedRun] = useState<TestRunDetail | null>(null); const [detailState, setDetailState] = useState<"idle" | "loading" | "error">("idle"); const [mutationError, setMutationError] = useState(""); const detailRequest = useRef<AbortController | null>(null);
  useEffect(() => () => detailRequest.current?.abort(), []);
  const [refreshing, setRefreshing] = useState(false);
  const performing = useRef(false);
  const writeAllowed = canWrite && !refreshing && (query.status === "success" || query.status === "empty") && !mutation.unavailable;
  const locked = !writeAllowed || mutation.pending !== null || mutation.busy;
  const canRetry = writeAllowed && mutation.pending !== null && !mutation.busy;
  const perform = async (intent?: RedTeamIntent) => {
    if (performing.current || !writeAllowed || intent && locked || !intent && !canRetry) return;
    performing.current = true;
    setMutationError("");
    try {
      if (intent) await recovery.execute(intent); else await recovery.retry();
      setRefreshing(true);
      detailRequest.current?.abort(); setDetailState("idle");
      setCreateOpen(false); setSelectedDefinition(null); setSelectedRun(null);
      await query.retry();
    } catch {
      setMutationError("The operation did not return a confirmed result.");
      if (!recovery.getSnapshot().pending) {
        setRefreshing(true);
        detailRequest.current?.abort(); setDetailState("idle");
        setSelectedDefinition(null); setSelectedRun(null);
        await query.retry();
      }
    } finally { setRefreshing(false); performing.current = false; }
  };
  if (query.status === "loading" || query.status === "idle") return <RedTeamState status="Loading authorized Red Team tests…" />;
  if (query.status === "forbidden") return <RedTeamState alert="Red Team is not authorized in this scope." />;
  if (query.status === "error") return <RedTeamState alert="Red Team is unavailable." retry={() => void query.retry()} />;
  const definitions = query.data?.definitions ?? []; const runs = query.data?.runs ?? []; const targets = query.data?.targets ?? [];
  const openDefinition = async (id: string) => { detailRequest.current?.abort(); const controller = new AbortController(); detailRequest.current = controller; setDetailState("loading"); setMutationError(""); try { const value = await api.getDefinition(id, controller.signal); if (!controller.signal.aborted) { setSelectedDefinition(value); setDetailState("idle"); } } catch { if (!controller.signal.aborted) setDetailState("error"); } };
  const openRun = async (id: string) => { detailRequest.current?.abort(); const controller = new AbortController(); detailRequest.current = controller; setDetailState("loading"); setMutationError(""); try { const value = await api.getRun(id, controller.signal); if (!controller.signal.aborted) { setSelectedRun(value); setDetailState("idle"); } } catch { if (!controller.signal.aborted) setDetailState("error"); } };
  const runDefinition = (definition: TestDefinition) => perform({ kind: "run", id: definition.id, version: definition.version, runID: redTeamProductID() });
  const updateDefinition = (definition: TestDefinition) => perform({ kind: "update", id: definition.id, version: definition.version, input: { name: definition.name, target_id: definition.target_id, target_kind: definition.target_kind, categories: definition.categories, safety: definition.safety, enabled: !definition.enabled } });
  const cancelRun = (run: TestRunDetail) => perform({ kind: "cancel", id: run.id, version: run.version });
  return <div className="page"><PageHeader title="Red Team" description="Tenant-scoped curated tests against fresh discovered agentic targets." actions={canWrite ? <Button variant="primary" disabled={locked} onClick={() => { if (!locked) setCreateOpen(true); }}>Create test</Button> : undefined} />{query.status === "stale" && <p role="alert">Showing stale Red Team data. Reload before making changes.</p>}{(mutation.error || mutationError) && <p role="alert" className="form-error">{mutation.error ?? mutationError}</p>}{mutation.busy && <p role="status">Submitting retained operation…</p>}{canRetry && !createOpen && <Button onClick={() => void perform()}>Retry retained operation</Button>}{query.status === "stale" && <Button onClick={() => void query.retry()}>Reload authoritative data</Button>}<Card title="Test definitions">{definitions.length === 0 ? <p>No Red Team tests in this scope.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Test</th><th>Target</th><th>Categories</th><th>Safety</th><th>Status</th><th /></tr></thead><tbody>{definitions.map((definition) => <tr key={definition.id}><td><button className="row-title" onClick={() => void openDefinition(definition.id)}>{definition.name}</button></td><td>{targetName(targets, definition.target_id)}</td><td>{definition.categories.length}</td><td>{definition.safety.environment} · {definition.safety.credential_class.replaceAll("_", " ")}</td><td><Badge tone={definition.enabled ? "success" : "neutral"}>{definition.enabled ? "enabled" : "disabled"}</Badge></td><td>{canWrite && <Button disabled={locked || !definition.enabled} aria-label={`Run ${definition.name}`} onClick={() => void runDefinition(definition)}>Run</Button>}</td></tr>)}</tbody></table></div>}</Card><Card title="Runs">{runs.length === 0 ? <p>No Red Team runs in this scope.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Run</th><th>Test</th><th>Status</th><th>Verdict</th><th>Attempt</th><th>Queued</th></tr></thead><tbody>{runs.map((run) => <tr key={run.id}><td><button className="row-title" aria-label={`Open run ${run.id}`} onClick={() => void openRun(run.id)}>{run.id}</button></td><td>{definitions.find((item) => item.id === run.definition_id)?.name ?? run.definition_id}</td><td><Badge tone={runTone(run)}>{run.cancel_requested && !["cancelled", "complete", "failed"].includes(run.status) ? "cancelling" : run.status}</Badge></td><td>{run.verdict ?? "—"}</td><td>{run.attempt}</td><td>{run.queued_at}</td></tr>)}</tbody></table></div>}</Card>{detailState === "loading" && <p role="status">Loading Red Team detail…</p>}{detailState === "error" && <p role="alert">Red Team detail is unavailable.</p>}<CreateTestModal api={api} open={createOpen} targets={targets} locked={locked} canRetry={canRetry} error={mutation.error} onRetry={() => void perform()} onClose={() => setCreateOpen(false)} onSubmit={(input) => perform({ kind: "create", input })} />{selectedDefinition && <Drawer open title="Red Team test" onClose={() => setSelectedDefinition(null)}><h2>{selectedDefinition.name}</h2><p><Badge tone={selectedDefinition.enabled ? "success" : "neutral"}>{selectedDefinition.enabled ? "enabled" : "disabled"}</Badge> · version {selectedDefinition.version}</p><dl><dt>Target</dt><dd>{targetName(targets, selectedDefinition.target_id)} · {selectedDefinition.target_kind.replaceAll("_", " ")}</dd><dt>Categories</dt><dd>{selectedDefinition.categories.join(", ")}</dd><dt>Safety</dt><dd>{selectedDefinition.safety.environment} · {selectedDefinition.safety.credential_class.replaceAll("_", " ")}</dd><dt>Expected side effects</dt><dd>{selectedDefinition.safety.expected_side_effects.join(", ")}</dd></dl>{canWrite && <div className="button-row"><Button disabled={locked || !selectedDefinition.enabled} onClick={() => void runDefinition(selectedDefinition)}>Run test</Button><Button disabled={locked} onClick={() => void updateDefinition(selectedDefinition)}>{selectedDefinition.enabled ? "Disable test" : "Enable test"}</Button></div>}</Drawer>}{selectedRun && <RunDrawer run={selectedRun} canWrite={canWrite} locked={locked} onClose={() => setSelectedRun(null)} onCancel={() => void cancelRun(selectedRun)} onNavigate={onNavigate} />}</div>;
}

function CreateTestModal({ api, open, targets, locked, canRetry, error: recoveryError, onRetry, onClose, onSubmit }: { api: ProductionRedTeamAPI; open: boolean; targets: readonly InventorySummary[]; locked: boolean; canRetry: boolean; error: string | null; onRetry(): void; onClose(): void; onSubmit(input: TestDefinitionInput): Promise<void> }) {
  const [name, setName] = useState("Curated agent safety"); const [targetID, setTargetID] = useState(""); const [targetKind, setTargetKind] = useState<TestDefinitionInput["target_kind"]>("agent_endpoint"); const [environment, setEnvironment] = useState<TestDefinitionInput["safety"]["environment"]>("staging"); const [credential, setCredential] = useState<TestDefinitionInput["safety"]["credential_class"]>("read_only"); const [categories, setCategories] = useState<TestDefinitionInput["categories"]>(["prompt_injection"]); const [saving, setSaving] = useState(false); const [error, setError] = useState("");
  const selectedTargetID = targetID || targets[0]?.id || ""; const selectedTarget = targets.find((item) => item.id === selectedTargetID); const inferredKind: TestDefinitionInput["target_kind"] = selectedTarget?.kind === "tool" ? "mcp_server" : targetKind;
  const toggle = (category: TestDefinitionInput["categories"][number]) => setCategories((current) => current.includes(category) ? current.filter((item) => item !== category) : [...current, category]);
  const save = async () => { if (locked || saving || name.trim() !== name || name.length < 1 || name.length > 128 || selectedTargetID === "" || categories.length < 1) return; setSaving(true); setError(""); try { await onSubmit({ id: redTeamProductID(), name, target_id: selectedTargetID, target_kind: inferredKind, categories, safety: { environment, credential_class: credential, expected_side_effects: ["bounded evaluation"] } }); } catch { setError("The test creation is unresolved. Reload the authoritative list before retrying."); } finally { setSaving(false); } };
  return <Modal open={open} title="Create Red Team test" onClose={onClose} size="large" footer={<><Button disabled={saving} onClick={onClose}>Cancel</Button><Button variant="primary" disabled={locked || saving || targets.length === 0 || categories.length === 0} onClick={() => void save()}>Save test</Button>{canRetry && <Button onClick={onRetry}>Retry retained operation</Button>}</>}><Field disabled={locked || saving} label="Test name" value={name} maxLength={128} onChange={(event) => setName(event.target.value)} /><Select disabled={locked || saving} label="Fresh discovered target" value={selectedTargetID} onChange={(event) => { setTargetID(event.target.value); const target = targets.find((item) => item.id === event.target.value); if (target?.kind === "tool") setTargetKind("mcp_server"); }}>{targets.map((target) => <option key={target.id} value={target.id}>{target.name}</option>)}</Select>{selectedTarget?.kind === "agent" && <Select disabled={locked || saving} label="Target mode" value={targetKind} onChange={(event) => setTargetKind(event.target.value as TestDefinitionInput["target_kind"])}><option value="agent_endpoint">Agent endpoint</option><option value="coding_agent">Coding agent</option></Select>}<div className="form-grid"><Select disabled={locked || saving} label="Safe environment" value={environment} onChange={(event) => setEnvironment(event.target.value as typeof environment)}><option value="development">Development</option><option value="test">Test</option><option value="staging">Staging</option></Select><Select disabled={locked || saving} label="Credential class" value={credential} onChange={(event) => setCredential(event.target.value as typeof credential)}><option value="read_only">Read only</option><option value="test_write">Test write</option></Select></div><RecommendedPacks key={selectedTargetID} target={selectedTarget} api={api} locked={locked || saving} onApply={setCategories} /><fieldset><legend>Curated categories</legend>{categoryOptions.map(([value, label]) => <label key={value}><input disabled={locked || saving} type="checkbox" checked={categories.includes(value)} onChange={() => toggle(value)} /> {label}</label>)}</fieldset><p>Production-write credentials, arbitrary prompts, arbitrary destinations, and shell access are rejected before queueing.</p>{targets.length === 0 && <p role="alert">No fresh supported agent or tool target is available in this scope.</p>}{(recoveryError || error) && <p role="alert">{recoveryError ?? error}</p>}</Modal>;
}

function RecommendedPacks({target,api,locked,onApply}:{target:InventorySummary|undefined;api:ProductionRedTeamAPI;locked:boolean;onApply(categories:TestDefinitionInput["categories"]):void}) {
  const load=useCallback((signal?:AbortSignal)=>{
    if(!target || target.kind!=="agent" && target.kind!=="tool") return Promise.reject(new Error("Unsupported target"));
    return api.getTargetRecommendations(target.id,target.kind,signal);
  },[api,target]);
  const query=useAPIQuery(`red-team:recommendations:${target?.id??"none"}`,load,Boolean(target));
  const retry=query.retry;
  const [refreshing,setRefreshing]=useState(false);
  const refresh=useCallback(async()=>{setRefreshing(true);try{await retry();}finally{setRefreshing(false);}},[retry]);
  useEffect(()=>{
    if(query.status!=="success" && query.status!=="empty" || !query.data)return;
    const remaining=Date.parse(query.data.freshUntil)-Date.now();
    const timer=setTimeout(()=>void refresh(),Math.max(0,Math.min(remaining,2_147_483_647)));
    return ()=>clearTimeout(timer);
  },[query.data,query.status,refresh]);
  if(!target)return null;
  if(refreshing || query.status==="loading" || query.status==="idle")return <p role="status">Loading capability-backed recommendations…</p>;
  if(query.status!=="success" && query.status!=="empty")return <section><p role="alert">Capability recommendations are unavailable. No recommended pack is confirmed.</p><Button disabled={locked} onClick={()=>void query.retry()}>Retry recommendations</Button></section>;
  const recommendations=query.data?.items??[];
  const apply=()=>{
    if(locked)return;
    if(query.data?.targetID!==target.id || !(Date.parse(query.data.freshUntil)>Date.now())){void refresh();return;}
    onApply(recommendations.map(item=>item.category));
  };
  return <section aria-label="Recommended security tests"><h3>Recommended categories</h3>{recommendations.length===0?<p>No relevant pack is established by the current capability evidence. You can choose curated categories explicitly; this is not a safety verdict.</p>:<><ul>{recommendations.map(item=><li key={item.category}><strong>{categoryOptions.find(([category])=>category===item.category)?.[1]}</strong><p>{item.explanation}</p><details><summary>Supporting evidence ({item.evidenceIDs.length})</summary><ul>{item.evidenceIDs.map(id=><li key={id}><code>{id}</code></li>)}</ul></details></li>)}</ul><Button disabled={locked} onClick={apply}>Use recommended categories</Button></>}<p>Recommendations do not authorize execution. Target and credential safety are checked again before queueing.</p></section>;
}

function RunDrawer({ run, canWrite, locked, onClose, onCancel, onNavigate }: { run: TestRunDetail; canWrite: boolean; locked: boolean; onClose(): void; onCancel(): void; onNavigate(path: string): void }) {
  const terminal = ["complete", "failed", "cancelled"].includes(run.status); return <Drawer open title="Red team run" onClose={onClose}><p><Badge tone={runTone(run)}>{run.cancel_requested && !terminal ? "cancelling" : run.status}</Badge> · attempt {run.attempt} · version {run.version}</p><p><code>{run.id}</code></p>{run.cancel_requested && !terminal && <p>Cancellation requested. The current lease cannot complete successfully.</p>}{run.verdict && <><h3>Verdict</h3><p>{run.verdict}</p></>}{run.error_code && <p role="alert">{run.error_code.replaceAll("_", " ")}</p>}{run.attempts.map((attempt) => <section key={attempt.attempt}><h3>Attempt {attempt.attempt}: {attempt.verdict}</h3><p>{attempt.objective}</p><p>{attempt.behavior}</p><h4>Evidence</h4><ul>{attempt.evidence.map((item) => <li key={item}>{item}</li>)}</ul><p>Immutable evidence: <code>{attempt.evidence_reference}</code></p></section>)}{canWrite && !terminal && !run.cancel_requested && <Button variant="danger" disabled={locked} onClick={onCancel}>Cancel run</Button>}{run.verdict === "fail" && <Button onClick={() => onNavigate("/test/attack-lab")}>Verify safely in Attack Lab</Button>}</Drawer>;
}

function targetName(targets: readonly InventorySummary[], id: string): string { return targets.find((item) => item.id === id)?.name ?? id; }
function runTone(run: TestRun): "success" | "critical" | "warning" | "info" | "neutral" { return run.status === "complete" && run.verdict === "pass" ? "success" : run.status === "complete" && run.verdict === "fail" || run.status === "failed" ? "critical" : run.status === "retryable" ? "warning" : run.status === "cancelled" ? "neutral" : "info"; }
function RedTeamState({ status, alert, retry }: { status?: string; alert?: string; retry?(): void }) { return <div className="page"><PageHeader title="Red Team" description="Tenant-scoped curated agentic security tests." />{status && <p role="status">{status}</p>}{alert && <p role="alert">{alert}</p>}{retry && <Button onClick={retry}>Retry</Button>}</div>; }

function browserRecoveryStorage(): RecoveryStorage | undefined { try { return typeof window === "undefined" ? undefined : window.sessionStorage; } catch { return undefined; } }
