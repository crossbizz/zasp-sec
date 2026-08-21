"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { AttackPath, BreakOption, Finding } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Badge, Button, Card, Drawer, Field, PageHeader } from "../../components/ui";
import { useRetainedWorkflowMutation } from "../workflows/useRetainedWorkflowMutation";
import { createProductionRiskAPI, type ProductionRiskAPI, type VersionedRisk } from "./api";

export function ProductionRiskView({ path, canWrite, api: suppliedAPI, onNavigate = navigateInBrowser }: { path: "/violations" | "/exposure/attack-paths"; canWrite: boolean; api?: ProductionRiskAPI; onNavigate?: (path: string) => void }) {
  const { client } = useAPI();
  const api = useMemo(() => suppliedAPI ?? createProductionRiskAPI(client), [client, suppliedAPI]);
  return path === "/violations" ? <ProductionFindingsView api={api} canWrite={canWrite} onNavigate={onNavigate} /> : <ProductionAttackPathsView api={api} />;
}

function ProductionFindingsView({ api, canWrite, onNavigate }: { api: ProductionRiskAPI; canWrite: boolean; onNavigate: (path: string) => void }) {
  const query = useAPIQuery("risk:findings", useCallback((signal?: AbortSignal) => api.listFindings(signal), [api]));
  const [detail, setDetail] = useState<VersionedRisk<Finding> | null>(null);
  const [detailState, setDetailState] = useState<"idle" | "loading" | "error">("idle");
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const detailRequest = useRef<AbortController | null>(null);
  const { invalidate } = useAPI();
  const update = useRetainedWorkflowMutation<{ id: string; status: "under_review"; version: string }>("finding:update", canWrite);
  const accept = useRetainedWorkflowMutation<{ id: string; reason: string; version: string }>("finding:accept", canWrite);
  const locked = update.isUnresolved || accept.isUnresolved;

  useEffect(() => () => {
    detailRequest.current?.abort();
    detailRequest.current = null;
  }, []);

  const open = async (finding: Finding) => {
    detailRequest.current?.abort(); const controller = new AbortController(); detailRequest.current = controller;
    setDetailState("loading"); setMutationError(null);
    try {
      const value = await api.getFinding(finding.id, controller.signal);
      if (controller.signal.aborted || detailRequest.current !== controller) return;
      setDetail(value); setDetailState("idle");
    } catch (error) {
      if (!controller.signal.aborted && detailRequest.current === controller) { setDetailState("error"); setMutationError(message(error, "Finding detail is unavailable.")); }
    }
  };
  const close = () => { detailRequest.current?.abort(); detailRequest.current = null; setDetail(null); setReason(""); setMutationError(null); };
  const markUnderReview = async () => {
    if (!canWrite || !detail || locked) return;
    setMutationError(null);
    try {
      const result = await update.execute({ id: detail.value.id, status: "under_review", version: detail.version }, (intent, attempt) => api.updateFinding(intent.id, intent.status, intent.version, attempt));
      setDetail({ value: result.value, version: result.version }); invalidate(["risk:findings"]);
    } catch (error) { setMutationError(message(error, "Finding update failed.")); }
  };
  const acceptRisk = async () => {
    if (!canWrite || !detail || locked || reason.trim() !== reason || reason.length < 1 || reason.length > 512) return;
    setMutationError(null);
    try {
      const result = await accept.execute({ id: detail.value.id, reason, version: detail.version }, (intent, attempt) => api.acceptFindingRisk(intent.id, intent.reason, intent.version, attempt));
      setDetail({ value: result.value, version: result.version }); setReason(""); invalidate(["risk:findings"]);
    } catch (error) { setMutationError(message(error, "Risk acceptance failed.")); }
  };

  if (query.status === "loading" || query.status === "idle") return <RiskState title="Findings" status="Loading authorized findings…" />;
  if (query.status === "forbidden") return <RiskState title="Findings" alert="Findings are not authorized in this scope." />;
  if (query.status === "error") return <RiskState title="Findings" alert="Findings are unavailable." retry={() => void query.retry()} />;
  const findings = query.data ?? [];
  return <div className="page"><PageHeader title="Findings" description="Authoritative scoped findings and their exact evidence." />{query.status === "stale" && <div role="alert" className="form-error">Showing stale findings. Retry before making decisions.</div>}<Card>{findings.length === 0 ? <p>No findings in this scope.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Updated</th></tr></thead><tbody>{findings.map((finding) => <tr key={finding.id}><td><button className="row-title" aria-label={`Open ${finding.title}`} onClick={() => void open(finding)}>{finding.title}</button></td><td><Badge tone={finding.severity}>{finding.severity}</Badge></td><td>{finding.status.replace("_", " ")}</td><td>{finding.updated_at}</td></tr>)}</tbody></table></div>}</Card>{detailState === "loading" && <p role="status">Loading finding detail…</p>}{detailState === "error" && <p role="alert">{mutationError}</p>}{detail && <Drawer open title={detail.value.title} closeDisabled={locked} onClose={close}><FindingDetail finding={detail.value} onNavigate={onNavigate} />{canWrite && <section aria-label="Finding controls"><h3>Change status</h3><Button disabled={locked || detail.value.status === "under_review"} onClick={() => void markUnderReview()}>Mark under review</Button><h3>Accept risk</h3><Field multiline label="Risk acceptance reason" value={reason} disabled={locked} maxLength={512} onChange={(event) => setReason(event.target.value)} /><Button variant="danger" disabled={locked || reason.length < 1 || reason.trim() !== reason} onClick={() => void acceptRisk()}>Accept risk</Button></section>}{mutationError && <p role="alert">{mutationError}</p>}{update.canRetry && <Button onClick={() => void update.retry()}>Retry retained finding update</Button>}{accept.canRetry && <Button onClick={() => void accept.retry()}>Retry retained risk acceptance</Button>}{locked && <p role="status">Reconciling finding change…</p>}</Drawer>}</div>;
}

function FindingDetail({ finding, onNavigate }: { finding: Finding; onNavigate: (path: string) => void }) {
  const guidance = guidanceFor(finding);
  return <div className="detail-content"><p><Badge tone={finding.severity}>{finding.severity}</Badge> · {finding.status.replace("_", " ")} · version {finding.version}</p>{finding.acceptance_reason && <><h3>Acceptance reason</h3><p>{finding.acceptance_reason}</p></>}<h3>Why</h3><p>{guidance.why}</p>{finding.risk_factors.length === 0 ? <p>No risk factors recorded.</p> : <dl>{finding.risk_factors.map((factor) => <div key={`${factor.name}/${factor.evidence_id}`}><dt>{factor.name}</dt><dd>Evidence <code>{factor.evidence_id}</code></dd></div>)}</dl>}<h3>Evidence</h3><ul>{finding.evidence_ids.map((id) => <li key={id}><code>{id}</code></li>)}</ul><h3>Path</h3>{finding.path_id ? <><p>Evidence-backed attack path <code>{finding.path_id}</code></p><Button onClick={() => onNavigate("/exposure/attack-paths")}>Open attack path</Button></> : <p>No evidence-backed attack path is linked to this finding.</p>}<h3>Fix</h3><p>{guidance.fix}</p><h3>Verify</h3><p>{guidance.verify}</p></div>;
}

type FindingGuidance = Readonly<{ why: string; fix: string; verify: string }>;

const postureGuidance: Readonly<Record<string, FindingGuidance>> = {
  ownerless_agent: { why: "The discovered production agent has no assigned security owner.", fix: "Assign a named owner with responsibility for the agent and its production access.", verify: "Run discovery again and confirm the owner is present and this finding resolves." },
  human_credential: { why: "The agent is using a credential associated with a human identity.", fix: "Replace the human credential with a dedicated workload identity scoped to the required actions.", verify: "Rotate the credential, run discovery again, and confirm no human credential remains." },
  shared_credential: { why: "The same credential fingerprint is active on more than one agent.", fix: "Issue a distinct workload credential for each agent and revoke the shared credential.", verify: "Run discovery again and confirm every active agent has a unique credential fingerprint." },
  untrusted_production_write: { why: "Untrusted input can reach an agent that has production write access.", fix: "Separate untrusted input handling from production writes and require an enforced authorization boundary.", verify: "Re-run discovery and confirm the input-to-write condition no longer matches." },
  shell_credential: { why: "Shell execution can use a credential that reaches production.", fix: "Remove interactive shell access or isolate the production credential from the shell runtime.", verify: "Run discovery again and confirm shell execution cannot access the production credential." },
  egress_sensitive: { why: "Unrestricted network egress can reach a sensitive data surface.", fix: "Restrict egress to an approved destination allowlist and remove unnecessary sensitive-data access.", verify: "Re-run discovery and confirm either egress or sensitive-data reach is no longer present." },
  unapproved_tool: { why: "The agent can reach a remote tool outside the approved integration set.", fix: "Remove the remote tool or add it to the approved integration allowlist after a security review.", verify: "Run discovery again and confirm every reachable remote tool is approved." },
  destructive_no_control: { why: "A destructive tool action is reachable without an enforced runtime control.", fix: "Apply a blocking runtime policy or supervised approval before the destructive action can execute.", verify: "Exercise the action through the runtime gateway and confirm the policy blocks or requires approval." },
  no_runtime_coverage: { why: "The production agent does not have supported runtime policy coverage.", fix: "Deploy a supported runtime gateway or sensor and attach an active policy to the agent.", verify: "Confirm runtime readiness, then run discovery again and verify coverage is reported." },
  weak_runtime_isolation: { why: "The runtime is privileged or can access the host filesystem.", fix: "Remove privileged execution and host filesystem mounts, then use the minimum required sandbox permissions.", verify: "Redeploy the runtime and run discovery again to confirm both isolation conditions are absent." },
  cicd_production_secret: { why: "A CI/CD write path can reach production secrets.", fix: "Separate build and production secret authority and require a narrowly scoped deployment identity.", verify: "Run discovery again and confirm CI/CD write authority cannot read production secrets." },
  zombie_credential: { why: "An inactive agent still has an active credential.", fix: "Revoke the credential and remove its provider-side authorization.", verify: "Run discovery again and confirm the inactive agent has no active credential." },
};

function guidanceFor(finding: Finding): FindingGuidance {
  if (finding.rule && postureGuidance[finding.rule]) return postureGuidance[finding.rule];
  const authority = finding.rule ?? finding.compliance_context ?? finding.source;
  return {
    why: `Authoritative ${finding.source} evidence matched ${authority}.`,
    fix: "Review the cited evidence and apply the narrowest scoped control that removes the reported condition.",
    verify: "Run the authoritative source sync again and confirm the finding resolves or its linked attack path is blocked.",
  };
}

function navigateInBrowser(path: string): void {
  if (typeof window !== "undefined") window.location.assign(path);
}

function ProductionAttackPathsView({ api }: { api: ProductionRiskAPI }) {
  const query = useAPIQuery("risk:attack-paths", useCallback((signal?: AbortSignal) => api.listAttackPaths(signal), [api]));
  const [selectedPathID, setSelectedPathID] = useState<string | null>(null);
  const [detail, setDetail] = useState<AttackPath | null>(null);
  const [options, setOptions] = useState<readonly BreakOption[] | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [optionsError, setOptionsError] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => {
    request.current?.abort();
    request.current = null;
  }, []);
  const open = async (path: AttackPath) => {
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setSelectedPathID(path.id); setDetailError(null); setOptionsError(null); setDetail(null); setOptions(null);
    const isCurrent = () => !controller.signal.aborted && request.current === controller;
    const detailRequest = api.getAttackPath(path.id, controller.signal).then(
      (value) => { if (isCurrent()) setDetail(value); },
      (error) => { if (isCurrent()) setDetailError(message(error, "Attack path detail is unavailable.")); },
    );
    const optionsRequest = api.getAttackPathBreakOptions(path, controller.signal).then(
      (value) => { if (isCurrent()) setOptions(value); },
      (error) => { if (isCurrent()) setOptionsError(message(error, "Break options are unavailable.")); },
    );
    await Promise.allSettled([detailRequest, optionsRequest]);
  };
  const close = () => { request.current?.abort(); request.current = null; setSelectedPathID(null); setDetail(null); setOptions(null); setDetailError(null); setOptionsError(null); };
  if (query.status === "loading" || query.status === "idle") return <RiskState title="Attack Paths" status="Loading authorized attack paths…" />;
  if (query.status === "forbidden") return <RiskState title="Attack Paths" alert="Attack paths are not authorized in this scope." />;
  if (query.status === "error") return <RiskState title="Attack Paths" alert="Attack paths are unavailable." retry={() => void query.retry()} />;
  const paths = query.data ?? [];
  return <div className="page"><PageHeader title="Attack Paths" description="Bounded evidence paths from entry conditions to impact." />{query.status === "stale" && <div role="alert" className="form-error">Showing stale attack paths.</div>}<Card>{paths.length === 0 ? <p>No attack paths in this scope.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Path</th><th>State</th><th>Nodes</th><th>Updated</th></tr></thead><tbody>{paths.map((path) => <tr key={path.id}><td><button className="row-title" aria-label={`Open attack path ${path.id}`} onClick={() => void open(path)}>{path.entry_id} → {path.sink_id}</button></td><td>{path.state}</td><td>{path.node_ids.length}</td><td>{path.updated_at}</td></tr>)}</tbody></table></div>}</Card>{selectedPathID === null ? null : <Drawer open title="Attack path detail" onClose={close}>{detailError ? <p role="alert">{detailError}</p> : detail ? <><p>{detail.node_ids.join(" → ")}</p><p>State {detail.state}{detail.state === "blocked" ? ` · blocked edge ${detail.blocked_edge}` : ""}</p><h3>Evidence</h3><ul>{detail.evidence_ids.map((id) => <li key={id}><code>{id}</code></li>)}</ul></> : <p role="status">Loading path detail…</p>}<h3>Break path</h3>{optionsError ? <p role="alert">{optionsError}</p> : options === null ? <p role="status">Loading break options…</p> : options.length === 0 ? <p>No deterministic break options are available.</p> : <ol>{options.map((option) => <li key={`${option.kind}/${option.target_id}`}>{option.rank}. {option.kind === "remove_node" ? "Remove node" : "Enforce policy"} at <code>{option.target_id}</code> · evidence <code>{option.evidence_id}</code></li>)}</ol>}</Drawer>}</div>;
}

function RiskState({ title, status, alert, retry }: { title: string; status?: string; alert?: string; retry?: () => void }) {
  return <div className="page"><PageHeader title={title} description="Authorized risk data for the selected scope." />{status && <p role="status">{status}</p>}{alert && <p role="alert">{alert}</p>}{retry && <Button onClick={retry}>Retry</Button>}</div>;
}

function message(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}
