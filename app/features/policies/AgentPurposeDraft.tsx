"use client";

import { useCallback, useMemo, useState } from "react";
import { APIProductError } from "../../../apps/web/api/client";
import { purposeAPI, type PurposeAttempt } from "./purpose-api";
import type { AgentPurpose, InventorySummary, Policy } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card, Field, Select } from "../../components/ui";
import { createProductionAgentSecurityAPI } from "../agents/ProductionAgentSecurityView";

import { ActionAnalysis } from "./ActionAnalysis";
import { SuggestedTools } from "./SuggestedTools";

export function AgentPurposeDraft({ disabled, onCreate, initialAgent = "", canManage = true }: { initialAgent?: string; canManage?:boolean; disabled: boolean; onCreate(value: Policy): void }) {
  const { client } = useAPI();
  const purpose = useMemo(() => purposeAPI(client), [client]);
  const inventory = useMemo(() => createProductionAgentSecurityAPI(client), [client]);
  const [expanded, setExpanded] = useState(Boolean(initialAgent));
  const [agentID, setAgentID] = useState(initialAgent);
  const agents = useAPIQuery("purpose:agents", inventory.listAgents, expanded);
  const tools = useAPIQuery("purpose:tools", inventory.listTools, expanded);
  const [filter, setFilter] = useState("");
  const getPurpose = useCallback((signal?: AbortSignal) => purpose.get(agentID, signal), [purpose, agentID]);
  const stored = useAPIQuery(`purpose:declaration:${agentID}`, getPurpose, expanded && Boolean(agentID));
  const [confirmed, setConfirmed] = useState<AgentPurpose | null>(null);
  const current = confirmed?.agent_id === agentID && confirmed.revision >= (stored.data?.revision ?? 0) ? confirmed : stored.data;
  const [draft, setDraft] = useState<string[] | null>(null);
  const allowed = draft ?? current?.allowed_tool_ids ?? [];
  const [pending, setPending] = useState<PurposeAttempt | null>(null);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState("");
  const blocked = disabled || saving || pending !== null;
  const savePurpose = async () => {
    if (!canManage || disabled || saving || !current || !draft && !pending || stored.status !== "success") return;
    const attempt = pending ?? { agent: agentID, revision: current.revision, tools: [...allowed].sort(), key: crypto.randomUUID() };
    setSaving(true); setNotice(""); setPending(attempt);
    try {
      const saved = await purpose.save(attempt);
      setConfirmed(saved); setPending(null); setDraft(null); setNotice(`Saved purpose revision ${saved.revision}.`);
    } catch (error) {
      if (error instanceof APIProductError && error.status >= 400 && error.status < 500 && error.status !== 429) {
        setPending(null); setDraft(null); setConfirmed(null); await stored.retry(); setNotice("Purpose was not saved. Review the current declaration and your access before retrying.");
      } else { setNotice("Purpose change unconfirmed. Retry the same change to retrieve its receipt."); }
    } finally { setSaving(false); }
  };
  const visibleTools = (tools.data ?? []).filter(tool => tool.name.toLowerCase().includes(filter.trim().toLowerCase()));
  const changeAgent = (id: string) => { setAgentID(id); setDraft(null); setConfirmed(null); setNotice(""); setFilter(""); };
  return <Card title="Purpose-based suggestions"><div className="policy-form-body">
    {!expanded ? <Button onClick={() => setExpanded(true)}>Review agent purpose</Button> : <>
      <Select label="Agent" value={agentID} disabled={blocked} onChange={event => changeAgent(event.target.value)}><option value="">Choose an agent</option>{agents.data?.map((agent: InventorySummary) => <option key={agent.id} value={agent.id}>{agent.name}</option>)}</Select>
      {agents.status === "empty" && <p>No agents have been discovered in this Environment.</p>}
      {[agents, tools, stored].some(query => query.status === "error" || query.status === "forbidden" || query.status === "stale") && <p role="alert">Current inventory evidence is unavailable. <Button onClick={() => { void agents.retry(); void tools.retry(); if (agentID) { void stored.retry(); } }}>Refresh evidence</Button></p>}
      {agentID && <>
        <fieldset className="policy-section" disabled={blocked || !canManage || stored.status !== "success"}><legend>Tools this agent is intended to use</legend>
          <div className="policy-stack"><Field label="Filter tools by name" value={filter} onChange={event => setFilter(event.target.value)} />
          {visibleTools.length > 50 && <p>Showing the first 50 of {visibleTools.length} tools. Filter by name to narrow the list.</p>}
          <div className="policy-choices">{visibleTools.slice(0, 50).map(tool => <label key={tool.id}><input type="checkbox" checked={allowed.includes(tool.id)} disabled={!allowed.includes(tool.id) && allowed.length >= 64} onChange={event => { setDraft(event.target.checked ? [...allowed, tool.id] : allowed.filter(id => id !== tool.id)); }} /><span>{tool.name}</span></label>)}</div>
          {(allowed.length > 0 || current?.revision === 0) && <Button onClick={() => { setDraft([]); }}>Declare no intended tools</Button>}
          </div>
        </fieldset>
        {stored.status === "success" && current && <p>{current.revision ? `Purpose revision ${current.revision}` : "No purpose has been saved for this agent."}</p>}
        {canManage && stored.status === "success" && current && <Button disabled={disabled || saving || !pending && !draft} onClick={() => void savePurpose()}>{pending ? "Retry purpose change" : "Save agent purpose"}</Button>}
        {notice && <p role="status">{notice}</p>}
        <ActionAnalysis key={agentID} agent={agentID} canManage={canManage} disabled={blocked}/>
        {current && current.revision > 0 && !draft && stored.status === "success" && <SuggestedTools key={agentID+"/"+current.revision} agent={agentID} revision={current.revision} canManage={canManage} disabled={blocked} tools={tools.data ?? []} onCreate={onCreate} />}
      </>}
    </>}
  </div></Card>;
}
