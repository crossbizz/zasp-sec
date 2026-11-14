"use client";

import { useCallback, useEffect, useState } from "react";

import { GATEWAY_TOOL_RISKS, type GatewayDecision, type GatewayPolicy, type MCPGatewayServer, type MCPToolRiskClass } from "../../../apps/web/api/gateway-decoders";
import { Badge, Button, Card, Field, LoadingState, Select } from "../../components/ui";
import { GatewayConflict, newGatewayServerID, type GatewayActivityFilter, type GatewayAPI } from "./gateway-api";

// The hosted gateway in the product: its policy and its activity on the
// Guardrails page, and the MCP servers registered behind it on the MCP
// servers page. The gateway's traffic itself is sent by agents with an API
// token, never by these views.

const riskLabels: Readonly<Record<MCPToolRiskClass, string>> = {
  execute: "Execute (runs code or commands)", write: "Write (changes something)", network: "Network (fetches from an address)", read: "Read", unclassified: "Unclassified",
};
const riskTone = { execute: "critical", write: "warning", network: "info", read: "neutral", unclassified: "neutral" } as const;
const approvalTone = { approved: "success", unapproved: "warning", blocked: "critical" } as const;
const approvalLabels = { approved: "Approved", unapproved: "Unapproved", blocked: "Blocked" } as const;
const decisionTone = { allow: "success", redact: "warning", block: "critical" } as const;
const reasonLabels: Readonly<Record<GatewayDecision["reason"], string>> = {
  none: "—", guardrail: "Guardrail rule", server_blocked: "Server blocked in the registry", server_unapproved: "Server not approved", server_disabled: "Server disabled",
  tool_denied: "Tool on the deny list", tool_not_allowed: "Tool not on the allow list", tool_risk_denied: "Tool risk class denied", tools_hidden: "Tools hidden from the list", stream_window_exceeded: "Stream could not be inspected",
};

function baseOrigin(origin?: string): string {
  return origin ?? (typeof window === "undefined" ? "https://<your Zasp address>" : window.location.origin);
}

type PolicyLoad = { status: "loading" } | { status: "error" } | { status: "ready"; policy: GatewayPolicy };
type PolicyDraft = { unapproved: "allow" | "refuse"; risks: readonly MCPToolRiskClass[]; rate: string };

function draftOf(policy: GatewayPolicy): PolicyDraft {
  return { unapproved: policy.unapproved_servers, risks: policy.denied_tool_risks, rate: String(policy.requests_per_minute) };
}

// The gateway policy of the Environment: what happens to a server the MCP
// registry has no decision for, the risk classes of tools the gateway hides
// and refuses, and the rate of one token. It is saved as a whole against the
// version the card loaded.
export function GatewayPolicyCard({ api, canWrite }: { api: GatewayAPI; canWrite: boolean }) {
  const [load, setLoad] = useState<PolicyLoad>({ status: "loading" });
  const [draft, setDraft] = useState<PolicyDraft>({ unapproved: "allow", risks: [], rate: "600" });
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const reload = useCallback(async (signal?: AbortSignal) => {
    try {
      const policy = await api.getPolicy(signal);
      if (signal?.aborted) return;
      setLoad({ status: "ready", policy }); setDraft(draftOf(policy));
    } catch { if (!signal?.aborted) setLoad({ status: "error" }); }
  }, [api]);
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => void reload(controller.signal));
    return () => controller.abort();
  }, [reload]);
  const policy = load.status === "ready" ? load.policy : null;
  const rate = /^(0|[1-9][0-9]{0,5})$/.test(draft.rate) ? Number(draft.rate) : Number.NaN;
  const validRate = Number.isInteger(rate) && rate <= 100_000;
  const dirty = policy !== null && (draft.unapproved !== policy.unapproved_servers || draft.rate !== String(policy.requests_per_minute) || [...draft.risks].sort().join() !== [...policy.denied_tool_risks].sort().join());
  const save = async () => {
    if (!policy || !dirty || !validRate || busy || !canWrite) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const saved = await api.savePolicy({ unapproved_servers: draft.unapproved, denied_tool_risks: GATEWAY_TOOL_RISKS.filter((risk) => draft.risks.includes(risk)), requests_per_minute: rate }, policy.version);
      setLoad({ status: "ready", policy: saved }); setDraft(draftOf(saved));
      setNotice(`Gateway policy saved as version ${saved.version}. It applies to the next request through the gateway.`);
    } catch (failure) {
      if (failure instanceof GatewayConflict) {
        await reload();
        setError("The gateway policy was changed by someone else since this page loaded it. The current policy is shown; make your changes again and save.");
      } else setError("The gateway policy was not saved. Check your permission to manage workflows and try again.");
    } finally { setBusy(false); }
  };
  return <Card title={<h2>Hosted gateway policy</h2>} action={policy ? <Badge tone={policy.version === 0 ? "neutral" : "brand"}>{policy.version === 0 ? "Defaults" : `Version ${policy.version}`}</Badge> : undefined}>
    {error && <div className="error-banner" role="alert">{error}</div>}
    {notice && <div className="success-banner" role="status">{notice}</div>}
    {load.status === "loading" && <LoadingState label="Loading gateway policy…" />}
    {load.status === "error" && <p role="alert">The gateway policy is unavailable. <Button onClick={() => { setLoad({ status: "loading" }); void reload(); }}>Retry</Button></p>}
    {policy && <>
      {!policy.gateway_enabled && <p role="note"><strong>This deployment does not host the gateway&apos;s traffic routes.</strong> The policy and the registered servers can be prepared here; an operator turns the gateway on in the deployment (<code>hostedGateway.enabled</code>).</p>}
      <p>The hosted gateway stands between your agents and their MCP servers and model providers. The guardrail rules above decide what it blocks and redacts in prompts, tool arguments, tool results and answers; this policy decides which servers and tools it lets through.</p>
      <div className="identity-form-grid">
        <Select label="MCP servers the registry has no decision for" value={draft.unapproved} disabled={!canWrite || busy} onChange={(event) => setDraft((current) => ({ ...current, unapproved: event.target.value === "refuse" ? "refuse" : "allow" }))}>
          <option value="allow">Allow (a blocked server is always refused)</option>
          <option value="refuse">Refuse until approved in the MCP registry</option>
        </Select>
        <Field label="Requests a minute for one token (0 is no limit)" inputMode="numeric" value={draft.rate} disabled={!canWrite || busy} error={validRate ? undefined : "Enter a whole number from 0 to 100000"} onChange={(event) => setDraft((current) => ({ ...current, rate: event.target.value.trim() }))} />
      </div>
      <fieldset disabled={!canWrite || busy}><legend>Tool risk classes the gateway hides from the tool list and refuses to call</legend>
        {GATEWAY_TOOL_RISKS.map((risk) => <label key={risk} style={{ display: "block" }}><input type="checkbox" checked={draft.risks.includes(risk)} onChange={(event) => setDraft((current) => ({ ...current, risks: event.target.checked ? [...current.risks, risk] : current.risks.filter((value) => value !== risk) }))} /> {riskLabels[risk]}</label>)}
      </fieldset>
      <p>A tool&apos;s risk class is read from the words of its name; a tool can also be allowed or denied by name on each server, under MCP servers.</p>
      {canWrite
        ? <div className="row-actions"><Button variant="primary" disabled={!dirty || !validRate || busy} onClick={() => void save()}>{busy ? "Saving…" : "Save gateway policy"}</Button><Button disabled={!dirty || busy} onClick={() => { setDraft(draftOf(policy)); setError(""); setNotice(""); }}>Discard changes</Button></div>
        : <p>You can view this policy. Changing it needs permission to manage workflows.</p>}
    </>}
  </Card>;
}

// How an agent is pointed at the hosted gateway: a URL changes and a token is
// presented. Nothing is installed.
export function HostedGatewaySetupCard({ origin, onNavigate }: { origin?: string; onNavigate?(path: string): void }) {
  const base = baseOrigin(origin);
  return <Card title={<h2>Route an agent through the hosted gateway</h2>}>
    <p>Nothing is installed in your environment. The platform hosts the gateway; an agent reaches it by changing one address in its configuration and presenting a platform token. Your MCP server&apos;s credential and your model provider&apos;s key travel in a header of each request and are never stored.</p>
    <ol>
      <li>Create an API token under {onNavigate ? <Button onClick={() => onNavigate("/administration/api-access")}>API Access</Button> : "Administration, API Access"} with the use “Hosted gateway only”. That token can send traffic through the gateway and can read nothing.</li>
      <li><strong>MCP:</strong> register the server under {onNavigate ? <Button onClick={() => onNavigate("/inventory/tools")}>MCP servers</Button> : "Inventory, Tools, MCP servers"} and put the gateway address it shows in the agent&apos;s MCP configuration in place of the server&apos;s own:</li>
    </ol>
    <pre aria-label="MCP configuration example">{`{
  "mcpServers": {
    "tickets": {
      "type": "http",
      "url": "${base}/api/v1/gateway/mcp/<gateway server id>",
      "headers": {
        "Authorization": "Bearer <platform token>",
        "X-Zasp-Upstream-Authorization": "Bearer <the MCP server's own token>",
        "X-Zasp-Agent-Id": "<the agent's id in the inventory>"
      }
    }
  }
}`}</pre>
    <ol start={3}><li><strong>Models:</strong> point the SDK&apos;s base URL at the gateway, use the platform token as the SDK&apos;s key, and send the provider&apos;s key in <code>X-Zasp-Upstream-Authorization</code>:</li></ol>
    <pre aria-label="Model SDK configuration example">{`# Chat completions and responses format
base_url = "${base}/api/v1/gateway/llm/v1"
api_key  = "<platform token>"
default_headers = {"X-Zasp-Upstream-Authorization": "Bearer <provider key>"}

# Messages format
base_url   = "${base}/api/v1/gateway/llm"
auth_token = "<platform token>"   # sent as Authorization: Bearer
default_headers = {"X-Zasp-Upstream-Authorization": "Bearer <provider key>"}`}</pre>
    <p>The gateway applies the guardrail rules to prompts, tool arguments, tool results and answers, streamed answers included, and records each decision without any text. Limits, latency and what is not covered are in <code>docs/operations/hosted-gateway.md</code>.</p>
  </Card>;
}

function subject(decision: GatewayDecision): string {
  if (decision.surface === "mcp") return `${decision.server_name ?? "removed server"}${decision.tool_name ? ` · ${decision.tool_name}` : ""}`;
  return `${decision.provider ?? ""}${decision.model ? ` · ${decision.model}` : ""}`;
}

// The decision records of the gateway, newest first. A record holds a
// decision and identifiers; it never holds a prompt, an argument, a result or
// an answer.
export function GatewayActivityCard({ api }: { api: GatewayAPI }) {
  const [filter, setFilter] = useState<GatewayActivityFilter>({});
  const [items, setItems] = useState<readonly GatewayDecision[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [more, setMore] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => {
      setStatus("loading");
      api.listActivity({ ...filter, limit: 25 }, controller.signal).then(
        (page) => { if (!controller.signal.aborted) { setItems(page.items); setNext(page.next_cursor); setStatus("ready"); } },
        () => { if (!controller.signal.aborted) setStatus("error"); },
      );
    });
    return () => controller.abort();
  }, [api, filter]);
  const loadMore = async () => {
    if (next === null || more) return;
    setMore(true);
    try {
      const page = await api.listActivity({ ...filter, limit: 25, before: next });
      setItems((current) => [...current, ...page.items]); setNext(page.next_cursor);
    } catch { setStatus("error"); } finally { setMore(false); }
  };
  return <Card title={<h2>Gateway activity</h2>}>
    <p>Every decision of the hosted gateway. A record holds the decision, the matched rules, the size and SHA-256 digest of the body, and the server, tool, provider, model and agent. It never holds a prompt, an argument, a tool result or an answer.</p>
    <div className="page-actions">
      <Select label="Traffic" value={filter.surface ?? ""} onChange={(event) => setFilter((current) => ({ ...current, surface: event.target.value === "mcp" ? "mcp" : event.target.value === "llm" ? "llm" : undefined }))}>
        <option value="">MCP and models</option><option value="mcp">MCP</option><option value="llm">Models</option>
      </Select>
      <Select label="Decision" value={filter.decision ?? ""} onChange={(event) => setFilter((current) => ({ ...current, decision: event.target.value === "allow" || event.target.value === "redact" || event.target.value === "block" ? event.target.value : undefined }))}>
        <option value="">Every decision</option><option value="block">Blocked</option><option value="redact">Redacted</option><option value="allow">Allowed</option>
      </Select>
    </div>
    {status === "loading" && <LoadingState label="Loading gateway activity…" />}
    {status === "error" && <p role="alert">Gateway activity is unavailable.</p>}
    {status === "ready" && (items.length === 0 ? <p>No decision was recorded{filter.surface || filter.decision ? " for this filter" : ""}. Decisions appear here once an agent sends traffic through the gateway.</p> :
      <div className="table-scroll"><table className="data-table" aria-label="Gateway activity"><thead><tr><th scope="col">Time</th><th scope="col">Traffic</th><th scope="col">Server or provider</th><th scope="col">Operation</th><th scope="col">Direction</th><th scope="col">Decision</th><th scope="col">Reason</th><th scope="col">Rules</th><th scope="col">Agent</th><th scope="col">Size</th></tr></thead><tbody>
        {items.map((decision) => <tr key={decision.id}>
          <td>{decision.created_at}</td>
          <td>{decision.surface === "mcp" ? "MCP" : "Model"}</td>
          <td>{subject(decision)}</td>
          <td><code>{decision.operation}</code></td>
          <td>{decision.direction === "request" ? "Request" : "Response"}</td>
          <td><Badge tone={decisionTone[decision.decision]}>{decision.decision}</Badge></td>
          <td>{reasonLabels[decision.reason]}</td>
          <td>{decision.rules.length === 0 ? "—" : decision.rules.map((rule) => `${rule.id} ×${rule.count} (${rule.mode})`).join(", ")}</td>
          <td>{decision.agent_id ?? "—"}</td>
          <td title={decision.content_digest}>{decision.bytes} bytes</td>
        </tr>)}
      </tbody></table></div>)}
    {status === "ready" && next !== null && <div className="row-actions"><Button disabled={more} onClick={() => void loadMore()}>{more ? "Loading…" : "Load older decisions"}</Button></div>}
  </Card>;
}

function toolNames(value: string): readonly string[] | null {
  const names = value.split(/[\s,]+/).filter((name) => name !== "");
  if (names.length > 128 || names.some((name) => !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(name)) || new Set(names).size !== names.length) return null;
  return names;
}

function validUpstream(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.username === "" && url.password === "" && url.search === "" && url.hash === "" && (url.port === "" || url.port === "443") && url.hostname.includes(".") && !value.includes("?") && !value.includes("#");
  } catch { return false; }
}

type ServerForm = { id: string | null; version: number; name: string; url: string; enabled: boolean; allowed: string; denied: string };
const emptyForm: ServerForm = { id: null, version: 0, name: "", url: "", enabled: true, allowed: "", denied: "" };

// The MCP servers registered behind the hosted gateway. Registering one
// gives the address to put in the agent's MCP configuration in place of the
// server's own. No credential of a server is asked for or stored.
export function GatewayServersPanel({ api, canWrite, origin }: { api: GatewayAPI; canWrite: boolean; origin?: string }) {
  const [servers, setServers] = useState<readonly MCPGatewayServer[] | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [failed, setFailed] = useState(false);
  const [form, setForm] = useState<ServerForm | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const reload = useCallback(async (signal?: AbortSignal) => {
    try {
      const list = await api.listServers(signal);
      if (signal?.aborted) return;
      setServers(list.items); setEnabled(list.gateway_enabled); setFailed(false);
    } catch { if (!signal?.aborted) setFailed(true); }
  }, [api]);
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => void reload(controller.signal));
    return () => controller.abort();
  }, [reload]);
  const base = baseOrigin(origin);
  const allowed = form ? toolNames(form.allowed) : [];
  const denied = form ? toolNames(form.denied) : [];
  const formError = !form ? "" : form.name.trim() === "" || form.name.trim().length > 128 ? "Enter a name of at most 128 characters."
    : !validUpstream(form.url) ? "Enter the server's https address, without credentials, a query or a port other than 443. The server's token is not entered here."
      : allowed === null || denied === null ? "Tool names are letters, digits and . _ : / - separated by commas or spaces."
        : allowed.some((name) => denied.includes(name)) ? "A tool cannot be on both lists." : "";
  const submit = async () => {
    if (!form || formError !== "" || busy || !canWrite || allowed === null || denied === null) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const saved = await api.saveServer(form.id ?? newGatewayServerID(), { name: form.name.trim(), upstream_url: form.url, enabled: form.enabled, allowed_tools: [...allowed].sort(), denied_tools: [...denied].sort() }, form.version);
      setForm(null);
      setNotice(form.id === null ? `${saved.name} is registered. Put ${base}${saved.gateway_path} in the agent's MCP configuration in place of the server's own address.` : `${saved.name} was saved.`);
      await reload();
    } catch (failure) {
      if (failure instanceof GatewayConflict) { await reload(); setForm(null); setError("The server was changed elsewhere, or its name is taken. The current servers are shown."); }
      else setError("The server was not saved. Check the address and your permission to manage workflows.");
    } finally { setBusy(false); }
  };
  const remove = async (server: MCPGatewayServer) => {
    if (busy || !canWrite) return;
    setBusy(true); setError(""); setNotice("");
    try { await api.removeServer(server.id, server.version); setNotice(`${server.name} was removed from the gateway. Its decision records are kept.`); await reload(); }
    catch (failure) { if (failure instanceof GatewayConflict) await reload(); setError("The server was not removed."); }
    finally { setBusy(false); }
  };
  return <Card title="MCP servers behind the hosted gateway" action={canWrite && form === null ? <Button variant="primary" disabled={busy} onClick={() => { setForm(emptyForm); setError(""); setNotice(""); }}>Register a server</Button> : undefined}>
    <p>An agent that reaches an MCP server through the gateway has its tool list filtered, its tool calls and their results inspected by the guardrail rules, and every call recorded. Nothing is installed: the agent&apos;s configuration names the gateway address shown here instead of the server&apos;s own.</p>
    {!enabled && <p role="note"><strong>This deployment does not host the gateway&apos;s traffic routes yet.</strong> Servers can be registered now; the gateway addresses answer once an operator turns the gateway on.</p>}
    {error && <p role="alert" className="form-error">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {form && <div role="group" aria-label={form.id === null ? "Register an MCP server" : "Change the MCP server"}>
      <div className="identity-form-grid">
        <Field label="Name" value={form.name} disabled={busy} onChange={(event) => setForm({ ...form, name: event.target.value })} />
        <Field label="Server address (https)" placeholder="https://mcp.example.org/mcp" value={form.url} disabled={busy} onChange={(event) => setForm({ ...form, url: event.target.value.trim() })} />
        <Field label="Only these tools may be called (empty: every tool)" value={form.allowed} disabled={busy} onChange={(event) => setForm({ ...form, allowed: event.target.value })} />
        <Field label="These tools may never be called" value={form.denied} disabled={busy} onChange={(event) => setForm({ ...form, denied: event.target.value })} />
      </div>
      <label><input type="checkbox" checked={form.enabled} disabled={busy} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} /> Enabled (a disabled server is refused at the gateway)</label>
      {formError && <p className="form-error">{formError}</p>}
      <div className="row-actions"><Button variant="primary" disabled={busy || formError !== ""} onClick={() => void submit()}>{busy ? "Saving…" : form.id === null ? "Register" : "Save server"}</Button><Button disabled={busy} onClick={() => setForm(null)}>Cancel</Button></div>
    </div>}
    {failed && <p role="alert">The gateway&apos;s servers are unavailable. <Button onClick={() => void reload()}>Retry</Button></p>}
    {!failed && servers === null && <p role="status">Loading gateway servers…</p>}
    {servers !== null && (servers.length === 0 ? <p>No MCP server is registered behind the gateway.</p> :
      <div className="table-scroll"><table className="data-table" aria-label="Gateway MCP servers"><thead><tr><th scope="col">Server</th><th scope="col">Gateway address for the agent</th><th scope="col">Registry</th><th scope="col">State</th><th scope="col">Tools seen through the gateway</th><th scope="col">Allow and deny lists</th><th scope="col">Last activity</th>{canWrite && <th scope="col">Change</th>}</tr></thead><tbody>
        {servers.map((server) => <tr key={server.id}>
          <td><strong>{server.name}</strong><br /><code>{server.upstream_url}</code></td>
          <td><code>{base}{server.gateway_path}</code></td>
          <td><Badge tone={approvalTone[server.approval]}>{approvalLabels[server.approval]}</Badge><br /><code>{server.identity}</code></td>
          <td>{server.enabled ? "Enabled" : "Disabled"}</td>
          <td>{server.tool_count === 0 ? "None listed yet" : <>{server.tools.map((tool) => <span key={tool.name}><Badge tone={riskTone[tool.risk]}>{tool.name} · {tool.risk}</Badge> </span>)}{server.tool_count > server.tools.length && <span>and {server.tool_count - server.tools.length} more</span>}</>}</td>
          <td>{server.allowed_tools.length === 0 && server.denied_tools.length === 0 ? "Every tool" : <>{server.allowed_tools.length > 0 && <span>Only: {server.allowed_tools.join(", ")}<br /></span>}{server.denied_tools.length > 0 && <span>Never: {server.denied_tools.join(", ")}</span>}</>}</td>
          <td>{server.last_activity_at ?? "None"}</td>
          {canWrite && <td><div className="page-actions">
            <Button disabled={busy} aria-label={`Change ${server.name}`} onClick={() => { setForm({ id: server.id, version: server.version, name: server.name, url: server.upstream_url, enabled: server.enabled, allowed: server.allowed_tools.join(", "), denied: server.denied_tools.join(", ") }); setError(""); setNotice(""); }}>Change</Button>
            <Button disabled={busy} variant="danger" aria-label={`Remove ${server.name}`} onClick={() => void remove(server)}>Remove</Button>
          </div></td>}
        </tr>)}
      </tbody></table></div>)}
  </Card>;
}
