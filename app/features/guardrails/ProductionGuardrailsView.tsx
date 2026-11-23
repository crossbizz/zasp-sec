"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import type { GuardrailMode, GuardrailPolicy, GuardrailPolicyRule } from "../../../apps/web/api/decoders";
import { useAPI } from "../../api/APIProvider";
import { useOptionalSession } from "../../auth/SessionProvider";
import { Badge, Button, Card, LoadingState, PageHeader, Select, Tabs } from "../../components/ui";
import { createGatewayAPI, type GatewayAPI } from "../gateway/gateway-api";
import { GatewayActivityCard, GatewayPolicyCard, HostedGatewaySetupCard } from "../gateway/GatewayViews";
import { createGuardrailPolicyAPI, GuardrailPolicyConflict, type GuardrailPolicyAPI } from "./guardrail-policy-api";
import { CalibrationPanel } from "./CalibrationPanel";
import { ClaudeEnterpriseSetup } from "./ClaudeEnterpriseSetup";

// The Guardrails page of the product: the Environment's guardrail policy
// (which rule blocks, redacts, only reports or is off), the policy and the
// activity of the gateway the platform hosts, and how a gateway the customer
// already runs asks for a decision. The decision API and the hosted
// gateway's traffic are called with an API token, never by this page.

const modeLabels: Readonly<Record<GuardrailMode, string>> = { block: "Block", redact: "Redact", monitor: "Monitor only", off: "Off" };
const categoryLabels: Readonly<Record<GuardrailPolicyRule["category"], string>> = { prompt_injection: "Prompt injection", sensitive_data: "Sensitive data" };

function modesOf(policy: GuardrailPolicy): Record<string, GuardrailMode> {
  return Object.fromEntries(policy.rules.map((rule) => [rule.id, rule.mode]));
}

type Load = { status: "loading" } | { status: "error" } | { status: "ready"; policy: GuardrailPolicy };

export function ProductionGuardrailsView({ canWrite, api: providedAPI, gatewayAPI: providedGatewayAPI, origin, onNavigate }: { canWrite: boolean; api?: GuardrailPolicyAPI; gatewayAPI?: GatewayAPI; origin?: string; onNavigate?(path: string): void }) {
  const { client } = useAPI();
  const session = useOptionalSession();
  const api = useMemo(() => providedAPI ?? createGuardrailPolicyAPI(client), [providedAPI, client]);
  // The hosted gateway's cards are shown with the product's own client, or
  // with the API a caller supplies.
  const gatewayAPI = useMemo(() => providedGatewayAPI ?? (providedAPI ? null : createGatewayAPI(client)), [providedGatewayAPI, providedAPI, client]);
  const [load, setLoad] = useState<Load>({ status: "loading" });
  // One section at a time; the others stay loaded, so a draft is not lost.
  const [section, setSection] = useState("rules");
  const [draft, setDraft] = useState<Record<string, GuardrailMode>>({});
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const reload = useCallback(async (signal?: AbortSignal) => {
    try {
      const policy = await api.getPolicy(signal);
      if (signal?.aborted) return;
      setLoad({ status: "ready", policy });
      setDraft(modesOf(policy));
    } catch {
      if (!signal?.aborted) setLoad({ status: "error" });
    }
  }, [api]);
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => void reload(controller.signal));
    return () => controller.abort();
  }, [reload]);

  const policy = load.status === "ready" ? load.policy : null;
  const dirty = policy !== null && policy.rules.some((rule) => draft[rule.id] !== rule.mode);
  const save = async () => {
    if (!policy || !dirty || busy || !canWrite) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const saved = await api.savePolicy(draft, policy.version);
      setLoad({ status: "ready", policy: saved });
      setDraft(modesOf(saved));
      setNotice(`Guardrail policy saved as version ${saved.version}.`);
    } catch (failure) {
      if (failure instanceof GuardrailPolicyConflict) {
        // Someone else saved first. Show their policy; nothing of this draft was applied.
        await reload();
        setError("The policy was changed by someone else since this page loaded it. The current policy is shown; make your changes again and save.");
      } else {
        setError("The policy was not saved. Check your permission to manage workflows and try again.");
      }
    } finally {
      setBusy(false);
    }
  };
  const base = origin ?? (typeof window === "undefined" ? "https://<your Zasp address>" : window.location.origin);

  return <div className="page guardrails">
    <PageHeader title="Guardrails" eyebrow="Protect" description="Decide what the hosted gateway, or a gateway you already run, blocks, redacts or lets through. Detection is deterministic: patterns, phrase lists and checksums, with no model call." />
    {error && <div className="error-banner" role="alert">{error}</div>}
    {notice && <div className="success-banner" role="status">{notice}</div>}
    <div className="page-tabs"><Tabs active={section} onChange={setSection} tabs={[{ id: "rules", label: "Rules" }, { id: "calibration", label: "Calibration" }, ...(gatewayAPI ? [{ id: "gateway", label: "Hosted gateway" }, { id: "activity", label: "Activity" }] : []), ...(onNavigate ? [{ id: "suggestions", label: "Suggestions" }] : []), { id: "setup", label: "Set up" }]} /></div>
    {section === "calibration" && <CalibrationPanel canWrite={canWrite} ruleIDs={policy?.rules.map(rule => rule.id) ?? []} />}
    {onNavigate && <div role="tabpanel" aria-label="Suggestions" hidden={section !== "suggestions"}><Card title="Agent purpose and runtime policy"><p>Review observed tool access against an agent’s intended tools. An authorized reviewer can save a draft rule and replay it against scoped runtime history.</p><Button onClick={() => onNavigate("/policies")}>Open runtime policies</Button></Card></div>}
    <div role="tabpanel" aria-label="Rules" hidden={section !== "rules"}>
    <Card title={<h2>Policy for this Environment</h2>} action={policy ? <Badge tone={policy.version === 0 ? "neutral" : "brand"}>{policy.version === 0 ? "Defaults" : `Version ${policy.version}`}</Badge> : undefined}>
      {load.status === "loading" && <LoadingState label="Loading guardrail policy…" />}
      {load.status === "error" && <p role="alert">The guardrail policy is unavailable. <Button onClick={() => { setLoad({ status: "loading" }); void reload(); }}>Retry</Button></p>}
      {policy && <>
        <p>{policy.version === 0 ? "No policy has been saved for this Environment: every rule has its default mode." : `Last saved ${policy.updated_at ?? ""}.`} A rule that blocks stops the interaction. A rule that redacts replaces what it matched and lets the rest through. A rule that only monitors reports the match in the decision and changes nothing.</p>
        <div className="table-scroll"><table className="data-table" aria-label="Guardrail rules">
          <thead><tr><th scope="col">Rule</th><th scope="col">Category</th><th scope="col">What it matches</th><th scope="col">Mode</th></tr></thead>
          <tbody>{policy.rules.map((rule) => <tr key={rule.id}>
            <td><code>{rule.id}</code>{rule.rule_class && <small className="cell-subtitle">{rule.rule_class === "hard" ? "Hard rule" : "Heuristic rule"}</small>}</td>
            <td>{categoryLabels[rule.category]}</td>
            <td style={{ whiteSpace: "normal", minWidth: 280 }}>{rule.description}</td>
            <td><Select label={`Mode of ${rule.id}`} value={draft[rule.id] ?? rule.mode} disabled={!canWrite || busy} onChange={(event) => setDraft((current) => ({ ...current, [rule.id]: event.target.value as GuardrailMode }))}>
              {(["block", "redact", "monitor", "off"] as const).filter((mode) => mode !== "redact" || rule.redactable).map((mode) => <option key={mode} value={mode}>{modeLabels[mode]}{mode === rule.default_mode ? " (default)" : ""}</option>)}
            </Select></td>
          </tr>)}</tbody>
        </table></div>
        {canWrite
          ? <div className="row-actions"><Button variant="primary" disabled={!dirty || busy} onClick={() => void save()}>{busy ? "Saving…" : "Save policy"}</Button><Button disabled={!dirty || busy} onClick={() => { setDraft(modesOf(policy)); setError(""); setNotice(""); }}>Discard changes</Button></div>
          : <p>You can view this policy. Changing it needs permission to manage workflows.</p>}
      </>}
    </Card>
    </div>
    {gatewayAPI && <div role="tabpanel" aria-label="Hosted gateway" hidden={section !== "gateway"}><GatewayPolicyCard api={gatewayAPI} canWrite={canWrite} /></div>}
    {gatewayAPI && <div role="tabpanel" aria-label="Activity" hidden={section !== "activity"}><GatewayActivityCard api={gatewayAPI} /></div>}
    <div role="tabpanel" aria-label="Set up" hidden={section !== "setup"}>
    <ClaudeEnterpriseSetup
      openAPIAccess={onNavigate && session?.hasCapability("api-access.manage") ? () => onNavigate("/administration/api-access") : undefined}
      openPolicies={onNavigate && session?.hasCapability("policies.read") ? () => onNavigate("/policies") : undefined}
    />
    {gatewayAPI && <HostedGatewaySetupCard origin={origin} onNavigate={onNavigate} />}
    <Card title={<h2>Ask for a decision from your gateway</h2>}>
      <p>Nothing is installed in your runtime. A gateway you already run (for example a LiteLLM guardrail hook) sends the text going into a model or coming out of it, and acts on the answer: <code>allow</code>, <code>redact</code> (use the returned <code>redacted_text</code>) or <code>block</code>. The text is used for that request only; it is not stored. The audit record of a decision holds the decision, the matched rules, the size of the text and its SHA-256 digest.</p>
      <ol>
        <li>Create an API token for the gateway under {onNavigate ? <Button onClick={() => onNavigate("/administration/api-access")}>API Access</Button> : "Administration, API Access"} with the use “Guardrail decisions only”. That token can ask for decisions and can read nothing.</li>
        <li>Send each interaction:</li>
      </ol>
      <pre aria-label="Decision request example">{`curl -sS -X POST ${base}/api/v1/guardrails/decisions \\
  -H "Authorization: Bearer $ZASP_GUARDRAIL_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"direction":"input","text":"<the prompt or the model answer>","agent_id":"support-agent"}'`}</pre>
      <p>The answer names the decision, the matched rule identifiers and the policy version. A request carries at most 32 KB of text. If a decision cannot be recorded the call fails and returns no decision; decide in the gateway whether that fails open or closed. The full request and response, the limits and a LiteLLM example are in <code>docs/operations/guardrail-decision-api.md</code>.</p>
    </Card>
    </div>
  </div>;
}
