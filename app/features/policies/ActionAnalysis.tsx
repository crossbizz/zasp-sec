"use client";

import { useCallback, useState } from "react";
import { APIProductError, requireAPIData } from "../../../apps/web/api/client";
import type {
  ActionAnalysisSettings,
  AgentActionAnalysis,
  WorkloadDestinationClass,
} from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useOptionalSession } from "../../auth/SessionProvider";
import { Button, Field } from "../../components/ui";
import { SourceFrameworkEvidence } from "../sessions/FrameworkCoverage";
import { activityLink } from "../../domain/activity-links";

const label = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const id = /^pid_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const destinations = ["internal", "approved_partner", "external", "public"] as const;
const issueLabels = {
  operation_outside_purpose: "Operation outside declaration",
  classification_outside_purpose: "Reported data classification outside declaration",
  destination_outside_purpose: "Reported destination outside declaration",
  sequence_outside_purpose: "Restricted sequence",
} as const;
const recommendationLabels = {
  review_purpose: "Review the declared purpose",
  review_destination: "Review the permitted destinations",
  review_sequence: "Review the sequence restriction",
  review_data_access: "Review access to the reported data class",
} as const;
type Draft = { classifier: boolean; operations: string; classes: string; dest: readonly WorkloadDestinationClass[]; transitions: string };
function fields(s: ActionAnalysisSettings): Draft {
  return {
    classifier: s.classifier_opt_in === true,
    operations: s.allowed_operations.join("\n"),
    classes: s.allowed_classifications.join("\n"),
    dest: s.allowed_destinations,
    transitions: s.blocked_transitions.map((t) => t.from + " -> " + t.to).join("\n"),
  };
}
function tokens(s: string) {
  const values = s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);
  if (values.length > 32 || values.some((x) => !label.test(x)) || new Set(values).size !== values.length)
    throw new Error("Use up to 32 distinct operation or classification labels.");
  return values.sort();
}
function settingsFrom(d: Draft): ActionAnalysisSettings {
  const lines = d.transitions
    .split("\n")
    .map((x) => x.trim())
    .filter(Boolean);
  const transitions = lines.map((line) => {
    const parts = line.split("->").map((x) => x.trim());
    if (parts.length !== 2 || !label.test(parts[0]) || !label.test(parts[1]))
      throw new Error("Enter each restricted sequence as two operation labels separated by ->.");
    return { from: parts[0], to: parts[1] };
  });
  if (transitions.length > 32 || new Set(transitions.map((t) => JSON.stringify(t))).size !== transitions.length)
    throw new Error("Use up to 32 distinct restricted sequences.");
  return {
    ...(d.classifier ? { classifier_opt_in: true } : {}),
    allowed_operations: tokens(d.operations),
    allowed_classifications: tokens(d.classes),
    allowed_destinations: [...d.dest].sort(),
    blocked_transitions: transitions.sort((a, b) => a.from.localeCompare(b.from) || a.to.localeCompare(b.to)),
  };
}
export function readAnalysis(value: unknown, agent: string): AgentActionAnalysis {
  const v = value as AgentActionAnalysis;
  if (
    !v ||
    v.agent_id !== agent ||
    v.source !== "bound_workload_reported" ||
    ![v.revision, v.pending, v.analyzed, v.unknown_destination].every((n) => Number.isSafeInteger(n) && n >= 0) ||
    typeof v.truncated !== "boolean" ||
    !v.settings ||
    (v.settings.classifier_opt_in !== undefined && typeof v.settings.classifier_opt_in !== "boolean") ||
    (v.intent_drafts !== undefined &&
      (!Array.isArray(v.intent_drafts) ||
        v.intent_drafts.length > 50 ||
        !v.intent_drafts.every((draft) =>
          id.test(draft.decision_id) &&
          Object.hasOwn(recommendationLabels, draft.recommendation) &&
          Number.isFinite(Date.parse(draft.occurred_at)),
        ))) ||
    !Array.isArray(v.findings) ||
    v.findings.length > 50
  )
    throw new TypeError("Invalid analysis overview");
  const d = fields(v.settings);
  settingsFrom(d);
  if (
    !d.dest.every((x) => destinations.includes(x)) ||
    new Set(d.dest).size !== d.dest.length ||
    !v.findings.every(
      (f) =>
        id.test(f.decision_id) &&
        id.test(f.session_id) &&
        label.test(f.operation) &&
        label.test(f.classification) &&
        (f.destination_class === null || destinations.includes(f.destination_class)) &&
        (f.previous_operation === null || label.test(f.previous_operation)) &&
        Number.isFinite(Date.parse(f.occurred_at)) &&
        Array.isArray(f.issues) &&
        f.issues.length > 0 &&
        f.issues.every((i: unknown) => typeof i === "string" && Object.hasOwn(issueLabels, i)),
    )
  )
    throw new TypeError("Invalid analysis findings");
  return v;
}

export function ActionAnalysis({
  agent,
  canManage,
  disabled,
}: {
  agent: string;
  canManage: boolean;
  disabled: boolean;
}) {
  const { client } = useAPI();
  const session = useOptionalSession();
  const [opened, setOpened] = useState(false);
  const read = useCallback(
    async (signal?: AbortSignal) =>
      requireAPIData(
        await client.GET("/api/v1/agents/{id}/action-analysis", { params: { path: { id: agent } }, signal }),
        (v) => readAnalysis(v, agent),
      ),
    [client, agent],
  );
  const query = useAPIQuery("action-analysis:" + agent, read, opened);
  const [local, setLocal] = useState<AgentActionAnalysis | null>(null);
  const current =
    query.status === "forbidden"
      ? undefined
      : local && (!query.data || local.revision >= query.data.revision)
        ? local
        : query.data;
  const [draft, setDraft] = useState<Draft | null>(null),
    [message, setMessage] = useState(""),
    [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState<{ revision: number; key: string; settings: ActionAnalysisSettings } | null>(
    null,
  );
  const refresh = async () => {
    setLocal(null);
    await query.retry();
  };
  const save = async () => {
    if (!canManage || disabled || busy || !current || (!draft && !attempt)) return;
    let request = attempt;
    if (!request) {
      try {
        request = { revision: current.revision, key: crypto.randomUUID(), settings: settingsFrom(draft!) };
      } catch (err) {
        setMessage((err as Error).message);
        return;
      }
    }
    setAttempt(request);
    setBusy(true);
    setMessage("");
    try {
      const result = await client.PUT("/api/v1/agents/{id}/action-analysis", {
        params: {
          path: { id: agent },
          header: { "X-CSRF-Token": "", "If-Match": `"${request.revision}"`, "Idempotency-Key": request.key },
        },
        body: request.settings,
      });
      const v = requireAPIData(result, (raw) => readAnalysis(raw, agent));
      if (v.revision !== request.revision + 1) throw new Error();
      setLocal(v);
      setAttempt(null);
      setDraft(null);
      setMessage(`Saved action analysis revision ${v.revision}.`);
    } catch (err) {
      if (err instanceof APIProductError && err.status >= 400 && err.status < 500 && err.status !== 429) {
        setAttempt(null);
        await refresh();
        setMessage("No settings were saved. Review the current revision and your declaration before submitting again.");
      } else setMessage("Settings receipt unconfirmed. Retry the same request to retrieve its result.");
    } finally {
      setBusy(false);
    }
  };
  if (!opened) return <Button onClick={() => setOpened(true)}>Inspect workload action analysis</Button>;
  const values = draft ?? (current ? fields(current.settings) : null);
  const change = (part: Partial<Draft>) => {
    if (values) {
      setDraft({ ...values, ...part });
      setMessage("");
    }
  };
  return (
    <section aria-label="Workload action analysis">
      <h3>Workload action analysis</h3>
      <p>
        Zasp analyzes admitted operations for agent-bound SDK credentials. Data classification and destination come from
        application metadata. Sequence findings describe adjacent observed admissions in one session. Unreported calls
        and downstream effects remain unknown.
      </p>
      <Button disabled={busy} onClick={() => void refresh()}>
        Refresh analysis
      </Button>
      {query.status === "loading" && <p role="status">Loading action analysis…</p>}
      {["error", "forbidden", "stale"].includes(query.status) && <p role="alert">Current analysis is unavailable.</p>}
      {current && values && (
        <>
          <p>
            {current.revision ? `Analysis revision ${current.revision}` : "No analysis declaration saved"}. Last 30
            days: {current.analyzed} analyzed, {current.pending} pending, {current.unknown_destination} with unknown
            destination.
          </p>
          <fieldset disabled={disabled || busy || !!attempt || !canManage || query.status !== "success"}>
            <legend>Declared workload use</legend>
            <label>
              <input type="checkbox" checked={values.classifier} onChange={(e) => change({ classifier: e.target.checked })} />
              Enable draft intent recommendations for this agent
            </label>
            <p>When your deployment enables OpenRouter, this sends the destination class, whether a previous action was observed, and four purpose-comparison flags. A reviewer decides how to use each recommendation.</p>
            <Field
              multiline
              label="Allowed operations"
              hint="One label per line. Empty leaves this dimension undeclared."
              value={values.operations}
              onChange={(e) => change({ operations: e.target.value })}
            />
            <Field
              multiline
              label="Allowed reported data classifications"
              value={values.classes}
              onChange={(e) => change({ classes: e.target.value })}
            />
            <fieldset>
              <legend>Allowed reported destinations</legend>
              {destinations.map((d) => (
                <label key={d}>
                  <input
                    type="checkbox"
                    checked={values.dest.includes(d)}
                    onChange={(e) =>
                      change({ dest: e.target.checked ? [...values.dest, d] : values.dest.filter((x) => x !== d) })
                    }
                  />
                  {d.replace("_", " ")}
                </label>
              ))}
            </fieldset>
            <Field
              multiline
              label="Restricted operation sequences"
              hint="One pair per line, for example ticket.read -> ticket.send. Sequence correlation ends after 15 minutes or a policy or settings revision change."
              value={values.transitions}
              onChange={(e) => change({ transitions: e.target.value })}
            />
          </fieldset>
          {canManage && (
            <Button
              disabled={disabled || busy || (!draft && !attempt) || query.status !== "success"}
              onClick={() => void save()}
            >
              {attempt ? "Retry analysis settings" : "Save analysis settings"}
            </Button>
          )}
          {current.findings.length === 0 ? (
            <p>No advisory findings in this revision’s review window.</p>
          ) : (
            <ul>
              {current.findings.map((f) => (
                <li key={f.decision_id}>
                  <strong>{f.issues.map((i) => issueLabels[i]).join(" · ")}</strong>
                  <p>
                    {f.occurred_at} · operation {f.operation} · classification {f.classification} · destination{" "}
                    {f.destination_class ?? "unknown"}
                    {f.previous_operation ? " · previous " + f.previous_operation : ""}
                  </p>
                  <p>
                    Decision <code>{f.decision_id}</code> ·{" "}
                    {session?.status === "authenticated" ? (
                      <a href={activityLink({ kind: "session", id: f.session_id }, session)}>Open session</a>
                    ) : (
                      <code>{f.session_id}</code>
                    )}
                  </p>
                  {session?.status === "authenticated" && session.hasCapability("compliance.read") &&
                    <SourceFrameworkEvidence client={client} scope={session} kind="runtime_action" id={f.decision_id} />}
                </li>
              ))}
            </ul>
          )}
          {(current.intent_drafts?.length ?? 0) > 0 && (
            <section aria-label="Draft intent recommendations">
              <h4>Draft intent recommendations</h4>
              <ul>
                {current.intent_drafts?.map((draft) => (
                  <li key={draft.decision_id}>
                    <strong>{recommendationLabels[draft.recommendation]}</strong> · {draft.occurred_at} · Decision{" "}
                    <code>{draft.decision_id}</code>
                  </li>
                ))}
              </ul>
            </section>
          )}
          {current.truncated && <p>Showing the latest 50 findings for this revision.</p>}
        </>
      )}
      {message && <p role="status">{message}</p>}
    </section>
  );
}
