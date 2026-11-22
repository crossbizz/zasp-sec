"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  APIProductError,
  APITransportError,
  requireAPIData,
  type APIClient,
} from "../../../apps/web/api/client";
import type { WorkloadContainment, WorkloadCredentialBinding } from "../../../apps/web/api/generated";
import { Button, Card, Field } from "../../components/ui";
import { Time } from "../../components/time";

const bindingPath = "/api/v1/runtime/workload-bindings/{id}" as const;
const containmentPath = "/api/v1/runtime/workload-bindings/{id}/containments/{runId}" as const;
const pid = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function invalid(): never {
  throw new APITransportError("invalid_response", "Unexpected workload control receipt");
}
function object(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : invalid();
}
function identifier(v: unknown): v is string {
  return typeof v === "string" && pid.test(v);
}
function timestamp(v: unknown): v is string {
  return typeof v === "string" && Number.isFinite(Date.parse(v));
}
export function decodeBinding(v: unknown, token: string): WorkloadCredentialBinding {
  const r = object(v);
  if (
    r.credential_id !== token ||
    !identifier(r.agent_id) ||
    !identifier(r.session_id) ||
    !identifier(r.created_by) ||
    !timestamp(r.created_at) ||
    r.source !== "administrator_bound_credential"
  )
    return invalid();
  return r as WorkloadCredentialBinding;
}
export function decodeContainment(
  v: unknown,
  token: string,
  run: string,
  session: string,
): WorkloadContainment {
  const r = object(v);
  if (
    r.credential_id !== token ||
    r.run_id !== run ||
    r.session_id !== session ||
    !identifier(r.step_id) ||
    !identifier(r.approval_id) ||
    !identifier(r.authorized_by) ||
    !timestamp(r.authorized_at) ||
    !timestamp(r.expires_at) ||
    !["pending_readback", "adapter_confirmed", "released", "expired"].includes(String(r.state)) ||
    (r.block_receipt_id !== null && !identifier(r.block_receipt_id)) ||
    (r.release_receipt_id !== null && !identifier(r.release_receipt_id))
  )
    return invalid();
  return r as WorkloadContainment;
}

type Token = { id: string; name: string; permissions: string[]; revokedAt: string | null; expiresAt: string };
type Context = { client: APIClient; fresh: boolean; canContain: boolean };
export function WorkloadControls({ tokens, ...context }: Context & { tokens: Token[] }) {
  const [tokenID, select] = useState("");
  const active = tokens.filter(
    (t) =>
      !t.revokedAt &&
      Date.parse(t.expiresAt) > Date.now() &&
      t.permissions.length > 0 &&
      t.permissions.every((permission) => permission === "decide_actions" || permission === "use_gateway"),
  );
  if (!active.length) return null;
  return (
    <Card title="Workload sessions">
      <label>
        Workload credential{" "}
        <select value={tokenID} onChange={(e) => select(e.target.value)}>
          <option value="">Choose a workload credential</option>
          {active.map((t) => (
            <option value={t.id} key={t.id}>
              {t.name}
            </option>
          ))}
        </select>
      </label>
      {active.some((t) => t.id === tokenID) && <Binding key={tokenID} id={tokenID} {...context} />}
    </Card>
  );
}
function Binding({ id, client, fresh, canContain }: Context & { id: string }) {
  const [binding, setBinding] = useState<WorkloadCredentialBinding | null>();
  const [agent, setAgent] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const active = useRef<AbortController | undefined>(undefined);
  const read = useCallback(
    async (agentID?: string) => {
      active.current?.abort();
      const controller = new AbortController();
      active.current = controller;
      setBusy(true);
      setMessage("");
      try {
        const request = { params: { path: { id } }, signal: controller.signal };
        const response = agentID
          ? await client.PUT(bindingPath, { ...request, body: { agent_id: agentID } })
          : await client.GET(bindingPath, request);
        const result = requireAPIData(response, (v) => decodeBinding(v, id));
        if (!controller.signal.aborted) setBinding(result);
      } catch (error) {
        if (controller.signal.aborted) return;
        if (!agentID && error instanceof APIProductError && error.status === 404) setBinding(null);
        else setMessage("Could not verify this credential binding. Refresh before retrying.");
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    },
    [client, id],
  );
  useEffect(() => {
    void read();
    return () => active.current?.abort();
  }, [read]);
  return (
    <div>
      {binding === undefined && !message && <p role="status">Checking binding…</p>}
      {message && (
        <p role="alert">
          {message}{" "}
          <Button onClick={() => void read()} disabled={busy}>
            Refresh binding
          </Button>
        </p>
      )}
      {binding === null && (
        <>
          <p>
            Bind this credential to one active inventory agent. Future actions will use its governed session.
          </p>
          <Field label="Inventory agent ID" value={agent} onChange={(e) => setAgent(e.target.value)} />
          <Button disabled={!fresh || busy || !identifier(agent)} onClick={() => void read(agent)}>
            Bind credential to agent
          </Button>
        </>
      )}
      {binding && (
        <>
          <p>
            Bound agent <code>{binding.agent_id}</code>. Governed session <code>{binding.session_id}</code>.
          </p>
          {canContain && (
            <Containment client={client} token={id} session={binding.session_id} fresh={fresh} />
          )}
        </>
      )}
    </div>
  );
}

function Containment({
  client,
  token,
  session,
  fresh,
}: {
  client: APIClient;
  token: string;
  session: string;
  fresh: boolean;
}) {
  const [run, setRun] = useState(""),
    [step, setStep] = useState("");
  const [result, setResult] = useState<WorkloadContainment>(),
    [message, setMessage] = useState(""),
    [busy, setBusy] = useState(false);
  const active = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => active.current?.abort(), []);
  async function act(action: "check" | "authorize" | "release") {
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setMessage("");
    try {
      const req = { params: { path: { id: token, runId: run } }, signal: controller.signal };
      const res =
        action === "check"
          ? await client.GET(containmentPath, req)
          : action === "release"
            ? await client.DELETE(containmentPath, req)
            : await client.PUT(containmentPath, { ...req, body: { step_id: step } });
      const receipt = requireAPIData(res, (v) => decodeContainment(v, token, run, session));
      if (!controller.signal.aborted) setResult(receipt);
    } catch (error) {
      if (!controller.signal.aborted) {
        setResult(undefined);
        setMessage(
          error instanceof APIProductError && error.status === 404
            ? "No containment was found for this run and credential."
            : "The requested containment state could not be verified.",
        );
      }
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  return (
    <fieldset disabled={busy}>
      <legend>Approved session containment</legend>
      <Field
        label="Security Agent run ID"
        value={run}
        onChange={(e) => {
          setRun(e.target.value);
          setResult(undefined);
          setStep("");
          setMessage("");
        }}
      />
      <Button disabled={!identifier(run)} onClick={() => void act("check")}>
        Check containment
      </Button>
      <Field label="Approved isolation step ID" value={step} onChange={(e) => setStep(e.target.value)} />
      <Button
        disabled={!fresh || !identifier(run) || !identifier(step) || !!result}
        onClick={() => void act("authorize")}
      >
        Apply approved isolation
      </Button>
      {message && <p role="status">{message}</p>}
      {result && (
        <>
          <p>
            State {result.state.replaceAll("_", " ")}. Expires <Time value={result.expires_at} />.
          </p>
          <p>
            Block receipt {result.block_receipt_id ?? "pending"} · Release receipt{" "}
            {result.release_receipt_id ?? "pending"}
          </p>
          <Button
            disabled={!fresh || result.state === "released" || result.state === "expired"}
            onClick={() => void act("release")}
          >
            Release this run’s isolation
          </Button>
        </>
      )}
    </fieldset>
  );
}
