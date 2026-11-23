"use client";

import { endpointAdapterLabels } from "../../../apps/web/api/endpoint-fleet";

import { useCallback, useEffect, useRef, useState } from "react";
import type { EndpointFleetAPI } from "../../../apps/web/api/endpoint-fleet";
import type { EndpointRegistration } from "../../../apps/web/api/generated";
import { DeviceActions } from "./DeviceActions";
import { useAPIQuery } from "../../api/query";
import { Button, Card, Field } from "../../components/ui";
import { Time } from "../../components/time";

type Props = {
  initialID?: string;
  scope?: string;
  api: EndpointFleetAPI;
  canWrite: boolean;
  fresh: boolean;
  onReauthenticate(): void;
};
export function DeviceFleet(props: Props) {
  const [history, setHistory] = useState<string[]>([]),
    [selected, setSelected] = useState(props.initialID ?? "");
  const [enroll, setEnroll] = useState(false);
  const cursor = history.at(-1);
  const load = useCallback((signal?: AbortSignal) => props.api.list(cursor, signal), [props.api, cursor]);
  const query = useAPIQuery(`fleet:${cursor ?? ""}`, load, !selected && !enroll);
  if (selected) return <DeviceDetail key={selected} {...props} id={selected} back={() => setSelected("")} />;
  if (enroll)
    return (
      <Enroll
        {...props}
        done={(id) => {
          setEnroll(false);
          setSelected(id);
        }}
      />
    );
  return (
    <Card
      title={<h2>Device inventory</h2>}
      className="managed-device-list"
      action={
        props.canWrite && (
          <Button onClick={() => (props.fresh ? setEnroll(true) : props.onReauthenticate())}>
            Enroll pilot device
          </Button>
        )
      }
    >
      {query.status === "loading" && <p role="status">Loading fleet…</p>}
      {["error", "forbidden", "stale"].includes(query.status) && (
        <p role="alert">
          Fleet coverage could not be refreshed. <Button onClick={() => void query.retry()}>Retry</Button>
        </p>
      )}
      {query.data && (
        <>
          <p>
            {query.data.counts.expected} assigned · {query.data.counts.enrolled} enrolled ·{" "}
            {query.data.counts.online} online · {query.data.counts.acknowledged} acknowledged policy
          </p>
          {query.data.items.length === 0 ? (
            <p>No devices assigned on this page.</p>
          ) : (
            <div className="table-scroll">
              <table className="data-table managed-device-table">
                <thead>
                  <tr>
                    <th scope="col">Device</th>
                    <th scope="col">Cohort</th>
                    <th scope="col">Connection</th>
                    <th scope="col">Policy</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.items.map((row) => (
                    <tr key={row.id}>
                      <td>
                        <Button onClick={() => setSelected(row.id)}>{row.id}</Button>
                      </td>
                      <td><span className="device-cell-label" aria-hidden="true">Cohort</span>{row.cohort}</td>
                      <td><span className="device-cell-label" aria-hidden="true">Connection</span>{row.connection.replace("_", " ")}</td>
                      <td>
                        <span className="device-cell-label" aria-hidden="true">Policy</span>
                        {row.acknowledged
                          ? `Acknowledged revision ${row.policy_revision}`
                          : "No current acknowledgment"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {cursor && <Button onClick={() => setHistory((h) => h.slice(0, -1))}>Previous page</Button>}
          {query.data.next_after_id && (
            <Button
              onClick={() => {
                const next = query.data?.next_after_id;
                if (next) setHistory((h) => [...h, next]);
              }}
            >
              Next page
            </Button>
          )}
        </>
      )}
    </Card>
  );
}
function Enroll({ api, fresh, canWrite, onReauthenticate, done }: Props & { done(id: string): void }) {
  const [form, setForm] = useState<EndpointRegistration>({
    credential_id: "",
    device_public_key: "",
    policy_public_key: "",
    cohort: "",
  });
  const [error, setError] = useState(""),
    [saving, setSaving] = useState(false);
  const attempt = useRef<{ key: string; body: EndpointRegistration } | null>(null);
  const controller = useRef<AbortController | null>(null);
  useEffect(() => () => controller.current?.abort(), []);
  function edit(field: keyof EndpointRegistration, value: string) {
    attempt.current = null;
    setForm({ ...form, [field]: value });
  }
  async function submit() {
    if (!canWrite || !fresh || controller.current) return;
    const request = attempt.current ?? { key: crypto.randomUUID(), body: { ...form } };
    attempt.current = request;
    const abort = new AbortController();
    controller.current = abort;
    setSaving(true);
    setError("");
    try {
      const row = await api.register(request.body, request.key, abort.signal);
      if (!abort.signal.aborted) done(row.id);
    } catch {
      if (!abort.signal.aborted)
        setError("Registration could not be confirmed. Check the keys and retry the same assignment.");
    } finally {
      controller.current = null;
      if (!abort.signal.aborted) setSaving(false);
    }
  }
  const valid =
    /^pid_[0-9a-f-]{36}$/.test(form.credential_id) &&
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(form.cohort) &&
    [form.device_public_key, form.policy_public_key].every((v) => /^[A-Za-z0-9+/]{43}=$/.test(v));
  return (
    <Card title={<h2>Enroll pilot device</h2>} className="managed-device-enroll">
      <p>
        Assign the public device and policy keys and the ID of a dedicated endpoint credential. The device
        reports health, applied revision, and scoped inventory metadata after check-in.
      </p>
      {(
        [
          ["cohort", "Cohort"],
          ["credential_id", "Endpoint credential ID"],
          ["device_public_key", "Device public key"],
          ["policy_public_key", "Policy signing public key"],
        ] as const
      ).map(([key, label]) => (
        <Field
          key={key}
          label={label}
          disabled={saving}
          value={form[key]}
          onChange={(e) => edit(key, e.target.value.trim())}
        />
      ))}
      {fresh ? (
        <Button disabled={!canWrite || !valid || saving} onClick={() => void submit()}>
          Register device
        </Button>
      ) : (
        <Button onClick={onReauthenticate}>Reauthenticate</Button>
      )}
      <Button disabled={saving} onClick={() => done("")}>
        Cancel
      </Button>
      {error && <p role="alert">{error}</p>}
    </Card>
  );
}
function Installations({
  items,
  total,
}: {
  items: readonly { installation_id: string; manifest_digest?: string }[];
  total: number;
}) {
  if (total === 0) return <p>No installations reported in this snapshot.</p>;
  return (
    <>
      <p>
        Showing {items.length} of {total} installations.
      </p>
      <ul>
        {items.map((item) => (
          <li key={item.installation_id}>
            Installation <code>{item.installation_id}</code> · Manifest{" "}
            <code>{item.manifest_digest ?? "digest unavailable"}</code>
          </li>
        ))}
      </ul>
    </>
  );
}
function DeviceDetail({
  api,
  scope,
  id,
  canWrite,
  fresh,
  onReauthenticate,
  back,
}: Props & { id: string; back(): void }) {
  const load = useCallback((signal?: AbortSignal) => api.get(id, signal), [api, id]);
  const query = useAPIQuery(`fleet-device:${id}`, load);
  const [notice, setNotice] = useState(""), [busy, setBusy] = useState(false);
  const row = query.data;
  return (
    <Card
      title={<h2>Device detail</h2>}
      className="managed-device-detail"
      action={
        <Button disabled={busy} onClick={back}>
          All devices
        </Button>
      }
    >
      {query.status === "loading" && <p role="status">Loading device…</p>}
      {["error", "forbidden", "stale"].includes(query.status) && (
        <p role="alert">
          Current device details unavailable. <Button onClick={() => void query.retry()}>Refresh</Button>
        </p>
      )}
      {row && (
        <>
          <dl className="managed-device-facts">
            <dt>Device</dt>
            <dd>{row.id}</dd>
            <dt>Cohort</dt>
            <dd>{row.cohort}</dd>
            <dt>Enrollment</dt>
            <dd>{row.state}</dd>
            <dt>Credential generation</dt>
            <dd>{row.credential_generation}</dd>
            <dt>Last contact</dt>
            <dd>{row.last_seen ? <Time value={row.last_seen} /> : "Never seen"}</dd>
            <dt>Assigned / reported policy revision</dt>
            <dd>
              {row.policy_revision} / {row.reported_policy_revision}
            </dd>
            <dt>Current policy acknowledgment</dt>
            <dd>{row.acknowledged ? "Acknowledged" : "No current acknowledgment"}</dd>
            <dt>Inventory partitions</dt>
            <dd>{row.inventory_partitions}</dd>
            <dt>Device observations</dt>
            <dd>{row.observation_count}</dd>
            <dt>Last reported adapter</dt>
            <dd>
              {
                endpointAdapterLabels[row.reported_adapter]
              }
            </dd>
            <dt>Receipt queue / dropped</dt>
            <dd>
              {row.queued_receipts ?? "Unknown"} / {row.dropped_receipts ?? "Unknown"}
            </dd>
          </dl>
          <section aria-label="Inventory evidence">
            <h3>Local inventory</h3>
            <p>
              Showing {row.partition_summaries.length} of {row.inventory_partitions} reported roots.
            </p>
            {row.partition_summaries.map((root) => (
              <details key={root.partition_id}>
                <summary>
                  Root {root.partition_id.slice(0, 12)} · {root.complete ? "Complete" : "Partial"} scan ·
                  generation {root.generation}
                </summary>
                <p>
                  Root identifier <code>{root.partition_id}</code>
                </p>
                <Installations items={root.observed_installations} total={root.observed_count} />
                {!root.complete &&
                  (root.last_complete_generation === null ? (
                    <p>No complete scan received for this root.</p>
                  ) : (
                    <>
                      <h4>Last complete scan · generation {root.last_complete_generation}</h4>
                      <Installations items={root.confirmed_installations} total={root.confirmed_count ?? 0} />
                    </>
                  ))}
              </details>
            ))}
          </section>
          <section aria-label="Local action receipts">
            <h3>Local action receipts</h3>
            <p>
              Showing {row.recent_observations.length} of {row.observation_count} device-reported agent actions. Skill use and target outcome are unknown.
            </p>
            {row.recent_observations.map((receipt) => (
              <details key={receipt.credential_generation + receipt.action_id}>
                <summary>
                  <Time value={receipt.observed_at} /> ·{" "}
                  {receipt.verdict === "deny"
                    ? "Denied"
                    : receipt.verdict === "unavailable"
                      ? "Decision unavailable"
                      : receipt.would_block
                        ? "Would block in enforce mode"
                        : "Continued"}
                </summary>
                <dl className="managed-device-facts">
                  {receipt.adapter && <><dt>Adapter</dt><dd>{endpointAdapterLabels[receipt.adapter as keyof typeof endpointAdapterLabels]}</dd></>}
                  {receipt.tool_class && <><dt>Tool class</dt><dd>{receipt.tool_class}</dd></>}
                  {receipt.rule_id && <><dt>Rule</dt><dd>{receipt.rule_id}</dd></>}
                  {receipt.reason_code && <><dt>Decision reason</dt><dd>{receipt.reason_code.replaceAll("_"," ")}</dd></>}
                  {receipt.graph_state && (
                    <>
                      <dt>Evidence graph</dt>
                      <dd>
                        {receipt.graph_state === "projected" ? "Projected" : "Awaiting projection"} ·{" "}
                        <code>{receipt.graph_evidence_id}</code>
                      </dd>
                    </>
                  )}
                  <dt>Action</dt>
                  <dd>
                    <code>{receipt.action_id}</code>
                  </dd>
                  <dt>Session</dt>
                  <dd>
                    <code>{receipt.session_ref}</code>
                  </dd>
                  <dt>Decision context</dt>
                  <dd>
                    {receipt.mode || "Unknown mode"} · policy revision {receipt.policy_revision} ·{" "}
                    {receipt.target_class.replaceAll("_", " ")}
                  </dd>
                </dl>
              </details>
            ))}
          </section>
          {canWrite && query.status === "success" && row.state !== "retired" && (
            <DeviceActions key={[scope, row.id, row.version].join("/")} api={api} row={row} scope={scope} fresh={fresh}
              reauthenticate={onReauthenticate} setBusy={setBusy} notify={setNotice} refresh={query.retry} />
          )}
        </>
      )}
      {notice && <p role="status">{notice}</p>}
    </Card>
  );
}
