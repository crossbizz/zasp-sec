"use client";

import { useState } from "react";
import { requireAPIData } from "../../../apps/web/api/client";
import type {
  TicketCohortPhase,
  TicketCohortReceipt,
  TicketCohortUpload,
  TicketCohortView,
} from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useOptionalSession } from "../../auth/SessionProvider";
import type { ActivityScope } from "../../domain/activity-links";
import { Button, Card, Field, Select } from "../../components/ui";

const label = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const product =
  /^pid_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const phases = ["monitor", "canary", "promote", "rollback"] as const;
const reasons: Record<string, string> = {
  independent_ticket_proof_required:
    "Attach the canary’s paired action digests and independent recorder readback to its staging Red Team run before promoting.",
  independent_ticket_proof_limit:
    "The canary revision exceeds the bounded proof window. Restore monitoring and verify a new canary revision.",
  independent_ticket_proof_invalid:
    "A bound run proof could not be verified. Inspect its Red Team evidence.",
  canary_unexpected_target_effect:
    "Independent evidence recorded a protected write. Restore the monitored rule and investigate this canary before continuing.",
  nonproduction_required: "Choose a staging, test, or development Environment.",
  cohort_too_large: "This pilot supports 32 assigned devices per named cohort.",
  destination_required:
    "Enter the synthetic ticket destination allowed by the rule.",
  destination_changed: "This phase must keep the monitored destination.",
  independent_policy_present:
    "A target has a separately issued policy. Review its current revision before using a dedicated pilot cohort.",
  managed_member_changed:
    "A managed device changed generation, revision, or enrollment. Inspect its Device detail before continuing.",
  membership_changed:
    "Eligible membership changed. Re-establish a monitored roster before promotion.",
  no_ticket_adapter: "No enrolled device reported a supported ticket adapter.",
  phase_out_of_order:
    "Choose the next phase for this cohort’s recorded rollout.",
  rollback_first:
    "Restore the monitored rules before starting another monitoring cycle.",
  paired_device_evidence_required:
    "Every eligible device must acknowledge its current revision, report both an allowed and an outside-destination action, and have a clear receipt queue.",
  canary_covers_cohort:
    "The acknowledged canary already covers the only eligible device.",
  canary_record_missing:
    "The recorded canary revision could not be established.",
  revision_limit:
    "A device reached its maximum policy revision. Inspect the device generation.",
  nothing_to_restore: "This cohort has no enforced ticket rule to restore.",
};
const validNumber = (v: unknown) =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
export function readCohort(
  value: unknown,
  cohort: string,
  phase: TicketCohortPhase,
  scope?: ActivityScope,
): TicketCohortView {
  const v = value as TicketCohortView;
  if (
    !v ||
    v.cohort !== cohort ||
    !validNumber(v.revision) ||
    !validNumber(v.assigned) ||
    !Array.isArray(v.members) ||
    v.members.length !== Math.min(32, v.assigned) ||
    typeof v.reason !== "string" ||
    !v.members.every(
      (m) =>
        product.test(m.id) &&
        validNumber(m.policy_revision) &&
        validNumber(m.version) &&
        validNumber(m.generation) &&
        typeof m.acknowledged === "boolean" &&
        typeof m.queue_clear === "boolean",
    ) ||
    new Set(v.members.map((m) => m.id)).size !== v.members.length
  )
    throw new TypeError("Invalid cohort response");
  if (
    v.plan &&
    (v.reason !== "ready" ||
      v.plan.schema_version !== "ticket-cohort-plan.v1" ||
      v.plan.cohort !== cohort ||
      v.plan.phase !== phase ||
      v.plan.expected_rollout_revision !== v.revision ||
      !Array.isArray(v.plan.items) ||
      !v.plan.items.length ||
      v.plan.items.length > 32 ||
      !v.plan.items.every(
        (item) =>
          v.members.some(
            (member) =>
              member.id === item.policy.binding.device_id &&
              member.generation === item.policy.binding.credential_generation &&
              member.version === item.expected_device_version &&
              member.policy_revision + 1 === item.policy.revision,
          ) &&
          item.policy.tool === "mcp__pilot__update_ticket" &&
          item.policy.mode ===
            (phase === "canary" || phase === "promote" ? "enforce" : "monitor"),
      ))
  )
    throw new TypeError("Invalid signing plan");
  if (
    scope &&
    v.plan?.items.some(({ policy }) => {
      const b = policy.binding;
      return (
        b.organization_id !== scope.organizationID ||
        b.workspace_id !== scope.workspaceID ||
        b.environment_id !== scope.environmentID
      );
    })
  )
    throw new TypeError("Signing plan belongs to another Environment");
  return v;
}
function download(plan: NonNullable<TicketCohortView["plan"]>) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(plan, null, 2) + "\n"], {
      type: "application/json",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = "ticket-cohort-plan.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function TicketCohort({
  canWrite,
  fresh,
  onReauthenticate,
}: {
  canWrite: boolean;
  fresh: boolean;
  onReauthenticate(): void;
}) {
  const { client } = useAPI();
  const session = useOptionalSession();
  const [cohort, setCohort] = useState(""),
    [phase, setPhase] = useState<TicketCohortPhase>("monitor"),
    [destination, setDestination] = useState("");
  const [view, setView] = useState<TicketCohortView | null>(null),
    [file, setFile] = useState<File | null>(null),
    [receipt, setReceipt] = useState<TicketCohortReceipt | null>(null);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const reset = () => {
    setView(null);
    setFile(null);
    setReceipt(null);
    setError("");
  };
  const inspect = async () => {
    if (busy || !label.test(cohort)) return;
    setBusy(true);
    setError("");
    setView(null);
    setFile(null);
    try {
      const result = await client.GET(
        "/api/v1/device-cohorts/{cohort}/ticket-rollout",
        {
          params: {
            path: { cohort },
            query: {
              phase,
              ...(phase === "monitor" && destination
                ? { allowed_destination: destination }
                : {}),
            },
          },
        },
      );
      setView(
        requireAPIData(result, (v) =>
          readCohort(
            v,
            cohort,
            phase,
            session?.status === "authenticated" ? session : undefined,
          ),
        ),
      );
    } catch {
      setError(
        "Cohort lookup failed. Check your Environment and access before retrying.",
      );
    } finally {
      setBusy(false);
    }
  };
  const publish = async () => {
    if (busy || !canWrite || !file || !view) return;
    if (!fresh) {
      onReauthenticate();
      return;
    }
    setBusy(true);
    setError("");
    try {
      if (file.size > 65536) throw new RangeError();
      const raw = await file.text(),
        body = JSON.parse(raw) as TicketCohortUpload;
      if (
        body.cohort !== cohort ||
        body.phase !== phase ||
        body.schema_version !== "ticket-cohort-bundle.v1" ||
        !validNumber(body.expected_rollout_revision) ||
        !Array.isArray(body.items) ||
        !body.items.length ||
        body.items.length > 32
      )
        throw new Error();
      // Older files can only recover a recorded idempotency receipt. Validate
      // a current file against every device shown in the reviewed signing plan.
      if (body.expected_rollout_revision > view.revision) throw new Error();
      if (body.expected_rollout_revision === view.revision) {
        const planned = view.plan;
        if (!planned || planned.items.length !== body.items.length)
          throw new Error();
        for (const [index, entry] of body.items.entries()) {
          const expected = planned.items[index],
            p = JSON.parse(
              atob(entry.bundle.payload),
            ) as typeof expected.policy;
          const b = p.binding,
            target = expected.policy.binding;
          if (
            entry.expected_device_version !==
              expected.expected_device_version ||
            p.audience !== expected.policy.audience ||
            p.revision !== expected.policy.revision ||
            p.mode !== expected.policy.mode ||
            p.tool !== expected.policy.tool ||
            p.allowed_destination !== expected.policy.allowed_destination ||
            b.organization_id !== target.organization_id ||
            b.workspace_id !== target.workspace_id ||
            b.environment_id !== target.environment_id ||
            b.device_id !== target.device_id ||
            b.credential_generation !== target.credential_generation
          )
            throw new Error();
        }
      }
      const checksum = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(raw),
      );
      const key =
        "ticket-cohort-" +
        [...new Uint8Array(checksum)]
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      const result = await client.PUT(
        "/api/v1/device-cohorts/{cohort}/ticket-rollout",
        {
          params: { path: { cohort }, header: { "Idempotency-Key": key } },
          body,
          bodySerializer: () => raw,
        },
      );
      setReceipt(
        requireAPIData(result, (value) => {
          const r = value as TicketCohortReceipt;
          if (
            !r ||
            r.cohort !== cohort ||
            r.phase !== phase ||
            r.revision !== body.expected_rollout_revision + 1 ||
            !Array.isArray(r.target_ids) ||
            r.target_ids.length !== body.items.length ||
            !r.target_ids.every((id) => product.test(id)) ||
            !/^[a-f0-9]{64}$/.test(r.request_sha256)
          )
            throw new Error();
          return r;
        }),
      );
      setView(null);
      setFile(null);
    } catch {
      setError(
        "Publication unconfirmed. Retry the same signed file to recover its receipt, or inspect the current cohort before preparing a new plan.",
      );
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Staging ticket cohort">
      <fieldset disabled={busy}>
        <legend>Prepare a ticket rule</legend>
        <Field
          label="Cohort name"
          maxLength={64}
          value={cohort}
          onChange={(e) => {
            reset();
            setCohort(e.target.value);
          }}
        />
        <Select
          label="Rollout phase"
          value={phase}
          onChange={(e) => {
            reset();
            setPhase(e.target.value as TicketCohortPhase);
          }}
        >
          {phases.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </Select>
        {phase === "monitor" && (
          <Field
            label="Allowed ticket destination"
            value={destination}
            maxLength={128}
            onChange={(e) => {
              reset();
              setDestination(e.target.value);
            }}
          />
        )}
        <Button disabled={!label.test(cohort)} onClick={() => void inspect()}>
          Inspect cohort
        </Button>
      </fieldset>
      {error && <p role="alert">{error}</p>}
      {receipt && (
        <p role="status">
          Published {receipt.phase} revision {receipt.revision} to{" "}
          {receipt.target_ids.length} devices. Receipt{" "}
          <code>{receipt.request_sha256}</code>. Inspect the cohort for device
          acknowledgments.
        </p>
      )}
      {view && (
        <>
          <p>
            {view.assigned} assigned · last rollout {view.phase}, revision{" "}
            {view.revision} · {view.environment_class}
          </p>
          {view.members.length > 0 && (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Adapter</th>
                  <th>Revision</th>
                  <th>Observed ticket calls</th>
                </tr>
              </thead>
              <tbody>
                {view.members.map((m) => (
                  <tr key={m.id}>
                    <td>{m.id}</td>
                    <td>
                      {m.adapter} · {m.online ? "online" : "offline or stale"}
                    </td>
                    <td>
                      {m.policy_revision || "none"} ·{" "}
                      {m.acknowledged ? "acknowledged" : "unconfirmed"}
                    </td>
                    <td>
                      Allowed {m.allowed_observed ? "seen" : "unknown"} ·
                      outside {m.outside_observed ? "seen" : "unknown"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p>
            Counts describe signed device observations. Independent target
            readback belongs to the Red Team ticket run.
          </p>
          {!view.plan && (
            <p role="status">
              {reasons[view.reason] ??
                "No signing plan available for this phase."}
            </p>
          )}
          {view.plan && canWrite && (
            <>
              <p>
                {view.plan.phase} will issue {view.plan.items.length} signed
                ticket policies to{" "}
                {view.plan.items
                  .map((x) => x.policy.binding.device_id)
                  .join(", ")}
                .
              </p>
              <Button
                disabled={busy}
                onClick={() => view.plan && download(view.plan)}
              >
                Download signing plan
              </Button>
              <p>
                On the issuer’s machine run{" "}
                <code>
                  endpoint-policy -cohort-plan ticket-cohort-plan.json -key
                  issuer.pem &gt; ticket-cohort-bundle.json
                </code>
                .
              </p>
            </>
          )}
          {canWrite && (
            <fieldset disabled={busy}>
              <legend>Publish or recover a signed batch</legend>
              <label>
                Signed cohort bundle
                <input
                  type="file"
                  accept="application/json,.json"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
              </label>
              <Button disabled={!file} onClick={() => void publish()}>
                {fresh
                  ? "Publish signed " + phase
                  : "Reauthenticate to publish"}
              </Button>
            </fieldset>
          )}
        </>
      )}
    </Card>
  );
}
