"use client";

import { useEffect, useState } from "react";
import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { SecurityCaseVerification } from "../../../apps/web/api/generated";
import { Badge, Button, Field } from "../../components/ui";

const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function checked(value: SecurityCaseVerification, id: string) {
  if (value.case_id !== id || !["open", "verified_complete"].includes(value.state) ||
      typeof value.business_task_preserved !== "boolean" || typeof value.security_check_passed !== "boolean" ||
      (value.state === "verified_complete") !== (value.business_task_preserved && value.security_check_passed) ||
      (value.state === "verified_complete" && (!value.business_receipt_id || !value.security_receipt_id || !value.fixture_run_id)) ||
      typeof value.reason !== "string") throw new Error("Invalid verification evidence");
  return value;
}

export function caseVerificationAPI(client: APIClient, current: () => void) {
  return {
    async get(id: string, signal: AbortSignal) {
      current();
      const result = await client.GET("/api/v1/security-agents/cases/{id}/verify", { params: { path: { id } }, signal });
      current();
      return checked(requireAPIData(result), id);
    },
    async submit(id: string, fixture: string) {
      current();
      const result = await client.POST("/api/v1/security-agents/cases/{id}/verify", {
        params: { path: { id }, header: { "X-CSRF-Token": "" } }, body: { fixture_run_id: fixture },
      });
      current();
      const value = checked(requireAPIData(result), id);
      if (value.fixture_run_id !== fixture) throw new Error("Verification fixture mismatch");
      return value;
    },
  };
}

export function CaseVerification({ id, api, canWrite, fresh, locked, reauthenticate }: {
  id: string; api: ReturnType<typeof caseVerificationAPI>; canWrite: boolean; fresh: boolean; locked: boolean; reauthenticate(): void;
}) {
  const [attempt, setAttempt] = useState(0);
  const [value, setValue] = useState<SecurityCaseVerification>();
  const [error, setError] = useState("");
  const [fixture, setFixture] = useState("");
  const [approved, setApproved] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void api.get(id, controller.signal).then(v => { if (!controller.signal.aborted) { setValue(v); setError(""); } })
      .catch(() => { if (!controller.signal.aborted) setError("Case verification could not be loaded."); });
    return () => controller.abort();
  }, [id, api, attempt]);
  async function submit() {
    if (busy || !canWrite || locked || !fresh || !approved || !productID.test(fixture)) return;
    setBusy(true); setError("");
    try { setValue(await api.submit(id, fixture)); setApproved(false); setFixture(""); }
    catch { setValue(undefined); setError("Verification was unconfirmed. Reload the case to check whether the fixture was attached."); }
    finally { setBusy(false); }
  }
  return <section className="security-agent-run-closure" aria-label="Remediation verification">
    <h3>Remediation verification</h3>
    {error && <p role="alert">{error} <Button onClick={() => { setError(""); setAttempt(attempt + 1); }}>Reload verification</Button></p>}
    {!value && !error && <p role="status">Loading case evidence…</p>}
    {value && <>
      <p><Badge tone={value.state === "verified_complete" ? "success" : "warning"}>{value.state === "verified_complete" ? "Verified complete" : "Open"}</Badge> · {value.reason.replaceAll("_", " ")}</p>
      <dl><dt>Unwanted action stopped</dt><dd>{value.security_check_passed ? "Verified" : "Unverified"} {value.security_receipt_id && <code>{value.security_receipt_id}</code>}</dd>
        <dt>Approved business task succeeded</dt><dd>{value.business_task_preserved ? "Verified" : "Unverified"} {value.business_receipt_id && <code>{value.business_receipt_id}</code>}</dd></dl>
      {value.fixture_run_id && <p>Fixture run <code>{value.fixture_run_id}</code></p>}
      {canWrite && value.reason !== "remediation_pending" && <fieldset disabled={busy || locked}><legend>Attach owner-approved evidence</legend>
        <p>Use a ticket verification run for this agent, recorded after remediation. The inventory owner must match your principal ID.</p>
        <Field label="Fixture run ID" value={fixture} onChange={event => { setFixture(event.target.value.trim()); setApproved(false); }} />
        <label><input type="checkbox" checked={approved} onChange={event => setApproved(event.target.checked)} /> I approve this fixture’s protected operation and business task for this case.</label>
        {fresh ? <Button disabled={!productID.test(fixture) || !approved} onClick={() => void submit()}>Verify both checks</Button> : <Button onClick={reauthenticate}>Reauthenticate to verify</Button>}
      </fieldset>}
    </>}
  </section>;
}
