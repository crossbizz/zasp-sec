"use client";

import { useEffect, useRef, useState } from "react";
import { APIProvider, useAPI } from "../../api/APIProvider";
import { SessionProvider, useSession } from "../../auth/SessionProvider";
import { AuthPage } from "../../components/AuthPage";
import { approveCLIRequest, readCLIRequest, type CLIRequest } from "../../../apps/web/api/cli-consent";

export function CLIConsent() {
  const { client } = useAPI();
  const session = useSession();
  const initialized = useRef(false);
  const [request, setRequest] = useState<CLIRequest | null | undefined>();
  const [code, setCode] = useState("");
  const [phase, setPhase] = useState<"ready" | "pending" | "approved" | "declined" | "error">("ready");
  const inFlight = useRef(false);
  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    const parsed = readCLIRequest(window.location.hash);
    window.history.replaceState(window.history.state, "", window.location.pathname);
    queueMicrotask(() => setRequest(parsed ?? null));
  }, []);
  useEffect(() => {
    if (!request) return;
    const timer = window.setTimeout(() => setRequest(null), Math.max(0, request.expires - Date.now()));
    return () => window.clearTimeout(timer);
  }, [request]);

  async function approve() {
    if (!request || session.status !== "authenticated" || !session.isFreshAuthenticated ||
        session.environmentID !== request.environment_id || !session.hasCapability("addon-scans.share") || !/^[0-9a-f]{8}$/.test(code) || inFlight.current) return;
    inFlight.current = true;
    setPhase("pending");
    try {
      const scope = [session.organizationID, session.workspaceID, session.environmentID].join("/");
      await approveCLIRequest(client, request, code, scope);
      setPhase("approved");
      setCode("");
    } catch {
      setPhase("error");
    } finally { inFlight.current = false; }
  }

  let content;
  if (phase === "approved") {
    content = <p role="status">Approved. Return to your terminal to complete sign-in.</p>;
  } else if (phase === "declined") {
    content = <p>Request dismissed. The CLI can be closed or left to expire.</p>;
  } else if (request === null) {
    content = <p role="alert">The login link is invalid or expired. Run zaspctl auth login again.</p>;
  } else if (!request || session.status === "loading") {
    content = <p role="status">Checking the request and your session…</p>;
  } else if (session.status !== "authenticated" || !session.isFreshAuthenticated) {
    content = <><p>Sign in or renew your Zasp session in a separate tab. Then check your session here.</p>
      <a href="/sign-in?return_to=%2F" target="_blank" rel="noopener noreferrer">Sign in to Zasp</a>{" "}
      <button onClick={() => void session.retry()}>Check session</button></>;
  } else if (session.environmentID !== request.environment_id) {
    const target = session.scopes.find((item) => item.environment_id === request.environment_id && item.organization_id === session.organizationID);
    content = <><p>The CLI requested Environment <code>{request.environment_id}</code>. Your current Environment is <code>{session.environmentID}</code>.</p>
      {target ? <button disabled={session.scopeSwitch.status === "pending"} onClick={() => void session.switchScope(target.workspace_id, target.environment_id)}>Switch to {target.label}</button>
        : <p>Start a login for an Environment you can access.</p>}</>;
  } else if (!session.hasCapability("addon-scans.share")) {
    content = <p>Your session cannot approve CLI credentials in this Environment. Ask your administrator for a developer or security role in this Environment.</p>;
  } else {
    const label = session.scopes.find((item) => item.environment_id === request.environment_id)?.label;
    content = <form className="form-stack" onSubmit={(event) => { event.preventDefault(); void approve(); }}>
      <p><strong>Environment</strong> {label && <>{label} · </>}<code>{request.environment_id}</code></p>
      <p>This CLI can submit findings-only add-on scans to this Environment for up to 15 minutes. Consent uses your security-testing grant in this Environment.</p>
      <label className="field" htmlFor="comparison-code">Enter the eight-character code shown in your terminal
        <input id="comparison-code" type="text" autoComplete="off" autoCapitalize="none" spellCheck={false}
          maxLength={8} pattern="[0-9a-f]{8}" value={code} onChange={(event) => setCode(event.target.value.toLowerCase())} />
      </label>
      {phase === "error" && <p role="alert">Approval failed. Check the code and your permissions or start a new login.</p>}
      <div className="button-row">
        <button type="submit" className="button button--primary" disabled={!/^[0-9a-f]{8}$/.test(code) || phase === "pending"}>Approve CLI access</button>
        <button type="button" className="button button--secondary" disabled={phase === "pending"} onClick={() => { setCode(""); setPhase("declined"); }}>Dismiss</button>
      </div>
    </form>;
  }
  return <AuthPage><h1>Authorize zaspctl</h1>{content}</AuthPage>;
}
export default function CLIConsentPage() {
  return <APIProvider><SessionProvider><CLIConsent /></SessionProvider></APIProvider>;
}
