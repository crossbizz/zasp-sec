"use client";

import { useCallback, useEffect, useState, useSyncExternalStore, type FormEvent } from "react";
import { BrandLogo } from "../components/BrandLogo";
import { Button, Field } from "../components/ui";
import { dashboardLink, operatorAPI, OperatorRequestError, type OperatorSession, type OperatorSettings, type ServiceAccess } from "./operator-api";
import "./deployment-admin.css";

function status(error: unknown) { return error instanceof OperatorRequestError ? error.status : 0; }

const stableHost = () => () => {};
const readHost = () => window.location.host;
const serverHost = () => "";

export function DeploymentAdmin() {
  const [session, setSession] = useState<OperatorSession | null>(null);
  const [phase, setPhase] = useState<"checking" | "signed-out" | "unavailable">("checking");
  const [message, setMessage] = useState("");
  const host = useSyncExternalStore(stableHost, readHost, serverHost);
  const [revision, setRevision] = useState(0);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const signInRequired = useCallback((reason: string) => {
    setSession(null); setPassword(""); setMessage(reason); setPhase("signed-out");
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void operatorAPI.session(controller.signal).then(value => {
      if (!controller.signal.aborted) { setSession(value); setMessage(""); }
    }, error => {
      if (controller.signal.aborted) return;
      if (status(error) === 401) signInRequired("");
      else setPhase("unavailable");
    });
    return () => controller.abort();
  }, [revision, signInRequired]);

  useEffect(() => {
    if (!session) return;
    const timer = window.setTimeout(() => signInRequired("Your operator session expired. Sign in again."), Math.min(2_147_483_647, Math.max(0, Date.parse(session.expires_at) - Date.now())));
    return () => window.clearTimeout(timer);
  }, [session, signInRequired]);

  useEffect(() => {
    const restore = (event: PageTransitionEvent) => {
      if (event.persisted) { setSession(null); setPassword(""); setPhase("checking"); setRevision(value => value + 1); }
    };
    window.addEventListener("pageshow", restore);
    return () => window.removeEventListener("pageshow", restore);
  }, []);

  async function signIn(event: FormEvent) {
    event.preventDefault();
    if (!password || busy) return;
    setBusy(true); setMessage(""); setPassword("");
    try { setSession(await operatorAPI.signIn(password)); }
    catch (error) {
      setMessage(status(error) === 401 ? "Incorrect operator password." : status(error) === 429 ? "Too many attempts. Wait before trying again." : "Operator sign-in is unavailable. Try again.");
    } finally { setBusy(false); }
  }

  async function signOut() {
    if (!session || busy) return;
    setBusy(true);
    try { await operatorAPI.signOut(session); signInRequired("Signed out."); }
    catch (error) {
      if ([401, 403].includes(status(error))) signInRequired("Your operator session changed. Sign in again.");
      else setMessage("Sign-out failed. Try again.");
    } finally { setBusy(false); }
  }

  // Leaving the operator surface requires a new tenant page and session bootstrap.
  // eslint-disable-next-line @next/next/no-html-link-for-pages
  const home = <a href="/" aria-label="Zasp home"><BrandLogo /></a>;
  return <div className="deployment-admin">
    <header className="deployment-admin__bar"><div>{home}<small>Deployment administration</small></div>
      {session && <Button disabled={busy} onClick={() => void signOut()}>Sign out</Button>}
    </header>
    <main className="deployment-admin__body"><div className={session ? undefined : "deployment-admin__login"}>
      <span className="deployment-admin__origin">{session ? `${session.deployment_id} · ${host}` : host}</span>
      <h1>Deployment Administrator</h1>
      {session ? <>
        <p>Manage the service addresses and credential references operators use for this deployment.</p>
        {message && <p role="alert">{message}</p>}
        <SettingsForm key={session.csrf_token} session={session} onSessionEnd={signInRequired} />
      </> : phase === "checking" ? <p role="status">Checking operator session…</p>
        : phase === "unavailable" ? <><p role="alert">Deployment administration is unavailable on this server.</p><Button onClick={() => { setPhase("checking"); setRevision(value => value + 1); }}>Retry</Button></>
        : <form onSubmit={signIn} className="deployment-admin__panel">
          <h2>Operator sign-in</h2><p>Use the operator password for this deployment.</p>
          <Field label="Operator password" type="password" maxLength={256} autoComplete="current-password" value={password} required disabled={busy} onChange={event => setPassword(event.target.value)} />
          {message && <p role={message === "Signed out." ? "status" : "alert"}>{message}</p>}
          <Button type="submit" variant="primary" disabled={busy || !password}>{busy ? "Signing in…" : "Sign in"}</Button>
        </form>}
    </div></main>
  </div>;
}

function SettingsForm({ session, onSessionEnd }: { session: OperatorSession; onSessionEnd(message: string): void }) {
  const [saved, setSaved] = useState<OperatorSettings | null>(null);
  const [draft, setDraft] = useState<OperatorSettings | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [conflict, setConflict] = useState(false);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const handleFailure = useCallback((cause: unknown, fallback: string) => {
    if ([401, 403].includes(status(cause))) onSessionEnd("Your operator session changed or expired. Sign in again.");
    else setError(fallback);
  }, [onSessionEnd]);

  useEffect(() => {
    const controller = new AbortController();
    void operatorAPI.settings(session, controller.signal).then(value => {
      if (!controller.signal.aborted) { setSaved(value); setDraft(value); setConflict(false); setError(""); }
    }, cause => { if (!controller.signal.aborted) handleFailure(cause, "Service access settings could not be loaded."); });
    return () => controller.abort();
  }, [handleFailure, revision, session]);

  const reload = () => { setError(""); setNotice(""); setSaved(null); setDraft(null); setRevision(value => value + 1); };
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || busy || conflict) return;
    for (const [name, access] of [["Nango", draft.nango], ["OpenSearch", draft.opensearch]] as const) {
      if ([access.api_url, access.dashboard_url].some(url => url && !dashboardLink(url))) {
        setError(`Check the ${name} addresses. Use HTTPS or a private HTTP address without embedded credentials or query parameters.`); return;
      }
      if (access.credential_ref && !/^(kubernetes:\/\/|vault:\/\/|arn:aws(?:-us-gov|-cn)?:secretsmanager:)/.test(access.credential_ref)) {
        setError(`Enter a Kubernetes, Vault, or AWS Secrets Manager reference for ${name}.`); return;
      }
    }
    setBusy(true); setError(""); setNotice("");
    try { const value = await operatorAPI.save(session, draft); setSaved(value); setDraft(value); setNotice("Service access settings saved."); }
    catch (cause) {
      if (status(cause) === 409) { setConflict(true); setError("Settings changed in another session. Reload the saved settings before editing again."); }
      else handleFailure(cause, status(cause) === 400 || status(cause) === 422 ? "Check the service addresses, account names and secret references." : "Saving settings could not be confirmed. Reload to check the saved values.");
    } finally { setBusy(false); }
  }
  if (!saved || !draft) return error ? <><p role="alert">{error}</p><Button onClick={reload}>Retry settings</Button></> : <p role="status">Loading service access…</p>;
  return <form onSubmit={save}>
    {(["nango", "opensearch"] as const).map(key => <ServiceFields key={key} name={key === "nango" ? "Nango" : "OpenSearch"} saved={saved[key]} value={draft[key]} disabled={busy || conflict} onChange={(field, value) => {
      setNotice(""); setError(""); setDraft({ ...draft, [key]: { ...draft[key], [field]: value } });
    }} />)}
    <p>Changes update these operator access records. Runtime connections use the deployment’s service configuration.</p>
    {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    <div className="deployment-admin__actions">
      <Button type="submit" variant="primary" disabled={busy || conflict || JSON.stringify(saved) === JSON.stringify(draft)}>{busy ? "Saving…" : "Save changes"}</Button>
      {error && <Button type="button" onClick={reload}>Reload saved settings</Button>}
    </div>
  </form>;
}

function ServiceFields({ name, saved, value, disabled, onChange }: { name: string; saved: ServiceAccess; value: ServiceAccess; disabled: boolean; onChange(key: keyof ServiceAccess, value: string): void }) {
  const dashboard = dashboardLink(saved.dashboard_url);
  return <section className="deployment-admin__panel" aria-label={name}>
    <div className="deployment-admin__heading"><h2>{name}</h2>{dashboard && <a className="deployment-admin__link" href={dashboard} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">Open {name} dashboard</a>}</div>
    <div className="deployment-admin__fields">
      <Field label="API URL" type="url" maxLength={2048} value={value.api_url} onChange={event => onChange("api_url", event.target.value)} disabled={disabled} />
      <Field label="Dashboard URL" type="url" maxLength={2048} value={value.dashboard_url} onChange={event => onChange("dashboard_url", event.target.value)} disabled={disabled} />
      <Field label="Login account" maxLength={128} value={value.login_hint} autoComplete="off" onChange={event => onChange("login_hint", event.target.value)} disabled={disabled} />
      <Field label="Credential reference" maxLength={512} value={value.credential_ref} autoComplete="off" hint="Enter the location of the credential in your secret manager. Retrieve its value there." onChange={event => onChange("credential_ref", event.target.value)} disabled={disabled} />
    </div>
    {name === "Nango" ? <details><summary>Access a private Nango dashboard</summary>
      <p>From a workstation with operator access, open the dashboard tunnel for your installation.</p>
      <ul><li>VPS <code>./zasp --profile vps nango dashboard</code></li>
        <li>Kubernetes <code>./zasp --profile kubernetes nango dashboard</code></li></ul>
      <p>Keep the tunnel open and use the address it prints. For a service using HTTPS, trust the deployment’s service CA and use the hostname on its certificate.</p>
    </details> : <p>Open private OpenSearch Dashboards through the deployment’s approved network or tunnel. Use the dashboard account from your secret manager.</p>}
  </section>;
}
