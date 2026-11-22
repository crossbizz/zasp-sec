"use client";

import { useEffect, useState } from "react";
import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { BrowserObservedOrigin, BrowserProfile } from "../../../apps/web/api/generated";
import { Button, Card, Field, Select } from "../../components/ui";
import type { APIAccessToken } from "./APIAccessView";

const path = "/api/v1/browser-profiles/{id}" as const;
const supported: readonly BrowserObservedOrigin[] = ["https://claude.ai", "https://chatgpt.com"];
const states: Record<BrowserProfile["state"], string> = {
  awaiting_profile: "Awaiting the profile’s first heartbeat", reporting: "Reporting",
  stale: "Last sync is more than two hours old", expired: "Token expired", revoked: "Retired or revoked",
};
const date = (value: unknown) => typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value);
const timestamp = (value: unknown) => typeof value === "string" && Number.isFinite(Date.parse(value));
const provider = (value: unknown): value is BrowserObservedOrigin => supported.some((origin) => origin === value);
export function decodeBrowserProfile(value: unknown, credential: string, environment: string): BrowserProfile {
  const p = value as Partial<BrowserProfile> | null;
  if (!p || p.credential_id !== credential || p.environment_id !== environment || !p.state || !Object.hasOwn(states, p.state) ||
      !Array.isArray(p.origins) || p.origins.length < 1 || p.origins.length > 2 || !p.origins.every(provider) ||
      !timestamp(p.expires_at) || !(p.last_sync === null || timestamp(p.last_sync)) || !(p.last_observation === null || date(p.last_observation)) ||
      !Array.isArray(p.observations) || p.observations.length > 60 || !p.observations.every((v) => v && provider(v.origin) && date(v.day) && p.origins?.includes(v.origin))) {
    throw Error("Unexpected browser profile response");
  }
  return p as BrowserProfile;
}

function Profile({ client, id, environment, fresh }: { client: APIClient; id: string; environment: string; fresh: boolean }) {
  const [key, setKey] = useState("");
  const [origins, setOrigins] = useState<BrowserObservedOrigin[]>([]);
  const [revision, setRevision] = useState(0);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{
    client: APIClient; revision: number; profile: BrowserProfile | null; missing: boolean; error?: string;
  }>();
  const current = result?.client === client && result.revision === revision ? result : undefined;
  const busy = saving || !current;
  const { profile, missing, error } = current ?? {};
  useEffect(() => {
    const abort = new AbortController();
    void client.GET(path, { params: { path: { id } }, signal: abort.signal }).then((response) => {
      if (abort.signal.aborted) return;
      const missing = response.response.status === 404;
      const profile = missing ? null : requireAPIData(response, (value) => decodeBrowserProfile(value, id, environment));
      setResult({ client, revision, missing, profile });
    }).catch(() => {
      if (!abort.signal.aborted) setResult({ client, revision, missing: false, profile: null, error: "Could not verify the profile status." });
    });
    return () => abort.abort();
  }, [client, id, environment, revision]);
  async function change(retire: boolean) {
    if (!current || busy) return;
    setSaving(true);
    setResult({ ...current, error: undefined });
    try {
      const params = { path: { id }, header: { "X-CSRF-Token": "" } };
      const response = retire ? await client.DELETE(path, { params }) : await client.PUT(path, { params, body: { public_key: key.trim(), origins } });
      const profile = requireAPIData(response, (value) => decodeBrowserProfile(value, id, environment));
      setResult((prior) => prior?.client === client && prior.revision === revision ? { client, revision, profile, missing: false } : prior);
    } catch {
      setResult((prior) => prior?.client === client && prior.revision === revision ? { ...prior, error: "Could not update the profile. Refresh its status before retrying." } : prior);
    } finally { setSaving(false); }
  }
  return <>
    <p>Profile credential <code>{id}</code> · Environment <code>{environment}</code></p>
    {!current && <p role="status">Checking profile status…</p>}
    {error && <p role="alert">{error}</p>}
    {profile && <>
      <p role="status">{states[profile.state]}</p>
      <p>Last sync {profile.last_sync ?? "pending"} · Last observed UTC day {profile.last_observation ?? "none"}</p>
      <p>Approved origins {profile.origins.join(", ")}</p>
      {profile.observations.length > 0 && <ul>{profile.observations.map((day) => <li key={day.day + day.origin}>{day.day} · {day.origin}</li>)}</ul>}
      {profile.state !== "revoked" && <Button variant="danger" disabled={!fresh || busy} onClick={() => {
        if (window.confirm("Retire this profile and remove its stored daily observations?")) void change(true);
      }}>Retire profile</Button>}
    </>}
    {missing && <>
      <Field label="Profile public key" value={key} onChange={(event) => setKey(event.target.value)} />
      <fieldset><legend>Approve origins for this profile</legend>{supported.map((origin) => <label key={origin}>
        <input type="checkbox" checked={origins.includes(origin)} onChange={(event) => setOrigins(event.target.checked ? [...origins, origin] : origins.filter((x) => x !== origin))} />{origin}
      </label>)}</fieldset>
      <Button disabled={busy || !fresh || origins.length === 0 || !/^B[A-Za-z0-9+/]{86}=$/.test(key.trim())} onClick={() => void change(false)}>Register profile public key</Button>
    </>}
    <Button disabled={busy} onClick={() => setRevision((v) => v + 1)}>Refresh profile status</Button>
  </>;
}
export function BrowserProfiles({ client, tokens, environment, fresh }: { client: APIClient; tokens: APIAccessToken[]; environment: string; fresh: boolean }) {
  const [selection, setSelection] = useState("");
  const profiles = tokens.filter((t) => t.environmentId === environment && t.permissions.length === 1 && t.permissions[0] === "report_browser_usage");
  if (!profiles.length) return null;
  const id = profiles.find((t) => t.id === selection)?.id ?? profiles[0].id;
  return <Card title={<h2>Managed browser profiles</h2>}>
    <Select label="Browser profile credential" value={id} onChange={(event) => setSelection(event.target.value)}>
      {profiles.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
    </Select>
    <Profile key={environment + "/" + id} client={client} fresh={fresh} environment={environment} id={id} />
  </Card>;
}
