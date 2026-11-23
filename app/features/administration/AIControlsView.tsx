"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { APIProductError, type APIClient } from "../../../apps/web/api/client";
import { createAIControlsAPI, modeLabels, type AISettings, type EnvironmentInput, type OrganizationInput } from "../../../apps/web/api/ai-controls";
import { Badge, Button, Card, LoadingState, PageHeader } from "../../components/ui";
import { QualificationRunner } from "./QualificationRunner";
import { EnvironmentFields, OrganizationFields, Qualifications } from "./AIControlFields";

type Scope = "organization" | "environment";
type Access = { canEditOrganization: boolean; canEditEnvironment: boolean; fresh: boolean; reauthenticate(): void };

export function AIControlsView({ client, expectedScope, ...access }: { client: APIClient; expectedScope: string } & Access) {
  const api = useMemo(() => createAIControlsAPI(client, expectedScope), [client, expectedScope]);
  const [settings, setSettings] = useState<AISettings | null>(null);
  const [revision, setRevision] = useState(0);
  const [loadError, setLoadError] = useState(false);
  const [saved, setSaved] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    api.load(controller.signal).then(data => {
      if (!controller.signal.aborted) { setSettings(data); setLoadError(false); }
    }).catch(() => { if (!controller.signal.aborted) setLoadError(true); });
    return () => controller.abort();
  }, [api, revision]);

  const refreshQualifications = useCallback(async () => {
    const items = await api.qualifications(AbortSignal.timeout(10_000));
    setSettings(current => current && { ...current, qualifications: items });
  }, [api]);

  function reload(message = "") { setSettings(null); setLoadError(false); setSaved(message); setRevision(v => v + 1); }
  return <div className="page ai-controls">
    <PageHeader title="AI & Models" description="Set the organization’s hosting and privacy limits, then choose which model capabilities this environment can use." />
    {saved && <p role="status" className="success-banner">{saved}</p>}
    {loadError ? <div role="alert" className="error-banner">AI settings could not be loaded. <Button onClick={() => reload()}>Retry</Button></div>
      : settings ? <AIEditors {...access} settings={settings} api={api} reload={reload} client={client} expectedScope={expectedScope} refreshQualifications={refreshQualifications} /> : <LoadingState label="Loading AI controls…" />}
  </div>;
}

function AIEditors({ settings, api, reload, client, expectedScope, refreshQualifications, canEditOrganization, canEditEnvironment, fresh, reauthenticate }: Access & {
  settings: AISettings; client: APIClient; expectedScope: string; refreshQualifications(): Promise<void>; api: ReturnType<typeof createAIControlsAPI>; reload(message?: string): void;
}) {
  const [editing, setEditing] = useState<Scope | null>(null);
  const [org, setOrg] = useState<OrganizationInput>({});
  const [env, setEnv] = useState<EnvironmentInput>({});
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [conflict, setConflict] = useState(false);
  const pending = useRef<AbortController | null>(null);
  useEffect(() => () => pending.current?.abort(), []);
  function cancel() { setEditing(null); setOrg({}); setEnv({}); setError(""); setConflict(false); }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!editing || !fresh || pending.current || conflict) return;
    const controller = new AbortController();
    pending.current = controller; setSaving(true); setError("");
    try {
      if (editing === "organization" && canEditOrganization) await api.updateOrganization(settings.organization.version, org, controller.signal);
      else if (editing === "environment" && canEditEnvironment) await api.updateEnvironment(settings.environment.version, env, controller.signal);
      else return;
      if (!controller.signal.aborted) reload(editing === "organization" ? "Organization AI policy saved." : "Environment AI controls saved.");
    } catch (cause) {
      if (controller.signal.aborted) return;
      if (cause instanceof APIProductError && [409, 412].includes(cause.status)) {
        setError("The policy changed while you were editing. Load the latest settings before saving."); setConflict(true);
      } else setError(cause instanceof APIProductError ? cause.product.message : "The change could not be confirmed. Reload to check the saved settings.");
    } finally { pending.current = null; if (!controller.signal.aborted) setSaving(false); }
  }
  function panel(scope: Scope, title: string, canEdit: boolean, fields: ReactNode) {
    const active = editing === scope;
    const dirty = Object.keys(scope === "organization" ? org : env).length > 0;
    return <Card title={<h2>{title}</h2>} action={!active && canEdit && <Button disabled={editing !== null || !fresh} onClick={() => setEditing(scope)}>Edit {scope} policy</Button>}>
      <form onSubmit={event => void save(event)}>
        <fieldset className="ai-form" aria-label={title} disabled={!active || !fresh || saving || conflict || !canEdit}>{fields}</fieldset>
        {active && <div className="ai-actions">
          <Button type="submit" variant="primary" disabled={!dirty || saving || !fresh || conflict || !canEdit}>{saving ? "Saving…" : "Save changes"}</Button>
          <Button type="button" disabled={saving} onClick={cancel}>Cancel</Button>
        </div>}
        {active && error && <p role="alert" className="error-banner">{error} <Button type="button" onClick={() => reload()}>Reload settings</Button></p>}
      </form>
    </Card>;
  }
  return <>
    <div className="ai-effective"><div><strong>Effective hosting mode</strong><p>{settings.environment.environment_class} environment · {settings.environment.collection_mode.replaceAll("_", " ")} collection</p></div><Badge tone={settings.environment.effective_mode === "deterministic_only" ? "neutral" : "info"}>{modeLabels[settings.environment.effective_mode]}</Badge></div>
    {!fresh && (canEditOrganization || canEditEnvironment) && <div role="status" className="ai-actions">Sign in again to change AI policies. <Button onClick={reauthenticate}>Reauthenticate</Button></div>}
    <div className="ai-panels">
      {panel("organization", "Organization AI policy", canEditOrganization, <OrganizationFields policy={{ ...settings.organization, ...org }} change={patch => setOrg(current => ({ ...current, ...patch }))} />)}
      {panel("environment", "Environment AI controls", canEditEnvironment, <EnvironmentFields settings={settings} draft={env} change={patch => setEnv(current => ({ ...current, ...patch }))} />)}
    </div>
    <Card title={<h2>Model qualifications</h2>}><div className="table-scroll"><Qualifications items={settings.qualifications} /></div><QualificationRunner client={client} expectedScope={expectedScope} environment={settings.environment} canEdit={canEditEnvironment} fresh={fresh} refreshQualifications={refreshQualifications} /></Card>
  </>;
}
