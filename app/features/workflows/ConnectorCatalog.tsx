"use client";

import { useEffect, useRef, useState } from "react";

import type { ConnectorManifest } from "../../../apps/web/api/generated";
import { ProviderLogo } from "../../components/ProviderLogo";
import { Button } from "../../components/ui";

const categories: readonly { id: string; label: string }[] = [
  { id: "cloud", label: "Cloud" },
  { id: "saas", label: "SaaS and AI platforms" },
  { id: "runtime", label: "Runtime" },
  { id: "developer", label: "Code" },
  { id: "identity", label: "Identity" },
  { id: "collaboration", label: "Collaboration" },
  { id: "notification", label: "Notifications" },
];

const authLabels: Readonly<Record<string, string>> = {
  aws_assume_role: "Read-only role",
  credential_reference: "Credential reference",
  kubernetes_service_account: "Service account",
  signed_webhook: "Signed webhook",
  secret_reference: "Secret reference",
  nango_connection: "Managed connection",
  managed_oauth: "Workspace authorization only",
  nango_sign_in: "Sign in",
  okta_oauth_pkce: "OAuth",
  github_app: "GitHub App",
};

function authLabel(mode: string): string {
  return authLabels[mode] ?? mode.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

type CatalogProps = {
  manifests: readonly ConnectorManifest[];
  disabled: boolean;
  focusSearch?: boolean;
  onChoose(manifest: ConnectorManifest): void;
  onRefresh(): Promise<void>;
};

export function ConnectorCatalog({ manifests, disabled, focusSearch, onChoose, onRefresh }: CatalogProps) {
  const [query, setQuery] = useState("");
  const search = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (focusSearch) search.current?.focus();
  }, [focusSearch]);
  const needle = query.trim().toLowerCase();
  // One Slack registration can enable both discovery and the older
  // workspace scope check. Keep its full manifest for saved records.
  const discoverySlack = manifests.some(entry => entry.platform === "slack");
  const offered = discoverySlack ? manifests.filter(entry => entry.key !== "slack") : manifests;
  const shown = offered.filter(entry => `${entry.provider} ${entry.description} ${entry.category}`.toLowerCase().includes(needle));
  const groups = [...categories, { id: "", label: "Other" }].map(category => ({
    ...category,
    entries: shown.filter(entry => category.id === "" ? !categories.some(value => value.id === entry.category) : entry.category === category.id),
  })).filter(group => group.entries.length > 0);

  return <div className="connector-catalog" id="add-source">
    <div className="table-toolbar">
      <input ref={search} type="search" className="table-filter" aria-label="Filter connectors" placeholder="Search sources" value={query} maxLength={64} onChange={event => setQuery(event.target.value)} />
      <span className="table-count">{shown.length} {shown.length === 1 ? "source" : "sources"}</span>
    </div>
    {shown.length === 0 && (manifests.length > 0
      ? <p className="table-empty">No source matches “{query.trim()}”.</p>
      : <div className="table-empty">
        <p>No Nango integrations are available.</p>
        <p>Ask your deployment operator to configure a supported provider in Nango. On Kubernetes, open the private dashboard with <code>./zasp --profile kubernetes nango dashboard</code>. In the linked environment (normally <code>prod</code>), add the provider with its Zasp integration key, such as <code>openai-admin</code> for OpenAI.</p>
        <Button disabled={disabled} onClick={onRefresh}>Refresh sources</Button>
      </div>)}
    {groups.map(group => <section key={group.id || "other"} aria-label={group.label} className="connector-group">
      <h3 className="connector-group__title">{group.label}</h3>
      <div className="connector-grid">
        {group.entries.map(entry => <article key={entry.key} className="connector-card">
          <div className="connector-card__head">
            <ProviderLogo provider={entry.key} />
            <div><h4>{entry.provider}</h4><span className="connector-auth">{authLabel(entry.auth_mode)}</span></div>
          </div>
          <p>{entry.description}</p>
          <Button variant="primary" disabled={disabled} aria-label={`Configure ${entry.provider}`} onClick={() => onChoose(entry)}>Connect</Button>
        </article>)}
      </div>
    </section>)}
  </div>;
}
