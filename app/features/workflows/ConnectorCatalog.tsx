"use client";

import { useState } from "react";

import type { ConnectorManifest } from "../../../apps/web/api/generated";
import { ProviderLogo } from "../../components/ProviderLogo";
import { Badge, Button } from "../../components/ui";

// Every source the product can read. One the deployment does not serve is
// still shown, marked as not enabled, so a person can see it exists and ask
// for it instead of concluding it is unsupported.
const known: readonly { key: string; name: string; category: string; description: string }[] = [
  { key: "aws", name: "Amazon Web Services", category: "cloud", description: "Bedrock agents, AgentCore runtimes and gateways, model-calling functions, roles and data stores, through a read-only role." },
  { key: "gcp", name: "Google Cloud", category: "cloud", description: "Vertex AI and Gemini Enterprise agents, service accounts and their roles, through a read-only service account." },
  { key: "microsoft", name: "Microsoft Entra and Copilot Studio", category: "saas", description: "Copilot Studio agents, Foundry agents, Entra agent identities and their owners." },
  { key: "kubernetes", name: "Kubernetes", category: "runtime", description: "Agent workloads, MCP servers and service accounts in one cluster." },
  { key: "github", name: "GitHub", category: "developer", description: "Agent projects, skills, instruction files and MCP configuration in repositories." },
  { key: "okta", name: "Okta", category: "identity", description: "AI applications people sign in to, service principals, and the groups that own them." },
  { key: "salesforce", name: "Salesforce Agentforce", category: "saas", description: "Agentforce agents, the user each runs as and its permission sets." },
  { key: "slack", name: "Slack", category: "collaboration", description: "AI apps installed in a workspace and what they may read." },
  { key: "saas-databricks", name: "Databricks", category: "saas", description: "Model serving endpoints, agents and the gateways in front of them." },
  { key: "saas-servicenow", name: "ServiceNow", category: "saas", description: "Now Assist agents and skills." },
  { key: "saas-google_workspace", name: "Google Workspace", category: "saas", description: "Gemini apps and third-party AI apps granted access to the domain." },
  { key: "saas-openai", name: "OpenAI", category: "saas", description: "Projects, assistants and API keys of an organization." },
  { key: "saas-anthropic", name: "Anthropic", category: "saas", description: "Workspaces and API keys of an organization." },
  { key: "saas-gitlab", name: "GitLab", category: "developer", description: "Duo agents and agent projects in groups." },
  { key: "saas-atlassian", name: "Atlassian", category: "saas", description: "Rovo agents in a site." },
  { key: "generic-webhook", name: "Generic Webhook", category: "notification", description: "Signed response and approval notifications to an HTTPS destination." },
];

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
  nango_sign_in: "Sign in",
  okta_oauth_pkce: "OAuth",
  github_app: "GitHub App",
};

function authLabel(mode: string): string {
  return authLabels[mode] ?? mode.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}


type Entry = { key: string; name: string; category: string; description: string; manifest?: ConnectorManifest };

export function ConnectorCatalog({ manifests, disabled, onChoose }: { manifests: readonly ConnectorManifest[]; disabled: boolean; onChoose(manifest: ConnectorManifest): void }) {
  const [query, setQuery] = useState("");
  const served = new Set(manifests.map((manifest) => manifest.key));
  const entries: Entry[] = [
    ...manifests.map((manifest) => ({ key: manifest.key, name: manifest.provider, category: manifest.category, description: manifest.description, manifest })),
    ...known.filter((entry) => !served.has(entry.key)),
  ];
  const needle = query.trim().toLowerCase();
  const shown = needle === "" ? entries : entries.filter((entry) => `${entry.name} ${entry.description} ${entry.category}`.toLowerCase().includes(needle));
  const groups = [...categories, { id: "", label: "Other" }].map((category) => ({ ...category, entries: shown.filter((entry) => category.id === "" ? !categories.some((value) => value.id === entry.category) : entry.category === category.id) })).filter((group) => group.entries.length > 0);
  return <div className="connector-catalog">
    <div className="table-toolbar">
      <input type="search" className="table-filter" aria-label="Filter connectors" placeholder="Search sources" value={query} maxLength={64} onChange={(event) => setQuery(event.target.value)} />
      <span className="table-count">{manifests.length} available · {entries.length - manifests.length} not enabled</span>
    </div>
    {groups.length === 0 && <p className="table-empty">No source matches “{query.trim()}”.</p>}
    {groups.map((group) => <section key={group.id || "other"} aria-label={group.label} className="connector-group">
      <h3 className="connector-group__title">{group.label}</h3>
      <div className="connector-grid">
        {group.entries.map((entry) => <article key={entry.key} className={`connector-card${entry.manifest ? "" : " connector-card--off"}`}>
          <div className="connector-card__head">
            <ProviderLogo provider={entry.key} />
            <div><h4>{entry.name}</h4>{entry.manifest ? <span className="connector-auth">{authLabel(entry.manifest.auth_mode)}</span> : <Badge tone="neutral">Not enabled</Badge>}</div>
          </div>
          <p>{entry.description}</p>
          {entry.manifest
            ? <Button variant="primary" disabled={disabled} aria-label={`Configure ${entry.name}`} onClick={() => onChoose(entry.manifest!)}>Connect</Button>
            : <small className="connector-card__note">This deployment does not serve this source. Your operator can enable it.</small>}
        </article>)}
      </div>
    </section>)}
  </div>;
}
