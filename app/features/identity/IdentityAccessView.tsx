"use client";

import { useCallback, useEffect, useState } from "react";

import { Badge, Button, Card, EmptyState, Field, LoadingState, PageHeader, Select } from "../../components/ui";
import { useOptionalIdentityAdminAPI } from "./IdentityAPIProvider";

export interface IdentityMember {
  id: string;
  memberReference: string;
  role: string;
  active: boolean;
}

export interface IdentityRole {
  role: string;
  permissions: string[];
}

export interface SSOConnectionItem {
  id: string;
  displayName: string;
  status: string;
  protocol: string;
  identityProvider: string;
}

export interface SCIMConnectionItem {
  id: string;
  displayName: string;
  status: string;
  identityProvider: string;
  baseUrl: string;
  bearerToken?: string;
}

export interface GroupMappingItem {
  groupReference: string;
  role: string;
  workspaceId: string;
  environmentId: string;
  version: number;
}

export interface GroupMappingUpdate {
  groupReference: string;
  role: string;
  workspaceId: string;
  environmentId: string;
  expectedVersion: number;
}

export interface IdentityAdminAPI {
  listMembers(): Promise<IdentityMember[]>;
  listRoles(): Promise<IdentityRole[]>;
  listSSO(): Promise<SSOConnectionItem[]>;
  createSSO(input: { displayName: string; protocol: string; identityProvider: string }): Promise<SSOConnectionItem>;
  testSSO(id: string): Promise<void>;
  deleteSSO(id: string): Promise<void>;
  listSCIM(): Promise<SCIMConnectionItem[]>;
  createSCIM(input: { displayName: string; identityProvider: string }): Promise<SCIMConnectionItem>;
  deleteSCIM(id: string): Promise<void>;
  listGroupMappings(): Promise<GroupMappingItem[]>;
  updateGroupMapping(input: GroupMappingUpdate): Promise<GroupMappingItem>;
}

interface LoadedState {
  members: IdentityMember[];
  roles: IdentityRole[];
  sso: SSOConnectionItem[];
  scim: SCIMConnectionItem[];
  mappings: GroupMappingItem[];
}

const emptyState: LoadedState = { members: [], roles: [], sso: [], scim: [], mappings: [] };

export function IdentityAccessView({ api: suppliedAPI }: { api?: IdentityAdminAPI }) {
  const contextAPI = useOptionalIdentityAdminAPI();
  const api = suppliedAPI ?? contextAPI;
  const [state, setState] = useState<LoadedState>(emptyState);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [ssoName, setSSOName] = useState("New SSO");
  const [ssoProtocol, setSSOProtocol] = useState("saml");
  const [scimName, setSCIMName] = useState("New SCIM");
  const [oneTimeToken, setOneTimeToken] = useState<string | null>(null);
  const [mapping, setMapping] = useState<GroupMappingUpdate>({
    groupReference: "", role: "read_only_viewer", workspaceId: "", environmentId: "", expectedVersion: 0,
  });
  const [mappingError, setMappingError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      if (!api) throw new Error("identity API unavailable");
      const [members, roles, sso, scim, mappings] = await Promise.all([
        api.listMembers(), api.listRoles(), api.listSSO(), api.listSCIM(), api.listGroupMappings(),
      ]);
      setState({ members, roles, sso, scim, mappings });
      if (mappings[0]) {
        setMapping({ ...mappings[0], expectedVersion: mappings[0].version });
      }
    } catch {
      setError("Identity data could not be loaded");
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    let active = true;
    queueMicrotask(() => { if (active) void load(); });
    return () => { active = false; };
  }, [load]);

  const action = async (operation: () => Promise<void>, success: string) => {
    setError(null);
    setNotice(null);
    try {
      await operation();
      setNotice(success);
    } catch {
      setError("Identity action could not be completed");
    }
  };

  if (loading) return <div className="page"><LoadingState label="Loading identity and access…" /></div>;

  return <div className="page identity-access">
    <PageHeader title="Identity & Access" eyebrow="Administration" description="Manage product roles, enterprise identity, provisioning, and group authorization." />
    <nav className="identity-section-nav" aria-label="Identity sections">
      <a href="#identity-members">Members</a>
      <a href="#identity-roles">Built-in roles</a>
      <a href="#identity-sso">SSO connections</a>
      <a href="#identity-scim">SCIM provisioning</a>
      <a href="#identity-groups">Group mappings</a>
    </nav>
    {error && <div className="error-banner" role="alert">{error}</div>}
    {notice && <div className="success-banner" role="status">{notice}</div>}
    <div className="identity-grid">
      <Card id="identity-members" title={<h2>Members</h2>}>
        {state.members.length === 0 ? <EmptyState title="No members" description="Provisioned members will appear here." /> :
          <ul className="identity-list">{state.members.map((member) => <li key={member.id}><span><strong>{member.memberReference}</strong><small>{member.role}</small></span><Badge tone={member.active ? "success" : "neutral"}>{member.active ? "Active" : "Disabled"}</Badge></li>)}</ul>}
      </Card>
      <Card id="identity-roles" title={<h2>Built-in roles</h2>}>
        {state.roles.length === 0 ? <EmptyState title="No roles" /> :
          <ul className="identity-list">{state.roles.map((role) => <li key={role.role}><span><strong>{role.role.replaceAll("_", " ")}</strong><small>{role.permissions.join(" · ")}</small></span></li>)}</ul>}
      </Card>
      <Card id="identity-sso" title={<h2>SSO connections</h2>}>
        <div className="identity-form-row">
          <Field label="SSO display name" value={ssoName} onChange={(event) => setSSOName(event.target.value)} />
          <Select label="Protocol" value={ssoProtocol} onChange={(event) => setSSOProtocol(event.target.value)}><option value="saml">SAML</option><option value="oidc">OIDC</option></Select>
          <Button variant="primary" onClick={() => void action(async () => {
            if (!api) throw new Error("identity API unavailable");
            const created = await api.createSSO({ displayName: ssoName, protocol: ssoProtocol, identityProvider: "generic" });
            setState((current) => ({ ...current, sso: [...current.sso, created] }));
          }, "SSO connection created")}>Create SSO connection</Button>
        </div>
        <ul className="identity-list">{state.sso.map((connection) => <li key={connection.id}><span><strong>{connection.displayName}</strong><small>{connection.protocol.toUpperCase()} · {connection.status}</small></span><div className="row-actions"><Button aria-label={`Test ${connection.displayName}`} onClick={() => void action(async () => { if (!api) throw new Error("identity API unavailable"); await api.testSSO(connection.id); }, "SSO connection is healthy")}>Test</Button><Button variant="danger" aria-label={`Delete ${connection.displayName}`} onClick={() => { if (window.confirm(`Delete ${connection.displayName}?`)) void action(async () => { if (!api) throw new Error("identity API unavailable"); await api.deleteSSO(connection.id); setState((current) => ({ ...current, sso: current.sso.filter((item) => item.id !== connection.id) })); }, "SSO connection deleted"); }}>Delete</Button></div></li>)}</ul>
      </Card>
      <Card id="identity-scim" title={<h2>SCIM provisioning</h2>}>
        <div className="identity-form-row"><Field label="SCIM display name" value={scimName} onChange={(event) => setSCIMName(event.target.value)} /><Button variant="primary" onClick={() => void action(async () => {
          if (!api) throw new Error("identity API unavailable");
          const created = await api.createSCIM({ displayName: scimName, identityProvider: "generic" });
          setOneTimeToken(created.bearerToken ?? null);
          setState((current) => ({ ...current, scim: [...current.scim, created] }));
        }, "SCIM connection created")}>Create SCIM connection</Button></div>
        {oneTimeToken && <div className="credential-once">Save this bearer token now: {oneTimeToken}</div>}
        <ul className="identity-list">{state.scim.map((connection) => <li key={connection.id}><span><strong>{connection.displayName}</strong><small>{connection.status} · {connection.baseUrl}</small></span><Button variant="danger" aria-label={`Delete ${connection.displayName}`} onClick={() => { if (window.confirm(`Delete ${connection.displayName}?`)) void action(async () => { if (!api) throw new Error("identity API unavailable"); await api.deleteSCIM(connection.id); setState((current) => ({ ...current, scim: current.scim.filter((item) => item.id !== connection.id) })); }, "SCIM connection deleted"); }}>Delete</Button></li>)}</ul>
      </Card>
      <Card id="identity-groups" title={<h2>Group mappings</h2>}>
        <div className="identity-form-grid">
          <Field label="IdP group reference" value={mapping.groupReference} error={mappingError ?? undefined} onChange={(event) => setMapping({ ...mapping, groupReference: event.target.value })} />
          <Select label="Built-in role" value={mapping.role} onChange={(event) => setMapping({ ...mapping, role: event.target.value })}>{["organization_admin", "security_admin", "security_engineer", "developer_owner", "compliance_viewer", "read_only_viewer"].map((role) => <option key={role} value={role}>{role.replaceAll("_", " ")}</option>)}</Select>
          <Field label="Workspace ID" value={mapping.workspaceId} onChange={(event) => setMapping({ ...mapping, workspaceId: event.target.value })} />
          <Field label="Environment ID" value={mapping.environmentId} onChange={(event) => setMapping({ ...mapping, environmentId: event.target.value })} />
        </div>
        <Button variant="primary" onClick={() => {
          if (!/^idp-group-[A-Za-z0-9_-]+$/.test(mapping.groupReference)) { setMappingError("Enter a valid IdP group reference"); return; }
          setMappingError(null);
          void action(async () => {
            if (!api) throw new Error("identity API unavailable");
            const saved = await api.updateGroupMapping(mapping);
            setMapping({ ...saved, expectedVersion: saved.version });
            setState((current) => ({ ...current, mappings: [...current.mappings.filter((item) => item.groupReference !== saved.groupReference), saved] }));
          }, "Group mapping saved");
        }}>Save group mapping</Button>
        <ul className="identity-list">{state.mappings.map((item) => <li key={item.groupReference}><span><strong>{item.groupReference}</strong><small>{item.role} · version {item.version}</small></span></li>)}</ul>
      </Card>
    </div>
  </div>;
}
