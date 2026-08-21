"use client";

import { useCallback, useEffect, useState } from "react";

import { Badge, Button, Card, EmptyState, Field, LoadingState, PageHeader, Select } from "../../components/ui";
import { useOptionalSession } from "../../auth/SessionProvider";
import { useOptionalIdentityAdminAPI } from "./IdentityAPIProvider";

export interface IdentityMember {
  id: string;
  memberReference: string;
  role: string;
  active: boolean;
  version: number;
}

export interface IdentityRole {
  role: string;
  permissions: string[];
}

export interface IdentitySSOConnection {
  id: string;
  status: "active" | "pending" | "disabled";
  displayName: string;
  protocol: "saml" | "oidc";
  identityProvider: string;
}

export interface IdentitySCIMConnection {
  id: string;
  status: "active" | "pending" | "disabled";
  displayName: string;
  identityProvider: string;
  baseURL: string;
}

export interface IdentitySCIMCredential extends IdentitySCIMConnection {
  bearerToken: string;
}

export interface IdentityAdminAPI {
  listMembers(): Promise<IdentityMember[]>;
  updateMemberRole(id: string, role: string, version: number): Promise<IdentityMember>;
  listRoles(): Promise<IdentityRole[]>;
  listSSOConnections(): Promise<IdentitySSOConnection[]>;
  createSSOConnection(input: { displayName: string; protocol: "saml" | "oidc"; identityProvider: string }): Promise<IdentitySSOConnection>;
  deleteSSOConnection(id: string): Promise<void>;
  testSSOConnection(id: string): Promise<void>;
  listSCIMConnections(): Promise<IdentitySCIMConnection[]>;
  createSCIMConnection(input: { displayName: string; identityProvider: string }): Promise<IdentitySCIMCredential>;
  deleteSCIMConnection(id: string): Promise<void>;
}

interface LoadedState {
  members: IdentityMember[];
  roles: IdentityRole[];
  ssoConnections: IdentitySSOConnection[];
  scimConnections: IdentitySCIMConnection[];
}

const emptyState: LoadedState = { members: [], roles: [], ssoConnections: [], scimConnections: [] };

export function IdentityAccessView({ api: suppliedAPI }: { api?: IdentityAdminAPI }) {
  const contextAPI = useOptionalIdentityAdminAPI();
  const api = suppliedAPI ?? contextAPI;
	const session = useOptionalSession();
	const fresh = session?.status === "authenticated" ? session.isFreshAuthenticated : true;
  const [state, setState] = useState<LoadedState>(emptyState);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [roleDrafts, setRoleDrafts] = useState<Record<string, string>>({});
  const [ssoDisplayName, setSSODisplayName] = useState("");
  const [ssoProtocol, setSSOProtocol] = useState<"saml" | "oidc">("saml");
  const [ssoProvider, setSSOProvider] = useState("generic");
  const [scimDisplayName, setSCIMDisplayName] = useState("");
  const [scimProvider, setSCIMProvider] = useState("generic");
  const [revealedCredential, setRevealedCredential] = useState<IdentitySCIMCredential | null>(null);

  const load = useCallback(async () => {
    try {
      if (!api) throw new Error("identity API unavailable");
      const [members, roles, ssoConnections, scimConnections] = await Promise.all([
        api.listMembers(), api.listRoles(), api.listSSOConnections(), api.listSCIMConnections(),
      ]);
      setState({ members, roles, ssoConnections, scimConnections });
      setRoleDrafts(Object.fromEntries(members.map((member) => [member.id, member.role])));
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
    <PageHeader title="Identity & Access" eyebrow="Administration" description="Manage tenant-scoped roles, enterprise SSO, and SCIM provisioning." />
    <nav className="identity-section-nav" aria-label="Identity sections">
      <a href="#identity-members">Members</a>
      <a href="#identity-roles">Built-in roles</a>
      <a href="#identity-provider">Enterprise identity</a>
      <a href="#identity-groups">Group mappings</a>
    </nav>
    {error && <div className="error-banner" role="alert">{error}</div>}
    {notice && <div className="success-banner" role="status">{notice}</div>}
	{!fresh && <div className="error-banner" role="alert">Fresh authentication expired. <Button onClick={() => session?.reauthenticate()}>Reauthenticate</Button></div>}
    <div className="identity-grid">
      <Card id="identity-members" title={<h2>Members</h2>}>
        {state.members.length === 0 ? <EmptyState title="No members" description="Provisioned members will appear here." /> :
          <ul className="identity-list">{state.members.map((member) => <li key={member.id}><span><strong>{member.memberReference}</strong><small>version {member.version}</small></span><div className="row-actions"><Select disabled={!fresh} label={`Role for ${member.memberReference}`} value={roleDrafts[member.id] ?? member.role} onChange={(event) => setRoleDrafts((current) => ({ ...current, [member.id]: event.target.value }))}>{state.roles.map((roleValue) => <option key={roleValue.role} value={roleValue.role}>{roleValue.role.replaceAll("_", " ")}</option>)}</Select><Button disabled={!fresh || !member.active || (roleDrafts[member.id] ?? member.role) === member.role} onClick={() => void action(async () => { if (!api) throw new Error(); const updated = await api.updateMemberRole(member.id, roleDrafts[member.id] ?? member.role, member.version); setState((current) => ({ ...current, members: current.members.map((item) => item.id === updated.id ? updated : item) })); }, "Member role updated; active sessions revoked")}>Update role</Button><Badge tone={member.active ? "success" : "neutral"}>{member.active ? "Active" : "Disabled"}</Badge></div></li>)}</ul>}
      </Card>
      <Card id="identity-roles" title={<h2>Built-in roles</h2>}>
        {state.roles.length === 0 ? <EmptyState title="No roles" /> :
          <ul className="identity-list">{state.roles.map((role) => <li key={role.role}><span><strong>{role.role.replaceAll("_", " ")}</strong><small>{role.permissions.join(" · ")}</small></span></li>)}</ul>}
      </Card>
      <Card id="identity-provider" title={<h2>Enterprise identity</h2>}>
        <Badge tone="success">Configured</Badge>
        <p>Connections are isolated to this organization and reconciled against the configured identity provider.</p>
        <h3>Single sign-on</h3>
        <div className="form-grid">
          <Field label="SSO display name" value={ssoDisplayName} maxLength={128} disabled={!fresh} onChange={(event) => setSSODisplayName(event.target.value)} />
          <Select label="SSO protocol" value={ssoProtocol} disabled={!fresh} onChange={(event) => setSSOProtocol(event.target.value as "saml" | "oidc")}><option value="saml">SAML</option><option value="oidc">OIDC</option></Select>
          <Select label="SSO identity provider" value={ssoProvider} disabled={!fresh} onChange={(event) => setSSOProvider(event.target.value)}><option value="generic">Generic</option><option value="okta">Okta</option><option value="microsoft-entra">Microsoft Entra</option><option value="google-workspace">Google Workspace</option></Select>
          <Button disabled={!fresh || ssoDisplayName.trim().length === 0} onClick={() => void action(async () => { if (!api) throw new Error(); const created = await api.createSSOConnection({ displayName: ssoDisplayName.trim(), protocol: ssoProtocol, identityProvider: ssoProvider }); setState((current) => ({ ...current, ssoConnections: [...current.ssoConnections, created] })); setSSODisplayName(""); }, "SSO connection created")}>Add SSO connection</Button>
        </div>
        {state.ssoConnections.length === 0 ? <EmptyState title="No SSO connections" description="Add the first connection for this organization." /> : <ul className="identity-list">{state.ssoConnections.map((connection) => <li key={connection.id}><span><strong>{connection.displayName}</strong><small>{connection.protocol.toUpperCase()} · {connection.identityProvider}</small></span><div className="row-actions"><Badge tone={connection.status === "active" ? "success" : "warning"}>{connection.status}</Badge><Button disabled={!fresh || connection.status !== "active"} onClick={() => void action(async () => { if (!api) throw new Error(); await api.testSSOConnection(connection.id); }, `${connection.displayName} connection is healthy`)}>Test {connection.displayName}</Button><Button variant="danger" disabled={!fresh} onClick={() => void action(async () => { if (!api) throw new Error(); await api.deleteSSOConnection(connection.id); setState((current) => ({ ...current, ssoConnections: current.ssoConnections.filter((item) => item.id !== connection.id) })); }, "SSO connection deleted")}>Delete {connection.displayName}</Button></div></li>)}</ul>}
        <h3>SCIM provisioning</h3>
        <div className="form-grid">
          <Field label="SCIM display name" value={scimDisplayName} maxLength={128} disabled={!fresh} onChange={(event) => setSCIMDisplayName(event.target.value)} />
          <Select label="SCIM identity provider" value={scimProvider} disabled={!fresh} onChange={(event) => setSCIMProvider(event.target.value)}><option value="generic">Generic</option><option value="okta">Okta</option><option value="microsoft-entra">Microsoft Entra</option></Select>
          <Button disabled={!fresh || scimDisplayName.trim().length === 0} onClick={() => void action(async () => { if (!api) throw new Error(); const created = await api.createSCIMConnection({ displayName: scimDisplayName.trim(), identityProvider: scimProvider }); setState((current) => ({ ...current, scimConnections: [...current.scimConnections, created] })); setRevealedCredential(created); setSCIMDisplayName(""); }, "SCIM connection created")}>Add SCIM connection</Button>
        </div>
        {revealedCredential && <div className="success-banner" role="status"><strong>Copy the SCIM bearer token now. It will not appear in connection lists.</strong><code>{revealedCredential.bearerToken}</code><Button onClick={() => setRevealedCredential(null)}>Hide token</Button></div>}
        {state.scimConnections.length === 0 ? <EmptyState title="No SCIM connections" description="Add the first provisioning connection for this organization." /> : <ul className="identity-list">{state.scimConnections.map((connection) => <li key={connection.id}><span><strong>{connection.displayName}</strong><small>{connection.identityProvider} · {connection.baseURL}</small></span><div className="row-actions"><Badge tone={connection.status === "active" ? "success" : "warning"}>{connection.status}</Badge><Button variant="danger" disabled={!fresh} onClick={() => void action(async () => { if (!api) throw new Error(); await api.deleteSCIMConnection(connection.id); setState((current) => ({ ...current, scimConnections: current.scimConnections.filter((item) => item.id !== connection.id) })); }, "SCIM connection deleted")}>Delete {connection.displayName}</Button></div></li>)}</ul>}
      </Card>
      <Card id="identity-groups" title={<h2>Group mappings</h2>}>
        <Badge tone="neutral">Unavailable</Badge>
		<p>Group mappings are hidden until verified provider group claims participate in effective authorization and deprovisioning.</p>
      </Card>
    </div>
  </div>;
}
