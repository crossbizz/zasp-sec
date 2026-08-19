"use client";

import { useCallback, useEffect, useState } from "react";

import { Badge, Button, Card, EmptyState, LoadingState, PageHeader, Select } from "../../components/ui";
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

export interface IdentityAdminAPI {
  listMembers(): Promise<IdentityMember[]>;
  updateMemberRole(id: string, role: string, version: number): Promise<IdentityMember>;
  listRoles(): Promise<IdentityRole[]>;
}

interface LoadedState {
  members: IdentityMember[];
  roles: IdentityRole[];
}

const emptyState: LoadedState = { members: [], roles: [] };

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

  const load = useCallback(async () => {
    try {
      if (!api) throw new Error("identity API unavailable");
      const [members, roles] = await Promise.all([
        api.listMembers(), api.listRoles(),
      ]);
      setState({ members, roles });
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
    <PageHeader title="Identity & Access" eyebrow="Administration" description="Manage durable product roles and group authorization. Provider administration is shown only when a complete provider boundary is installed." />
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
      <Card id="identity-provider" title={<h2>Enterprise identity</h2>}><Badge tone="neutral">Unavailable</Badge><p>SSO configuration and SCIM provisioning are not enabled because no complete provider configuration, verified webhook, reconciliation, and deprovisioning boundary is registered.</p></Card>
      <Card id="identity-groups" title={<h2>Group mappings</h2>}>
        <Badge tone="neutral">Unavailable</Badge>
		<p>Group mappings are hidden until verified provider group claims participate in effective authorization and deprovisioning.</p>
      </Card>
    </div>
  </div>;
}
