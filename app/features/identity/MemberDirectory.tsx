"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import type { MemberAccessScope, MemberInvitation, MemberInvitationInput } from "../../../apps/web/api/generated";
import { APIProductError } from "../../../apps/web/api/client";
import { Badge, Button, Card, EmptyState, Field, LoadingState, Modal, SearchBox, Select, Tabs } from "../../components/ui";
import type { IdentityAdminAPI, IdentityMember, IdentityRole } from "./IdentityAccessView";

type Props = {
  heading: ReactNode;
  api: IdentityAdminAPI;
  roles: IdentityRole[];
  fresh: boolean;
  selfID?: string;
  scopeLabel?: string;
  organizationName?: string;
};

function memberName(member: IdentityMember) {
  return member.displayName || member.email || member.memberReference;
}

function roleLabel(role: string) {
  return role.replaceAll("_", " ").replace(/^./, letter => letter.toUpperCase());
}

function writeError(cause: unknown) {
  if (cause instanceof APIProductError) {
    if (cause.status === 412 || cause.product.code === "version_conflict") return "This record changed. Close this dialog and refresh the directory before trying again.";
    if (cause.status === 409) return "This change conflicts with the current membership. Refresh the directory and check the member’s status and role.";
    if (cause.status === 403) return "You do not have permission for this change, or your sign-in has expired.";
  }
  return "The change could not be confirmed. Refresh the directory to check its status.";
}

export function MemberDirectory({ heading, api, roles, fresh, selfID, scopeLabel, organizationName }: Props) {
  const [tab, setTab] = useState("members");
  const [search, setSearch] = useState("");
  const [revision, setRevision] = useState(0);
  const [members, setMembers] = useState<IdentityMember[]>([]);
  const [invitations, setInvitations] = useState<readonly MemberInvitation[]>([]);
  const [readState, setReadState] = useState<"loading" | "ready" | "error">("loading");
  const [inviting, setInviting] = useState(false);
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const selected = members.find(member => member.id === selectedID);

  useEffect(() => {
    let current = true;
    const read = async () => {
      try {
        if (tab === "members") {
          const values = await api.listMembers();
          if (current) setMembers(values);
        } else {
          const values = await api.listInvitations();
          if (current) setInvitations(values);
        }
        if (current) setReadState("ready");
      } catch {
        if (current) setReadState("error");
      }
    };
    void read();
    return () => { current = false; };
  }, [api, tab, revision]);

  function refresh() {
    setReadState("loading");
    setRevision(value => value + 1);
  }
  function changeTab(next: string) {
    if (next === tab) return;
    setSearch("");
    setNotice("");
    setReadState("loading");
    setTab(next);
  }
  const needle = search.trim().toLocaleLowerCase();
  const matches = (...parts: (string | undefined)[]) => parts.some(part => part?.toLocaleLowerCase().includes(needle));
  const filteredMembers = members.filter(member => matches(member.displayName, member.email, member.memberReference));
  const filteredInvites = invitations.filter(invite => matches(invite.display_name, invite.email));
  const isMembers = tab === "members";

  return <Card className="member-directory" title={heading}
    action={<Button variant="primary" disabled={!fresh || roles.length === 0} onClick={() => { setNotice(""); setInviting(true); }}>Invite member</Button>}>
    <Tabs active={tab} tabs={[{ id: "members", label: "Directory" }, { id: "invitations", label: "Invitations" }]} onChange={changeTab} />
    <div className="member-toolbar">
      <SearchBox aria-label={isMembers ? "Search members" : "Search invitations"} placeholder="Search by name or email" value={search} onChange={event => setSearch(event.target.value)} />
      <Button disabled={readState === "loading"} onClick={refresh}>Refresh</Button>
    </div>
    {notice && <p role="status" className="success-banner">{notice}</p>}
    {readState === "loading" && <LoadingState label={isMembers ? "Loading members…" : "Loading invitations…"} />}
    {readState === "error" && <p role="alert" className="error-banner">{isMembers ? "Members" : "Invitations"} could not be loaded. Refresh to try again.</p>}
    {readState === "ready" && (isMembers ? filteredMembers.length > 0 : filteredInvites.length > 0) &&
      <table className="data-table member-table" aria-label={isMembers ? "Organization members" : "Organization invitations"}>
        <thead><tr><th scope="col">Name and email</th><th scope="col">Role</th><th scope="col">Status</th>{isMembers && <th scope="col">Actions</th>}</tr></thead>
        <tbody>{isMembers ? filteredMembers.map(member => <tr key={member.id}>
          <th scope="row"><strong>{memberName(member)}</strong><small>{member.email && member.displayName ? member.email : !member.email ? "Email unavailable" : ""}</small></th>
          <td data-label="Role">{roleLabel(member.role)}</td><td data-label="Status"><Badge tone={member.active ? "success" : "neutral"}>{member.active ? "Active" : "Disabled"}</Badge></td>
          <td><Button aria-label={`Manage ${memberName(member)}`} onClick={() => { setNotice(""); setSelectedID(member.id); }}>Manage</Button></td>
        </tr>) : filteredInvites.map(invite => <tr key={invite.id}>
          <th scope="row"><strong>{invite.display_name || invite.email}</strong>{invite.display_name && <small>{invite.email}</small>}</th>
          <td data-label="Role">{roleLabel(invite.role)}</td><td data-label="Status"><Badge tone={invite.status === "pending" ? "warning" : "success"}>{roleLabel(invite.status)}</Badge></td>
        </tr>)}</tbody>
      </table>}
    {readState === "ready" && (isMembers ? !filteredMembers.length : !filteredInvites.length) &&
      <EmptyState title={needle ? "No matches" : isMembers ? "No members" : "No invitations"} description={needle ? "Try another name or email." : "Invite someone to this organization to get started."} />}
    {inviting && <InviteMemberDialog api={api} roles={roles} fresh={fresh} scopeLabel={scopeLabel} organizationName={organizationName} close={() => setInviting(false)} onInvited={invite => {
      setInviting(false);
      setSearch("");
      setTab("invitations");
      refresh();
      setNotice(`Invitation pending for ${invite.email}.`);
    }} />}
    {selected && <MemberDetails key={selected.id} api={api} member={selected} roles={roles} fresh={fresh} isSelf={selfID === selected.id} organizationName={organizationName} close={() => setSelectedID(null)} onChanged={(member, message) => {
      // A mutation can return a durable membership without directory-enriched profile fields.
      setMembers(current => current.map(existing => existing.id === member.id
        ? { ...member, displayName: member.displayName ?? existing.displayName, email: member.email ?? existing.email }
        : existing));
      setSelectedID(null);
      setNotice(message);
    }} />}
  </Card>;
}

function InviteMemberDialog({ api, roles, fresh, scopeLabel, organizationName, close, onInvited }: Pick<Props, "api" | "roles" | "fresh" | "scopeLabel" | "organizationName"> & {
  close(): void; onInvited(invite: MemberInvitation): void;
}) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState(roles.some(value => value.role === "read_only_viewer") ? "read_only_viewer" : "");
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const [error, setError] = useState("");
  return <Modal open title="Invite member" onClose={close} closeDisabled={busy}>
    <form className="member-form" onSubmit={async event => {
      event.preventDefault();
      if (inFlight.current || !fresh || !role || !name.trim()) return;
      inFlight.current = true;
      setBusy(true);
      setError("");
      try {
        const invitation = await api.inviteMember({ email: email.trim(), display_name: name.trim(), role: role as MemberInvitationInput["role"] });
        onInvited(invitation);
      } catch (cause) {
        setError(writeError(cause));
      } finally { inFlight.current = false; setBusy(false); }
    }}>
      <Field required label="Email address" type="email" maxLength={254} value={email} disabled={!fresh || busy} onChange={event => setEmail(event.target.value)} />
      <Field required label="Display name" maxLength={128} value={name} disabled={!fresh || busy} onChange={event => setName(event.target.value)} />
      <Select label="Initial role" disabled={!fresh || busy} value={role} onChange={event => setRole(event.target.value)}>
        <option value="" disabled>Choose a role</option>{roles.map(item => <option key={item.role} value={item.role}>{roleLabel(item.role)}</option>)}
      </Select>
      <p>The invitation grants membership in {organizationName || "this organization"} with initial access to {scopeLabel || "the selected workspace and environment"}.</p>
      {error && <p role="alert" className="error-banner">{error}</p>}
      {!fresh && <p role="alert">Close this dialog and reauthenticate to send the invitation.</p>}
      <div className="member-form-actions"><Button type="button" disabled={busy} onClick={close}>Cancel</Button>
        <Button variant="primary" type="submit" disabled={!fresh || busy || !email.trim() || !name.trim() || !role}>{busy ? "Sending…" : "Send invitation"}</Button></div>
    </form>
  </Modal>;
}

function MemberDetails({ api, member, roles, fresh, isSelf, organizationName, close, onChanged }: Pick<Props, "api" | "roles" | "fresh" | "organizationName"> & {
  member: IdentityMember; isSelf: boolean; close(): void; onChanged(member: IdentityMember, message: string): void;
}) {
  const [tab, setTab] = useState("profile");
  const [name, setName] = useState(member.displayName || "");
  const [role, setRole] = useState(member.role);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const writable = member.active && fresh && !busy;
  const identity = memberName(member);

  async function save(operation: () => Promise<IdentityMember>, message: string) {
    if (!writable || inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError("");
    try { onChanged(await operation(), message); }
    catch (cause) { setError(writeError(cause)); }
    finally { inFlight.current = false; setBusy(false); }
  }

  return <Modal open title={confirmRemove ? "Remove organization access?" : identity} onClose={close} closeDisabled={busy}>
    {(!fresh || error) && <p role="alert" className="error-banner">{error || "Close this dialog and reauthenticate to make changes."}</p>}
    {confirmRemove ? <div className="member-form">
      <p><strong>{identity}</strong> will lose access to {organizationName || "this organization"} and its workspaces and environments. Their active sessions will be revoked.</p>
      <div className="member-form-actions"><Button disabled={busy} onClick={() => { setConfirmRemove(false); setError(""); }}>Cancel</Button>
        <Button variant="danger" disabled={!writable || isSelf} onClick={() => void save(() => api.removeMember(member.id, member.version), `Removed organization access for ${identity}.`)}>Confirm removal</Button></div>
    </div> : <>
      <Tabs active={tab} tabs={[{ id: "profile", label: "Profile and role" }, { id: "access", label: "Workspace access" }]} onChange={value => { if (!busy) { setTab(value); setError(""); } }} />
      {tab === "access" ? <MemberAccess api={api} id={member.id} /> : <div className="member-form">
        {member.email && <p>{member.email}</p>}
        <form className="member-edit-action" onSubmit={event => { event.preventDefault(); if (name.trim() && name.trim() !== member.displayName) void save(() => api.updateMemberProfile(member.id, name.trim(), member.version), "Member profile updated."); }}>
          <Field label="Display name" maxLength={128} required value={name} disabled={!writable} onChange={event => setName(event.target.value)} />
          <Button type="submit" disabled={!writable || !name.trim() || name.trim() === member.displayName}>Save name</Button>
        </form>
        <div className="member-edit-action"><Select label="Organization role" value={role} disabled={!writable} onChange={event => setRole(event.target.value)}>
          {roles.map(item => <option key={item.role} value={item.role}>{roleLabel(item.role)}</option>)}
        </Select><Button disabled={!writable || role === member.role || !roles.some(item => item.role === role)} onClick={() => void save(() => api.updateMemberRole(member.id, role, member.version), "Member role updated; active sessions revoked")}>Update role</Button></div>
        <p>Changing this role revokes the member’s active sessions.</p>
        {member.active && !isSelf && <div className="member-form-actions"><Button variant="danger" disabled={!writable} onClick={() => { setError(""); setConfirmRemove(true); }}>Remove from organization</Button></div>}
      </div>}
    </>}
  </Modal>;
}

function MemberAccess({ api, id }: { api: IdentityAdminAPI; id: string }) {
  const [items, setItems] = useState<readonly MemberAccessScope[] | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let current = true;
    void api.memberAccess(id).then(result => { if (current) setItems(result); }).catch(() => { if (current) setFailed(true); });
    return () => { current = false; };
  }, [id, api]);
  if (failed) return <p role="alert" className="error-banner">Access details could not be loaded. Reopen this tab to try again.</p>;
  if (!items) return <LoadingState label="Loading access details…" />;
  if (!items.length) return <EmptyState title="No workspace access" description="This member has no authorized environments in this organization." />;
  return <ul className="member-scope-list">{items.map(scope => <li key={scope.workspace_id + "/" + scope.environment_id + "/" + scope.role}>
    <strong>{scope.workspace_name} / {scope.environment_name}</strong><span>{roleLabel(scope.role)}</span>
    <p>{scope.permissions.map(roleLabel).join(", ") || "No permissions"}</p>
  </li>)}</ul>;
}
