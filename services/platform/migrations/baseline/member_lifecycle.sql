-- Member administration. Provider references are bound to the customer by the
-- administrator's verified membership. A delivered invitation grants nothing
-- until sign-in proves the same provider organization and member.
CREATE TABLE IF NOT EXISTS public.zasp_member_profiles(
 organization_id text NOT NULL, principal_id text NOT NULL, display_name text NOT NULL, email text,
 PRIMARY KEY(organization_id,principal_id),
 CHECK (length(display_name) >= 1 AND length(display_name) <= 128 AND display_name=btrim(display_name)),
 CHECK (email IS NULL OR (length(email) >= 3 AND length(email) <= 254 AND email=lower(email)))
);
CREATE TABLE IF NOT EXISTS public.zasp_member_invitations(
 id text PRIMARY KEY CHECK(public.zasp_valid_product_id(id)),
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 organization_reference text NOT NULL, member_reference text,
 email text NOT NULL CHECK(length(email) >= 3 AND length(email) <= 254 AND email=lower(email)),
 display_name text NOT NULL CHECK(length(display_name) >= 1 AND length(display_name) <= 128 AND display_name=btrim(display_name)),
 role text NOT NULL CHECK(role IN('organization_admin','security_admin','security_engineer','developer_owner','compliance_viewer','read_only_viewer')),
 status text NOT NULL CHECK(status IN('delivering','pending','accepted','expired')),
 actor_id text NOT NULL, idempotency_key text NOT NULL, lease_id text NOT NULL,
 lease_until timestamptz NOT NULL, expires_at timestamptz,
 UNIQUE(organization_id,actor_id,idempotency_key),
 CHECK (status='delivering' OR (member_reference IS NOT NULL AND expires_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS zasp_member_invitations_pending_email ON public.zasp_member_invitations(organization_id,email) WHERE status IN('delivering','pending');
CREATE UNIQUE INDEX IF NOT EXISTS zasp_member_invitations_pending_identity ON public.zasp_member_invitations(organization_reference,member_reference) WHERE status='pending';
ALTER TABLE public.zasp_member_profiles OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_member_invitations OWNER TO zasp_discovery_authority;
REVOKE ALL ON TABLE public.zasp_member_profiles,public.zasp_member_invitations FROM PUBLIC;

CREATE OR REPLACE FUNCTION zasp_authorization80.member_value(o text,i text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT jsonb_strip_nulls(jsonb_build_object('id',m.principal_id,'organization_id',m.organization_id,
  'organization_reference',m.organization_reference,'member_reference',m.member_reference,'role',m.role,
  'active',m.active,'version',m.version,'email',profile.email,'display_name',profile.display_name))
 FROM public.zasp_identity_memberships m LEFT JOIN public.zasp_member_profiles profile USING(organization_id,principal_id)
 WHERE (m.organization_id,m.principal_id)=(o,i)
$$;

CREATE OR REPLACE FUNCTION zasp_authorization80.member_page(o text,w text,e text,actor text,a text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.require_identity_read('listMembers',o,w,e,actor);
 IF NOT COALESCE(n BETWEEN 1 AND 101 AND a IS NOT NULL AND (a='' OR public.zasp_valid_product_id(a)),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid member page'; END IF;
 RETURN (SELECT jsonb_build_object('items',COALESCE(jsonb_agg(zasp_authorization80.member_value(o,p.principal_id) ORDER BY p.principal_id),'[]'))
  FROM (SELECT m.principal_id FROM public.zasp_identity_memberships m WHERE m.organization_id=o AND m.principal_id>a ORDER BY m.principal_id LIMIT n) p);
END $$;

CREATE OR REPLACE FUNCTION zasp_authorization80.invitation_value(inv public.zasp_member_invitations) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $$
 SELECT jsonb_build_object('id',inv.id,'email',inv.email,'display_name',inv.display_name,'role',inv.role,
  'status',inv.status,'workspace_id',inv.workspace_id,'environment_id',inv.environment_id)
$$;

CREATE OR REPLACE FUNCTION zasp_authorization80.member_lifecycle_read(o text,w text,e text,actor text,op text,i text,a text,n integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb;
BEGIN
 IF op NOT IN('getMemberAccess','listMemberInvitations') OR op IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid member read'; END IF;
 proof:=zasp_authorization80.product_request(o,w,e,actor,op,'manage_identity','organization_identity',o,false,true,false,false);
 IF op='listMemberInvitations' THEN
  IF NOT COALESCE(n BETWEEN 1 AND 101 AND (a='' OR public.zasp_valid_product_id(a)),false)
  THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid invitation page'; END IF;
  RETURN (SELECT jsonb_build_object('items',COALESCE(jsonb_agg(zasp_authorization80.invitation_value(p.inv) ORDER BY p.id),'[]'))
   FROM (SELECT t AS inv,t.id FROM public.zasp_member_invitations t WHERE t.organization_id=o AND t.status='pending' AND t.expires_at>clock_timestamp() AND t.id>a ORDER BY t.id LIMIT n) p);
 END IF;
 IF i IS DISTINCT FROM proof#>>'{path_parameters,id}' OR NOT public.zasp_valid_product_id(i) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid member target'; END IF;
 IF NOT EXISTS(SELECT FROM public.zasp_identity_memberships m WHERE (m.organization_id,m.principal_id)=(o,i))
 THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='member not found'; END IF;
 RETURN (WITH grants AS (
  SELECT s.workspace_id,s.environment_id,m.role FROM public.zasp_authorized_scopes s JOIN public.zasp_identity_memberships m USING(organization_id,principal_id)
  WHERE (m.organization_id,m.principal_id)=(o,i) AND m.active
  UNION
  SELECT gm.workspace_id,gm.environment_id,gm.role FROM public.zasp_group_mappings gm
  JOIN public.zasp_identity_member_groups g USING(organization_id,group_reference) JOIN public.zasp_identity_memberships m USING(organization_id,principal_id)
  WHERE (m.organization_id,m.principal_id)=(o,i) AND m.active)
  SELECT jsonb_build_object('member_id',i,'items',COALESCE(jsonb_agg(jsonb_build_object('workspace_id',g.workspace_id,'environment_id',g.environment_id,
   'workspace_name',ws.name,'environment_name',env.name,'role',g.role,'permissions',public.zasp_effective_scope_permissions('[]'::jsonb,g.role))
   ORDER BY ws.name,env.name,g.workspace_id,g.environment_id,g.role),'[]')) FROM grants g
  JOIN public.zasp_workspaces ws ON(ws.organization_id,ws.id)=(o,g.workspace_id)
  JOIN public.zasp_environments env ON(env.organization_id,env.workspace_id,env.id)=(o,g.workspace_id,g.environment_id));
END $$;

-- A lease permits only one sender. A retry after an uncertain provider result
-- looks up the address in the same provider organization before issuing mail.
CREATE OR REPLACE FUNCTION zasp_authorization80.member_invitation_write(o text,w text,e text,actor text,i text,b jsonb,audit text) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE inv public.zasp_member_invitations%ROWTYPE; org_ref text; phase text:=b->>'phase'; link_expiry timestamptz;
BEGIN
 IF NOT COALESCE(phase IN('reserve','send_new','check','complete','release') AND length(b->>'key') BETWEEN 16 AND 128
  AND length(b->>'email') BETWEEN 3 AND 254 AND b->>'email'=lower(b->>'email') AND b->>'email' ~ '^[^@[:space:]]+@[^@[:space:]]+$'
  AND length(b->>'display_name') BETWEEN 1 AND 128 AND b->>'display_name'=btrim(b->>'display_name')
  AND b->>'role' IN('organization_admin','security_admin','security_engineer','developer_owner','compliance_viewer','read_only_viewer'),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid invitation'; END IF;
 SELECT organization_reference INTO STRICT org_ref FROM public.zasp_identity_memberships m WHERE(m.organization_id,m.principal_id)=(o,actor) AND m.active;
 IF phase='reserve' THEN
  UPDATE public.zasp_member_invitations t SET status='expired'
   WHERE (t.organization_id,t.email)=(o,b->>'email') AND t.status='pending' AND t.expires_at<=clock_timestamp();
 END IF;
 SELECT * INTO inv FROM public.zasp_member_invitations t WHERE(t.organization_id,t.actor_id,t.idempotency_key)=(o,actor,b->>'key') FOR UPDATE;
 IF FOUND AND (inv.email,inv.display_name,inv.role,inv.workspace_id,inv.environment_id) IS DISTINCT FROM
   (b->>'email',b->>'display_name',b->>'role',w,e) THEN RETURN '{"_mutation_state":"conflict"}'; END IF;
 IF phase='reserve' THEN
  IF inv.status='expired' THEN RETURN '{"_mutation_state":"conflict"}'; END IF;
  IF inv.id IS NOT NULL AND inv.status IN('pending','accepted') THEN RETURN zasp_authorization80.invitation_value(inv); END IF;
  IF inv.id IS NULL THEN
   IF EXISTS(SELECT FROM public.zasp_member_profiles pr JOIN public.zasp_identity_memberships m USING(organization_id,principal_id)
    WHERE pr.organization_id=o AND pr.email=b->>'email' AND m.active)
   THEN RETURN '{"_mutation_state":"conflict"}'; END IF;
   -- A different key can resume an abandoned delivery with the same intent.
   SELECT * INTO inv FROM public.zasp_member_invitations t WHERE(t.organization_id,t.email)=(o,b->>'email') AND t.status IN('delivering','pending') FOR UPDATE;
   IF FOUND AND (inv.display_name,inv.role,inv.workspace_id,inv.environment_id) IS DISTINCT FROM (b->>'display_name',b->>'role',w,e)
   THEN RETURN '{"_mutation_state":"conflict"}'; END IF;
   IF FOUND AND inv.status='pending' THEN RETURN zasp_authorization80.invitation_value(inv); END IF;
  END IF;
  IF inv.id IS NULL THEN
   INSERT INTO public.zasp_member_invitations(id,organization_id,workspace_id,environment_id,organization_reference,email,display_name,role,status,actor_id,idempotency_key,lease_id,lease_until)
   VALUES(i,o,w,e,org_ref,b->>'email',b->>'display_name',b->>'role','delivering',actor,b->>'key',i,clock_timestamp()+interval '90 seconds');
  ELSIF inv.lease_until<=clock_timestamp() THEN
   UPDATE public.zasp_member_invitations SET lease_id=i,actor_id=actor,idempotency_key=b->>'key',lease_until=clock_timestamp()+interval '90 seconds' WHERE id=inv.id;
  ELSE RETURN '{"_mutation_state":"conflict"}'; END IF;
  RETURN jsonb_build_object('_deliver_to',org_ref,'_resume',COALESCE(inv.expires_at>clock_timestamp(),false));
 END IF;
 IF inv.id IS NULL OR inv.status<>'delivering' OR inv.lease_id<>i THEN RETURN '{"_mutation_state":"conflict"}'; END IF;
 IF phase='release' THEN
  UPDATE public.zasp_member_invitations SET lease_until=clock_timestamp() WHERE id=inv.id;
  RETURN '{}';
 END IF;
 IF phase='send_new' THEN
  -- The provider had no member for this address. Only a newly appearing
  -- invited member can recover this attempted send after an uncertain result.
  UPDATE public.zasp_member_invitations SET expires_at=clock_timestamp()+interval '7 days' WHERE id=inv.id;
  RETURN '{}';
 END IF;
 IF NOT COALESCE(length(b->>'member_reference') BETWEEN 8 AND 128 AND b->>'member_reference' ~ '^member-[A-Za-z0-9_-]+$',false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid invited member reference'; END IF;
 IF EXISTS(SELECT FROM public.zasp_identity_memberships m WHERE(m.organization_reference,m.member_reference)=(org_ref,b->>'member_reference') AND m.active)
 THEN
  DELETE FROM public.zasp_member_invitations WHERE id=inv.id;
  RETURN '{"_mutation_state":"conflict"}';
 END IF;
 IF phase='check' THEN RETURN '{}'; END IF;
 -- An address can change in the provider directory during an outstanding invitation.
 UPDATE public.zasp_member_invitations t SET status='expired' WHERE (t.organization_reference,t.member_reference)=(org_ref,b->>'member_reference')
  AND t.status='pending' AND t.expires_at<=clock_timestamp();
 link_expiry:=clock_timestamp()+CASE WHEN b->'login_link'='true'::jsonb THEN interval '1 hour' ELSE interval '7 days' END;
 IF inv.expires_at>clock_timestamp() THEN link_expiry:=least(link_expiry,inv.expires_at); END IF;
 UPDATE public.zasp_member_invitations SET member_reference=b->>'member_reference',status='pending',expires_at=link_expiry WHERE id=inv.id RETURNING * INTO inv;
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
 VALUES(o,w,e,audit,actor,'member.invite',inv.id,'succeeded',jsonb_build_object('role',inv.role));
 RETURN zasp_authorization80.invitation_value(inv);
END $$;

-- An inactive principal can be invited again later. Remove their object grants
-- as well as scoped roles and credentials so a new invitation starts clean.
CREATE OR REPLACE FUNCTION zasp_authorization80_identity.clear_member_access(o text,member_id text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  UPDATE public.zasp_product_sessions SET revoked_at=transaction_timestamp(),version=version+1 WHERE (organization_id,principal_id)=(o,member_id) AND revoked_at IS NULL;
  UPDATE public.zasp_product_api_tokens SET revoked_at=transaction_timestamp(),version=version+1 WHERE (organization_id,principal_id)=(o,member_id) AND revoked_at IS NULL;
  DELETE FROM public.zasp_authorized_scopes WHERE (organization_id,principal_id)=(o,member_id);
  DELETE FROM public.zasp_identity_member_groups WHERE (organization_id,principal_id)=(o,member_id);
  DELETE FROM zasp_authorization79.grants WHERE organization_id=o AND principal_kind='user' AND principal_id=member_id;
END $$;

CREATE OR REPLACE FUNCTION zasp_authorization80.member_lifecycle_write(o text,w text,e text,actor text,op text,i text,b jsonb,audit text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb; m public.zasp_identity_memberships%ROWTYPE; result jsonb;
BEGIN
 IF op IS NULL OR op NOT IN('inviteMember','updateMemberProfile','removeMember') OR
  NOT COALESCE(public.zasp_valid_product_id(i) AND public.zasp_valid_product_id(audit),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid member mutation'; END IF;
 proof:=zasp_authorization80.product_request(o,w,e,actor,op,'manage_identity','organization_identity',o,false,true,true,true);
 IF op='inviteMember' THEN RETURN zasp_authorization80.member_invitation_write(o,w,e,actor,i,b,audit); END IF;
 IF i IS DISTINCT FROM proof#>>'{path_parameters,id}' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid member target'; END IF;
 SELECT * INTO m FROM public.zasp_identity_memberships x WHERE(x.organization_id,x.principal_id)=(o,i) FOR UPDATE;
 IF NOT FOUND THEN RETURN '{"_mutation_state":"not_found"}'; END IF;
 IF NOT m.active OR (b->>'version')::bigint IS DISTINCT FROM m.version THEN RETURN '{"_mutation_state":"conflict"}'; END IF;
 IF op='updateMemberProfile' THEN
  IF NOT COALESCE(length(b->>'display_name') BETWEEN 1 AND 128 AND b->>'display_name'=btrim(b->>'display_name'),false)
  THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid display name'; END IF;
  PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','member_profile','organization_id',o,'principal_id',i,'version',m.version));
  UPDATE public.zasp_identity_memberships SET version=version+1 WHERE (organization_id,principal_id)=(o,i);
  INSERT INTO public.zasp_member_profiles(organization_id,principal_id,display_name) VALUES(o,i,b->>'display_name')
  ON CONFLICT(organization_id,principal_id) DO UPDATE SET display_name=excluded.display_name;
 ELSE
  IF i=actor THEN RETURN '{"_mutation_state":"conflict"}'; END IF;
  -- The existing deprovision permit admits only one member's deactivation,
  -- session/token revocations and removal of their direct and group grants.
  PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','deprovision','organization_id',o,'principal_id',i));
  UPDATE public.zasp_identity_memberships SET active=false,version=version+1 WHERE (organization_id,principal_id)=(o,i);
  PERFORM zasp_authorization80_identity.clear_member_access(o,i);
 END IF;
 PERFORM zasp_authorization80_identity.clear_permit();
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
 VALUES(o,w,e,audit,actor,CASE op WHEN 'removeMember' THEN 'member.remove' ELSE 'member.profile.update' END,i,'succeeded',jsonb_build_object('version',m.version+1));
 RETURN zasp_authorization80.member_value(o,i);
END $$;

-- Only administrator-initiated changes protect the last administrator.
-- Verified provider deprovisioning must still revoke a departed employee.
CREATE OR REPLACE FUNCTION zasp_authorization80_identity.keep_last_admin() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT EXISTS(SELECT FROM zasp_authorization80_identity.permits x WHERE x.pid=pg_backend_pid() AND x.tx=pg_current_xact_id()
  AND x.principal=session_user AND (x.body->>'operation'='updateMemberRole' OR x.body->>'purpose'='deprovision' AND x.body->>'project' IS NULL))
 THEN RETURN NEW; END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=OLD.organization_id FOR UPDATE;
 IF NOT EXISTS(SELECT FROM public.zasp_identity_memberships m WHERE m.organization_id=OLD.organization_id AND m.principal_id<>OLD.principal_id AND m.active AND m.role='organization_admin')
 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='the organization must retain an active administrator'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE TRIGGER zasp_member_keep_last_admin BEFORE UPDATE OF role,active ON public.zasp_identity_memberships
 FOR EACH ROW WHEN(OLD.active AND OLD.role='organization_admin' AND (NOT NEW.active OR NEW.role<>'organization_admin'))
 EXECUTE FUNCTION zasp_authorization80_identity.keep_last_admin();

-- The hierarchy guard accepts the table owner for INSERT. This private
-- operation accepts only an invitation row locked by the admission, and has
-- no caller-controlled permissions or scope parameters.
CREATE OR REPLACE FUNCTION zasp_authorization80_identity.grant_invited_scope(inv public.zasp_member_invitations,member_id text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT EXISTS(SELECT FROM zasp_authorization80_identity.permits x WHERE x.pid=pg_backend_pid() AND x.tx=pg_current_xact_id() AND x.principal=session_user
  AND x.body->>'purpose'='member_accept' AND (x.body->>'invitation',x.body->>'principal_id',x.body->>'organization_id')=(inv.id,member_id,inv.organization_id))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invitation admission required'; END IF;
 INSERT INTO public.zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default)
 SELECT member_id,inv.organization_id,inv.workspace_id,inv.environment_id,left(w.name||' / '||e.name,128),'[]',true
 FROM public.zasp_environments e JOIN public.zasp_workspaces w ON(w.organization_id,w.id)=(e.organization_id,e.workspace_id)
 WHERE(e.organization_id,e.workspace_id,e.id)=(inv.organization_id,inv.workspace_id,inv.environment_id);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invitation scope unavailable'; END IF;
END $$;

CREATE OR REPLACE FUNCTION zasp_authorization80_identity.accept_invitation(b jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE inv public.zasp_member_invitations%ROWTYPE; m public.zasp_identity_memberships%ROWTYPE; pid text; org text;
BEGIN
 SELECT organization_id INTO org FROM public.zasp_member_invitations t WHERE(t.organization_reference,t.member_reference,t.status)=(b->>'organization',b->>'member','pending') AND t.expires_at>clock_timestamp();
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=org FOR UPDATE;
 SELECT * INTO inv FROM public.zasp_member_invitations t WHERE(t.organization_reference,t.member_reference,t.status)=(b->>'organization',b->>'member','pending') AND t.expires_at>clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 -- Admission and session resolution commit together. An invalid, expired or
 -- replayed login attempt rolls back the member, their scope and the receipt.
 SELECT * INTO m FROM public.zasp_identity_memberships x WHERE(x.organization_reference,x.member_reference)=(inv.organization_reference,inv.member_reference) FOR UPDATE;
 IF m.active OR m.organization_id IS NOT NULL AND m.organization_id<>inv.organization_id
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invitation identity conflict'; END IF;
 pid:=COALESCE(m.principal_id, 'pid_'||gen_random_uuid()::text);
 IF m.principal_id IS NOT NULL THEN
  -- Historical provider deprovisioning did not delete explicit resource grants.
  PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','deprovision','organization_id',inv.organization_id,'principal_id',pid));
  PERFORM zasp_authorization80_identity.clear_member_access(inv.organization_id,pid);
  PERFORM zasp_authorization80_identity.clear_permit();
 END IF;
 PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','member_accept','invitation',inv.id,'organization_id',inv.organization_id,
  'principal_id',pid,'organization_reference',inv.organization_reference,'member_reference',inv.member_reference,'role',inv.role));
 IF m.principal_id IS NULL THEN
  INSERT INTO public.zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role)
  VALUES(pid,inv.organization_id,inv.organization_reference,inv.member_reference,inv.role);
 ELSE
  UPDATE public.zasp_identity_memberships SET active=true,role=inv.role,version=version+1 WHERE(organization_id,principal_id)=(inv.organization_id,pid);
 END IF;
 PERFORM zasp_authorization80_identity.grant_invited_scope(inv,pid);
 INSERT INTO public.zasp_member_profiles(organization_id,principal_id,email,display_name)
 VALUES(inv.organization_id,pid,inv.email,inv.display_name)
 ON CONFLICT(organization_id,principal_id) DO UPDATE SET email=excluded.email,display_name=excluded.display_name;
 UPDATE public.zasp_member_invitations SET status='accepted' WHERE id=inv.id;
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
 VALUES(inv.organization_id,inv.workspace_id,inv.environment_id,'pid_'||gen_random_uuid()::text,pid,'member.invitation.accept',pid,'succeeded',jsonb_build_object('invitation_id',inv.id));
 PERFORM zasp_authorization80_identity.clear_permit();
END $$;

-- Extend the installed, sealed trigger and login definitions at their
-- admission points. Their existing checks and deployment-specific bindings
-- remain in force for all other identities, tables, and purposes.
DO $install$
DECLARE source text; anchor text; extension text;
BEGIN
 source:=pg_get_functiondef('zasp_authorization80_identity.write_guard()'::regprocedure);
 anchor:=' allowed:=CASE TG_TABLE_NAME';
 extension:=$extension$
 IF TG_RELID='public.zasp_identity_memberships'::regclass AND purpose IN('member_accept','member_profile') THEN
  IF (purpose='member_profile' AND TG_OP<>'UPDATE') OR (purpose='member_accept' AND TG_OP NOT IN('INSERT','UPDATE'))
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid member transition'; END IF;
  IF TG_LEVEL='STATEMENT' THEN RETURN NULL; END IF;
  IF (NEW.organization_id,NEW.principal_id) IS DISTINCT FROM (b->>'organization_id',b->>'principal_id')
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='wrong member transition'; END IF;
  IF purpose='member_profile' THEN
   allowed:=OLD.active AND OLD.version=(b->>'version')::bigint AND NEW.version=OLD.version+1 AND to_jsonb(NEW)-'version'=to_jsonb(OLD)-'version';
  ELSE
   allowed:=NEW.active AND (NEW.organization_reference,NEW.member_reference,NEW.role)=(b->>'organization_reference',b->>'member_reference',b->>'role')
    AND CASE WHEN TG_OP='INSERT' THEN NEW.version=1 ELSE NOT OLD.active AND NEW.version=OLD.version+1 AND to_jsonb(NEW)-ARRAY['active','version','role']=to_jsonb(OLD)-ARRAY['active','version','role'] END;
  END IF;
  IF NOT COALESCE(allowed,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='member transition rejected'; END IF;
  RETURN NEW;
 END IF;
$extension$;
 IF strpos(source,anchor)=0 THEN RAISE EXCEPTION 'unsupported identity write guard'; END IF;
 IF strpos(source,extension||anchor)=0 THEN
  EXECUTE replace(source,anchor,extension||anchor);
 END IF;
 source:=pg_get_functiondef('zasp_authorization80_identity.resolve_login(text)'::regprocedure);
 anchor:=' SELECT organization_id,principal_id INTO o,p FROM public.zasp_identity_memberships';
 IF strpos(source,anchor)=0 THEN RAISE EXCEPTION 'unsupported verified login admission'; END IF;
 extension:=' PERFORM zasp_authorization80_identity.accept_invitation(b);'||chr(10);
 IF strpos(source,extension||anchor)=0 THEN
  EXECUTE replace(source,anchor,extension||anchor);
 END IF;
END $install$;

ALTER FUNCTION zasp_authorization80.member_value(text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.invitation_value(public.zasp_member_invitations) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.member_lifecycle_read(text,text,text,text,text,text,text,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.member_invitation_write(text,text,text,text,text,jsonb,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.member_lifecycle_write(text,text,text,text,text,text,jsonb,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80_identity.keep_last_admin() OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80_identity.accept_invitation(jsonb) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80_identity.grant_invited_scope(public.zasp_member_invitations,text) OWNER TO zasp_operator;
REVOKE ALL ON FUNCTION zasp_authorization80.member_value(text,text),zasp_authorization80.invitation_value(public.zasp_member_invitations),zasp_authorization80.member_lifecycle_read(text,text,text,text,text,text,text,integer),zasp_authorization80.member_invitation_write(text,text,text,text,text,jsonb,text),zasp_authorization80.member_lifecycle_write(text,text,text,text,text,text,jsonb,text),zasp_authorization80_identity.keep_last_admin(),zasp_authorization80_identity.accept_invitation(jsonb),zasp_authorization80_identity.grant_invited_scope(public.zasp_member_invitations,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.grant_invited_scope(public.zasp_member_invitations,text) TO zasp_discovery_authority;
GRANT INSERT(principal_id,organization_id,organization_reference,member_reference,role) ON public.zasp_identity_memberships TO zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_authorization80.member_lifecycle_read(text,text,text,text,text,text,text,integer),zasp_authorization80.member_lifecycle_write(text,text,text,text,text,text,jsonb,text) TO zasp_discovery_api;

ALTER FUNCTION zasp_authorization80_identity.clear_member_access(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80_identity.clear_member_access(text,text) FROM PUBLIC;
