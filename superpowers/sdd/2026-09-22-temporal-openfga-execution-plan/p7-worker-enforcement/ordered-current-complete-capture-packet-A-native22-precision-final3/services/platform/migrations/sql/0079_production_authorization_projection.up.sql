-- Additive permission projection. No dependency on private Temporal extension78.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_authorization79 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_authorization79 FROM PUBLIC;
CREATE TABLE zasp_authorization79.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_authorization79.organizations(
 organization_id text PRIMARY KEY CHECK(public.zasp_valid_product_id(organization_id)),
 desired bigint NOT NULL DEFAULT 1 CHECK(desired>0),applied bigint NOT NULL DEFAULT 0 CHECK(applied>=0 AND applied<=desired),
 generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),store_id text NOT NULL DEFAULT '',model_id text NOT NULL DEFAULT '',
 pending_since timestamptz NOT NULL DEFAULT clock_timestamp(),last_attempt_at timestamptz,applied_at timestamptz,
 blocked_reason text NOT NULL DEFAULT 'unconfigured' CHECK(blocked_reason IN('','unconfigured','pending','delivery_failed','invalid_source','conflict')),
 CHECK((generation=0 AND store_id='' AND model_id='') OR (generation>0 AND store_id~'^[0-7][0-9A-HJKMNP-TV-Z]{25}$' AND model_id~'^[0-7][0-9A-HJKMNP-TV-Z]{25}$'))
);
CREATE TABLE zasp_authorization79.outbox(
 organization_id text NOT NULL REFERENCES zasp_authorization79.organizations,revision bigint NOT NULL CHECK(revision>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),applied_at timestamptz,PRIMARY KEY(organization_id,revision)
);
CREATE TABLE zasp_authorization79.inventory(
 organization_id text NOT NULL REFERENCES zasp_authorization79.organizations,store_id text NOT NULL,tuple jsonb NOT NULL CHECK(jsonb_typeof(tuple)='object'),
 PRIMARY KEY(organization_id,store_id,tuple)
);
CREATE TABLE zasp_authorization79.stages(
 organization_id text PRIMARY KEY REFERENCES zasp_authorization79.organizations,revision bigint NOT NULL,generation bigint NOT NULL,store_id text NOT NULL,model_id text NOT NULL,tuples jsonb NOT NULL
);
CREATE TABLE zasp_authorization79.receipts(
 organization_id text NOT NULL,revision bigint NOT NULL,generation bigint NOT NULL,store_id text NOT NULL,model_id text NOT NULL,tuple_count integer NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,revision),FOREIGN KEY(organization_id,revision) REFERENCES zasp_authorization79.outbox
);
-- These are product-owned explicit grants, never inferred from a creator or an
-- IdP identity. Only the registered authority can write them in this release.
CREATE TABLE zasp_authorization79.grants(
 organization_id text NOT NULL CHECK(public.zasp_valid_product_id(organization_id)),workspace_id text NOT NULL CHECK(public.zasp_valid_product_id(workspace_id)),environment_id text NOT NULL CHECK(public.zasp_valid_product_id(environment_id)),
 kind text NOT NULL CHECK(kind~'^[a-z][a-z0-9_]{0,62}$'),id text NOT NULL CHECK(public.zasp_valid_product_id(id)),principal_kind text NOT NULL CHECK(principal_kind IN('user','agent','service')),principal_id text NOT NULL CHECK(public.zasp_valid_product_id(principal_id)),
 permission text NOT NULL CHECK(permission IN('investigate_sessions','manage_api_tokens','manage_data_controls','manage_findings','manage_identity','manage_workflows','revoke_sessions','run_tests','view','view_audit','view_compliance')),
 task_id text NOT NULL DEFAULT '',CHECK((principal_kind='user' AND task_id='') OR(principal_kind<>'user' AND public.zasp_valid_product_id(task_id))),
 PRIMARY KEY(organization_id,workspace_id,environment_id,kind,id,principal_kind,principal_id,permission,task_id)
);
CREATE INDEX pending ON zasp_authorization79.organizations((COALESCE(last_attempt_at,pending_since)),organization_id) WHERE desired<>applied;

CREATE FUNCTION zasp_authorization79.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS(
 SELECT concat_ws('|','schema',nspowner::regrole::text,nspacl::text) FROM pg_namespace WHERE nspname='zasp_authorization79'
 UNION ALL SELECT concat_ws('|','function',p.proname,p.proowner::regrole::text,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE pronamespace='zasp_authorization79'::regnamespace
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE relnamespace='zasp_authorization79'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization79'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization79'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization79'::regnamespace
 UNION ALL SELECT concat_ws('|','view',c.relname,pg_get_viewdef(c.oid)) FROM pg_class c WHERE relnamespace='zasp_authorization79'::regnamespace AND relkind='v'
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgname='zasp_authorization79_capture'
 ) SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_authorization79.ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT c='-- authorization79 checksum' AND EXISTS(SELECT 1 FROM zasp_authorization79.registration WHERE checksum=c AND fingerprint=zasp_authorization79.fingerprint())
$$;
CREATE FUNCTION zasp_authorization79.operator() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
$$;
CREATE FUNCTION zasp_authorization79.worker() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT public.zasp_discovery_principal_ready('zasp_outbox_worker') AND zasp_authorization79.ready('-- authorization79 checksum') $$;
CREATE FUNCTION zasp_authorization79.reader() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_authorization79.ready('-- authorization79 checksum') AND (zasp_authorization79.worker() OR public.zasp_discovery_principal_ready('zasp_discovery_api') OR public.zasp_security_agent_principal_ready('zasp_security_agent_api') OR public.zasp_security_agent_principal_ready('zasp_security_agent_worker'))
$$;
CREATE FUNCTION zasp_authorization79.touch(o text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE rev bigint;
BEGIN
 INSERT INTO zasp_authorization79.organizations(organization_id) VALUES(o) ON CONFLICT(organization_id) DO UPDATE SET desired=zasp_authorization79.organizations.desired+1,pending_since=CASE WHEN zasp_authorization79.organizations.desired=zasp_authorization79.organizations.applied THEN clock_timestamp() ELSE zasp_authorization79.organizations.pending_since END,blocked_reason='pending' RETURNING desired INTO rev;
 INSERT INTO zasp_authorization79.outbox(organization_id,revision) VALUES(o,rev);
END $$;
CREATE FUNCTION zasp_authorization79.capture() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE prior text;next_org text;org text;old_value jsonb;new_value jsonb;columns text[];
BEGIN
 old_value:=CASE WHEN TG_OP<>'INSERT' THEN to_jsonb(OLD) END;new_value:=CASE WHEN TG_OP<>'DELETE' THEN to_jsonb(NEW) END;
 -- Ignore unrelated payload/status updates. Every permission-affecting column
 -- is listed in the trigger installation below, including raw SQL write paths.
 columns:=string_to_array(TG_ARGV[1],',');
 IF TG_OP='UPDATE' AND (SELECT jsonb_object_agg(k,old_value->k) FROM unnest(columns) k) IS NOT DISTINCT FROM (SELECT jsonb_object_agg(k,new_value->k) FROM unnest(columns) k) THEN RETURN NEW;END IF;
 prior:=old_value->>TG_ARGV[0];next_org:=new_value->>TG_ARGV[0];
 FOR org IN SELECT DISTINCT x FROM unnest(ARRAY[prior,next_org]) x WHERE x IS NOT NULL ORDER BY x LOOP PERFORM zasp_authorization79.touch(org);END LOOP;
 -- Row triggers do not precede PostgreSQL tuple locks. A lock inversion must
 -- abort the whole caller transaction; callers restart at a fresh Check.
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $$;

CREATE VIEW zasp_authorization79.resources AS
 SELECT organization_id,workspace_id,environment_id,'finding'::text kind,id FROM public.zasp_risk_findings
 UNION SELECT organization_id,workspace_id,environment_id,'attack_path',id FROM public.zasp_risk_attack_paths
 UNION SELECT organization_id,workspace_id,environment_id,kind,id FROM public.zasp_workflow_records WHERE deleted_at IS NULL AND kind NOT IN('security_agent','security_agent_run','integration')
 UNION SELECT organization_id,workspace_id,environment_id,'integration',id FROM public.zasp_integrations WHERE deleted_at IS NULL AND state<>'deleted'
 UNION SELECT organization_id,workspace_id,environment_id,'security_agent',definition_id FROM public.zasp_security_agent_definitions WHERE deleted_at IS NULL
 UNION SELECT organization_id,workspace_id,environment_id,'security_agent_run',run_id FROM public.zasp_security_agent_runs
 UNION SELECT organization_id,workspace_id,environment_id,'discovery_schedule',id FROM public.zasp_discovery_schedules WHERE state<>'deleted'
 UNION SELECT organization_id,workspace_id,environment_id,'discovery_sync',id FROM public.zasp_discovery_syncs
 UNION SELECT organization_id,workspace_id,environment_id,kind,id FROM public.zasp_inventory_entities WHERE state='active';
CREATE VIEW zasp_authorization79.members AS
 SELECT organization_id,'user'::text kind,principal_id id FROM public.zasp_identity_memberships WHERE active
 UNION SELECT organization_id,'agent',definition_id FROM public.zasp_security_agent_definitions WHERE deleted_at IS NULL AND activation IN('supervised','autonomous')
 UNION SELECT s.organization_id,'service',s.id FROM public.zasp_discovery_schedules s JOIN public.zasp_integrations i ON(i.organization_id,i.workspace_id,i.environment_id,i.id)=(s.organization_id,s.workspace_id,s.environment_id,s.integration_id) WHERE s.state='enabled' AND i.state='active' AND i.deleted_at IS NULL AND EXISTS(SELECT 1 FROM public.zasp_integration_connections c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.integration_id)=(s.organization_id,s.workspace_id,s.environment_id,s.integration_id) AND c.state='verified' AND c.revoked_at IS NULL);
CREATE VIEW zasp_authorization79.current_grants AS
 SELECT g.* FROM zasp_authorization79.grants g JOIN zasp_authorization79.members m ON(m.organization_id,m.kind,m.id)=(g.organization_id,g.principal_kind,g.principal_id)
 JOIN zasp_authorization79.resources r ON(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(g.organization_id,g.workspace_id,g.environment_id,g.kind,g.id)
 WHERE g.principal_kind='user'
 OR(g.principal_kind='agent' AND EXISTS(SELECT 1 FROM public.zasp_security_agent_runs t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.definition_id,t.run_id)=(g.organization_id,g.workspace_id,g.environment_id,g.principal_id,g.task_id) AND t.state IN('queued','planning','waiting_approval','running','verifying')))
 OR(g.principal_kind='service' AND EXISTS(SELECT 1 FROM public.zasp_discovery_syncs t JOIN public.zasp_discovery_schedules s ON(s.organization_id,s.workspace_id,s.environment_id,s.integration_id)=(t.organization_id,t.workspace_id,t.environment_id,t.integration_id) WHERE(t.organization_id,t.workspace_id,t.environment_id,t.id,s.id,t.principal_id)=(g.organization_id,g.workspace_id,g.environment_id,g.task_id,g.principal_id,g.principal_id) AND t.trigger_kind IN('schedule','retry') AND t.state IN('queued','running')));

CREATE FUNCTION zasp_authorization79.configure(o text,s text,m text,repair boolean DEFAULT false) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE row_value zasp_authorization79.organizations%ROWTYPE;
BEGIN
 IF NOT zasp_authorization79.operator() OR NOT zasp_authorization79.ready('-- authorization79 checksum') OR s!~'^[0-7][0-9A-HJKMNP-TV-Z]{25}$' OR m!~'^[0-7][0-9A-HJKMNP-TV-Z]{25}$' OR NOT EXISTS(SELECT 1 FROM public.zasp_organizations WHERE id=o) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection configuration rejected';END IF;
 -- Configuration takes the same session advisory serialization as reconcile,
 -- so no old-store operation is still running when a generation changes.
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||o,0));
 SELECT * INTO row_value FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND OR (row_value.store_id,row_value.model_id) IS DISTINCT FROM(s,m) OR repair THEN
  PERFORM zasp_authorization79.touch(o);
  UPDATE zasp_authorization79.organizations SET generation=generation+1,store_id=s,model_id=m,blocked_reason='pending' WHERE organization_id=o;
 END IF;
 RETURN (SELECT to_jsonb(x) FROM zasp_authorization79.organizations x WHERE organization_id=o);
END $$;
CREATE FUNCTION zasp_authorization79.revision(o text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT zasp_authorization79.reader() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection reader rejected';END IF;
 RETURN(SELECT to_jsonb(x) FROM zasp_authorization79.organizations x WHERE organization_id=o);
END $$;
CREATE FUNCTION zasp_authorization79.revalidate(o text,d bigint,g bigint,s text,m text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v zasp_authorization79.organizations%ROWTYPE;
BEGIN
 IF NOT zasp_authorization79.reader() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection fence rejected';END IF;
 SELECT * INTO v FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND OR (v.desired,v.applied,v.generation,v.store_id,v.model_id) IS DISTINCT FROM(d,d,g,s,m) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='authorization changed; retry from Check';END IF;
END $$;
CREATE FUNCTION zasp_authorization79.locked(o text) RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND mode='ExclusiveLock' AND objsubid=1 AND classid=((hashtextextended('zasp-auth79/'||o,0)>>32)&4294967295)::oid AND objid=(hashtextextended('zasp-auth79/'||o,0)&4294967295)::oid)
$$;
CREATE FUNCTION zasp_authorization79.snapshot(o text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 IF NOT zasp_authorization79.worker() OR NOT zasp_authorization79.locked(o) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection session rejected';END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_environments WHERE organization_id=o GROUP BY id HAVING count(*)>1)
 OR EXISTS(SELECT 1 FROM zasp_authorization79.resources WHERE organization_id=o GROUP BY kind,id HAVING count(*)>1)
 OR EXISTS(SELECT 1 FROM zasp_authorization79.resources r WHERE r.organization_id=o AND NOT EXISTS(SELECT 1 FROM public.zasp_environments e WHERE(e.organization_id,e.workspace_id,e.id)=(r.organization_id,r.workspace_id,r.environment_id))) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='authorization source ancestry rejected';END IF;
 -- One SQL statement snapshot binds source facts and desired revision. Missing
 -- parents or duplicate scoped IDs fail closed rather than manufacturing edges.
 WITH scopes AS(SELECT e.organization_id,e.workspace_id,e.id environment_id FROM public.zasp_environments e JOIN public.zasp_workspaces w ON(w.organization_id,w.id)=(e.organization_id,e.workspace_id) JOIN public.zasp_organizations x ON x.id=e.organization_id WHERE e.organization_id=o),
 roles AS(SELECT a.organization_id,a.workspace_id,a.environment_id,a.principal_id,m.role FROM public.zasp_authorized_scopes a JOIN public.zasp_identity_memberships m USING(organization_id,principal_id) WHERE a.organization_id=o AND m.active UNION SELECT g.organization_id,g.workspace_id,g.environment_id,v.principal_id,g.role FROM public.zasp_group_mappings g JOIN public.zasp_identity_member_groups v USING(organization_id,group_reference) JOIN public.zasp_identity_memberships m USING(organization_id,principal_id) WHERE g.organization_id=o AND m.active)
 SELECT jsonb_build_object('revision',(SELECT to_jsonb(x) FROM zasp_authorization79.organizations x WHERE organization_id=o),
 'scopes',COALESCE((SELECT jsonb_agg(to_jsonb(x)) FROM scopes x),'[]'),
 'members',COALESCE((SELECT jsonb_agg(to_jsonb(x)-'organization_id') FROM zasp_authorization79.members x WHERE organization_id=o),'[]'),
 'roles',COALESCE((SELECT jsonb_agg(to_jsonb(x)) FROM roles x),'[]'),
 'resources',COALESCE((SELECT jsonb_agg(to_jsonb(x)) FROM zasp_authorization79.resources x WHERE organization_id=o),'[]'),
 'grants',COALESCE((SELECT jsonb_agg(to_jsonb(x)) FROM zasp_authorization79.current_grants x WHERE organization_id=o),'[]'),
 'known',COALESCE((SELECT jsonb_agg(i.tuple) FROM zasp_authorization79.inventory i JOIN zasp_authorization79.organizations x USING(organization_id,store_id) WHERE i.organization_id=o),'[]')) INTO result;
 UPDATE zasp_authorization79.organizations SET last_attempt_at=clock_timestamp() WHERE organization_id=o;
 RETURN result;
END $$;
CREATE FUNCTION zasp_authorization79.stage(o text,d bigint,g bigint,s text,m text,tuples_value jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT zasp_authorization79.worker() OR NOT zasp_authorization79.locked(o) OR jsonb_typeof(tuples_value)<>'array' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection stage rejected';END IF;
 PERFORM zasp_authorization79.revalidate_pending(o,d,g,s,m);
 INSERT INTO zasp_authorization79.inventory SELECT o,s,v FROM jsonb_array_elements(tuples_value) v ON CONFLICT DO NOTHING;
 INSERT INTO zasp_authorization79.stages VALUES(o,d,g,s,m,tuples_value) ON CONFLICT(organization_id) DO UPDATE SET revision=d,generation=g,store_id=s,model_id=m,tuples=tuples_value;
END $$;
CREATE FUNCTION zasp_authorization79.revalidate_pending(o text,d bigint,g bigint,s text,m text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v zasp_authorization79.organizations%ROWTYPE;
BEGIN
 SELECT * INTO v FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND OR(v.desired,v.generation,v.store_id,v.model_id) IS DISTINCT FROM(d,g,s,m) OR v.applied>=d THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='projection changed';END IF;
END $$;
CREATE FUNCTION zasp_authorization79.ack(o text,d bigint,g bigint,s text,m text,tuples_value jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT zasp_authorization79.worker() OR NOT zasp_authorization79.locked(o) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection acknowledgement rejected';END IF;
 PERFORM zasp_authorization79.revalidate_pending(o,d,g,s,m);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization79.stages WHERE(organization_id,revision,generation,store_id,model_id,tuples)=(o,d,g,s,m,tuples_value)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='projection stage mismatch';END IF;
 DELETE FROM zasp_authorization79.inventory WHERE organization_id=o AND store_id=s;
 INSERT INTO zasp_authorization79.inventory SELECT o,s,v FROM jsonb_array_elements(tuples_value) v;
 UPDATE zasp_authorization79.outbox SET applied_at=clock_timestamp() WHERE organization_id=o AND revision<=d AND applied_at IS NULL;
 INSERT INTO zasp_authorization79.receipts(organization_id,revision,generation,store_id,model_id,tuple_count) VALUES(o,d,g,s,m,jsonb_array_length(tuples_value));
 UPDATE zasp_authorization79.organizations SET applied=d,applied_at=clock_timestamp(),blocked_reason='' WHERE organization_id=o;
 DELETE FROM zasp_authorization79.stages WHERE organization_id=o;
END $$;
CREATE FUNCTION zasp_authorization79.pending(n integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT zasp_authorization79.worker() OR n NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection queue rejected';END IF;
 RETURN(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]') FROM(SELECT organization_id,desired,applied,generation,store_id,model_id,pending_since,last_attempt_at,blocked_reason FROM zasp_authorization79.organizations WHERE desired<>applied ORDER BY COALESCE(last_attempt_at,pending_since),organization_id LIMIT n)x);
END $$;
CREATE FUNCTION zasp_authorization79.blocked(o text,reason text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT zasp_authorization79.worker() OR NOT zasp_authorization79.locked(o) OR reason NOT IN('delivery_failed','invalid_source','conflict') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection outcome rejected';END IF;
 UPDATE zasp_authorization79.organizations SET blocked_reason=reason,last_attempt_at=clock_timestamp() WHERE organization_id=o AND desired<>applied;
END $$;

DO $triggers$ DECLARE spec text[];BEGIN
 FOREACH spec SLICE 1 IN ARRAY ARRAY[
 ['zasp_identity_memberships','organization_id','organization_id,principal_id,role,active,organization_reference,member_reference'],
 ['zasp_authorized_scopes','organization_id','organization_id,workspace_id,environment_id,principal_id,permissions'],
 ['zasp_group_mappings','organization_id','organization_id,workspace_id,environment_id,group_reference,role'],
 ['zasp_identity_member_groups','organization_id','organization_id,principal_id,group_reference'],
 ['zasp_organizations','id','id'],['zasp_workspaces','organization_id','organization_id,id'],['zasp_environments','organization_id','organization_id,workspace_id,id'],
 ['zasp_workflow_records','organization_id','organization_id,workspace_id,environment_id,kind,id,deleted_at'],
 ['zasp_risk_findings','organization_id','organization_id,workspace_id,environment_id,id'],['zasp_risk_attack_paths','organization_id','organization_id,workspace_id,environment_id,id'],
 ['zasp_integrations','organization_id','organization_id,workspace_id,environment_id,id,state,deleted_at'],
 ['zasp_integration_connections','organization_id','organization_id,workspace_id,environment_id,integration_id,state,verified_at,revoked_at'],
 ['zasp_discovery_schedules','organization_id','organization_id,workspace_id,environment_id,id,integration_id,state'],
 ['zasp_discovery_syncs','organization_id','organization_id,workspace_id,environment_id,id,integration_id,principal_id,trigger_kind,state'],
 ['zasp_security_agent_definitions','organization_id','organization_id,workspace_id,environment_id,definition_id,activation,deleted_at'],
 ['zasp_security_agent_runs','organization_id','organization_id,workspace_id,environment_id,run_id,definition_id,state'],
 ['zasp_inventory_entities','organization_id','organization_id,workspace_id,environment_id,kind,id,state']]
 LOOP EXECUTE format('CREATE TRIGGER zasp_authorization79_capture BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture(%L,%L)',spec[1],spec[2],spec[3]);END LOOP;
END $triggers$;
CREATE TRIGGER zasp_authorization79_capture BEFORE INSERT OR UPDATE OR DELETE ON zasp_authorization79.grants FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,kind,id,principal_kind,principal_id,permission,task_id');
GRANT SELECT ON public.zasp_organizations,public.zasp_workspaces,public.zasp_environments TO zasp_discovery_authority;
DO $owners$ DECLARE row_value record;BEGIN
 FOR row_value IN SELECT c.oid::regclass name,c.relkind FROM pg_class c WHERE c.relnamespace='zasp_authorization79'::regnamespace AND c.relkind IN('r','v') LOOP
  EXECUTE format('ALTER %s %s OWNER TO zasp_discovery_authority',CASE WHEN row_value.relkind='v' THEN 'VIEW' ELSE 'TABLE' END,row_value.name);
  IF row_value.relkind='r' THEN EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',row_value.name);EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',row_value.name);EXECUTE format('CREATE POLICY authority ON %s USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',row_value.name);END IF;
 END LOOP;
 FOR row_value IN SELECT oid::regprocedure name FROM pg_proc WHERE pronamespace='zasp_authorization79'::regnamespace LOOP EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',row_value.name);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',row_value.name);END LOOP;
END $owners$;
REVOKE ALL ON ALL TABLES IN SCHEMA zasp_authorization79 FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_authorization79 TO zasp_outbox_worker,zasp_discovery_api,zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_authorization79.ready(text) TO zasp_outbox_worker,zasp_discovery_api,zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_authorization79.revision(text),zasp_authorization79.revalidate(text,bigint,bigint,text,text) TO zasp_outbox_worker,zasp_discovery_api,zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_authorization79.snapshot(text),zasp_authorization79.stage(text,bigint,bigint,text,text,jsonb),zasp_authorization79.ack(text,bigint,bigint,text,text,jsonb),zasp_authorization79.pending(integer),zasp_authorization79.blocked(text,text) TO zasp_outbox_worker;
-- Bootstrap existing tenants as pending in the installation transaction.
SELECT zasp_authorization79.touch(id) FROM public.zasp_organizations ORDER BY id;
