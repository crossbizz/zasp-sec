-- Checked source7 hierarchy creation. Historical SQL, owners and ACLs remain
-- unchanged. Only these two wrappers retain the registered migration owner so
-- their atomic controls seed can use the existing forced-RLS owner policy.
-- Statement-level INVOKER identity is intentional: a raw API request cannot
-- impersonate a trusted SECURITY DEFINER caller. The one trigger argument is
-- captured from registered catalog ownership during migration, never a request.
CREATE FUNCTION zasp_authorization80.hierarchy_write_guard() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $$
DECLARE admitted boolean;
BEGIN
 IF TG_NARGS<>1 OR TG_LEVEL<>'STATEMENT' OR TG_WHEN<>'BEFORE'
  OR TG_RELID NOT IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='hierarchy writer contract rejected';END IF;
 IF current_user=TG_ARGV[0] AND EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.oid=TG_RELID AND r.rolname=TG_ARGV[0] AND r.rolcanlogin)
 THEN RETURN NULL;END IF;
 -- Source19 deprovision removes direct grants under its exact nonlogin owner.
 -- It does not need scope INSERT/UPDATE, hierarchy writes or TRUNCATE.
 IF current_user='zasp_discovery_authority' AND TG_RELID='public.zasp_authorized_scopes'::regclass AND TG_OP='DELETE'
  AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
 THEN
  IF EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE identity_mode<>'none') THEN
   EXECUTE 'SELECT zasp_authorization80_identity.scope_cleanup_allowed()' INTO admitted;
   IF NOT COALESCE(admitted,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='verified identity cleanup required';END IF;
  END IF;
  RETURN NULL;
 END IF;
 RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked hierarchy writer required';
END $$;

DO $hierarchy_write_isolation$
DECLARE owner_name text;relation_value regclass;
BEGIN
 SELECT b.principal_name INTO STRICT owner_name FROM public.zasp_discovery_principal_bindings b
 JOIN pg_class c ON c.oid='public.zasp_data_controls'::regclass AND c.relowner=b.principal_name::regrole
 JOIN pg_roles r ON r.rolname=b.principal_name AND r.rolcanlogin
 WHERE b.authority_role='zasp_discovery_authority';
 IF owner_name IS DISTINCT FROM current_user THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='hierarchy source owner rejected';END IF;
 FOREACH relation_value IN ARRAY ARRAY['public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=relation_value AND relkind='r' AND relowner=owner_name::regrole)
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='hierarchy relation owner rejected';END IF;
  EXECUTE format('CREATE TRIGGER zasp_authorization80_hierarchy_write_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80.hierarchy_write_guard(%L)',relation_value,owner_name);
 END LOOP;
END $hierarchy_write_isolation$;

CREATE FUNCTION zasp_authorization80.hierarchy_write_guards_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE((SELECT count(*)=4 AND bool_and(
  c.relowner=b.principal_name::regrole AND c.relkind='r'
  AND t.tgenabled='O' AND t.tgtype=62 AND NOT t.tgisinternal AND NOT t.tgdeferrable AND NOT t.tginitdeferred
  AND t.tgconstraint=0 AND t.tgconstrrelid=0 AND t.tgconstrindid=0 AND t.tgnargs=1 AND t.tgattr=''::int2vector AND t.tgqual IS NULL AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
  AND t.tgfoid='zasp_authorization80.hierarchy_write_guard()'::regprocedure
  AND t.tgargs=convert_to(b.principal_name,'UTF8')||decode('00','hex'))
  FROM pg_class c JOIN pg_trigger t ON t.tgrelid=c.oid AND t.tgname='zasp_authorization80_hierarchy_write_guard'
  JOIN public.zasp_discovery_principal_bindings b ON b.authority_role='zasp_discovery_authority'
  JOIN pg_roles r ON r.rolname=b.principal_name AND r.rolcanlogin
  WHERE c.oid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass))
 AND EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='zasp_authorization80.hierarchy_write_guard()'::regprocedure
  AND p.proowner='zasp_discovery_authority'::regrole AND NOT p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}'),false)
$$;

CREATE FUNCTION zasp_authorization80.hierarchy_create_source_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(zasp_authorization80.data_controls_source_ready()
 AND zasp_authorization80.hierarchy_write_guards_ready()
 AND (SELECT count(*)=2 FROM pg_proc p JOIN pg_class c ON c.oid='public.zasp_data_controls'::regclass
  JOIN public.zasp_discovery_principal_bindings b ON b.principal_name=c.relowner::regrole::text AND b.authority_role='zasp_discovery_authority'
  WHERE p.oid IN(to_regprocedure('zasp_authorization80.create_workspace(text,text,text,text,text,text,text,text,jsonb)'),to_regprocedure('zasp_authorization80.create_environment(text,text,text,text,text,text,text,text,jsonb)'))
  AND p.proowner=c.relowner AND p.prosecdef AND COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public']
  AND NOT has_function_privilege('public',p.oid,'EXECUTE') AND has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE'))
 AND EXISTS(SELECT 1 FROM pg_class WHERE oid='public.zasp_workspaces'::regclass AND relkind='r')
 AND EXISTS(SELECT 1 FROM pg_class WHERE oid='public.zasp_environments'::regclass AND relkind='r'),false)
$$;

CREATE FUNCTION zasp_authorization80.require_hierarchy_create(o text,w text,e text,actor_value text,operation_value text,permissions_value jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb;
BEGIN
 proof:=zasp_authorization80.context();
 IF NOT COALESCE(zasp_authorization80.hierarchy_create_source_ready()
  AND public.zasp_discovery_principal_ready('zasp_discovery_api')
  AND operation_value IN('createWorkspace','createEnvironment')
  AND (proof->>'organization_id',proof->>'workspace_id',proof->>'environment_id',proof->>'principal_id',proof->>'operation_id',proof->>'permission',proof->>'credential_kind')=(o,w,e,actor_value,operation_value,'manage_identity','1')
  AND (proof->>'fresh_auth')::boolean
  AND zasp_authorization80.allowed(o,w,e,'environment',e),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current hierarchy creation authorization required';END IF;
 IF permissions_value IS DISTINCT FROM '[]'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inert scope compatibility array required';END IF;
 PERFORM zasp_authorization80.identity_fence(proof);
 -- Native direct-row admission is additional to FGA, never a permission allow.
 IF NOT EXISTS(SELECT 1 FROM public.zasp_authorized_scopes s
  JOIN public.zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(s.organization_id,s.principal_id) AND m.active
  JOIN public.zasp_workspaces parent ON(parent.organization_id,parent.id)=(s.organization_id,s.workspace_id)
  JOIN public.zasp_environments env ON(env.organization_id,env.workspace_id,env.id)=(s.organization_id,s.workspace_id,s.environment_id)
  WHERE(s.organization_id,s.workspace_id,s.environment_id,s.principal_id)=(o,w,e,actor_value))
 THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='hierarchy parent unavailable';END IF;
END $$;

CREATE FUNCTION zasp_authorization80.create_workspace(new_id text,o text,name_value text,w text,e text,audit_value text,actor_value text,new_environment_id text,permissions_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_hierarchy_create(o,w,e,actor_value,'createWorkspace',permissions_value);
 IF NOT COALESCE(public.zasp_valid_product_id(new_id) AND public.zasp_valid_product_id(new_environment_id) AND public.zasp_valid_product_id(audit_value),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid hierarchy creation identifier';END IF;
 WITH created_workspace AS (
  INSERT INTO public.zasp_workspaces(id,organization_id,name) VALUES(new_id,o,name_value) RETURNING *
 ),created_environment AS (
  INSERT INTO public.zasp_environments(id,organization_id,workspace_id,name,environment_class)
  SELECT new_environment_id,o,new_id,'Development','development' FROM created_workspace RETURNING *
 ),granted AS (
  INSERT INTO public.zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default)
  SELECT actor_value,o,new_id,new_environment_id,left(name_value||' / Development',128),'[]'::jsonb,false FROM created_environment
 ),bootstrap AS (
  INSERT INTO public.zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload)
  SELECT o,new_id,new_environment_id,'session_bootstrap:'||actor_value,jsonb_build_object('correlation_id',audit_value) FROM created_environment
 ),controls AS (
  INSERT INTO public.zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled)
  SELECT o,new_id,new_environment_id,'development','metadata_only',30,true FROM created_environment
 ),audited AS (
  INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
  SELECT o,w,e,audit_value,actor_value,'workspace.onboard',new_id,'succeeded',jsonb_build_object('initial_environment_id',new_environment_id) FROM created_environment
 ) SELECT jsonb_build_object('id',id,'organization_id',organization_id,'name',name,'version',version,'initial_environment_id',new_environment_id,'audit_correlation_id',audit_value) INTO result FROM created_workspace;
 RETURN result;
END $$;

CREATE FUNCTION zasp_authorization80.create_environment(new_id text,o text,requested_workspace text,name_value text,audit_value text,actor_value text,w text,e text,permissions_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_hierarchy_create(o,w,e,actor_value,'createEnvironment',permissions_value);
 IF requested_workspace IS DISTINCT FROM w THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='hierarchy parent unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(new_id) AND public.zasp_valid_product_id(audit_value),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid hierarchy creation identifier';END IF;
 WITH created AS (
  INSERT INTO public.zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES(new_id,o,w,name_value,'development') RETURNING *
 ),granted AS (
  INSERT INTO public.zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default)
  SELECT actor_value,o,w,new_id,name_value,'[]'::jsonb,false FROM created
 ),bootstrap AS (
  INSERT INTO public.zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload)
  SELECT o,w,new_id,'session_bootstrap:'||actor_value,jsonb_build_object('correlation_id',audit_value) FROM created
 ),controls AS (
  INSERT INTO public.zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled)
  SELECT organization_id,workspace_id,id,environment_class,'metadata_only',30,true FROM created
 ),audited AS (
  INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
  SELECT o,w,new_id,audit_value,actor_value,'environment.create',new_id,'succeeded','{}'::jsonb FROM created
 ) SELECT jsonb_build_object('id',id,'organization_id',organization_id,'workspace_id',workspace_id,'name',name,'environment_class',environment_class,'version',version,'audit_correlation_id',audit_value) INTO result FROM created;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION zasp_authorization80.create_workspace(text,text,text,text,text,text,text,text,jsonb),zasp_authorization80.create_environment(text,text,text,text,text,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.create_workspace(text,text,text,text,text,text,text,text,jsonb),zasp_authorization80.create_environment(text,text,text,text,text,text,text,text,jsonb) TO zasp_discovery_api;
