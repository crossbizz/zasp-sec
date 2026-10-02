-- Source7 has a migration-login owner and source10 retained raw API CRUD.
-- Preserve owner/ACLs and the source56 owner helper. Direct API rows are closed;
-- only the two checked owner functions below admit application access.
DO $data_controls_isolation$
DECLARE owner_name text;
BEGIN
 SELECT b.principal_name INTO STRICT owner_name FROM public.zasp_discovery_principal_bindings b
 JOIN pg_class c ON c.oid='public.zasp_data_controls'::regclass AND c.relowner=b.principal_name::regrole
 JOIN pg_roles r ON r.rolname=b.principal_name AND r.rolcanlogin
 WHERE b.authority_role='zasp_discovery_authority' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity;
 IF owner_name IS DISTINCT FROM current_user OR EXISTS(SELECT 1 FROM pg_policy WHERE polrelid='public.zasp_data_controls'::regclass)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='data controls source owner rejected';END IF;
 ALTER TABLE public.zasp_data_controls ENABLE ROW LEVEL SECURITY;
 ALTER TABLE public.zasp_data_controls FORCE ROW LEVEL SECURITY;
 EXECUTE format('CREATE POLICY authorization80_owner ON public.zasp_data_controls TO %I USING(current_user=%L) WITH CHECK(current_user=%L)',owner_name,owner_name,owner_name);
END $data_controls_isolation$;

CREATE FUNCTION zasp_authorization80.data_controls_source_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(zasp_authorization80.ready('-- authorization80 checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=7 AND name='production_administration' AND checksum='-- authorization80 administration7 checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_administration_fingerprint' AND value='-- authorization80 administration7 fingerprint')
 AND EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner JOIN public.zasp_discovery_principal_bindings b ON b.principal_name=r.rolname AND b.authority_role='zasp_discovery_authority'
  WHERE c.oid='public.zasp_data_controls'::regclass AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity AND r.rolcanlogin
  AND NOT pg_has_role(session_user,r.oid,'MEMBER')
  AND NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid IN(to_regprocedure('zasp_authorization80.get_data_controls(text,text,text)'),to_regprocedure('zasp_authorization80.update_data_controls(text,text,text,text,integer,boolean,bigint,text,text,text)'))
   AND(p.proowner<>c.relowner OR NOT p.prosecdef OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR has_function_privilege('public',p.oid,'EXECUTE'))))
 AND NOT has_table_privilege('public','public.zasp_data_controls','SELECT,INSERT,UPDATE,DELETE')
 AND public.zasp_audit_export_source_acl_ready(),false)
$$;

CREATE FUNCTION zasp_authorization80.data_controls_authorized(o text,w text,e text,op text,p text DEFAULT NULL) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(zasp_authorization80.data_controls_source_ready() AND public.zasp_discovery_principal_ready('zasp_discovery_api')
 AND (proof->>'organization_id',proof->>'workspace_id',proof->>'environment_id',proof->>'operation_id',proof->>'credential_kind')=(o,w,e,op,'1')
 AND op IN('getDataControls','updateDataControls')
 AND proof->>'permission'=CASE op WHEN 'getDataControls' THEN 'view_compliance' WHEN 'updateDataControls' THEN 'manage_data_controls' END
 AND (op<>'updateDataControls' OR(p IS NOT NULL AND proof->>'principal_id'=p AND COALESCE((proof->>'fresh_auth')::boolean,false)))
 AND zasp_authorization80.allowed(o,w,e,'environment',e),false)
 FROM(SELECT zasp_authorization80.context() proof) current_proof
$$;

-- These exact two signatures keep the registered table owner's SECURITY DEFINER
-- identity through SQL80 finalization. They never use legacy role permissions.
CREATE FUNCTION zasp_authorization80.get_data_controls(o text,w text,e text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 IF NOT zasp_authorization80.data_controls_authorized(o,w,e,'getDataControls') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current data controls authorization required';END IF;
 SELECT jsonb_build_object('environment_id',environment_id,'environment_class',environment_class,'collection_mode',collection_mode,'retention_days',retention_days,'deletion_enabled',deletion_enabled,'version',version) INTO result
 FROM public.zasp_data_controls WHERE(organization_id,workspace_id,environment_id)=(o,w,e);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='data controls missing';END IF;
 RETURN result;
END $$;

CREATE FUNCTION zasp_authorization80.update_data_controls(o text,w text,e text,mode_value text,days_value integer,deletion_value boolean,version_value bigint,class_value text,audit_value text,actor_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 IF NOT zasp_authorization80.data_controls_authorized(o,w,e,'updateDataControls',actor_value) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current data controls authorization required';END IF;
 IF NOT public.zasp_valid_product_id(audit_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid data controls audit identifier';END IF;
 WITH updated AS (
  UPDATE public.zasp_data_controls SET collection_mode=mode_value,retention_days=days_value,deletion_enabled=deletion_value,version=version+1,migration_seeded=false,updated_at=transaction_timestamp()
  WHERE(organization_id,workspace_id,environment_id)=(o,w,e) AND version=version_value AND environment_class=class_value RETURNING *
 ),audited AS (
  INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
  SELECT o,w,e,audit_value,actor_value,'data_controls.update',e,'succeeded',jsonb_build_object('collection_mode',mode_value,'retention_days',days_value::text) FROM updated
 ) SELECT jsonb_build_object('environment_id',environment_id,'environment_class',environment_class,'collection_mode',collection_mode,'retention_days',retention_days,'deletion_enabled',deletion_enabled,'version',version,'audit_correlation_id',audit_value) INTO result FROM updated;
 RETURN COALESCE(result,jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM public.zasp_data_controls WHERE(organization_id,workspace_id,environment_id)=(o,w,e)) THEN 'conflict' ELSE 'not_found' END));
END $$;
REVOKE ALL ON FUNCTION zasp_authorization80.get_data_controls(text,text,text),zasp_authorization80.update_data_controls(text,text,text,text,integer,boolean,bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.get_data_controls(text,text,text),zasp_authorization80.update_data_controls(text,text,text,text,integer,boolean,bigint,text,text,text) TO zasp_discovery_api;
