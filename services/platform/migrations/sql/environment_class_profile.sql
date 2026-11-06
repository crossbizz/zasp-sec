-- Supplementary environment classification; published parents remain immutable.
CREATE SCHEMA zasp_environment_class_v1 AUTHORIZATION zasp_discovery_authority;
-- environment class authority definitions
CREATE TABLE zasp_environment_class_v1.registration(singleton boolean PRIMARY KEY CHECK(singleton),checksum text NOT NULL,worker_checksum text NOT NULL,runtime_checksum text NOT NULL,source_owner oid NOT NULL,fingerprint text NOT NULL);
REVOKE ALL ON SCHEMA zasp_environment_class_v1 FROM PUBLIC;
REVOKE ALL ON TABLE zasp_environment_class_v1.registration FROM PUBLIC;
ALTER TABLE zasp_environment_class_v1.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_environment_class_v1.registration FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_environment_class_v1.registration TO zasp_discovery_authority USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
GRANT USAGE ON SCHEMA zasp_environment_class_v1 TO zasp_discovery_api;
CREATE FUNCTION zasp_environment_class_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS (
 SELECT concat_ws('|','schema',nspowner,nspacl::text) FROM pg_namespace WHERE nspname='zasp_environment_class_v1'
 UNION ALL SELECT concat_ws('|','function',p.proname,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_environment_class_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_environment_class_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_environment_class_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid WHERE c.relnamespace='zasp_environment_class_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_environment_class_v1'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','policy',p.polrelid,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_environment_class_v1'::regnamespace
 ) SELECT encode(public.digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_environment_class_v1.catalog_ready(c text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE r zasp_environment_class_v1.registration;BEGIN
 SELECT * INTO r FROM zasp_environment_class_v1.registration WHERE singleton;
 RETURN COALESCE(c='-- environment class checksum' AND r.checksum=c AND r.worker_checksum='-- environment class worker checksum' AND r.runtime_checksum='-- environment class runtime checksum'
 AND r.fingerprint=zasp_environment_class_v1.fingerprint()
 AND zasp_authorization79.ready('-- environment class authorization79 checksum') AND zasp_authorization80.ready('-- environment class authorization80 checksum')
 AND zasp_temporal78.ready('-- environment class temporal78 checksum','-- environment class temporal78 fingerprint')
 AND zasp_authorization80_worker.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum=r.worker_checksum)
 AND zasp_authorization80_runtime.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum=r.runtime_checksum)
 AND zasp_authorization80.hierarchy_create_source_ready()
 AND EXISTS(SELECT 1 FROM pg_class e JOIN pg_class d ON d.oid='public.zasp_data_controls'::regclass JOIN pg_roles p ON p.oid=e.relowner JOIN public.zasp_discovery_principal_bindings b ON b.principal_name=p.rolname AND b.authority_role='zasp_discovery_authority' WHERE e.oid='public.zasp_environments'::regclass AND e.relowner=d.relowner AND e.relowner=r.source_owner AND p.rolcanlogin AND NOT p.rolsuper AND NOT p.rolbypassrls AND NOT p.rolcreaterole AND NOT p.rolcreatedb)
 AND (SELECT count(*)=8 AND bool_and(p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proowner=CASE WHEN p.proname IN('write_create_environment','write_update_environment') THEN r.source_owner ELSE 'zasp_discovery_authority'::regrole::oid END AND NOT has_function_privilege('public',p.oid,'EXECUTE')) FROM pg_proc p WHERE p.pronamespace='zasp_environment_class_v1'::regnamespace)

 -- A fingerprint is not initial ACL admission. Reject default/non-PUBLIC
 -- privileges BEFORE accepting the first stored seal, including inner writers.
 AND NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.pronamespace='zasp_environment_class_v1'::regnamespace AND
  (a.privilege_type<>'EXECUTE' OR a.grantee NOT IN(p.proowner,
    CASE WHEN p.proname IN('caller_ready','create_environment','update_environment') THEN 'zasp_discovery_api'::regrole::oid
         WHEN p.proname='require_api' THEN r.source_owner
         WHEN p.proname IN('write_create_environment','write_update_environment') THEN 'zasp_discovery_authority'::regrole::oid
         ELSE p.proowner END) OR(a.is_grantable AND a.grantee<>p.proowner)))
 AND (SELECT count(*)=3 FROM pg_proc p WHERE p.pronamespace='zasp_environment_class_v1'::regnamespace AND p.proname IN('caller_ready','create_environment','update_environment') AND has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE'))
 AND EXISTS(SELECT 1 FROM pg_proc p WHERE p.pronamespace='zasp_environment_class_v1'::regnamespace AND p.proname='require_api' AND has_function_privilege(r.source_owner,p.oid,'EXECUTE'))
 AND (SELECT count(*)=2 FROM pg_proc p WHERE p.pronamespace='zasp_environment_class_v1'::regnamespace AND p.proname IN('write_create_environment','write_update_environment') AND has_function_privilege('zasp_discovery_authority',p.oid,'EXECUTE'))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_environment_class_v1' AND
  (a.grantee NOT IN(n.nspowner,'zasp_discovery_api'::regrole::oid,r.source_owner) OR(a.grantee<>n.nspowner AND(a.privilege_type<>'USAGE' OR a.is_grantable))))
 AND has_schema_privilege(r.source_owner,'zasp_environment_class_v1'::regnamespace,'USAGE')
 AND has_schema_privilege('zasp_discovery_api','zasp_environment_class_v1','USAGE')
 AND NOT EXISTS(SELECT 1 FROM pg_class t CROSS JOIN LATERAL aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE t.oid='zasp_environment_class_v1.registration'::regclass AND a.grantee<>t.relowner)
 AND NOT EXISTS(SELECT 1 FROM pg_attribute col JOIN pg_class t ON t.oid=col.attrelid CROSS JOIN LATERAL aclexplode(col.attacl) a WHERE t.oid='zasp_environment_class_v1.registration'::regclass AND col.attnum>0 AND NOT col.attisdropped AND a.grantee<>t.relowner)
 AND NOT has_schema_privilege('public','zasp_environment_class_v1','USAGE') AND NOT has_schema_privilege(r.source_owner,'zasp_environment_class_v1'::regnamespace,'CREATE'),false);
END $$;
CREATE FUNCTION zasp_environment_class_v1.caller_ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(zasp_environment_class_v1.catalog_ready(c) AND public.zasp_discovery_principal_ready('zasp_discovery_api'),false)
$$;
-- Read-only gate; only the authority and exact original source LOGIN may call.
CREATE FUNCTION zasp_environment_class_v1.require_api(o text,w text,e text,a text,op text,c text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;r jsonb;BEGIN
 p:=zasp_authorization80.context();r:=p->'revision';
 IF NOT COALESCE(zasp_environment_class_v1.caller_ready(c) AND op IN('createEnvironment','updateEnvironment') AND (p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'operation_id',p->>'permission',p->>'credential_kind')=(o,w,e,a,op,'manage_identity','1') AND (p->>'fresh_auth')::boolean AND zasp_authorization80.allowed(o,w,e,'environment',e),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='environment classification authorization required';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY[op],'manage_identity',true,a);
 PERFORM zasp_authorization79.revalidate(o,(r->>'desired')::bigint,(r->>'generation')::bigint,r->>'store_id',r->>'model_id');
 PERFORM zasp_authorization80.identity_fence(p);
 -- Re-read the expiring sealed context AFTER the final lock wait. A direct
 -- source-owner session still fails caller_ready: session_user must be API.
 IF zasp_environment_class_v1.caller_ready(c) IS NOT TRUE OR zasp_authorization80.context() IS DISTINCT FROM p THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='environment classification authority expired';END IF;
 RETURN p;
END $$;
CREATE FUNCTION zasp_environment_class_v1.create_environment(new_id text,o text,requested_workspace text,name_value text,class_value text,audit_value text,actor_value text,w text,e text,permissions_value jsonb,c text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;BEGIN
 PERFORM zasp_environment_class_v1.require_api(o,w,e,actor_value,'createEnvironment',c);
 PERFORM zasp_authorization80.require_hierarchy_create(o,w,e,actor_value,'createEnvironment',permissions_value);
 result:=zasp_environment_class_v1.write_create_environment(new_id,o,requested_workspace,name_value,class_value,audit_value,actor_value,w,e,permissions_value);
 IF jsonb_typeof(result) IS DISTINCT FROM 'object' OR NOT(result ?& ARRAY['result','class_changed']) OR result-ARRAY['result','class_changed']<>'{}'::jsonb OR result->'class_changed' IS DISTINCT FROM 'false'::jsonb THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='environment classification result rejected';END IF;
 -- Creation's existing hierarchy INSERT triggers intentionally advance79.
 -- Do not revalidate the old revision or duplicate its outbox touch afterward.
 IF zasp_environment_class_v1.caller_ready(c) IS NOT TRUE OR zasp_authorization80.context() IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='environment classification authority changed';END IF;
 PERFORM zasp_authorization80.identity_fence(zasp_authorization80.context());
 RETURN result->'result';
END $$;
CREATE FUNCTION zasp_environment_class_v1.update_environment(o text,w text,e text,target_id text,name_value text,class_value text,expected_version bigint,audit_value text,actor_value text,c text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;BEGIN
 PERFORM zasp_environment_class_v1.require_api(o,w,e,actor_value,'updateEnvironment',c);
 result:=zasp_environment_class_v1.write_update_environment(o,w,e,target_id,name_value,class_value,expected_version,audit_value,actor_value);
 IF jsonb_typeof(result) IS DISTINCT FROM 'object' OR NOT(result ?& ARRAY['result','class_changed']) OR result-ARRAY['result','class_changed']<>'{}'::jsonb OR jsonb_typeof(result->'class_changed') IS DISTINCT FROM 'boolean' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='environment classification result rejected';END IF;
 -- Class/version are absent from original79 capture. Only a real class delta
 -- invalidates other-resource proofs; a rename/no-op does not bump79.
 PERFORM zasp_environment_class_v1.require_api(o,w,e,actor_value,'updateEnvironment',c);
 IF (result->>'class_changed')::boolean THEN PERFORM zasp_authorization79.touch(o);END IF;
 RETURN result->'result';
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zasp_environment_class_v1 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_environment_class_v1.caller_ready(text),zasp_environment_class_v1.create_environment(text,text,text,text,text,text,text,text,text,jsonb,text),zasp_environment_class_v1.update_environment(text,text,text,text,text,text,bigint,text,text,text) TO zasp_discovery_api;
-- environment class source LOGIN writers
CREATE FUNCTION zasp_environment_class_v1.write_create_environment(new_id text,o text,requested_workspace text,name_value text,class_value text,audit_value text,actor_value text,w text,e text,permissions_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;BEGIN
 IF NOT COALESCE(requested_workspace=w AND permissions_value='[]'::jsonb AND public.zasp_valid_product_id(new_id) AND public.zasp_valid_product_id(audit_value) AND class_value IN('development','test','staging','production') AND length(name_value) BETWEEN 1 AND 128,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='environment classification input rejected';END IF;
 -- Hold the existing parent row through creation; recheck current proof after
 -- any wait, under the authority-only read gate in this supplementary schema.
 PERFORM 1 FROM public.zasp_environments x WHERE(x.organization_id,x.workspace_id,x.id)=(o,w,e) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='hierarchy parent unavailable';END IF;
 PERFORM zasp_environment_class_v1.require_api(o,w,e,actor_value,'createEnvironment','-- environment class checksum');
 WITH created AS (
 INSERT INTO public.zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES(new_id,o,w,name_value,class_value) RETURNING *
 ),granted AS (
 INSERT INTO public.zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) SELECT actor_value,o,w,new_id,name_value,'[]'::jsonb,false FROM created
 ),bootstrap AS (
 INSERT INTO public.zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) SELECT o,w,new_id,'session_bootstrap:'||actor_value,jsonb_build_object('correlation_id',audit_value) FROM created
 ),controls AS (
 INSERT INTO public.zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) SELECT organization_id,workspace_id,id,environment_class,'metadata_only',30,true FROM created
 ),audited AS (
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT o,w,new_id,audit_value,actor_value,'environment.create',new_id,'succeeded',jsonb_build_object('environment_class',class_value) FROM created
 ) SELECT jsonb_build_object('id',id,'organization_id',organization_id,'workspace_id',workspace_id,'name',name,'environment_class',environment_class,'version',version,'audit_correlation_id',audit_value) INTO result FROM created;
 RETURN jsonb_build_object('result',result,'class_changed',false);
END $$;
CREATE FUNCTION zasp_environment_class_v1.write_update_environment(o text,w text,e text,target_id text,name_value text,class_value text,expected_version bigint,audit_value text,actor_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE env public.zasp_environments;controls public.zasp_data_controls;next_class text;changed boolean;result jsonb;BEGIN
 IF NOT COALESCE(target_id=e AND public.zasp_valid_product_id(audit_value) AND expected_version>0 AND expected_version<9223372036854775807 AND length(name_value) BETWEEN 1 AND 128 AND (class_value IS NULL OR class_value IN('development','test','staging','production')),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='environment classification input rejected';END IF;
 SELECT * INTO env FROM public.zasp_environments x WHERE(x.organization_id,x.workspace_id,x.id)=(o,w,e) FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('result',jsonb_build_object('_mutation_state','not_found'),'class_changed',false);END IF;
 SELECT * INTO controls FROM public.zasp_data_controls x WHERE(x.organization_id,x.workspace_id,x.environment_id)=(o,w,e) FOR UPDATE;
 IF NOT FOUND OR controls.environment_class IS DISTINCT FROM env.environment_class THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='environment classification controls unavailable';END IF;
 PERFORM zasp_environment_class_v1.require_api(o,w,e,actor_value,'updateEnvironment','-- environment class checksum');
 IF env.version<>expected_version THEN RETURN jsonb_build_object('result',jsonb_build_object('_mutation_state','conflict'),'class_changed',false);END IF;
 next_class:=COALESCE(class_value,env.environment_class);changed:=next_class IS DISTINCT FROM env.environment_class;
 IF next_class='production' AND controls.collection_mode<>'metadata_only' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='production requires metadata-only collection';END IF;
 IF changed AND controls.version>=9223372036854775807 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='environment classification version exhausted';END IF;
 UPDATE public.zasp_environments x SET name=name_value,environment_class=next_class,version=x.version+1 WHERE(x.organization_id,x.workspace_id,x.id,x.version)=(o,w,e,expected_version) RETURNING * INTO STRICT env;
 IF changed THEN UPDATE public.zasp_data_controls x SET environment_class=next_class,version=x.version+1 WHERE(x.organization_id,x.workspace_id,x.environment_id,x.version)=(o,w,e,controls.version);IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='environment classification controls changed';END IF;END IF;
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES(o,w,e,audit_value,actor_value,'environment.update',e,'succeeded',jsonb_build_object('previous_environment_class',controls.environment_class,'environment_class',next_class));
 result:=jsonb_build_object('id',env.id,'organization_id',env.organization_id,'workspace_id',env.workspace_id,'name',env.name,'environment_class',env.environment_class,'version',env.version,'audit_correlation_id',audit_value);
 RETURN jsonb_build_object('result',result,'class_changed',changed);
END $$;
REVOKE ALL ON FUNCTION zasp_environment_class_v1.write_create_environment(text,text,text,text,text,text,text,text,text,jsonb),zasp_environment_class_v1.write_update_environment(text,text,text,text,text,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_environment_class_v1.write_create_environment(text,text,text,text,text,text,text,text,text,jsonb),zasp_environment_class_v1.write_update_environment(text,text,text,text,text,text,bigint,text,text) TO zasp_discovery_authority;
