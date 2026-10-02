-- existing test candidate fragments

-- Preserve public54 client gates. Only inherited server-side callers move to55.
DO $save_compatibility$
DECLARE signature_value text; source_value text; name_value text; needle text; occurrences integer; expected integer; check_value text:=current_setting('check_function_bodies');
BEGIN
 FOREACH signature_value IN ARRAY ARRAY[
  'zasp_production_audit_exports_readiness(text,text)',
  'zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',
  'zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)',
  'zasp_production_security_agent_attack_path_security_ready()',
  'zasp_production_workflow_compatibility_security_ready()',
  'zasp_production_security_agent_run_context_activity_browser(text,text,text,text,bytea,text,text)',
  'zasp_production_security_agent_run_context_audit(text,text,text,text,bytea,text,text)'
 ] LOOP
  name_value:=split_part(signature_value,'(',1);
  source_value:=pg_get_functiondef(('public.'||signature_value)::regprocedure);
  EXECUTE replace(source_value,'FUNCTION public.'||name_value||'(','FUNCTION zasp_existing_tests_predecessor.'||name_value||'(');
  EXECUTE format('ALTER FUNCTION zasp_existing_tests_predecessor.%s OWNER TO zasp_discovery_authority',signature_value);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_existing_tests_predecessor.%s FROM PUBLIC',signature_value);
  IF name_value IN('zasp_workflow_mutate','zasp_risk_mutate','zasp_production_security_agent_attack_path_security_ready','zasp_production_workflow_compatibility_security_ready') THEN
   occurrences:=0;
   expected:=CASE WHEN name_value IN('zasp_workflow_mutate','zasp_risk_mutate') THEN 1 ELSE 3 END;
   FOREACH needle IN ARRAY ARRAY['later_release."version" > 54','later."version">54','later."version" > 54'] LOOP
    occurrences:=occurrences+(length(source_value)-length(replace(source_value,needle,'')))/length(needle);
    source_value:=replace(source_value,needle,replace(needle,'54','55'));
   END LOOP;
   IF occurrences<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test compatibility predecessor rejected';END IF;
  ELSE
   needle:='zasp_production_security_agent_run_context_readiness(';
   IF (length(source_value)-length(replace(source_value,needle,'')))/length(needle)<>1 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test readiness caller rejected';
   END IF;
   source_value:=replace(source_value,needle,'zasp_production_security_agent_existing_tests_readiness(');
   source_value:=replace(source_value,'''production_security_agent_run_context_checksum''','''production_security_agent_existing_tests_checksum''');
   source_value:=replace(source_value,'''production_security_agent_run_context_fingerprint''','''production_security_agent_existing_tests_fingerprint''');
   IF name_value='zasp_production_audit_exports_readiness' THEN
    source_value:=replace(source_value,'WHERE version=54','WHERE version=55');
   END IF;
  END IF;
  -- SQL function validation is deferred until the pinned gate below exists.
  PERFORM set_config('check_function_bodies','off',true);
  EXECUTE source_value;
 END LOOP;
 PERFORM set_config('check_function_bodies',check_value,true);
END
$save_compatibility$;

-- Clone only private fingerprint ancestry; never change historical public pins.
DO $fingerprint_base$
DECLARE source_value text; needle text;
BEGIN
 source_value:=pg_get_functiondef('zasp_run_context_predecessor.audit_fingerprint()'::regprocedure);
 needle:='''production_security_agent_run_context_checksum'',''production_security_agent_run_context_fingerprint''';
 IF (length(source_value)-length(replace(source_value,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test fingerprint predecessor rejected';END IF;
 source_value:=replace(source_value,needle,needle||',''production_security_agent_existing_tests_checksum'',''production_security_agent_existing_tests_fingerprint''');
 EXECUTE replace(source_value,'FUNCTION zasp_run_context_predecessor.audit_fingerprint(','FUNCTION zasp_existing_tests_predecessor.audit_fingerprint(');
 source_value:=pg_get_functiondef('zasp_run_context_predecessor.budget_fingerprint()'::regprocedure);
 source_value:=replace(source_value,'FUNCTION zasp_run_context_predecessor.budget_fingerprint(','FUNCTION zasp_existing_tests_predecessor.budget_fingerprint(');
 EXECUTE replace(source_value,'zasp_run_context_predecessor.audit_fingerprint()','zasp_existing_tests_predecessor.audit_fingerprint()');
 source_value:=pg_get_functiondef('public.zasp_production_security_agent_run_context_live_fingerprint()'::regprocedure);
 source_value:=replace(source_value,'FUNCTION public.zasp_production_security_agent_run_context_live_fingerprint(','FUNCTION zasp_existing_tests_predecessor.run_context_fingerprint(');
 EXECUTE replace(source_value,'zasp_run_context_predecessor.budget_fingerprint()','zasp_existing_tests_predecessor.budget_fingerprint()');
 ALTER FUNCTION zasp_existing_tests_predecessor.audit_fingerprint() OWNER TO zasp_discovery_authority;
 ALTER FUNCTION zasp_existing_tests_predecessor.budget_fingerprint() OWNER TO zasp_discovery_authority;
 ALTER FUNCTION zasp_existing_tests_predecessor.run_context_fingerprint() OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_existing_tests_predecessor.audit_fingerprint(),zasp_existing_tests_predecessor.budget_fingerprint(),zasp_existing_tests_predecessor.run_context_fingerprint() FROM PUBLIC;
END
$fingerprint_base$;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_function_identity(function_value oid)
RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $identity$
 SELECT CASE WHEN function_value=to_regprocedure('public.zasp_production_security_agent_existing_tests_readiness(text,text)')
 THEN regexp_replace(pg_get_functiondef(function_value),$$expected_(checksum|fingerprint) = '[a-f0-9]{64}'$$,$$expected_\1 = '<compiled-pin>'$$,'g')
 ELSE pg_get_functiondef(function_value) END
$identity$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_function_identity(oid) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_function_identity(oid) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_live_fingerprint()
RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_existing_tests_predecessor.run_context_fingerprint())
 UNION ALL SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_existing_tests_predecessor'
 UNION ALL SELECT concat_ws('|','function',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),public.zasp_production_security_agent_existing_tests_function_identity(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='zasp_existing_tests_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_production_security_agent_existing_tests')
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,c.relowner::regrole::text,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
 UNION ALL SELECT concat_ws('|','column',a.attrelid::regclass::text,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,a.attcollation::regcollation::text,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations')) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',k.conrelid::regclass::text,k.conname,k.convalidated,pg_get_constraintdef(k.oid,true)) FROM pg_constraint k WHERE k.conrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
 UNION ALL SELECT concat_ws('|','index',i.indrelid::regclass::text,i.indexrelid::regclass::text,i.indisvalid,i.indisready,i.indislive,pg_get_indexdef(i.indexrelid)) FROM pg_index i WHERE i.indrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
 UNION ALL SELECT concat_ws('|','policy',p.polrelid::regclass::text,p.polname,p.polpermissive,p.polcmd,(SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(p.polroles) r),pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p WHERE p.polrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,true),t.tgfoid::regprocedure::text) FROM pg_trigger t WHERE t.tgrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations')) AND NOT t.tgisinternal
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_live_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_live_fingerprint() FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_readiness(expected_checksum text,expected_fingerprint text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $readiness$
 SELECT COALESCE(expected_checksum = '-- compiled existing tests checksum'
 AND expected_fingerprint = '-- compiled existing tests fingerprint'
 AND (SELECT count(*)=55 FROM public.zasp_schema_versions)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version<1 OR version>55)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_budgets_predecessor_releases() p LEFT JOIN public.zasp_schema_versions r USING(version) WHERE r.name IS DISTINCT FROM p.name OR r.checksum IS DISTINCT FROM p.checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=53 AND name='production_security_agent_budgets' AND checksum='-- existing tests budget checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_budgets_checksum' AND value='-- existing tests budget checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_budgets_fingerprint' AND value='-- existing tests budget fingerprint')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=54 AND name='production_security_agent_run_context' AND checksum='-- existing tests context checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_checksum' AND value='-- existing tests context checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_fingerprint' AND value='-- existing tests context fingerprint')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=55 AND name='production_security_agent_existing_tests' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_existing_tests_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_existing_tests_fingerprint' AND value=expected_fingerprint)
 AND public.zasp_production_runtime_sandbox_binding_security_ready()
 AND public.zasp_audit_export_policy_state_ready()
 AND public.zasp_audit_export_worker_security_ready()
 AND public.zasp_audit_export_source_acl_ready()
 AND public.zasp_audit_export_workflow_acl_ready()
 AND public.zasp_production_security_agent_existing_tests_live_fingerprint()=expected_fingerprint,false)
$readiness$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_readiness(text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_client_ready(expected_checksum text,expected_fingerprint text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $client$
 SELECT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint)
$client$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_client_ready(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_client_ready(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_client_ready(text,text) TO zasp_discovery_api,zasp_runtime_ingest,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_audit_export_worker,zasp_audit_export_outbox,zasp_red_team_worker,zasp_red_team_adapter;

-- A versioned write entrypoint prevents an in-flight55 request from using the
-- restored54 mutation after rollback. Transaction-held relation locks conflict
-- with both registered down and the explicit retention check in its SQL body.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_mutate_definition(
 mutation_value text,definition_value text,organization_value text,workspace_value text,
 environment_value text,principal_value text,operation_value text,key_value text,
 expected_version bigint,intent_value jsonb,body_value jsonb,audit_value text,
 correlation_value text,receipt_value text,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $mutation$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';
 END IF;
 LOCK TABLE public.zasp_workflow_records,public.zasp_security_agent_definitions,
  public.zasp_security_agent_definition_versions IN ROW EXCLUSIVE MODE NOWAIT;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test definition release unavailable';
 END IF;
 result_value:=public.zasp_security_agent_mutate_definition(mutation_value,definition_value,
  organization_value,workspace_value,environment_value,principal_value,operation_value,
  key_value,expected_version,intent_value,body_value,audit_value,correlation_value,receipt_value);
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test definition release unavailable';
 END IF;
 RETURN result_value;
END
$mutation$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text) TO zasp_security_agent_api;

-- Replay returns immutable receipts and admits no work. It still requires55
-- authority so the HTTP pre-mutation replay cannot bypass compiled release pins.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_replay_definition(
 organization_value text,workspace_value text,environment_value text,principal_value text,
 operation_value text,key_value text,intent_value jsonb,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $replay$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';
 END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test definition release unavailable';
 END IF;
 result_value:=public.zasp_security_agent_replay_definition(organization_value,workspace_value,
  environment_value,principal_value,operation_value,key_value,intent_value);
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test definition release unavailable';
 END IF;
 RETURN result_value;
END
$replay$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_replay_definition(text,text,text,text,text,text,jsonb,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_replay_definition(text,text,text,text,text,text,jsonb,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_replay_definition(text,text,text,text,text,text,jsonb,text,text) TO zasp_security_agent_api;
