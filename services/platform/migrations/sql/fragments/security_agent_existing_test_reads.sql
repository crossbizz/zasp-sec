-- Extend immutable predecessor read implementations under private55 names.
-- Never replace published54 bodies or grant callers access to an ungated core.
DO $read_cores$
DECLARE item record;source_value text;old_value text;new_value text;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('zasp_security_agent_run_detail_v24(text,text,text,text)','zasp_security_agent_run_detail_v24','zasp_production_security_agent_existing_tests_run_detail_core'),
  ('zasp_security_agent_approval_detail_v24(text,text,text,text)','zasp_security_agent_approval_detail_v24','zasp_production_security_agent_existing_tests_approval_core'),
  ('zasp_security_agent_approval_page_v24(text,text,text,text,text,timestamptz,text,integer)','zasp_security_agent_approval_page_v24','zasp_production_security_agent_existing_tests_page_core'),
  ('zasp_security_agent_run_context_v54(text,text,text,text)','zasp_security_agent_run_context_v54','zasp_production_security_agent_existing_tests_run_context_core'),
  ('zasp_production_security_agent_run_context_approval(text,text,text,text)','zasp_production_security_agent_run_context_approval','zasp_production_security_agent_existing_tests_approval_ctx_core'),
  ('zasp_production_security_agent_run_context_approval_page(text,text,text,text,text,timestamptz,text,integer)','zasp_production_security_agent_run_context_approval_page','zasp_production_security_agent_existing_tests_page_ctx_core')
 ) AS functions(signature,old_name,new_name) LOOP
  source_value:=pg_get_functiondef(to_regprocedure('public.'||item.signature));
  IF source_value IS NULL OR position('FUNCTION public.'||item.old_name||'(' IN source_value)=0 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test read predecessor unavailable';
  END IF;
  source_value:=replace(source_value,'FUNCTION public.'||item.old_name||'(','FUNCTION public.'||item.new_name||'(');
  source_value:=replace(source_value,'zasp_security_agent_approval_value_v24(','zasp_production_security_agent_existing_tests_approval_value(');
  source_value:=replace(source_value,'zasp_security_agent_run_detail_v24(','zasp_production_security_agent_existing_tests_run_detail_core(');
  source_value:=replace(source_value,'zasp_security_agent_approval_detail_v24(','zasp_production_security_agent_existing_tests_approval_core(');
  source_value:=replace(source_value,'zasp_security_agent_approval_page_v24(','zasp_production_security_agent_existing_tests_page_core(');
  source_value:=replace(source_value,'zasp_security_agent_run_context_v54(','zasp_production_security_agent_existing_tests_run_context_core(');
  IF item.old_name='zasp_security_agent_run_context_v54' THEN
   old_value:=$old$IF action_value NOT IN('update_finding_response','create_temporary_policy','isolate_session','revoke_integration_connection') THEN$old$;
   new_value:=$new$IF action_value NOT IN('update_finding_response','create_temporary_policy','isolate_session','revoke_integration_connection','run_test','rerun_test') THEN$new$;
   IF (length(source_value)-length(replace(source_value,old_value,'')))/length(old_value)<>1 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test context action predecessor changed';
   END IF;
   source_value:=replace(source_value,old_value,new_value);
   old_value:=$old$WHEN 'revoke_integration_connection' THEN jsonb_build_object('target_id',planned_step->'target_id','integration_id',planned_step->'integration_id') END;$old$;
   new_value:=$new$WHEN 'revoke_integration_connection' THEN jsonb_build_object('target_id',planned_step->'target_id','integration_id',planned_step->'integration_id')
     WHEN 'run_test' THEN jsonb_build_object('target_id',planned_step->'target_id','expected_version',planned_step->'test_definition_version')
     WHEN 'rerun_test' THEN jsonb_build_object('target_id',planned_step->'target_id','expected_version',planned_step->'test_definition_version') END;$new$;
   IF (length(source_value)-length(replace(source_value,old_value,'')))/length(old_value)<>1 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test context arguments predecessor changed';
   END IF;
   source_value:=replace(source_value,old_value,new_value);
  END IF;
  EXECUTE source_value;
  EXECUTE format('ALTER FUNCTION public.%s OWNER TO zasp_discovery_authority',replace(item.signature,item.old_name,item.new_name));
  EXECUTE format('REVOKE ALL ON FUNCTION public.%s FROM PUBLIC',replace(item.signature,item.old_name,item.new_name));
 END LOOP;
END
$read_cores$;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_approval(o text,w text,e text,a text,expected_checksum text,expected_fingerprint text)
RETURNS SETOF jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';
 END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test approval release unavailable';
 END IF;
 RETURN QUERY SELECT * FROM public.zasp_production_security_agent_existing_tests_approval_ctx_core(o,w,e,a);
END
$read$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_approval(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_approval(text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_approval(text,text,text,text,text,text) TO zasp_security_agent_api;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_approval_page(o text,w text,e text,state_value text,run_value text,before_created_value timestamptz,before_id_value text,limit_value integer,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';
 END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test approval release unavailable';
 END IF;
 RETURN public.zasp_production_security_agent_existing_tests_page_ctx_core(o,w,e,state_value,run_value,before_created_value,before_id_value,limit_value);
END
$read$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_approval_page(text,text,text,text,text,timestamptz,text,integer,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_approval_page(text,text,text,text,text,timestamptz,text,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_approval_page(text,text,text,text,text,timestamptz,text,integer,text,text) TO zasp_security_agent_api;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_run_context(o text,w text,e text,r text,expected_checksum text,expected_fingerprint text)
RETURNS SETOF jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';
 END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test read release unavailable';
 END IF;
 RETURN QUERY SELECT * FROM public.zasp_production_security_agent_existing_tests_run_context_core(o,w,e,r);
END
$read$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_run_context(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_run_context(text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_run_context(text,text,text,text,text,text) TO zasp_security_agent_api;
