-- Execution controls are authority for new work, never for retained history.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_controls_guard(o text,w text,e text,a text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
DECLARE row_value record;count_value integer:=0;
BEGIN
 FOR row_value IN SELECT * FROM public.zasp_security_agent_kill_switches
 WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*')
 OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*',a)
 ORDER BY organization_id,workspace_id,environment_id,action_key FOR SHARE LOOP
  count_value:=count_value+1;
  IF NOT row_value.execution_enabled THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test execution disabled';END IF;
 END LOOP;
 IF count_value<>3 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test execution disabled';END IF;
END
$guard$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_controls_guard(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_controls_guard(text,text,text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_controls(o text,w text,e text,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $controls$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test controls release unavailable';END IF;
 result_value:=public.zasp_security_agent_execution_control_detail(o,w,e);
 RETURN jsonb_set(result_value,'{actions}',(SELECT jsonb_agg(jsonb_build_object('target','action','action_key',k.key,'enabled',coalesce(s.execution_enabled,false),'version',coalesce(s.version,0)) ORDER BY k.key)
 FROM unnest(ARRAY['create_temporary_policy','isolate_session','rerun_test','revoke_integration_connection','run_test','update_finding_response']) k(key)
 LEFT JOIN public.zasp_security_agent_kill_switches s ON (s.organization_id,s.workspace_id,s.environment_id,s.action_key)=(o,w,e,k.key)));
END
$controls$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_controls(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_controls(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_controls(text,text,text,text,text) TO zasp_security_agent_api;

-- Reuse the existing idempotency/version/audit transaction with an exact action
-- allowlist. The clone is private; only the compiled55 wrapper can call it.
DO $control_core$
DECLARE source_value text;needle text;
BEGIN
 source_value:=pg_get_functiondef('public.zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)'::regprocedure);
 source_value:=replace(source_value,'FUNCTION public.zasp_security_agent_mutate_execution_control(','FUNCTION public.zasp_production_security_agent_existing_tests_control_core(');
 needle:='''create_temporary_policy'',''isolate_session'',''revoke_integration_connection'',''update_finding_response''';
 IF (length(source_value)-length(replace(source_value,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test control predecessor changed';END IF;
 source_value:=replace(source_value,needle,'''create_temporary_policy'',''isolate_session'',''rerun_test'',''revoke_integration_connection'',''run_test'',''update_finding_response''');
 source_value:=replace(source_value,'transaction_timestamp()','clock_timestamp()');
 EXECUTE source_value;
END
$control_core$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_control_core(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_control_core(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_set_control(o text,w text,e text,actor_value text,key_value text,target_value text,action_value text,enabled_value boolean,version_value bigint,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $set_control$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test controls release unavailable';END IF;
 -- Global/environment locks precede the action mutation. Lock the mutation
 -- target exclusively so concurrent readers cannot deadlock on lock upgrade.
 PERFORM 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') FOR SHARE;
 IF target_value='action' THEN PERFORM 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=(o,w,e,'*') FOR SHARE;END IF;
 result_value:=public.zasp_production_security_agent_existing_tests_control_core(o,w,e,actor_value,key_value,target_value,action_value,enabled_value,version_value,fresh_value,audit_value,correlation_value,receipt_value);
 IF fresh_value IS NULL OR fresh_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent control authority expired';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test controls release unavailable';END IF;
 RETURN result_value;
END
$set_control$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_set_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_set_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_set_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text,text,text) TO zasp_security_agent_api;
