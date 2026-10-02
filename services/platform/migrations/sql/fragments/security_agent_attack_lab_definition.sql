-- Extend only the existing closed pair. The original resolver remains byte for
-- byte in the saved predecessor; other actions keep their release55 authority.
DO $binding$
DECLARE signature_value text:='zasp_production_security_agent_run_context_test_binding(text,text,text,text,bigint)';d text;anchor text;
BEGIN
 PERFORM public.zasp_sa_attack_lab_save(signature_value);
 d:=pg_get_functiondef(('public.'||signature_value)::regprocedure);
 anchor:='body_value->''allowed_actions'' IN (''["run_test"]''::jsonb,''["rerun_test"]''::jsonb) AND body_value->>''verification_kind''=''test_run''';
 IF (length(d)-length(replace(d,anchor,'')))/length(anchor)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab binding predecessor rejected';END IF;
 d:=replace(d,anchor,'('||anchor||' OR body_value->''allowed_actions''=''["start_attack_lab"]''::jsonb AND body_value->>''verification_kind''=''attack_lab_run'' AND public.zasp_sa_attack_lab_guard())');
 EXECUTE d;
END $binding$;

-- Existing admission and its public run wrapper still own provenance, trigger
-- receipts and accounting. Add the exact new pair without weakening old pairs.
DO $admission$
DECLARE signature_value text;d text;anchor text;
BEGIN
 signature_value:='zasp_production_security_agent_existing_tests_admit(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)';
 PERFORM public.zasp_sa_attack_lab_save(signature_value);
 d:=pg_get_functiondef(('public.'||signature_value)::regprocedure);
 anchor:='action_value NOT IN(''run_test'',''rerun_test'')';
 d:=replace(d,anchor,'action_value NOT IN(''run_test'',''rerun_test'',''start_attack_lab'')');
 anchor:='definition_row.body->>''verification_kind'' IS DISTINCT FROM ''test_run''';
 d:=replace(d,anchor,'definition_row.body->>''verification_kind'' IS DISTINCT FROM (CASE action_value WHEN ''start_attack_lab'' THEN ''attack_lab_run'' ELSE ''test_run'' END)');
 EXECUTE d;
END $admission$;

DO $fences$
DECLARE p record;d text;needle text:='ARRAY[''run_test'',''rerun_test'']';signature_value text;
BEGIN
 FOR p IN SELECT oid,proname,pg_get_function_identity_arguments(oid) args FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname IN(
 'zasp_security_agent_mutate_definition','zasp_security_agent_activate','zasp_security_agent_simulate',
 'zasp_production_security_agent_existing_tests_activate_core','zasp_production_security_agent_existing_tests_simulate_core','zasp_production_security_agent_existing_tests_run') LOOP
  signature_value:=replace(p.oid::regprocedure::text,'public.','');
  PERFORM public.zasp_sa_attack_lab_save(signature_value);
  d:=pg_get_functiondef(p.oid);
  IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab lifecycle fence predecessor rejected';END IF;
  EXECUTE replace(d,needle,'ARRAY[''run_test'',''rerun_test'',''start_attack_lab'']');
 END LOOP;
 signature_value:='zasp_production_security_agent_existing_tests_candidate_binding(text,text,text,jsonb,text)';
 PERFORM public.zasp_sa_attack_lab_save(signature_value);
 d:=pg_get_functiondef(('public.'||signature_value)::regprocedure);
 needle:='b->''allowed_actions'' IN(''["run_test"]''::jsonb,''["rerun_test"]''::jsonb) AND b->>''verification_kind''=''test_run''';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab scheduler predecessor rejected';END IF;
 PERFORM set_config('check_function_bodies','off',true);
 EXECUTE replace(d,needle,'('||needle||' OR b->''allowed_actions''=''["start_attack_lab"]''::jsonb AND b->>''verification_kind''=''attack_lab_run'' AND public.zasp_sa_attack_lab_guard())');
 PERFORM set_config('check_function_bodies','on',true);
 signature_value:='zasp_production_security_agent_existing_tests_control_core(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)';
 PERFORM public.zasp_sa_attack_lab_save(signature_value);
 d:=pg_get_functiondef(('public.'||signature_value)::regprocedure);
 needle:='''rerun_test'',''revoke_integration_connection'',''run_test''';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab control predecessor rejected';END IF;
 EXECUTE replace(d,needle,needle||',''start_attack_lab''');
 signature_value:='zasp_production_security_agent_existing_tests_controls(text,text,text,text,text)';
 PERFORM public.zasp_sa_attack_lab_save(signature_value);
 d:=pg_get_functiondef(('public.'||signature_value)::regprocedure);
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab controls read predecessor rejected';END IF;
 EXECUTE replace(d,needle,needle||',''start_attack_lab''');
END $fences$;
