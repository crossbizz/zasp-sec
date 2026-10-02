-- Old callers cannot authorize the new exact-test contract. Preserve the live
-- release54 bodies (including53 budget guards) for private55 delegation and
-- unused rollback. Published migration files and function signatures stay put.
DO $legacy_lifecycle_fence$
DECLARE item record;source_value text;anchor_value text;guard_value text;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('zasp_security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)','zasp_security_agent_activate'),
  ('zasp_security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text)','zasp_security_agent_simulate')
 ) AS functions(signature,name) LOOP
  source_value:=pg_get_functiondef(('public.'||item.signature)::regprocedure);
  IF source_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle predecessor missing';END IF;
  EXECUTE replace(source_value,'FUNCTION public.'||item.name||'(','FUNCTION zasp_existing_tests_predecessor.'||item.name||'(');
  EXECUTE format('ALTER FUNCTION zasp_existing_tests_predecessor.%s OWNER TO zasp_discovery_authority',item.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_existing_tests_predecessor.%s FROM PUBLIC',item.signature);

  -- The inherited row lock is already held here, before any authority writes.
  -- A preflight lookup before that lock would race a concurrent draft update.
  anchor_value:=CASE item.name WHEN 'zasp_security_agent_activate'
   THEN '  IF target_activation IN(''supervised'',''autonomous'') THEN'
   ELSE '  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE=''22023'',MESSAGE=''security agent simulation definition rejected'';END IF;' END;
  IF (length(source_value)-length(replace(source_value,anchor_value,'')))/length(anchor_value)<>1 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle lock anchor changed';
  END IF;
  guard_value:=$fresh$
  IF definition_row.body ? 'existing_test' OR definition_row.body->'allowed_actions' ?| ARRAY['run_test','rerun_test'] THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle requires versioned authority';
  END IF;
$fresh$;
  IF item.name='zasp_security_agent_activate' THEN
   source_value:=replace(source_value,anchor_value,guard_value||anchor_value);
  ELSE
   source_value:=replace(source_value,anchor_value,anchor_value||guard_value);
  END IF;

  -- A receipt must not bypass the fence after its current definition changes.
  -- Match the persisted input version as well as the current scoped definition.
  anchor_value:='    RETURN receipt_row.response||jsonb_build_object(''replayed'',true);';
  IF (length(source_value)-length(replace(source_value,anchor_value,'')))/length(anchor_value)<>1 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle replay anchor changed';
  END IF;
  guard_value:=$replay$
    IF EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions d
      WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=(organization_value,workspace_value,environment_value,definition_value)
       AND (d.body ? 'existing_test' OR d.body->'allowed_actions' ?| ARRAY['run_test','rerun_test']))
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions h
      WHERE (h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(organization_value,workspace_value,environment_value,definition_value,receipt_row.expected_version)
       AND (h.definition ? 'existing_test' OR h.definition->'allowed_actions' ?| ARRAY['run_test','rerun_test'])) THEN
     RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle requires versioned authority';
    END IF;
$replay$;
  EXECUTE replace(source_value,anchor_value,guard_value||anchor_value);
 END LOOP;
END
$legacy_lifecycle_fence$;

-- Lock scoped evidence before simulation writes and recheck after those writes.
-- Preserve inherited accepted evidence kinds; no evidence is a target override.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_sim_evidence(o text,w text,e text,values_value jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $evidence$
DECLARE evidence_value text;
BEGIN
 FOR evidence_value IN SELECT jsonb_array_elements_text(values_value) ORDER BY 1 LOOP
  PERFORM 1 FROM public.zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,evidence_value) AND status IN('open','under_review','accepted') FOR SHARE;
  IF FOUND THEN CONTINUE;END IF;
  PERFORM 1 FROM public.zasp_risk_attack_paths WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,evidence_value) AND state IN('observed','verified') FOR SHARE;
  IF FOUND THEN CONTINUE;END IF;
  PERFORM 1 FROM public.zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state)=(o,w,e,evidence_value,'active') FOR SHARE;
  IF FOUND THEN CONTINUE;END IF;
  PERFORM 1 FROM public.zasp_inventory_evidence WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,evidence_value) FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent simulation evidence denied';END IF;
 END LOOP;
END
$evidence$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_sim_evidence(text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_sim_evidence(text,text,text,jsonb) FROM PUBLIC;

-- New private cores belong to the55 prefix, not the predecessor schema: unused
-- rollback removes these cores and restores only genuine saved public bodies.
DO $lifecycle_cores$
DECLARE item record;source_value text;anchor_value text;guard_value text;core_name text;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('zasp_security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)','zasp_security_agent_activate','activate'),
  ('zasp_security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text)','zasp_security_agent_simulate','simulate')
 ) AS functions(signature,name,operation) LOOP
  core_name:='zasp_production_security_agent_existing_tests_'||item.operation||'_core';
  source_value:=pg_get_functiondef(('zasp_existing_tests_predecessor.'||item.signature)::regprocedure);
  source_value:=replace(source_value,'FUNCTION zasp_existing_tests_predecessor.'||item.name||'(','FUNCTION public.'||core_name||'(');
  anchor_value:='DECLARE definition_row ';
  IF (length(source_value)-length(replace(source_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle declaration changed';END IF;
  source_value:=replace(source_value,anchor_value,'DECLARE binding_value jsonb; definition_row ');
  -- Expiry checks must not inherit the transaction-start clock across waits.
  source_value:=replace(source_value,'<=transaction_timestamp()','<=clock_timestamp()');

  IF item.operation='activate' THEN
   anchor_value:='  IF target_activation IN(''supervised'',''autonomous'') THEN';
   guard_value:=$activation$
  IF definition_row.body ? 'existing_test' OR definition_row.body->'allowed_actions' ?| ARRAY['run_test','rerun_test'] THEN
   binding_value:=public.zasp_production_security_agent_run_context_test_binding(organization_value,workspace_value,environment_value,definition_value,expected_version);
   IF target_activation IN('supervised','autonomous') THEN
    PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(organization_value,workspace_value,environment_value,definition_row.body->'allowed_actions'->>0);
    PERFORM public.zasp_production_security_agent_run_context_test_binding(organization_value,workspace_value,environment_value,definition_value,expected_version);
    IF fresh_auth_expires_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent activation authority expired';END IF;
   END IF;
  END IF;
$activation$;
  ELSE
   anchor_value:='  SELECT jsonb_agg(jsonb_build_object(''index'',ordinality-1,';
   guard_value:=$simulation$
  IF definition_row.body ? 'existing_test' OR definition_row.body->'allowed_actions' ?| ARRAY['run_test','rerun_test'] THEN
   binding_value:=public.zasp_production_security_agent_run_context_test_binding(organization_value,workspace_value,environment_value,definition_value,expected_version);
  END IF;
  PERFORM public.zasp_production_security_agent_existing_tests_sim_evidence(organization_value,workspace_value,environment_value,canonical_evidence);
$simulation$;
  END IF;
  IF (length(source_value)-length(replace(source_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle fresh anchor changed';END IF;
  source_value:=replace(source_value,anchor_value,guard_value||anchor_value);

  IF item.operation='simulate' THEN
   -- Expiry is generated by the HTTP handler, not supplied by the user's
   -- idempotent intent. Reconstruct the original digest with its durable expiry
   -- under the inherited idempotency lock; never renew that expiry on replay.
   anchor_value:='  IF FOUND THEN';
   IF (length(source_value)-length(replace(source_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test simulation receipt anchor changed';END IF;
   guard_value:=$receipt_expiry$
    intent_value:=jsonb_set(intent_value,'{expires_at}',receipt_row.response->'expires_at');
    intent_digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');
$receipt_expiry$;
   source_value:=replace(source_value,anchor_value,anchor_value||chr(10)||guard_value);
   anchor_value:='  plan_digest:=digest(convert_to(plan_value::text,''UTF8''),''sha256'');';
   IF (length(source_value)-length(replace(source_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test simulation digest anchor changed';END IF;
   source_value:=replace(source_value,anchor_value,'  IF binding_value IS NOT NULL THEN plan_value:=plan_value||jsonb_build_object(''existing_test'',binding_value);END IF;'||chr(10)||anchor_value);
  END IF;

  anchor_value:='    RETURN receipt_row.response||jsonb_build_object(''replayed'',true);';
  IF item.operation='activate' THEN
   guard_value:=$activation_replay$
    IF fresh_auth_expires_value<=clock_timestamp() OR receipt_row.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent activation authority expired';END IF;
    IF target_activation IN('supervised','autonomous') AND EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions h
      WHERE (h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(organization_value,workspace_value,environment_value,definition_value,expected_version)
       AND (h.definition ? 'existing_test' OR h.definition->'allowed_actions' ?| ARRAY['run_test','rerun_test'])) THEN
     SELECT * INTO definition_row FROM public.zasp_security_agent_definitions
      WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(organization_value,workspace_value,environment_value,definition_value,(receipt_row.response->>'version')::bigint) AND deleted_at IS NULL FOR SHARE;
     IF NOT FOUND OR definition_row.activation IS DISTINCT FROM target_activation OR definition_row.body->>'autonomy' IS DISTINCT FROM target_activation OR definition_row.body->'enabled' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test activation replay changed';END IF;
     binding_value:=public.zasp_production_security_agent_run_context_test_binding(organization_value,workspace_value,environment_value,definition_value,definition_row.version);
     PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(organization_value,workspace_value,environment_value,definition_row.body->'allowed_actions'->>0);
     PERFORM public.zasp_production_security_agent_run_context_test_binding(organization_value,workspace_value,environment_value,definition_value,definition_row.version);
     IF (receipt_row.intent->>'fresh_auth_expires_at')::timestamptz IS NULL OR (receipt_row.intent->>'fresh_auth_expires_at')::timestamptz<=clock_timestamp() OR fresh_auth_expires_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent activation authority expired';END IF;
    END IF;
$activation_replay$;
  ELSE
   guard_value:=$simulation_replay$
    SELECT * INTO STRICT definition_row FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(organization_value,workspace_value,environment_value,definition_value,expected_version) AND deleted_at IS NULL FOR SHARE;
    IF definition_row.body ? 'existing_test' OR definition_row.body->'allowed_actions' ?| ARRAY['run_test','rerun_test'] THEN
     binding_value:=public.zasp_production_security_agent_run_context_test_binding(organization_value,workspace_value,environment_value,definition_value,expected_version);
     PERFORM 1 FROM public.zasp_security_agent_plans p JOIN public.zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id)
     WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id,p.definition_id,p.definition_version)=(organization_value,workspace_value,environment_value,receipt_row.response->>'run_id',definition_value,expected_version)
      AND (r.definition_id,r.definition_version,r.state)=(definition_value,expected_version,'simulated') AND r.completed_at IS NOT NULL
      AND p.plan->'existing_test'=binding_value AND p.plan_hash=digest(convert_to(p.plan::text,'UTF8'),'sha256') AND r.plan_hash=p.plan_hash
      AND 'sha256:'||encode(p.plan_hash,'hex')=receipt_row.response->>'plan_hash'
      AND p.expires_at>clock_timestamp() AND p.expires_at<=expires_value AND p.expires_at=(receipt_row.response->>'expires_at')::timestamptz
      AND p.plan->>'definition_id'=definition_value AND p.plan->'definition_version'=to_jsonb(expected_version)
      AND p.plan->'target_scope'=jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value)
     FOR SHARE OF p,r;
     IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test simulation replay binding changed';END IF;
    END IF;
    PERFORM public.zasp_production_security_agent_existing_tests_sim_evidence(organization_value,workspace_value,environment_value,receipt_row.response->'matched_evidence_ids');
    IF binding_value IS NOT NULL AND public.zasp_production_security_agent_run_context_test_binding(organization_value,workspace_value,environment_value,definition_value,expected_version) IS DISTINCT FROM binding_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test simulation binding changed';END IF;
    IF expires_value<=clock_timestamp() OR receipt_row.expires_at<=clock_timestamp() OR (receipt_row.response->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent simulation authority expired';END IF;
$simulation_replay$;
  END IF;
  IF (length(source_value)-length(replace(source_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle replay anchor changed';END IF;
  source_value:=replace(source_value,anchor_value,guard_value||anchor_value);

  anchor_value:='  RETURN response_value;';
  IF item.operation='activate' THEN
   source_value:=replace(source_value,'expected_version,intent_value,intent_digest_value,response_value','expected_version,intent_value||jsonb_build_object(''fresh_auth_expires_at'',fresh_auth_expires_value),intent_digest_value,response_value');
   guard_value:=$activation_final$
  IF binding_value IS NOT NULL AND public.zasp_production_security_agent_run_context_test_binding(organization_value,workspace_value,environment_value,definition_value,definition_row.version) IS DISTINCT FROM binding_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test activation binding changed';END IF;
  IF fresh_auth_expires_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent activation authority expired';END IF;
$activation_final$;
  ELSE
   guard_value:=$simulation_final$
  PERFORM public.zasp_production_security_agent_existing_tests_sim_evidence(organization_value,workspace_value,environment_value,canonical_evidence);
  IF binding_value IS NOT NULL AND public.zasp_production_security_agent_run_context_test_binding(organization_value,workspace_value,environment_value,definition_value,expected_version) IS DISTINCT FROM binding_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test simulation binding changed';END IF;
  IF expires_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent simulation authority expired';END IF;
$simulation_final$;
  END IF;
  IF (length(source_value)-length(replace(source_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle return anchor changed';END IF;
  source_value:=replace(source_value,anchor_value,guard_value||anchor_value);
  EXECUTE source_value;
  EXECUTE format('ALTER FUNCTION public.%s OWNER TO zasp_discovery_authority',replace(item.signature,item.name,core_name));
  EXECUTE format('REVOKE ALL ON FUNCTION public.%s FROM PUBLIC',replace(item.signature,item.name,core_name));
 END LOOP;
END
$lifecycle_cores$;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_activate(o text,w text,e text,d text,a text,k text,v bigint,activation_value text,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $activate$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle release unavailable';END IF;
 LOCK TABLE public.zasp_workflow_records,public.zasp_security_agent_definitions,public.zasp_security_agent_definition_versions IN ROW EXCLUSIVE MODE;
 result_value:=public.zasp_production_security_agent_existing_tests_activate_core(o,w,e,d,a,k,v,activation_value,fresh_value,audit_value,correlation_value,receipt_value);
 IF fresh_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent activation authority expired';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle release unavailable';END IF;
 RETURN result_value;
END
$activate$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text) TO zasp_security_agent_api;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_simulate(o text,w text,e text,d text,a text,k text,v bigint,r text,goal_value text,evidence_value jsonb,expires_value timestamptz,audit_value text,correlation_value text,receipt_value text,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $simulate$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle release unavailable';END IF;
 LOCK TABLE public.zasp_workflow_records,public.zasp_security_agent_definitions,public.zasp_security_agent_definition_versions IN ROW EXCLUSIVE MODE;
 result_value:=public.zasp_production_security_agent_existing_tests_simulate_core(o,w,e,d,a,k,v,r,goal_value,evidence_value,expires_value,audit_value,correlation_value,receipt_value);
 IF expires_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent simulation authority expired';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test lifecycle release unavailable';END IF;
 RETURN result_value;
END
$simulate$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text,text,text) TO zasp_security_agent_api;
