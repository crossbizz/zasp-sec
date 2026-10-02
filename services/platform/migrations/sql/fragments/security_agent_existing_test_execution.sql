-- Registered execution entrypoint. Private dispatch remains inaccessible to
-- application roles; rollout still requires the complete schema55 candidate.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_execute_run(
 o text,w text,e text,r text,worker_value text,lease_value text,audit_value text,correlation_value text,
 expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $execute$
DECLARE run_row public.zasp_security_agent_runs%ROWTYPE;plan_row public.zasp_security_agent_plans%ROWTYPE;
 definition_row public.zasp_security_agent_definitions%ROWTYPE;step_row public.zasp_security_agent_steps%ROWTYPE;
 test_count integer:=0;test_step text;test_intent boolean;result_value jsonb;
 deadline_value timestamptz;budget_deadline timestamptz;target_deadline timestamptz;credential_deadline timestamptz;runtime_deadline timestamptz;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='existing test execution principal rejected';
 END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test execution release unavailable';
 END IF;
 IF NOT public.zasp_security_agent_budget_can_start(o,w,e,r,worker_value,lease_value) THEN
  result_value:=public.zasp_security_agent_budget_stop_result(o,w,e,r,'execute');
 ELSE
  SELECT * INTO STRICT run_row FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  SELECT deadline_at INTO STRICT budget_deadline FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  deadline_value:=LEAST(run_row.lease_expires_at,budget_deadline);
  SELECT * INTO plan_row FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
  FOR step_row IN SELECT * FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_index FOR UPDATE LOOP
   IF step_row.action_key IN('run_test','rerun_test') THEN test_count:=test_count+1;test_step:=step_row.step_id;END IF;
  END LOOP;
  SELECT * INTO definition_row FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,run_row.definition_id,run_row.definition_version) AND deleted_at IS NULL FOR SHARE;
  deadline_value:=LEAST(deadline_value,plan_row.expires_at,
   (SELECT min(a.expires_at) FROM public.zasp_security_agent_approvals a JOIN public.zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
    WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.state,s.state)=(o,w,e,r,'approved','authorized')));
  IF definition_row.body->>'trigger_kind'='runtime_decision' THEN
   SELECT credential.expires_at INTO STRICT runtime_deadline FROM public.zasp_runtime_gateway_events event
    JOIN public.zasp_gateway_credentials credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id,credential.id)=(event.organization_id,event.workspace_id,event.environment_id,event.device_id,event.credential_id)
    JOIN public.zasp_security_agent_trigger_receipts trigger ON (trigger.organization_id,trigger.workspace_id,trigger.environment_id,trigger.trigger_id,trigger.trigger_version)=(event.organization_id,event.workspace_id,event.environment_id,event.classification->>'session_id',event.sequence)
    WHERE (trigger.organization_id,trigger.workspace_id,trigger.environment_id,trigger.run_id)=(o,w,e,r);
   deadline_value:=LEAST(deadline_value,runtime_deadline);
  END IF;
  test_intent:=COALESCE(definition_row.body ? 'existing_test' OR definition_row.body->'allowed_actions' ?| ARRAY['run_test','rerun_test'],false)
   OR test_count>0 OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(plan_row.plan->'steps')='array' THEN plan_row.plan->'steps' ELSE '[]'::jsonb END) item WHERE item->>'action' IN('run_test','rerun_test'));
  IF test_intent THEN
   IF test_count<>1 OR budget_deadline IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test execution intent changed';END IF;
   PERFORM public.zasp_production_security_agent_existing_tests_authorize_step(o,w,e,r,test_step);
   PERFORM public.zasp_production_security_agent_run_context_test_binding(o,w,e,run_row.definition_id,run_row.definition_version);
   SELECT target.fresh_until,credential.valid_until INTO STRICT target_deadline,credential_deadline
    FROM public.zasp_red_team_definitions test
    JOIN public.zasp_inventory_entities target ON (target.organization_id,target.workspace_id,target.environment_id,target.id)=(test.organization_id,test.workspace_id,test.environment_id,test.target_id)
    JOIN public.zasp_attack_lab_credential_bindings credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.target_id,credential.credential_reference,credential.state)=(target.organization_id,target.workspace_id,target.environment_id,target.id,target.winning_attributes->'red_team'->>'credential_reference','active')
    WHERE (test.organization_id,test.workspace_id,test.environment_id,test.definition_id)=(o,w,e,definition_row.body->'existing_test'->>'definition_id');
   deadline_value:=LEAST(deadline_value,plan_row.expires_at,target_deadline,credential_deadline,
    (SELECT min(expires_at) FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,test_step)));
   result_value:=public.zasp_security_agent_test_dispatch(o,w,e,r,worker_value,lease_value,audit_value,correlation_value);
   IF result_value->>'state'='running' THEN
    PERFORM public.zasp_production_security_agent_existing_tests_authorize_invocation(o,w,e,r,test_step);
    PERFORM public.zasp_production_security_agent_run_context_test_binding(o,w,e,run_row.definition_id,run_row.definition_version);
   END IF;
  ELSE
   result_value:=public.zasp_security_agent_execute_run_v24(o,w,e,r,worker_value,lease_value,audit_value,correlation_value);
  END IF;
 END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test execution release unavailable';
 END IF;
 -- Dispatch clears the lease. Validate the captured authority after its final
 -- writes and our final readiness work, without relying on cleared columns.
 IF result_value->>'state'<>'needs_human' AND (deadline_value IS NULL OR deadline_value<=clock_timestamp()) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test execution authority expired';
 END IF;
 RETURN result_value;
END
$execute$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_execute_run(text,text,text,text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_execute_run(text,text,text,text,text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_execute_run(text,text,text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;
