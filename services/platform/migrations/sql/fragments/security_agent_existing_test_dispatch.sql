-- Unexposed candidate. Release55 must not grant this entry point until the
-- linked invocation protocol prevents unknown-outcome redispatch end to end.
CREATE FUNCTION public.zasp_security_agent_test_dispatch(o text,w text,e text,r text,worker_value text,lease_value text,audit_value text,correlation_value text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public
AS $dispatch$
DECLARE run_row public.zasp_security_agent_runs%ROWTYPE;step_row public.zasp_security_agent_steps%ROWTYPE;
 plan_row public.zasp_security_agent_plans%ROWTYPE;definition_row public.zasp_security_agent_definitions%ROWTYPE;
 trigger_row public.zasp_security_agent_trigger_receipts%ROWTYPE;control_row record;control_count integer:=0;
 link_value jsonb;step_value jsonb;outcome_value text;result_digest_value bytea;response_value jsonb;runtime_expires timestamptz;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='existing test dispatch input rejected';END IF;
 -- The existing guard establishes principal, full scope, organization-before-
 -- run lock order, current lease and authoritative budget/stop state.
 IF NOT public.zasp_security_agent_budget_can_start(o,w,e,r,worker_value,lease_value) THEN RETURN public.zasp_security_agent_budget_stop_result(o,w,e,r,'execute');END IF;
 SELECT * INTO STRICT run_row FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO plan_row FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,definition_version)=(o,w,e,r,run_row.definition_id,run_row.definition_version) FOR SHARE;
 IF NOT FOUND OR plan_row.plan_hash IS DISTINCT FROM run_row.plan_hash OR plan_row.plan_hash IS DISTINCT FROM digest(convert_to(plan_row.plan::text,'UTF8'),'sha256') OR plan_row.expires_at<=clock_timestamp()
  OR jsonb_typeof(plan_row.plan->'steps') IS DISTINCT FROM 'array' OR jsonb_array_length(plan_row.plan->'steps')<>1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test plan changed';END IF;
 SELECT * INTO step_row FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index,state)=(o,w,e,r,0,'authorized') FOR UPDATE;
 IF NOT FOUND OR step_row.action_key NOT IN('run_test','rerun_test') OR step_row.input_digest IS DISTINCT FROM digest(convert_to((plan_row.plan->'steps'->0)::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test step changed';END IF;
 SELECT * INTO definition_row FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,run_row.definition_id,run_row.definition_version) AND deleted_at IS NULL FOR SHARE;
 IF NOT FOUND OR definition_row.activation NOT IN('supervised','autonomous') OR definition_row.body->>'autonomy' IS DISTINCT FROM definition_row.activation OR definition_row.body->'enabled' IS DISTINCT FROM 'true'::jsonb
  OR definition_row.body->'allowed_actions' IS DISTINCT FROM jsonb_build_array(step_row.action_key) OR definition_row.body->>'verification_kind' IS DISTINCT FROM 'test_run' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test definition changed';END IF;
 step_value:=plan_row.plan->'steps'->0;
 PERFORM public.zasp_production_security_agent_existing_tests_authorize_step(o,w,e,r,step_row.step_id);
 SELECT * INTO trigger_row FROM public.zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,trigger_id,trigger_digest)=(o,w,e,r,run_row.definition_id,run_row.trigger_id,plan_row.trigger_digest) FOR SHARE;
 IF NOT FOUND OR trigger_row.trigger_kind IS DISTINCT FROM definition_row.body->>'trigger_kind' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test trigger changed';END IF;
 IF trigger_row.trigger_kind='finding' THEN
  PERFORM 1 FROM public.zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,id,version,status,rule)=(o,w,e,trigger_row.trigger_id,trigger_row.trigger_version,'open',definition_row.body->>'trigger_source') FOR SHARE;
 ELSIF trigger_row.trigger_kind='attack_path' THEN
  PERFORM 1 FROM public.zasp_risk_attack_paths p WHERE (organization_id,workspace_id,environment_id,id,version,state)=(o,w,e,trigger_row.trigger_id,trigger_row.trigger_version,definition_row.body->>'trigger_source') AND state IN('observed','verified') AND public.zasp_risk_attack_path_valid(p) FOR SHARE;
 ELSIF trigger_row.trigger_kind='runtime_decision' THEN
  SELECT credential.expires_at INTO runtime_expires FROM public.zasp_runtime_gateway_events event
  JOIN public.zasp_gateway_devices device ON (device.organization_id,device.workspace_id,device.environment_id,device.id,device.state)=(event.organization_id,event.workspace_id,event.environment_id,event.device_id,'active')
  JOIN public.zasp_gateway_credentials credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id,credential.id)=(event.organization_id,event.workspace_id,event.environment_id,event.device_id,event.credential_id)
  WHERE (event.organization_id,event.workspace_id,event.environment_id,event.classification->>'session_id',event.sequence,event.decision,event.classification->>'outcome')=(o,w,e,trigger_row.trigger_id,trigger_row.trigger_version,'block',definition_row.body->>'trigger_source')
   AND credential.revoked_at IS NULL AND credential.expires_at>clock_timestamp()
   AND digest(convert_to(jsonb_build_object('kind','runtime_decision','session_id',trigger_row.trigger_id,'device_id',event.device_id,'event_id',event.event_id,'sequence',event.sequence,'request_digest','sha256:'||encode(event.request_digest,'hex'))::text,'UTF8'),'sha256')=trigger_row.trigger_digest
  FOR SHARE OF event,device,credential;
 ELSE RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test trigger unsupported';
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test evidence changed';END IF;
 FOR control_row IN SELECT * FROM public.zasp_security_agent_kill_switches
  WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*',step_row.action_key)
  ORDER BY organization_id,workspace_id,environment_id,action_key FOR SHARE LOOP
  control_count:=control_count+1;
  IF NOT control_row.execution_enabled THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test execution disabled';END IF;
 END LOOP;
 IF control_count<>3 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test execution disabled';END IF;
 BEGIN
  IF NOT public.zasp_security_agent_budget_reserve_step(o,w,e,r,worker_value,lease_value,step_row.step_id) THEN RETURN public.zasp_security_agent_budget_stop_result(o,w,e,r,'execute');END IF;
  INSERT INTO public.zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state) VALUES(o,w,e,r,step_row.step_id,step_row.action_key,step_row.input_digest,'pending');
  link_value:=public.zasp_security_agent_test_link_enqueue(o,w,e,r,step_row.step_id,correlation_value);
  IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id,target_id,target_kind)=(o,w,e,r,step_row.step_id,step_value->>'test_target_id',step_value->>'test_target_kind')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test target changed';END IF;
  IF plan_row.expires_at<=clock_timestamp() OR runtime_expires<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test authority expired';END IF;
  PERFORM public.zasp_production_security_agent_existing_tests_authorize_step(o,w,e,r,step_row.step_id);
  IF NOT public.zasp_security_agent_budget_can_start(o,w,e,r,worker_value,lease_value) THEN RAISE EXCEPTION USING ERRCODE='PZ001',MESSAGE='existing test budget stopped';END IF;
  outcome_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_effect',r||chr(31)||step_row.step_id||chr(31)||step_row.action_key);
  result_digest_value:=digest(convert_to(link_value::text,'UTF8'),'sha256');
  UPDATE public.zasp_security_agent_effects SET outcome_id=outcome_value,result_digest=result_digest_value WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,step_row.step_id,step_row.action_key);
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,correlation_value,r,step_row.step_id,worker_value,'effect_dispatched',result_digest_value,jsonb_build_object('run_id',r,'step_id',step_row.step_id,'action',step_row.action_key,'test_run_id',link_value->>'test_run_id','test_definition_id',link_value->>'definition_id','outcome_id',outcome_value));
  -- Audit relation/index waits can outlive any earlier check. Keep the lease
  -- until all potentially blocking writes finish, then recheck held authority.
  PERFORM public.zasp_production_security_agent_run_context_test_binding(o,w,e,run_row.definition_id,run_row.definition_version);
  PERFORM public.zasp_production_security_agent_existing_tests_authorize_step(o,w,e,r,step_row.step_id);
  IF plan_row.expires_at<=clock_timestamp() OR runtime_expires<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test authority expired';END IF;
  IF NOT public.zasp_security_agent_budget_can_start(o,w,e,r,worker_value,lease_value) THEN RAISE EXCEPTION USING ERRCODE='PZ001',MESSAGE='existing test budget stopped';END IF;
  UPDATE public.zasp_security_agent_steps SET state='executing',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,step_row.step_id);
  UPDATE public.zasp_security_agent_runs SET state='running',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  response_value:=jsonb_build_object('run_id',r,'state','running','version',run_row.version+1,'step_id',step_row.step_id,'effect_state','pending','outcome_id',outcome_value,'result_digest','sha256:'||encode(result_digest_value,'hex'));
  RETURN response_value;
 EXCEPTION WHEN SQLSTATE 'PZ001' THEN
  -- Roll back reservation, effect, link and enqueue, then persist the stop
  -- outside that subtransaction. Never return a stop alongside hidden work.
  IF NOT public.zasp_security_agent_budget_can_start(o,w,e,r,worker_value,lease_value) THEN RETURN public.zasp_security_agent_budget_stop_result(o,w,e,r,'execute');END IF;
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test budget changed';
 END;
END
$dispatch$;
ALTER FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM PUBLIC;
