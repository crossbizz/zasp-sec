-- Private projection: callers must establish scoped API read/decision authority.
-- Approval describes permission to enqueue, never completed verification.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_approval_value(o text,w text,e text,a text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $projection$
DECLARE approval_row public.zasp_security_agent_approvals%ROWTYPE;
 run_row public.zasp_security_agent_runs%ROWTYPE;step_row public.zasp_security_agent_steps%ROWTYPE;
 plan_row public.zasp_security_agent_plans%ROWTYPE;item jsonb;
BEGIN
 SELECT * INTO STRICT approval_row FROM public.zasp_security_agent_approvals
 WHERE (organization_id,workspace_id,environment_id,approval_id)=(o,w,e,a);
 SELECT * INTO STRICT step_row FROM public.zasp_security_agent_steps
 WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,approval_row.run_id,approval_row.step_id);
 IF step_row.action_key NOT IN('run_test','rerun_test') THEN
  RETURN public.zasp_security_agent_approval_value_v24(o,w,e,a);
 END IF;
 SELECT * INTO STRICT run_row FROM public.zasp_security_agent_runs
 WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,approval_row.run_id);
 SELECT * INTO STRICT plan_row FROM public.zasp_security_agent_plans
 WHERE (organization_id,workspace_id,environment_id,run_id,plan_hash)=(o,w,e,approval_row.run_id,approval_row.plan_hash);
 item:=plan_row.plan->'steps'->step_row.step_index;
 IF run_row.plan_hash IS DISTINCT FROM approval_row.plan_hash
  OR plan_row.plan_hash IS DISTINCT FROM digest(convert_to(plan_row.plan::text,'UTF8'),'sha256')
  OR (plan_row.definition_id,plan_row.definition_version) IS DISTINCT FROM (run_row.definition_id,run_row.definition_version)
  OR step_row.input_digest IS DISTINCT FROM digest(convert_to(item::text,'UTF8'),'sha256')
  OR item->>'step_id' IS DISTINCT FROM step_row.step_id
  OR item->>'action' IS DISTINCT FROM step_row.action_key
  OR item->'index' IS DISTINCT FROM to_jsonb(step_row.step_index)
  OR item->>'authorization' IS DISTINCT FROM 'approval_required'
  OR step_row.authorization_result IS DISTINCT FROM 'approval_required'
  OR NOT COALESCE(public.zasp_valid_product_id(item->>'target_id'),false)
  OR NOT COALESCE(CASE WHEN jsonb_typeof(item->'test_definition_version')='number' THEN
   (item->>'test_definition_version')::numeric BETWEEN 1 AND 1000000
   AND trunc((item->>'test_definition_version')::numeric)=(item->>'test_definition_version')::numeric ELSE false END,false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test approval authority changed';END IF;
 RETURN jsonb_build_object('id',a,'run_id',approval_row.run_id,'step_id',approval_row.step_id,
  'state',approval_row.state,'expires_at',to_char(approval_row.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'version',approval_row.version,'expected_effect',CASE step_row.action_key WHEN 'run_test' THEN 'Run existing test' ELSE 'Rerun existing test' END,
  'reversible',false,'ttl_seconds',0,'evidence_summary',jsonb_build_array(run_row.trigger_id));
END
$projection$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_approval_value(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_approval_value(text,text,text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_decide_approval(
 o text,w text,e text,a text,actor_value text,key_value text,expected_version bigint,
 decision_value text,fresh_auth_value timestamptz,audit_value text,correlation_value text,receipt_value text,
 expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $decision$
DECLARE response_value jsonb;action_value text;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';
 END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test approval release unavailable';
 END IF;
 SELECT s.action_key INTO action_value FROM public.zasp_security_agent_approvals p
 JOIN public.zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
 WHERE (p.organization_id,p.workspace_id,p.environment_id,p.approval_id)=(o,w,e,a);
 IF action_value IS DISTINCT FROM 'run_test' AND action_value IS DISTINCT FROM 'rerun_test' THEN
  response_value:=public.zasp_security_agent_decide_approval_v24(o,w,e,a,actor_value,key_value,expected_version,
   decision_value,fresh_auth_value,audit_value,correlation_value,receipt_value);
 ELSE
 -- Preserve the original principal/fresh-auth/requester/CAS/idempotency checks.
 -- Do not call v24: its projection rejects test actions after the mutation.
 response_value:=public.zasp_security_agent_decide_approval(o,w,e,a,actor_value,key_value,expected_version,
  decision_value,fresh_auth_value,audit_value,correlation_value,receipt_value);
 IF response_value->>'replayed' IS DISTINCT FROM 'true' THEN
 response_value:=response_value||public.zasp_production_security_agent_existing_tests_approval_value(o,w,e,a);
 -- Persist the displayed result in the same statement as the decision. Replay
 -- must return that receipt, not project mutable current approval state.
 UPDATE public.zasp_security_agent_request_receipts SET response=response_value
 WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,receipt_id)=
  (o,w,e,actor_value,'decideSecurityAgentApproval',key_value,a,receipt_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test approval receipt unavailable';END IF;
 END IF;
 END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test approval release unavailable';
 END IF;
 RETURN response_value;
END
$decision$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text) TO zasp_security_agent_api;
