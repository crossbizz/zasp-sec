-- Complete finding changes are mandatory approval evidence, not negotiated
-- planner prose. These private helpers consume the already verified78 plan.
CREATE FUNCTION zasp_temporal78.approval_envelope(o text,w text,e text,a text,env jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $projection$
DECLARE detail_value jsonb;result_value jsonb;BEGIN
 SELECT value-'approval_context' INTO detail_value FROM jsonb_array_elements(env->'detail'->'approvals') item(value) WHERE value->>'id'=a;
 IF detail_value IS NULL OR detail_value->>'expected_effect' NOT IN('Move finding to under review','Assign investigator and update finding response') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding approval display changed';END IF;
 detail_value:=detail_value||jsonb_build_object('expected_effect','Assign investigator and update finding response');
 result_value:=public.zasp_production_security_agent_run_context_approval_assemble(o,w,e,a,detail_value,env);
 IF result_value->'context'->>'action'<>'update_finding_response' OR NOT zasp_sa_multistep_prior.closed(result_value->'context'->'arguments',ARRAY['target_id','expected_version','target_status','assignee_id','response_status','note']) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding approval arguments changed';END IF;
 RETURN jsonb_set(result_value,'{context,planner_receipt}','null'::jsonb);
END $projection$;

CREATE FUNCTION zasp_temporal78.approval_public(q jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $projection$
 SELECT q->'detail'||jsonb_build_object('approval_context',jsonb_build_object('agent_id',q->'context'->'agent_id','action','update_finding_response','target_id',q->'context'->'arguments'->'target_id','plan_hash',q->'context'->'plan_hash','catalog_version',q->'context'->'catalog_version',
 'requester',jsonb_build_object('state','available','id',q->'context'->'requester_id'),'reason',jsonb_build_object('code','operator_approval_required','source','persisted_step'),'risk',jsonb_build_object('class','low','source','action_catalog'),'rationale',NULL,'finding_response',q->'context'->'arguments'))
$projection$;

CREATE FUNCTION zasp_temporal78.project_approvals(o text,w text,e text,env jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $projection$
DECLARE a jsonb;items jsonb:='[]';BEGIN
 FOR a IN SELECT value FROM jsonb_array_elements(env->'detail'->'approvals') item(value) LOOP
  items:=items||jsonb_build_array(zasp_temporal78.approval_public(zasp_temporal78.approval_envelope(o,w,e,a->>'id',env)));
 END LOOP;
 RETURN jsonb_set(env,'{detail,approvals}',items);
END $projection$;

CREATE FUNCTION zasp_temporal78.approval(o text,w text,e text,a text,actor_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
DECLARE r text;env jsonb;BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.api_ready('-- finding78 checksum','-- finding78 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding approval read unavailable';END IF;
 PERFORM zasp_temporal74.approval_viewer(o,w,e,actor_value);
 SELECT x.run_id INTO r FROM zasp_temporal78.run_owners x JOIN public.zasp_security_agent_approvals ap USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE(ap.organization_id,ap.workspace_id,ap.environment_id,ap.approval_id)=(o,w,e,a);
 IF NOT FOUND THEN RETURN NULL;END IF;
 env:=zasp_temporal78.run_context(o,w,e,r);
 RETURN zasp_temporal78.approval_envelope(o,w,e,a,env);
END $read$;

CREATE FUNCTION zasp_temporal78.approval_page(o text,w text,e text,state_value text,run_value text,before_created_value timestamptz,before_id_value text,limit_value integer,actor_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $page$
DECLARE page_value jsonb;item jsonb;replacement jsonb;items jsonb:='[]';BEGIN
 IF NOT zasp_temporal78.api_ready('-- finding78 checksum','-- finding78 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding approval page unavailable';END IF;
 page_value:=zasp_temporal74.approval_page(o,w,e,state_value,run_value,before_created_value,before_id_value,limit_value,actor_value);
 FOR item IN SELECT value FROM jsonb_array_elements(page_value->'items') rows(value) LOOP
  replacement:=zasp_temporal78.approval(o,w,e,item->'detail'->>'id',actor_value);
  items:=items||jsonb_build_array(COALESCE(replacement,item));
 END LOOP;
 RETURN jsonb_set(page_value,'{items}',items);
END $page$;

CREATE FUNCTION zasp_temporal78.decide_approval(o text,w text,e text,a text,actor_value text,key_value text,expected_version bigint,decision_value text,fresh_auth_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $decision$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;prior public.zasp_security_agent_request_receipts%ROWTYPE;result_value jsonb;env jsonb;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='finding approval isolation rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.api_ready('-- finding78 checksum','-- finding78 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding approval unavailable';END IF;
 SELECT own.* INTO x FROM zasp_temporal78.run_owners own JOIN public.zasp_security_agent_approvals ap USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE(ap.organization_id,ap.workspace_id,ap.environment_id,ap.approval_id)=(o,w,e,a);
 IF NOT FOUND THEN RETURN NULL;END IF;
 PERFORM zasp_temporal78.manager(o,w,e,actor_value);
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,x.run_id) FOR UPDATE;
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor_value,'decideSecurityAgentApproval',key_value);
 IF FOUND THEN
  PERFORM zasp_temporal78.decision_owner(c) FROM zasp_temporal78.control_intents c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.actor_id,c.operation,c.idempotency_key,c.resource_id,c.receipt_id)=(o,w,e,x.run_id,actor_value,'decideSecurityAgentApproval',key_value,a,prior.receipt_id);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding approval replay proof absent';END IF;
  result_value:=public.zasp_security_agent_decide_approval(o,w,e,a,actor_value,key_value,expected_version,decision_value,fresh_auth_value,audit_value,correlation_value,receipt_value);
  IF result_value IS DISTINCT FROM prior.response||jsonb_build_object('replayed',true) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding approval replay changed';END IF;
 ELSE
  PERFORM zasp_temporal78.approval_context(o,w,e,x.run_id);
  env:=zasp_temporal78.approval(o,w,e,a,actor_value);
  result_value:=public.zasp_security_agent_decide_approval(o,w,e,a,actor_value,key_value,expected_version,decision_value,fresh_auth_value,audit_value,correlation_value,receipt_value);
  env:=zasp_temporal78.approval(o,w,e,a,actor_value);
  result_value:=result_value||zasp_temporal78.approval_public(env);
  UPDATE public.zasp_security_agent_request_receipts SET response=result_value WHERE(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,receipt_id)=(o,w,e,actor_value,'decideSecurityAgentApproval',key_value,a,receipt_value);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding approval final receipt absent';END IF;
 END IF;
 PERFORM zasp_temporal78.manager(o,w,e,actor_value);
 RETURN result_value;
END $decision$;
