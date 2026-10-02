-- API-only service validation shares the exact current grant predicate. It is
-- private: neither the API role nor a worker may invoke it directly.
DO $service$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal74.authorize(text,text,text,text,bigint)'::regprocedure) INTO d;
 d:=replace(d,'FUNCTION zasp_temporal74.authorize(','FUNCTION zasp_temporal74.approval_service(');
 d:=replace(d,$old$zasp_temporal68.principal_ready('zasp_temporal_executor')$old$,$new$public.zasp_security_agent_principal_ready('zasp_security_agent_api')$new$);
 EXECUTE d;
END $service$;

CREATE FUNCTION zasp_temporal74.decide_approval(o text,w text,e text,a text,actor_value text,key_value text,expected_version bigint,decision_value text,fresh_auth_value timestamptz,audit_value text,correlation_value text,receipt_value text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $decision$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;approval public.zasp_security_agent_approvals%ROWTYPE;d public.zasp_security_agent_definitions%ROWTYPE;response_value jsonb;requester text;prior public.zasp_security_agent_request_receipts%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='single-test approval isolation rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.api_ready('-- test74 checksum','-- test74 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test approval authority rejected';END IF;
 SELECT own.* INTO x FROM zasp_temporal74.run_owners own JOIN public.zasp_security_agent_approvals ap USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE (ap.organization_id,ap.workspace_id,ap.environment_id,ap.approval_id)=(o,w,e,a);
 IF x.run_id IS NULL THEN RETURN NULL;END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,x.run_id) FOR UPDATE;
 SELECT * INTO STRICT approval FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,approval_id)=(o,w,e,a) FOR UPDATE;
 PERFORM zasp_temporal74.human(o,w,e,actor_value);
 -- A historical decision receipt is not permission for another effect. Prove
 -- its immutable committed control/audit binding, then retain the original
 -- core's identity, intent, fresh-auth and receipt-expiry replay contract.
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts rc WHERE (rc.organization_id,rc.workspace_id,rc.environment_id,rc.principal_id,rc.operation,rc.idempotency_key)=(o,w,e,actor_value,'decideSecurityAgentApproval',key_value);
 IF FOUND THEN
  PERFORM zasp_temporal74.decision_owner(c) FROM zasp_temporal74.control_intents c WHERE (c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.actor_id,c.operation,c.idempotency_key,c.resource_id,c.receipt_id)=(o,w,e,x.run_id,actor_value,'decideSecurityAgentApproval',key_value,a,prior.receipt_id);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test approval replay proof absent';END IF;
  response_value:=public.zasp_security_agent_decide_approval(o,w,e,a,actor_value,key_value,expected_version,decision_value,fresh_auth_value,audit_value,correlation_value,receipt_value);
  IF response_value IS DISTINCT FROM prior.response||jsonb_build_object('replayed',true) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test approval replay changed';END IF;
  PERFORM zasp_temporal74.human(o,w,e,actor_value);
  IF NOT zasp_temporal74.api_ready('-- test74 checksum','-- test74 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test approval authority changed';END IF;
  RETURN response_value;
 END IF;
 SELECT * INTO d FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,x.definition_id,x.definition_version) AND deleted_at IS NULL FOR SHARE;
 IF d.definition_id IS NULL OR d.activation<>'supervised' OR d.body->>'autonomy'<>'supervised' OR d.body->'enabled' IS DISTINCT FROM 'true'::jsonb OR d.body->'allowed_actions' IS DISTINCT FROM jsonb_build_array(x.action_key)
  OR NOT COALESCE(rr.state IN('waiting_approval','queued','running','verifying') AND rr.completed_at IS NULL,false) OR rr.lease_owner IS NOT NULL OR rr.lease_token IS NOT NULL OR rr.lease_expires_at IS NOT NULL
  OR approval.expires_at<=clock_timestamp() OR approval.plan_hash IS DISTINCT FROM rr.plan_hash
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_plans p JOIN public.zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id,p.plan_hash,p.definition_id,p.definition_version)=(o,w,e,x.run_id,rr.plan_hash,x.definition_id,x.definition_version) AND p.expires_at>clock_timestamp() AND b.deadline_at>clock_timestamp() AND b.stop_reason IS NULL)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test approval current state rejected';END IF;
 requester:=rr.requested_by;
 IF x.source_kind='automatic73' THEN requester:=zasp_temporal74.approval_service(o,w,e,x.definition_id,x.definition_version)->>'principal_id';
 ELSE PERFORM zasp_temporal74.human(o,w,e,requester);END IF;
 IF approval.requester_id IS DISTINCT FROM requester OR requester=actor_value THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test approval requester rejected';END IF;
 PERFORM zasp_temporal71.body21(o,w,e,x.definition_id,x.definition_version);
 PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,x.action_key);
 PERFORM public.zasp_production_security_agent_existing_tests_approval_value(o,w,e,a);
 response_value:=public.zasp_security_agent_decide_approval(o,w,e,a,actor_value,key_value,expected_version,decision_value,fresh_auth_value,audit_value,correlation_value,receipt_value);
 IF response_value->>'replayed' IS DISTINCT FROM 'true' THEN
  response_value:=response_value||public.zasp_production_security_agent_existing_tests_approval_value(o,w,e,a);
  UPDATE public.zasp_security_agent_request_receipts SET response=response_value WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,receipt_id)=(o,w,e,actor_value,'decideSecurityAgentApproval',key_value,a,receipt_value);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='single-test approval receipt unavailable';END IF;
 END IF;
 PERFORM zasp_temporal74.record_control(o,w,e,x.run_id,actor_value,'decideSecurityAgentApproval',key_value);
 PERFORM zasp_temporal74.human(o,w,e,actor_value);
 IF NOT zasp_temporal74.api_ready('-- test74 checksum','-- test74 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test approval authority changed';END IF;
 RETURN response_value;
END $decision$;

CREATE FUNCTION zasp_temporal74.approval_viewer(o text,w text,e text,a text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $viewer$
DECLARE m public.zasp_identity_memberships%ROWTYPE;s public.zasp_authorized_scopes%ROWTYPE;
BEGIN
 IF NOT zasp_temporal74.api_ready('-- test74 checksum','-- test74 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test approval read unavailable';END IF;
 SELECT * INTO m FROM public.zasp_identity_memberships WHERE (organization_id,principal_id)=(o,a) FOR SHARE;
 s:=zasp_sa_multistep_prior.lock_scope(o,w,e,a);
 IF m.active IS DISTINCT FROM true OR s.principal_id IS NULL OR NOT COALESCE(s.permissions?'view' AND public.zasp_effective_scope_permissions(s.permissions,m.role)?'view',false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test approval read denied';END IF;
END $viewer$;

CREATE FUNCTION zasp_temporal74.approval(o text,w text,e text,a text,actor_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
DECLARE result_value jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 PERFORM zasp_temporal74.approval_viewer(o,w,e,actor_value);
 SELECT value INTO result_value FROM public.zasp_production_security_agent_existing_tests_approval_ctx_core(o,w,e,a) r(value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='approval not found';END IF;
 RETURN result_value;
END $read$;

CREATE FUNCTION zasp_temporal74.approval_page(o text,w text,e text,state_value text,run_value text,before_created_value timestamptz,before_id_value text,limit_value integer,actor_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $page$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 PERFORM zasp_temporal74.approval_viewer(o,w,e,actor_value);
 RETURN public.zasp_production_security_agent_existing_tests_page_ctx_core(o,w,e,state_value,run_value,before_created_value,before_id_value,limit_value);
END $page$;
