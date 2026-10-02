-- The response is one local transaction. Assignment/note and exact finding
-- transition share the immutable effect proof; there is no dispatch lease.
CREATE TABLE zasp_temporal78.response_metadata(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,
 finding_id text NOT NULL,expected_version bigint NOT NULL CHECK(expected_version>0),result_version bigint NOT NULL CHECK(result_version=expected_version+1),
 assignee_id text NOT NULL,response_status text NOT NULL CHECK(response_status IN('open','investigating')),note text NOT NULL CHECK(octet_length(note) BETWEEN 1 AND 512),
 outcome_id text NOT NULL,result_value jsonb NOT NULL,result_digest bytea NOT NULL CHECK(result_digest=digest(convert_to(result_value::text,'UTF8'),'sha256')),receipt jsonb NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),UNIQUE(organization_id,workspace_id,environment_id,outcome_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES public.zasp_security_agent_steps,
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal78.run_owners);
ALTER TABLE zasp_temporal78.response_metadata OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal78.response_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal78.response_metadata FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal78.response_metadata USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal78.response_metadata FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

INSERT INTO zasp_temporal78.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid='zasp_temporal74.start_identity(jsonb)'::regprocedure;
DO $identity$ DECLARE d text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal78.predecessor_functions WHERE signature='zasp_temporal74.start_identity(jsonb)';
 d:=replace(d,'zasp_temporal74.','zasp_temporal78.');
 EXECUTE replace(d,'security-agent-test/v1/','security-agent-finding/v1/');
END $identity$;

CREATE FUNCTION zasp_temporal78.current_step(o text,w text,e text,r text,s text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $step$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;b public.zasp_security_agent_run_budgets%ROWTYPE;a public.zasp_security_agent_approvals%ROWTYPE;j zasp_temporal78.planning_jobs%ROWTYPE;
 cv jsonb;item jsonb;authorization_value text;
BEGIN
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO x FROM zasp_temporal78.run_owners WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO p FROM public.zasp_security_agent_plans WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR UPDATE;
 SELECT * INTO b FROM public.zasp_security_agent_run_budgets WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO j FROM zasp_temporal78.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 cv:=zasp_temporal78.context(o,w,e,r);item:=p.plan->'steps'->0;
 authorization_value:=CASE cv->'definition'->>'autonomy' WHEN 'supervised' THEN 'approval_required' ELSE 'autonomous' END;
 IF rr.run_id IS NULL OR x.run_id IS NULL OR p.run_id IS NULL OR st.run_id IS NULL OR b.run_id IS NULL OR j.run_id IS NULL OR rr.state<>'queued' OR st.state<>'authorized' OR st.step_index<>0 OR st.action_key<>'update_finding_response'
  OR b.stop_reason IS NOT NULL OR b.deadline_at<=clock_timestamp() OR b.max_steps<>1 OR p.expires_at<=clock_timestamp()
  OR p.plan_hash IS DISTINCT FROM rr.plan_hash OR p.plan_hash IS DISTINCT FROM digest(convert_to(p.plan::text,'UTF8'),'sha256') OR (p.definition_id,p.definition_version) IS DISTINCT FROM(rr.definition_id,rr.definition_version)
  OR jsonb_array_length(p.plan->'steps')<>1 OR item IS DISTINCT FROM zasp_temporal78.plan_item(x,j.result_value->'candidate',authorization_value)
  OR st.input_digest IS DISTINCT FROM digest(convert_to(item::text,'UTF8'),'sha256') OR st.authorization_result IS DISTINCT FROM authorization_value
  OR j.state<>'admitted' OR j.context_value IS DISTINCT FROM cv OR j.result_value IS DISTINCT FROM zasp_temporal78.planning_result(j.raw_result,j.lookup_request->>'model',cv)
  OR j.input_version IS NULL OR j.output_version IS NULL OR NOT zasp_temporal78.candidate_valid(j.result_value->'candidate',cv)
  OR NOT EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.run_id,v.reservation_id)=(o,w,e,r,j.reservation_id) AND v.settled_at IS NOT NULL AND v.released_at IS NULL AND v.total_tokens<=b.max_tokens AND v.cost_nano_credits<=b.max_cost_nano_credits AND v.total_tokens=(j.result_value->'usage'->>'total_tokens')::bigint AND v.cost_nano_credits=(j.result_value->'usage'->>'cost_nano_credits')::bigint)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding current step changed';END IF;
 IF NOT zasp_temporal78.assignee(o,w,e,item->>'assignee_id') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding assignee authority changed';END IF;
 SELECT * INTO a FROM public.zasp_security_agent_approvals WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR SHARE;
 IF authorization_value='approval_required' THEN
  IF a.run_id IS NULL OR a.state<>'approved' OR a.plan_hash IS DISTINCT FROM p.plan_hash OR a.requester_id IS DISTINCT FROM rr.requested_by OR a.approver_id IS NULL OR a.approver_id=a.requester_id OR a.fresh_auth_at IS NULL OR a.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding approval unavailable';END IF;
  PERFORM zasp_temporal78.manager(o,w,e,a.approver_id);
 ELSIF a.run_id IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding unexpected approval';END IF;
END $step$;

CREATE FUNCTION zasp_temporal78.effect_evidence(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $evidence$
DECLARE m zasp_temporal78.response_metadata%ROWTYPE;x zasp_temporal78.run_owners%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;ef public.zasp_security_agent_effects%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;a public.zasp_security_agent_audit%ROWTYPE;item jsonb;receipt_value jsonb;
BEGIN
 SELECT * INTO x FROM zasp_temporal78.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO m FROM zasp_temporal78.response_metadata WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,x.step_id);
 SELECT * INTO p FROM public.zasp_security_agent_plans WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO ef FROM public.zasp_security_agent_effects WHERE(organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,x.step_id,'update_finding_response');
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,x.step_id);
 SELECT * INTO a FROM public.zasp_security_agent_audit WHERE(organization_id,workspace_id,environment_id,audit_id)=(o,w,e,public.zasp_discovery_canonical_id(o,w,e,'security_agent_finding_effect_audit',r));
 item:=p.plan->'steps'->0;
 receipt_value:=jsonb_build_object('contract_version',78,'workflow_id',x.workflow_id,'run_id',r,'step_id',x.step_id,'state','remediated','outcome_id',m.outcome_id,'result_digest','sha256:'||encode(m.result_digest,'hex'));
 IF m.run_id IS NULL OR p.run_id IS NULL OR ef.run_id IS NULL OR st.state IS DISTINCT FROM 'succeeded' OR ef.state IS DISTINCT FROM 'verified' OR ef.lease_token IS NOT NULL OR ef.lease_owner IS NOT NULL OR ef.lease_expires_at IS NOT NULL
  OR (m.finding_id,m.expected_version,m.result_version,m.assignee_id,m.response_status,m.note) IS DISTINCT FROM(x.trigger_id,x.trigger_version,x.trigger_version+1,item->>'assignee_id',item->>'response_status',item->>'note')
  OR m.result_value IS DISTINCT FROM jsonb_build_object('run_id',r,'step_id',x.step_id,'finding_id',x.trigger_id,'previous_version',x.trigger_version,'version',x.trigger_version+1,'status',item->>'target_status','assignee_id',m.assignee_id,'response_status',m.response_status,'note',m.note,'source_digest',encode(x.snapshot_digest,'hex'))
  OR m.result_digest IS DISTINCT FROM digest(convert_to(m.result_value::text,'UTF8'),'sha256') OR m.outcome_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_effect',r||chr(31)||x.step_id||chr(31)||'update_finding_response')
  OR (ef.outcome_id,ef.result_digest,ef.input_digest) IS DISTINCT FROM(m.outcome_id,m.result_digest,st.input_digest) OR st.input_digest IS DISTINCT FROM digest(convert_to(item::text,'UTF8'),'sha256')
  OR m.receipt IS DISTINCT FROM receipt_value OR a.body IS DISTINCT FROM receipt_value OR a.event_kind IS DISTINCT FROM 'effect_verified' OR a.event_digest IS DISTINCT FROM digest(convert_to(a.body::text,'UTF8'),'sha256')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id,state,plan_hash)=(o,w,e,r,'remediated',p.plan_hash))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding effect proof changed';END IF;
 RETURN receipt_value;
END $evidence$;

CREATE FUNCTION zasp_temporal78.apply(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $apply$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;item jsonb;result_value jsonb;result_hash bytea;receipt_value jsonb;result_version bigint;outcome_value text;audit_value text;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='finding apply requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding apply unavailable';END IF;
 x:=zasp_temporal78.start_identity(q);
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE;
 IF EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN RETURN zasp_temporal78.effect_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);END IF;
 PERFORM zasp_temporal78.current_step(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);
 SELECT * INTO STRICT st FROM public.zasp_security_agent_steps WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);
 SELECT plan->'steps'->0 INTO STRICT item FROM public.zasp_security_agent_plans WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 INSERT INTO public.zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest) VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.action_key,st.input_digest);
 UPDATE public.zasp_risk_findings SET status=item->>'target_status',acceptance_reason=NULL,version=version+1,updated_at=clock_timestamp()
 WHERE(organization_id,workspace_id,environment_id,id,version,status)=(x.organization_id,x.workspace_id,x.environment_id,x.trigger_id,x.trigger_version,'open') RETURNING version INTO result_version;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding version changed before apply';END IF;
 result_value:=jsonb_build_object('run_id',x.run_id,'step_id',x.step_id,'finding_id',x.trigger_id,'previous_version',x.trigger_version,'version',result_version,'status',item->>'target_status','assignee_id',item->>'assignee_id','response_status',item->>'response_status','note',item->>'note','source_digest',encode(x.snapshot_digest,'hex'));
 result_hash:=digest(convert_to(result_value::text,'UTF8'),'sha256');
 outcome_value:=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_effect',x.run_id||chr(31)||x.step_id||chr(31)||x.action_key);
 receipt_value:=jsonb_build_object('contract_version',78,'workflow_id',x.workflow_id,'run_id',x.run_id,'step_id',x.step_id,'state','remediated','outcome_id',outcome_value,'result_digest','sha256:'||encode(result_hash,'hex'));
 INSERT INTO public.zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,attempt,outcome_id,result_digest) VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.action_key,st.input_digest,'verified',1,outcome_value,result_hash);
 INSERT INTO zasp_temporal78.response_metadata VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.trigger_id,x.trigger_version,result_version,item->>'assignee_id',item->>'response_status',item->>'note',outcome_value,result_value,result_hash,receipt_value);
 UPDATE public.zasp_security_agent_steps SET state='succeeded',version=version+1,updated_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);
 UPDATE public.zasp_security_agent_runs SET state='remediated',version=version+1,updated_at=clock_timestamp(),completed_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 audit_value:=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_finding_effect_audit',x.run_id);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(x.organization_id,x.workspace_id,x.environment_id,audit_value,audit_value,x.run_id,x.step_id,rr.requested_by,'effect_verified',digest(convert_to(receipt_value::text,'UTF8'),'sha256'),receipt_value);
 IF x.source_kind='human78' THEN PERFORM zasp_temporal78.human_authorize(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 ELSE PERFORM zasp_temporal78.authorize(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version);END IF;
 IF NOT zasp_temporal78.assignee(x.organization_id,x.workspace_id,x.environment_id,item->>'assignee_id') OR NOT zasp_temporal78.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding apply authority changed';END IF;
 RETURN zasp_temporal78.effect_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
END $apply$;
