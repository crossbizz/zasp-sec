-- A private advisory can review one already-admitted approval. It cannot
-- create an effect, change the plan, approve a step, or advance a workflow.
CREATE TABLE IF NOT EXISTS public.zasp_studio_advisories (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 owner_id text NOT NULL, session_id text NOT NULL, thread_id text NOT NULL, message_id text NOT NULL,
 approval_id text NOT NULL, approval_version bigint NOT NULL, plan_hash bytea NOT NULL,
 lease_id text NOT NULL, deployment_digest text NOT NULL, reserved_nano_credits bigint NOT NULL CHECK(reserved_nano_credits>0),
 state text NOT NULL CHECK(state IN ('pending','reviewed','no_recommendation','unavailable')), created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,owner_id,session_id,thread_id,message_id,approval_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,owner_id,session_id,thread_id) REFERENCES public.zasp_security_agent_chat_threads
);
ALTER TABLE public.zasp_studio_advisories OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_studio_advisories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_studio_advisories FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_studio_advisories FROM PUBLIC;
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='zasp_studio_advisories' AND policyname='advisory_authority') THEN
  CREATE POLICY advisory_authority ON public.zasp_studio_advisories TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $$;

CREATE OR REPLACE FUNCTION zasp_authorization80.studio_advisory(o text,w text,e text,a text,s text,t text,m text,approval text,op text,attestation text,req jsonb,cfg jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $advisory$
DECLARE
 proof jsonb; secondary jsonb; result jsonb; current_thread public.zasp_security_agent_chat_threads%ROWTYPE;
 profile jsonb; cited public.zasp_security_agent_chat_messages%ROWTYPE; job public.zasp_studio_advisories%ROWTYPE;
 candidate jsonb:=jsonb_build_object('action','isolate_session','target_id',s,'rollback','ttl_release');
 current_version bigint; current_hash bytea; cost bigint; cap bigint; steps_used bigint; credits_used numeric;
 phase text:=req->>'phase'; next_state text;
BEGIN
 IF op NOT IN('getStudioRemediationAdvisory','requestStudioRemediationAdvisory') OR
   NOT coalesce(phase IN('get','reserve','dispatch','finish','fail') AND (phase='get')=(op='getStudioRemediationAdvisory'),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023'; END IF;
 proof:=zasp_authorization80.product_request(o,w,e,a,op,'investigate_sessions','session',s,false,true,phase<>'get',phase<>'get');
 secondary:=zasp_authorization80.security_agent_second_decision(proof,attestation,'getSecurityAgentApproval',false);
 IF proof#>>'{path_parameters,id}' IS DISTINCT FROM t OR secondary#>>'{path_parameters,id}' IS DISTINCT FROM approval
   OR NOT zasp_authorization80.security_agent_attested_allowed(secondary,o,w,e,'security_agent_approval',approval) THEN RAISE EXCEPTION USING ERRCODE='42501';END IF;
 result:=jsonb_build_object('session_id',s,'approval_id',approval,'message_id',m);
 SELECT * INTO current_thread FROM public.zasp_security_agent_chat_threads x
 WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.id)=(o,w,e,a,s,t) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 IF cfg IS NULL OR NOT zasp_authorization80.cloud_job_allowed(o,w,e,'security_agent_remediate',cfg) OR NOT zasp_authorization80.chat_allowed(o,w,e,NULL)
 THEN RETURN result||'{"state":"unavailable"}'::jsonb;END IF;
 profile:=zasp_authorization80.studio_revision(o,w,e,current_thread.studio_id,0);
 SELECT * INTO cited FROM public.zasp_security_agent_chat_messages x
 WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id,x.status)=(o,w,e,a,s,t,'answered') AND jsonb_array_length(x.evidence_ids)>0
 ORDER BY x.finished_at DESC,x.assistant_id DESC LIMIT 1;
 IF current_thread.studio_id IS NULL OR (profile->>'revision')::bigint IS DISTINCT FROM current_thread.studio_revision
   OR profile#>>'{definition,require_approval}' IS DISTINCT FROM 'true' OR profile#>>'{definition,proposal}' IS DISTINCT FROM 'request_containment'
   OR profile#>>'{definition,model_pin}' IS DISTINCT FROM cfg->>'model' OR cited.assistant_id IS DISTINCT FROM m
   OR jsonb_array_length(cited.evidence_ids) NOT BETWEEN 1 AND 6 THEN RETURN 'null'::jsonb; END IF;

 SELECT ap.version,ap.plan_hash INTO current_version,current_hash FROM public.zasp_security_agent_approvals ap
 JOIN public.zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id,plan_hash)
 JOIN public.zasp_security_agent_runs run USING(organization_id,workspace_id,environment_id,run_id,plan_hash)
 JOIN public.zasp_security_agent_steps st USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN public.zasp_security_agent_trigger_receipts tr USING(organization_id,workspace_id,environment_id,run_id)
 WHERE (ap.organization_id,ap.workspace_id,ap.environment_id,ap.approval_id,ap.state)=(o,w,e,approval,'pending') AND ap.expires_at>now() AND p.expires_at>now()
   AND run.state='waiting_approval' AND run.trigger_id=s AND tr.trigger_kind='runtime_decision' AND tr.trigger_id=s AND st.action_key='isolate_session' AND st.step_index=0
   AND st.authorization_result='approval_required' AND st.state='waiting_approval' AND jsonb_array_length(p.plan->'steps')=1
   AND p.plan#>'{steps,0}' @> jsonb_build_object('action','isolate_session','target_id',s,'session_id',s,'scope',e,'step_id',ap.step_id,'authorization','approval_required')
   AND p.plan_hash=public.digest(convert_to(p.plan::text,'UTF8'),'sha256')
   AND st.input_digest=public.digest(convert_to((p.plan#>'{steps,0}')::text,'UTF8'),'sha256')
   AND (p.plan#>>'{steps,0,ttl_seconds}')::integer BETWEEN 60 AND 3600 FOR SHARE OF ap,st,p,run,tr;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 IF NOT EXISTS (SELECT FROM jsonb_array_elements(secondary->'allowed') row_value
  WHERE row_value->>'kind'='security_agent_approval' AND coalesce(nullif(row_value->>'source_id',''),row_value->>'id')=approval
   AND (row_value->>'version')::bigint=current_version) THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 SELECT * INTO job FROM public.zasp_studio_advisories x WHERE
  (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id,x.message_id,x.approval_id)=(o,w,e,a,s,t,m,approval);
 IF job.lease_id IS NOT NULL AND (job.approval_version<>current_version OR job.plan_hash<>current_hash OR job.deployment_digest IS DISTINCT FROM cfg->>'deployment_digest'
    OR (job.state='pending' AND job.created_at<now()-interval '2 minutes')) THEN RETURN result||'{"state":"unavailable"}'::jsonb; END IF;
 IF job.lease_id IS NULL THEN
  SELECT coalesce(sum(1+x.approved_external_read::int),0),coalesce(sum(x.reserved_nano_credits),0) INTO steps_used,credits_used FROM public.zasp_security_agent_chat_messages x
   WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id)=(o,w,e,a,s,t);
  SELECT steps_used+count(*),credits_used+coalesce(sum(x.reserved_nano_credits),0) INTO steps_used,credits_used FROM public.zasp_studio_advisories x
   WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id)=(o,w,e,a,s,t);
  cost:=(cfg->>'cost')::bigint;
  SELECT monthly_budget_nano_credits INTO cap FROM public.zasp_environment_ai_controls WHERE (organization_id,workspace_id,environment_id)=(o,w,e) FOR SHARE;
  IF cost IS NULL OR cost<=0 OR cap IS NULL OR cost>cap OR steps_used+1>(profile#>>'{definition,max_steps}')::int OR credits_used+cost>(profile#>>'{definition,budget_nano_credits}')::bigint
   OR EXISTS(SELECT FROM public.zasp_ai_monthly_usage x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.month_start)=(o,w,e,date_trunc('month',now() AT TIME ZONE 'UTC')::date) AND x.reserved_nano_credits>cap-cost)
  THEN RETURN result||'{"state":"unavailable"}'::jsonb;END IF;
  IF phase='get' THEN RETURN result||'{"state":"available"}'::jsonb; END IF;
  IF phase<>'reserve' OR NOT coalesce(public.zasp_valid_product_id(req->>'lease_id'),false) THEN RETURN '"conflict"'::jsonb; END IF;
  INSERT INTO public.zasp_ai_monthly_usage AS u VALUES(o,w,e,date_trunc('month',now() AT TIME ZONE 'UTC')::date,cost) ON CONFLICT(organization_id,workspace_id,environment_id,month_start)
   DO UPDATE SET reserved_nano_credits=u.reserved_nano_credits+cost WHERE u.reserved_nano_credits<=cap-cost;
  IF NOT FOUND THEN RETURN '"budget"'::jsonb;END IF;
  INSERT INTO public.zasp_studio_advisories VALUES(o,w,e,a,s,t,m,approval,current_version,current_hash,req->>'lease_id',cfg->>'deployment_digest',cost,'pending',now());
  PERFORM zasp_authorization80.product_settled(proof);
  RETURN result||jsonb_build_object('state','pending','lease_id',req->>'lease_id');
 END IF;
 IF phase IN('get','reserve') THEN
  IF job.state='reviewed' THEN result:=result||jsonb_build_object('candidate',candidate); END IF;
  RETURN result||jsonb_build_object('state',job.state);
 END IF;
 IF job.state<>'pending' OR job.lease_id IS DISTINCT FROM req->>'lease_id' THEN RETURN '"conflict"'::jsonb; END IF;
 IF phase='dispatch' THEN
  RETURN result||jsonb_build_object('state','pending','input',jsonb_build_object('candidates',jsonb_build_array(candidate),'evidence_ids',cited.evidence_ids));
 END IF;
 next_state:=CASE WHEN phase='fail' THEN 'unavailable' WHEN req->'output'=jsonb_build_object('steps',jsonb_build_array(candidate)) THEN 'reviewed'
   WHEN req->'output'='{"steps":[]}'::jsonb THEN 'no_recommendation' END;
 IF next_state IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023'; END IF;
 UPDATE public.zasp_studio_advisories x SET state=next_state WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id,x.message_id,x.approval_id,x.lease_id)=(o,w,e,a,s,t,m,approval,job.lease_id);
 PERFORM zasp_authorization80.ai_observed_health(o,w,e,cfg->>'provider',cfg->>'model','security_agent_remediate',cfg->>'deployment_digest',phase='finish');
 PERFORM zasp_authorization80.product_settled(proof);
 RETURN result||jsonb_build_object('state',next_state);
END $advisory$;
ALTER FUNCTION zasp_authorization80.studio_advisory(text,text,text,text,text,text,text,text,text,text,jsonb,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.studio_advisory(text,text,text,text,text,text,text,text,text,text,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.studio_advisory(text,text,text,text,text,text,text,text,text,text,jsonb,jsonb) TO zasp_discovery_api;
