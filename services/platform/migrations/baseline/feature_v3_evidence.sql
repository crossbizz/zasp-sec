-- Only bind a receipt across sources by a durable decision or session identity.
-- Adjacency in time does not establish that one action caused another.
CREATE OR REPLACE FUNCTION zasp_authorization80.session_intent_evidence(o text,w text,e text,s text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $intent$
DECLARE result jsonb;
BEGIN
 IF NOT EXISTS (SELECT FROM public.zasp_runtime_session_events v WHERE (v.organization_id,v.workspace_id,v.environment_id,v.session_id)=(o,w,e,s))
 AND NOT EXISTS (SELECT FROM public.zasp_workload_bindings b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.session_id)=(o,w,e,s))
 THEN RETURN 'null'::jsonb; END IF;
 WITH events AS (
  SELECT v.event_id decision_id,v.source,CASE v.event_class WHEN 'process' THEN 'runtime' ELSE v.event_class END AS class,
   v.action,''::text receipt,v.title operation,v.event_time observed_at,ARRAY[v.evidence_id] evidence_ids,v.agent_id,v.confidence
  FROM public.zasp_runtime_session_events v WHERE (v.organization_id,v.workspace_id,v.environment_id,v.session_id)=(o,w,e,s)
  ORDER BY v.event_time DESC,v.event_id DESC LIMIT 101
 ), workload AS (
  SELECT x.receipt->>'decision_id' decision_id,'authenticated_workload'::text source,'tool'::text class,
   x.receipt->>'verdict' AS action,coalesce(x.outcome->>'status','') receipt,x.request->>'operation' operation,
   x.created_at observed_at,CASE WHEN x.outcome IS NULL THEN ARRAY[x.receipt->>'decision_id'] ELSE ARRAY[x.receipt->>'decision_id',
    public.zasp_discovery_canonical_id(o,w,e,'workload_outcome',x.receipt->>'decision_id')] END evidence_ids,b.agent_id,'exact'::text confidence
  FROM public.zasp_workload_bindings b JOIN public.zasp_workload_actions x
   ON (b.organization_id,b.workspace_id,b.environment_id,b.credential_id)=(x.organization_id,x.workspace_id,x.environment_id,x.credential_id) AND b.created_at<=x.created_at
  WHERE (b.organization_id,b.workspace_id,b.environment_id,b.session_id)=(o,w,e,s)
  ORDER BY x.created_at DESC,x.receipt->>'decision_id' DESC LIMIT 101
 ), recent AS (SELECT * FROM events UNION ALL SELECT * FROM workload ORDER BY observed_at DESC,decision_id DESC LIMIT 101)
 SELECT coalesce(jsonb_agg(to_jsonb(recent) ORDER BY observed_at DESC,decision_id DESC),'[]'::jsonb) INTO result FROM recent;
 RETURN result;
END $intent$;
ALTER FUNCTION zasp_authorization80.session_intent_evidence(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.session_intent_evidence(text,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION zasp_authorization80.session_intent(o text,w text,e text,a text,s text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $read$
BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,a,'getSessionIntent','investigate_sessions','session',s,true,true,false,false);
 RETURN zasp_authorization80.session_intent_evidence(o,w,e,s);
END $read$;

-- An owner attaches an already archived fixture to the remediation they are
-- reviewing. The server recomputes the result using current evidence trust.
CREATE TABLE IF NOT EXISTS public.verification_case_checks (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 case_id text NOT NULL,fixture_run_id text NOT NULL,step_id text NOT NULL,owner_id text NOT NULL,
 checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),window_end timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,case_id,fixture_run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,case_id,step_id)
 REFERENCES public.zasp_security_agent_provider_remediations(organization_id,workspace_id,environment_id,run_id,step_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,fixture_run_id)
 REFERENCES public.zasp_ticket_verification_imports(organization_id,workspace_id,environment_id,run_id)
);
ALTER TABLE public.verification_case_checks ADD COLUMN IF NOT EXISTS business_fixture_unavailable boolean NOT NULL DEFAULT false;
ALTER TABLE public.verification_case_checks OWNER TO zasp_discovery_authority;
ALTER TABLE public.verification_case_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.verification_case_checks FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.verification_case_checks FROM PUBLIC;
DO $policy$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='verification_case_checks' AND policyname='verification_case_authority') THEN
  CREATE POLICY verification_case_authority ON public.verification_case_checks TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $policy$;

CREATE OR REPLACE FUNCTION zasp_authorization80.case_verification(o text,w text,e text,a text,r text,f text,business_unavailable boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $verification$
DECLARE rem public.zasp_security_agent_provider_remediations%ROWTYPE; fixture public.zasp_ticket_verification_imports%ROWTYPE;
 previous public.verification_case_checks%ROWTYPE; proof jsonb; end_at timestamptz;
BEGIN
 IF business_unavailable IS NULL OR (f IS NULL AND business_unavailable) THEN RETURN '"ineligible"'::jsonb; END IF;
 IF f IS NULL THEN
  PERFORM zasp_authorization80.product_request(o,w,e,a,'getSecurityCaseVerification','view','security_agent_run',r,true,true,false,false);
 ELSE
  proof:=zasp_authorization80.product_request(o,w,e,a,'verifySecurityCase','manage_workflows','security_agent_run',r,true,true,true,true);
 END IF;
 -- This pilot covers a single provider remediation per case. Ambiguous runs
 -- cannot be certified by a single target's fixture.
 SELECT * INTO rem FROM public.zasp_security_agent_provider_remediations x
 WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) ORDER BY x.step_id LIMIT 1 FOR SHARE;
 IF NOT FOUND OR EXISTS(SELECT FROM public.zasp_security_agent_provider_remediations x WHERE
  (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.step_id<>rem.step_id) THEN RETURN 'null'::jsonb;END IF;
 IF f IS NOT NULL THEN
  IF rem.state<>'verified' THEN RETURN '"remediation_pending"'::jsonb; END IF;
  -- Owner annotations may be human labels. Only an exact principal binding
  -- authorizes a person to approve the two tasks represented by this fixture.
  PERFORM FROM public.zasp_inventory_annotations n WHERE (n.organization_id,n.workspace_id,n.environment_id,n.entity_id,n.owner_value)=(o,w,e,rem.entity_id,a) FOR SHARE;
  IF NOT FOUND THEN RETURN '"owner_required"'::jsonb; END IF;
  SELECT * INTO fixture FROM public.zasp_ticket_verification_imports t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(o,w,e,f);
  IF NOT FOUND OR fixture.bundle#>>'{scenario,target_id}' IS DISTINCT FROM rem.entity_id
   OR fixture.bundle#>>'{scenario,operation}' IS DISTINCT FROM 'synthetic_ticket_update'
   OR (fixture.bundle#>>'{scenario,window_start}')::timestamptz < rem.completed_at THEN RETURN '"ineligible"'::jsonb; END IF;
  end_at:=(fixture.bundle#>>'{scenario,window_end}')::timestamptz;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws('/',o,w,e,r,'case_verification'),0));
 END IF;
 SELECT * INTO previous FROM public.verification_case_checks x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.case_id)=(o,w,e,r)
 ORDER BY x.window_end DESC LIMIT 1;
 IF f IS NOT NULL THEN
  IF previous.fixture_run_id IS DISTINCT FROM f AND previous.window_end>=end_at THEN RETURN '"stale"'::jsonb;END IF;
  -- An owner can acknowledge the missing business fixture only before
  -- attaching any business fixture, including a failed one.
  IF (business_unavailable AND EXISTS(SELECT FROM public.verification_case_checks x WHERE
   (x.organization_id,x.workspace_id,x.environment_id,x.case_id)=(o,w,e,r) AND NOT x.business_fixture_unavailable))
   OR (previous.fixture_run_id=f AND previous.business_fixture_unavailable<>business_unavailable) THEN RETURN '"stale"'::jsonb; END IF;
  INSERT INTO public.verification_case_checks(organization_id,workspace_id,environment_id,case_id,fixture_run_id,step_id,owner_id,window_end,business_fixture_unavailable)
  VALUES(o,w,e,r,f,rem.step_id,a,end_at,business_unavailable) ON CONFLICT DO NOTHING;
  IF FOUND THEN
   INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
   VALUES(o,w,e,public.zasp_discovery_canonical_id(o,w,e,'case_verification',r||'/'||f),a,'attach_case_verification_evidence',r,'succeeded',
    jsonb_build_object('fixture_run_id',f,'remediation_step_id',rem.step_id,'business_fixture_unavailable',business_unavailable));
  END IF;
  PERFORM zasp_authorization80.product_settled(proof);
 ELSIF previous.fixture_run_id IS NOT NULL THEN
  SELECT * INTO STRICT fixture FROM public.zasp_ticket_verification_imports t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(o,w,e,previous.fixture_run_id);
 END IF;
 RETURN jsonb_build_object('case_id',r,'remediation_verified',rem.state='verified','target_id',rem.entity_id,'fixture_run_id',fixture.run_id,
  'submitted_at',fixture.submitted_at,'bundle',fixture.bundle,'business_fixture_unavailable',CASE WHEN f IS NULL THEN coalesce(previous.business_fixture_unavailable,false) ELSE business_unavailable END);
END $verification$;
ALTER FUNCTION zasp_authorization80.session_intent(text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.case_verification(text,text,text,text,text,text,boolean) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.session_intent(text,text,text,text,text),zasp_authorization80.case_verification(text,text,text,text,text,text,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.session_intent(text,text,text,text,text),zasp_authorization80.case_verification(text,text,text,text,text,text,boolean) TO zasp_discovery_api;
