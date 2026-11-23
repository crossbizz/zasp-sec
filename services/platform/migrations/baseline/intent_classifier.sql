-- The programmable classifier can only claim redacted features for a current,
-- consenting analysis revision. Completion writes a review code, never a policy.
ALTER TABLE public.zasp_action_analysis_evidence
 ADD COLUMN IF NOT EXISTS intent_attempts integer NOT NULL DEFAULT 0 CHECK(intent_attempts BETWEEN 0 AND 3),
 ADD COLUMN IF NOT EXISTS intent_lease uuid,
 ADD COLUMN IF NOT EXISTS intent_ready_at timestamptz,
 ADD COLUMN IF NOT EXISTS intent_recommendation text CHECK(intent_recommendation IN ('none','review_purpose','review_destination','review_sequence','review_data_access')),
 ADD COLUMN IF NOT EXISTS intent_finished_at timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS zasp_intent_lease ON public.zasp_action_analysis_evidence(intent_lease) WHERE intent_lease IS NOT NULL;
CREATE INDEX IF NOT EXISTS zasp_intent_pending ON public.zasp_action_analysis_evidence(seq)
 WHERE analyzed_at IS NOT NULL AND intent_finished_at IS NULL AND intent_attempts<3;

DO $intent_read$
DECLARE fn regprocedure; d text; before_text text; after_text text;
BEGIN
 fn:='zasp_authorization80.action_analysis_settings_valid(jsonb)'::regprocedure;
 d:=pg_get_functiondef(fn);
 before_text:='IF jsonb_typeof(s) IS DISTINCT FROM ''object''';
 after_text:=$fragment$IF s ? 'classifier_opt_in' THEN
  IF jsonb_typeof(s->'classifier_opt_in') IS DISTINCT FROM 'boolean' THEN RETURN false; END IF;
  s:=s-'classifier_opt_in';
 END IF;
 IF jsonb_typeof(s) IS DISTINCT FROM 'object'$fragment$;
 IF position('classifier_opt_in' in d)=0 THEN
  IF position(before_text in d)=0 THEN RAISE EXCEPTION 'unknown action settings source'; END IF;
  EXECUTE replace(d,before_text,after_text);
 END IF;
 fn:='zasp_authorization80.action_analysis(text,text,text,text,text,text,bigint,jsonb)'::regprocedure; d:=pg_get_functiondef(fn);
 before_text:=$fragment$'source','bound_workload_reported'$fragment$;
 after_text:=$fragment$'intent_drafts',coalesce((SELECT jsonb_agg(jsonb_build_object('decision_id',q.decision_id,'recommendation',q.intent_recommendation,'occurred_at',q.occurred_at) ORDER BY q.seq DESC) FROM
   (SELECT decision_id,seq,occurred_at,intent_recommendation FROM scope WHERE intent_finished_at IS NOT NULL AND intent_recommendation<>'none' ORDER BY seq DESC LIMIT 50) q),'[]'::jsonb),
 'source','bound_workload_reported'$fragment$;
 IF position('intent_drafts' in d)=0 THEN
  IF position(before_text in d)=0 THEN RAISE EXCEPTION 'unknown analysis response source'; END IF;
  EXECUTE replace(d,before_text,after_text);
 END IF;
END $intent_read$;

CREATE OR REPLACE FUNCTION public.zasp_claim_intent_draft() RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $intent_claim$
 WITH next_job AS MATERIALIZED (
  SELECT a.seq FROM public.zasp_action_analysis_evidence a JOIN public.zasp_action_analysis_versions v
   USING(organization_id,workspace_id,environment_id,agent_id,revision)
  WHERE v.settings->'classifier_opt_in'='true'::jsonb
   AND a.analyzed_at IS NOT NULL AND a.occurred_at>=clock_timestamp()-interval '24 hours'
   AND a.intent_finished_at IS NULL AND a.intent_attempts<3 AND (a.intent_ready_at IS NULL OR a.intent_ready_at<=clock_timestamp())
   AND NOT EXISTS(SELECT 1 FROM public.zasp_action_analysis_versions newer WHERE
    (newer.organization_id,newer.workspace_id,newer.environment_id,newer.agent_id)=(a.organization_id,a.workspace_id,a.environment_id,a.agent_id) AND newer.revision>a.revision)
  ORDER BY a.seq LIMIT 1 FOR UPDATE OF a SKIP LOCKED
 ), claimed AS (
  UPDATE public.zasp_action_analysis_evidence a SET intent_attempts=intent_attempts+1,intent_lease=gen_random_uuid(),intent_ready_at=clock_timestamp()+interval '5 minutes'
  FROM next_job WHERE a.seq=next_job.seq RETURNING a.*
 )
 SELECT coalesce((SELECT jsonb_build_object('lease',intent_lease,'features',jsonb_build_object(
  'destination',CASE WHEN destination IN('internal','approved_partner','external','public') THEN destination ELSE 'unknown' END,
  'has_previous',previous_operation IS NOT NULL,'operation_mismatch','operation_outside_purpose'=ANY(issues),
  'classification_mismatch','classification_outside_purpose'=ANY(issues),'destination_mismatch','destination_outside_purpose'=ANY(issues),
  'sequence_mismatch','sequence_outside_purpose'=ANY(issues))) FROM claimed),'null'::jsonb)
$intent_claim$;

CREATE OR REPLACE FUNCTION public.zasp_finish_intent_draft(token uuid,recommendation text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $intent_finish$
BEGIN
 IF token IS NULL OR (recommendation IS NOT NULL AND recommendation NOT IN('none','review_purpose','review_destination','review_sequence','review_data_access')) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unrecognized advisory review code'; END IF;
 UPDATE public.zasp_action_analysis_evidence a SET intent_lease=NULL,intent_recommendation=recommendation,intent_finished_at=CASE WHEN recommendation IS NOT NULL THEN clock_timestamp() END
 WHERE a.intent_lease=token AND a.intent_ready_at>clock_timestamp() AND a.intent_finished_at IS NULL
 AND EXISTS(SELECT FROM public.zasp_action_analysis_versions v WHERE (v.organization_id,v.workspace_id,v.environment_id,v.agent_id,v.revision)=(a.organization_id,a.workspace_id,a.environment_id,a.agent_id,a.revision) AND v.settings->'classifier_opt_in'='true'::jsonb)
 AND NOT EXISTS(SELECT FROM public.zasp_action_analysis_versions newer WHERE (newer.organization_id,newer.workspace_id,newer.environment_id,newer.agent_id)=(a.organization_id,a.workspace_id,a.environment_id,a.agent_id) AND newer.revision>a.revision);
 RETURN FOUND;
END $intent_finish$;
ALTER FUNCTION public.zasp_claim_intent_draft() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_finish_intent_draft(uuid,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_claim_intent_draft(),public.zasp_finish_intent_draft(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_claim_intent_draft(),public.zasp_finish_intent_draft(uuid,text) TO zasp_discovery_scheduler;

CREATE OR REPLACE FUNCTION zasp_authorization80.intent_flow(o text,w text,e text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $flow$
DECLARE enabled boolean; result text;
BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'getExternalDataFlows','view','environment',e,false,true,false,false);
 SELECT EXISTS(SELECT FROM (SELECT DISTINCT ON(agent_id) settings FROM public.zasp_action_analysis_versions WHERE (organization_id,workspace_id,environment_id)=(o,w,e) ORDER BY agent_id,revision DESC) agents WHERE settings->'classifier_opt_in'='true'::jsonb) INTO enabled;
 SELECT CASE WHEN intent_finished_at IS NULL THEN 'degraded' ELSE 'healthy' END INTO result
 FROM public.zasp_action_analysis_evidence WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND intent_attempts>0 AND intent_ready_at > now()-interval '1 day' ORDER BY intent_ready_at DESC LIMIT 1;
 RETURN jsonb_build_object('id','openrouter-intent-classifier','required',false,'categories',jsonb_build_array('redacted_summary'),'enabled',enabled,'health',CASE WHEN enabled THEN coalesce(result,'degraded') ELSE 'disabled' END);
END $flow$;
ALTER FUNCTION zasp_authorization80.intent_flow(text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.intent_flow(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.intent_flow(text,text,text) TO zasp_discovery_api;
