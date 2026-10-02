-- Reuse the existing principal-scoped66 read before inspecting private78 data.
-- This is historical display proof, not fresh permission to execute an effect.
CREATE FUNCTION zasp_temporal78.run_context(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
DECLARE envelope jsonb;item jsonb;step_value jsonb;arguments_value jsonb;x zasp_temporal78.run_owners%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;j zasp_temporal78.planning_jobs%ROWTYPE;BEGIN
 IF NOT zasp_temporal78.api_ready('-- finding78 checksum','-- finding78 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding public read unavailable';END IF;
 SELECT value INTO envelope FROM zasp_temporal66.run_context(o,w,e,r,(SELECT checksum FROM zasp_temporal66.registration),(SELECT fingerprint FROM zasp_temporal66.registration)) rows(value);
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT * INTO x FROM zasp_temporal78.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF envelope->'detail'->'run'->>'id' IS DISTINCT FROM r OR envelope->'action_details'->>'run_id' IS DISTINCT FROM r THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding public identity changed';END IF;
 IF envelope->'detail'->'plan'='null'::jsonb THEN RETURN envelope;END IF;
 SELECT * INTO p FROM public.zasp_security_agent_plans WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO j FROM zasp_temporal78.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 item:=p.plan->'steps'->0;step_value:=envelope->'action_details'->'steps'->0;
 IF p.run_id IS NULL OR j.run_id IS NULL OR j.state<>'admitted' OR p.plan_hash IS DISTINCT FROM digest(convert_to(p.plan::text,'UTF8'),'sha256')
  OR 'sha256:'||encode(p.plan_hash,'hex') IS DISTINCT FROM envelope->'action_details'->>'plan_hash' OR jsonb_array_length(p.plan->'steps')<>1 OR jsonb_array_length(envelope->'action_details'->'steps')<>1
  OR item IS DISTINCT FROM zasp_temporal78.plan_item(x,j.result_value->'candidate',item->>'authorization') OR NOT zasp_temporal78.candidate_valid(j.result_value->'candidate',j.context_value)
  OR (step_value->>'step_id',step_value->>'action') IS DISTINCT FROM(x.step_id,x.action_key) OR step_value->'index' IS DISTINCT FROM '0'::jsonb
  OR step_value->'arguments' IS DISTINCT FROM jsonb_build_object('target_id',item->'target_id','expected_version',item->'expected_version','target_status',item->'target_status')
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding public plan proof changed';END IF;
 IF (step_value->'effect'<>'null'::jsonb) IS DISTINCT FROM EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding public effect proof changed';END IF;
 IF step_value->'effect'<>'null'::jsonb THEN PERFORM zasp_temporal78.effect_evidence(o,w,e,r);END IF;
 arguments_value:=step_value->'arguments'||jsonb_build_object('assignee_id',item->'assignee_id','response_status',item->'response_status','note',item->'note');
 RETURN zasp_temporal78.project_approvals(o,w,e,jsonb_set(envelope,'{action_details,steps,0,arguments}',arguments_value));
END $read$;
