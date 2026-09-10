DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>46) OR NOT public.zasp_production_reconciliation_lane_plan_security_ready()
 OR public.zasp_production_reconciliation_lane_plan_live_fingerprint()<>(SELECT value FROM public.zasp_schema_metadata WHERE key='production_reconciliation_lane_plan_fingerprint') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='reconciliation plan rollback rejected';
 END IF;
END
$guard$;
DROP FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness(text,text);
ALTER FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness_v45(text,text) RENAME TO zasp_production_runtime_enrollment_pairing_readiness;
DROP FUNCTION public.zasp_production_reconciliation_lane_plan_readiness(text,text);
DROP FUNCTION public.zasp_production_reconciliation_lane_plan_live_fingerprint();
DROP FUNCTION public.zasp_production_reconciliation_lane_plan_security_ready();
DO $rewrite$
DECLARE definition text; restored_body text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_connector_claim_reconciliation(text,integer,integer)'::regprocedure) INTO STRICT definition;
 definition:=replace(definition,$new$WITH eligible_lanes AS MATERIALIZED (SELECT lane.* FROM zasp_connector_effect_lane_scopes lane WHERE NOT EXISTS(SELECT 1 FROM zasp_connector_effects live WHERE live.provider=lane.provider AND live.operation=lane.operation AND live.status='unknown' AND live.lease_expires_at>transaction_timestamp())), candidates AS$new$,'WITH candidates AS');
 definition:=replace(definition,'FROM eligible_lanes lane CROSS JOIN LATERAL','FROM zasp_connector_effect_lane_scopes lane CROSS JOIN LATERAL');
 definition:=replace(definition,$before$ AND (candidate.operation<>'pkce_cleanup'$before$,$after$ AND NOT EXISTS(SELECT 1 FROM zasp_connector_effects live WHERE live.provider=candidate.provider AND live.operation=candidate.operation AND live.status='unknown' AND live.lease_expires_at>transaction_timestamp()) AND (candidate.operation<>'pkce_cleanup'$after$);
 EXECUTE definition;
 SELECT prosrc INTO STRICT restored_body FROM pg_proc WHERE oid='public.zasp_connector_claim_reconciliation(text,integer,integer)'::regprocedure;
 IF encode(digest(convert_to(restored_body,'UTF8'),'sha256'),'hex')<>'93de1fd6a09761ee6eb5317907d090a30014dd6ce46b33accc85ce23e140dd07' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='reconciliation claim restoration rejected';END IF;
END
$rewrite$;
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 46','later_release."version" > 45'),'later."version">46','later."version">45'),'later."version" > 46','later."version" > 45');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='reconciliation plan compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

DELETE FROM public.zasp_schema_metadata WHERE key='production_reconciliation_lane_plan_fingerprint';
