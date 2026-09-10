-- Lock both retained-data tables before checking emptiness. Concurrent admission
-- must commit or roll back before this check; no evidence is deleted to downgrade.
-- Freeze reads the prior snapshot before admitting observations. Match that
-- acquisition order so rollback cannot invert the two relation locks.
LOCK TABLE public.zasp_runtime_candidate_snapshots,public.zasp_runtime_candidate_observations IN ACCESS EXCLUSIVE MODE;
DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>47)
 OR NOT COALESCE(public.zasp_production_runtime_candidate_authority_security_ready(),false)
 OR public.zasp_production_runtime_candidate_authority_live_fingerprint() IS DISTINCT FROM (SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_candidate_authority_fingerprint')
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_candidate_observations) OR EXISTS(SELECT 1 FROM public.zasp_runtime_candidate_snapshots) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime candidate rollback rejected';
 END IF;
END
$guard$;
DROP FUNCTION public.zasp_production_reconciliation_lane_plan_readiness(text,text);
ALTER FUNCTION public.zasp_production_reconciliation_lane_plan_readiness_v46(text,text) RENAME TO zasp_production_reconciliation_lane_plan_readiness;
DROP FUNCTION public.zasp_runtime_freeze_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea);
DROP FUNCTION public.zasp_runtime_candidate_execution_live(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea);
DROP FUNCTION public.zasp_runtime_candidate_lineage_valid(jsonb,timestamptz);
DROP FUNCTION public.zasp_production_runtime_candidate_authority_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_candidate_authority_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_candidate_authority_security_ready();
DROP TABLE public.zasp_runtime_candidate_snapshots;
DROP TABLE public.zasp_runtime_candidate_observations;
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 47','later_release."version" > 46'),'later."version">47','later."version">46'),'later."version" > 47','later."version" > 46');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime candidate compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_candidate_authority_fingerprint';
