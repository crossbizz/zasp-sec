DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>33)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_attack_path_fingerprint' AND value='17fb3400df07d6385314df4bf85de861800baf67bca664ff3ea20e5a8ae491cf')
     OR NOT public.zasp_production_security_agent_attack_path_security_ready()
     OR public.zasp_production_security_agent_attack_path_live_fingerprint()<>'17fb3400df07d6385314df4bf85de861800baf67bca664ff3ea20e5a8ae491cf' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production security agent attack path rollback rejected';
  END IF;
  IF EXISTS(SELECT 1 FROM public.zasp_security_agent_trigger_receipts WHERE trigger_kind='attack_path') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack path runs block rollback';
  END IF;
END
$guard$;

DROP FUNCTION public.zasp_production_security_agent_planner_readiness(text,text);
ALTER FUNCTION public.zasp_production_security_agent_planner_readiness_v32(text,text) RENAME TO zasp_production_security_agent_planner_readiness;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_planner_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_planner_readiness(text,text) TO zasp_security_agent_worker;

DROP FUNCTION public.zasp_production_security_agent_attack_path_readiness(text,text);
DROP FUNCTION public.zasp_production_security_agent_attack_path_live_fingerprint();
DROP FUNCTION public.zasp_production_security_agent_attack_path_security_ready();
DROP FUNCTION public.zasp_security_agent_fail_planner_v33(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_accept_planner_candidate_v33(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_planner_context_v33(text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_prepare_run_v33(text,text,text,text,text,text,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_prepare_temporary_policy_run_v33(text,text,text,text,text,text,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_schedule_triggers_v33(text,integer);
DROP FUNCTION public.zasp_security_agent_schedule_attack_path_triggers_v33(text,integer);

DO $compatibility$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'later_release."version" > 33','later_release."version" > 32');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v32 compatibility restoration failed';END IF;
  EXECUTE definition;
  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(replace(definition,'later."version">33','later."version">32'),'later."version" > 33','later."version" > 32');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v32 compatibility restoration failed';END IF;
  EXECUTE definition;
END
$compatibility$;

CREATE OR REPLACE FUNCTION public.zasp_production_workflow_compatibility_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_approval_notification_security_ready()
 AND position('later_release."version" > 32' IN pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure))>0
 AND (position('later."version">32' IN pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure))>0
      OR position('later."version" > 32' IN pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure))>0)
$security$;

DELETE FROM public.zasp_schema_metadata WHERE key='production_security_agent_attack_path_fingerprint';
