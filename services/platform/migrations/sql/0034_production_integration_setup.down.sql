DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>34)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_integration_setup_fingerprint' AND value='02b12cb41460db83cb28c45d25ccfc0a9e8648504a59e17bdcdbfefe8abbc73b')
     OR NOT public.zasp_production_integration_setup_security_ready()
     OR public.zasp_production_integration_setup_live_fingerprint()<>'02b12cb41460db83cb28c45d25ccfc0a9e8648504a59e17bdcdbfefe8abbc73b' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production integration setup rollback rejected';
  END IF;
END
$guard$;

DROP FUNCTION public.zasp_production_security_agent_attack_path_readiness(text,text);
ALTER FUNCTION public.zasp_production_security_agent_attack_path_readiness_v33(text,text) RENAME TO zasp_production_security_agent_attack_path_readiness;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_attack_path_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_attack_path_readiness(text,text) TO zasp_security_agent_worker;

DROP FUNCTION public.zasp_production_integration_setup_readiness(text,text);
DROP FUNCTION public.zasp_production_integration_setup_live_fingerprint();
DROP FUNCTION public.zasp_production_integration_setup_security_ready();
DROP FUNCTION public.zasp_execution_integration_setup_status(text,text,text,text,text,text);

DO $compatibility$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'later_release."version" > 34','later_release."version" > 33');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v33 compatibility restoration failed';END IF;
  EXECUTE definition;
  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(replace(definition,'later."version">34','later."version">33'),'later."version" > 34','later."version" > 33');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v33 compatibility restoration failed';END IF;
  EXECUTE definition;
  SELECT pg_get_functiondef('public.zasp_production_security_agent_attack_path_security_ready()'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 34','later_release."version" > 33'),'later."version">34','later."version">33'),'later."version" > 34','later."version" > 33');
  IF definition=original_definition THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack path v33 compatibility restoration failed';END IF;
  EXECUTE definition;
END
$compatibility$;

CREATE OR REPLACE FUNCTION public.zasp_production_workflow_compatibility_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_approval_notification_security_ready()
 AND position('later_release."version" > 33' IN pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure))>0
 AND (position('later."version">33' IN pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure))>0
      OR position('later."version" > 33' IN pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure))>0)
$security$;

DELETE FROM public.zasp_schema_metadata WHERE key='production_integration_setup_fingerprint';
