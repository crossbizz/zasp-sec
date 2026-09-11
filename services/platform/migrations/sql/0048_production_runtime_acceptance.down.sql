DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>48)
 OR NOT COALESCE(public.zasp_production_runtime_acceptance_security_ready(),false)
 OR public.zasp_production_runtime_acceptance_live_fingerprint() IS DISTINCT FROM (SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_acceptance_fingerprint') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime acceptance rollback rejected';
 END IF;
END
$guard$;
DROP FUNCTION public.zasp_production_runtime_candidate_authority_readiness(text,text);
ALTER FUNCTION public.zasp_production_runtime_candidate_authority_readiness_v47(text,text) RENAME TO zasp_production_runtime_candidate_authority_readiness;
DROP FUNCTION public.zasp_runtime_lookup_acceptance(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer,text,text,text,text);
DROP FUNCTION public.zasp_production_runtime_acceptance_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_acceptance_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_acceptance_security_ready();
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 48','later_release."version" > 47'),'later."version">48','later."version">47'),'later."version" > 48','later."version" > 47');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime acceptance compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_acceptance_fingerprint';
