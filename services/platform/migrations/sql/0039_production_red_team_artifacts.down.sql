DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>39)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_red_team_artifacts_fingerprint' AND value='945775780a1752765398d6da17ce9aaf75c2fec8877d20c14c871020bfb0039c')
 OR NOT public.zasp_production_red_team_artifacts_security_ready()
 OR public.zasp_production_red_team_artifacts_live_fingerprint()<>'945775780a1752765398d6da17ce9aaf75c2fec8877d20c14c871020bfb0039c'
 OR EXISTS(SELECT 1 FROM public.zasp_red_team_attempts WHERE input_artifact IS NOT NULL) THEN
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team artifacts rollback rejected; retained input references require forward recovery';
 END IF;
END
$guard$;

DROP FUNCTION public.zasp_production_red_team_invocation_readiness(text,text);
ALTER FUNCTION public.zasp_production_red_team_invocation_readiness_v38(text,text) RENAME TO zasp_production_red_team_invocation_readiness;
REVOKE ALL ON FUNCTION public.zasp_production_red_team_invocation_readiness(text,text) FROM PUBLIC;
DROP FUNCTION public.zasp_production_red_team_artifacts_readiness(text,text);
DROP FUNCTION public.zasp_production_red_team_artifacts_live_fingerprint();
DROP FUNCTION public.zasp_production_red_team_artifacts_security_ready();
DROP FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb);
DROP FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint);
ALTER FUNCTION public.zasp_red_team_finish_run_v38(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint) RENAME TO zasp_red_team_finish_run;
REVOKE ALL ON FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint) TO zasp_red_team_worker;
DO $detail$
DECLARE definition text; prior text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_red_team_get_run(text,text,text,text)'::regprocedure) INTO STRICT definition;prior:=definition;
 definition:=replace(definition,'''evidence_reference'',evidence_reference,''input_artifact'',input_artifact','''evidence_reference'',evidence_reference');
 IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team input detail rollback rejected';END IF;
 EXECUTE definition;
END
$detail$;
ALTER TABLE public.zasp_red_team_attempts DROP COLUMN input_artifact;
DROP FUNCTION public.zasp_red_team_valid_input_artifact(text,text,text,jsonb);

DO $compatibility$
DECLARE definition text; prior text; function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 39','later_release."version" > 38'),'later."version">39','later."version">38'),'later."version" > 39','later."version" > 38');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team artifacts compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_red_team_artifacts_fingerprint';
