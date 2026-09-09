LOCK TABLE public.zasp_runtime_session_events,public.zasp_runtime_session_projection_receipts IN ACCESS EXCLUSIVE MODE;
DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>40)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_runtime_sessions_fingerprint' AND value='7f965cecd58fa1cec602bd85f4b7ac81a9984f8216bf51444a17b31194311063')
 OR NOT public.zasp_production_runtime_sessions_security_ready()
 OR public.zasp_production_runtime_sessions_live_fingerprint()<>'7f965cecd58fa1cec602bd85f4b7ac81a9984f8216bf51444a17b31194311063'
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_session_events)
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_session_projection_receipts) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sessions rollback rejected; retained projections require forward recovery';
 END IF;
END
$guard$;
DROP FUNCTION public.zasp_production_red_team_artifacts_readiness(text,text);
ALTER FUNCTION public.zasp_production_red_team_artifacts_readiness_v39(text,text) RENAME TO zasp_production_red_team_artifacts_readiness;
DROP FUNCTION public.zasp_production_runtime_sessions_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_sessions_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_sessions_security_ready();
DROP FUNCTION public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea);
DROP FUNCTION public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer);
ALTER FUNCTION public.zasp_runtime_finish_stage_v39(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer) RENAME TO zasp_runtime_finish_stage;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer) TO zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker;
DROP TABLE public.zasp_runtime_session_projection_receipts;
DROP TABLE public.zasp_runtime_session_events;
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 40','later_release."version" > 39'),'later."version">40','later."version">39'),'later."version" > 40','later."version" > 39');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sessions compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_sessions_fingerprint';
