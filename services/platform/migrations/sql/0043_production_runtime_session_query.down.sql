DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>43) OR NOT public.zasp_production_runtime_session_query_security_ready()
 OR public.zasp_production_runtime_session_query_live_fingerprint()<>(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_session_query_fingerprint') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session query rollback rejected';
 END IF;
END
$guard$;
DROP FUNCTION public.zasp_production_runtime_session_search_readiness(text,text);
ALTER FUNCTION public.zasp_production_runtime_session_search_readiness_v42(text,text) RENAME TO zasp_production_runtime_session_search_readiness;
DROP FUNCTION public.zasp_runtime_session_query_hydrate(text,text,text,text,text[]);
DROP FUNCTION public.zasp_runtime_session_query_status(text,text,text,text);
DROP FUNCTION public.zasp_production_runtime_session_query_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_session_query_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_session_query_security_ready();
DROP INDEX public.zasp_runtime_session_query_pending_idx;
DROP INDEX public.zasp_runtime_session_query_quarantine_idx;
DROP INDEX public.zasp_runtime_session_query_indexed_idx;
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 43','later_release."version" > 42'),'later."version">43','later."version">42'),'later."version" > 43','later."version" > 42');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session query compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_session_query_fingerprint';
