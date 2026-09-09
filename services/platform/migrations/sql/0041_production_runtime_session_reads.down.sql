LOCK TABLE public.zasp_runtime_session_events IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.zasp_runtime_session_summaries IN ACCESS EXCLUSIVE MODE;
DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>41)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_runtime_session_reads_fingerprint' AND value='f7ab24a108da3edb743e164646f0db64119dd505f50723cde3a4635565b96d4f')
 OR NOT public.zasp_production_runtime_session_reads_security_ready()
 OR public.zasp_production_runtime_session_reads_live_fingerprint()<>'f7ab24a108da3edb743e164646f0db64119dd505f50723cde3a4635565b96d4f' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session reads rollback rejected';
 END IF;
END
$guard$;
DROP FUNCTION public.zasp_production_runtime_sessions_readiness(text,text);
ALTER FUNCTION public.zasp_production_runtime_sessions_readiness_v40(text,text) RENAME TO zasp_production_runtime_sessions_readiness;
DROP FUNCTION public.zasp_production_runtime_session_reads_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_session_reads_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_session_reads_security_ready();
DROP FUNCTION public.zasp_runtime_session_page(text,text,text,text,text,integer,text,timestamptz,timestamptz);
DROP FUNCTION public.zasp_runtime_session_get(text,text,text,text,text);
DROP FUNCTION public.zasp_runtime_session_event_page(text,text,text,text,text,timestamptz,text,integer);
DROP FUNCTION public.zasp_runtime_session_read_authorized(text,text,text,text);
DROP FUNCTION public.zasp_runtime_session_summary_json(public.zasp_runtime_session_summaries);
DROP TRIGGER zasp_runtime_session_summary_projection ON public.zasp_runtime_session_events;
DROP FUNCTION public.zasp_runtime_session_maintain_summary();
DROP INDEX public.zasp_runtime_session_investigation_events_idx;
-- Only derived summaries are discarded. All source events and receipts remain.
DROP TABLE public.zasp_runtime_session_summaries;
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 41','later_release."version" > 40'),'later."version">41','later."version">40'),'later."version" > 41','later."version" > 40');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session reads compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_session_reads_fingerprint';
