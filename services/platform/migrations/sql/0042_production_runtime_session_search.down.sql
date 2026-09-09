LOCK TABLE public.zasp_runtime_session_projection_receipts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.zasp_runtime_session_search_outbox IN ACCESS EXCLUSIVE MODE;
DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>42)
 OR NOT public.zasp_production_runtime_session_search_security_ready()
 OR public.zasp_production_runtime_session_search_live_fingerprint()<>(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_session_search_fingerprint')
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_session_search_outbox WHERE state='leased' AND lease_until>clock_timestamp()) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session search rollback rejected';
 END IF;
END
$guard$;
DROP FUNCTION public.zasp_production_runtime_session_reads_readiness(text,text);
ALTER FUNCTION public.zasp_production_runtime_session_reads_readiness_v41(text,text) RENAME TO zasp_production_runtime_session_reads_readiness;
DROP FUNCTION public.zasp_production_runtime_session_search_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_session_search_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_session_search_security_ready();
DROP FUNCTION public.zasp_runtime_session_search_worker_ready();
DROP FUNCTION public.zasp_runtime_session_search_claim(text,text,integer);
DROP FUNCTION public.zasp_runtime_session_search_heartbeat(text,text,text,text,bigint,text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_session_search_finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer);
DROP TRIGGER zasp_runtime_session_search_enqueue ON public.zasp_runtime_session_projection_receipts;
DROP FUNCTION public.zasp_runtime_session_search_enqueue();
DROP FUNCTION public.zasp_runtime_session_search_document_ids(text,text,text,text,bigint,text[]);
-- Derived queue/checkpoints are reconstructable from retained committed receipts.
-- Re-upgrade backfills them; immutable index writes reconcile existing documents.
DROP TABLE public.zasp_runtime_session_search_outbox;
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 42','later_release."version" > 41'),'later."version">42','later."version">41'),'later."version" > 42','later."version" > 41');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session search compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_session_search_fingerprint';
