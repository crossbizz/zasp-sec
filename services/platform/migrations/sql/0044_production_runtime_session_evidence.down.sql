-- Serialize the retained-new-class check with every projection insert. A
-- downgrade never drops or relabels evidence that the older release cannot read.
LOCK TABLE public.zasp_runtime_session_events IN SHARE ROW EXCLUSIVE MODE;
DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>44) OR NOT public.zasp_production_runtime_session_evidence_security_ready()
 OR public.zasp_production_runtime_session_evidence_live_fingerprint()<>(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_session_evidence_fingerprint')
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_session_events WHERE event_class IN('credential','policy')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session evidence rollback rejected';
 END IF;
END
$guard$;
DROP FUNCTION public.zasp_production_runtime_session_query_readiness(text,text);
ALTER FUNCTION public.zasp_production_runtime_session_query_readiness_v43(text,text) RENAME TO zasp_production_runtime_session_query_readiness;
DROP FUNCTION public.zasp_runtime_session_event_get(text,text,text,text,text,text);
DROP FUNCTION public.zasp_production_runtime_session_evidence_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_session_evidence_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_session_evidence_security_ready();
ALTER TABLE public.zasp_runtime_session_events DROP CONSTRAINT zasp_runtime_session_event_source_action_v44;
ALTER TABLE public.zasp_runtime_session_events DROP CONSTRAINT zasp_runtime_session_events_event_class_check;
ALTER TABLE public.zasp_runtime_session_events DROP CONSTRAINT zasp_runtime_session_events_action_check;
ALTER TABLE public.zasp_runtime_session_events ADD CONSTRAINT zasp_runtime_session_events_event_class_check CHECK(event_class IN('tool','process','file','network'));
ALTER TABLE public.zasp_runtime_session_events ADD CONSTRAINT zasp_runtime_session_events_action_check CHECK(action IN('invoke','exec','exit','read','write','connect','accept'));
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 44','later_release."version" > 43'),'later."version">44','later."version">43'),'later."version" > 44','later."version" > 43');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session evidence compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_session_evidence_fingerprint';
