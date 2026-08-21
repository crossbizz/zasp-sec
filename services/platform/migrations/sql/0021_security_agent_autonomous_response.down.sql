DO $rollback_guard$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='security_agent_autonomous_fingerprint' AND value='dae50d0d29cdfb697c26a9fd919a34920ac864fddf1193b2b7ccf96d46749675')
     OR zasp_security_agent_autonomous_live_fingerprint()<>'dae50d0d29cdfb697c26a9fd919a34920ac864fddf1193b2b7ccf96d46749675'
     OR NOT zasp_security_agent_autonomous_security_ready()
     OR NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-autonomous-v1')
     OR EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>21)
     OR EXISTS(SELECT 1 FROM zasp_security_agent_definitions WHERE activation='autonomous' OR body->>'autonomy'='autonomous')
     OR EXISTS(SELECT 1 FROM zasp_security_agent_steps WHERE authorization_result='autonomous') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent autonomous rollback rejected';
  END IF;
END
$rollback_guard$;

DROP FUNCTION public.zasp_security_agent_autonomous_readiness(text,text);
DROP FUNCTION public.zasp_security_agent_autonomous_live_fingerprint();
DROP FUNCTION public.zasp_security_agent_autonomous_security_ready();
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_schedule_triggers_v21(text,integer),public.zasp_security_agent_prepare_run_v21(text,text,text,text,text,text,text,timestamptz,text,text),public.zasp_security_agent_execute_run_v21(text,text,text,text,text,text,text,text) FROM zasp_security_agent_worker;
DROP FUNCTION public.zasp_security_agent_execute_run_v21(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_prepare_run_v21(text,text,text,text,text,text,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_schedule_triggers_v21(text,integer);
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_schedule_triggers(text,integer),public.zasp_security_agent_prepare_run(text,text,text,text,text,text,text,timestamptz,text,text),public.zasp_security_agent_execute_run(text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;

DROP TRIGGER zasp_security_agent_sync_autonomy_v21 ON public.zasp_security_agent_definitions;
DROP FUNCTION public.zasp_security_agent_sync_autonomy_v21();

ALTER TABLE public.zasp_security_agent_steps DROP CONSTRAINT zasp_security_agent_steps_authorization_result_check;
ALTER TABLE public.zasp_security_agent_steps ADD CONSTRAINT zasp_security_agent_steps_authorization_result_check CHECK(authorization_result IN('allow','approval_required','deny'));

DELETE FROM public.zasp_schema_metadata WHERE key='security_agent_autonomous_fingerprint';
UPDATE public.zasp_schema_metadata SET value='security-agent-controls-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='security-agent-autonomous-v1';

DO $product_release_restore$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-autonomous-v1','security-agent-controls-v1');
  definition:=replace(definition,'release."version" = 21','release."version" = 20');
  definition:=replace(definition,'release."name" = ''security_agent_autonomous_response''','release."name" = ''security_agent_controls''');
  definition:=replace(definition,'later_release."version" > 21','later_release."version" > 20');
  IF definition=original_definition OR position('security-agent-controls-v1' IN definition)=0 OR position('release."version" = 20' IN definition)=0 OR position('release."name" = ''security_agent_controls''' IN definition)=0 OR position('later_release."version" > 20' IN definition)=0 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v20 compatibility restore failed';
  END IF;
  EXECUTE definition;

  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-autonomous-v1','security-agent-controls-v1');
  definition:=replace(replace(definition,'release."version"=21','release."version"=20'),'release."version" = 21','release."version" = 20');
  definition:=replace(replace(definition,'release."name"=''security_agent_autonomous_response''','release."name"=''security_agent_controls'''),'release."name" = ''security_agent_autonomous_response''','release."name" = ''security_agent_controls''');
  definition:=replace(replace(definition,'later."version">21','later."version">20'),'later."version" > 21','later."version" > 20');
  IF definition=original_definition OR position('security-agent-controls-v1' IN definition)=0 OR position('security_agent_controls' IN definition)=0 OR position('release."version"=20' IN definition)=0 AND position('release."version" = 20' IN definition)=0 OR position('later."version">20' IN definition)=0 AND position('later."version" > 20' IN definition)=0 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v20 compatibility restore failed';
  END IF;
  EXECUTE definition;
END
$product_release_restore$;
