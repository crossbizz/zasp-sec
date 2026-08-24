DO $rollback_guard$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-connector-revocation-v1')
     OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>23)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='security_agent_connector_revocation_fingerprint' AND value='65cb411e946fa081b4c2ab7cf38e07ac0c9487af4d5a09d7fb55b8aa9bc066cc')
     OR public.zasp_security_agent_connector_revocation_live_fingerprint()<>'65cb411e946fa081b4c2ab7cf38e07ac0c9487af4d5a09d7fb55b8aa9bc066cc'
     OR NOT public.zasp_security_agent_connector_revocation_security_ready()
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE action_key='revoke_integration_connection')
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_connector_revocations)
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions WHERE body->'allowed_actions' ? 'revoke_integration_connection')
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_kill_switches WHERE action_key='revoke_integration_connection') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent connector revocation rollback rejected';
  END IF;
END
$rollback_guard$;

DROP FUNCTION public.zasp_security_agent_connector_revocation_readiness(text,text);
DROP FUNCTION public.zasp_security_agent_connector_revocation_live_fingerprint();
DROP FUNCTION public.zasp_security_agent_connector_revocation_security_ready();

REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_schedule_triggers_v23(text,integer),public.zasp_security_agent_claim_runs_v23(text,text,integer,integer),public.zasp_security_agent_prepare_run_v23(text,text,text,text,text,text,text,timestamptz,text,text),public.zasp_security_agent_execute_run_v23(text,text,text,text,text,text,text,text) FROM zasp_security_agent_worker;
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_run_detail_v23(text,text,text,text),public.zasp_security_agent_approval_page_v23(text,text,text,text,text,timestamptz,text,integer),public.zasp_security_agent_approval_detail_v23(text,text,text,text),public.zasp_security_agent_decide_approval_v23(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) FROM zasp_security_agent_api;
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_reconcile_connector_revocations(text,integer) FROM zasp_security_agent_action_worker;

DROP FUNCTION public.zasp_security_agent_decide_approval_v23(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text);
DROP FUNCTION public.zasp_security_agent_approval_detail_v23(text,text,text,text);
DROP FUNCTION public.zasp_security_agent_approval_page_v23(text,text,text,text,text,timestamptz,text,integer);
DROP FUNCTION public.zasp_security_agent_run_detail_v23(text,text,text,text);
DROP FUNCTION public.zasp_security_agent_approval_value_v23(text,text,text,text);
DROP FUNCTION public.zasp_security_agent_reconcile_connector_revocations(text,integer);
DROP FUNCTION public.zasp_security_agent_execute_run_v23(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_dispatch_connector_revocation_run(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_prepare_run_v23(text,text,text,text,text,text,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_prepare_connector_revocation_run(text,text,text,text,text,text,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_claim_runs_v23(text,text,integer,integer);
DROP FUNCTION public.zasp_security_agent_schedule_triggers_v23(text,integer);
DROP FUNCTION public.zasp_security_agent_schedule_connector_revocation_triggers(text,integer);

DO $connector_restore$
DECLARE definition text;restored_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_connector_complete_revocation_v22(text,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  restored_definition:=replace(definition,'zasp_connector_complete_revocation_v22','zasp_connector_complete_revocation');
  IF restored_definition=definition THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='connector revocation restore failed';END IF;
  EXECUTE restored_definition;
END
$connector_restore$;
DROP FUNCTION public.zasp_connector_complete_revocation_v22(text,text,text,text,text,text);

DO $controls_restore$
DECLARE definition text;restored_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_security_agent_execution_control_detail_v22_restore(text,text,text)'::regprocedure) INTO STRICT definition;
  restored_definition:=replace(definition,'zasp_security_agent_execution_control_detail_v22_restore','zasp_security_agent_execution_control_detail');
  IF restored_definition=definition THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution control detail restore failed';END IF;
  EXECUTE restored_definition;

  SELECT pg_get_functiondef('public.zasp_security_agent_mutate_execution_control_v22_restore(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)'::regprocedure) INTO STRICT definition;
  restored_definition:=replace(definition,'zasp_security_agent_mutate_execution_control_v22_restore','zasp_security_agent_mutate_execution_control');
  IF restored_definition=definition THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution control mutation restore failed';END IF;
  EXECUTE restored_definition;
END
$controls_restore$;
DROP FUNCTION public.zasp_security_agent_execution_control_detail_v22_restore(text,text,text);
DROP FUNCTION public.zasp_security_agent_mutate_execution_control_v22_restore(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text);

ALTER TABLE public.zasp_security_agent_definitions DROP CONSTRAINT zasp_security_agent_connector_revocation_supervised_check;
DROP TABLE public.zasp_security_agent_connector_revocations;
DELETE FROM public.zasp_schema_metadata WHERE key='security_agent_connector_revocation_fingerprint';
UPDATE public.zasp_schema_metadata SET value='security-agent-temporary-policy-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='security-agent-connector-revocation-v1';

DO $product_release_restore$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-connector-revocation-v1','security-agent-temporary-policy-v1');
  definition:=replace(definition,'release."version" = 23','release."version" = 22');
  definition:=replace(definition,'release."name" = ''security_agent_connector_revocation''','release."name" = ''security_agent_temporary_policy''');
  definition:=replace(definition,'later_release."version" > 23','later_release."version" > 22');
  IF definition=original_definition OR position('security-agent-temporary-policy-v1' IN definition)=0 OR position('release."version" = 22' IN definition)=0 OR position('security_agent_temporary_policy' IN definition)=0 OR position('later_release."version" > 22' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v22 compatibility restore failed';END IF;
  EXECUTE definition;

  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-connector-revocation-v1','security-agent-temporary-policy-v1');
  definition:=replace(replace(definition,'release."version"=23','release."version"=22'),'release."version" = 23','release."version" = 22');
  definition:=replace(replace(definition,'release."name"=''security_agent_connector_revocation''','release."name"=''security_agent_temporary_policy'''),'release."name" = ''security_agent_connector_revocation''','release."name" = ''security_agent_temporary_policy''');
  definition:=replace(replace(definition,'later."version">23','later."version">22'),'later."version" > 23','later."version" > 22');
  IF definition=original_definition OR position('security-agent-temporary-policy-v1' IN definition)=0 OR position('security_agent_temporary_policy' IN definition)=0 OR position('release."version"=22' IN definition)=0 AND position('release."version" = 22' IN definition)=0 OR position('later."version">22' IN definition)=0 AND position('later."version" > 22' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v22 compatibility restore failed';END IF;
  EXECUTE definition;
END
$product_release_restore$;
