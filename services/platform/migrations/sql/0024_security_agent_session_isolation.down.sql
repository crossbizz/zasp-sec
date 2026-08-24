DO $rollback_guard$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-session-isolation-v1')
     OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>24)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='security_agent_session_isolation_fingerprint' AND value='83c45008cc9ab2c939788c082c7b46c05d2c761470a109e06ff14091ff100fe4')
     OR public.zasp_security_agent_session_isolation_live_fingerprint()<>'83c45008cc9ab2c939788c082c7b46c05d2c761470a109e06ff14091ff100fe4'
     OR NOT public.zasp_security_agent_session_isolation_security_ready()
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE action_key='isolate_session')
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions WHERE body->'allowed_actions' ? 'isolate_session')
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_kill_switches WHERE action_key='isolate_session') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent session isolation rollback rejected';
  END IF;
END
$rollback_guard$;

DROP FUNCTION public.zasp_security_agent_session_isolation_readiness(text,text);
DROP FUNCTION public.zasp_security_agent_session_isolation_live_fingerprint();
DROP FUNCTION public.zasp_security_agent_session_isolation_security_ready();

REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_schedule_triggers_v24(text,integer),public.zasp_security_agent_prepare_run_v24(text,text,text,text,text,text,text,timestamptz,text,text),public.zasp_security_agent_execute_run_v24(text,text,text,text,text,text,text,text) FROM zasp_security_agent_worker;
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_run_v24(text,text,text,text,text,text,bigint,text,text,text,text,text,text),public.zasp_security_agent_run_detail_v24(text,text,text,text),public.zasp_security_agent_approval_page_v24(text,text,text,text,text,timestamptz,text,integer),public.zasp_security_agent_approval_detail_v24(text,text,text,text),public.zasp_security_agent_decide_approval_v24(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) FROM zasp_security_agent_api;
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_claim_session_policy_effects(text,text,integer,integer),public.zasp_security_agent_heartbeat_session_policy_effect(text,text,text,text,text,text,text,integer),public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea),public.zasp_security_agent_read_session_policy_target(text,text,text,text,text,text,text),public.zasp_security_agent_finish_session_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text) FROM zasp_security_agent_action_worker;

DROP FUNCTION public.zasp_security_agent_decide_approval_v24(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text);
DROP FUNCTION public.zasp_security_agent_approval_detail_v24(text,text,text,text);
DROP FUNCTION public.zasp_security_agent_approval_page_v24(text,text,text,text,text,timestamptz,text,integer);
DROP FUNCTION public.zasp_security_agent_run_detail_v24(text,text,text,text);
DROP FUNCTION public.zasp_security_agent_approval_value_v24(text,text,text,text);
DROP FUNCTION public.zasp_security_agent_finish_session_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text);
DROP FUNCTION public.zasp_security_agent_read_session_policy_target(text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea);
DROP FUNCTION public.zasp_security_agent_heartbeat_session_policy_effect(text,text,text,text,text,text,text,integer);
DROP FUNCTION public.zasp_security_agent_claim_session_policy_effects(text,text,integer,integer);
DROP FUNCTION public.zasp_security_agent_execute_run_v24(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_dispatch_session_isolation_run(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_prepare_run_v24(text,text,text,text,text,text,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_prepare_session_isolation_run(text,text,text,text,text,text,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_run_v24(text,text,text,text,text,text,bigint,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_schedule_triggers_v24(text,integer);
DROP FUNCTION public.zasp_security_agent_schedule_session_isolation_triggers(text,integer);

DO $restore_functions$
DECLARE definition text;restored_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_runtime_gateway_record_event_v23_restore(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz)'::regprocedure) INTO STRICT definition;
  restored_definition:=replace(definition,'zasp_runtime_gateway_record_event_v23_restore','zasp_runtime_gateway_record_event');
  IF restored_definition=definition THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway event restore rejected';END IF;
  EXECUTE restored_definition;

  SELECT pg_get_functiondef('public.zasp_security_agent_execution_control_detail_v23_restore(text,text,text)'::regprocedure) INTO STRICT definition;
  restored_definition:=replace(definition,'zasp_security_agent_execution_control_detail_v23_restore','zasp_security_agent_execution_control_detail');
  IF restored_definition=definition THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution control restore rejected';END IF;
  EXECUTE restored_definition;

  SELECT pg_get_functiondef('public.zasp_security_agent_mutate_execution_control_v23_restore(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)'::regprocedure) INTO STRICT definition;
  restored_definition:=replace(definition,'zasp_security_agent_mutate_execution_control_v23_restore','zasp_security_agent_mutate_execution_control');
  IF restored_definition=definition THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution control mutation restore rejected';END IF;
  EXECUTE restored_definition;
END
$restore_functions$;
DROP FUNCTION public.zasp_runtime_gateway_record_event_v23_restore(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz);
DROP FUNCTION public.zasp_security_agent_execution_control_detail_v23_restore(text,text,text);
DROP FUNCTION public.zasp_security_agent_mutate_execution_control_v23_restore(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text);

DROP INDEX public.zasp_runtime_gateway_events_session_v24_idx;
ALTER TABLE public.zasp_security_agent_definitions DROP CONSTRAINT zasp_security_agent_session_isolation_supervised_check;
ALTER TABLE public.zasp_security_agent_temporary_policy_targets DROP CONSTRAINT zasp_security_agent_temporary_policy_targets_action_key_check;
ALTER TABLE public.zasp_security_agent_temporary_policy_targets ADD CONSTRAINT zasp_security_agent_temporary_policy_targets_action_key_check CHECK(action_key='create_temporary_policy');

DELETE FROM public.zasp_schema_metadata WHERE key='security_agent_session_isolation_fingerprint';
UPDATE public.zasp_schema_metadata SET value='security-agent-connector-revocation-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='security-agent-session-isolation-v1';

DO $product_release_restore$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-session-isolation-v1','security-agent-connector-revocation-v1');
  definition:=replace(definition,'release."version" = 24','release."version" = 23');
  definition:=replace(definition,'release."name" = ''security_agent_session_isolation''','release."name" = ''security_agent_connector_revocation''');
  definition:=replace(definition,'later_release."version" > 24','later_release."version" > 23');
  IF definition=original_definition OR position('security-agent-connector-revocation-v1' IN definition)=0 OR position('release."version" = 23' IN definition)=0 OR position('security_agent_connector_revocation' IN definition)=0 OR position('later_release."version" > 23' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v23 compatibility restore failed';END IF;
  EXECUTE definition;

  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-session-isolation-v1','security-agent-connector-revocation-v1');
  definition:=replace(replace(definition,'release."version"=24','release."version"=23'),'release."version" = 24','release."version" = 23');
  definition:=replace(replace(definition,'release."name"=''security_agent_session_isolation''','release."name"=''security_agent_connector_revocation'''),'release."name" = ''security_agent_session_isolation''','release."name" = ''security_agent_connector_revocation''');
  definition:=replace(replace(definition,'later."version">24','later."version">23'),'later."version" > 24','later."version" > 23');
  IF definition=original_definition OR position('security-agent-connector-revocation-v1' IN definition)=0 OR position('security_agent_connector_revocation' IN definition)=0 OR position('release."version"=23' IN definition)=0 AND position('release."version" = 23' IN definition)=0 OR position('later."version">23' IN definition)=0 AND position('later."version" > 23' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v23 compatibility restore failed';END IF;
  EXECUTE definition;
END
$product_release_restore$;
