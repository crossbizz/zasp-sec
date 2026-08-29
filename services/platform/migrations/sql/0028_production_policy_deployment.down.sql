DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>28)
     OR NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='production-recovery-v1')
     OR NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_policy_deployment_fingerprint' AND value='9e1b9c6ca6764465b6208efd779e7ca197fd4fad84a71dab78b8a3925693b9e8')
     OR NOT zasp_policy_deployment_execution_security_ready() OR zasp_policy_deployment_execution_live_fingerprint()<>'9e1b9c6ca6764465b6208efd779e7ca197fd4fad84a71dab78b8a3925693b9e8' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='policy deployment rollback rejected';END IF;
  IF EXISTS(SELECT 1 FROM zasp_policy_deployment_work WHERE state='leased' OR applied_generation>0) OR EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets WHERE desired_generation IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='policy deployment rollback unsafe';END IF;
END
$guard$;

DROP TRIGGER zasp_workflow_records_policy_deployment ON public.zasp_workflow_records;
DROP TRIGGER zasp_gateway_devices_policy_deployment ON public.zasp_gateway_devices;
DROP TRIGGER zasp_gateway_credentials_policy_deployment ON public.zasp_gateway_credentials;
DROP TRIGGER zasp_security_agent_targets_policy_sequence ON public.zasp_security_agent_temporary_policy_targets;
DROP TRIGGER zasp_security_agent_targets_policy_verify ON public.zasp_security_agent_temporary_policy_targets;

REVOKE ALL ON FUNCTION public.zasp_recovery_execution_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_recovery_worker,zasp_recovery_outbox_worker,zasp_discovery_worker,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter,zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy;
DROP FUNCTION public.zasp_recovery_execution_readiness(text,text);
ALTER FUNCTION public.zasp_recovery_execution_readiness_v27(text,text) RENAME TO zasp_recovery_execution_readiness;
GRANT EXECUTE ON FUNCTION public.zasp_recovery_execution_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_api,zasp_recovery_worker,zasp_recovery_outbox_worker,zasp_discovery_worker,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter,zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy;

DROP FUNCTION public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea);
DROP FUNCTION public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea);
DROP FUNCTION public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea);
ALTER FUNCTION public.zasp_security_agent_store_temporary_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea) RENAME TO zasp_security_agent_store_temporary_policy_target;
ALTER FUNCTION public.zasp_security_agent_store_session_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea) RENAME TO zasp_security_agent_store_session_policy_target;
ALTER TABLE public.zasp_security_agent_temporary_policy_targets DROP COLUMN desired_generation;

REVOKE ALL ON FUNCTION public.zasp_policy_deployment_execution_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_runtime_gateway,zasp_policy_deployment_worker;
DROP FUNCTION public.zasp_policy_deployment_execution_readiness(text,text);
DROP FUNCTION public.zasp_policy_deployment_execution_live_fingerprint();
DROP FUNCTION public.zasp_policy_deployment_execution_security_ready();
DROP FUNCTION public.zasp_security_agent_expire_approvals_v28(text,integer);
DROP FUNCTION public.zasp_policy_deployment_finish(text,text,text,text,bigint,text,text,bytea);
DROP FUNCTION public.zasp_policy_deployment_read(text,text,text,text,bigint);
DROP FUNCTION public.zasp_policy_deployment_store(text,text,text,text,bigint,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea);
DROP FUNCTION public.zasp_policy_deployment_heartbeat(text,text,text,text,bigint,text,text,integer);
DROP FUNCTION public.zasp_policy_deployment_claim(text,text,integer,integer);
DROP FUNCTION public.zasp_policy_deployment_target_verify_guard();
DROP FUNCTION public.zasp_policy_deployment_target_sequence_guard();
DROP FUNCTION public.zasp_policy_deployment_source_trigger();
DROP FUNCTION public.zasp_policy_deployment_enqueue_device(text,text,text,text);
DROP FUNCTION public.zasp_policy_deployment_principal_ready();
DROP FUNCTION public.zasp_policy_deployment_register_principal(text,text);
DO $principals$
DECLARE binding record;
BEGIN
  FOR binding IN SELECT principal_name FROM public.zasp_policy_deployment_principal_bindings LOOP
    EXECUTE format('REVOKE zasp_policy_deployment_worker FROM %I',binding.principal_name);
  END LOOP;
END
$principals$;
DROP TABLE public.zasp_policy_deployment_work;
DROP TABLE public.zasp_policy_deployment_fairness;
DROP TABLE public.zasp_policy_deployment_principal_bindings;
REVOKE zasp_policy_deployment_worker FROM zasp_discovery_authority CASCADE;
DROP ROLE zasp_policy_deployment_worker;

DO $product_release_restore$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;
  definition:=replace(definition,'later_release."version" > 28','later_release."version" > 27');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v27 restore failed';END IF;EXECUTE definition;
  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;
  definition:=replace(replace(definition,'later."version">28','later."version">27'),'later."version" > 28','later."version" > 27');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v27 restore failed';END IF;EXECUTE definition;
END
$product_release_restore$;

DELETE FROM public.zasp_schema_metadata WHERE key='production_policy_deployment_fingerprint';
