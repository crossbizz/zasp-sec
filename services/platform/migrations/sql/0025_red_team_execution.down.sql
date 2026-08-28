DO $rollback_guard$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='red-team-execution-v1') OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>25) OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='red_team_execution_fingerprint' AND value='bb848d5c9936143cc9251dd44410de037a382b1190e1d04069df18b0a38f669a') OR NOT public.zasp_red_team_execution_security_ready() OR public.zasp_red_team_execution_live_fingerprint()<>'bb848d5c9936143cc9251dd44410de037a382b1190e1d04069df18b0a38f669a' OR EXISTS(SELECT 1 FROM public.zasp_red_team_definitions) OR EXISTS(SELECT 1 FROM public.zasp_red_team_runs) OR EXISTS(SELECT 1 FROM public.zasp_red_team_outbox) OR EXISTS(SELECT 1 FROM public.zasp_red_team_request_receipts) OR EXISTS(SELECT 1 FROM public.zasp_red_team_audit) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team execution rollback rejected';END IF;
END
$rollback_guard$;

DROP FUNCTION public.zasp_red_team_target_adapter_readiness(text,text);
DROP FUNCTION public.zasp_red_team_execution_readiness(text,text);
DROP FUNCTION public.zasp_red_team_execution_live_fingerprint();
DROP FUNCTION public.zasp_red_team_execution_security_ready();
DROP FUNCTION public.zasp_red_team_cancel_claimed_run(text,text,text,text,text,bytea,bytea);
DROP FUNCTION public.zasp_red_team_retry_run(text,text,text,text,text,bytea,bytea,text,timestamptz);
DROP FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint);
DROP FUNCTION public.zasp_red_team_heartbeat_run(text,text,text,text,text,bytea,integer);
DROP FUNCTION public.zasp_red_team_claim_run(text,text,text,text,text,bytea,integer);
DROP FUNCTION public.zasp_red_team_retry_outbox(text,text,text,text,text,bytea,timestamptz);
DROP FUNCTION public.zasp_red_team_ack_outbox(text,text,text,text,text,bytea,text);
DROP FUNCTION public.zasp_red_team_heartbeat_outbox(text,text,text,text,text,bytea,integer);
DROP FUNCTION public.zasp_red_team_claim_outbox(text,bytea,integer,integer);
DROP FUNCTION public.zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text);
DROP FUNCTION public.zasp_red_team_get_run(text,text,text,text);
DROP FUNCTION public.zasp_red_team_list_runs(text,text,text,timestamptz,text,integer);
DROP FUNCTION public.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text);
DROP FUNCTION public.zasp_red_team_update_definition(text,text,text,text,text,text,bigint,text,text,text,jsonb,jsonb,boolean,text);
DROP FUNCTION public.zasp_red_team_create_definition(text,text,text,text,text,text,text,text,text,jsonb,jsonb,text);
DROP FUNCTION public.zasp_red_team_get_definition(text,text,text,text);
DROP FUNCTION public.zasp_red_team_list_definitions(text,text,text,text,integer);
DROP FUNCTION public.zasp_red_team_run_json(public.zasp_red_team_runs);
DROP FUNCTION public.zasp_red_team_definition_json(public.zasp_red_team_definitions);
DROP FUNCTION public.zasp_red_team_mutation_result(text,text,text,text,text,text,text,text,jsonb);
DROP FUNCTION public.zasp_red_team_resolve_target(text,text,text,text,text);
DROP FUNCTION public.zasp_red_team_target_valid(text,text,text,text,text);
DROP FUNCTION public.zasp_red_team_target_binding_valid(jsonb,text);
DROP FUNCTION public.zasp_red_team_definition_valid(text,text,text,jsonb,jsonb);
DROP FUNCTION public.zasp_red_team_principals_ready();
DROP FUNCTION public.zasp_red_team_principal_ready(text);
DO $principal_cleanup$
DECLARE binding record;
BEGIN
 EXECUTE 'REVOKE zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter FROM zasp_discovery_authority CASCADE';
 FOR binding IN SELECT principal_name,authority_role FROM public.zasp_red_team_principal_bindings LOOP
   EXECUTE format('REVOKE %I FROM %I',binding.authority_role,binding.principal_name);
 END LOOP;
END
$principal_cleanup$;
DROP FUNCTION public.zasp_red_team_register_principals(text,text,text,text);
DROP TABLE public.zasp_red_team_audit;
DROP TABLE public.zasp_red_team_request_receipts;
DROP TABLE public.zasp_red_team_outbox;
DROP TABLE public.zasp_red_team_attempts;
DROP TABLE public.zasp_red_team_runs;
DROP TABLE public.zasp_red_team_definitions;
DROP TABLE public.zasp_red_team_principal_bindings;
DELETE FROM public.zasp_schema_metadata WHERE key='red_team_execution_fingerprint';
UPDATE public.zasp_schema_metadata SET value='security-agent-session-isolation-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='red-team-execution-v1';

CREATE OR REPLACE FUNCTION public.zasp_effective_scope_permissions(requested_permissions jsonb,requested_role text) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $permissions$
 SELECT CASE requested_role
  WHEN 'organization_admin' THEN '["investigate_sessions","manage_api_tokens","manage_data_controls","manage_findings","manage_identity","manage_workflows","revoke_sessions","view","view_audit","view_compliance"]'::jsonb
  WHEN 'security_admin' THEN '["investigate_sessions","manage_api_tokens","manage_data_controls","manage_findings","manage_identity","manage_workflows","revoke_sessions","view","view_audit","view_compliance"]'::jsonb
  WHEN 'security_engineer' THEN '["investigate_sessions","manage_findings","manage_workflows","view"]'::jsonb
  WHEN 'developer_owner' THEN '["investigate_sessions","view"]'::jsonb
  WHEN 'compliance_viewer' THEN '["view","view_audit","view_compliance"]'::jsonb
  WHEN 'read_only_viewer' THEN '["view"]'::jsonb
  ELSE '[]'::jsonb END
$permissions$;

DO $prior_permissions_owner_restore$
DECLARE prior_owner text;
BEGIN
 SELECT marker.value INTO prior_owner
 FROM public.zasp_schema_metadata marker
 JOIN pg_roles role_value ON role_value.rolname=marker.value
 WHERE marker.key='red_team_execution_prior_permissions_owner' AND role_value.rolcanlogin
   AND (marker.value=session_user OR EXISTS(SELECT 1 FROM zasp_discovery_principal_bindings binding WHERE binding.principal_name=marker.value AND binding.authority_role='zasp_discovery_authority'));
 IF prior_owner IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='inherited permissions owner unavailable';END IF;
 EXECUTE format('ALTER FUNCTION public.zasp_effective_scope_permissions(jsonb,text) OWNER TO %I',prior_owner);
 REVOKE ALL ON FUNCTION public.zasp_effective_scope_permissions(jsonb,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_authority;
 GRANT EXECUTE ON FUNCTION public.zasp_effective_scope_permissions(jsonb,text) TO PUBLIC,zasp_discovery_api;
END
$prior_permissions_owner_restore$;
DELETE FROM public.zasp_schema_metadata WHERE key='red_team_execution_prior_permissions_owner';

CREATE OR REPLACE FUNCTION public.zasp_security_agent_session_isolation_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=24 AND name='security_agent_session_isolation' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-session-isolation-v1') AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>24) AND zasp_security_agent_session_isolation_security_ready() AND zasp_security_agent_session_isolation_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_security_agent_session_isolation_readiness(text,text) OWNER TO zasp_discovery_authority;

DO $product_release_restore$
DECLARE definition text;original_definition text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'red-team-execution-v1','security-agent-session-isolation-v1');definition:=replace(definition,'release."version" = 25','release."version" = 24');definition:=replace(definition,'release."name" = ''red_team_execution''','release."name" = ''security_agent_session_isolation''');definition:=replace(definition,'later_release."version" > 25','later_release."version" > 24');IF definition=original_definition OR position('security-agent-session-isolation-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v24 compatibility restore failed';END IF;EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'red-team-execution-v1','security-agent-session-isolation-v1');definition:=replace(replace(definition,'release."version"=25','release."version"=24'),'release."version" = 25','release."version" = 24');definition:=replace(replace(definition,'release."name"=''red_team_execution''','release."name"=''security_agent_session_isolation'''),'release."name" = ''red_team_execution''','release."name" = ''security_agent_session_isolation''');definition:=replace(replace(definition,'later."version">25','later."version">24'),'later."version" > 25','later."version" > 24');IF definition=original_definition OR position('security-agent-session-isolation-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v24 compatibility restore failed';END IF;EXECUTE definition;
END
$product_release_restore$;
