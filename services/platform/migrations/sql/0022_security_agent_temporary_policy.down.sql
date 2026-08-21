DO $rollback_guard$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-temporary-policy-v1') OR EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>22)
     OR NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='security_agent_temporary_policy_fingerprint' AND value='93401d5f12b682d2b3ead34f80a430711a4266f0b61018c3a0e712bb549cac25')
     OR zasp_security_agent_temporary_policy_live_fingerprint()<>'93401d5f12b682d2b3ead34f80a430711a4266f0b61018c3a0e712bb549cac25' OR NOT zasp_security_agent_temporary_policy_security_ready()
     OR EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE action_key='create_temporary_policy') OR EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets)
     OR EXISTS(SELECT 1 FROM zasp_security_agent_definitions WHERE body->'allowed_actions' ? 'create_temporary_policy') OR EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE action_key='create_temporary_policy') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent temporary policy rollback rejected';
  END IF;
END
$rollback_guard$;
ALTER TABLE public.zasp_security_agent_definitions DROP CONSTRAINT zasp_security_agent_temporary_policy_supervised_check;
CREATE OR REPLACE FUNCTION public.zasp_security_agent_execution_control_detail(organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $detail$
DECLARE global_row zasp_security_agent_kill_switches%ROWTYPE;environment_row zasp_security_agent_kill_switches%ROWTYPE;action_row zasp_security_agent_kill_switches%ROWTYPE;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent execution control detail rejected';END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_environments environment WHERE (environment.organization_id,environment.workspace_id,environment.id)=(organization_value,workspace_value,environment_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent execution control scope not found';END IF;
  SELECT * INTO STRICT global_row FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*');
  SELECT * INTO environment_row FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=(organization_value,workspace_value,environment_value,'*');
  SELECT * INTO action_row FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=(organization_value,workspace_value,environment_value,'update_finding_response');
  RETURN jsonb_build_object(
    'global',jsonb_build_object('target','global','action_key','*','enabled',global_row.execution_enabled,'version',global_row.version),
    'environment',jsonb_build_object('target','environment','action_key','*','enabled',COALESCE(environment_row.execution_enabled,false),'version',COALESCE(environment_row.version,0)),
    'actions',jsonb_build_array(jsonb_build_object('target','action','action_key','update_finding_response','enabled',COALESCE(action_row.execution_enabled,false),'version',COALESCE(action_row.version,0)))
  );
END
$detail$;

CREATE OR REPLACE FUNCTION public.zasp_security_agent_mutate_execution_control(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,target_value text,action_value text,enabled_value boolean,expected_version bigint,fresh_auth_expires_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $mutate$
DECLARE row_organization text;row_workspace text;row_environment text;row_action text;intent_value jsonb;intent_digest_value bytea;receipt_row zasp_security_agent_request_receipts%ROWTYPE;result_value jsonb;response_value jsonb;resource_value text;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(receipt_value)
     OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' OR target_value NOT IN('environment','action') OR expected_version<0
     OR fresh_auth_expires_value IS NULL OR fresh_auth_expires_value<=transaction_timestamp() OR fresh_auth_expires_value>transaction_timestamp()+interval '5 minutes 5 seconds'
     OR (target_value='action' AND action_value<>'update_finding_response') OR (target_value<>'action' AND action_value<>'*') THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent execution control mutation rejected';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_environments environment WHERE (environment.organization_id,environment.workspace_id,environment.id)=(organization_value,workspace_value,environment_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent execution control scope not found';END IF;
  IF target_value='environment' THEN row_organization:=organization_value;row_workspace:=workspace_value;row_environment:=environment_value;row_action:='*';
  ELSE row_organization:=organization_value;row_workspace:=workspace_value;row_environment:=environment_value;row_action:=action_value;END IF;
  resource_value:=target_value||':'||row_action;
  intent_value:=jsonb_build_object('target',target_value,'action_key',row_action,'enabled',enabled_value,'expected_version',expected_version);
  intent_digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'setSecurityAgentExecutionControl',idempotency_value),0));
  SELECT * INTO receipt_row FROM zasp_security_agent_request_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.principal_id,receipt.operation,receipt.idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'setSecurityAgentExecutionControl',idempotency_value);
  IF FOUND THEN
    IF receipt_row.resource_id<>resource_value OR receipt_row.expected_version<>expected_version OR receipt_row.intent_digest<>intent_digest_value OR receipt_row.expires_at<=transaction_timestamp()
       OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch_row WHERE (switch_row.organization_id,switch_row.workspace_id,switch_row.environment_id,switch_row.action_key,switch_row.execution_enabled,switch_row.version)=(row_organization,row_workspace,row_environment,row_action,enabled_value,(receipt_row.response->>'version')::bigint)) THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent execution control replay conflict';
    END IF;
    RETURN receipt_row.response||jsonb_build_object('replayed',true);
  END IF;
  IF enabled_value AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=('*','*','*','*',true)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent global execution disabled';END IF;
  IF enabled_value AND target_value='action' AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'*',true)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent environment execution disabled';END IF;
  result_value:=zasp_security_agent_set_kill_switch(row_organization,row_workspace,row_environment,row_action,enabled_value,expected_version,actor_value,audit_value,correlation_value);
  response_value:=result_value||jsonb_build_object('target',target_value,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
  INSERT INTO zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id)
  VALUES(organization_value,workspace_value,environment_value,actor_value,'setSecurityAgentExecutionControl',idempotency_value,resource_value,expected_version,intent_value,intent_digest_value,response_value,audit_value,correlation_value,receipt_value);
  RETURN response_value;
END
$mutate$;
CREATE OR REPLACE FUNCTION public.zasp_runtime_gateway_policy_bundle(credential_value text,after_sequence_value bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;bundle_value zasp_runtime_gateway_policy_bundles%ROWTYPE;
BEGIN
 IF after_sequence_value<0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway policy rejected';END IF;
 authority_value:=zasp_runtime_gateway_credential_authority(credential_value,'runtime-gateway');
 SELECT * INTO bundle_value FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id)=(authority_value->>'organization_id',authority_value->>'workspace_id',authority_value->>'environment_id',authority_value->>'device_id') AND bundle.sequence>after_sequence_value ORDER BY bundle.sequence DESC LIMIT 1;
 IF NOT FOUND THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('contract_version',bundle_value.contract_version,'key_id',bundle_value.key_id,'algorithm',bundle_value.algorithm,'audience',bundle_value.audience,'organization_id',bundle_value.organization_id,'workspace_id',bundle_value.workspace_id,'environment_id',bundle_value.environment_id,'device_id',bundle_value.device_id,'credential_id',bundle_value.credential_id,'sequence',bundle_value.sequence,'policy_version',bundle_value.policy_version,'issued_at',to_char(bundle_value.issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char(bundle_value.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'failure_mode',bundle_value.failure_mode,'payload_digest',encode(bundle_value.payload_digest,'hex'),'policies',bundle_value.policies,'signature',translate(rtrim(encode(bundle_value.signature,'base64'),'='),'+/','-_'));
END $$;
DROP FUNCTION public.zasp_security_agent_temporary_policy_readiness(text,text);
DROP FUNCTION public.zasp_security_agent_temporary_policy_live_fingerprint();
DROP FUNCTION public.zasp_security_agent_temporary_policy_security_ready();
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_run_detail_v22(text,text,text,text),public.zasp_security_agent_approval_page_v22(text,text,text,text,text,timestamptz,text,integer),public.zasp_security_agent_approval_detail_v22(text,text,text,text),public.zasp_security_agent_decide_approval_v22(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) FROM zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_run_detail(text,text,text,text),public.zasp_security_agent_approval_page(text,text,text,text,text,timestamptz,text,integer),public.zasp_security_agent_approval_detail(text,text,text,text),public.zasp_security_agent_decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO zasp_security_agent_api;
DROP FUNCTION public.zasp_security_agent_decide_approval_v22(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text);
DROP FUNCTION public.zasp_security_agent_approval_detail_v22(text,text,text,text);
DROP FUNCTION public.zasp_security_agent_approval_page_v22(text,text,text,text,text,timestamptz,text,integer);
DROP FUNCTION public.zasp_security_agent_run_detail_v22(text,text,text,text);
DROP FUNCTION public.zasp_security_agent_approval_value_v22(text,text,text,text);
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_action_principal_ready(),public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer),public.zasp_security_agent_heartbeat_temporary_policy_effect(text,text,text,text,text,text,text,integer),public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea),public.zasp_security_agent_read_temporary_policy_target(text,text,text,text,text,text,text),public.zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text) FROM zasp_security_agent_action_worker;
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_schedule_triggers_v22(text,integer),public.zasp_security_agent_claim_runs_v22(text,text,integer,integer),public.zasp_security_agent_prepare_run_v22(text,text,text,text,text,text,text,timestamptz,text,text),public.zasp_security_agent_execute_run_v22(text,text,text,text,text,text,text,text) FROM zasp_security_agent_worker;
DROP FUNCTION public.zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text);
DROP FUNCTION public.zasp_security_agent_read_temporary_policy_target(text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea);
DROP FUNCTION public.zasp_security_agent_heartbeat_temporary_policy_effect(text,text,text,text,text,text,text,integer);
DROP FUNCTION public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer);
DROP FUNCTION public.zasp_security_agent_execute_run_v22(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_prepare_run_v22(text,text,text,text,text,text,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_dispatch_temporary_policy_run(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_prepare_temporary_policy_run(text,text,text,text,text,text,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_claim_runs_v22(text,text,integer,integer);
DROP FUNCTION public.zasp_security_agent_schedule_triggers_v22(text,integer);
DROP FUNCTION public.zasp_security_agent_schedule_temporary_policy_triggers(text,integer);
DROP FUNCTION public.zasp_security_agent_register_action_principal(text,text);
DROP FUNCTION public.zasp_security_agent_action_principal_ready();
DROP TABLE public.zasp_security_agent_temporary_policy_targets;
DO $principal$
DECLARE principal_value text;
BEGIN
  FOR principal_value IN SELECT principal_name FROM zasp_security_agent_action_principal_bindings LOOP EXECUTE format('REVOKE zasp_security_agent_action_worker FROM %I',principal_value);END LOOP;
END
$principal$;
DROP TABLE public.zasp_security_agent_action_principal_bindings;
REVOKE zasp_security_agent_action_worker FROM zasp_discovery_authority CASCADE;
DROP ROLE zasp_security_agent_action_worker;
DELETE FROM public.zasp_schema_metadata WHERE key='security_agent_temporary_policy_fingerprint';
UPDATE public.zasp_schema_metadata SET value='security-agent-autonomous-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='security-agent-temporary-policy-v1';

DO $product_release_restore$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-temporary-policy-v1','security-agent-autonomous-v1');
  definition:=replace(definition,'release."version" = 22','release."version" = 21');
  definition:=replace(definition,'release."name" = ''security_agent_temporary_policy''','release."name" = ''security_agent_autonomous_response''');
  definition:=replace(definition,'later_release."version" > 22','later_release."version" > 21');
  IF definition=original_definition OR position('security-agent-autonomous-v1' IN definition)=0 OR position('release."version" = 21' IN definition)=0 OR position('release."name" = ''security_agent_autonomous_response''' IN definition)=0 OR position('later_release."version" > 21' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v21 compatibility restore failed';END IF;
  EXECUTE definition;

  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-temporary-policy-v1','security-agent-autonomous-v1');
  definition:=replace(replace(definition,'release."version"=22','release."version"=21'),'release."version" = 22','release."version" = 21');
  definition:=replace(replace(definition,'release."name"=''security_agent_temporary_policy''','release."name"=''security_agent_autonomous_response'''),'release."name" = ''security_agent_temporary_policy''','release."name" = ''security_agent_autonomous_response''');
  definition:=replace(replace(definition,'later."version">22','later."version">21'),'later."version" > 22','later."version" > 21');
  IF definition=original_definition OR position('security-agent-autonomous-v1' IN definition)=0 OR position('security_agent_autonomous_response' IN definition)=0 OR position('release."version"=21' IN definition)=0 AND position('release."version" = 21' IN definition)=0 OR position('later."version">21' IN definition)=0 AND position('later."version" > 21' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v21 compatibility restore failed';END IF;
  EXECUTE definition;
END
$product_release_restore$;
