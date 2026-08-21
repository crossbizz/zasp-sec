DO $product_release_evolution$ DECLARE definition text;original_definition text;BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'identity-administration-v1','security-agent-controls-v1');
 definition:=replace(definition,'release."version" = 19','release."version" = 20');
 definition:=replace(definition,'release."name" = ''identity_administration''','release."name" = ''security_agent_controls''');
 definition:=replace(definition,'later_release."version" > 19','later_release."version" > 20');
 IF definition=original_definition OR position('security-agent-controls-v1' IN definition)=0 OR position('release."version" = 20' IN definition)=0 OR position('release."name" = ''security_agent_controls''' IN definition)=0 OR position('later_release."version" > 20' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v20 compatibility evolution failed';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'identity-administration-v1','security-agent-controls-v1');
 definition:=replace(replace(definition,'release."version"=19','release."version"=20'),'release."version" = 19','release."version" = 20');
 definition:=replace(replace(definition,'release."name"=''identity_administration''','release."name"=''security_agent_controls'''),'release."name" = ''identity_administration''','release."name" = ''security_agent_controls''');
 definition:=replace(replace(definition,'later."version">19','later."version">20'),'later."version" > 19','later."version" > 20');
 IF definition=original_definition OR position('security-agent-controls-v1' IN definition)=0 OR position('security_agent_controls' IN definition)=0 OR position('release."version"=20' IN definition)=0 AND position('release."version" = 20' IN definition)=0 OR position('later."version">20' IN definition)=0 AND position('later."version" > 20' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v20 compatibility evolution failed';END IF;
 EXECUTE definition;
END $product_release_evolution$;

ALTER TABLE public.zasp_security_agent_request_receipts DROP CONSTRAINT zasp_security_agent_request_receipts_operation_check;
ALTER TABLE public.zasp_security_agent_request_receipts ADD CONSTRAINT zasp_security_agent_request_receipts_operation_check
  CHECK(operation IN('activateSecurityAgent','simulateSecurityAgent','runSecurityAgent','cancelSecurityAgentRun','decideSecurityAgentApproval','setSecurityAgentExecutionControl'));
GRANT SELECT ON TABLE public.zasp_environments TO zasp_discovery_authority;

CREATE FUNCTION public.zasp_security_agent_execution_control_detail(organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $detail$
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

CREATE FUNCTION public.zasp_security_agent_mutate_execution_control(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,target_value text,action_value text,enabled_value boolean,expected_version bigint,fresh_auth_expires_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $mutate$
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

ALTER FUNCTION public.zasp_security_agent_execution_control_detail(text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_execution_control_detail(text,text,text),public.zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text) FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_execution_control_detail(text,text,text),public.zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text) TO zasp_security_agent_api;
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_set_kill_switch(text,text,text,text,boolean,bigint,text,text,text) FROM zasp_security_agent_api;

CREATE FUNCTION public.zasp_security_agent_controls_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $security$
  SELECT (SELECT count(*) FROM pg_roles role_value WHERE role_value.rolname IN('zasp_security_agent_api','zasp_security_agent_worker') AND NOT role_value.rolcanlogin AND NOT role_value.rolinherit AND NOT role_value.rolsuper AND NOT role_value.rolcreatedb AND NOT role_value.rolcreaterole AND NOT role_value.rolreplication AND NOT role_value.rolbypassrls)=2
    AND EXISTS(SELECT 1 FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_request_receipts'::regclass AND constraint_value.conname='zasp_security_agent_request_receipts_operation_check' AND constraint_value.convalidated AND position('setSecurityAgentExecutionControl' IN pg_get_constraintdef(constraint_value.oid,true))>0)
    AND has_table_privilege('zasp_discovery_authority','public.zasp_environments','SELECT') AND NOT has_table_privilege('zasp_security_agent_api','public.zasp_environments','SELECT') AND NOT has_table_privilege('zasp_security_agent_worker','public.zasp_environments','SELECT')
    AND NOT has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_set_kill_switch(text,text,text,text,boolean,bigint,text,text,text)','EXECUTE')
    AND NOT EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_execution_control_detail','zasp_security_agent_mutate_execution_control']) AND (procedure.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure.prosecdef OR NOT COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR NOT has_function_privilege('zasp_security_agent_api',procedure.oid,'EXECUTE') OR has_function_privilege('public',procedure.oid,'EXECUTE') OR has_function_privilege('zasp_security_agent_worker',procedure.oid,'EXECUTE')))
$security$;
ALTER FUNCTION public.zasp_security_agent_controls_security_ready() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_controls_security_ready() FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker;

CREATE FUNCTION public.zasp_security_agent_controls_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
  WITH identities(value) AS (
    SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_set_kill_switch','zasp_security_agent_execution_control_detail','zasp_security_agent_mutate_execution_control','zasp_security_agent_controls_security_ready'])
    UNION ALL
    SELECT concat_ws('|','constraint',constraint_value.conname,constraint_value.convalidated,pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_request_receipts'::regclass AND constraint_value.conname='zasp_security_agent_request_receipts_operation_check'
    UNION ALL
    SELECT concat_ws('|','table','zasp_environments',COALESCE(table_value.relacl::text,'')) FROM pg_class table_value JOIN pg_namespace namespace ON namespace.oid=table_value.relnamespace WHERE namespace.nspname='public' AND table_value.relname='zasp_environments'
  ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_security_agent_controls_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
  SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
    AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=20 AND name='security_agent_controls' AND checksum=expected_checksum)
    AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-controls-v1') AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>20)
    AND zasp_identity_admin_security_ready() AND zasp_security_agent_controls_security_ready()
    AND has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_controls_readiness(text,text)','EXECUTE')
    AND zasp_security_agent_controls_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_security_agent_controls_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_controls_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_controls_live_fingerprint(),public.zasp_security_agent_controls_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_controls_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_security_agent_api,zasp_security_agent_worker;

DO $schema_marker$
BEGIN
  UPDATE public.zasp_schema_metadata SET value='security-agent-controls-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='identity-administration-v1';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent controls schema marker drift';END IF;
END
$schema_marker$;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('security_agent_execution_controls_fingerprint', '3ed37647773abf9c3d3b871e70e627aeb191916062da8881c09e5e867656717a') ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;
