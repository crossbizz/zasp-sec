DO $release_guard$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=21 AND name='security_agent_autonomous_response')
     OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>21)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-autonomous-v1') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent temporary policy release drift';
  END IF;
END
$release_guard$;

DO $product_release_evolution$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-autonomous-v1','security-agent-temporary-policy-v1');
  definition:=replace(definition,'release."version" = 21','release."version" = 22');
  definition:=replace(definition,'release."name" = ''security_agent_autonomous_response''','release."name" = ''security_agent_temporary_policy''');
  definition:=replace(definition,'later_release."version" > 21','later_release."version" > 22');
  IF definition=original_definition OR position('security-agent-temporary-policy-v1' IN definition)=0 OR position('release."version" = 22' IN definition)=0 OR position('release."name" = ''security_agent_temporary_policy''' IN definition)=0 OR position('later_release."version" > 22' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v22 compatibility evolution failed';END IF;
  EXECUTE definition;

  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-autonomous-v1','security-agent-temporary-policy-v1');
  definition:=replace(replace(definition,'release."version"=21','release."version"=22'),'release."version" = 21','release."version" = 22');
  definition:=replace(replace(definition,'release."name"=''security_agent_autonomous_response''','release."name"=''security_agent_temporary_policy'''),'release."name" = ''security_agent_autonomous_response''','release."name" = ''security_agent_temporary_policy''');
  definition:=replace(replace(definition,'later."version">21','later."version">22'),'later."version" > 21','later."version" > 22');
  IF definition=original_definition OR position('security-agent-temporary-policy-v1' IN definition)=0 OR position('security_agent_temporary_policy' IN definition)=0 OR position('release."version"=22' IN definition)=0 AND position('release."version" = 22' IN definition)=0 OR position('later."version">22' IN definition)=0 AND position('later."version" > 22' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v22 compatibility evolution failed';END IF;
  EXECUTE definition;
END
$product_release_evolution$;

DO $role$
DECLARE action_role record;
BEGIN
  SELECT * INTO action_role FROM pg_roles WHERE rolname='zasp_security_agent_action_worker';
  IF NOT FOUND THEN
    CREATE ROLE zasp_security_agent_action_worker NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  ELSIF action_role.rolcanlogin OR action_role.rolinherit OR action_role.rolsuper OR action_role.rolcreatedb OR action_role.rolcreaterole OR action_role.rolreplication OR action_role.rolbypassrls
     OR EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=action_role.oid OR member=action_role.oid) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe security agent action role';
  END IF;
END
$role$;
GRANT zasp_security_agent_action_worker TO zasp_discovery_authority WITH ADMIN OPTION;

CREATE TABLE public.zasp_security_agent_action_principal_bindings(
  principal_name text PRIMARY KEY CHECK(principal_name~'^[a-z][a-z0-9_]{2,62}$'),
  authority_role text NOT NULL DEFAULT 'zasp_security_agent_action_worker' CHECK(authority_role='zasp_security_agent_action_worker'),
  registered_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.zasp_security_agent_temporary_policy_targets(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
  run_id text NOT NULL,step_id text NOT NULL,action_key text NOT NULL DEFAULT 'create_temporary_policy' CHECK(action_key='create_temporary_policy'),phase text NOT NULL CHECK(phase IN('apply','cleanup')),
  device_id text NOT NULL,credential_id text NOT NULL,sequence bigint NOT NULL CHECK(sequence>0),policy_version bigint NOT NULL CHECK(policy_version>0),
  state text NOT NULL DEFAULT 'planned' CHECK(state IN('planned','stored','verified')),
  key_id text CHECK(key_id IS NULL OR key_id~'^[a-z][a-z0-9_-]{7,63}$'),
  issued_at timestamptz,expires_at timestamptz,failure_mode text CHECK(failure_mode IS NULL OR failure_mode IN('open','closed')),
  payload_digest bytea CHECK(payload_digest IS NULL OR octet_length(payload_digest)=32),policies jsonb CHECK(policies IS NULL OR jsonb_typeof(policies)='array' AND jsonb_array_length(policies)<=100),
  signature bytea CHECK(signature IS NULL OR octet_length(signature)=64),envelope_digest bytea CHECK(envelope_digest IS NULL OR octet_length(envelope_digest)=32),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),stored_at timestamptz,verified_at timestamptz,
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id),
  UNIQUE(organization_id,workspace_id,environment_id,device_id,sequence),
  FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id,action_key) REFERENCES public.zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key),
  FOREIGN KEY(organization_id,workspace_id,environment_id,device_id,credential_id) REFERENCES public.zasp_gateway_credentials(organization_id,workspace_id,environment_id,device_id,id),
  CHECK((state='planned' AND key_id IS NULL AND issued_at IS NULL AND expires_at IS NULL AND failure_mode IS NULL AND payload_digest IS NULL AND policies IS NULL AND signature IS NULL AND envelope_digest IS NULL AND stored_at IS NULL AND verified_at IS NULL)
     OR (state IN('stored','verified') AND key_id IS NOT NULL AND issued_at IS NOT NULL AND expires_at>issued_at AND failure_mode IS NOT NULL AND payload_digest IS NOT NULL AND policies IS NOT NULL AND signature IS NOT NULL AND envelope_digest IS NOT NULL AND stored_at IS NOT NULL)),
  CHECK(verified_at IS NULL OR state='verified')
);

ALTER TABLE public.zasp_security_agent_action_principal_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_temporary_policy_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_action_principal_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_temporary_policy_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_security_agent_action_principal_bindings_authority ON public.zasp_security_agent_action_principal_bindings FOR ALL TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_security_agent_temporary_policy_targets_authority ON public.zasp_security_agent_temporary_policy_targets FOR ALL TO zasp_discovery_authority USING(true) WITH CHECK(true);
ALTER TABLE public.zasp_security_agent_action_principal_bindings OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_security_agent_temporary_policy_targets OWNER TO zasp_discovery_authority;
REVOKE ALL ON TABLE public.zasp_security_agent_action_principal_bindings,public.zasp_security_agent_temporary_policy_targets FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_gateway_control;

ALTER TABLE public.zasp_security_agent_definitions ADD CONSTRAINT zasp_security_agent_temporary_policy_supervised_check
  CHECK(NOT (body->'allowed_actions' ? 'create_temporary_policy') OR activation<>'autonomous' AND body->>'autonomy'<>'autonomous');

CREATE OR REPLACE FUNCTION public.zasp_security_agent_execution_control_detail(organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $detail$
DECLARE global_row zasp_security_agent_kill_switches%ROWTYPE;environment_row zasp_security_agent_kill_switches%ROWTYPE;temporary_row zasp_security_agent_kill_switches%ROWTYPE;finding_row zasp_security_agent_kill_switches%ROWTYPE;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent execution control detail rejected';END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_environments environment WHERE (environment.organization_id,environment.workspace_id,environment.id)=(organization_value,workspace_value,environment_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent execution control scope not found';END IF;
  SELECT * INTO STRICT global_row FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*');
  SELECT * INTO environment_row FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=(organization_value,workspace_value,environment_value,'*');
  SELECT * INTO temporary_row FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=(organization_value,workspace_value,environment_value,'create_temporary_policy');
  SELECT * INTO finding_row FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=(organization_value,workspace_value,environment_value,'update_finding_response');
  RETURN jsonb_build_object(
    'global',jsonb_build_object('target','global','action_key','*','enabled',global_row.execution_enabled,'version',global_row.version),
    'environment',jsonb_build_object('target','environment','action_key','*','enabled',COALESCE(environment_row.execution_enabled,false),'version',COALESCE(environment_row.version,0)),
    'actions',jsonb_build_array(
      jsonb_build_object('target','action','action_key','create_temporary_policy','enabled',COALESCE(temporary_row.execution_enabled,false),'version',COALESCE(temporary_row.version,0)),
      jsonb_build_object('target','action','action_key','update_finding_response','enabled',COALESCE(finding_row.execution_enabled,false),'version',COALESCE(finding_row.version,0)))
  );
END
$detail$;

CREATE OR REPLACE FUNCTION public.zasp_security_agent_mutate_execution_control(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,target_value text,action_value text,enabled_value boolean,expected_version bigint,fresh_auth_expires_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $mutate$
DECLARE row_organization text;row_workspace text;row_environment text;row_action text;intent_value jsonb;intent_digest_value bytea;receipt_row zasp_security_agent_request_receipts%ROWTYPE;result_value jsonb;response_value jsonb;resource_value text;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(receipt_value)
     OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' OR target_value NOT IN('environment','action') OR expected_version<0
     OR fresh_auth_expires_value IS NULL OR fresh_auth_expires_value<=transaction_timestamp() OR fresh_auth_expires_value>transaction_timestamp()+interval '5 minutes 5 seconds'
     OR (target_value='action' AND action_value NOT IN('create_temporary_policy','update_finding_response')) OR (target_value<>'action' AND action_value<>'*') THEN
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
REVOKE ALL ON FUNCTION public.zasp_security_agent_execution_control_detail(text,text,text),public.zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text) FROM PUBLIC,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_execution_control_detail(text,text,text),public.zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text) TO zasp_security_agent_api;

CREATE FUNCTION public.zasp_security_agent_action_principal_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $ready$
  SELECT EXISTS(SELECT 1 FROM zasp_security_agent_action_principal_bindings binding JOIN pg_roles principal ON principal.rolname=binding.principal_name
    WHERE binding.principal_name=session_user AND binding.authority_role='zasp_security_agent_action_worker' AND principal.rolcanlogin AND principal.rolinherit
      AND NOT principal.rolsuper AND NOT principal.rolcreatedb AND NOT principal.rolcreaterole AND NOT principal.rolreplication AND NOT principal.rolbypassrls)
    AND pg_has_role(session_user,'zasp_security_agent_action_worker','MEMBER')
    AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND NOT pg_has_role(session_user,'zasp_security_agent_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_gateway_control','MEMBER')
$ready$;

CREATE FUNCTION public.zasp_security_agent_register_action_principal(migration_principal text,action_principal text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $register$
DECLARE principal record;
BEGIN
  IF migration_principal<>session_user OR action_principal=migration_principal OR action_principal!~'^[a-z][a-z0-9_]{2,62}$' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid security agent action principal';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('zasp-security-agent-action-principal-registration',0));
  SELECT * INTO principal FROM pg_roles WHERE rolname=action_principal;
  IF NOT FOUND OR NOT principal.rolcanlogin OR NOT principal.rolinherit OR principal.rolsuper OR principal.rolcreatedb OR principal.rolcreaterole OR principal.rolreplication OR principal.rolbypassrls
     OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=principal.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>'zasp_security_agent_action_worker') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe security agent action principal';
  END IF;
  EXECUTE format('GRANT zasp_security_agent_action_worker TO %I',action_principal);
  INSERT INTO zasp_security_agent_action_principal_bindings(principal_name) VALUES(action_principal)
  ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role WHERE zasp_security_agent_action_principal_bindings.authority_role=excluded.authority_role;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent action principal conflict';END IF;
  RETURN true;
END
$register$;

CREATE FUNCTION public.zasp_security_agent_schedule_temporary_policy_triggers(worker_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $schedule$
DECLARE candidate record;trigger_digest_value bytea;run_value text;audit_value text;correlation_value text;created_value integer:=0;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR length(worker_value) NOT BETWEEN 1 AND 128 OR limit_value NOT BETWEEN 1 AND 25 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy scheduling rejected';END IF;
  FOR candidate IN
    WITH eligible AS (
      SELECT definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version AS definition_version,(definition.body->>'concurrency_limit')::integer AS concurrency_limit,
        finding.id AS trigger_id,finding.version AS trigger_version,finding.updated_at,row_number() OVER(PARTITION BY definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id ORDER BY finding.updated_at,finding.id) AS definition_ordinal
      FROM zasp_security_agent_definitions definition JOIN zasp_risk_findings finding ON (finding.organization_id,finding.workspace_id,finding.environment_id)=(definition.organization_id,definition.workspace_id,definition.environment_id)
      WHERE definition.activation='supervised' AND definition.deleted_at IS NULL AND definition.body->>'enabled'='true' AND definition.body->>'trigger_kind'='finding' AND definition.body->'environment_ids' ? definition.environment_id
        AND COALESCE(finding.rule,finding.source)=definition.body->>'trigger_source' AND finding.status='open' AND definition.body->'allowed_actions'=jsonb_build_array('create_temporary_policy') AND definition.body->>'verification_kind'='policy_state'
        AND (definition.body->>'temporary_policy_seconds')::integer BETWEEN 60 AND 3600
        AND EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=('*','*','*','*',true))
        AND EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=(definition.organization_id,definition.workspace_id,definition.environment_id,'*',true))
        AND EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=(definition.organization_id,definition.workspace_id,definition.environment_id,'create_temporary_policy',true))
        AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_trigger_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.definition_id,receipt.trigger_id,receipt.trigger_version)=(definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,finding.id,finding.version))
        AND (SELECT count(*) FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.definition_id)=(definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id) AND run.state IN('queued','planning','waiting_approval','running','verifying','contained'))<(definition.body->>'concurrency_limit')::integer
    ) SELECT * FROM eligible WHERE definition_ordinal=1 ORDER BY updated_at,organization_id,workspace_id,environment_id,definition_id,trigger_id LIMIT limit_value
  LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id,'temporary-policy-trigger'),0));
    CONTINUE WHEN EXISTS(SELECT 1 FROM zasp_security_agent_trigger_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.definition_id,receipt.trigger_id,receipt.trigger_version)=(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id,candidate.trigger_id,candidate.trigger_version));
    CONTINUE WHEN (SELECT count(*) FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.definition_id)=(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id) AND run.state IN('queued','planning','waiting_approval','running','verifying','contained'))>=candidate.concurrency_limit;
    trigger_digest_value:=digest(convert_to(jsonb_build_object('kind','finding','id',candidate.trigger_id,'version',candidate.trigger_version)::text,'UTF8'),'sha256');
    run_value:=zasp_discovery_canonical_id(candidate.organization_id,candidate.workspace_id,candidate.environment_id,'security_agent_run',candidate.definition_id||chr(31)||candidate.trigger_id||chr(31)||candidate.trigger_version::text);
    INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) VALUES(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id,candidate.trigger_id,'finding',candidate.trigger_version,trigger_digest_value,run_value) ON CONFLICT DO NOTHING;
    CONTINUE WHEN NOT FOUND;
    INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES(candidate.organization_id,candidate.workspace_id,candidate.environment_id,run_value,candidate.definition_id,candidate.definition_version,candidate.trigger_id,worker_value,'queued');
    audit_value:=zasp_discovery_canonical_id(candidate.organization_id,candidate.workspace_id,candidate.environment_id,'security_agent_audit',run_value||chr(31)||'temporary-policy-trigger');
    correlation_value:=zasp_discovery_canonical_id(candidate.organization_id,candidate.workspace_id,candidate.environment_id,'security_agent_correlation',run_value||chr(31)||'temporary-policy-trigger');
    INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES(candidate.organization_id,candidate.workspace_id,candidate.environment_id,audit_value,correlation_value,run_value,worker_value,'run_queued',trigger_digest_value,jsonb_build_object('run_id',run_value,'definition_id',candidate.definition_id,'definition_version',candidate.definition_version,'trigger_kind','finding','trigger_id',candidate.trigger_id,'trigger_version',candidate.trigger_version,'automatic',true,'action','create_temporary_policy'));
    created_value:=created_value+1;
  END LOOP;
  IF created_value>0 THEN UPDATE zasp_security_agent_execution_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;END IF;
  RETURN jsonb_build_object('created',created_value);
END
$schedule$;

CREATE FUNCTION public.zasp_security_agent_schedule_triggers_v22(worker_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $schedule_all$
DECLARE temporary_result jsonb;finding_result jsonb;temporary_limit integer;temporary_created integer;finding_created integer:=0;
BEGIN
  IF limit_value NOT BETWEEN 1 AND 25 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent scheduling rejected';END IF;
  temporary_limit:=greatest(1,(limit_value+1)/2);
  temporary_result:=zasp_security_agent_schedule_temporary_policy_triggers(worker_value,temporary_limit);
  temporary_created:=(temporary_result->>'created')::integer;
  IF temporary_created<limit_value THEN finding_result:=zasp_security_agent_schedule_triggers_v21(worker_value,limit_value-temporary_created);finding_created:=(finding_result->>'created')::integer;END IF;
  RETURN jsonb_build_object('created',temporary_created+finding_created);
END
$schedule_all$;

CREATE FUNCTION public.zasp_security_agent_claim_runs_v22(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim_runs$
DECLARE result_value jsonb;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 30 AND 300 OR claim_limit NOT BETWEEN 1 AND 25 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent claim rejected';END IF;
  UPDATE zasp_security_agent_runs run SET state='queued',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,available_at=transaction_timestamp(),last_error_code='lease_expired' WHERE run.state IN('planning','running','verifying') AND run.lease_expires_at<=transaction_timestamp();
  WITH selected AS (
    SELECT run.ctid FROM zasp_security_agent_runs run WHERE run.state='queued' AND run.available_at<=transaction_timestamp() ORDER BY run.available_at,run.organization_id,run.workspace_id,run.environment_id,run.run_id LIMIT claim_limit FOR UPDATE SKIP LOCKED
  ), claimed AS (
    UPDATE zasp_security_agent_runs run SET state='planning',attempt=run.attempt+1,lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),version=run.version+1,updated_at=transaction_timestamp() FROM selected WHERE run.ctid=selected.ctid RETURNING run.*
  ) SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('organization_id',claimed.organization_id,'workspace_id',claimed.workspace_id,'environment_id',claimed.environment_id,'run_id',claimed.run_id,'definition_id',claimed.definition_id,'definition_version',claimed.definition_version,'trigger_id',claimed.trigger_id,'state',claimed.state,'version',claimed.version,'attempt',claimed.attempt,'lease_expires_at',to_char(claimed.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'prepared',EXISTS(SELECT 1 FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=(claimed.organization_id,claimed.workspace_id,claimed.environment_id,claimed.run_id))) ORDER BY claimed.organization_id,claimed.workspace_id,claimed.environment_id,claimed.run_id),'[]'::jsonb)) INTO result_value FROM claimed;
  RETURN result_value;
END
$claim_runs$;

CREATE FUNCTION public.zasp_security_agent_prepare_temporary_policy_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text,approval_value text,approval_expires_value timestamptz,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $prepare$
DECLARE run_row zasp_security_agent_runs%ROWTYPE;definition_row zasp_security_agent_definitions%ROWTYPE;trigger_row zasp_security_agent_trigger_receipts%ROWTYPE;finding_version bigint;step_value text;plan_value jsonb;plan_digest bytea;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(approval_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR approval_expires_value<=transaction_timestamp() OR approval_expires_value>transaction_timestamp()+interval '16 minutes' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy plan rejected';END IF;
  SELECT * INTO run_row FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state,run.lease_owner,run.lease_token)=(organization_value,workspace_value,environment_value,run_value,'planning',worker_value,lease_token_value) AND run.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent lease lost';END IF;
  SELECT * INTO STRICT definition_row FROM zasp_security_agent_definitions definition WHERE (definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version)=(organization_value,workspace_value,environment_value,run_row.definition_id,run_row.definition_version) AND definition.activation='supervised' AND definition.deleted_at IS NULL AND definition.body->'allowed_actions'=jsonb_build_array('create_temporary_policy') AND definition.body->>'verification_kind'='policy_state' AND (definition.body->>'temporary_policy_seconds')::integer BETWEEN 60 AND 3600 FOR SHARE;
  SELECT * INTO STRICT trigger_row FROM zasp_security_agent_trigger_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.run_id,receipt.trigger_kind)=(organization_value,workspace_value,environment_value,run_value,'finding');
  SELECT finding.version INTO finding_version FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id,finding.status)=(organization_value,workspace_value,environment_value,trigger_row.trigger_id,'open') FOR SHARE;
  IF NOT FOUND OR finding_version<>trigger_row.trigger_version THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent evidence changed';END IF;
  step_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'security_agent_step',run_value||chr(31)||'0');
  plan_value:=jsonb_build_object('definition_id',run_row.definition_id,'definition_version',run_row.definition_version,'catalog_version','security-agent-actions-v1','evidence_ids',jsonb_build_array(trigger_row.trigger_id),'steps',jsonb_build_array(jsonb_build_object('index',0,'step_id',step_value,'action','create_temporary_policy','target_id',environment_value,'mode','block','scope',environment_value,'ttl_seconds',(definition_row.body->>'temporary_policy_seconds')::integer,'authorization','approval_required')),'verification',jsonb_build_object('kind','policy_state','expected_state','active'),'expires_at',to_char(approval_expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  plan_digest:=digest(convert_to(plan_value::text,'UTF8'),'sha256');
  INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at) VALUES(organization_value,workspace_value,environment_value,run_value,run_row.definition_id,run_row.definition_version,trigger_row.trigger_digest,'security-agent-actions-v1',plan_value,plan_digest,approval_expires_value);
  INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) VALUES(organization_value,workspace_value,environment_value,run_value,step_value,0,'create_temporary_policy',digest(convert_to((plan_value->'steps'->0)::text,'UTF8'),'sha256'),'approval_required','waiting_approval');
  INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at) VALUES(organization_value,workspace_value,environment_value,approval_value,run_value,step_value,plan_digest,'pending',run_row.requested_by,approval_expires_value);
  UPDATE zasp_security_agent_runs run SET state='waiting_approval',plan_hash=plan_digest,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=run.version+1,updated_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body) VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,step_value,approval_value,worker_value,'approval_requested',plan_digest,jsonb_build_object('run_id',run_value,'step_id',step_value,'action','create_temporary_policy','approval_id',approval_value,'plan_hash','sha256:'||encode(plan_digest,'hex')));
  RETURN jsonb_build_object('run_id',run_value,'state','waiting_approval','version',run_row.version+1,'approval_id',approval_value,'step_id',step_value,'plan_hash','sha256:'||encode(plan_digest,'hex'));
END
$prepare$;

CREATE FUNCTION public.zasp_security_agent_dispatch_temporary_policy_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $dispatch$
DECLARE run_row zasp_security_agent_runs%ROWTYPE;plan_row zasp_security_agent_plans%ROWTYPE;step_row zasp_security_agent_steps%ROWTYPE;outcome_value text;result_digest_value bytea;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy dispatch rejected';END IF;
  SELECT * INTO run_row FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state,run.lease_owner,run.lease_token)=(organization_value,workspace_value,environment_value,run_value,'planning',worker_value,lease_token_value) AND run.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent lease lost';END IF;
  SELECT * INTO STRICT plan_row FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id,plan.plan_hash)=(organization_value,workspace_value,environment_value,run_value,run_row.plan_hash) AND plan.expires_at>transaction_timestamp() FOR SHARE;
  SELECT * INTO STRICT step_row FROM zasp_security_agent_steps step WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.action_key,step.state,step.authorization_result)=(organization_value,workspace_value,environment_value,run_value,'create_temporary_policy','authorized','approval_required') FOR UPDATE;
  PERFORM 1 FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id,approval.step_id,approval.state,approval.plan_hash)=(organization_value,workspace_value,environment_value,run_value,step_row.step_id,'approved',run_row.plan_hash) AND approval.expires_at>transaction_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='temporary policy approval missing';END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=('*','*','*','*',true)) OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=(organization_value,workspace_value,environment_value,'*',true)) OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=(organization_value,workspace_value,environment_value,'create_temporary_policy',true)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent execution disabled';END IF;
  INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state) VALUES(organization_value,workspace_value,environment_value,run_value,step_row.step_id,'create_temporary_policy',step_row.input_digest,'pending');
  UPDATE zasp_security_agent_steps step SET state='executing',version=step.version+1,updated_at=transaction_timestamp() WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.step_id)=(organization_value,workspace_value,environment_value,run_value,step_row.step_id);
  UPDATE zasp_security_agent_runs run SET state='running',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=run.version+1,updated_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  outcome_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'security_agent_effect',run_value||chr(31)||step_row.step_id||chr(31)||'create_temporary_policy');
  result_digest_value:=digest(convert_to(jsonb_build_object('run_id',run_value,'step_id',step_row.step_id,'action','create_temporary_policy','state','pending')::text,'UTF8'),'sha256');
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,step_row.step_id,worker_value,'effect_dispatched',result_digest_value,jsonb_build_object('run_id',run_value,'step_id',step_row.step_id,'action','create_temporary_policy','outcome_id',outcome_value));
  RETURN jsonb_build_object('run_id',run_value,'state','running','version',run_row.version+1,'step_id',step_row.step_id,'effect_state','pending','outcome_id',outcome_value,'result_digest','sha256:'||encode(result_digest_value,'hex'));
END
$dispatch$;

CREATE FUNCTION public.zasp_security_agent_prepare_run_v22(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text,approval_value text,approval_expires_value timestamptz,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $prepare_all$
DECLARE action_value text;
BEGIN
  SELECT definition.body->'allowed_actions'->>0 INTO action_value FROM zasp_security_agent_runs run JOIN zasp_security_agent_definitions definition ON (definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version)=(run.organization_id,run.workspace_id,run.environment_id,run.definition_id,run.definition_version) WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  IF action_value='create_temporary_policy' THEN RETURN zasp_security_agent_prepare_temporary_policy_run(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value,approval_value,approval_expires_value,audit_value,correlation_value);END IF;
  IF action_value='update_finding_response' THEN RETURN zasp_security_agent_prepare_run_v21(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value,approval_value,approval_expires_value,audit_value,correlation_value);END IF;
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent action rejected';
END
$prepare_all$;

CREATE FUNCTION public.zasp_security_agent_execute_run_v22(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $execute_all$
DECLARE action_value text;
BEGIN
  SELECT step.action_key INTO action_value FROM zasp_security_agent_steps step WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id)=(organization_value,workspace_value,environment_value,run_value);
  IF action_value='create_temporary_policy' THEN RETURN zasp_security_agent_dispatch_temporary_policy_run(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value,audit_value,correlation_value);END IF;
  IF action_value='update_finding_response' THEN RETURN zasp_security_agent_execute_run_v21(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value,audit_value,correlation_value);END IF;
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent action rejected';
END
$execute_all$;

CREATE FUNCTION public.zasp_security_agent_claim_temporary_policy_effects(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE item record;device_row record;target_row record;items jsonb:='[]'::jsonb;targets jsonb;phase_value text;ttl_seconds integer;sequence_value bigint;policy_version_value bigint;no_target_result bytea;no_target_outcome text;no_target_audit text;no_target_correlation text;
BEGIN
  IF NOT zasp_security_agent_action_principal_ready() OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 30 AND 300 OR claim_limit NOT BETWEEN 1 AND 25 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy claim rejected';
  END IF;
  UPDATE zasp_security_agent_effects effect SET state=CASE WHEN EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase,target.state)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,'apply','verified')) THEN 'cleanup_pending' ELSE 'pending' END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp()
  WHERE effect.action_key='create_temporary_policy' AND effect.state='leased' AND effect.lease_expires_at<=transaction_timestamp();
  FOR item IN SELECT effect.* FROM zasp_security_agent_effects effect WHERE effect.action_key='create_temporary_policy' AND effect.state='cleanup_pending' AND effect.updated_at<=transaction_timestamp()
    AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets applied JOIN zasp_gateway_devices device ON (device.organization_id,device.workspace_id,device.environment_id,device.id,device.state)=(applied.organization_id,applied.workspace_id,applied.environment_id,applied.device_id,'active') JOIN zasp_gateway_credentials credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id)=(device.organization_id,device.workspace_id,device.environment_id,device.id)
      WHERE (applied.organization_id,applied.workspace_id,applied.environment_id,applied.run_id,applied.step_id,applied.phase,applied.state)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,'apply','verified') AND credential.revoked_at IS NULL AND credential.expires_at>transaction_timestamp())
    ORDER BY effect.updated_at,effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id LIMIT claim_limit FOR UPDATE SKIP LOCKED
  LOOP
    no_target_result:=digest(item.input_digest,'sha256');
    no_target_outcome:=zasp_discovery_canonical_id(item.organization_id,item.workspace_id,item.environment_id,'security_agent_effect',item.run_id||chr(31)||item.step_id||chr(31)||'cleanup');
    no_target_audit:=zasp_discovery_canonical_id(item.organization_id,item.workspace_id,item.environment_id,'security_agent_audit',item.run_id||chr(31)||item.step_id||chr(31)||'cleanup-no-active-target');
    no_target_correlation:=zasp_discovery_canonical_id(item.organization_id,item.workspace_id,item.environment_id,'security_agent_correlation',item.run_id||chr(31)||item.step_id||chr(31)||'cleanup-no-active-target');
    UPDATE zasp_security_agent_effects effect SET state='cleaned',outcome_id=no_target_outcome,result_digest=no_target_result,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=effect.version+1,updated_at=transaction_timestamp() WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key,effect.state)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id,'create_temporary_policy','cleanup_pending');
    UPDATE zasp_security_agent_runs run SET state='remediated',version=run.version+1,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id,'contained');
    INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(item.organization_id,item.workspace_id,item.environment_id,no_target_audit,no_target_correlation,item.run_id,item.step_id,worker_value,'effect_cleaned',no_target_result,jsonb_build_object('run_id',item.run_id,'step_id',item.step_id,'action','create_temporary_policy','phase','cleanup','outcome_id',no_target_outcome,'result_digest','sha256:'||encode(no_target_result,'hex'),'reason','no_active_gateway_target')) ON CONFLICT DO NOTHING;
  END LOOP;
  FOR item IN
    WITH selected AS (
      SELECT effect.ctid,effect.state AS prior_state FROM zasp_security_agent_effects effect
      WHERE effect.action_key='create_temporary_policy' AND (effect.state='pending' OR effect.state='cleanup_pending' AND effect.updated_at<=transaction_timestamp())
        AND (effect.state='cleanup_pending' OR (
          EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=('*','*','*','*',true))
          AND EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=(effect.organization_id,effect.workspace_id,effect.environment_id,'*',true))
          AND EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=(effect.organization_id,effect.workspace_id,effect.environment_id,'create_temporary_policy',true))))
        AND EXISTS(SELECT 1 FROM zasp_gateway_devices device JOIN zasp_gateway_credentials credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id)=(device.organization_id,device.workspace_id,device.environment_id,device.id)
          WHERE (device.organization_id,device.workspace_id,device.environment_id,device.state)=(effect.organization_id,effect.workspace_id,effect.environment_id,'active') AND credential.revoked_at IS NULL AND credential.expires_at>transaction_timestamp())
      ORDER BY effect.updated_at,effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id LIMIT claim_limit FOR UPDATE SKIP LOCKED
    ), claimed AS (
      UPDATE zasp_security_agent_effects effect SET state='leased',lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),attempt=effect.attempt+1,version=effect.version+1,updated_at=transaction_timestamp()
      FROM selected WHERE effect.ctid=selected.ctid RETURNING effect.*,selected.prior_state
    ) SELECT * FROM claimed
  LOOP
    phase_value:=CASE item.prior_state WHEN 'cleanup_pending' THEN 'cleanup' ELSE 'apply' END;
    SELECT COALESCE((plan.plan->'steps'->0->>'ttl_seconds')::integer,300) INTO ttl_seconds FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id);
    IF ttl_seconds NOT BETWEEN 60 AND 3600 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy ttl rejected';END IF;
    FOR device_row IN
      SELECT device.id AS device_id,credential.id AS credential_id
      FROM zasp_gateway_devices device JOIN LATERAL (
        SELECT credential.id FROM zasp_gateway_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id)=(device.organization_id,device.workspace_id,device.environment_id,device.id) AND credential.revoked_at IS NULL AND credential.expires_at>transaction_timestamp() ORDER BY credential.issued_at DESC,credential.id DESC LIMIT 1
      ) credential ON true
      WHERE (device.organization_id,device.workspace_id,device.environment_id,device.state)=(item.organization_id,item.workspace_id,item.environment_id,'active')
        AND (phase_value='apply' OR EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets applied WHERE (applied.organization_id,applied.workspace_id,applied.environment_id,applied.run_id,applied.step_id,applied.phase,applied.device_id,applied.state)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id,'apply',device.id,'verified')))
      ORDER BY device.id
    LOOP
      PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),item.organization_id,item.workspace_id,item.environment_id,device_row.device_id,'temporary-policy-sequence'),0));
      SELECT COALESCE(max(bundle.sequence)+1,1),COALESCE(max(bundle.policy_version)+1,1) INTO sequence_value,policy_version_value FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id)=(item.organization_id,item.workspace_id,item.environment_id,device_row.device_id);
      INSERT INTO zasp_security_agent_temporary_policy_targets(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id,credential_id,sequence,policy_version)
      VALUES(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id,phase_value,device_row.device_id,device_row.credential_id,sequence_value,policy_version_value)
      ON CONFLICT(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id) DO UPDATE
      SET credential_id=excluded.credential_id,sequence=excluded.sequence,policy_version=excluded.policy_version,state='planned',key_id=NULL,issued_at=NULL,expires_at=NULL,failure_mode=NULL,payload_digest=NULL,policies=NULL,signature=NULL,envelope_digest=NULL,stored_at=NULL,verified_at=NULL
      WHERE zasp_security_agent_temporary_policy_targets.state='planned' OR zasp_security_agent_temporary_policy_targets.credential_id<>excluded.credential_id;
    END LOOP;
    targets:='[]'::jsonb;
    FOR target_row IN SELECT * FROM zasp_security_agent_temporary_policy_targets value WHERE (value.organization_id,value.workspace_id,value.environment_id,value.run_id,value.step_id,value.phase)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id,phase_value) ORDER BY value.device_id LOOP
      targets:=targets||jsonb_build_array(jsonb_build_object('device_id',target_row.device_id,'credential_id',target_row.credential_id,'sequence',target_row.sequence,'policy_version',target_row.policy_version));
    END LOOP;
    items:=items||jsonb_build_array(jsonb_build_object('organization_id',item.organization_id,'workspace_id',item.workspace_id,'environment_id',item.environment_id,'run_id',item.run_id,'step_id',item.step_id,'phase',phase_value,'input_digest','sha256:'||encode(item.input_digest,'hex'),'ttl_seconds',ttl_seconds,'lease_expires_at',to_char(item.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'targets',targets));
  END LOOP;
  RETURN jsonb_build_object('items',items);
END
$claim$;

CREATE FUNCTION public.zasp_security_agent_heartbeat_temporary_policy_effect(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,worker_value text,lease_token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
DECLARE expires_value timestamptz;
BEGIN
  IF NOT zasp_security_agent_action_principal_ready() OR lease_seconds NOT BETWEEN 30 AND 300 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy heartbeat rejected';END IF;
  UPDATE zasp_security_agent_effects effect SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp()
  WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key,effect.state,effect.lease_owner,effect.lease_token)=(organization_value,workspace_value,environment_value,run_value,step_value,'create_temporary_policy','leased',worker_value,lease_token_value) AND effect.lease_expires_at>transaction_timestamp()
  RETURNING effect.lease_expires_at INTO expires_value;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='temporary policy lease lost';END IF;
  RETURN jsonb_build_object('lease_expires_at',to_char(expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END
$heartbeat$;

CREATE FUNCTION public.zasp_security_agent_store_temporary_policy_target(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,phase_value text,worker_value text,lease_token_value text,device_value text,credential_value text,sequence_value bigint,policy_version_value bigint,key_value text,issued_value timestamptz,expires_value timestamptz,failure_mode_value text,payload_digest_value bytea,policies_value jsonb,signature_value bytea,envelope_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $store$
DECLARE target_row zasp_security_agent_temporary_policy_targets%ROWTYPE;ttl_seconds integer;
BEGIN
  IF NOT zasp_security_agent_action_principal_ready() OR phase_value NOT IN('apply','cleanup') OR octet_length(payload_digest_value)<>32 OR octet_length(signature_value)<>64 OR octet_length(envelope_digest_value)<>32 OR jsonb_typeof(policies_value)<>'array' OR jsonb_array_length(policies_value)>100 OR (phase_value='cleanup' AND policies_value<>'[]'::jsonb) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy target rejected';
  END IF;
  PERFORM 1 FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key,effect.state,effect.lease_owner,effect.lease_token)=(organization_value,workspace_value,environment_value,run_value,step_value,'create_temporary_policy','leased',worker_value,lease_token_value) AND effect.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='temporary policy lease lost';END IF;
  SELECT (plan.plan->'steps'->0->>'ttl_seconds')::integer INTO STRICT ttl_seconds FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=(organization_value,workspace_value,environment_value,run_value);
  IF ttl_seconds NOT BETWEEN 60 AND 3600 OR failure_mode_value<>'closed' OR phase_value='apply' AND expires_value<>issued_value+make_interval(secs=>ttl_seconds) OR phase_value='cleanup' AND expires_value<>issued_value+interval '5 minutes' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy target rejected';
  END IF;
  IF phase_value='apply' AND (NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=('*','*','*','*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'create_temporary_policy',true))) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='temporary policy execution disabled';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_gateway_devices device WHERE (device.organization_id,device.workspace_id,device.environment_id,device.id,device.state)=(organization_value,workspace_value,environment_value,device_value,'active'))
     OR credential_value IS DISTINCT FROM (SELECT credential.id FROM zasp_gateway_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id)=(organization_value,workspace_value,environment_value,device_value) AND credential.revoked_at IS NULL AND credential.expires_at>transaction_timestamp() ORDER BY credential.issued_at DESC,credential.id DESC LIMIT 1) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='temporary policy credential changed';
  END IF;
  SELECT * INTO target_row FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase,target.device_id,target.credential_id,target.sequence,target.policy_version)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value,device_value,credential_value,sequence_value,policy_version_value) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='temporary policy target missing';END IF;
  IF target_row.state<>'planned' THEN
    IF (target_row.key_id,target_row.issued_at,target_row.expires_at,target_row.failure_mode,target_row.payload_digest,target_row.policies,target_row.signature,target_row.envelope_digest) IS DISTINCT FROM (key_value,issued_value,expires_value,failure_mode_value,payload_digest_value,policies_value,signature_value,envelope_digest_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='temporary policy target replay conflict';END IF;
  ELSE
    INSERT INTO zasp_runtime_gateway_policy_bundles(organization_id,workspace_id,environment_id,device_id,credential_id,sequence,policy_version,key_id,algorithm,audience,issued_at,expires_at,failure_mode,payload_digest,policies,signature,envelope_digest)
    VALUES(organization_value,workspace_value,environment_value,device_value,credential_value,sequence_value,policy_version_value,key_value,'Ed25519','runtime-gateway-policy',issued_value,expires_value,failure_mode_value,payload_digest_value,policies_value,signature_value,envelope_digest_value)
    ON CONFLICT(organization_id,workspace_id,environment_id,device_id,sequence) DO NOTHING;
    IF NOT FOUND AND NOT EXISTS(SELECT 1 FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id,bundle.credential_id,bundle.sequence,bundle.policy_version,bundle.key_id,bundle.issued_at,bundle.expires_at,bundle.failure_mode,bundle.payload_digest,bundle.policies,bundle.signature,bundle.envelope_digest)=(organization_value,workspace_value,environment_value,device_value,credential_value,sequence_value,policy_version_value,key_value,issued_value,expires_value,failure_mode_value,payload_digest_value,policies_value,signature_value,envelope_digest_value)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='temporary policy bundle conflict';END IF;
    UPDATE zasp_security_agent_temporary_policy_targets target SET state='stored',key_id=key_value,issued_at=issued_value,expires_at=expires_value,failure_mode=failure_mode_value,payload_digest=payload_digest_value,policies=policies_value,signature=signature_value,envelope_digest=envelope_digest_value,stored_at=transaction_timestamp()
    WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase,target.device_id)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value,device_value);
  END IF;
  RETURN jsonb_build_object('device_id',device_value,'phase',phase_value,'sequence',sequence_value,'policy_version',policy_version_value,'envelope_digest','sha256:'||encode(envelope_digest_value,'hex'));
END
$store$;

CREATE FUNCTION public.zasp_security_agent_read_temporary_policy_target(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,phase_value text,device_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $read$
DECLARE result_value jsonb;
BEGIN
  IF NOT zasp_security_agent_action_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='temporary policy target denied';END IF;
  SELECT jsonb_build_object('device_id',target.device_id,'credential_id',target.credential_id,'phase',target.phase,'state',target.state,'sequence',target.sequence,'policy_version',target.policy_version,'key_id',target.key_id,'issued_at',to_char(target.issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char(target.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'failure_mode',target.failure_mode,'payload_digest','sha256:'||encode(target.payload_digest,'hex'),'policies',target.policies,'signature',encode(target.signature,'base64'),'envelope_digest','sha256:'||encode(target.envelope_digest,'hex')) INTO result_value
  FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase,target.device_id)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value,device_value) AND target.state IN('stored','verified');
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='temporary policy target missing';END IF;
  RETURN result_value;
END
$read$;

CREATE OR REPLACE FUNCTION public.zasp_runtime_gateway_policy_bundle(credential_value text,after_sequence_value bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $gateway_policy$
DECLARE authority_value jsonb;bundle_value zasp_runtime_gateway_policy_bundles%ROWTYPE;
BEGIN
 IF after_sequence_value<0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway policy rejected';END IF;
 authority_value:=zasp_runtime_gateway_credential_authority(credential_value,'runtime-gateway');
 SELECT * INTO bundle_value FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id)=(authority_value->>'organization_id',authority_value->>'workspace_id',authority_value->>'environment_id',authority_value->>'device_id') AND bundle.sequence>after_sequence_value ORDER BY bundle.sequence DESC LIMIT 1;
 IF NOT FOUND THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('contract_version',bundle_value.contract_version,'key_id',bundle_value.key_id,'algorithm',bundle_value.algorithm,'audience',bundle_value.audience,'organization_id',bundle_value.organization_id,'workspace_id',bundle_value.workspace_id,'environment_id',bundle_value.environment_id,'device_id',bundle_value.device_id,'credential_id',bundle_value.credential_id,'sequence',bundle_value.sequence,'policy_version',bundle_value.policy_version,'issued_at',to_char(bundle_value.issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char(bundle_value.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'failure_mode',bundle_value.failure_mode,'payload_digest',encode(bundle_value.payload_digest,'hex'),'policies',bundle_value.policies,'signature',replace(translate(rtrim(encode(bundle_value.signature,'base64'),'='),'+/','-_'),chr(10),''));
END
$gateway_policy$;

CREATE FUNCTION public.zasp_security_agent_finish_temporary_policy_effect(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,phase_value text,worker_value text,lease_token_value text,result_digest_value bytea,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $finish$
DECLARE effect_row zasp_security_agent_effects%ROWTYPE;outcome_value text;expires_value timestamptz;expected_digest bytea;
BEGIN
  IF NOT zasp_security_agent_action_principal_ready() OR phase_value NOT IN('apply','cleanup') OR octet_length(result_digest_value)<>32 OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy finish rejected';END IF;
  SELECT * INTO effect_row FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key,effect.state,effect.lease_owner,effect.lease_token)=(organization_value,workspace_value,environment_value,run_value,step_value,'create_temporary_policy','leased',worker_value,lease_token_value) AND effect.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='temporary policy lease lost';END IF;
  IF phase_value='apply' AND (NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=('*','*','*','*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'create_temporary_policy',true))) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='temporary policy execution disabled';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value))
     OR EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value) AND target.state<>'stored') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='temporary policy verification incomplete';END IF;
  IF EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value)
    AND (NOT EXISTS(SELECT 1 FROM zasp_gateway_devices device WHERE (device.organization_id,device.workspace_id,device.environment_id,device.id,device.state)=(target.organization_id,target.workspace_id,target.environment_id,target.device_id,'active'))
      OR target.credential_id IS DISTINCT FROM (SELECT credential.id FROM zasp_gateway_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id)=(target.organization_id,target.workspace_id,target.environment_id,target.device_id) AND credential.revoked_at IS NULL AND credential.expires_at>transaction_timestamp() ORDER BY credential.issued_at DESC,credential.id DESC LIMIT 1))) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='temporary policy credential changed';
  END IF;
  SELECT digest(effect_row.input_digest||decode(string_agg(encode(target.envelope_digest,'hex'),'' ORDER BY target.device_id),'hex'),'sha256') INTO STRICT expected_digest FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase,target.state)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value,'stored');
  IF expected_digest IS DISTINCT FROM result_digest_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy result rejected';END IF;
  UPDATE zasp_security_agent_temporary_policy_targets target SET state='verified',verified_at=transaction_timestamp() WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value);
  outcome_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'security_agent_effect',run_value||chr(31)||step_value||chr(31)||phase_value);
  IF phase_value='apply' THEN
    SELECT max(target.expires_at) INTO STRICT expires_value FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase)=(organization_value,workspace_value,environment_value,run_value,step_value,'apply');
    UPDATE zasp_security_agent_effects effect SET state='cleanup_pending',outcome_id=outcome_value,result_digest=result_digest_value,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=effect.version+1,updated_at=expires_value WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key)=(organization_value,workspace_value,environment_value,run_value,step_value,'create_temporary_policy');
    UPDATE zasp_security_agent_steps step SET state='succeeded',version=step.version+1,updated_at=transaction_timestamp() WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.step_id)=(organization_value,workspace_value,environment_value,run_value,step_value);
    UPDATE zasp_security_agent_runs run SET state='contained',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=run.version+1,updated_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  ELSE
    UPDATE zasp_security_agent_effects effect SET state='cleaned',outcome_id=outcome_value,result_digest=result_digest_value,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=effect.version+1,updated_at=transaction_timestamp() WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key)=(organization_value,workspace_value,environment_value,run_value,step_value,'create_temporary_policy');
    UPDATE zasp_security_agent_runs run SET state='remediated',version=run.version+1,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  END IF;
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,step_value,worker_value,CASE phase_value WHEN 'apply' THEN 'effect_verified' ELSE 'effect_cleaned' END,result_digest_value,jsonb_build_object('run_id',run_value,'step_id',step_value,'action','create_temporary_policy','phase',phase_value,'outcome_id',outcome_value,'result_digest','sha256:'||encode(result_digest_value,'hex')));
  RETURN jsonb_build_object('run_id',run_value,'step_id',step_value,'phase',phase_value,'effect_state',CASE phase_value WHEN 'apply' THEN 'cleanup_pending' ELSE 'cleaned' END,'outcome_id',outcome_value,'result_digest','sha256:'||encode(result_digest_value,'hex'));
END
$finish$;

CREATE FUNCTION public.zasp_security_agent_approval_value_v22(organization_value text,workspace_value text,environment_value text,approval_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $approval_value$
DECLARE approval_row zasp_security_agent_approvals%ROWTYPE;run_row zasp_security_agent_runs%ROWTYPE;step_row zasp_security_agent_steps%ROWTYPE;plan_row zasp_security_agent_plans%ROWTYPE;expected_effect_value text;ttl_seconds_value integer;
BEGIN
  SELECT * INTO STRICT approval_row FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.approval_id)=(organization_value,workspace_value,environment_value,approval_value);
  SELECT * INTO STRICT run_row FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,approval_row.run_id);
  SELECT * INTO STRICT step_row FROM zasp_security_agent_steps step WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.step_id)=(organization_value,workspace_value,environment_value,approval_row.run_id,approval_row.step_id);
  SELECT * INTO STRICT plan_row FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id,plan.plan_hash)=(organization_value,workspace_value,environment_value,approval_row.run_id,approval_row.plan_hash);
  IF step_row.action_key='update_finding_response' THEN expected_effect_value:='Move finding to under review';ttl_seconds_value:=0;
  ELSIF step_row.action_key='create_temporary_policy' THEN
    expected_effect_value:='Apply temporary containment policy';
    SELECT (item->>'ttl_seconds')::integer INTO STRICT ttl_seconds_value FROM jsonb_array_elements(plan_row.plan->'steps') item WHERE item->>'step_id'=approval_row.step_id AND item->>'action'='create_temporary_policy';
    IF ttl_seconds_value NOT BETWEEN 60 AND 3600 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent approval ttl rejected';END IF;
  ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent approval effect rejected';END IF;
  RETURN jsonb_build_object('id',approval_row.approval_id,'run_id',approval_row.run_id,'step_id',approval_row.step_id,'state',approval_row.state,'expires_at',to_char(approval_row.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'version',approval_row.version,'expected_effect',expected_effect_value,'reversible',true,'ttl_seconds',ttl_seconds_value,'evidence_summary',jsonb_build_array(run_row.trigger_id));
END
$approval_value$;

CREATE FUNCTION public.zasp_security_agent_run_detail_v22(organization_value text,workspace_value text,environment_value text,run_value text) RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $run_detail$
  SELECT detail.value||jsonb_build_object('approvals',COALESCE((SELECT jsonb_agg(zasp_security_agent_approval_value_v22(approval.organization_id,approval.workspace_id,approval.environment_id,approval.approval_id) ORDER BY approval.created_at,approval.approval_id) FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id)=(organization_value,workspace_value,environment_value,run_value)),'[]'::jsonb))
  FROM zasp_security_agent_run_detail(organization_value,workspace_value,environment_value,run_value) detail(value)
$run_detail$;

CREATE FUNCTION public.zasp_security_agent_approval_page_v22(organization_value text,workspace_value text,environment_value text,state_value text,run_value text,before_created_value timestamptz,before_id_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $approval_page$
DECLARE page_value jsonb;items_value jsonb;
BEGIN
  page_value:=zasp_security_agent_approval_page(organization_value,workspace_value,environment_value,state_value,run_value,before_created_value,before_id_value,limit_value);
  SELECT COALESCE(jsonb_agg(zasp_security_agent_approval_value_v22(organization_value,workspace_value,environment_value,item.value->>'id') ORDER BY item.ordinality),'[]'::jsonb) INTO items_value FROM jsonb_array_elements(page_value->'items') WITH ORDINALITY item(value,ordinality);
  RETURN jsonb_set(page_value,'{items}',items_value,false);
END
$approval_page$;

CREATE FUNCTION public.zasp_security_agent_approval_detail_v22(organization_value text,workspace_value text,environment_value text,approval_value text) RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $approval_detail$
  SELECT zasp_security_agent_approval_value_v22(organization_value,workspace_value,environment_value,approval_value)
  WHERE EXISTS(SELECT 1 FROM zasp_security_agent_approval_detail(organization_value,workspace_value,environment_value,approval_value))
$approval_detail$;

CREATE FUNCTION public.zasp_security_agent_decide_approval_v22(organization_value text,workspace_value text,environment_value text,approval_value text,actor_value text,idempotency_value text,expected_version bigint,decision_value text,fresh_auth_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $decide$
DECLARE response_value jsonb;
BEGIN
  response_value:=zasp_security_agent_decide_approval(organization_value,workspace_value,environment_value,approval_value,actor_value,idempotency_value,expected_version,decision_value,fresh_auth_value,audit_value,correlation_value,receipt_value);
  RETURN response_value||zasp_security_agent_approval_value_v22(organization_value,workspace_value,environment_value,approval_value);
END
$decide$;

DO $functions$
DECLARE procedure_oid oid;
BEGIN
  FOR procedure_oid IN SELECT procedure.oid FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_action_principal_ready','zasp_security_agent_register_action_principal','zasp_security_agent_schedule_temporary_policy_triggers','zasp_security_agent_schedule_triggers_v22','zasp_security_agent_claim_runs_v22','zasp_security_agent_prepare_temporary_policy_run','zasp_security_agent_prepare_run_v22','zasp_security_agent_dispatch_temporary_policy_run','zasp_security_agent_execute_run_v22','zasp_security_agent_claim_temporary_policy_effects','zasp_security_agent_heartbeat_temporary_policy_effect','zasp_security_agent_store_temporary_policy_target','zasp_security_agent_read_temporary_policy_target','zasp_security_agent_finish_temporary_policy_effect','zasp_security_agent_approval_value_v22','zasp_security_agent_run_detail_v22','zasp_security_agent_approval_page_v22','zasp_security_agent_approval_detail_v22','zasp_security_agent_decide_approval_v22']) LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_gateway_control',procedure_oid::regprocedure);
  END LOOP;
END
$functions$;
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_run_detail(text,text,text,text),public.zasp_security_agent_approval_page(text,text,text,text,text,timestamptz,text,integer),public.zasp_security_agent_approval_detail(text,text,text,text),public.zasp_security_agent_decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) FROM zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_run_detail_v22(text,text,text,text),public.zasp_security_agent_approval_page_v22(text,text,text,text,text,timestamptz,text,integer),public.zasp_security_agent_approval_detail_v22(text,text,text,text),public.zasp_security_agent_decide_approval_v22(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_schedule_triggers_v22(text,integer),public.zasp_security_agent_claim_runs_v22(text,text,integer,integer),public.zasp_security_agent_prepare_run_v22(text,text,text,text,text,text,text,timestamptz,text,text),public.zasp_security_agent_execute_run_v22(text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_action_principal_ready(),public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer),public.zasp_security_agent_heartbeat_temporary_policy_effect(text,text,text,text,text,text,text,integer),public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea),public.zasp_security_agent_read_temporary_policy_target(text,text,text,text,text,text,text),public.zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text) TO zasp_security_agent_action_worker;

CREATE FUNCTION public.zasp_security_agent_temporary_policy_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $security$
  SELECT zasp_security_agent_autonomous_security_ready()
	AND EXISTS(SELECT 1 FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_definitions'::regclass AND constraint_value.conname='zasp_security_agent_temporary_policy_supervised_check' AND constraint_value.convalidated)
    AND NOT EXISTS(SELECT 1 FROM pg_roles role WHERE role.rolname='zasp_security_agent_action_worker' AND (role.rolcanlogin OR role.rolinherit OR role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR role.rolreplication OR role.rolbypassrls))
    AND NOT has_function_privilege('zasp_security_agent_worker','public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)','EXECUTE')
    AND NOT has_function_privilege('zasp_gateway_control','public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)','EXECUTE')
    AND has_function_privilege('zasp_security_agent_worker','public.zasp_security_agent_schedule_triggers_v22(text,integer)','EXECUTE')
    AND has_function_privilege('zasp_security_agent_worker','public.zasp_security_agent_prepare_run_v22(text,text,text,text,text,text,text,timestamptz,text,text)','EXECUTE')
    AND has_function_privilege('zasp_security_agent_worker','public.zasp_security_agent_execute_run_v22(text,text,text,text,text,text,text,text)','EXECUTE')
    AND has_function_privilege('zasp_gateway_control','public.zasp_runtime_gateway_policy_bundle(text,bigint)','EXECUTE')
	AND has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_execution_control_detail(text,text,text)','EXECUTE')
	AND has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)','EXECUTE')
	AND has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_run_detail_v22(text,text,text,text)','EXECUTE')
	AND has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_approval_page_v22(text,text,text,text,text,timestamptz,text,integer)','EXECUTE')
	AND has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_approval_detail_v22(text,text,text,text)','EXECUTE')
	AND has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_decide_approval_v22(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)','EXECUTE')
	AND NOT has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_run_detail(text,text,text,text)','EXECUTE')
	AND NOT has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_approval_page(text,text,text,text,text,timestamptz,text,integer)','EXECUTE')
	AND NOT has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_approval_detail(text,text,text,text)','EXECUTE')
	AND NOT has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)','EXECUTE')
	AND NOT has_function_privilege('zasp_security_agent_action_worker','public.zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)','EXECUTE')
    AND NOT has_function_privilege('zasp_security_agent_action_worker','public.zasp_runtime_gateway_policy_bundle(text,bigint)','EXECUTE')
    AND NOT has_function_privilege('zasp_security_agent_action_worker','public.zasp_runtime_gateway_put_policy_bundle(text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea)','EXECUTE')
$security$;

CREATE FUNCTION public.zasp_security_agent_temporary_policy_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
  WITH identities(value) AS (
    SELECT concat_ws('|','table',class.relname,owner.rolname,class.relrowsecurity,class.relforcerowsecurity,COALESCE(class.relacl::text,'')) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_security_agent_action_principal_bindings','zasp_security_agent_temporary_policy_targets']) AND class.relkind IN('r','i')
    UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_action_principal_ready','zasp_security_agent_register_action_principal','zasp_security_agent_execution_control_detail','zasp_security_agent_mutate_execution_control','zasp_security_agent_schedule_temporary_policy_triggers','zasp_security_agent_schedule_triggers_v22','zasp_security_agent_claim_runs_v22','zasp_security_agent_prepare_temporary_policy_run','zasp_security_agent_prepare_run_v22','zasp_security_agent_dispatch_temporary_policy_run','zasp_security_agent_execute_run_v22','zasp_security_agent_claim_temporary_policy_effects','zasp_security_agent_heartbeat_temporary_policy_effect','zasp_security_agent_store_temporary_policy_target','zasp_security_agent_read_temporary_policy_target','zasp_security_agent_finish_temporary_policy_effect','zasp_security_agent_approval_value_v22','zasp_security_agent_run_detail_v22','zasp_security_agent_approval_page_v22','zasp_security_agent_approval_detail_v22','zasp_security_agent_decide_approval_v22','zasp_security_agent_temporary_policy_security_ready','zasp_runtime_gateway_policy_bundle','zasp_workflow_mutate','zasp_risk_mutate'])
	UNION ALL SELECT concat_ws('|','constraint',constraint_value.conname,constraint_value.convalidated,pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_definitions'::regclass AND constraint_value.conname='zasp_security_agent_temporary_policy_supervised_check'
  ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_security_agent_temporary_policy_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
  SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
    AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=22 AND name='security_agent_temporary_policy' AND checksum=expected_checksum)
    AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-temporary-policy-v1') AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>22)
    AND zasp_security_agent_temporary_policy_security_ready() AND zasp_security_agent_temporary_policy_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_security_agent_temporary_policy_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_temporary_policy_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_temporary_policy_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_temporary_policy_security_ready(),public.zasp_security_agent_temporary_policy_live_fingerprint(),public.zasp_security_agent_temporary_policy_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_temporary_policy_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

UPDATE public.zasp_schema_metadata SET value='security-agent-temporary-policy-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='security-agent-autonomous-v1';
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('security_agent_temporary_policy_fingerprint', '93401d5f12b682d2b3ead34f80a430711a4266f0b61018c3a0e712bb549cac25') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
