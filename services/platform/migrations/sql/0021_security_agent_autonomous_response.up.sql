DO $release_guard$
DECLARE checksum_value text;
BEGIN
  SELECT checksum INTO STRICT checksum_value FROM public.zasp_schema_versions WHERE version=20 AND name='security_agent_controls';
  IF NOT public.zasp_security_agent_controls_readiness(checksum_value,'8b228f9e7424846ef07a73d598166ab30c24e5f7e4bd74628a9d208fe41768c8') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent autonomous response prerequisite drift';
  END IF;
END
$release_guard$;

DO $product_release_evolution$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-controls-v1','security-agent-autonomous-v1');
  definition:=replace(definition,'release."version" = 20','release."version" = 21');
  definition:=replace(definition,'release."name" = ''security_agent_controls''','release."name" = ''security_agent_autonomous_response''');
  definition:=replace(definition,'later_release."version" > 20','later_release."version" > 21');
  IF definition=original_definition OR position('security-agent-autonomous-v1' IN definition)=0 OR position('release."version" = 21' IN definition)=0 OR position('release."name" = ''security_agent_autonomous_response''' IN definition)=0 OR position('later_release."version" > 21' IN definition)=0 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v21 compatibility evolution failed';
  END IF;
  EXECUTE definition;

  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'security-agent-controls-v1','security-agent-autonomous-v1');
  definition:=replace(replace(definition,'release."version"=20','release."version"=21'),'release."version" = 20','release."version" = 21');
  definition:=replace(replace(definition,'release."name"=''security_agent_controls''','release."name"=''security_agent_autonomous_response'''),'release."name" = ''security_agent_controls''','release."name" = ''security_agent_autonomous_response''');
  definition:=replace(replace(definition,'later."version">20','later."version">21'),'later."version" > 20','later."version" > 21');
  IF definition=original_definition OR position('security-agent-autonomous-v1' IN definition)=0 OR position('security_agent_autonomous_response' IN definition)=0 OR position('release."version"=21' IN definition)=0 AND position('release."version" = 21' IN definition)=0 OR position('later."version">21' IN definition)=0 AND position('later."version" > 21' IN definition)=0 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v21 compatibility evolution failed';
  END IF;
  EXECUTE definition;
END
$product_release_evolution$;

ALTER TABLE public.zasp_security_agent_steps DROP CONSTRAINT zasp_security_agent_steps_authorization_result_check;
ALTER TABLE public.zasp_security_agent_steps ADD CONSTRAINT zasp_security_agent_steps_authorization_result_check CHECK(authorization_result IN('allow','approval_required','autonomous','deny'));

CREATE FUNCTION public.zasp_security_agent_sync_autonomy_v21() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog, public AS $sync_autonomy$
BEGIN
  NEW.body:=NEW.body||jsonb_build_object('autonomy',CASE WHEN NEW.activation='autonomous' THEN 'autonomous' ELSE 'supervised' END);
  RETURN NEW;
END
$sync_autonomy$;
ALTER FUNCTION public.zasp_security_agent_sync_autonomy_v21() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_sync_autonomy_v21() FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker;
CREATE TRIGGER zasp_security_agent_sync_autonomy_v21 BEFORE UPDATE OF activation ON public.zasp_security_agent_definitions FOR EACH ROW EXECUTE FUNCTION public.zasp_security_agent_sync_autonomy_v21();

CREATE FUNCTION public.zasp_security_agent_schedule_triggers_v21(worker_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $schedule_triggers$
DECLARE candidate record;trigger_digest_value bytea;run_value text;audit_value text;correlation_value text;created_value integer:=0;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR length(worker_value) NOT BETWEEN 1 AND 128 OR limit_value NOT BETWEEN 1 AND 25 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent trigger scheduling rejected';
  END IF;
  FOR candidate IN
    WITH eligible AS (
      SELECT definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version AS definition_version,
             (definition.body->>'concurrency_limit')::integer AS concurrency_limit,finding.id AS trigger_id,finding.version AS trigger_version,
             finding.updated_at,row_number() OVER(PARTITION BY definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id ORDER BY finding.updated_at,finding.id) AS definition_ordinal
      FROM zasp_security_agent_definitions definition
      JOIN zasp_risk_findings finding ON (finding.organization_id,finding.workspace_id,finding.environment_id)=(definition.organization_id,definition.workspace_id,definition.environment_id)
      WHERE definition.activation IN('supervised','autonomous') AND definition.deleted_at IS NULL AND definition.body->>'enabled'='true'
        AND definition.body->>'trigger_kind'='finding' AND definition.body->'environment_ids' ? definition.environment_id
        AND COALESCE(finding.rule,finding.source)=definition.body->>'trigger_source' AND finding.status='open'
        AND definition.body->'allowed_actions'=jsonb_build_array('update_finding_response') AND definition.body->>'verification_kind'='finding_state'
        AND EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=('*','*','*','*',true))
        AND EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=(definition.organization_id,definition.workspace_id,definition.environment_id,'*',true))
        AND EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches switch WHERE (switch.organization_id,switch.workspace_id,switch.environment_id,switch.action_key,switch.execution_enabled)=(definition.organization_id,definition.workspace_id,definition.environment_id,'update_finding_response',true))
        AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_trigger_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.definition_id,receipt.trigger_id,receipt.trigger_version)=(definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,finding.id,finding.version))
        AND (SELECT count(*) FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.definition_id)=(definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id) AND run.state IN('queued','planning','waiting_approval','running','verifying'))<(definition.body->>'concurrency_limit')::integer
    )
    SELECT organization_id,workspace_id,environment_id,definition_id,definition_version,concurrency_limit,trigger_id,trigger_version
    FROM eligible WHERE definition_ordinal=1
    ORDER BY updated_at,organization_id,workspace_id,environment_id,definition_id,trigger_id
    LIMIT limit_value
  LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id,'automatic-trigger'),0));
    CONTINUE WHEN EXISTS(SELECT 1 FROM zasp_security_agent_trigger_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.definition_id,receipt.trigger_id,receipt.trigger_version)=(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id,candidate.trigger_id,candidate.trigger_version));
    CONTINUE WHEN (SELECT count(*) FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.definition_id)=(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id) AND run.state IN('queued','planning','waiting_approval','running','verifying'))>=candidate.concurrency_limit;
    trigger_digest_value:=digest(convert_to(jsonb_build_object('kind','finding','id',candidate.trigger_id,'version',candidate.trigger_version)::text,'UTF8'),'sha256');
    run_value:=zasp_discovery_canonical_id(candidate.organization_id,candidate.workspace_id,candidate.environment_id,'security_agent_run',candidate.definition_id||chr(31)||candidate.trigger_id||chr(31)||candidate.trigger_version::text);
    INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id)
    VALUES(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id,candidate.trigger_id,'finding',candidate.trigger_version,trigger_digest_value,run_value)
    ON CONFLICT DO NOTHING;
    CONTINUE WHEN NOT FOUND;
    INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state)
    VALUES(candidate.organization_id,candidate.workspace_id,candidate.environment_id,run_value,candidate.definition_id,candidate.definition_version,candidate.trigger_id,worker_value,'queued');
    audit_value:=zasp_discovery_canonical_id(candidate.organization_id,candidate.workspace_id,candidate.environment_id,'security_agent_audit',run_value||chr(31)||'automatic-trigger');
    correlation_value:=zasp_discovery_canonical_id(candidate.organization_id,candidate.workspace_id,candidate.environment_id,'security_agent_correlation',run_value||chr(31)||'automatic-trigger');
    INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body)
    VALUES(candidate.organization_id,candidate.workspace_id,candidate.environment_id,audit_value,correlation_value,run_value,worker_value,'run_queued',trigger_digest_value,jsonb_build_object('run_id',run_value,'definition_id',candidate.definition_id,'definition_version',candidate.definition_version,'trigger_kind','finding','trigger_id',candidate.trigger_id,'trigger_version',candidate.trigger_version,'automatic',true));
    created_value:=created_value+1;
  END LOOP;
  IF created_value>0 THEN UPDATE zasp_security_agent_execution_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;END IF;
  RETURN jsonb_build_object('created',created_value);
END
$schedule_triggers$;

CREATE FUNCTION public.zasp_security_agent_prepare_run_v21(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text,approval_value text,approval_expires_value timestamptz,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $prepare$
DECLARE run_row zasp_security_agent_runs%ROWTYPE;definition_row zasp_security_agent_definitions%ROWTYPE;trigger_row zasp_security_agent_trigger_receipts%ROWTYPE;finding_version bigint;step_value text;trigger_digest_value bytea;plan_value jsonb;plan_digest bytea;authorization_value text;run_state_value text;approval_result jsonb;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(approval_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value)
     OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR approval_expires_value<=transaction_timestamp() OR approval_expires_value>transaction_timestamp()+interval '16 minutes' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent plan rejected';
  END IF;
  SELECT * INTO run_row FROM zasp_security_agent_runs run
  WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state,run.lease_owner,run.lease_token)=(organization_value,workspace_value,environment_value,run_value,'planning',worker_value,lease_token_value)
    AND run.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent lease lost';END IF;
  SELECT * INTO STRICT definition_row FROM zasp_security_agent_definitions definition
  WHERE (definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version)=(organization_value,workspace_value,environment_value,run_row.definition_id,run_row.definition_version)
    AND definition.activation IN('supervised','autonomous') AND definition.deleted_at IS NULL AND definition.body->'allowed_actions'=jsonb_build_array('update_finding_response') AND definition.body->>'verification_kind'='finding_state' FOR SHARE;
  SELECT * INTO STRICT trigger_row FROM zasp_security_agent_trigger_receipts trigger_receipt
  WHERE (trigger_receipt.organization_id,trigger_receipt.workspace_id,trigger_receipt.environment_id,trigger_receipt.run_id,trigger_receipt.trigger_kind)=(organization_value,workspace_value,environment_value,run_value,'finding');
  SELECT finding.version INTO finding_version FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id,finding.status)=(organization_value,workspace_value,environment_value,trigger_row.trigger_id,'open') FOR SHARE;
  IF NOT FOUND OR finding_version<>trigger_row.trigger_version THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent evidence changed';END IF;
  authorization_value:=CASE definition_row.activation WHEN 'autonomous' THEN 'autonomous' ELSE 'approval_required' END;
  run_state_value:=CASE definition_row.activation WHEN 'autonomous' THEN 'queued' ELSE 'waiting_approval' END;
  trigger_digest_value:=trigger_row.trigger_digest;
  step_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'security_agent_step',run_value||chr(31)||'0');
  plan_value:=jsonb_build_object('definition_id',run_row.definition_id,'definition_version',run_row.definition_version,'catalog_version','security-agent-actions-v1','evidence_ids',jsonb_build_array(trigger_row.trigger_id),'steps',jsonb_build_array(jsonb_build_object('index',0,'step_id',step_value,'action','update_finding_response','target_id',trigger_row.trigger_id,'expected_version',trigger_row.trigger_version,'target_status','under_review','authorization',authorization_value)),'verification',jsonb_build_object('kind','finding_state','expected_status','under_review'),'expires_at',to_char(approval_expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  plan_digest:=digest(convert_to(plan_value::text,'UTF8'),'sha256');
  INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
  VALUES(organization_value,workspace_value,environment_value,run_value,run_row.definition_id,run_row.definition_version,trigger_digest_value,'security-agent-actions-v1',plan_value,plan_digest,approval_expires_value);
  INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
  VALUES(organization_value,workspace_value,environment_value,run_value,step_value,0,'update_finding_response',digest(convert_to((plan_value->'steps'->0)::text,'UTF8'),'sha256'),authorization_value,CASE definition_row.activation WHEN 'autonomous' THEN 'authorized' ELSE 'waiting_approval' END);
  IF definition_row.activation='supervised' THEN
    INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at)
    VALUES(organization_value,workspace_value,environment_value,approval_value,run_value,step_value,plan_digest,'pending',run_row.requested_by,approval_expires_value);
    approval_result:=to_jsonb(approval_value);
  ELSE
    approval_result:='null'::jsonb;
  END IF;
  UPDATE zasp_security_agent_runs run SET state=run_state_value,plan_hash=plan_digest,available_at=CASE WHEN definition_row.activation='autonomous' THEN transaction_timestamp() ELSE run.available_at END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=run.version+1,updated_at=transaction_timestamp()
  WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body)
  VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,step_value,CASE WHEN definition_row.activation='supervised' THEN approval_value ELSE NULL END,worker_value,CASE WHEN definition_row.activation='autonomous' THEN 'run_authorized' ELSE 'approval_requested' END,plan_digest,jsonb_build_object('run_id',run_value,'step_id',step_value,'approval_id',approval_result,'action','update_finding_response','target_id',trigger_row.trigger_id,'authorization',authorization_value,'plan_hash','sha256:'||encode(plan_digest,'hex')));
  RETURN jsonb_build_object('run_id',run_value,'state',run_state_value,'version',run_row.version+1,'approval_id',approval_result,'step_id',step_value,'plan_hash','sha256:'||encode(plan_digest,'hex'));
END
$prepare$;

CREATE FUNCTION public.zasp_security_agent_execute_run_v21(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $execute$
DECLARE run_row zasp_security_agent_runs%ROWTYPE;definition_row zasp_security_agent_definitions%ROWTYPE;trigger_row zasp_security_agent_trigger_receipts%ROWTYPE;plan_row zasp_security_agent_plans%ROWTYPE;step_row zasp_security_agent_steps%ROWTYPE;approval_row zasp_security_agent_approvals%ROWTYPE;finding_version bigint;outcome_value text;result_digest_value bytea;approval_value text;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent execution rejected';
  END IF;
  SELECT * INTO run_row FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state,run.lease_owner,run.lease_token)=(organization_value,workspace_value,environment_value,run_value,'planning',worker_value,lease_token_value) AND run.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent lease lost';END IF;
  SELECT * INTO STRICT definition_row FROM zasp_security_agent_definitions definition WHERE (definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version)=(organization_value,workspace_value,environment_value,run_row.definition_id,run_row.definition_version) AND definition.activation IN('supervised','autonomous') AND definition.deleted_at IS NULL AND definition.body->'allowed_actions'=jsonb_build_array('update_finding_response') FOR SHARE;
  SELECT * INTO STRICT trigger_row FROM zasp_security_agent_trigger_receipts trigger_receipt WHERE (trigger_receipt.organization_id,trigger_receipt.workspace_id,trigger_receipt.environment_id,trigger_receipt.run_id,trigger_receipt.trigger_kind)=(organization_value,workspace_value,environment_value,run_value,'finding');
  SELECT * INTO STRICT plan_row FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id,plan.plan_hash)=(organization_value,workspace_value,environment_value,run_value,run_row.plan_hash) AND plan.expires_at>transaction_timestamp() FOR SHARE;
  SELECT * INTO STRICT step_row FROM zasp_security_agent_steps step WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.action_key,step.state)=(organization_value,workspace_value,environment_value,run_value,'update_finding_response','authorized') FOR UPDATE;
  IF definition_row.activation='supervised' THEN
    SELECT * INTO STRICT approval_row FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id,approval.step_id,approval.state,approval.plan_hash)=(organization_value,workspace_value,environment_value,run_value,step_row.step_id,'approved',run_row.plan_hash) AND approval.expires_at>transaction_timestamp() FOR SHARE;
    approval_value:=approval_row.approval_id;
  ELSE
    IF step_row.authorization_result<>'autonomous' OR plan_row.plan->'steps'->0->>'authorization'<>'autonomous' OR EXISTS(SELECT 1 FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id)=(organization_value,workspace_value,environment_value,run_value)) THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent autonomous authorization drift';
    END IF;
    approval_value:=NULL;
  END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=('*','*','*','*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'update_finding_response',true)) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent execution disabled';
  END IF;
  INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,lease_owner,lease_token,lease_expires_at,attempt)
  VALUES(organization_value,workspace_value,environment_value,run_value,step_row.step_id,'update_finding_response',step_row.input_digest,'leased',worker_value,lease_token_value,run_row.lease_expires_at,1);
  UPDATE zasp_risk_findings finding SET status='under_review',acceptance_reason=NULL,version=finding.version+1,updated_at=transaction_timestamp()
  WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id,finding.status,finding.version)=(organization_value,workspace_value,environment_value,trigger_row.trigger_id,'open',trigger_row.trigger_version)
  RETURNING finding.version INTO finding_version;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent evidence changed';END IF;
  outcome_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'security_agent_effect',run_value||chr(31)||step_row.step_id||chr(31)||'update_finding_response');
  result_digest_value:=digest(convert_to(jsonb_build_object('finding_id',trigger_row.trigger_id,'status','under_review','version',finding_version)::text,'UTF8'),'sha256');
  UPDATE zasp_security_agent_effects effect SET state='verified',outcome_id=outcome_value,result_digest=result_digest_value,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=effect.version+1,updated_at=transaction_timestamp()
  WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key)=(organization_value,workspace_value,environment_value,run_value,step_row.step_id,'update_finding_response');
  UPDATE zasp_security_agent_steps step SET state='succeeded',version=step.version+1,updated_at=transaction_timestamp() WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.step_id)=(organization_value,workspace_value,environment_value,run_value,step_row.step_id);
  UPDATE zasp_security_agent_runs run SET state='remediated',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=run.version+1,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body)
  VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,step_row.step_id,approval_value,worker_value,'effect_verified',result_digest_value,jsonb_build_object('run_id',run_value,'step_id',step_row.step_id,'action','update_finding_response','target_id',trigger_row.trigger_id,'authorization',step_row.authorization_result,'outcome_id',outcome_value,'result_digest','sha256:'||encode(result_digest_value,'hex')));
  RETURN jsonb_build_object('run_id',run_value,'state','remediated','version',run_row.version+1,'step_id',step_row.step_id,'effect_state','verified','outcome_id',outcome_value,'result_digest','sha256:'||encode(result_digest_value,'hex'));
END
$execute$;

ALTER FUNCTION public.zasp_security_agent_schedule_triggers_v21(text,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_prepare_run_v21(text,text,text,text,text,text,text,timestamptz,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_execute_run_v21(text,text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_schedule_triggers_v21(text,integer),public.zasp_security_agent_prepare_run_v21(text,text,text,text,text,text,text,timestamptz,text,text),public.zasp_security_agent_execute_run_v21(text,text,text,text,text,text,text,text) FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker;
REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_schedule_triggers(text,integer),public.zasp_security_agent_prepare_run(text,text,text,text,text,text,text,timestamptz,text,text),public.zasp_security_agent_execute_run(text,text,text,text,text,text,text,text) FROM zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_schedule_triggers_v21(text,integer),public.zasp_security_agent_prepare_run_v21(text,text,text,text,text,text,text,timestamptz,text,text),public.zasp_security_agent_execute_run_v21(text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;

CREATE FUNCTION public.zasp_security_agent_autonomous_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $security$
  SELECT zasp_security_agent_controls_security_ready()
    AND EXISTS(SELECT 1 FROM pg_constraint constraint_row WHERE constraint_row.conrelid='public.zasp_security_agent_steps'::regclass AND constraint_row.conname='zasp_security_agent_steps_authorization_result_check' AND pg_get_constraintdef(constraint_row.oid,true)='CHECK (authorization_result = ANY (ARRAY[''allow''::text, ''approval_required''::text, ''autonomous''::text, ''deny''::text]))')
    AND EXISTS(SELECT 1 FROM pg_trigger trigger_row WHERE trigger_row.tgrelid='public.zasp_security_agent_definitions'::regclass AND trigger_row.tgname='zasp_security_agent_sync_autonomy_v21' AND NOT trigger_row.tgisinternal AND trigger_row.tgenabled='O' AND trigger_row.tgtype=19 AND trigger_row.tgfoid='public.zasp_security_agent_sync_autonomy_v21()'::regprocedure AND trigger_row.tgattr::text=(SELECT attribute.attnum::text FROM pg_attribute attribute WHERE attribute.attrelid='public.zasp_security_agent_definitions'::regclass AND attribute.attname='activation' AND NOT attribute.attisdropped))
    AND EXISTS(SELECT 1 FROM pg_proc procedure WHERE procedure.oid='public.zasp_security_agent_sync_autonomy_v21()'::regprocedure AND procedure.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND NOT procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT has_function_privilege('public',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_security_agent_api',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_security_agent_worker',procedure.oid,'EXECUTE'))
    AND NOT has_function_privilege('zasp_security_agent_worker','public.zasp_security_agent_schedule_triggers(text,integer)','EXECUTE')
    AND NOT has_function_privilege('zasp_security_agent_worker','public.zasp_security_agent_prepare_run(text,text,text,text,text,text,text,timestamptz,text,text)','EXECUTE')
    AND NOT has_function_privilege('zasp_security_agent_worker','public.zasp_security_agent_execute_run(text,text,text,text,text,text,text,text)','EXECUTE')
    AND NOT EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_schedule_triggers_v21','zasp_security_agent_prepare_run_v21','zasp_security_agent_execute_run_v21']) AND (procedure.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure.prosecdef OR NOT COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR NOT has_function_privilege('zasp_security_agent_worker',procedure.oid,'EXECUTE') OR has_function_privilege('public',procedure.oid,'EXECUTE') OR has_function_privilege('zasp_security_agent_api',procedure.oid,'EXECUTE')))
$security$;
ALTER FUNCTION public.zasp_security_agent_autonomous_security_ready() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_autonomous_security_ready() FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker;

CREATE FUNCTION public.zasp_security_agent_autonomous_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
  WITH identities(value) AS (
    SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_schedule_triggers','zasp_security_agent_prepare_run','zasp_security_agent_execute_run','zasp_security_agent_schedule_triggers_v21','zasp_security_agent_prepare_run_v21','zasp_security_agent_execute_run_v21','zasp_security_agent_sync_autonomy_v21','zasp_security_agent_autonomous_security_ready','zasp_workflow_mutate','zasp_risk_mutate'])
    UNION ALL SELECT concat_ws('|','constraint',constraint_row.conname,pg_get_constraintdef(constraint_row.oid,true)) FROM pg_constraint constraint_row WHERE constraint_row.conrelid='public.zasp_security_agent_steps'::regclass AND constraint_row.conname='zasp_security_agent_steps_authorization_result_check'
    UNION ALL SELECT concat_ws('|','trigger',trigger_row.tgname,pg_get_triggerdef(trigger_row.oid,true)) FROM pg_trigger trigger_row WHERE trigger_row.tgrelid='public.zasp_security_agent_definitions'::regclass AND trigger_row.tgname='zasp_security_agent_sync_autonomy_v21' AND NOT trigger_row.tgisinternal
  ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_security_agent_autonomous_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
  SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
    AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=21 AND name='security_agent_autonomous_response' AND checksum=expected_checksum)
    AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-autonomous-v1') AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>21)
    AND zasp_security_agent_autonomous_security_ready()
    AND has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_autonomous_readiness(text,text)','EXECUTE')
    AND has_function_privilege('zasp_security_agent_worker','public.zasp_security_agent_autonomous_readiness(text,text)','EXECUTE')
    AND zasp_security_agent_autonomous_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_security_agent_autonomous_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_autonomous_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_autonomous_live_fingerprint(),public.zasp_security_agent_autonomous_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_autonomous_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_security_agent_api,zasp_security_agent_worker;

DO $schema_marker$
BEGIN
  UPDATE public.zasp_schema_metadata SET value='security-agent-autonomous-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='security-agent-controls-v1';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent autonomous schema marker drift';END IF;
END
$schema_marker$;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('security_agent_autonomous_fingerprint', 'dae50d0d29cdfb697c26a9fd919a34920ac864fddf1193b2b7ccf96d46749675') ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;
