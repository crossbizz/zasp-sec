-- New source-only routines derived from immutable22; no old routine replaced.

CREATE FUNCTION zasp_sa_temporary81.claim_effects(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
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
    UPDATE zasp_security_agent_effects effect SET state=CASE zasp_sa_temporary81.plan_mode(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id) WHEN 'monitor' THEN 'cleanup_failed' ELSE 'cleaned' END,outcome_id=no_target_outcome,result_digest=no_target_result,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=effect.version+1,updated_at=transaction_timestamp() WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key,effect.state)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id,'create_temporary_policy','cleanup_pending');
    UPDATE zasp_security_agent_runs run SET state=CASE zasp_sa_temporary81.plan_mode(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id) WHEN 'monitor' THEN 'needs_human' ELSE 'remediated' END,version=run.version+1,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id,CASE zasp_sa_temporary81.plan_mode(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id) WHEN 'monitor' THEN 'needs_human' ELSE 'contained' END);
    INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(item.organization_id,item.workspace_id,item.environment_id,no_target_audit,no_target_correlation,item.run_id,item.step_id,worker_value,CASE zasp_sa_temporary81.plan_mode(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id) WHEN 'monitor' THEN 'cleanup_failed' ELSE 'effect_cleaned' END,no_target_result,jsonb_build_object('run_id',item.run_id,'step_id',item.step_id,'action','create_temporary_policy','phase','cleanup','outcome_id',no_target_outcome,'result_digest','sha256:'||encode(no_target_result,'hex'),'reason','no_active_gateway_target','mode',zasp_sa_temporary81.plan_mode(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id))) ON CONFLICT DO NOTHING;
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
    items:=items||jsonb_build_array(jsonb_build_object('organization_id',item.organization_id,'workspace_id',item.workspace_id,'environment_id',item.environment_id,'run_id',item.run_id,'step_id',item.step_id,'phase',phase_value,'mode',zasp_sa_temporary81.plan_mode(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id),'input_digest','sha256:'||encode(item.input_digest,'hex'),'ttl_seconds',ttl_seconds,'lease_expires_at',to_char(item.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'targets',targets));
  END LOOP;
  RETURN jsonb_build_object('items',items);
END
$claim$;

CREATE FUNCTION zasp_sa_temporary81.heartbeat_effect(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,worker_value text,lease_token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
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

CREATE FUNCTION zasp_sa_temporary81.store_target(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,phase_value text,worker_value text,lease_token_value text,device_value text,credential_value text,sequence_value bigint,policy_version_value bigint,key_value text,issued_value timestamptz,expires_value timestamptz,failure_mode_value text,payload_digest_value bytea,policies_value jsonb,signature_value bytea,envelope_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $store$
DECLARE target_row zasp_security_agent_temporary_policy_targets%ROWTYPE;ttl_seconds integer;
BEGIN
  IF NOT zasp_security_agent_action_principal_ready() OR phase_value NOT IN('apply','cleanup') OR octet_length(payload_digest_value)<>32 OR octet_length(signature_value)<>64 OR octet_length(envelope_digest_value)<>32 OR jsonb_typeof(policies_value)<>'array' OR jsonb_array_length(policies_value)>100 OR (phase_value='cleanup' AND policies_value<>'[]'::jsonb) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy target rejected';
  END IF;
  IF phase_value='apply' AND (jsonb_array_length(policies_value)<>2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(policies_value) p WHERE p->>'action' IS DISTINCT FROM zasp_sa_temporary81.plan_mode(organization_value,workspace_value,environment_value,run_value,step_value))) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='temporary policy mode mismatch';END IF;
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

CREATE FUNCTION zasp_sa_temporary81.read_target(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,phase_value text,device_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $read$
DECLARE result_value jsonb;
BEGIN
  IF NOT zasp_security_agent_action_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='temporary policy target denied';END IF;
  SELECT jsonb_build_object('device_id',target.device_id,'credential_id',target.credential_id,'phase',target.phase,'state',target.state,'sequence',target.sequence,'policy_version',target.policy_version,'key_id',target.key_id,'issued_at',to_char(target.issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char(target.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'failure_mode',target.failure_mode,'payload_digest','sha256:'||encode(target.payload_digest,'hex'),'policies',target.policies,'signature',encode(target.signature,'base64'),'envelope_digest','sha256:'||encode(target.envelope_digest,'hex')) INTO result_value
  FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase,target.device_id)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value,device_value) AND target.state IN('stored','verified');
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='temporary policy target missing';END IF;
  RETURN result_value;
END
$read$;

CREATE FUNCTION zasp_sa_temporary81.finish_effect(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,phase_value text,worker_value text,lease_token_value text,result_digest_value bytea,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $finish$
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
    UPDATE zasp_security_agent_runs run SET state=CASE zasp_sa_temporary81.plan_mode(organization_value,workspace_value,environment_value,run_value,step_value) WHEN 'monitor' THEN 'needs_human' ELSE 'contained' END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=run.version+1,updated_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  ELSE
    UPDATE zasp_security_agent_effects effect SET state='cleaned',outcome_id=outcome_value,result_digest=result_digest_value,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=effect.version+1,updated_at=transaction_timestamp() WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key)=(organization_value,workspace_value,environment_value,run_value,step_value,'create_temporary_policy');
    UPDATE zasp_security_agent_runs run SET state=CASE zasp_sa_temporary81.plan_mode(organization_value,workspace_value,environment_value,run_value,step_value) WHEN 'monitor' THEN 'needs_human' ELSE 'remediated' END,version=run.version+1,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  END IF;
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,step_value,worker_value,CASE phase_value WHEN 'apply' THEN 'effect_verified' ELSE 'effect_cleaned' END,result_digest_value,jsonb_build_object('run_id',run_value,'step_id',step_value,'action','create_temporary_policy','phase',phase_value,'mode',zasp_sa_temporary81.plan_mode(organization_value,workspace_value,environment_value,run_value,step_value),'outcome_id',outcome_value,'result_digest','sha256:'||encode(result_digest_value,'hex')));
  RETURN jsonb_build_object('run_id',run_value,'step_id',step_value,'phase',phase_value,'mode',zasp_sa_temporary81.plan_mode(organization_value,workspace_value,environment_value,run_value,step_value),'run_state',CASE WHEN zasp_sa_temporary81.plan_mode(organization_value,workspace_value,environment_value,run_value,step_value)='monitor' THEN 'needs_human' WHEN phase_value='apply' THEN 'contained' ELSE 'remediated' END,'effect_state',CASE phase_value WHEN 'apply' THEN 'cleanup_pending' ELSE 'cleaned' END,'outcome_id',outcome_value,'result_digest','sha256:'||encode(result_digest_value,'hex'));
END
$finish$;
