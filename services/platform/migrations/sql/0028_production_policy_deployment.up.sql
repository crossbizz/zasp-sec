DO $release_guard$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=27 AND name='production_recovery')
     OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>27)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='production-recovery-v1') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='policy deployment release drift';
  END IF;
END
$release_guard$;

DO $product_release_evolution$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'later_release."version" > 27','later_release."version" > 28');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v28 compatibility evolution failed';END IF;
  EXECUTE definition;
  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(replace(definition,'later."version">27','later."version">28'),'later."version" > 27','later."version" > 28');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v28 compatibility evolution failed';END IF;
  EXECUTE definition;
END
$product_release_evolution$;

DO $role$
DECLARE worker_role record;
BEGIN
  SELECT * INTO worker_role FROM pg_roles WHERE rolname='zasp_policy_deployment_worker';
  IF NOT FOUND THEN
    CREATE ROLE zasp_policy_deployment_worker NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  ELSIF worker_role.rolcanlogin OR worker_role.rolinherit OR worker_role.rolsuper OR worker_role.rolcreatedb OR worker_role.rolcreaterole OR worker_role.rolreplication OR worker_role.rolbypassrls
     OR EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=worker_role.oid OR member=worker_role.oid) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe policy deployment role';
  END IF;
END
$role$;
GRANT zasp_policy_deployment_worker TO zasp_discovery_authority WITH ADMIN OPTION;

CREATE TABLE public.zasp_policy_deployment_principal_bindings(
  principal_name text PRIMARY KEY CHECK(principal_name~'^[a-z][a-z0-9_]{2,62}$'),
  authority_role text NOT NULL DEFAULT 'zasp_policy_deployment_worker' CHECK(authority_role='zasp_policy_deployment_worker'),
  registered_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.zasp_policy_deployment_fairness(
  organization_id text PRIMARY KEY CHECK(zasp_valid_product_id(organization_id)),
  last_claimed_at timestamptz NOT NULL DEFAULT '-infinity'::timestamptz
);

CREATE TABLE public.zasp_policy_deployment_work(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,device_id text NOT NULL,
  desired_generation bigint NOT NULL DEFAULT 1 CHECK(desired_generation>0),applied_generation bigint NOT NULL DEFAULT 0 CHECK(applied_generation>=0 AND applied_generation<=desired_generation),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','leased','retryable','scheduled','exhausted')),
  attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  lease_owner text,lease_token text,lease_expires_at timestamptz,last_heartbeat_at timestamptz,
  leased_generation bigint,leased_sequence bigint,leased_policy_version bigint,leased_credential_id text,leased_input_digest bytea,
  applied_envelope_digest bytea CHECK(applied_envelope_digest IS NULL OR octet_length(applied_envelope_digest)=32),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,device_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,device_id) REFERENCES public.zasp_gateway_devices(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
  CHECK((state='leased')=(lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND leased_generation IS NOT NULL AND leased_sequence IS NOT NULL AND leased_policy_version IS NOT NULL AND leased_credential_id IS NOT NULL AND leased_input_digest IS NOT NULL)),
  CHECK(leased_input_digest IS NULL OR octet_length(leased_input_digest)=32),CHECK(leased_sequence IS NULL OR leased_sequence>0),CHECK(leased_policy_version IS NULL OR leased_policy_version>0)
);
CREATE INDEX zasp_policy_deployment_work_claim_idx ON public.zasp_policy_deployment_work(state,available_at,organization_id,workspace_id,environment_id,device_id) WHERE state IN('pending','retryable','scheduled');

ALTER TABLE public.zasp_policy_deployment_principal_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_policy_deployment_fairness ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_policy_deployment_work ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_policy_deployment_principal_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_policy_deployment_fairness FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_policy_deployment_work FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_policy_deployment_principal_bindings_authority ON public.zasp_policy_deployment_principal_bindings FOR ALL TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_policy_deployment_fairness_authority ON public.zasp_policy_deployment_fairness FOR ALL TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_policy_deployment_work_authority ON public.zasp_policy_deployment_work FOR ALL TO zasp_discovery_authority USING(true) WITH CHECK(true);
ALTER TABLE public.zasp_policy_deployment_principal_bindings OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_policy_deployment_fairness OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_policy_deployment_work OWNER TO zasp_discovery_authority;
ALTER INDEX public.zasp_policy_deployment_work_claim_idx OWNER TO zasp_discovery_authority;
REVOKE ALL ON TABLE public.zasp_policy_deployment_principal_bindings,public.zasp_policy_deployment_fairness,public.zasp_policy_deployment_work FROM PUBLIC,zasp_discovery_api,zasp_security_agent_action_worker,zasp_runtime_gateway,zasp_policy_deployment_worker;

CREATE FUNCTION public.zasp_policy_deployment_principal_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $ready$
  SELECT EXISTS(SELECT 1 FROM zasp_policy_deployment_principal_bindings binding JOIN pg_roles principal ON principal.rolname=binding.principal_name
    WHERE binding.principal_name=session_user AND binding.authority_role='zasp_policy_deployment_worker' AND principal.rolcanlogin AND principal.rolinherit
      AND NOT principal.rolsuper AND NOT principal.rolcreatedb AND NOT principal.rolcreaterole AND NOT principal.rolreplication AND NOT principal.rolbypassrls)
    AND pg_has_role(session_user,'zasp_policy_deployment_worker','MEMBER')
    AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND NOT pg_has_role(session_user,'zasp_security_agent_action_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_runtime_gateway','MEMBER')
$ready$;

CREATE FUNCTION public.zasp_policy_deployment_register_principal(migration_principal text,worker_principal text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $register$
DECLARE principal record;
BEGIN
  IF migration_principal<>session_user OR worker_principal=migration_principal OR worker_principal!~'^[a-z][a-z0-9_]{2,62}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid policy deployment principal';END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('zasp-policy-deployment-principal-registration',0));
  SELECT * INTO principal FROM pg_roles WHERE rolname=worker_principal;
  IF NOT FOUND OR NOT principal.rolcanlogin OR NOT principal.rolinherit OR principal.rolsuper OR principal.rolcreatedb OR principal.rolcreaterole OR principal.rolreplication OR principal.rolbypassrls
     OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=principal.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>'zasp_policy_deployment_worker') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe policy deployment principal';
  END IF;
  EXECUTE format('GRANT zasp_policy_deployment_worker TO %I',worker_principal);
  INSERT INTO zasp_policy_deployment_principal_bindings(principal_name) VALUES(worker_principal) ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role WHERE zasp_policy_deployment_principal_bindings.authority_role=excluded.authority_role;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='policy deployment principal conflict';END IF;
  RETURN true;
END
$register$;

CREATE FUNCTION public.zasp_policy_deployment_enqueue_device(organization_value text,workspace_value text,environment_value text,device_value text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $enqueue$
DECLARE generation_value bigint;
BEGIN
  IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(device_value)
     OR NOT EXISTS(SELECT 1 FROM zasp_gateway_devices device WHERE (device.organization_id,device.workspace_id,device.environment_id,device.id)=(organization_value,workspace_value,environment_value,device_value)) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy deployment enqueue rejected';
  END IF;
  INSERT INTO zasp_policy_deployment_fairness(organization_id) VALUES(organization_value) ON CONFLICT DO NOTHING;
  INSERT INTO zasp_policy_deployment_work(organization_id,workspace_id,environment_id,device_id) VALUES(organization_value,workspace_value,environment_value,device_value)
  ON CONFLICT(organization_id,workspace_id,environment_id,device_id) DO UPDATE SET desired_generation=zasp_policy_deployment_work.desired_generation+1,
    state=CASE WHEN zasp_policy_deployment_work.state='leased' THEN 'leased' ELSE 'pending' END,attempt=CASE WHEN zasp_policy_deployment_work.state='leased' THEN zasp_policy_deployment_work.attempt ELSE 0 END,
    available_at=transaction_timestamp(),updated_at=transaction_timestamp()
  RETURNING desired_generation INTO generation_value;
  RETURN generation_value;
END
$enqueue$;

CREATE FUNCTION public.zasp_policy_deployment_source_trigger() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $trigger$
DECLARE device_row record;
BEGIN
  IF TG_TABLE_NAME='zasp_workflow_records' THEN
    IF TG_OP='DELETE' AND OLD.kind='policy' THEN
      FOR device_row IN SELECT device.id FROM zasp_gateway_devices device WHERE (device.organization_id,device.workspace_id,device.environment_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id) LOOP
        PERFORM zasp_policy_deployment_enqueue_device(OLD.organization_id,OLD.workspace_id,OLD.environment_id,device_row.id);
      END LOOP;
    ELSIF TG_OP<>'DELETE' AND NEW.kind='policy' THEN
      FOR device_row IN SELECT device.id FROM zasp_gateway_devices device WHERE (device.organization_id,device.workspace_id,device.environment_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id) LOOP
        PERFORM zasp_policy_deployment_enqueue_device(NEW.organization_id,NEW.workspace_id,NEW.environment_id,device_row.id);
      END LOOP;
    END IF;
  ELSIF TG_TABLE_NAME='zasp_gateway_devices' THEN
    IF TG_OP='DELETE' THEN
      RETURN OLD;
    END IF;
    PERFORM zasp_policy_deployment_enqueue_device(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.id);
  ELSIF TG_OP='DELETE' THEN
    PERFORM zasp_policy_deployment_enqueue_device(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.device_id);
  ELSE
    PERFORM zasp_policy_deployment_enqueue_device(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.device_id);
  END IF;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END
$trigger$;
CREATE TRIGGER zasp_workflow_records_policy_deployment AFTER INSERT OR UPDATE OR DELETE ON public.zasp_workflow_records FOR EACH ROW EXECUTE FUNCTION public.zasp_policy_deployment_source_trigger();
CREATE TRIGGER zasp_gateway_devices_policy_deployment AFTER INSERT OR UPDATE OF state ON public.zasp_gateway_devices FOR EACH ROW EXECUTE FUNCTION public.zasp_policy_deployment_source_trigger();
CREATE TRIGGER zasp_gateway_credentials_policy_deployment AFTER INSERT OR UPDATE OF revoked_at,expires_at ON public.zasp_gateway_credentials FOR EACH ROW EXECUTE FUNCTION public.zasp_policy_deployment_source_trigger();

CREATE FUNCTION public.zasp_policy_deployment_target_sequence_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $sequence$
DECLARE next_value bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.device_id,'policy-deployment-source-sequence'),0));
  SELECT GREATEST(COALESCE((SELECT max(bundle.sequence) FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.device_id)),0),
                  COALESCE((SELECT max(target.sequence) FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.device_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.device_id) AND (TG_OP='INSERT' OR (target.run_id,target.step_id,target.phase,target.device_id)<>(OLD.run_id,OLD.step_id,OLD.phase,OLD.device_id))),0))+1 INTO next_value;
  NEW.sequence:=next_value;NEW.policy_version:=next_value;RETURN NEW;
END
$sequence$;
CREATE TRIGGER zasp_security_agent_targets_policy_sequence BEFORE INSERT OR UPDATE OF credential_id ON public.zasp_security_agent_temporary_policy_targets FOR EACH ROW WHEN (NEW.state='planned') EXECUTE FUNCTION public.zasp_policy_deployment_target_sequence_guard();

ALTER TABLE public.zasp_security_agent_temporary_policy_targets ADD COLUMN desired_generation bigint CHECK(desired_generation IS NULL OR desired_generation>0);

CREATE FUNCTION public.zasp_policy_deployment_target_verify_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $verify$
BEGIN
  IF OLD.state='stored' AND NEW.state='verified' AND (NEW.desired_generation IS NULL OR NOT EXISTS(SELECT 1 FROM zasp_policy_deployment_work work WHERE (work.organization_id,work.workspace_id,work.environment_id,work.device_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.device_id) AND work.applied_generation>=NEW.desired_generation)) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='policy deployment pending';
  END IF;
  RETURN NEW;
END
$verify$;
CREATE TRIGGER zasp_security_agent_targets_policy_verify BEFORE UPDATE OF state ON public.zasp_security_agent_temporary_policy_targets FOR EACH ROW EXECUTE FUNCTION public.zasp_policy_deployment_target_verify_guard();

ALTER FUNCTION public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea) RENAME TO zasp_security_agent_store_temporary_policy_target_v27;
ALTER FUNCTION public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea) RENAME TO zasp_security_agent_store_session_policy_target_v27;

CREATE FUNCTION public.zasp_policy_deployment_store_temporary_source(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,phase_value text,worker_value text,lease_token_value text,device_value text,credential_value text,sequence_value bigint,policy_version_value bigint,key_value text,issued_value timestamptz,expires_value timestamptz,failure_mode_value text,payload_digest_value bytea,policies_value jsonb,signature_value bytea,envelope_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $store_source$
DECLARE target_row zasp_security_agent_temporary_policy_targets%ROWTYPE;ttl_seconds integer;session_value text;generation_value bigint;
BEGIN
  IF NOT zasp_security_agent_action_principal_ready() OR phase_value NOT IN('apply','cleanup') OR octet_length(payload_digest_value)<>32 OR octet_length(signature_value)<>64 OR octet_length(envelope_digest_value)<>32 OR jsonb_typeof(policies_value)<>'array' OR jsonb_array_length(policies_value)>100 OR phase_value='cleanup' AND policies_value<>'[]'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy source target rejected';END IF;
  SELECT * INTO target_row FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase,target.device_id,target.credential_id,target.sequence,target.policy_version)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value,device_value,credential_value,sequence_value,policy_version_value) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='policy source target missing';END IF;
  PERFORM 1 FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key,effect.state,effect.lease_owner,effect.lease_token)=(organization_value,workspace_value,environment_value,run_value,step_value,target_row.action_key,'leased',worker_value,lease_token_value) AND effect.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='policy source lease lost';END IF;
  SELECT (plan.plan->'steps'->0->>'ttl_seconds')::integer,plan.plan->'steps'->0->>'session_id' INTO STRICT ttl_seconds,session_value FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=(organization_value,workspace_value,environment_value,run_value);
  IF ttl_seconds NOT BETWEEN 60 AND 3600 OR failure_mode_value<>'closed' OR phase_value='apply' AND expires_value<>issued_value+make_interval(secs=>ttl_seconds) OR phase_value='cleanup' AND expires_value<>issued_value+interval '5 minutes' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy source target rejected';END IF;
  IF target_row.action_key='isolate_session' AND phase_value='apply' AND (NOT zasp_valid_product_id(session_value) OR jsonb_array_length(policies_value)<>2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(policies_value) policy WHERE policy->>'action'<>'block' OR NOT policy->'conditions' @> jsonb_build_array(jsonb_build_object('field','session_id','operator','equals','value',session_value)))) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='session isolation policy rejected';END IF;
  IF phase_value='apply' AND (NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=('*','*','*','*',true)) OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'*',true)) OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,target_row.action_key,true))) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='policy source execution disabled';END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_gateway_devices device WHERE (device.organization_id,device.workspace_id,device.environment_id,device.id,device.state)=(organization_value,workspace_value,environment_value,device_value,'active')) OR credential_value IS DISTINCT FROM (SELECT credential.id FROM zasp_gateway_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id)=(organization_value,workspace_value,environment_value,device_value) AND credential.revoked_at IS NULL AND credential.expires_at>transaction_timestamp() ORDER BY credential.issued_at DESC,credential.id DESC LIMIT 1) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='policy source credential changed';END IF;
  IF target_row.state<>'planned' THEN
    IF (target_row.key_id,target_row.issued_at,target_row.expires_at,target_row.failure_mode,target_row.payload_digest,target_row.policies,target_row.signature,target_row.envelope_digest) IS DISTINCT FROM (key_value,issued_value,expires_value,failure_mode_value,payload_digest_value,policies_value,signature_value,envelope_digest_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='policy source target replay conflict';END IF;
    generation_value:=target_row.desired_generation;
  ELSE
    UPDATE zasp_security_agent_temporary_policy_targets target SET state='stored',key_id=key_value,issued_at=issued_value,expires_at=expires_value,failure_mode=failure_mode_value,payload_digest=payload_digest_value,policies=policies_value,signature=signature_value,envelope_digest=envelope_digest_value,stored_at=transaction_timestamp() WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase,target.device_id)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value,device_value);
  END IF;
  IF generation_value IS NULL THEN
    generation_value:=zasp_policy_deployment_enqueue_device(organization_value,workspace_value,environment_value,device_value);
    UPDATE zasp_security_agent_temporary_policy_targets target SET desired_generation=generation_value WHERE (target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.phase,target.device_id)=(organization_value,workspace_value,environment_value,run_value,step_value,phase_value,device_value);
  END IF;
  RETURN jsonb_build_object('device_id',device_value,'phase',phase_value,'sequence',sequence_value,'policy_version',policy_version_value,'envelope_digest','sha256:'||encode(envelope_digest_value,'hex'));
END
$store_source$;

CREATE FUNCTION public.zasp_security_agent_store_temporary_policy_target(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,phase_value text,worker_value text,lease_token_value text,device_value text,credential_value text,sequence_value bigint,policy_version_value bigint,key_value text,issued_value timestamptz,expires_value timestamptz,failure_mode_value text,payload_digest_value bytea,policies_value jsonb,signature_value bytea,envelope_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $store$
BEGIN
  RETURN zasp_policy_deployment_store_temporary_source(organization_value,workspace_value,environment_value,run_value,step_value,phase_value,worker_value,lease_token_value,device_value,credential_value,sequence_value,policy_version_value,key_value,issued_value,expires_value,failure_mode_value,payload_digest_value,policies_value,signature_value,envelope_digest_value);
END
$store$;

CREATE FUNCTION public.zasp_security_agent_store_session_policy_target(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,phase_value text,worker_value text,lease_token_value text,device_value text,credential_value text,sequence_value bigint,policy_version_value bigint,key_value text,issued_value timestamptz,expires_value timestamptz,failure_mode_value text,payload_digest_value bytea,policies_value jsonb,signature_value bytea,envelope_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $store$
BEGIN
  RETURN zasp_policy_deployment_store_temporary_source(organization_value,workspace_value,environment_value,run_value,step_value,phase_value,worker_value,lease_token_value,device_value,credential_value,sequence_value,policy_version_value,key_value,issued_value,expires_value,failure_mode_value,payload_digest_value,policies_value,signature_value,envelope_digest_value);
END
$store$;

CREATE FUNCTION public.zasp_policy_deployment_claim(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE organization_row record;item zasp_policy_deployment_work%ROWTYPE;credential_value text;persistent_value jsonb;temporary_value jsonb;temporary_expires_value timestamptz;sequence_value bigint;digest_value bytea;items jsonb:='[]'::jsonb;
BEGIN
  IF NOT zasp_policy_deployment_principal_ready() OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 30 AND 300 OR claim_limit NOT BETWEEN 1 AND 25 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy deployment claim rejected';END IF;
  UPDATE zasp_policy_deployment_work SET state=CASE WHEN attempt>=100 THEN 'exhausted' ELSE 'retryable' END,available_at=CASE WHEN attempt>=100 THEN 'infinity'::timestamptz ELSE transaction_timestamp() END,
    lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_heartbeat_at=NULL,leased_generation=NULL,leased_sequence=NULL,leased_policy_version=NULL,leased_credential_id=NULL,leased_input_digest=NULL,updated_at=transaction_timestamp()
  WHERE state='leased' AND lease_expires_at<=transaction_timestamp();
  FOR organization_row IN SELECT fairness.organization_id FROM zasp_policy_deployment_fairness fairness WHERE EXISTS(SELECT 1 FROM zasp_policy_deployment_work work JOIN zasp_gateway_devices device ON (device.organization_id,device.workspace_id,device.environment_id,device.id,device.state)=(work.organization_id,work.workspace_id,work.environment_id,work.device_id,'active') WHERE work.organization_id=fairness.organization_id AND work.state IN('pending','retryable','scheduled') AND work.available_at<=transaction_timestamp() AND work.attempt<100 AND EXISTS(SELECT 1 FROM zasp_gateway_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id)=(work.organization_id,work.workspace_id,work.environment_id,work.device_id) AND credential.revoked_at IS NULL AND credential.expires_at>transaction_timestamp())) ORDER BY fairness.last_claimed_at,fairness.organization_id LIMIT claim_limit FOR UPDATE SKIP LOCKED
  LOOP
    SELECT work.* INTO item FROM zasp_policy_deployment_work work JOIN zasp_gateway_devices device ON (device.organization_id,device.workspace_id,device.environment_id,device.id,device.state)=(work.organization_id,work.workspace_id,work.environment_id,work.device_id,'active') WHERE work.organization_id=organization_row.organization_id AND work.state IN('pending','retryable','scheduled') AND work.available_at<=transaction_timestamp() AND work.attempt<100 AND EXISTS(SELECT 1 FROM zasp_gateway_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id)=(work.organization_id,work.workspace_id,work.environment_id,work.device_id) AND credential.revoked_at IS NULL AND credential.expires_at>transaction_timestamp()) ORDER BY work.available_at,work.workspace_id,work.environment_id,work.device_id LIMIT 1 FOR UPDATE OF work SKIP LOCKED;
    IF NOT FOUND THEN CONTINUE;END IF;
    SELECT credential.id INTO STRICT credential_value FROM zasp_gateway_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id)=(item.organization_id,item.workspace_id,item.environment_id,item.device_id) AND credential.revoked_at IS NULL AND credential.expires_at>transaction_timestamp() ORDER BY credential.issued_at DESC,credential.id DESC LIMIT 1;
    SELECT COALESCE(jsonb_agg(record.body ORDER BY record.id),'[]'::jsonb) INTO persistent_value FROM zasp_workflow_records record WHERE (record.organization_id,record.workspace_id,record.environment_id,record.kind)=(item.organization_id,item.workspace_id,item.environment_id,'policy') AND record.deleted_at IS NULL AND record.body->>'rollout' IN('monitor','enforced');
    SELECT COALESCE(jsonb_agg(policy_value.value ORDER BY policy_value.value->>'id'),'[]'::jsonb),min(target.expires_at) INTO temporary_value,temporary_expires_value FROM zasp_security_agent_temporary_policy_targets target CROSS JOIN LATERAL jsonb_array_elements(target.policies) policy_value(value) WHERE (target.organization_id,target.workspace_id,target.environment_id,target.device_id,target.phase)=(item.organization_id,item.workspace_id,item.environment_id,item.device_id,'apply') AND target.state IN('stored','verified') AND target.expires_at>transaction_timestamp() AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets cleanup WHERE (cleanup.organization_id,cleanup.workspace_id,cleanup.environment_id,cleanup.run_id,cleanup.step_id,cleanup.device_id,cleanup.phase)=(target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.device_id,'cleanup') AND cleanup.state IN('stored','verified'));
    SELECT COALESCE(max(bundle.sequence)+1,1) INTO sequence_value FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id)=(item.organization_id,item.workspace_id,item.environment_id,item.device_id);
    digest_value:=digest(convert_to(jsonb_build_object('credential_id',credential_value,'desired_generation',item.desired_generation,'persistent_policies',persistent_value,'temporary_policies',temporary_value,'temporary_expires_at',CASE WHEN temporary_expires_value IS NULL THEN NULL ELSE to_char(temporary_expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END)::text,'UTF8'),'sha256');
    UPDATE zasp_policy_deployment_work work SET state='leased',attempt=work.attempt+1,lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),last_heartbeat_at=transaction_timestamp(),leased_generation=work.desired_generation,leased_sequence=sequence_value,leased_policy_version=sequence_value,leased_credential_id=credential_value,leased_input_digest=digest_value,updated_at=transaction_timestamp() WHERE (work.organization_id,work.workspace_id,work.environment_id,work.device_id)=(item.organization_id,item.workspace_id,item.environment_id,item.device_id) RETURNING * INTO item;
    UPDATE zasp_policy_deployment_fairness SET last_claimed_at=transaction_timestamp() WHERE organization_id=item.organization_id;
    items:=items||jsonb_build_array(jsonb_build_object('organization_id',item.organization_id,'workspace_id',item.workspace_id,'environment_id',item.environment_id,'device_id',item.device_id,'credential_id',credential_value,'desired_generation',item.leased_generation,'sequence',sequence_value,'policy_version',sequence_value,'input_digest','sha256:'||encode(digest_value,'hex'),'lease_expires_at',to_char(item.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'persistent_policies',persistent_value,'temporary_policies',temporary_value,'temporary_expires_at',CASE WHEN temporary_expires_value IS NULL THEN NULL ELSE to_char(temporary_expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END));
  END LOOP;
  RETURN jsonb_build_object('items',items);
END
$claim$;

CREATE FUNCTION public.zasp_policy_deployment_heartbeat(organization_value text,workspace_value text,environment_value text,device_value text,generation_value bigint,worker_value text,lease_token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
DECLARE expires_value timestamptz;
BEGIN
  IF NOT zasp_policy_deployment_principal_ready() OR lease_seconds NOT BETWEEN 30 AND 300 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy deployment heartbeat rejected';END IF;
  UPDATE zasp_policy_deployment_work work SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),last_heartbeat_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE (work.organization_id,work.workspace_id,work.environment_id,work.device_id,work.state,work.leased_generation,work.lease_owner,work.lease_token)=(organization_value,workspace_value,environment_value,device_value,'leased',generation_value,worker_value,lease_token_value) AND work.lease_expires_at>transaction_timestamp() RETURNING work.lease_expires_at INTO expires_value;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='policy deployment lease lost';END IF;
  RETURN jsonb_build_object('lease_expires_at',to_char(expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END
$heartbeat$;

CREATE FUNCTION public.zasp_policy_deployment_store(organization_value text,workspace_value text,environment_value text,device_value text,generation_value bigint,worker_value text,lease_token_value text,credential_value text,sequence_value bigint,policy_version_value bigint,key_value text,issued_value timestamptz,expires_value timestamptz,failure_mode_value text,payload_digest_value bytea,policies_value jsonb,signature_value bytea,envelope_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $store$
DECLARE work_row zasp_policy_deployment_work%ROWTYPE;
BEGIN
  IF NOT zasp_policy_deployment_principal_ready() OR generation_value<1 OR sequence_value<1 OR policy_version_value<>sequence_value OR key_value!~'^[a-z][a-z0-9_-]{7,63}$' OR issued_value>transaction_timestamp()+interval '30 seconds' OR expires_value<=transaction_timestamp() OR expires_value<=issued_value OR expires_value>issued_value+interval '24 hours' OR failure_mode_value NOT IN('open','closed') OR octet_length(payload_digest_value)<>32 OR jsonb_typeof(policies_value)<>'array' OR jsonb_array_length(policies_value)>100 OR octet_length(signature_value)<>64 OR octet_length(envelope_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy deployment store rejected';END IF;
  SELECT * INTO work_row FROM zasp_policy_deployment_work work WHERE (work.organization_id,work.workspace_id,work.environment_id,work.device_id,work.state,work.leased_generation,work.lease_owner,work.lease_token)=(organization_value,workspace_value,environment_value,device_value,'leased',generation_value,worker_value,lease_token_value) AND work.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND OR work_row.desired_generation<>generation_value OR (work_row.leased_credential_id,work_row.leased_sequence,work_row.leased_policy_version) IS DISTINCT FROM (credential_value,sequence_value,policy_version_value) OR credential_value IS DISTINCT FROM (SELECT credential.id FROM zasp_gateway_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id)=(organization_value,workspace_value,environment_value,device_value) AND credential.revoked_at IS NULL AND credential.expires_at>transaction_timestamp() ORDER BY credential.issued_at DESC,credential.id DESC LIMIT 1) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='policy deployment authority changed';END IF;
  INSERT INTO zasp_runtime_gateway_policy_bundles(organization_id,workspace_id,environment_id,device_id,credential_id,sequence,policy_version,key_id,algorithm,audience,issued_at,expires_at,failure_mode,payload_digest,policies,signature,envelope_digest) VALUES(organization_value,workspace_value,environment_value,device_value,credential_value,sequence_value,policy_version_value,key_value,'Ed25519','runtime-gateway-policy',issued_value,expires_value,failure_mode_value,payload_digest_value,policies_value,signature_value,envelope_digest_value) ON CONFLICT(organization_id,workspace_id,environment_id,device_id,sequence) DO NOTHING;
  IF NOT FOUND AND NOT EXISTS(SELECT 1 FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id,bundle.credential_id,bundle.sequence,bundle.policy_version,bundle.key_id,bundle.issued_at,bundle.expires_at,bundle.failure_mode,bundle.payload_digest,bundle.policies,bundle.signature,bundle.envelope_digest)=(organization_value,workspace_value,environment_value,device_value,credential_value,sequence_value,policy_version_value,key_value,issued_value,expires_value,failure_mode_value,payload_digest_value,policies_value,signature_value,envelope_digest_value)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='policy deployment bundle conflict';END IF;
  RETURN jsonb_build_object('envelope_digest','sha256:'||encode(envelope_digest_value,'hex'));
END
$store$;

CREATE FUNCTION public.zasp_policy_deployment_read(organization_value text,workspace_value text,environment_value text,device_value text,sequence_value bigint) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $read$
DECLARE result_value jsonb;
BEGIN
  IF NOT zasp_policy_deployment_principal_ready() OR sequence_value<1 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy deployment read rejected';END IF;
 SELECT jsonb_build_object('contract_version',bundle.contract_version,'key_id',bundle.key_id,'algorithm',bundle.algorithm,'audience',bundle.audience,'organization_id',bundle.organization_id,'workspace_id',bundle.workspace_id,'environment_id',bundle.environment_id,'device_id',bundle.device_id,'sequence',bundle.sequence,'policy_version',bundle.policy_version,'issued_at',to_char(bundle.issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char(bundle.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'failure_mode',bundle.failure_mode,'payload_digest',encode(bundle.payload_digest,'hex'),'policies',bundle.policies,'signature',replace(replace(replace(replace(trim(trailing '=' from encode(bundle.signature,'base64')),chr(10),''),chr(13),''),'+','-'),'/','_')) INTO result_value FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id,bundle.sequence)=(organization_value,workspace_value,environment_value,device_value,sequence_value);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='policy deployment bundle missing';END IF;
  RETURN result_value;
END
$read$;

CREATE FUNCTION public.zasp_policy_deployment_finish(organization_value text,workspace_value text,environment_value text,device_value text,generation_value bigint,worker_value text,lease_token_value text,envelope_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $finish$
DECLARE work_row zasp_policy_deployment_work%ROWTYPE;next_state text;next_available timestamptz;
BEGIN
  IF NOT zasp_policy_deployment_principal_ready() OR generation_value<1 OR octet_length(envelope_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy deployment finish rejected';END IF;
  SELECT * INTO work_row FROM zasp_policy_deployment_work work WHERE (work.organization_id,work.workspace_id,work.environment_id,work.device_id,work.state,work.leased_generation,work.lease_owner,work.lease_token)=(organization_value,workspace_value,environment_value,device_value,'leased',generation_value,worker_value,lease_token_value) AND work.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id,bundle.sequence,bundle.envelope_digest)=(organization_value,workspace_value,environment_value,device_value,work_row.leased_sequence,envelope_digest_value)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='policy deployment finish lost';END IF;
  next_state:=CASE WHEN work_row.desired_generation>generation_value THEN 'pending' ELSE 'scheduled' END;
  next_available:=CASE WHEN next_state='pending' THEN transaction_timestamp() ELSE LEAST(transaction_timestamp()+interval '12 hours',COALESCE((SELECT min(target.expires_at) FROM zasp_security_agent_temporary_policy_targets target WHERE (target.organization_id,target.workspace_id,target.environment_id,target.device_id,target.phase)=(organization_value,workspace_value,environment_value,device_value,'apply') AND target.state IN('stored','verified') AND target.expires_at>transaction_timestamp() AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets cleanup WHERE (cleanup.organization_id,cleanup.workspace_id,cleanup.environment_id,cleanup.run_id,cleanup.step_id,cleanup.device_id,cleanup.phase)=(target.organization_id,target.workspace_id,target.environment_id,target.run_id,target.step_id,target.device_id,'cleanup') AND cleanup.state IN('stored','verified'))),'infinity'::timestamptz)) END;
  UPDATE zasp_policy_deployment_work work SET applied_generation=GREATEST(work.applied_generation,generation_value),state=next_state,attempt=0,available_at=next_available,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_heartbeat_at=NULL,leased_generation=NULL,leased_sequence=NULL,leased_policy_version=NULL,leased_credential_id=NULL,leased_input_digest=NULL,applied_envelope_digest=envelope_digest_value,updated_at=transaction_timestamp() WHERE (work.organization_id,work.workspace_id,work.environment_id,work.device_id)=(organization_value,workspace_value,environment_value,device_value);
  RETURN jsonb_build_object('desired_generation',work_row.desired_generation,'applied_generation',generation_value,'state',next_state,'envelope_digest','sha256:'||encode(envelope_digest_value,'hex'));
END
$finish$;

INSERT INTO public.zasp_policy_deployment_fairness(organization_id) SELECT DISTINCT device.organization_id FROM public.zasp_gateway_devices device ON CONFLICT DO NOTHING;
INSERT INTO public.zasp_policy_deployment_work(organization_id,workspace_id,environment_id,device_id) SELECT device.organization_id,device.workspace_id,device.environment_id,device.id FROM public.zasp_gateway_devices device WHERE device.state='active' ON CONFLICT DO NOTHING;

DO $functions$
DECLARE procedure_oid oid;
BEGIN
  FOR procedure_oid IN SELECT procedure.oid FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_policy_deployment_principal_ready','zasp_policy_deployment_register_principal','zasp_policy_deployment_enqueue_device','zasp_policy_deployment_source_trigger','zasp_policy_deployment_target_sequence_guard','zasp_policy_deployment_target_verify_guard','zasp_policy_deployment_store_temporary_source','zasp_policy_deployment_claim','zasp_policy_deployment_heartbeat','zasp_policy_deployment_store','zasp_policy_deployment_read','zasp_policy_deployment_finish','zasp_security_agent_store_temporary_policy_target','zasp_security_agent_store_session_policy_target']) LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api,zasp_security_agent_action_worker,zasp_runtime_gateway,zasp_policy_deployment_worker',procedure_oid::regprocedure);
  END LOOP;
END
$functions$;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea),public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea) TO zasp_security_agent_action_worker;
GRANT EXECUTE ON FUNCTION public.zasp_policy_deployment_principal_ready(),public.zasp_policy_deployment_claim(text,text,integer,integer),public.zasp_policy_deployment_heartbeat(text,text,text,text,bigint,text,text,integer),public.zasp_policy_deployment_store(text,text,text,text,bigint,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea),public.zasp_policy_deployment_read(text,text,text,text,bigint),public.zasp_policy_deployment_finish(text,text,text,text,bigint,text,text,bytea) TO zasp_policy_deployment_worker;

CREATE FUNCTION public.zasp_policy_deployment_execution_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_recovery_execution_security_ready()
 AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_policy_deployment_worker' AND NOT rolsuper AND NOT rolinherit AND NOT rolcanlogin AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 AND EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname='zasp_policy_deployment_worker' AND member.rolname='zasp_discovery_authority' AND membership.admin_option)
 AND NOT has_table_privilege('zasp_policy_deployment_worker','public.zasp_policy_deployment_work','SELECT')
 AND has_function_privilege('zasp_policy_deployment_worker','public.zasp_policy_deployment_claim(text,text,integer,integer)','EXECUTE')
 AND has_function_privilege('zasp_policy_deployment_worker','public.zasp_policy_deployment_store(text,text,text,text,bigint,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea)','EXECUTE')
 AND NOT has_function_privilege('zasp_runtime_gateway','public.zasp_policy_deployment_store(text,text,text,text,bigint,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea)','EXECUTE')
$security$;

CREATE FUNCTION public.zasp_policy_deployment_execution_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
  SELECT concat_ws('|','prior',zasp_recovery_execution_live_fingerprint())
  UNION ALL SELECT concat_ws('|','role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls) FROM pg_roles WHERE rolname='zasp_policy_deployment_worker'
  UNION ALL SELECT concat_ws('|','membership',granted.rolname,member.rolname,membership.admin_option) FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname='zasp_policy_deployment_worker' AND member.rolname='zasp_discovery_authority'
  UNION ALL SELECT concat_ws('|','table',class.relname,owner.rolname,class.relrowsecurity,class.relforcerowsecurity,COALESCE(class.relacl::text,'')) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_policy_deployment_%' AND class.relkind IN('r','i')
  UNION ALL SELECT concat_ws('|','column',class.relname,attribute.attname,attribute.atttypid::regtype::text,attribute.attnotnull,attribute.attidentity,attribute.attgenerated,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND (class.relname LIKE 'zasp_policy_deployment_%' OR class.relname IN('zasp_security_agent_temporary_policy_targets','zasp_security_agent_session_policy_targets')) AND attribute.attnum>0 AND NOT attribute.attisdropped
  UNION ALL SELECT concat_ws('|','index',class.relname,pg_get_indexdef(class.oid)) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_policy_deployment_%' AND class.relkind='i'
  UNION ALL SELECT concat_ws('|','constraint',class.relname,constraint_value.conname,constraint_value.contype,constraint_value.convalidated,pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_policy_deployment_%'
  UNION ALL SELECT concat_ws('|','policy',class.relname,policy.polname,policy.polpermissive,pg_get_expr(policy.polqual,policy.polrelid),pg_get_expr(policy.polwithcheck,policy.polrelid)) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_policy_deployment_%'
  UNION ALL SELECT concat_ws('|','trigger',class.relname,trigger.tgname,pg_get_triggerdef(trigger.oid,true)) FROM pg_trigger trigger JOIN pg_class class ON class.oid=trigger.tgrelid WHERE trigger.tgname LIKE '%policy_deployment%' OR trigger.tgname LIKE '%policy_sequence' OR trigger.tgname LIKE '%policy_verify'
  UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_policy_deployment_%' OR procedure.proname IN('zasp_security_agent_store_temporary_policy_target','zasp_security_agent_store_session_policy_target'))
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_policy_deployment_execution_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=28 AND name='production_policy_deployment' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='production-recovery-v1') AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>28)
 AND zasp_policy_deployment_execution_security_ready() AND zasp_policy_deployment_execution_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_policy_deployment_execution_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_policy_deployment_execution_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_policy_deployment_execution_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_policy_deployment_execution_security_ready(),public.zasp_policy_deployment_execution_live_fingerprint(),public.zasp_policy_deployment_execution_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_action_worker,zasp_runtime_gateway,zasp_policy_deployment_worker;
GRANT EXECUTE ON FUNCTION public.zasp_policy_deployment_execution_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_action_worker,zasp_runtime_gateway,zasp_policy_deployment_worker;

ALTER FUNCTION public.zasp_recovery_execution_readiness(text,text) RENAME TO zasp_recovery_execution_readiness_v27;
REVOKE ALL ON FUNCTION public.zasp_recovery_execution_readiness_v27(text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_recovery_worker,zasp_recovery_outbox_worker,zasp_discovery_worker,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter,zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy;
CREATE FUNCTION public.zasp_recovery_execution_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=27 AND name='production_recovery' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_recovery_fingerprint' AND value=expected_fingerprint)
 AND zasp_policy_deployment_execution_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=28 AND name='production_policy_deployment'),(SELECT value FROM zasp_schema_metadata WHERE key='production_policy_deployment_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_recovery_execution_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_recovery_execution_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_recovery_execution_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_api,zasp_recovery_worker,zasp_recovery_outbox_worker,zasp_discovery_worker,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter,zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_policy_deployment_fingerprint', '84e625560595f2405649bc4ac5c690ed53ae7df315024c5d6d3adc20f01f09dd') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
