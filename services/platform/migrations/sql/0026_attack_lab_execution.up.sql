DO $release_guard$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=25 AND name='red_team_execution')
     OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>25)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='red-team-execution-v1')
     OR NOT public.zasp_red_team_execution_security_ready()
     OR public.zasp_red_team_execution_live_fingerprint()<>'bb848d5c9936143cc9251dd44410de037a382b1190e1d04069df18b0a38f669a' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab execution release drift';
  END IF;
END
$release_guard$;

DO $roles$
DECLARE role_name text; role_row record;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy'] LOOP
    SELECT * INTO role_row FROM pg_roles WHERE rolname=role_name;
    IF FOUND THEN
      IF role_row.rolsuper OR role_row.rolinherit OR role_row.rolcreaterole OR role_row.rolcreatedb OR role_row.rolcanlogin OR role_row.rolreplication OR role_row.rolbypassrls
         OR EXISTS(SELECT 1 FROM pg_auth_members membership WHERE membership.member=role_row.oid OR membership.roleid=role_row.oid) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab execution role rejected';
      END IF;
    ELSE
      EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',role_name);
    END IF;
  END LOOP;
END
$roles$;
GRANT zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy TO zasp_discovery_authority WITH ADMIN OPTION;
GRANT SELECT ON TABLE public.zasp_environments TO zasp_discovery_authority;

CREATE TABLE public.zasp_attack_lab_principal_bindings(
  principal_name text PRIMARY KEY,
  authority_role text NOT NULL CHECK(authority_role IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy')),
  registered_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.zasp_attack_lab_credential_bindings(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,binding_id text NOT NULL,target_id text NOT NULL,
  credential_reference text NOT NULL,credential_class text NOT NULL,version bigint NOT NULL,reference_digest bytea NOT NULL,state text NOT NULL,valid_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,binding_id),UNIQUE(organization_id,workspace_id,environment_id,target_id,credential_reference),
  FOREIGN KEY(organization_id,workspace_id,environment_id,target_id) REFERENCES public.zasp_inventory_entities(organization_id,workspace_id,environment_id,id),
  CHECK(zasp_valid_product_id(binding_id) AND zasp_valid_product_id(target_id)),CHECK(credential_reference~'^ref:red-team/[a-z][a-z0-9_-]{7,127}$'),
  CHECK(credential_class IN('read_only','test_write')),CHECK(version BETWEEN 1 AND 1000000),CHECK(octet_length(reference_digest)=32),CHECK(state IN('active','revoked')),CHECK(valid_until>created_at)
);

CREATE TABLE public.zasp_attack_lab_runs(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
  version bigint NOT NULL DEFAULT 1,source_run_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,
  target_id text NOT NULL,target_kind text NOT NULL,environment text NOT NULL,credential_class text NOT NULL,destination text NOT NULL,
  credential_binding_id text NOT NULL,credential_binding_version bigint NOT NULL,credential_binding_digest bytea NOT NULL,
  requested_by text NOT NULL,state text NOT NULL DEFAULT 'queued',attempt integer NOT NULL DEFAULT 0,cancel_requested boolean NOT NULL DEFAULT false,
  cleanup_state text NOT NULL DEFAULT 'pending',controller_id text,lease_token bytea,lease_expires_at timestamptz,
	  queued_at timestamptz NOT NULL DEFAULT transaction_timestamp(),started_at timestamptz,attempt_started_at timestamptz,completed_at timestamptz,next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
	  input_digest bytea NOT NULL,preflight jsonb,sandbox_name text,sandbox_reference text,verdict text,error_code text,evidence_reference text,evidence_key text,evidence_version_id text,evidence_checksum bytea,evidence_size bigint,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,source_run_id) REFERENCES public.zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id) REFERENCES public.zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,credential_binding_id) REFERENCES public.zasp_attack_lab_credential_bindings(organization_id,workspace_id,environment_id,binding_id),
  CHECK(zasp_valid_product_id(run_id) AND zasp_valid_product_id(target_id) AND zasp_valid_product_id(requested_by)),
  CHECK(version BETWEEN 1 AND 1000000 AND definition_version BETWEEN 1 AND 1000000 AND credential_binding_version BETWEEN 1 AND 1000000 AND octet_length(credential_binding_digest)=32),
  CHECK(target_kind IN('agent_endpoint','mcp_server','coding_agent')),CHECK(environment IN('development','test','staging')),CHECK(credential_class IN('read_only','test_write')),
  CHECK(length(destination) BETWEEN 1 AND 253 AND destination=lower(destination) AND destination~'^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$' AND destination NOT LIKE '%..%'),
  CHECK(state IN('queued','leased','running','retryable','cleanup','complete','failed','cancelled')),CHECK(attempt BETWEEN 0 AND 5),CHECK(cleanup_state IN('pending','in_progress','complete','failed')),
  CHECK((state IN('leased','running','cleanup'))=(controller_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK(controller_id IS NULL OR length(controller_id) BETWEEN 3 AND 128 AND controller_id~'^[a-z][a-z0-9.-]{2,127}$'),CHECK(lease_token IS NULL OR octet_length(lease_token)=32),CHECK(octet_length(input_digest)=32),
	  CHECK(preflight IS NULL OR jsonb_typeof(preflight)='object'),CHECK(sandbox_name IS NULL OR sandbox_name~'^zasp-attack-lab-[a-f0-9]{32}$'),
	  CHECK(sandbox_reference IS NULL OR sandbox_reference~'^k8s://attack-lab/jobs/zasp-attack-lab-[a-z0-9-]{8,64}@[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),CHECK(verdict IS NULL OR verdict IN('verified','not_reproduced','inconclusive')),CHECK(error_code IS NULL OR error_code IN('retryable','denied','malformed','outcome_unknown','cleanup_failed','cancelled','exhausted')),
	  CHECK(attempt=0 OR attempt_started_at IS NOT NULL),CHECK(attempt_started_at IS NULL OR attempt_started_at>=queued_at),
	  CHECK(evidence_checksum IS NULL OR octet_length(evidence_checksum)=32),CHECK(evidence_size IS NULL OR evidence_size BETWEEN 1 AND 67108864)
);

CREATE TABLE public.zasp_attack_lab_attempts(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,attempt integer NOT NULL,
  input_digest bytea NOT NULL,evidence_state text NOT NULL,verdict text,criterion_observed boolean NOT NULL,canary_touched boolean NOT NULL,cleanup_completed boolean NOT NULL,error_code text,
  evidence jsonb NOT NULL,evidence_reference text,evidence_key text,evidence_version_id text,evidence_checksum bytea,evidence_size bigint,
  completed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,attempt),
  FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_attack_lab_runs(organization_id,workspace_id,environment_id,run_id),
  CHECK(attempt BETWEEN 1 AND 5 AND octet_length(input_digest)=32),CHECK(evidence_state IN('complete','unavailable')),CHECK(verdict IS NULL OR verdict IN('verified','not_reproduced','inconclusive')),
  CHECK(error_code IS NULL OR error_code IN('denied','malformed','outcome_unknown','cleanup_failed','cancelled','exhausted')),
  CHECK(jsonb_typeof(evidence)='array'),
  CHECK(evidence_state<>'complete' OR jsonb_array_length(evidence)=5 AND evidence->>0 LIKE 'semantic:%' AND evidence->>1 LIKE 'gateway:%' AND evidence->>2 LIKE 'egress:%' AND evidence->>3 LIKE 'kubernetes:%' AND evidence->>4 LIKE 'cloud:%' AND evidence_reference IS NOT NULL AND evidence_key IS NOT NULL AND evidence_version_id IS NOT NULL AND octet_length(evidence_checksum)=32 AND evidence_size BETWEEN 1 AND 67108864),
  CHECK(evidence_state<>'unavailable' OR evidence='[]'::jsonb AND evidence_reference IS NULL AND evidence_key IS NULL AND evidence_version_id IS NULL AND evidence_checksum IS NULL AND evidence_size IS NULL AND (verdict='inconclusive' AND error_code='outcome_unknown' OR verdict IS NULL AND error_code='cancelled')),
  CHECK(verdict IS DISTINCT FROM 'verified' OR criterion_observed AND canary_touched),CHECK(verdict IS DISTINCT FROM 'not_reproduced' OR NOT criterion_observed AND NOT canary_touched),CHECK(cleanup_completed)
);

CREATE TABLE public.zasp_attack_lab_cleanup_checkpoints(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,attempt integer NOT NULL,input_digest bytea NOT NULL,sandbox_reference text NOT NULL,
  evidence_state text NOT NULL DEFAULT 'pending',verdict text,criterion_observed boolean NOT NULL DEFAULT false,canary_touched boolean NOT NULL DEFAULT false,error_code text,evidence jsonb NOT NULL DEFAULT '[]'::jsonb,evidence_reference text,evidence_key text,evidence_version_id text,evidence_checksum bytea,evidence_size bigint,
  finish_digest bytea,finish_result jsonb,finished_at timestamptz,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,attempt),
  FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_attack_lab_runs(organization_id,workspace_id,environment_id,run_id),
  CHECK(attempt BETWEEN 1 AND 5 AND octet_length(input_digest)=32),CHECK(sandbox_reference~'^k8s://attack-lab/jobs/zasp-attack-lab-[a-z0-9-]{8,64}@[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  CHECK(evidence_state IN('pending','complete','unavailable')),CHECK(verdict IS NULL OR verdict IN('verified','not_reproduced','inconclusive')),CHECK(verdict IS DISTINCT FROM 'verified' OR criterion_observed AND canary_touched),CHECK(verdict IS DISTINCT FROM 'not_reproduced' OR NOT criterion_observed AND NOT canary_touched),CHECK(error_code IS NULL OR verdict='inconclusive' AND error_code IN('denied','malformed','outcome_unknown','cancelled','exhausted')),
  CHECK(jsonb_typeof(evidence)='array'),
  CHECK(evidence_state<>'pending' OR verdict IS NULL AND NOT criterion_observed AND NOT canary_touched AND error_code IS NULL AND evidence='[]'::jsonb AND evidence_reference IS NULL AND evidence_key IS NULL AND evidence_version_id IS NULL AND evidence_checksum IS NULL AND evidence_size IS NULL),
  CHECK(evidence_state<>'complete' OR jsonb_array_length(evidence)=5 AND evidence->>0 LIKE 'semantic:%' AND evidence->>1 LIKE 'gateway:%' AND evidence->>2 LIKE 'egress:%' AND evidence->>3 LIKE 'kubernetes:%' AND evidence->>4 LIKE 'cloud:%' AND evidence_reference IS NOT NULL AND evidence_key IS NOT NULL AND evidence_version_id IS NOT NULL AND octet_length(evidence_checksum)=32 AND evidence_size BETWEEN 1 AND 67108864),
  CHECK(evidence_state<>'unavailable' OR verdict='inconclusive' AND NOT criterion_observed AND NOT canary_touched AND error_code IN('outcome_unknown','cancelled') AND evidence='[]'::jsonb AND evidence_reference IS NULL AND evidence_key IS NULL AND evidence_version_id IS NULL AND evidence_checksum IS NULL AND evidence_size IS NULL),
  CHECK(finish_digest IS NULL OR octet_length(finish_digest)=32),CHECK(finish_result IS NULL OR jsonb_typeof(finish_result)='object'),CHECK((finish_digest IS NULL AND finish_result IS NULL AND finished_at IS NULL) OR (finish_digest IS NOT NULL AND finish_result IS NOT NULL AND finished_at IS NOT NULL))
);

CREATE TABLE public.zasp_attack_lab_outbox(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,outbox_id text NOT NULL,
  topic text NOT NULL DEFAULT 'attack-lab-jobs',deterministic_key text NOT NULL,payload jsonb NOT NULL,payload_digest bytea NOT NULL,
  state text NOT NULL DEFAULT 'pending',attempt integer NOT NULL DEFAULT 0,worker_id text,lease_token bytea,lease_expires_at timestamptz,
  available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),provider_ack text,published_at timestamptz,last_error text,completion_digest bytea,completion_result jsonb,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,outbox_id),UNIQUE(organization_id,workspace_id,environment_id,deterministic_key),
  FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id),
  CHECK(zasp_valid_product_id(outbox_id)),CHECK(topic='attack-lab-jobs'),CHECK(length(deterministic_key) BETWEEN 16 AND 256),CHECK(jsonb_typeof(payload)='object'),CHECK(octet_length(payload_digest)=32),
  CHECK(state IN('pending','leased','published','failed')),CHECK(attempt BETWEEN 0 AND 100),
  CHECK((state='leased')=(worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),CHECK(worker_id IS NULL OR length(worker_id) BETWEEN 3 AND 128 AND worker_id~'^[a-z][a-z0-9.-]{2,127}$'),CHECK(lease_token IS NULL OR octet_length(lease_token)=32),
  CHECK((state='published')=(provider_ack IS NOT NULL AND published_at IS NOT NULL)),CHECK(provider_ack IS NULL OR provider_ack~'^sha256:[a-f0-9]{64}$'),CHECK(last_error IS NULL OR last_error='queue_publish_unknown'),CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32),CHECK(completion_result IS NULL OR jsonb_typeof(completion_result)='object')
);

CREATE TABLE public.zasp_attack_lab_outbox_fairness(
  topic text PRIMARY KEY CHECK(topic='attack-lab-jobs'),
  last_organization_id text CHECK(last_organization_id IS NULL OR zasp_valid_product_id(last_organization_id)),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.zasp_attack_lab_request_receipts(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,principal_id text NOT NULL,operation text NOT NULL,idempotency_key text NOT NULL,
  resource_id text NOT NULL,expected_version bigint NOT NULL,intent_digest bytea NOT NULL,audit_id text NOT NULL,correlation_id text NOT NULL,receipt_id text NOT NULL,result jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),expires_at timestamptz NOT NULL DEFAULT transaction_timestamp()+interval '24 hours',
  PRIMARY KEY(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key),
  CHECK(zasp_valid_product_id(principal_id) AND zasp_valid_product_id(resource_id) AND zasp_valid_product_id(audit_id) AND zasp_valid_product_id(correlation_id) AND zasp_valid_product_id(receipt_id)),
  CHECK(operation IN('createAttackLabRun','cancelAttackLabRun','rerunAttackLabRun')),CHECK(length(idempotency_key) BETWEEN 16 AND 128),CHECK(expected_version BETWEEN 0 AND 1000000),CHECK(octet_length(intent_digest)=32),CHECK(jsonb_typeof(result)='object')
);

CREATE TABLE public.zasp_attack_lab_audit(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,audit_id text NOT NULL,correlation_id text NOT NULL,receipt_id text NOT NULL,
  actor_id text NOT NULL,event_kind text NOT NULL,resource_id text NOT NULL,event_digest bytea NOT NULL,body jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,audit_id),UNIQUE(organization_id,receipt_id),
  CHECK(zasp_valid_product_id(audit_id) AND zasp_valid_product_id(correlation_id) AND zasp_valid_product_id(receipt_id) AND zasp_valid_product_id(actor_id) AND zasp_valid_product_id(resource_id)),
  CHECK(event_kind IN('attack_lab_run_queued','attack_lab_run_cancelled','attack_lab_run_rerun')),CHECK(octet_length(event_digest)=32),CHECK(jsonb_typeof(body)='object')
);

CREATE INDEX zasp_attack_lab_runs_list_idx ON public.zasp_attack_lab_runs(organization_id,workspace_id,environment_id,queued_at DESC,run_id DESC);
CREATE INDEX zasp_attack_lab_runs_claim_idx ON public.zasp_attack_lab_runs(next_attempt_at,queued_at) WHERE state IN('queued','retryable','leased','running','cleanup');
CREATE INDEX zasp_attack_lab_outbox_claim_idx ON public.zasp_attack_lab_outbox(available_at,created_at) WHERE state IN('pending','leased');
CREATE INDEX zasp_attack_lab_receipts_expiry_idx ON public.zasp_attack_lab_request_receipts(expires_at);

DO $authority$
DECLARE table_name text;
BEGIN
	  FOREACH table_name IN ARRAY ARRAY['zasp_attack_lab_principal_bindings','zasp_attack_lab_credential_bindings','zasp_attack_lab_runs','zasp_attack_lab_attempts','zasp_attack_lab_cleanup_checkpoints','zasp_attack_lab_outbox','zasp_attack_lab_outbox_fairness','zasp_attack_lab_request_receipts','zasp_attack_lab_audit'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',table_name);
    EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',table_name||'_authority',table_name);
    EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy',table_name);
    EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO zasp_discovery_authority',table_name);
  END LOOP;
END
$authority$;

CREATE FUNCTION public.zasp_attack_lab_register_principals(migration_principal text,controller_principal text,outbox_principal text,proxy_principal text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $register$
DECLARE principals text[]:=ARRAY[controller_principal,outbox_principal,proxy_principal];authorities text[]:=ARRAY['zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy'];index_value integer;role_value record;
BEGIN
 IF migration_principal<>session_user OR cardinality(ARRAY(SELECT DISTINCT unnest(ARRAY[migration_principal,controller_principal,outbox_principal,proxy_principal])))<>4 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab principals rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-attack-lab-principal-registration',0));
 FOR index_value IN 1..3 LOOP
  SELECT role_row.oid,role_row.rolcanlogin,role_row.rolsuper,role_row.rolcreatedb,role_row.rolcreaterole,role_row.rolreplication,role_row.rolinherit,role_row.rolbypassrls INTO role_value FROM pg_roles role_row WHERE role_row.rolname=principals[index_value];
  IF NOT FOUND OR NOT role_value.rolcanlogin OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR NOT role_value.rolinherit OR role_value.rolbypassrls OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=role_value.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>authorities[index_value]) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab principal rejected';END IF;
  EXECUTE format('GRANT %I TO %I',authorities[index_value],principals[index_value]);
  INSERT INTO zasp_attack_lab_principal_bindings(principal_name,authority_role) VALUES(principals[index_value],authorities[index_value]) ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role WHERE zasp_attack_lab_principal_bindings.authority_role=excluded.authority_role;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='attack lab principal conflict';END IF;
 END LOOP;
 RETURN true;
END
$register$;

CREATE FUNCTION public.zasp_attack_lab_principal_ready(expected_authority text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $principal$
 SELECT expected_authority IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy')
 AND EXISTS(SELECT 1 FROM zasp_attack_lab_principal_bindings binding JOIN pg_roles role_value ON role_value.rolname=binding.principal_name WHERE binding.principal_name=session_user AND binding.authority_role=expected_authority AND role_value.rolcanlogin AND role_value.rolinherit AND NOT role_value.rolsuper AND NOT role_value.rolcreatedb AND NOT role_value.rolcreaterole AND NOT role_value.rolreplication AND NOT role_value.rolbypassrls)
 AND pg_has_role(session_user,expected_authority,'MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
$principal$;

CREATE FUNCTION public.zasp_attack_lab_principals_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $principals$
 SELECT (SELECT count(*) FROM zasp_attack_lab_principal_bindings)=3
 AND NOT EXISTS(SELECT 1 FROM zasp_attack_lab_principal_bindings binding LEFT JOIN pg_roles principal ON principal.rolname=binding.principal_name LEFT JOIN pg_roles authority ON authority.rolname=binding.authority_role WHERE principal.oid IS NULL OR authority.oid IS NULL OR NOT principal.rolcanlogin OR NOT principal.rolinherit OR principal.rolsuper OR principal.rolcreatedb OR principal.rolcreaterole OR principal.rolreplication OR principal.rolbypassrls OR NOT pg_has_role(principal.rolname,authority.rolname,'MEMBER') OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=principal.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>authority.rolname))
$principals$;

CREATE FUNCTION public.zasp_attack_lab_register_credential_binding(organization_value text,workspace_value text,environment_value text,binding_value text,target_value text,reference_value text,class_value text,version_value bigint,digest_value bytea,valid_until_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $register_binding$
DECLARE target_row zasp_inventory_entities%ROWTYPE;binding_row zasp_attack_lab_credential_bindings%ROWTYPE;replayed_value boolean:=false;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(binding_value) OR NOT zasp_valid_product_id(target_value) OR reference_value!~'^ref:red-team/[a-z][a-z0-9_-]{7,127}$' OR class_value NOT IN('read_only','test_write') OR version_value NOT BETWEEN 1 AND 1000000 OR octet_length(digest_value)<>32 OR valid_until_value IS NULL OR valid_until_value<=transaction_timestamp() OR valid_until_value>transaction_timestamp()+interval '90 days' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab credential binding rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,target_value,reference_value),0));
 SELECT * INTO STRICT target_row FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state)=(organization_value,workspace_value,environment_value,target_value,'active') AND fresh_until>transaction_timestamp() AND (zasp_red_team_target_binding_valid(winning_attributes->'red_team','agent_endpoint') OR zasp_red_team_target_binding_valid(winning_attributes->'red_team','mcp_server') OR zasp_red_team_target_binding_valid(winning_attributes->'red_team','coding_agent'));
 IF target_row.winning_attributes->'red_team'->>'credential_reference'<>reference_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab credential target rejected';END IF;
 SELECT * INTO binding_row FROM zasp_attack_lab_credential_bindings WHERE (organization_id,workspace_id,environment_id,binding_id)=(organization_value,workspace_value,environment_value,binding_value) FOR UPDATE;
 IF FOUND THEN
  IF (binding_row.target_id,binding_row.credential_reference,binding_row.credential_class,binding_row.version,binding_row.reference_digest,binding_row.state,binding_row.valid_until)=(target_value,reference_value,class_value,version_value,digest_value,'active',valid_until_value) THEN replayed_value:=true;
  ELSIF binding_row.target_id<>target_value OR binding_row.credential_reference<>reference_value OR version_value<>binding_row.version+1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab credential binding conflict';
  ELSE UPDATE zasp_attack_lab_credential_bindings SET credential_class=class_value,version=version_value,reference_digest=digest_value,state='active',valid_until=valid_until_value,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,binding_id)=(organization_value,workspace_value,environment_value,binding_value) RETURNING * INTO binding_row;
  END IF;
 ELSE
  INSERT INTO zasp_attack_lab_credential_bindings(organization_id,workspace_id,environment_id,binding_id,target_id,credential_reference,credential_class,version,reference_digest,state,valid_until) VALUES(organization_value,workspace_value,environment_value,binding_value,target_value,reference_value,class_value,version_value,digest_value,'active',valid_until_value) RETURNING * INTO binding_row;
 END IF;
 RETURN jsonb_build_object('organization_id',binding_row.organization_id,'workspace_id',binding_row.workspace_id,'environment_id',binding_row.environment_id,'binding_id',binding_row.binding_id,'target_id',binding_row.target_id,'credential_reference',binding_row.credential_reference,'credential_class',binding_row.credential_class,'version',binding_row.version,'reference_digest',encode(binding_row.reference_digest,'hex'),'state',binding_row.state,'valid_until',binding_row.valid_until,'replayed',replayed_value);
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab credential target unavailable';
END
$register_binding$;

CREATE FUNCTION public.zasp_attack_lab_revoke_credential_binding(organization_value text,workspace_value text,environment_value text,binding_value text,expected_version_value bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $revoke_binding$
DECLARE binding_row zasp_attack_lab_credential_bindings%ROWTYPE;replayed_value boolean:=false;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(binding_value) OR expected_version_value NOT BETWEEN 1 AND 1000000 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab credential revocation rejected';END IF;
 SELECT * INTO STRICT binding_row FROM zasp_attack_lab_credential_bindings WHERE (organization_id,workspace_id,environment_id,binding_id)=(organization_value,workspace_value,environment_value,binding_value) FOR UPDATE;
 IF binding_row.version<>expected_version_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab credential revocation conflict';END IF;
 IF binding_row.state='revoked' THEN replayed_value:=true;ELSE UPDATE zasp_attack_lab_credential_bindings SET state='revoked',updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,binding_id)=(organization_value,workspace_value,environment_value,binding_value) RETURNING * INTO binding_row;END IF;
 RETURN jsonb_build_object('organization_id',binding_row.organization_id,'workspace_id',binding_row.workspace_id,'environment_id',binding_row.environment_id,'binding_id',binding_row.binding_id,'target_id',binding_row.target_id,'credential_reference',binding_row.credential_reference,'credential_class',binding_row.credential_class,'version',binding_row.version,'reference_digest',encode(binding_row.reference_digest,'hex'),'state',binding_row.state,'valid_until',binding_row.valid_until,'replayed',replayed_value);
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab credential binding unavailable';
END
$revoke_binding$;

CREATE FUNCTION public.zasp_attack_lab_run_json(row_value public.zasp_attack_lab_runs) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $json$
 SELECT jsonb_strip_nulls(jsonb_build_object(
  'id',row_value.run_id,'version',row_value.version,'source_run_id',row_value.source_run_id,'definition_id',row_value.definition_id,'definition_version',row_value.definition_version,
  'target_id',row_value.target_id,'target_kind',row_value.target_kind,'environment',row_value.environment,'credential_class',row_value.credential_class,'destination',row_value.destination,
  'status',row_value.state,'attempt',row_value.attempt,'cancel_requested',row_value.cancel_requested,'cleanup_state',row_value.cleanup_state,
  'limits',jsonb_build_object('cpu','500m','memory','1Gi','ephemeral_storage','2Gi','timeout_seconds',300),
	  'queued_at',row_value.queued_at,'started_at',row_value.started_at,'attempt_started_at',row_value.attempt_started_at,'completed_at',row_value.completed_at,'verdict',row_value.verdict,'error_code',row_value.error_code,'evidence_reference',row_value.evidence_reference))
$json$;

CREATE FUNCTION public.zasp_attack_lab_mutation_result(organization_value text,workspace_value text,environment_value text,actor_value text,operation_value text,resource_value text,correlation_value text,idempotency_value text,body_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $mutation$
DECLARE audit_value text;receipt_value text;event_value text;result_value jsonb;
BEGIN
 IF operation_value NOT IN('createAttackLabRun','cancelAttackLabRun','rerunAttackLabRun') OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(resource_value) OR NOT zasp_valid_product_id(correlation_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR jsonb_typeof(body_value)<>'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab mutation result rejected';END IF;
 audit_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'attack_lab_audit',actor_value||chr(31)||operation_value||chr(31)||idempotency_value);
 receipt_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'attack_lab_receipt',actor_value||chr(31)||operation_value||chr(31)||idempotency_value);
 event_value:=CASE operation_value WHEN 'createAttackLabRun' THEN 'attack_lab_run_queued' WHEN 'cancelAttackLabRun' THEN 'attack_lab_run_cancelled' ELSE 'attack_lab_run_rerun' END;
 result_value:=jsonb_build_object('body',body_value,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
 INSERT INTO zasp_attack_lab_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,receipt_id,actor_id,event_kind,resource_id,event_digest,body) VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,receipt_value,actor_value,event_value,resource_value,digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
 RETURN result_value;
END
$mutation$;

CREATE FUNCTION public.zasp_attack_lab_list_runs(organization_value text,workspace_value text,environment_value text,before_value timestamptz,before_id_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $list$
DECLARE result_value jsonb;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR limit_value NOT BETWEEN 1 AND 100 OR before_value IS NULL AND before_id_value IS NOT NULL OR before_value IS NOT NULL AND NOT zasp_valid_product_id(before_id_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab run list rejected';END IF;
 WITH visible AS (SELECT * FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND (before_value IS NULL OR (queued_at,run_id)<(before_value,before_id_value)) ORDER BY queued_at DESC,run_id DESC LIMIT limit_value),cursor_row AS (SELECT queued_at,run_id FROM visible ORDER BY queued_at,run_id LIMIT 1)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(zasp_attack_lab_run_json(run_row) ORDER BY queued_at DESC,run_id DESC) FROM visible run_row),'[]'::jsonb),'next_cursor',CASE WHEN (SELECT count(*) FROM visible)=limit_value THEN (SELECT jsonb_build_object('queued_at',queued_at,'id',run_id) FROM cursor_row) END) INTO result_value;
 RETURN result_value;
END
$list$;

CREATE FUNCTION public.zasp_attack_lab_get_run(organization_value text,workspace_value text,environment_value text,run_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $get$
DECLARE row_value zasp_attack_lab_runs%ROWTYPE;attempt_value jsonb;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab run rejected';END IF;
 SELECT * INTO STRICT row_value FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
 SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('attempt',attempt,'evidence_state',evidence_state,'verdict',verdict,'criterion_observed',criterion_observed,'canary_touched',canary_touched,'cleanup_completed',cleanup_completed,'error_code',error_code,'evidence',evidence,'evidence_reference',evidence_reference,'completed_at',completed_at)) ORDER BY attempt) INTO attempt_value FROM zasp_attack_lab_attempts WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
 RETURN zasp_attack_lab_run_json(row_value)||jsonb_build_object('attempts',COALESCE(attempt_value,'[]'::jsonb));
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab run not found';
END
$get$;

CREATE FUNCTION public.zasp_attack_lab_create_run(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,run_value text,source_run_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $create$
DECLARE source_row zasp_red_team_runs%ROWTYPE;definition_row zasp_red_team_definitions%ROWTYPE;target_row zasp_inventory_entities%ROWTYPE;binding_row zasp_attack_lab_credential_bindings%ROWTYPE;intent_value jsonb;digest_value bytea;receipt_row zasp_attack_lab_request_receipts%ROWTYPE;run_row zasp_attack_lab_runs%ROWTYPE;payload_value jsonb;result_value jsonb;destination_value text;environment_class_value text;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(source_run_value) OR run_value=source_run_value OR NOT zasp_valid_product_id(correlation_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab create rejected';END IF;
 intent_value:=jsonb_build_object('approved',true,'run_id',run_value,'source_run_id',source_run_value);digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'createAttackLabRun',idempotency_value),0));
 SELECT * INTO receipt_row FROM zasp_attack_lab_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'createAttackLabRun',idempotency_value);
 IF FOUND THEN IF receipt_row.resource_id<>run_value OR receipt_row.expected_version<>0 OR receipt_row.intent_digest<>digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab create replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 SELECT * INTO STRICT source_row FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,verdict)=(organization_value,workspace_value,environment_value,source_run_value,'complete','fail') FOR UPDATE;
 SELECT * INTO STRICT definition_row FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,enabled)=(organization_value,workspace_value,environment_value,source_row.definition_id,source_row.definition_version,true) FOR SHARE;
 SELECT environment_class INTO STRICT environment_class_value FROM zasp_environments WHERE (organization_id,workspace_id,id)=(organization_value,workspace_value,environment_value);
 IF environment_class_value='production' OR environment_class_value<>definition_row.safety->>'environment' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab environment rejected';END IF;
 SELECT * INTO STRICT target_row FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state)=(organization_value,workspace_value,environment_value,definition_row.target_id,'active') AND fresh_until>transaction_timestamp() AND zasp_red_team_target_binding_valid(winning_attributes->'red_team',definition_row.target_kind) FOR SHARE;
 SELECT * INTO STRICT binding_row FROM zasp_attack_lab_credential_bindings WHERE (organization_id,workspace_id,environment_id,target_id,credential_reference,credential_class,state)=(organization_value,workspace_value,environment_value,definition_row.target_id,target_row.winning_attributes->'red_team'->>'credential_reference',definition_row.safety->>'credential_class','active') AND valid_until>transaction_timestamp() FOR SHARE;
 destination_value:=substring(target_row.winning_attributes->'red_team'->>'endpoint' FROM '^https://([^/]+)/v1/evaluate$');IF destination_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab destination rejected';END IF;
 INSERT INTO zasp_attack_lab_runs(organization_id,workspace_id,environment_id,run_id,source_run_id,definition_id,definition_version,target_id,target_kind,environment,credential_class,destination,credential_binding_id,credential_binding_version,credential_binding_digest,requested_by,input_digest)
 VALUES(organization_value,workspace_value,environment_value,run_value,source_run_value,definition_row.definition_id,definition_row.version,definition_row.target_id,definition_row.target_kind,environment_class_value,binding_row.credential_class,destination_value,binding_row.binding_id,binding_row.version,binding_row.reference_digest,actor_value,digest_value) RETURNING * INTO run_row;
 payload_value:=jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value,'run_id',run_value,'source_run_id',source_run_value,'definition_id',definition_row.definition_id,'definition_version',definition_row.version,'target_id',definition_row.target_id,'target_kind',definition_row.target_kind,'input_digest',encode(digest_value,'hex'));
 INSERT INTO zasp_attack_lab_outbox(organization_id,workspace_id,environment_id,outbox_id,deterministic_key,payload,payload_digest) VALUES(organization_value,workspace_value,environment_value,zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'attack_lab_outbox',run_value),'attack-lab-jobs:'||run_value,payload_value,digest(convert_to(payload_value::text,'UTF8'),'sha256'));
 result_value:=zasp_attack_lab_mutation_result(organization_value,workspace_value,environment_value,actor_value,'createAttackLabRun',run_value,correlation_value,idempotency_value,zasp_attack_lab_run_json(run_row));
 INSERT INTO zasp_attack_lab_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent_digest,audit_id,correlation_id,receipt_id,result) VALUES(organization_value,workspace_value,environment_value,actor_value,'createAttackLabRun',idempotency_value,run_value,0,digest_value,result_value->>'audit_id',result_value->>'correlation_id',result_value->>'receipt_id',result_value);RETURN result_value;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab source unavailable';
END
$create$;

CREATE FUNCTION public.zasp_attack_lab_cancel_run(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,run_value text,expected_version_value bigint,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $cancel$
DECLARE row_value zasp_attack_lab_runs%ROWTYPE;intent_value jsonb;digest_value bytea;receipt_row zasp_attack_lab_request_receipts%ROWTYPE;result_value jsonb;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(run_value) OR expected_version_value NOT BETWEEN 1 AND 999999 OR NOT zasp_valid_product_id(correlation_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab cancel rejected';END IF;
 intent_value:=jsonb_build_object('run_id',run_value,'expected_version',expected_version_value);digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'cancelAttackLabRun',idempotency_value),0));
 SELECT * INTO receipt_row FROM zasp_attack_lab_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'cancelAttackLabRun',idempotency_value);IF FOUND THEN IF receipt_row.resource_id<>run_value OR receipt_row.expected_version<>expected_version_value OR receipt_row.intent_digest<>digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab cancel replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 UPDATE zasp_attack_lab_runs SET version=version+1,cancel_requested=true,state=CASE WHEN state IN('queued','retryable') THEN 'cancelled' ELSE state END,cleanup_state=CASE WHEN state IN('queued','retryable') THEN 'complete' ELSE cleanup_state END,completed_at=CASE WHEN state IN('queued','retryable') THEN transaction_timestamp() ELSE completed_at END,error_code=CASE WHEN state IN('queued','retryable') THEN 'cancelled' ELSE error_code END,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,version)=(organization_value,workspace_value,environment_value,run_value,expected_version_value) AND state NOT IN('complete','failed','cancelled') RETURNING * INTO row_value;
 IF NOT FOUND THEN IF NOT EXISTS(SELECT 1 FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab run not found';END IF;RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab run version conflict';END IF;
 result_value:=zasp_attack_lab_mutation_result(organization_value,workspace_value,environment_value,actor_value,'cancelAttackLabRun',run_value,correlation_value,idempotency_value,zasp_attack_lab_run_json(row_value));
 INSERT INTO zasp_attack_lab_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent_digest,audit_id,correlation_id,receipt_id,result) VALUES(organization_value,workspace_value,environment_value,actor_value,'cancelAttackLabRun',idempotency_value,run_value,expected_version_value,digest_value,result_value->>'audit_id',result_value->>'correlation_id',result_value->>'receipt_id',result_value);RETURN result_value;
END
$cancel$;

CREATE FUNCTION public.zasp_attack_lab_rerun(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,source_value text,expected_version_value bigint,run_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $rerun$
DECLARE source_row zasp_attack_lab_runs%ROWTYPE;definition_row zasp_red_team_definitions%ROWTYPE;target_row zasp_inventory_entities%ROWTYPE;binding_row zasp_attack_lab_credential_bindings%ROWTYPE;intent_value jsonb;digest_value bytea;receipt_row zasp_attack_lab_request_receipts%ROWTYPE;run_row zasp_attack_lab_runs%ROWTYPE;payload_value jsonb;result_value jsonb;destination_value text;environment_class_value text;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(source_value) OR NOT zasp_valid_product_id(run_value) OR source_value=run_value OR expected_version_value NOT BETWEEN 1 AND 1000000 OR NOT zasp_valid_product_id(correlation_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab rerun rejected';END IF;
 intent_value:=jsonb_build_object('run_id',run_value,'source_attack_lab_run_id',source_value,'expected_version',expected_version_value);digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'rerunAttackLabRun',idempotency_value),0));
 SELECT * INTO receipt_row FROM zasp_attack_lab_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'rerunAttackLabRun',idempotency_value);IF FOUND THEN IF receipt_row.resource_id<>run_value OR receipt_row.expected_version<>expected_version_value OR receipt_row.intent_digest<>digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab rerun replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 SELECT * INTO STRICT source_row FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id,version)=(organization_value,workspace_value,environment_value,source_value,expected_version_value) AND state IN('complete','failed','cancelled') FOR UPDATE;
 SELECT * INTO STRICT definition_row FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,enabled,target_id,target_kind)=(organization_value,workspace_value,environment_value,source_row.definition_id,source_row.definition_version,true,source_row.target_id,source_row.target_kind) FOR SHARE;
 SELECT environment_class INTO STRICT environment_class_value FROM zasp_environments WHERE (organization_id,workspace_id,id)=(organization_value,workspace_value,environment_value);
 IF environment_class_value='production' OR environment_class_value<>definition_row.safety->>'environment' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab environment rejected';END IF;
 SELECT * INTO STRICT target_row FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state)=(organization_value,workspace_value,environment_value,source_row.target_id,'active') AND fresh_until>transaction_timestamp() AND zasp_red_team_target_binding_valid(winning_attributes->'red_team',source_row.target_kind) FOR SHARE;
 SELECT * INTO STRICT binding_row FROM zasp_attack_lab_credential_bindings WHERE (organization_id,workspace_id,environment_id,target_id,credential_reference,credential_class,state)=(organization_value,workspace_value,environment_value,source_row.target_id,target_row.winning_attributes->'red_team'->>'credential_reference',definition_row.safety->>'credential_class','active') AND valid_until>transaction_timestamp() FOR SHARE;
 destination_value:=substring(target_row.winning_attributes->'red_team'->>'endpoint' FROM '^https://([^/]+)/v1/evaluate$');IF destination_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab destination rejected';END IF;
 INSERT INTO zasp_attack_lab_runs(organization_id,workspace_id,environment_id,run_id,source_run_id,definition_id,definition_version,target_id,target_kind,environment,credential_class,destination,credential_binding_id,credential_binding_version,credential_binding_digest,requested_by,input_digest)
 VALUES(organization_value,workspace_value,environment_value,run_value,source_row.source_run_id,definition_row.definition_id,definition_row.version,definition_row.target_id,definition_row.target_kind,environment_class_value,binding_row.credential_class,destination_value,binding_row.binding_id,binding_row.version,binding_row.reference_digest,actor_value,digest_value) RETURNING * INTO run_row;
 payload_value:=jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value,'run_id',run_value,'source_run_id',source_row.source_run_id,'definition_id',source_row.definition_id,'definition_version',source_row.definition_version,'target_id',source_row.target_id,'target_kind',source_row.target_kind,'input_digest',encode(digest_value,'hex'));
 INSERT INTO zasp_attack_lab_outbox(organization_id,workspace_id,environment_id,outbox_id,deterministic_key,payload,payload_digest) VALUES(organization_value,workspace_value,environment_value,zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'attack_lab_outbox',run_value),'attack-lab-jobs:'||run_value,payload_value,digest(convert_to(payload_value::text,'UTF8'),'sha256'));
 result_value:=zasp_attack_lab_mutation_result(organization_value,workspace_value,environment_value,actor_value,'rerunAttackLabRun',run_value,correlation_value,idempotency_value,zasp_attack_lab_run_json(run_row));
 INSERT INTO zasp_attack_lab_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent_digest,audit_id,correlation_id,receipt_id,result) VALUES(organization_value,workspace_value,environment_value,actor_value,'rerunAttackLabRun',idempotency_value,run_value,expected_version_value,digest_value,result_value->>'audit_id',result_value->>'correlation_id',result_value->>'receipt_id',result_value);RETURN result_value;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab rerun source unavailable';
END
$rerun$;

CREATE FUNCTION public.zasp_attack_lab_claim_outbox(worker_value text,token_value bytea,lease_seconds integer,limit_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE result_value jsonb;last_organization text;claimed_last_organization text;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_outbox_worker') OR length(worker_value) NOT BETWEEN 3 AND 128 OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 5 AND 900 OR limit_value NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab outbox claim rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp_attack_lab_outbox:attack-lab-jobs',0));
 INSERT INTO zasp_attack_lab_outbox_fairness(topic) VALUES('attack-lab-jobs') ON CONFLICT(topic) DO NOTHING;
 SELECT last_organization_id INTO last_organization FROM zasp_attack_lab_outbox_fairness WHERE topic='attack-lab-jobs' FOR UPDATE;
 UPDATE zasp_attack_lab_outbox SET state='failed',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,last_error=COALESCE(last_error,'queue_publish_unknown'),updated_at=transaction_timestamp() WHERE topic='attack-lab-jobs' AND state='leased' AND attempt>=100 AND lease_expires_at<=transaction_timestamp();
 WITH organizations AS (
  SELECT candidate.organization_id,min(candidate.available_at) due FROM zasp_attack_lab_outbox candidate
  WHERE candidate.topic='attack-lab-jobs' AND candidate.attempt<100 AND (candidate.state='pending' OR candidate.state='leased' AND candidate.lease_expires_at<=transaction_timestamp()) AND candidate.available_at<=transaction_timestamp()
   AND NOT EXISTS(SELECT 1 FROM zasp_attack_lab_outbox live WHERE live.organization_id=candidate.organization_id AND live.topic='attack-lab-jobs' AND live.state='leased' AND live.lease_expires_at>transaction_timestamp())
  GROUP BY candidate.organization_id
 ),ordered_organizations AS (
  SELECT organization_id,due,row_number() OVER(ORDER BY CASE WHEN last_organization IS NULL OR organization_id>last_organization THEN 0 ELSE 1 END,organization_id) fair_order FROM organizations ORDER BY fair_order LIMIT limit_value
 ),picked AS (
  SELECT chosen.ctid,chosen.organization_id,chosen.available_at,chosen.created_at,chosen.outbox_id,organization.fair_order FROM ordered_organizations organization
  CROSS JOIN LATERAL (SELECT outbox.ctid,outbox.organization_id,outbox.available_at,outbox.created_at,outbox.outbox_id FROM zasp_attack_lab_outbox outbox WHERE outbox.organization_id=organization.organization_id AND outbox.topic='attack-lab-jobs' AND outbox.attempt<100 AND (outbox.state='pending' OR outbox.state='leased' AND outbox.lease_expires_at<=transaction_timestamp()) AND outbox.available_at<=transaction_timestamp() ORDER BY outbox.available_at,outbox.created_at,outbox.outbox_id LIMIT 1 FOR UPDATE SKIP LOCKED) chosen
 ),leased AS (
  UPDATE zasp_attack_lab_outbox outbox SET state='leased',attempt=attempt+1,worker_id=worker_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),provider_ack=NULL,published_at=NULL,last_error=NULL,completion_digest=NULL,completion_result=NULL,updated_at=transaction_timestamp() FROM (SELECT * FROM picked ORDER BY fair_order) candidate WHERE outbox.ctid=candidate.ctid RETURNING outbox.*,candidate.fair_order
 ) SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'outbox_id',outbox_id,'topic',topic,'payload',payload::text,'payload_digest',encode(payload_digest,'hex'),'attempt',attempt,'lease_expires_at',lease_expires_at) ORDER BY fair_order),'[]'::jsonb)),(array_agg(organization_id ORDER BY fair_order DESC))[1] INTO result_value,claimed_last_organization FROM leased;
 IF claimed_last_organization IS NOT NULL THEN UPDATE zasp_attack_lab_outbox_fairness SET last_organization_id=claimed_last_organization,updated_at=transaction_timestamp() WHERE topic='attack-lab-jobs';END IF;
 RETURN result_value;
END
$claim$;

CREATE FUNCTION public.zasp_attack_lab_heartbeat_outbox(worker_value text,token_value bytea,lease_seconds integer,expected_count integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
DECLARE expiration_value timestamptz;updated_count integer;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_outbox_worker') OR length(worker_value) NOT BETWEEN 3 AND 128 OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 5 AND 900 OR expected_count NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab outbox heartbeat rejected';END IF;
 expiration_value:=transaction_timestamp()+make_interval(secs=>lease_seconds);
 UPDATE zasp_attack_lab_outbox SET lease_expires_at=expiration_value,updated_at=transaction_timestamp() WHERE topic='attack-lab-jobs' AND state='leased' AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp();GET DIAGNOSTICS updated_count=ROW_COUNT;
 IF updated_count<>expected_count THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab outbox lease set conflict';END IF;
 RETURN jsonb_build_object('topic','attack-lab-jobs','lease_expires_at',expiration_value,'remaining_count',updated_count);
END
$heartbeat$;

CREATE FUNCTION public.zasp_attack_lab_ack_outbox(organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,token_value bytea,ack_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $ack$
DECLARE requested_value bytea;result_value jsonb;published_value timestamptz;remaining_count integer;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_outbox_worker') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(outbox_value) OR length(worker_value) NOT BETWEEN 3 AND 128 OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR ack_value!~'^sha256:[a-f0-9]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab outbox acknowledgement rejected';END IF;
 requested_value:=digest(convert_to(concat_ws(chr(31),outbox_value,worker_value,encode(token_value,'hex'),ack_value),'UTF8'),'sha256');
 SELECT completion_result INTO result_value FROM zasp_attack_lab_outbox WHERE (organization_id,workspace_id,environment_id,outbox_id,topic,state,completion_digest)=(organization_value,workspace_value,environment_value,outbox_value,'attack-lab-jobs','published',requested_value) FOR UPDATE;
 IF FOUND THEN SELECT count(*) INTO remaining_count FROM zasp_attack_lab_outbox WHERE topic='attack-lab-jobs' AND state='leased' AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp();RETURN result_value||jsonb_build_object('remaining_count',remaining_count,'replayed',true);END IF;
 IF EXISTS(SELECT 1 FROM zasp_attack_lab_outbox WHERE (organization_id,workspace_id,environment_id,outbox_id,topic,state)=(organization_value,workspace_value,environment_value,outbox_value,'attack-lab-jobs','published')) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='attack lab outbox acknowledgement conflict';END IF;
 UPDATE zasp_attack_lab_outbox SET state='published',provider_ack=ack_value,published_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,last_error=NULL,completion_digest=requested_value,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,outbox_id,topic,state,worker_id,lease_token)=(organization_value,workspace_value,environment_value,outbox_value,'attack-lab-jobs','leased',worker_value,token_value) AND lease_expires_at>transaction_timestamp() RETURNING published_at INTO published_value;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab outbox lease rejected';END IF;
 result_value:=jsonb_build_object('outbox_id',outbox_value,'state','published','provider_ack',ack_value,'published_at',published_value);UPDATE zasp_attack_lab_outbox SET completion_result=result_value WHERE (organization_id,workspace_id,environment_id,outbox_id)=(organization_value,workspace_value,environment_value,outbox_value);
 SELECT count(*) INTO remaining_count FROM zasp_attack_lab_outbox WHERE topic='attack-lab-jobs' AND state='leased' AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp();RETURN result_value||jsonb_build_object('remaining_count',remaining_count,'replayed',false);
END
$ack$;

CREATE FUNCTION public.zasp_attack_lab_retry_outbox(organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,token_value bytea,retry_seconds integer,error_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $retry$
DECLARE requested_value bytea;result_value jsonb;available_value timestamptz;state_value text;remaining_count integer;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_outbox_worker') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(outbox_value) OR length(worker_value) NOT BETWEEN 3 AND 128 OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR retry_seconds NOT BETWEEN 1 AND 3600 OR error_value<>'queue_publish_unknown' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab outbox retry rejected';END IF;
 requested_value:=digest(convert_to(concat_ws(chr(31),outbox_value,worker_value,encode(token_value,'hex'),retry_seconds::text,error_value),'UTF8'),'sha256');
 SELECT completion_result INTO result_value FROM zasp_attack_lab_outbox WHERE (organization_id,workspace_id,environment_id,outbox_id,topic,completion_digest)=(organization_value,workspace_value,environment_value,outbox_value,'attack-lab-jobs',requested_value) AND state IN('pending','failed') FOR UPDATE;
 IF FOUND THEN SELECT count(*) INTO remaining_count FROM zasp_attack_lab_outbox WHERE topic='attack-lab-jobs' AND state='leased' AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp();RETURN result_value||jsonb_build_object('remaining_count',remaining_count,'replayed',true);END IF;
 UPDATE zasp_attack_lab_outbox SET state=CASE WHEN attempt>=100 THEN 'failed' ELSE 'pending' END,available_at=transaction_timestamp()+make_interval(secs=>retry_seconds),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,last_error=error_value,completion_digest=requested_value,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,outbox_id,topic,state,worker_id,lease_token)=(organization_value,workspace_value,environment_value,outbox_value,'attack-lab-jobs','leased',worker_value,token_value) AND lease_expires_at>transaction_timestamp() RETURNING available_at,state INTO available_value,state_value;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab outbox lease rejected';END IF;
 result_value:=jsonb_build_object('outbox_id',outbox_value,'state',state_value,'available_at',available_value,'error_code',error_value);UPDATE zasp_attack_lab_outbox SET completion_result=result_value WHERE (organization_id,workspace_id,environment_id,outbox_id)=(organization_value,workspace_value,environment_value,outbox_value);
 SELECT count(*) INTO remaining_count FROM zasp_attack_lab_outbox WHERE topic='attack-lab-jobs' AND state='leased' AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp();RETURN result_value||jsonb_build_object('remaining_count',remaining_count,'replayed',false);
END
$retry$;

CREATE FUNCTION public.zasp_attack_lab_claim_run(organization_value text,workspace_value text,environment_value text,run_value text,controller_value text,token_value bytea,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE run_row zasp_attack_lab_runs%ROWTYPE;definition_row zasp_red_team_definitions%ROWTYPE;target_row zasp_inventory_entities%ROWTYPE;binding_row zasp_attack_lab_credential_bindings%ROWTYPE;source_row zasp_red_team_runs%ROWTYPE;source_attempt zasp_red_team_attempts%ROWTYPE;checkpoint_row zasp_attack_lab_cleanup_checkpoints%ROWTYPE;destination_value text;environment_class_value text;preflight_value jsonb;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_controller') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) OR length(controller_value) NOT BETWEEN 3 AND 128 OR controller_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 30 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab run claim rejected';END IF;
 SELECT * INTO run_row FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab run not found';END IF;
 IF run_row.state IN('complete','failed','cancelled') THEN RETURN jsonb_build_object('disposition','ack_terminal');END IF;
 IF run_row.state IN('leased','running','cleanup') AND run_row.lease_expires_at>transaction_timestamp() OR run_row.next_attempt_at>transaction_timestamp() THEN RETURN jsonb_build_object('disposition','retry_later');END IF;
 IF run_row.state='running' AND run_row.attempt_started_at+interval '300 seconds'<=transaction_timestamp() THEN
  UPDATE zasp_attack_lab_cleanup_checkpoints SET evidence_state='unavailable',verdict='inconclusive',criterion_observed=false,canary_touched=false,error_code='outcome_unknown',evidence='[]'::jsonb,evidence_reference=NULL,evidence_key=NULL,evidence_version_id=NULL,evidence_checksum=NULL,evidence_size=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,attempt,input_digest,evidence_state)=(organization_value,workspace_value,environment_value,run_value,run_row.attempt,run_row.input_digest,'pending');
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab expired attempt cleanup intent missing';END IF;
  UPDATE zasp_attack_lab_runs SET version=version+1,state='cleanup',cleanup_state='in_progress',controller_id=controller_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),error_code='outcome_unknown',updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,state)=(organization_value,workspace_value,environment_value,run_value,'running') RETURNING * INTO run_row;
 END IF;
	 IF run_row.state='cleanup' THEN UPDATE zasp_attack_lab_runs SET controller_id=controller_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) RETURNING * INTO run_row;SELECT * INTO STRICT checkpoint_row FROM zasp_attack_lab_cleanup_checkpoints WHERE (organization_id,workspace_id,environment_id,run_id,attempt,input_digest)=(organization_value,workspace_value,environment_value,run_value,run_row.attempt,run_row.input_digest);RETURN jsonb_build_object('disposition','cleanup','run',zasp_attack_lab_run_json(run_row),'checkpoint',jsonb_strip_nulls(jsonb_build_object('attempt',checkpoint_row.attempt,'sandbox_reference',checkpoint_row.sandbox_reference,'evidence_state',checkpoint_row.evidence_state,'verdict',checkpoint_row.verdict,'criterion_observed',checkpoint_row.criterion_observed,'canary_touched',checkpoint_row.canary_touched,'error_code',checkpoint_row.error_code,'evidence',checkpoint_row.evidence,'evidence_reference',checkpoint_row.evidence_reference,'evidence_key',checkpoint_row.evidence_key,'evidence_version_id',checkpoint_row.evidence_version_id,'evidence_checksum',encode(checkpoint_row.evidence_checksum,'hex'),'evidence_size',checkpoint_row.evidence_size)),'input_digest',encode(run_row.input_digest,'hex'),'lease_expires_at',run_row.lease_expires_at);END IF;
	 IF run_row.state='leased' AND run_row.sandbox_name IS NOT NULL THEN
	  UPDATE zasp_attack_lab_runs SET controller_id=controller_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,state)=(organization_value,workspace_value,environment_value,run_value,'leased') AND preflight IS NOT NULL AND sandbox_reference IS NULL RETURNING * INTO run_row;
	  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab provisioning intent missing';END IF;
	  RETURN jsonb_build_object('disposition','provisioning','run',zasp_attack_lab_run_json(run_row),'preflight',run_row.preflight,'sandbox_name',run_row.sandbox_name,'input_digest',encode(run_row.input_digest,'hex'),'lease_expires_at',run_row.lease_expires_at);
	 END IF;
	 IF run_row.state='running' THEN
  UPDATE zasp_attack_lab_runs SET controller_id=controller_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,state)=(organization_value,workspace_value,environment_value,run_value,'running') AND sandbox_reference IS NOT NULL RETURNING * INTO run_row;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab running checkpoint missing';END IF;
	  RETURN jsonb_build_object('disposition','running','run',zasp_attack_lab_run_json(run_row),'preflight',run_row.preflight,'sandbox_reference',run_row.sandbox_reference,'input_digest',encode(run_row.input_digest,'hex'),'lease_expires_at',run_row.lease_expires_at);
 END IF;
 IF run_row.state IN('queued','retryable') AND run_row.attempt>=5 THEN UPDATE zasp_attack_lab_runs SET version=version+1,state='failed',cleanup_state='complete',error_code='exhausted',completed_at=transaction_timestamp(),controller_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) RETURNING * INTO run_row;RETURN jsonb_build_object('disposition','ack_terminal');END IF;
 SELECT * INTO STRICT source_row FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,verdict)=(organization_value,workspace_value,environment_value,run_row.source_run_id,'complete','fail') FOR SHARE;
 SELECT * INTO STRICT source_attempt FROM zasp_red_team_attempts WHERE (organization_id,workspace_id,environment_id,run_id,attempt,verdict)=(organization_value,workspace_value,environment_value,run_row.source_run_id,source_row.attempt,'fail') FOR SHARE;
 SELECT * INTO STRICT definition_row FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,enabled,target_id,target_kind)=(organization_value,workspace_value,environment_value,run_row.definition_id,run_row.definition_version,true,run_row.target_id,run_row.target_kind) FOR SHARE;
 SELECT environment_class INTO STRICT environment_class_value FROM zasp_environments WHERE (organization_id,workspace_id,id)=(organization_value,workspace_value,environment_value);
 SELECT * INTO STRICT target_row FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state)=(organization_value,workspace_value,environment_value,run_row.target_id,'active') AND fresh_until>transaction_timestamp() AND zasp_red_team_target_binding_valid(winning_attributes->'red_team',run_row.target_kind) FOR SHARE;
 SELECT * INTO STRICT binding_row FROM zasp_attack_lab_credential_bindings WHERE (organization_id,workspace_id,environment_id,binding_id,target_id,credential_reference,credential_class,version,reference_digest,state)=(organization_value,workspace_value,environment_value,run_row.credential_binding_id,run_row.target_id,target_row.winning_attributes->'red_team'->>'credential_reference',run_row.credential_class,run_row.credential_binding_version,run_row.credential_binding_digest,'active') AND valid_until>transaction_timestamp() FOR SHARE;
 destination_value:=substring(target_row.winning_attributes->'red_team'->>'endpoint' FROM '^https://([^/]+)/v1/evaluate$');
 IF environment_class_value='production' OR environment_class_value<>run_row.environment OR destination_value IS NULL OR destination_value<>run_row.destination OR definition_row.safety->>'environment'<>run_row.environment OR definition_row.safety->>'credential_class'<>run_row.credential_class THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab run authority drift';END IF;
	 preflight_value:=jsonb_build_object('environment',run_row.environment,'credential_class',run_row.credential_class,'destination',run_row.destination,'allowed_destinations',jsonb_build_array(run_row.destination),'success_criterion',source_attempt.objective,'expected_side_effects',definition_row.safety->'expected_side_effects');
	 UPDATE zasp_attack_lab_runs SET version=version+1,state='leased',attempt=CASE WHEN state IN('queued','retryable') THEN attempt+1 ELSE attempt END,attempt_started_at=transaction_timestamp(),preflight=preflight_value,sandbox_name=NULL,controller_id=controller_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),started_at=COALESCE(started_at,transaction_timestamp()),error_code=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) RETURNING * INTO run_row;
	 RETURN jsonb_build_object('disposition','claimed','run',zasp_attack_lab_run_json(run_row),'preflight',run_row.preflight,'input_digest',encode(run_row.input_digest,'hex'),'lease_expires_at',run_row.lease_expires_at);
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab run authority unavailable';
END
$claim$;

CREATE FUNCTION public.zasp_attack_lab_heartbeat_run(organization_value text,workspace_value text,environment_value text,run_value text,controller_value text,token_value bytea,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
DECLARE cancel_value boolean;expiration_value timestamptz;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_controller') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) OR length(controller_value) NOT BETWEEN 3 AND 128 OR controller_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 30 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab run heartbeat rejected';END IF;
 expiration_value:=transaction_timestamp()+make_interval(secs=>lease_seconds);UPDATE zasp_attack_lab_runs SET lease_expires_at=expiration_value,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,controller_id,lease_token)=(organization_value,workspace_value,environment_value,run_value,controller_value,token_value) AND state IN('leased','running','cleanup') AND lease_expires_at>transaction_timestamp() RETURNING cancel_requested INTO cancel_value;
 RETURN jsonb_build_object('renewed',FOUND,'cancel_requested',COALESCE(cancel_value,false),'lease_expires_at',CASE WHEN FOUND THEN expiration_value END);
END
$heartbeat$;

CREATE FUNCTION public.zasp_attack_lab_retry_run(organization_value text,workspace_value text,environment_value text,run_value text,controller_value text,token_value bytea,input_digest_value bytea,error_value text,retry_at_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $retry_run$
DECLARE run_row zasp_attack_lab_runs%ROWTYPE;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_controller') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) OR length(controller_value) NOT BETWEEN 3 AND 128 OR controller_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR octet_length(input_digest_value)<>32 OR error_value NOT IN('retryable','denied','malformed') OR retry_at_value IS NULL OR retry_at_value<transaction_timestamp() OR retry_at_value>transaction_timestamp()+interval '1 hour' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab run retry rejected';END IF;
 UPDATE zasp_attack_lab_runs SET version=version+1,
  state=CASE WHEN cancel_requested THEN 'cancelled' WHEN error_value='retryable' AND attempt<5 THEN 'retryable' ELSE 'failed' END,
  cleanup_state=CASE WHEN NOT cancel_requested AND error_value='retryable' AND attempt<5 THEN 'pending' ELSE 'complete' END,
  error_code=CASE WHEN cancel_requested THEN 'cancelled' WHEN error_value='retryable' AND attempt>=5 THEN 'exhausted' ELSE error_value END,
  next_attempt_at=retry_at_value,completed_at=CASE WHEN cancel_requested OR error_value<>'retryable' OR attempt>=5 THEN transaction_timestamp() END,
	  preflight=NULL,sandbox_name=NULL,controller_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp()
 WHERE (organization_id,workspace_id,environment_id,run_id,state,controller_id,lease_token,input_digest)=(organization_value,workspace_value,environment_value,run_value,'leased',controller_value,token_value,input_digest_value) AND sandbox_reference IS NULL AND lease_expires_at>transaction_timestamp() RETURNING * INTO run_row;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab run retry lease rejected';END IF;
 IF run_row.state='cancelled' THEN
  INSERT INTO zasp_attack_lab_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,evidence_state,verdict,criterion_observed,canary_touched,cleanup_completed,error_code,evidence,completed_at)
  VALUES(organization_value,workspace_value,environment_value,run_value,run_row.attempt,input_digest_value,'unavailable',NULL,false,false,true,'cancelled','[]'::jsonb,run_row.completed_at);
 END IF;
 RETURN zasp_attack_lab_run_json(run_row);
END
$retry_run$;

CREATE FUNCTION public.zasp_attack_lab_begin_provisioning(organization_value text,workspace_value text,environment_value text,run_value text,controller_value text,token_value bytea,input_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $provision$
DECLARE run_row zasp_attack_lab_runs%ROWTYPE;name_value text;replayed_value boolean:=false;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_controller') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) OR length(controller_value) NOT BETWEEN 3 AND 128 OR controller_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR octet_length(input_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab provisioning intent rejected';END IF;
 name_value:='zasp-attack-lab-'||substring(encode(digest(convert_to(concat_ws(chr(31),organization_value,workspace_value,environment_value,run_value),'UTF8'),'sha256'),'hex') FROM 1 FOR 32);
 IF name_value!~'^zasp-attack-lab-[a-f0-9]{32}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab provisioning identity rejected';END IF;
 SELECT * INTO run_row FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,controller_id,lease_token,input_digest)=(organization_value,workspace_value,environment_value,run_value,'leased',controller_value,token_value,input_digest_value) AND lease_expires_at>transaction_timestamp() AND preflight IS NOT NULL AND sandbox_reference IS NULL FOR UPDATE;
 IF NOT FOUND OR run_row.sandbox_name IS NOT NULL AND run_row.sandbox_name<>name_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab provisioning lease rejected';END IF;
 IF run_row.sandbox_name=name_value THEN replayed_value:=true;ELSE UPDATE zasp_attack_lab_runs SET sandbox_name=name_value,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) RETURNING * INTO run_row;END IF;
 RETURN zasp_attack_lab_run_json(run_row)||jsonb_build_object('replayed',replayed_value);
END
$provision$;

CREATE FUNCTION public.zasp_attack_lab_mark_running(organization_value text,workspace_value text,environment_value text,run_value text,controller_value text,token_value bytea,input_digest_value bytea,sandbox_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $running$
DECLARE run_row zasp_attack_lab_runs%ROWTYPE;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_controller') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) OR length(controller_value) NOT BETWEEN 3 AND 128 OR controller_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR octet_length(input_digest_value)<>32 OR sandbox_value!~'^k8s://attack-lab/jobs/zasp-attack-lab-[a-z0-9-]{8,64}@[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab running transition rejected';END IF;
 SELECT * INTO run_row FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,controller_id,lease_token,input_digest,sandbox_reference)=(organization_value,workspace_value,environment_value,run_value,'running',controller_value,token_value,input_digest_value,sandbox_value) AND lease_expires_at>transaction_timestamp() FOR UPDATE;
 IF FOUND THEN
  IF NOT EXISTS(SELECT 1 FROM zasp_attack_lab_cleanup_checkpoints WHERE (organization_id,workspace_id,environment_id,run_id,attempt,input_digest,sandbox_reference,evidence_state)=(organization_value,workspace_value,environment_value,run_value,run_row.attempt,input_digest_value,sandbox_value,'pending')) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab cleanup intent missing';END IF;
  RETURN zasp_attack_lab_run_json(run_row)||jsonb_build_object('replayed',true);
 END IF;
	 UPDATE zasp_attack_lab_runs SET version=version+1,state='running',sandbox_reference=sandbox_value,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,state,controller_id,lease_token,input_digest)=(organization_value,workspace_value,environment_value,run_value,'leased',controller_value,token_value,input_digest_value) AND lease_expires_at>transaction_timestamp() AND preflight IS NOT NULL AND sandbox_name=substring(sandbox_value FROM '^k8s://attack-lab/jobs/([^@]+)@') AND sandbox_reference IS NULL RETURNING * INTO run_row;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab running lease rejected';END IF;
 INSERT INTO zasp_attack_lab_cleanup_checkpoints(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,sandbox_reference) VALUES(organization_value,workspace_value,environment_value,run_value,run_row.attempt,input_digest_value,sandbox_value);
 RETURN zasp_attack_lab_run_json(run_row)||jsonb_build_object('replayed',false);
END
$running$;

CREATE FUNCTION public.zasp_attack_lab_resolve_egress(organization_value text,workspace_value text,environment_value text,run_value text,destination_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $resolve$
DECLARE run_row zasp_attack_lab_runs%ROWTYPE;definition_row zasp_red_team_definitions%ROWTYPE;target_row zasp_inventory_entities%ROWTYPE;binding_row zasp_attack_lab_credential_bindings%ROWTYPE;expiration_value timestamptz;current_destination text;environment_class_value text;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_proxy') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) OR length(destination_value) NOT BETWEEN 1 AND 253 OR destination_value<>lower(destination_value) OR destination_value!~'^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$' OR destination_value LIKE '%..%' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab egress resolution rejected';END IF;
 SELECT * INTO STRICT run_row FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,destination)=(organization_value,workspace_value,environment_value,run_value,'running',destination_value) AND cleanup_state='pending' AND NOT cancel_requested AND lease_expires_at>transaction_timestamp();
 SELECT * INTO STRICT definition_row FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,enabled,target_id,target_kind)=(organization_value,workspace_value,environment_value,run_row.definition_id,run_row.definition_version,true,run_row.target_id,run_row.target_kind);
 SELECT environment_class INTO STRICT environment_class_value FROM zasp_environments WHERE (organization_id,workspace_id,id)=(organization_value,workspace_value,environment_value);
 SELECT * INTO STRICT target_row FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state)=(organization_value,workspace_value,environment_value,run_row.target_id,'active') AND fresh_until>transaction_timestamp() AND zasp_red_team_target_binding_valid(winning_attributes->'red_team',run_row.target_kind);
 SELECT * INTO STRICT binding_row FROM zasp_attack_lab_credential_bindings WHERE (organization_id,workspace_id,environment_id,binding_id,target_id,credential_reference,credential_class,version,reference_digest,state)=(organization_value,workspace_value,environment_value,run_row.credential_binding_id,run_row.target_id,target_row.winning_attributes->'red_team'->>'credential_reference',run_row.credential_class,run_row.credential_binding_version,run_row.credential_binding_digest,'active') AND valid_until>transaction_timestamp();
 current_destination:=substring(target_row.winning_attributes->'red_team'->>'endpoint' FROM '^https://([^/]+)/v1/evaluate$');
 IF environment_class_value='production' OR environment_class_value<>run_row.environment OR current_destination IS NULL OR current_destination<>run_row.destination OR definition_row.safety->>'environment'<>run_row.environment OR definition_row.safety->>'credential_class'<>run_row.credential_class THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab egress unavailable';END IF;
 expiration_value:=LEAST(run_row.lease_expires_at,run_row.attempt_started_at+interval '300 seconds');IF expiration_value<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab egress expired';END IF;
 RETURN jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value,'run_id',run_value,'destination',destination_value,'credential_reference',binding_row.credential_reference,'methods',jsonb_build_array('POST'),'expires_at',expiration_value);
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab egress unavailable';
END
$resolve$;

CREATE FUNCTION public.zasp_attack_lab_begin_cleanup(organization_value text,workspace_value text,environment_value text,run_value text,controller_value text,token_value bytea,input_digest_value bytea,sandbox_value text,verdict_value text,criterion_value boolean,canary_value boolean,error_value text,evidence_value jsonb,reference_value text,key_value text,version_value text,checksum_value bytea,size_value bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $cleanup$
DECLARE run_row zasp_attack_lab_runs%ROWTYPE;checkpoint_row zasp_attack_lab_cleanup_checkpoints%ROWTYPE;evidence_state_value text;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_controller') OR octet_length(input_digest_value)<>32 OR sandbox_value!~'^k8s://attack-lab/jobs/zasp-attack-lab-[a-z0-9-]{8,64}@[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' OR verdict_value NOT IN('verified','not_reproduced','inconclusive') OR verdict_value='verified' AND (NOT criterion_value OR NOT canary_value) OR verdict_value='not_reproduced' AND (criterion_value OR canary_value) OR verdict_value IN('verified','not_reproduced') AND error_value IS NOT NULL OR verdict_value='inconclusive' AND error_value NOT IN('denied','malformed','outcome_unknown','exhausted','cancelled') OR jsonb_typeof(evidence_value)<>'array' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab cleanup checkpoint rejected';END IF;
 evidence_state_value:=CASE WHEN reference_value='' THEN 'unavailable' ELSE 'complete' END;
 IF evidence_state_value='complete' AND (jsonb_array_length(evidence_value)<>5 OR evidence_value->>0 NOT LIKE 'semantic:%' OR evidence_value->>1 NOT LIKE 'gateway:%' OR evidence_value->>2 NOT LIKE 'egress:%' OR evidence_value->>3 NOT LIKE 'kubernetes:%' OR evidence_value->>4 NOT LIKE 'cloud:%' OR EXISTS(SELECT 1 FROM jsonb_array_elements(evidence_value) item WHERE jsonb_typeof(item)<>'string' OR length(item#>>'{}') NOT BETWEEN 1 AND 512 OR item#>>'{}'<>btrim(item#>>'{}') OR item#>>'{}'~'[[:cntrl:]]') OR reference_value!~'^s3://[a-z0-9][a-z0-9.-]{2,62}/organizations/' OR key_value IS DISTINCT FROM 'organizations/'||organization_value||'/workspaces/'||workspace_value||'/environments/'||environment_value||'/artifacts/'||zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'attack_lab_evidence',run_value||chr(31)||(SELECT attempt::text FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value))) OR substring(reference_value FROM '^s3://[a-z0-9][a-z0-9.-]{2,62}/(.+)$') IS DISTINCT FROM key_value OR length(version_value) NOT BETWEEN 1 AND 512 OR version_value~'[[:space:][:cntrl:]]' OR octet_length(checksum_value)<>32 OR size_value NOT BETWEEN 1 AND 67108864) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab cleanup evidence rejected';END IF;
 IF evidence_state_value='unavailable' AND (verdict_value<>'inconclusive' OR criterion_value OR canary_value OR error_value NOT IN('outcome_unknown','cancelled') OR evidence_value<>'[]'::jsonb OR key_value<>'' OR version_value<>'' OR octet_length(checksum_value)<>0 OR size_value<>0) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab unavailable evidence rejected';END IF;
 SELECT * INTO STRICT run_row FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id,controller_id,lease_token,input_digest,sandbox_reference)=(organization_value,workspace_value,environment_value,run_value,controller_value,token_value,input_digest_value,sandbox_value) AND state IN('running','cleanup') AND lease_expires_at>transaction_timestamp() FOR UPDATE;
 SELECT * INTO STRICT checkpoint_row FROM zasp_attack_lab_cleanup_checkpoints WHERE (organization_id,workspace_id,environment_id,run_id,attempt,input_digest,sandbox_reference)=(organization_value,workspace_value,environment_value,run_value,run_row.attempt,input_digest_value,sandbox_value) FOR UPDATE;
 IF checkpoint_row.evidence_state<>'pending' THEN
  IF (checkpoint_row.evidence_state,checkpoint_row.verdict,checkpoint_row.criterion_observed,checkpoint_row.canary_touched,checkpoint_row.error_code,checkpoint_row.evidence,checkpoint_row.evidence_reference,checkpoint_row.evidence_key,checkpoint_row.evidence_version_id,checkpoint_row.evidence_checksum,checkpoint_row.evidence_size) IS DISTINCT FROM (evidence_state_value,verdict_value,criterion_value,canary_value,error_value,evidence_value,NULLIF(reference_value,''),NULLIF(key_value,''),NULLIF(version_value,''),NULLIF(checksum_value,''::bytea),NULLIF(size_value,0)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='attack lab cleanup checkpoint conflict';END IF;
  IF run_row.state<>'cleanup' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab cleanup state missing';END IF;
  RETURN zasp_attack_lab_run_json(run_row)||jsonb_build_object('replayed',true);
 END IF;
 IF run_row.state<>'running' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab cleanup evidence missing';END IF;
 UPDATE zasp_attack_lab_cleanup_checkpoints SET evidence_state=evidence_state_value,verdict=verdict_value,criterion_observed=criterion_value,canary_touched=canary_value,error_code=error_value,evidence=evidence_value,evidence_reference=NULLIF(reference_value,''),evidence_key=NULLIF(key_value,''),evidence_version_id=NULLIF(version_value,''),evidence_checksum=NULLIF(checksum_value,''::bytea),evidence_size=NULLIF(size_value,0),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(organization_value,workspace_value,environment_value,run_value,run_row.attempt);
 UPDATE zasp_attack_lab_runs SET version=version+1,state='cleanup',cleanup_state='in_progress',updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) RETURNING * INTO run_row;RETURN zasp_attack_lab_run_json(run_row)||jsonb_build_object('replayed',false);
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab cleanup lease rejected';
END
$cleanup$;

CREATE FUNCTION public.zasp_attack_lab_finish_cleanup(organization_value text,workspace_value text,environment_value text,run_value text,controller_value text,token_value bytea,input_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $finish$
DECLARE run_row zasp_attack_lab_runs%ROWTYPE;checkpoint_row zasp_attack_lab_cleanup_checkpoints%ROWTYPE;requested_value bytea;result_value jsonb;
BEGIN
 IF NOT zasp_attack_lab_principal_ready('zasp_attack_lab_controller') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) OR length(controller_value) NOT BETWEEN 3 AND 128 OR controller_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR octet_length(input_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab cleanup completion rejected';END IF;
 requested_value:=digest(convert_to(concat_ws(chr(31),run_value,controller_value,encode(token_value,'hex'),encode(input_digest_value,'hex')),'UTF8'),'sha256');SELECT * INTO checkpoint_row FROM zasp_attack_lab_cleanup_checkpoints WHERE (organization_id,workspace_id,environment_id,run_id,input_digest)=(organization_value,workspace_value,environment_value,run_value,input_digest_value) ORDER BY attempt DESC LIMIT 1 FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab cleanup checkpoint missing';END IF;
 IF checkpoint_row.finish_digest=requested_value THEN RETURN checkpoint_row.finish_result||jsonb_build_object('replayed',true);ELSIF checkpoint_row.finish_digest IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='attack lab cleanup completion conflict';END IF;
 SELECT * INTO STRICT run_row FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,controller_id,lease_token,input_digest,attempt)=(organization_value,workspace_value,environment_value,run_value,'cleanup',controller_value,token_value,input_digest_value,checkpoint_row.attempt) AND lease_expires_at>transaction_timestamp() FOR UPDATE;
 IF run_row.cancel_requested THEN
  INSERT INTO zasp_attack_lab_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,evidence_state,verdict,criterion_observed,canary_touched,cleanup_completed,error_code,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size) VALUES(organization_value,workspace_value,environment_value,run_value,checkpoint_row.attempt,input_digest_value,checkpoint_row.evidence_state,NULL,false,false,true,'cancelled',checkpoint_row.evidence,checkpoint_row.evidence_reference,checkpoint_row.evidence_key,checkpoint_row.evidence_version_id,checkpoint_row.evidence_checksum,checkpoint_row.evidence_size);
  UPDATE zasp_attack_lab_runs SET version=version+1,state='cancelled',cleanup_state='complete',verdict=NULL,error_code='cancelled',evidence_reference=checkpoint_row.evidence_reference,evidence_key=checkpoint_row.evidence_key,evidence_version_id=checkpoint_row.evidence_version_id,evidence_checksum=checkpoint_row.evidence_checksum,evidence_size=checkpoint_row.evidence_size,completed_at=transaction_timestamp(),controller_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) RETURNING * INTO run_row;
 ELSE
  INSERT INTO zasp_attack_lab_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,evidence_state,verdict,criterion_observed,canary_touched,cleanup_completed,error_code,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size) VALUES(organization_value,workspace_value,environment_value,run_value,checkpoint_row.attempt,input_digest_value,checkpoint_row.evidence_state,checkpoint_row.verdict,checkpoint_row.criterion_observed,checkpoint_row.canary_touched,true,checkpoint_row.error_code,checkpoint_row.evidence,checkpoint_row.evidence_reference,checkpoint_row.evidence_key,checkpoint_row.evidence_version_id,checkpoint_row.evidence_checksum,checkpoint_row.evidence_size);
  UPDATE zasp_attack_lab_runs SET version=version+1,state='complete',cleanup_state='complete',verdict=checkpoint_row.verdict,error_code=CASE WHEN checkpoint_row.evidence_state='unavailable' THEN checkpoint_row.error_code END,evidence_reference=checkpoint_row.evidence_reference,evidence_key=checkpoint_row.evidence_key,evidence_version_id=checkpoint_row.evidence_version_id,evidence_checksum=checkpoint_row.evidence_checksum,evidence_size=checkpoint_row.evidence_size,completed_at=transaction_timestamp(),controller_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) RETURNING * INTO run_row;
 END IF;
 result_value:=zasp_attack_lab_run_json(run_row);UPDATE zasp_attack_lab_cleanup_checkpoints SET finish_digest=requested_value,finish_result=result_value,finished_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(organization_value,workspace_value,environment_value,run_value,checkpoint_row.attempt);RETURN result_value||jsonb_build_object('replayed',false);
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab cleanup lease rejected';
END
$finish$;

DO $function_owners$
DECLARE function_value regprocedure;
BEGIN
	 FOREACH function_value IN ARRAY ARRAY[
	  'public.zasp_attack_lab_register_principals(text,text,text,text)'::regprocedure,'public.zasp_attack_lab_principal_ready(text)'::regprocedure,'public.zasp_attack_lab_principals_ready()'::regprocedure,'public.zasp_attack_lab_register_credential_binding(text,text,text,text,text,text,text,bigint,bytea,timestamptz)'::regprocedure,'public.zasp_attack_lab_revoke_credential_binding(text,text,text,text,bigint)'::regprocedure,'public.zasp_attack_lab_run_json(public.zasp_attack_lab_runs)'::regprocedure,'public.zasp_attack_lab_mutation_result(text,text,text,text,text,text,text,text,jsonb)'::regprocedure,
  'public.zasp_attack_lab_list_runs(text,text,text,timestamptz,text,integer)'::regprocedure,'public.zasp_attack_lab_get_run(text,text,text,text)'::regprocedure,'public.zasp_attack_lab_create_run(text,text,text,text,text,text,text,text)'::regprocedure,'public.zasp_attack_lab_cancel_run(text,text,text,text,text,text,bigint,text)'::regprocedure,'public.zasp_attack_lab_rerun(text,text,text,text,text,text,bigint,text,text)'::regprocedure,
  'public.zasp_attack_lab_claim_outbox(text,bytea,integer,integer)'::regprocedure,'public.zasp_attack_lab_heartbeat_outbox(text,bytea,integer,integer)'::regprocedure,'public.zasp_attack_lab_ack_outbox(text,text,text,text,text,bytea,text)'::regprocedure,'public.zasp_attack_lab_retry_outbox(text,text,text,text,text,bytea,integer,text)'::regprocedure,
	  'public.zasp_attack_lab_claim_run(text,text,text,text,text,bytea,integer)'::regprocedure,'public.zasp_attack_lab_heartbeat_run(text,text,text,text,text,bytea,integer)'::regprocedure,'public.zasp_attack_lab_retry_run(text,text,text,text,text,bytea,bytea,text,timestamptz)'::regprocedure,'public.zasp_attack_lab_begin_provisioning(text,text,text,text,text,bytea,bytea)'::regprocedure,'public.zasp_attack_lab_mark_running(text,text,text,text,text,bytea,bytea,text)'::regprocedure,'public.zasp_attack_lab_resolve_egress(text,text,text,text,text)'::regprocedure,'public.zasp_attack_lab_begin_cleanup(text,text,text,text,text,bytea,bytea,text,text,boolean,boolean,text,jsonb,text,text,text,bytea,bigint)'::regprocedure,'public.zasp_attack_lab_finish_cleanup(text,text,text,text,text,bytea,bytea)'::regprocedure
 ] LOOP EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',function_value);END LOOP;
END
$function_owners$;

REVOKE ALL ON FUNCTION public.zasp_attack_lab_register_principals(text,text,text,text),public.zasp_attack_lab_principal_ready(text),public.zasp_attack_lab_principals_ready(),public.zasp_attack_lab_register_credential_binding(text,text,text,text,text,text,text,bigint,bytea,timestamptz),public.zasp_attack_lab_revoke_credential_binding(text,text,text,text,bigint),public.zasp_attack_lab_run_json(public.zasp_attack_lab_runs),public.zasp_attack_lab_mutation_result(text,text,text,text,text,text,text,text,jsonb),public.zasp_attack_lab_list_runs(text,text,text,timestamptz,text,integer),public.zasp_attack_lab_get_run(text,text,text,text),public.zasp_attack_lab_create_run(text,text,text,text,text,text,text,text),public.zasp_attack_lab_cancel_run(text,text,text,text,text,text,bigint,text),public.zasp_attack_lab_rerun(text,text,text,text,text,text,bigint,text,text),public.zasp_attack_lab_claim_outbox(text,bytea,integer,integer),public.zasp_attack_lab_heartbeat_outbox(text,bytea,integer,integer),public.zasp_attack_lab_ack_outbox(text,text,text,text,text,bytea,text),public.zasp_attack_lab_retry_outbox(text,text,text,text,text,bytea,integer,text),public.zasp_attack_lab_claim_run(text,text,text,text,text,bytea,integer),public.zasp_attack_lab_heartbeat_run(text,text,text,text,text,bytea,integer),public.zasp_attack_lab_retry_run(text,text,text,text,text,bytea,bytea,text,timestamptz),public.zasp_attack_lab_begin_provisioning(text,text,text,text,text,bytea,bytea),public.zasp_attack_lab_mark_running(text,text,text,text,text,bytea,bytea,text),public.zasp_attack_lab_resolve_egress(text,text,text,text,text),public.zasp_attack_lab_begin_cleanup(text,text,text,text,text,bytea,bytea,text,text,boolean,boolean,text,jsonb,text,text,text,bytea,bigint),public.zasp_attack_lab_finish_cleanup(text,text,text,text,text,bytea,bytea) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy;
GRANT EXECUTE ON FUNCTION public.zasp_attack_lab_list_runs(text,text,text,timestamptz,text,integer),public.zasp_attack_lab_get_run(text,text,text,text),public.zasp_attack_lab_create_run(text,text,text,text,text,text,text,text),public.zasp_attack_lab_cancel_run(text,text,text,text,text,text,bigint,text),public.zasp_attack_lab_rerun(text,text,text,text,text,text,bigint,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION public.zasp_attack_lab_principal_ready(text) TO zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy;
GRANT EXECUTE ON FUNCTION public.zasp_attack_lab_claim_outbox(text,bytea,integer,integer),public.zasp_attack_lab_heartbeat_outbox(text,bytea,integer,integer),public.zasp_attack_lab_ack_outbox(text,text,text,text,text,bytea,text),public.zasp_attack_lab_retry_outbox(text,text,text,text,text,bytea,integer,text) TO zasp_attack_lab_outbox_worker;
GRANT EXECUTE ON FUNCTION public.zasp_attack_lab_claim_run(text,text,text,text,text,bytea,integer),public.zasp_attack_lab_heartbeat_run(text,text,text,text,text,bytea,integer),public.zasp_attack_lab_retry_run(text,text,text,text,text,bytea,bytea,text,timestamptz),public.zasp_attack_lab_begin_provisioning(text,text,text,text,text,bytea,bytea),public.zasp_attack_lab_mark_running(text,text,text,text,text,bytea,bytea,text),public.zasp_attack_lab_begin_cleanup(text,text,text,text,text,bytea,bytea,text,text,boolean,boolean,text,jsonb,text,text,text,bytea,bigint),public.zasp_attack_lab_finish_cleanup(text,text,text,text,text,bytea,bytea) TO zasp_attack_lab_controller;
GRANT EXECUTE ON FUNCTION public.zasp_attack_lab_resolve_egress(text,text,text,text,text) TO zasp_attack_lab_proxy;

CREATE FUNCTION public.zasp_attack_lab_execution_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_red_team_execution_security_ready()
 AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy') AND (rolsuper OR rolinherit OR rolcanlogin OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
 AND (SELECT count(*) FROM pg_roles WHERE rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy'))=3
 AND (SELECT count(*) FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy') AND member.rolname='zasp_discovery_authority' AND membership.admin_option)=3
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE (granted.rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy') OR member.rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy')) AND NOT (granted.rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy') AND member.rolname='zasp_discovery_authority' AND membership.admin_option) AND NOT EXISTS(SELECT 1 FROM zasp_attack_lab_principal_bindings binding WHERE binding.principal_name=member.rolname AND binding.authority_role=granted.rolname))
 AND has_function_privilege('zasp_security_agent_api','public.zasp_attack_lab_create_run(text,text,text,text,text,text,text,text)','EXECUTE')
 AND has_function_privilege('zasp_security_agent_api','public.zasp_attack_lab_cancel_run(text,text,text,text,text,text,bigint,text)','EXECUTE')
 AND has_function_privilege('zasp_attack_lab_outbox_worker','public.zasp_attack_lab_claim_outbox(text,bytea,integer,integer)','EXECUTE')
 AND has_function_privilege('zasp_attack_lab_outbox_worker','public.zasp_attack_lab_heartbeat_outbox(text,bytea,integer,integer)','EXECUTE')
 AND has_function_privilege('zasp_attack_lab_outbox_worker','public.zasp_attack_lab_ack_outbox(text,text,text,text,text,bytea,text)','EXECUTE')
 AND has_function_privilege('zasp_attack_lab_outbox_worker','public.zasp_attack_lab_retry_outbox(text,text,text,text,text,bytea,integer,text)','EXECUTE')
 AND has_function_privilege('zasp_attack_lab_controller','public.zasp_attack_lab_claim_run(text,text,text,text,text,bytea,integer)','EXECUTE')
 AND has_function_privilege('zasp_attack_lab_controller','public.zasp_attack_lab_heartbeat_run(text,text,text,text,text,bytea,integer)','EXECUTE')
	 AND has_function_privilege('zasp_attack_lab_controller','public.zasp_attack_lab_retry_run(text,text,text,text,text,bytea,bytea,text,timestamptz)','EXECUTE')
	 AND has_function_privilege('zasp_attack_lab_controller','public.zasp_attack_lab_begin_provisioning(text,text,text,text,text,bytea,bytea)','EXECUTE')
 AND has_function_privilege('zasp_attack_lab_controller','public.zasp_attack_lab_mark_running(text,text,text,text,text,bytea,bytea,text)','EXECUTE')
 AND has_function_privilege('zasp_attack_lab_controller','public.zasp_attack_lab_begin_cleanup(text,text,text,text,text,bytea,bytea,text,text,boolean,boolean,text,jsonb,text,text,text,bytea,bigint)','EXECUTE')
 AND has_function_privilege('zasp_attack_lab_controller','public.zasp_attack_lab_finish_cleanup(text,text,text,text,text,bytea,bytea)','EXECUTE')
	 AND has_function_privilege('zasp_attack_lab_proxy','public.zasp_attack_lab_resolve_egress(text,text,text,text,text)','EXECUTE')
	 AND has_function_privilege('zasp_discovery_authority','public.zasp_attack_lab_register_credential_binding(text,text,text,text,text,text,text,bigint,bytea,timestamptz)','EXECUTE')
	 AND has_function_privilege('zasp_discovery_authority','public.zasp_attack_lab_revoke_credential_binding(text,text,text,text,bigint)','EXECUTE')
	 AND NOT has_function_privilege('zasp_security_agent_api','public.zasp_attack_lab_register_credential_binding(text,text,text,text,text,text,text,bigint,bytea,timestamptz)','EXECUTE')
	 AND NOT has_function_privilege('zasp_attack_lab_controller','public.zasp_attack_lab_register_credential_binding(text,text,text,text,text,text,text,bigint,bytea,timestamptz)','EXECUTE')
 AND NOT has_table_privilege('zasp_security_agent_api','public.zasp_attack_lab_runs','SELECT') AND NOT has_table_privilege('zasp_attack_lab_controller','public.zasp_attack_lab_runs','SELECT') AND NOT has_table_privilege('zasp_attack_lab_proxy','public.zasp_attack_lab_runs','SELECT')
$security$;

CREATE FUNCTION public.zasp_attack_lab_execution_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
  SELECT concat_ws('|','prior',zasp_red_team_execution_live_fingerprint())
  UNION ALL SELECT concat_ws('|','role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls) FROM pg_roles WHERE rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy')
  UNION ALL SELECT concat_ws('|','membership',granted.rolname,member.rolname,membership.admin_option) FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy') AND member.rolname='zasp_discovery_authority'
  UNION ALL SELECT concat_ws('|','table',class.relname,owner.rolname,class.relrowsecurity,class.relforcerowsecurity,COALESCE(class.relacl::text,'')) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_attack_lab_%' AND class.relkind IN('r','i')
  UNION ALL SELECT concat_ws('|','index',class.relname,pg_get_indexdef(class.oid)) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_attack_lab_%' AND class.relkind='i'
  UNION ALL SELECT concat_ws('|','column',class.relname,attribute.attname,attribute.atttypid::regtype::text,attribute.attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_attack_lab_%' AND attribute.attnum>0 AND NOT attribute.attisdropped
  UNION ALL SELECT concat_ws('|','constraint',class.relname,constraint_value.conname,constraint_value.contype,constraint_value.convalidated,pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_attack_lab_%'
  UNION ALL SELECT concat_ws('|','policy',class.relname,policy.polname,policy.polpermissive,pg_get_expr(policy.polqual,policy.polrelid),pg_get_expr(policy.polwithcheck,policy.polrelid)) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_attack_lab_%'
  UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_attack_lab_%'
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_attack_lab_execution_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=26 AND name='attack_lab_execution' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='attack-lab-execution-v1')
 AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>26) AND zasp_attack_lab_execution_security_ready() AND zasp_attack_lab_execution_live_fingerprint()=expected_fingerprint
$readiness$;

ALTER FUNCTION public.zasp_attack_lab_execution_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_attack_lab_execution_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_attack_lab_execution_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_attack_lab_execution_security_ready(),public.zasp_attack_lab_execution_live_fingerprint(),public.zasp_attack_lab_execution_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy;
GRANT EXECUTE ON FUNCTION public.zasp_attack_lab_execution_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_api,zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy;

DO $product_release_evolution$
DECLARE definition text;original_definition text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'red-team-execution-v1','attack-lab-execution-v1');definition:=replace(definition,'release."version" = 25','release."version" = 26');definition:=replace(definition,'release."name" = ''red_team_execution''','release."name" = ''attack_lab_execution''');definition:=replace(definition,'later_release."version" > 25','later_release."version" > 26');IF definition=original_definition OR position('attack-lab-execution-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v26 compatibility evolution failed';END IF;EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'red-team-execution-v1','attack-lab-execution-v1');definition:=replace(replace(definition,'release."version"=25','release."version"=26'),'release."version" = 25','release."version" = 26');definition:=replace(replace(definition,'release."name"=''red_team_execution''','release."name"=''attack_lab_execution'''),'release."name" = ''red_team_execution''','release."name" = ''attack_lab_execution''');definition:=replace(replace(definition,'later."version">25','later."version">26'),'later."version" > 25','later."version" > 26');IF definition=original_definition OR position('attack-lab-execution-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v26 compatibility evolution failed';END IF;EXECUTE definition;
END
$product_release_evolution$;

UPDATE public.zasp_schema_metadata SET value='attack-lab-execution-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='red-team-execution-v1';
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('attack_lab_execution_fingerprint', 'fb752d90dd53bbfcee0e6bd75fa2a61c745fa7a37c66afa73d0c632840c3ee8f') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
