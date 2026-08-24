DO $release_guard$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=25 AND name='red_team_execution')
     OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>25)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='red-team-execution-v1')
     OR NOT public.zasp_red_team_execution_security_ready()
     OR public.zasp_red_team_execution_live_fingerprint()<>'5f3a61dcc185dd6667a6e02551338549632338bfc7e21602fdd521e75fd90c48' THEN
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

CREATE TABLE public.zasp_attack_lab_principal_bindings(
  principal_name text PRIMARY KEY,
  authority_role text NOT NULL CHECK(authority_role IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy')),
  registered_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.zasp_attack_lab_runs(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
  version bigint NOT NULL DEFAULT 1,source_run_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,
  target_id text NOT NULL,target_kind text NOT NULL,environment text NOT NULL,credential_class text NOT NULL,destination text NOT NULL,
  requested_by text NOT NULL,state text NOT NULL DEFAULT 'queued',attempt integer NOT NULL DEFAULT 0,cancel_requested boolean NOT NULL DEFAULT false,
  cleanup_state text NOT NULL DEFAULT 'pending',controller_id text,lease_token bytea,lease_expires_at timestamptz,
  queued_at timestamptz NOT NULL DEFAULT transaction_timestamp(),started_at timestamptz,completed_at timestamptz,next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  input_digest bytea NOT NULL,verdict text,error_code text,evidence_reference text,evidence_key text,evidence_version_id text,evidence_checksum bytea,evidence_size bigint,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,source_run_id) REFERENCES public.zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id) REFERENCES public.zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id),
  CHECK(zasp_valid_product_id(run_id) AND zasp_valid_product_id(target_id) AND zasp_valid_product_id(requested_by)),
  CHECK(version BETWEEN 1 AND 1000000 AND definition_version BETWEEN 1 AND 1000000),
  CHECK(target_kind IN('agent_endpoint','mcp_server','coding_agent')),CHECK(environment IN('development','test','staging')),CHECK(credential_class IN('read_only','test_write')),
  CHECK(length(destination) BETWEEN 1 AND 253 AND destination=lower(destination) AND destination~'^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$' AND destination NOT LIKE '%..%'),
  CHECK(state IN('queued','leased','running','retryable','cleanup','complete','failed','cancelled')),CHECK(attempt BETWEEN 0 AND 5),CHECK(cleanup_state IN('pending','in_progress','complete','failed')),
  CHECK((state IN('leased','running','cleanup'))=(controller_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK(controller_id IS NULL OR length(controller_id) BETWEEN 3 AND 128 AND controller_id~'^[a-z][a-z0-9.-]{2,127}$'),CHECK(lease_token IS NULL OR octet_length(lease_token)=32),CHECK(octet_length(input_digest)=32),
  CHECK(verdict IS NULL OR verdict IN('verified','not_reproduced','inconclusive')),CHECK(error_code IS NULL OR error_code IN('retryable','denied','malformed','outcome_unknown','cleanup_failed','cancelled','exhausted')),
  CHECK(evidence_checksum IS NULL OR octet_length(evidence_checksum)=32),CHECK(evidence_size IS NULL OR evidence_size BETWEEN 1 AND 67108864)
);

CREATE TABLE public.zasp_attack_lab_attempts(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,attempt integer NOT NULL,
  input_digest bytea NOT NULL,verdict text NOT NULL,criterion_observed boolean NOT NULL,canary_touched boolean NOT NULL,cleanup_completed boolean NOT NULL,error_code text,
  evidence jsonb NOT NULL,evidence_reference text NOT NULL,evidence_key text NOT NULL,evidence_version_id text NOT NULL,evidence_checksum bytea NOT NULL,evidence_size bigint NOT NULL,
  completed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,attempt),
  FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_attack_lab_runs(organization_id,workspace_id,environment_id,run_id),
  CHECK(attempt BETWEEN 1 AND 5 AND octet_length(input_digest)=32),CHECK(verdict IN('verified','not_reproduced','inconclusive')),
  CHECK(error_code IS NULL OR error_code IN('denied','malformed','outcome_unknown','cleanup_failed','exhausted')),
  CHECK(jsonb_typeof(evidence)='array' AND jsonb_array_length(evidence) BETWEEN 1 AND 5),CHECK(octet_length(evidence_checksum)=32),CHECK(evidence_size BETWEEN 1 AND 67108864),
  CHECK(verdict<>'verified' OR criterion_observed AND canary_touched),CHECK(verdict<>'not_reproduced' OR NOT criterion_observed AND NOT canary_touched),CHECK(cleanup_completed)
);

CREATE TABLE public.zasp_attack_lab_outbox(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,outbox_id text NOT NULL,
  topic text NOT NULL DEFAULT 'attack-lab-jobs',deterministic_key text NOT NULL,payload jsonb NOT NULL,payload_digest bytea NOT NULL,
  state text NOT NULL DEFAULT 'pending',attempt integer NOT NULL DEFAULT 0,worker_id text,lease_token bytea,lease_expires_at timestamptz,
  available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),provider_ack text,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,outbox_id),UNIQUE(organization_id,workspace_id,environment_id,deterministic_key),
  FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id),
  CHECK(zasp_valid_product_id(outbox_id)),CHECK(topic='attack-lab-jobs'),CHECK(length(deterministic_key) BETWEEN 16 AND 256),CHECK(jsonb_typeof(payload)='object'),CHECK(octet_length(payload_digest)=32),
  CHECK(state IN('pending','leased','published','failed')),CHECK(attempt BETWEEN 0 AND 100),
  CHECK((state='leased')=(worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),CHECK(worker_id IS NULL OR length(worker_id) BETWEEN 3 AND 128 AND worker_id~'^[a-z][a-z0-9.-]{2,127}$'),CHECK(lease_token IS NULL OR octet_length(lease_token)=32),CHECK(provider_ack IS NULL OR provider_ack~'^sha256:[a-f0-9]{64}$')
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
  FOREACH table_name IN ARRAY ARRAY['zasp_attack_lab_principal_bindings','zasp_attack_lab_runs','zasp_attack_lab_attempts','zasp_attack_lab_outbox','zasp_attack_lab_request_receipts','zasp_attack_lab_audit'] LOOP
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

CREATE FUNCTION public.zasp_attack_lab_run_json(row_value public.zasp_attack_lab_runs) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $json$
 SELECT jsonb_strip_nulls(jsonb_build_object(
  'id',row_value.run_id,'version',row_value.version,'source_run_id',row_value.source_run_id,'definition_id',row_value.definition_id,'definition_version',row_value.definition_version,
  'target_id',row_value.target_id,'target_kind',row_value.target_kind,'environment',row_value.environment,'credential_class',row_value.credential_class,'destination',row_value.destination,
  'status',row_value.state,'attempt',row_value.attempt,'cancel_requested',row_value.cancel_requested,'cleanup_state',row_value.cleanup_state,
  'limits',jsonb_build_object('cpu','500m','memory','1Gi','ephemeral_storage','2Gi','timeout_seconds',300),
  'queued_at',row_value.queued_at,'started_at',row_value.started_at,'completed_at',row_value.completed_at,'verdict',row_value.verdict,'error_code',row_value.error_code,'evidence_reference',row_value.evidence_reference))
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
 SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('attempt',attempt,'verdict',verdict,'criterion_observed',criterion_observed,'canary_touched',canary_touched,'cleanup_completed',cleanup_completed,'error_code',error_code,'evidence',evidence,'evidence_reference',evidence_reference,'completed_at',completed_at)) ORDER BY attempt) INTO attempt_value FROM zasp_attack_lab_attempts WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
 RETURN zasp_attack_lab_run_json(row_value)||jsonb_build_object('attempts',COALESCE(attempt_value,'[]'::jsonb));
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab run not found';
END
$get$;

CREATE FUNCTION public.zasp_attack_lab_create_run(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,run_value text,source_run_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $create$
DECLARE source_row zasp_red_team_runs%ROWTYPE;definition_row zasp_red_team_definitions%ROWTYPE;target_row zasp_inventory_entities%ROWTYPE;intent_value jsonb;digest_value bytea;receipt_row zasp_attack_lab_request_receipts%ROWTYPE;run_row zasp_attack_lab_runs%ROWTYPE;payload_value jsonb;result_value jsonb;destination_value text;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(source_run_value) OR run_value=source_run_value OR NOT zasp_valid_product_id(correlation_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab create rejected';END IF;
 intent_value:=jsonb_build_object('approved',true,'run_id',run_value,'source_run_id',source_run_value);digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'createAttackLabRun',idempotency_value),0));
 SELECT * INTO receipt_row FROM zasp_attack_lab_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'createAttackLabRun',idempotency_value);
 IF FOUND THEN IF receipt_row.resource_id<>run_value OR receipt_row.expected_version<>0 OR receipt_row.intent_digest<>digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab create replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 SELECT * INTO STRICT source_row FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,verdict)=(organization_value,workspace_value,environment_value,source_run_value,'complete','fail') FOR UPDATE;
 SELECT * INTO STRICT definition_row FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,enabled)=(organization_value,workspace_value,environment_value,source_row.definition_id,source_row.definition_version,true) FOR SHARE;
 SELECT * INTO STRICT target_row FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state)=(organization_value,workspace_value,environment_value,definition_row.target_id,'active') AND fresh_until>transaction_timestamp() AND zasp_red_team_target_binding_valid(winning_attributes->'red_team',definition_row.target_kind) FOR SHARE;
 destination_value:=substring(target_row.winning_attributes->'red_team'->>'endpoint' FROM '^https://([^/]+)/v1/evaluate$');IF destination_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab destination rejected';END IF;
 INSERT INTO zasp_attack_lab_runs(organization_id,workspace_id,environment_id,run_id,source_run_id,definition_id,definition_version,target_id,target_kind,environment,credential_class,destination,requested_by,input_digest)
 VALUES(organization_value,workspace_value,environment_value,run_value,source_run_value,definition_row.definition_id,definition_row.version,definition_row.target_id,definition_row.target_kind,definition_row.safety->>'environment',definition_row.safety->>'credential_class',destination_value,actor_value,digest_value) RETURNING * INTO run_row;
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
DECLARE source_row zasp_attack_lab_runs%ROWTYPE;definition_row zasp_red_team_definitions%ROWTYPE;target_row zasp_inventory_entities%ROWTYPE;intent_value jsonb;digest_value bytea;receipt_row zasp_attack_lab_request_receipts%ROWTYPE;run_row zasp_attack_lab_runs%ROWTYPE;payload_value jsonb;result_value jsonb;destination_value text;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(source_value) OR NOT zasp_valid_product_id(run_value) OR source_value=run_value OR expected_version_value NOT BETWEEN 1 AND 1000000 OR NOT zasp_valid_product_id(correlation_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab rerun rejected';END IF;
 intent_value:=jsonb_build_object('run_id',run_value,'source_attack_lab_run_id',source_value,'expected_version',expected_version_value);digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'rerunAttackLabRun',idempotency_value),0));
 SELECT * INTO receipt_row FROM zasp_attack_lab_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'rerunAttackLabRun',idempotency_value);IF FOUND THEN IF receipt_row.resource_id<>run_value OR receipt_row.expected_version<>expected_version_value OR receipt_row.intent_digest<>digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab rerun replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 SELECT * INTO STRICT source_row FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,run_id,version)=(organization_value,workspace_value,environment_value,source_value,expected_version_value) AND state IN('complete','failed','cancelled') FOR UPDATE;
 SELECT * INTO STRICT definition_row FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,enabled,target_id,target_kind)=(organization_value,workspace_value,environment_value,source_row.definition_id,source_row.definition_version,true,source_row.target_id,source_row.target_kind) FOR SHARE;
 SELECT * INTO STRICT target_row FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state)=(organization_value,workspace_value,environment_value,source_row.target_id,'active') AND fresh_until>transaction_timestamp() AND zasp_red_team_target_binding_valid(winning_attributes->'red_team',source_row.target_kind) FOR SHARE;
 destination_value:=substring(target_row.winning_attributes->'red_team'->>'endpoint' FROM '^https://([^/]+)/v1/evaluate$');IF destination_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab destination rejected';END IF;
 INSERT INTO zasp_attack_lab_runs(organization_id,workspace_id,environment_id,run_id,source_run_id,definition_id,definition_version,target_id,target_kind,environment,credential_class,destination,requested_by,input_digest)
 VALUES(organization_value,workspace_value,environment_value,run_value,source_row.source_run_id,definition_row.definition_id,definition_row.version,definition_row.target_id,definition_row.target_kind,definition_row.safety->>'environment',definition_row.safety->>'credential_class',destination_value,actor_value,digest_value) RETURNING * INTO run_row;
 payload_value:=jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value,'run_id',run_value,'source_run_id',source_row.source_run_id,'definition_id',source_row.definition_id,'definition_version',source_row.definition_version,'target_id',source_row.target_id,'target_kind',source_row.target_kind,'input_digest',encode(digest_value,'hex'));
 INSERT INTO zasp_attack_lab_outbox(organization_id,workspace_id,environment_id,outbox_id,deterministic_key,payload,payload_digest) VALUES(organization_value,workspace_value,environment_value,zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'attack_lab_outbox',run_value),'attack-lab-jobs:'||run_value,payload_value,digest(convert_to(payload_value::text,'UTF8'),'sha256'));
 result_value:=zasp_attack_lab_mutation_result(organization_value,workspace_value,environment_value,actor_value,'rerunAttackLabRun',run_value,correlation_value,idempotency_value,zasp_attack_lab_run_json(run_row));
 INSERT INTO zasp_attack_lab_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent_digest,audit_id,correlation_id,receipt_id,result) VALUES(organization_value,workspace_value,environment_value,actor_value,'rerunAttackLabRun',idempotency_value,run_value,expected_version_value,digest_value,result_value->>'audit_id',result_value->>'correlation_id',result_value->>'receipt_id',result_value);RETURN result_value;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='attack lab rerun source unavailable';
END
$rerun$;

DO $function_owners$
DECLARE function_value regprocedure;
BEGIN
 FOREACH function_value IN ARRAY ARRAY[
  'public.zasp_attack_lab_register_principals(text,text,text,text)'::regprocedure,'public.zasp_attack_lab_principal_ready(text)'::regprocedure,'public.zasp_attack_lab_principals_ready()'::regprocedure,'public.zasp_attack_lab_run_json(public.zasp_attack_lab_runs)'::regprocedure,'public.zasp_attack_lab_mutation_result(text,text,text,text,text,text,text,text,jsonb)'::regprocedure,
  'public.zasp_attack_lab_list_runs(text,text,text,timestamptz,text,integer)'::regprocedure,'public.zasp_attack_lab_get_run(text,text,text,text)'::regprocedure,'public.zasp_attack_lab_create_run(text,text,text,text,text,text,text,text)'::regprocedure,'public.zasp_attack_lab_cancel_run(text,text,text,text,text,text,bigint,text)'::regprocedure,'public.zasp_attack_lab_rerun(text,text,text,text,text,text,bigint,text,text)'::regprocedure
 ] LOOP EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',function_value);END LOOP;
END
$function_owners$;

REVOKE ALL ON FUNCTION public.zasp_attack_lab_register_principals(text,text,text,text),public.zasp_attack_lab_principal_ready(text),public.zasp_attack_lab_principals_ready(),public.zasp_attack_lab_run_json(public.zasp_attack_lab_runs),public.zasp_attack_lab_mutation_result(text,text,text,text,text,text,text,text,jsonb),public.zasp_attack_lab_list_runs(text,text,text,timestamptz,text,integer),public.zasp_attack_lab_get_run(text,text,text,text),public.zasp_attack_lab_create_run(text,text,text,text,text,text,text,text),public.zasp_attack_lab_cancel_run(text,text,text,text,text,text,bigint,text),public.zasp_attack_lab_rerun(text,text,text,text,text,text,bigint,text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy;
GRANT EXECUTE ON FUNCTION public.zasp_attack_lab_list_runs(text,text,text,timestamptz,text,integer),public.zasp_attack_lab_get_run(text,text,text,text),public.zasp_attack_lab_create_run(text,text,text,text,text,text,text,text),public.zasp_attack_lab_cancel_run(text,text,text,text,text,text,bigint,text),public.zasp_attack_lab_rerun(text,text,text,text,text,text,bigint,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION public.zasp_attack_lab_principal_ready(text) TO zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy;

CREATE FUNCTION public.zasp_attack_lab_execution_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_red_team_execution_security_ready()
 AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy') AND (rolsuper OR rolinherit OR rolcanlogin OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
 AND (SELECT count(*) FROM pg_roles WHERE rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy'))=3
 AND (SELECT count(*) FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy') AND member.rolname='zasp_discovery_authority' AND membership.admin_option)=3
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE (granted.rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy') OR member.rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy')) AND NOT (granted.rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy') AND member.rolname='zasp_discovery_authority' AND membership.admin_option) AND NOT EXISTS(SELECT 1 FROM zasp_attack_lab_principal_bindings binding WHERE binding.principal_name=member.rolname AND binding.authority_role=granted.rolname))
 AND has_function_privilege('zasp_security_agent_api','public.zasp_attack_lab_create_run(text,text,text,text,text,text,text,text)','EXECUTE')
 AND has_function_privilege('zasp_security_agent_api','public.zasp_attack_lab_cancel_run(text,text,text,text,text,text,bigint,text)','EXECUTE')
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
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('attack_lab_execution_fingerprint', '0418f278a333033bd22578eba39806d489e9a819978b8aaf3d2ea394ef06ac38') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
