DO $release_guard$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=24 AND name='security_agent_session_isolation')
     OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>24)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-session-isolation-v1') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team execution release drift';
  END IF;
END
$release_guard$;

DO $roles$
DECLARE role_name text; role_row record;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter'] LOOP
    SELECT * INTO role_row FROM pg_roles WHERE rolname=role_name;
    IF FOUND THEN
      IF role_row.rolsuper OR role_row.rolinherit OR role_row.rolcreaterole OR role_row.rolcreatedb OR role_row.rolcanlogin OR role_row.rolreplication OR role_row.rolbypassrls
         OR EXISTS(SELECT 1 FROM pg_auth_members membership WHERE membership.member=role_row.oid OR membership.roleid=role_row.oid) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team execution role rejected';
      END IF;
    ELSE
      EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',role_name);
    END IF;
  END LOOP;
END
$roles$;
GRANT zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter TO zasp_discovery_authority WITH ADMIN OPTION;

CREATE TABLE public.zasp_red_team_principal_bindings(
  principal_name text PRIMARY KEY,
  authority_role text NOT NULL CHECK(authority_role IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter')),
  registered_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.zasp_red_team_definitions(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
  definition_id text NOT NULL,version bigint NOT NULL DEFAULT 1,name text NOT NULL,target_id text NOT NULL,
  target_kind text NOT NULL,categories jsonb NOT NULL,safety jsonb NOT NULL,enabled boolean NOT NULL DEFAULT true,
  created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id),
  CHECK(zasp_valid_product_id(definition_id) AND zasp_valid_product_id(target_id) AND zasp_valid_product_id(created_by)),
  CHECK(version BETWEEN 1 AND 1000000),CHECK(length(name) BETWEEN 1 AND 128 AND name=btrim(name)),
  CHECK(target_kind IN('agent_endpoint','mcp_server','coding_agent')),
  CHECK(jsonb_typeof(categories)='array' AND jsonb_array_length(categories) BETWEEN 1 AND 16),
  CHECK(jsonb_typeof(safety)='object' AND safety ?& ARRAY['environment','credential_class','expected_side_effects'] AND safety-ARRAY['environment','credential_class','expected_side_effects']='{}'::jsonb)
);
CREATE TABLE public.zasp_red_team_runs(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
  version bigint NOT NULL DEFAULT 1,definition_id text NOT NULL,definition_version bigint NOT NULL,requested_by text NOT NULL,state text NOT NULL DEFAULT 'queued',
  attempt integer NOT NULL DEFAULT 0,cancel_requested boolean NOT NULL DEFAULT false,worker_id text,lease_token bytea,lease_expires_at timestamptz,
  queued_at timestamptz NOT NULL DEFAULT transaction_timestamp(),started_at timestamptz,completed_at timestamptz,next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  input_digest bytea NOT NULL,verdict text,error_code text,evidence_reference text,evidence_key text,evidence_version_id text,evidence_checksum bytea,evidence_size bigint,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id) REFERENCES public.zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id),
  CHECK(zasp_valid_product_id(run_id) AND zasp_valid_product_id(requested_by)),CHECK(version BETWEEN 1 AND 1000000),CHECK(definition_version BETWEEN 1 AND 1000000),
  CHECK(state IN('queued','leased','retryable','complete','failed','cancelled')),CHECK(attempt BETWEEN 0 AND 5),CHECK(octet_length(input_digest)=32),
  CHECK((state='leased')=(worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK(worker_id IS NULL OR length(worker_id) BETWEEN 3 AND 128 AND worker_id~'^[a-z][a-z0-9.-]{2,127}$'),CHECK(lease_token IS NULL OR octet_length(lease_token)=32),
  CHECK(verdict IS NULL OR verdict IN('pass','fail','engine_error')),CHECK(error_code IS NULL OR error_code IN('retryable','rate_limited','denied','malformed','outcome_unknown','cancelled','exhausted')),
  CHECK(evidence_checksum IS NULL OR octet_length(evidence_checksum)=32),CHECK(evidence_size IS NULL OR evidence_size BETWEEN 1 AND 67108864)
);
CREATE TABLE public.zasp_red_team_attempts(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,attempt integer NOT NULL,
  input_digest bytea NOT NULL,verdict text NOT NULL,objective text NOT NULL,behavior text NOT NULL,error_code text,
  evidence jsonb NOT NULL,evidence_reference text NOT NULL,evidence_key text NOT NULL,evidence_version_id text NOT NULL,evidence_checksum bytea NOT NULL,evidence_size bigint NOT NULL,
  completed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,attempt),
  FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id),
  CHECK(attempt BETWEEN 1 AND 5),CHECK(octet_length(input_digest)=32),CHECK(verdict IN('pass','fail','engine_error')),
  CHECK(length(objective) BETWEEN 1 AND 512 AND length(behavior) BETWEEN 1 AND 2048),CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 64),
  CHECK(jsonb_typeof(evidence)='array' AND jsonb_array_length(evidence)<=64),CHECK(octet_length(evidence_checksum)=32),CHECK(evidence_size BETWEEN 1 AND 67108864)
);
CREATE TABLE public.zasp_red_team_outbox(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,outbox_id text NOT NULL,
  topic text NOT NULL DEFAULT 'test-jobs',deterministic_key text NOT NULL,payload jsonb NOT NULL,payload_digest bytea NOT NULL,
  state text NOT NULL DEFAULT 'pending',attempt integer NOT NULL DEFAULT 0,worker_id text,lease_token bytea,lease_expires_at timestamptz,
  available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),provider_ack text,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,outbox_id),UNIQUE(organization_id,workspace_id,environment_id,deterministic_key),
  FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id),
  CHECK(zasp_valid_product_id(outbox_id)),CHECK(topic='test-jobs'),CHECK(length(deterministic_key) BETWEEN 16 AND 256),CHECK(jsonb_typeof(payload)='object'),CHECK(octet_length(payload_digest)=32),
  CHECK(state IN('pending','leased','published','failed')),CHECK(attempt BETWEEN 0 AND 100),
  CHECK((state='leased')=(worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),CHECK(worker_id IS NULL OR length(worker_id) BETWEEN 3 AND 128 AND worker_id~'^[a-z][a-z0-9.-]{2,127}$'),CHECK(lease_token IS NULL OR octet_length(lease_token)=32),
  CHECK(provider_ack IS NULL OR provider_ack~'^sha256:[a-f0-9]{64}$')
);
CREATE TABLE public.zasp_red_team_request_receipts(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,principal_id text NOT NULL,operation text NOT NULL,idempotency_key text NOT NULL,
  resource_id text NOT NULL,expected_version bigint NOT NULL,intent_digest bytea NOT NULL,audit_id text NOT NULL,correlation_id text NOT NULL,receipt_id text NOT NULL,result jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),expires_at timestamptz NOT NULL DEFAULT transaction_timestamp()+interval '24 hours',
  PRIMARY KEY(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key),
  CHECK(zasp_valid_product_id(principal_id) AND zasp_valid_product_id(resource_id) AND zasp_valid_product_id(audit_id) AND zasp_valid_product_id(correlation_id) AND zasp_valid_product_id(receipt_id)),CHECK(operation IN('createTest','updateTest','runTest','cancelTestRun')),CHECK(length(idempotency_key) BETWEEN 16 AND 128),CHECK(expected_version BETWEEN 0 AND 1000000),CHECK(octet_length(intent_digest)=32),CHECK(jsonb_typeof(result)='object')
);
CREATE TABLE public.zasp_red_team_audit(
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,audit_id text NOT NULL,correlation_id text NOT NULL,receipt_id text NOT NULL,
  actor_id text NOT NULL,event_kind text NOT NULL,resource_id text NOT NULL,event_digest bytea NOT NULL,body jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,audit_id),UNIQUE(organization_id,receipt_id),
  CHECK(zasp_valid_product_id(audit_id) AND zasp_valid_product_id(correlation_id) AND zasp_valid_product_id(receipt_id) AND zasp_valid_product_id(actor_id) AND zasp_valid_product_id(resource_id)),
  CHECK(event_kind IN('red_team_definition_created','red_team_definition_updated','red_team_run_queued','red_team_run_cancelled')),CHECK(octet_length(event_digest)=32),CHECK(jsonb_typeof(body)='object')
);

CREATE INDEX zasp_red_team_definitions_list_idx ON public.zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id);
CREATE INDEX zasp_red_team_runs_list_idx ON public.zasp_red_team_runs(organization_id,workspace_id,environment_id,queued_at DESC,run_id DESC);
CREATE INDEX zasp_red_team_runs_claim_idx ON public.zasp_red_team_runs(next_attempt_at,queued_at) WHERE state IN('queued','retryable','leased');
CREATE INDEX zasp_red_team_outbox_claim_idx ON public.zasp_red_team_outbox(available_at,created_at) WHERE state IN('pending','leased');
CREATE INDEX zasp_red_team_receipts_expiry_idx ON public.zasp_red_team_request_receipts(expires_at);

DO $authority$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['zasp_red_team_principal_bindings','zasp_red_team_definitions','zasp_red_team_runs','zasp_red_team_attempts','zasp_red_team_outbox','zasp_red_team_request_receipts','zasp_red_team_audit'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',table_name);
    EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',table_name||'_authority',table_name);
    EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter',table_name);
    EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO zasp_discovery_authority',table_name);
  END LOOP;
END
$authority$;

CREATE FUNCTION public.zasp_red_team_register_principals(migration_principal text,worker_principal text,outbox_principal text,adapter_principal text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $register$
DECLARE principals text[]:=ARRAY[worker_principal,outbox_principal,adapter_principal];authorities text[]:=ARRAY['zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter'];index_value integer;role_value record;
BEGIN
  IF migration_principal<>session_user OR cardinality(ARRAY(SELECT DISTINCT unnest(ARRAY[migration_principal,worker_principal,outbox_principal,adapter_principal])))<>4 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team principals rejected';END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('zasp-red-team-principal-registration',0));
  FOR index_value IN 1..3 LOOP
    SELECT role_row.oid,role_row.rolcanlogin,role_row.rolsuper,role_row.rolcreatedb,role_row.rolcreaterole,role_row.rolreplication,role_row.rolinherit,role_row.rolbypassrls INTO role_value FROM pg_roles role_row WHERE role_row.rolname=principals[index_value];
    IF NOT FOUND OR NOT role_value.rolcanlogin OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR NOT role_value.rolinherit OR role_value.rolbypassrls OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=role_value.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>authorities[index_value]) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team principal rejected';END IF;
    EXECUTE format('GRANT %I TO %I',authorities[index_value],principals[index_value]);
    INSERT INTO zasp_red_team_principal_bindings(principal_name,authority_role) VALUES(principals[index_value],authorities[index_value]) ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role WHERE zasp_red_team_principal_bindings.authority_role=excluded.authority_role;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='red team principal conflict';END IF;
  END LOOP;
  RETURN true;
END
$register$;

CREATE FUNCTION public.zasp_red_team_principal_ready(expected_authority text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $principal$
 SELECT expected_authority IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter')
 AND EXISTS(SELECT 1 FROM zasp_red_team_principal_bindings binding JOIN pg_roles role_value ON role_value.rolname=binding.principal_name WHERE binding.principal_name=session_user AND binding.authority_role=expected_authority AND role_value.rolcanlogin AND role_value.rolinherit AND NOT role_value.rolsuper AND NOT role_value.rolcreatedb AND NOT role_value.rolcreaterole AND NOT role_value.rolreplication AND NOT role_value.rolbypassrls)
 AND pg_has_role(session_user,expected_authority,'MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
$principal$;

CREATE FUNCTION public.zasp_red_team_principals_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $principals$
 SELECT (SELECT count(*) FROM zasp_red_team_principal_bindings)=3
 AND NOT EXISTS(
   SELECT 1 FROM zasp_red_team_principal_bindings binding
   LEFT JOIN pg_roles principal ON principal.rolname=binding.principal_name
   LEFT JOIN pg_roles authority ON authority.rolname=binding.authority_role
   WHERE principal.oid IS NULL OR authority.oid IS NULL OR NOT principal.rolcanlogin OR NOT principal.rolinherit OR principal.rolsuper OR principal.rolcreatedb OR principal.rolcreaterole OR principal.rolreplication OR principal.rolbypassrls
     OR NOT pg_has_role(principal.rolname,authority.rolname,'MEMBER')
     OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=principal.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>authority.rolname)
 )
$principals$;

CREATE FUNCTION public.zasp_red_team_definition_valid(name_value text,target_value text,target_kind_value text,categories_value jsonb,safety_value jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog, public AS $valid$
 SELECT length(name_value) BETWEEN 1 AND 128 AND name_value=btrim(name_value) AND zasp_valid_product_id(target_value) AND target_kind_value IN('agent_endpoint','mcp_server','coding_agent')
 AND jsonb_typeof(categories_value)='array' AND jsonb_array_length(categories_value) BETWEEN 1 AND 16
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(categories_value) category WHERE jsonb_typeof(category)<>'string' OR category#>>'{}' NOT IN('prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information'))
 AND (SELECT count(*)=count(DISTINCT category#>>'{}') FROM jsonb_array_elements(categories_value) category)
 AND jsonb_typeof(safety_value)='object' AND safety_value ?& ARRAY['environment','credential_class','expected_side_effects'] AND safety_value-ARRAY['environment','credential_class','expected_side_effects']='{}'::jsonb
 AND safety_value->>'environment' IN('development','test','staging') AND safety_value->>'credential_class' IN('read_only','test_write')
 AND jsonb_typeof(safety_value->'expected_side_effects')='array' AND jsonb_array_length(safety_value->'expected_side_effects') BETWEEN 1 AND 16
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(safety_value->'expected_side_effects') item WHERE jsonb_typeof(item)<>'string' OR length(item#>>'{}') NOT BETWEEN 1 AND 256 OR item#>>'{}'<>btrim(item#>>'{}'))
$valid$;

CREATE FUNCTION public.zasp_red_team_target_binding_valid(attributes_value jsonb,target_kind_value text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog, public AS $binding$
 SELECT jsonb_typeof(attributes_value)='object' AND attributes_value ?& ARRAY['enabled','endpoint','credential_reference','target_kinds'] AND attributes_value-ARRAY['enabled','endpoint','credential_reference','target_kinds']='{}'::jsonb
 AND attributes_value->'enabled'='true'::jsonb AND jsonb_typeof(attributes_value->'endpoint')='string' AND jsonb_typeof(attributes_value->'credential_reference')='string' AND jsonb_typeof(attributes_value->'target_kinds')='array'
 AND attributes_value->>'endpoint'~'^https://[a-z0-9][a-z0-9.-]{1,253}/v1/evaluate$' AND attributes_value->>'endpoint' NOT LIKE '%..%' AND attributes_value->>'endpoint' NOT LIKE 'https://localhost/%' AND attributes_value->>'endpoint' NOT LIKE '%.local/%' AND attributes_value->>'endpoint' NOT LIKE '%.internal/%' AND attributes_value->>'endpoint' NOT LIKE '%.svc/%'
 AND attributes_value->>'credential_reference'~'^ref:red-team/[a-z][a-z0-9_-]{7,127}$'
 AND jsonb_array_length(attributes_value->'target_kinds') BETWEEN 1 AND 3
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(attributes_value->'target_kinds') kind_value WHERE jsonb_typeof(kind_value)<>'string' OR kind_value#>>'{}' NOT IN('agent_endpoint','mcp_server','coding_agent'))
 AND (SELECT count(*)=count(DISTINCT kind_value#>>'{}') FROM jsonb_array_elements(attributes_value->'target_kinds') kind_value)
 AND EXISTS(SELECT 1 FROM jsonb_array_elements_text(attributes_value->'target_kinds') kind_value WHERE kind_value=target_kind_value)
$binding$;

CREATE FUNCTION public.zasp_red_team_target_valid(organization_value text,workspace_value text,environment_value text,target_value text,target_kind_value text) RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $target$
 SELECT zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value) AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(target_value)
 AND target_kind_value IN('agent_endpoint','mcp_server','coding_agent')
 AND EXISTS(
   SELECT 1 FROM zasp_inventory_entities entity_value
   WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.state)=(organization_value,workspace_value,environment_value,target_value,'active')
     AND entity_value.product_kind=CASE target_kind_value WHEN 'mcp_server' THEN 'tool' ELSE 'agent' END
     AND entity_value.fresh_until>transaction_timestamp()
     AND zasp_red_team_target_binding_valid(entity_value.winning_attributes->'red_team',target_kind_value)
 )
$target$;

CREATE FUNCTION public.zasp_red_team_resolve_target(organization_value text,workspace_value text,environment_value text,target_value text,target_kind_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $resolve$
DECLARE result_value jsonb;
BEGIN
 IF NOT zasp_red_team_principal_ready('zasp_red_team_adapter') OR NOT zasp_red_team_target_valid(organization_value,workspace_value,environment_value,target_value,target_kind_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team target resolution rejected';END IF;
 SELECT jsonb_build_object('target_id',entity_value.id,'target_kind',target_kind_value,'endpoint',entity_value.winning_attributes->'red_team'->>'endpoint','credential_reference',entity_value.winning_attributes->'red_team'->>'credential_reference','version',entity_value.version) INTO STRICT result_value
 FROM zasp_inventory_entities entity_value
 JOIN zasp_inventory_source_observations observation ON (observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.provider,observation.source,observation.entity_id,observation.source_native_id,observation.snapshot_id,observation.generation,observation.evidence_id,observation.source_state)=(entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.winning_integration_id,entity_value.winning_provider,entity_value.winning_source,entity_value.id,entity_value.winning_source_native_id,entity_value.winning_snapshot_id,entity_value.winning_generation,entity_value.winning_evidence_id,'present')
 JOIN zasp_discovery_snapshots snapshot_value ON (snapshot_value.organization_id,snapshot_value.workspace_id,snapshot_value.environment_id,snapshot_value.integration_id,snapshot_value.source,snapshot_value.id,snapshot_value.state,snapshot_value.complete,snapshot_value.is_last_good)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.source,observation.snapshot_id,'complete',true,true)
 JOIN zasp_inventory_evidence evidence_value ON (evidence_value.organization_id,evidence_value.workspace_id,evidence_value.environment_id,evidence_value.id,evidence_value.integration_id,evidence_value.snapshot_id,evidence_value.entity_id,evidence_value.source,evidence_value.generation)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.evidence_id,observation.integration_id,observation.snapshot_id,observation.entity_id,observation.source,observation.generation)
 WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,target_value,'active',CASE target_kind_value WHEN 'mcp_server' THEN 'tool' ELSE 'agent' END) AND entity_value.fresh_until>transaction_timestamp() AND zasp_red_team_target_binding_valid(entity_value.winning_attributes->'red_team',target_kind_value);
 RETURN result_value;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='red team target unavailable';
END
$resolve$;

CREATE FUNCTION public.zasp_red_team_definition_json(row_value public.zasp_red_team_definitions) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $json$
 SELECT jsonb_build_object('id',row_value.definition_id,'version',row_value.version,'name',row_value.name,'target_id',row_value.target_id,'target_kind',row_value.target_kind,'categories',row_value.categories,'safety',row_value.safety,'enabled',row_value.enabled,'created_at',row_value.created_at,'updated_at',row_value.updated_at)
$json$;
CREATE FUNCTION public.zasp_red_team_run_json(row_value public.zasp_red_team_runs) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $json$
 SELECT jsonb_strip_nulls(jsonb_build_object('id',row_value.run_id,'version',row_value.version,'definition_id',row_value.definition_id,'definition_version',row_value.definition_version,'status',row_value.state,'attempt',row_value.attempt,'cancel_requested',row_value.cancel_requested,'queued_at',row_value.queued_at,'started_at',row_value.started_at,'completed_at',row_value.completed_at,'verdict',row_value.verdict,'error_code',row_value.error_code,'evidence_reference',row_value.evidence_reference))
$json$;

CREATE FUNCTION public.zasp_red_team_mutation_result(organization_value text,workspace_value text,environment_value text,actor_value text,operation_value text,resource_value text,correlation_value text,idempotency_value text,body_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $mutation$
DECLARE audit_value text;receipt_value text;event_value text;result_value jsonb;
BEGIN
 IF operation_value NOT IN('createTest','updateTest','runTest','cancelTestRun') OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(resource_value) OR NOT zasp_valid_product_id(correlation_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR jsonb_typeof(body_value)<>'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team mutation result rejected';END IF;
 audit_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'red_team_audit',actor_value||chr(31)||operation_value||chr(31)||idempotency_value);
 receipt_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'red_team_receipt',actor_value||chr(31)||operation_value||chr(31)||idempotency_value);
 event_value:=CASE operation_value WHEN 'createTest' THEN 'red_team_definition_created' WHEN 'updateTest' THEN 'red_team_definition_updated' WHEN 'runTest' THEN 'red_team_run_queued' ELSE 'red_team_run_cancelled' END;
 result_value:=jsonb_build_object('body',body_value,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
 INSERT INTO zasp_red_team_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,receipt_id,actor_id,event_kind,resource_id,event_digest,body) VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,receipt_value,actor_value,event_value,resource_value,digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
 RETURN result_value;
END
$mutation$;

CREATE FUNCTION public.zasp_red_team_list_definitions(organization_value text,workspace_value text,environment_value text,after_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $list$
DECLARE result_value jsonb;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR limit_value NOT BETWEEN 1 AND 100 OR after_value IS NOT NULL AND NOT zasp_valid_product_id(after_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team list rejected';END IF;
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(zasp_red_team_definition_json(definition_row) ORDER BY definition_id),'[]'::jsonb),'next_cursor',CASE WHEN count(*)=limit_value THEN max(definition_id) END) INTO result_value FROM (SELECT * FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND (after_value IS NULL OR definition_id>after_value) ORDER BY definition_id LIMIT limit_value) definition_row;
 RETURN result_value;
END
$list$;
CREATE FUNCTION public.zasp_red_team_get_definition(organization_value text,workspace_value text,environment_value text,definition_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $get$
DECLARE row_value zasp_red_team_definitions%ROWTYPE;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(definition_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team definition rejected';END IF;
 SELECT * INTO STRICT row_value FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(organization_value,workspace_value,environment_value,definition_value);RETURN zasp_red_team_definition_json(row_value);
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='red team definition not found';
END
$get$;
CREATE FUNCTION public.zasp_red_team_create_definition(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,definition_value text,name_value text,target_value text,target_kind_value text,categories_value jsonb,safety_value jsonb,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $create$
DECLARE intent_value jsonb;digest_value bytea;receipt_row zasp_red_team_request_receipts%ROWTYPE;created_row zasp_red_team_definitions%ROWTYPE;result_value jsonb;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(definition_value) OR NOT zasp_valid_product_id(correlation_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' OR NOT zasp_red_team_definition_valid(name_value,target_value,target_kind_value,categories_value,safety_value) OR NOT zasp_red_team_target_valid(organization_value,workspace_value,environment_value,target_value,target_kind_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team definition rejected';END IF;
 intent_value:=jsonb_build_object('definition_id',definition_value,'name',name_value,'target_id',target_value,'target_kind',target_kind_value,'categories',categories_value,'safety',safety_value);digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'createTest',idempotency_value),0));
 SELECT * INTO receipt_row FROM zasp_red_team_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'createTest',idempotency_value);
 IF FOUND THEN IF receipt_row.resource_id<>definition_value OR receipt_row.expected_version<>0 OR receipt_row.intent_digest<>digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team definition replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES(organization_value,workspace_value,environment_value,definition_value,name_value,target_value,target_kind_value,categories_value,safety_value,actor_value) RETURNING * INTO created_row;result_value:=zasp_red_team_mutation_result(organization_value,workspace_value,environment_value,actor_value,'createTest',definition_value,correlation_value,idempotency_value,zasp_red_team_definition_json(created_row));
 INSERT INTO zasp_red_team_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent_digest,audit_id,correlation_id,receipt_id,result) VALUES(organization_value,workspace_value,environment_value,actor_value,'createTest',idempotency_value,definition_value,0,digest_value,result_value->>'audit_id',result_value->>'correlation_id',result_value->>'receipt_id',result_value);RETURN result_value;
END
$create$;
CREATE FUNCTION public.zasp_red_team_update_definition(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,definition_value text,expected_version bigint,name_value text,target_value text,target_kind_value text,categories_value jsonb,safety_value jsonb,enabled_value boolean,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $update$
DECLARE intent_value jsonb;digest_value bytea;receipt_row zasp_red_team_request_receipts%ROWTYPE;updated_row zasp_red_team_definitions%ROWTYPE;result_value jsonb;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR expected_version NOT BETWEEN 1 AND 999999 OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(definition_value) OR NOT zasp_valid_product_id(correlation_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' OR NOT zasp_red_team_definition_valid(name_value,target_value,target_kind_value,categories_value,safety_value) OR NOT zasp_red_team_target_valid(organization_value,workspace_value,environment_value,target_value,target_kind_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team definition rejected';END IF;
 intent_value:=jsonb_build_object('definition_id',definition_value,'expected_version',expected_version,'name',name_value,'target_id',target_value,'target_kind',target_kind_value,'categories',categories_value,'safety',safety_value,'enabled',enabled_value);digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'updateTest',idempotency_value),0));
 SELECT * INTO receipt_row FROM zasp_red_team_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'updateTest',idempotency_value);IF FOUND THEN IF receipt_row.resource_id<>definition_value OR receipt_row.expected_version<>expected_version OR receipt_row.intent_digest<>digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team definition replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 UPDATE zasp_red_team_definitions SET version=version+1,name=name_value,target_id=target_value,target_kind=target_kind_value,categories=categories_value,safety=safety_value,enabled=enabled_value,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(organization_value,workspace_value,environment_value,definition_value,expected_version) RETURNING * INTO updated_row;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team definition version conflict';END IF;result_value:=zasp_red_team_mutation_result(organization_value,workspace_value,environment_value,actor_value,'updateTest',definition_value,correlation_value,idempotency_value,zasp_red_team_definition_json(updated_row));
 INSERT INTO zasp_red_team_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent_digest,audit_id,correlation_id,receipt_id,result) VALUES(organization_value,workspace_value,environment_value,actor_value,'updateTest',idempotency_value,definition_value,expected_version,digest_value,result_value->>'audit_id',result_value->>'correlation_id',result_value->>'receipt_id',result_value);RETURN result_value;
END
$update$;

CREATE FUNCTION public.zasp_red_team_run_test(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,definition_value text,definition_version_value bigint,run_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $run$
DECLARE definition_row zasp_red_team_definitions%ROWTYPE;intent_value jsonb;digest_value bytea;receipt_row zasp_red_team_request_receipts%ROWTYPE;run_row zasp_red_team_runs%ROWTYPE;payload_value jsonb;result_value jsonb;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(definition_value) OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(correlation_value) OR definition_version_value NOT BETWEEN 1 AND 1000000 OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team run rejected';END IF;
 intent_value:=jsonb_build_object('definition_id',definition_value,'definition_version',definition_version_value,'run_id',run_value);digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'runTest',idempotency_value),0));
 SELECT * INTO receipt_row FROM zasp_red_team_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'runTest',idempotency_value);IF FOUND THEN IF receipt_row.resource_id<>run_value OR receipt_row.expected_version<>definition_version_value OR receipt_row.intent_digest<>digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team run replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 SELECT * INTO STRICT definition_row FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,enabled)=(organization_value,workspace_value,environment_value,definition_value,definition_version_value,true) AND zasp_red_team_target_valid(organization_id,workspace_id,environment_id,target_id,target_kind) FOR UPDATE;
 INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest) VALUES(organization_value,workspace_value,environment_value,run_value,definition_value,definition_version_value,actor_value,digest_value) RETURNING * INTO run_row;
 payload_value:=jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value,'run_id',run_value,'definition_id',definition_value,'definition_version',definition_version_value,'input_digest',encode(digest_value,'hex'));
 INSERT INTO zasp_red_team_outbox(organization_id,workspace_id,environment_id,outbox_id,deterministic_key,payload,payload_digest) VALUES(organization_value,workspace_value,environment_value,zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'red_team_outbox',run_value),'test-jobs:'||run_value,payload_value,digest(convert_to(payload_value::text,'UTF8'),'sha256'));
 result_value:=zasp_red_team_mutation_result(organization_value,workspace_value,environment_value,actor_value,'runTest',run_value,correlation_value,idempotency_value,zasp_red_team_run_json(run_row));INSERT INTO zasp_red_team_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent_digest,audit_id,correlation_id,receipt_id,result) VALUES(organization_value,workspace_value,environment_value,actor_value,'runTest',idempotency_value,run_value,definition_version_value,digest_value,result_value->>'audit_id',result_value->>'correlation_id',result_value->>'receipt_id',result_value);RETURN result_value;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='red team definition not found';
END
$run$;
CREATE FUNCTION public.zasp_red_team_list_runs(organization_value text,workspace_value text,environment_value text,before_value timestamptz,before_id_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $list$
DECLARE result_value jsonb;
BEGIN IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR limit_value NOT BETWEEN 1 AND 100 OR before_value IS NULL AND before_id_value IS NOT NULL OR before_value IS NOT NULL AND NOT zasp_valid_product_id(before_id_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team run list rejected';END IF;
 WITH visible AS (
   SELECT * FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND (before_value IS NULL OR (queued_at,run_id)<(before_value,before_id_value)) ORDER BY queued_at DESC,run_id DESC LIMIT limit_value
 ), cursor_row AS (
   SELECT queued_at,run_id FROM visible ORDER BY queued_at,run_id LIMIT 1
 ) SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(zasp_red_team_run_json(run_row) ORDER BY queued_at DESC,run_id DESC) FROM visible run_row),'[]'::jsonb),'next_cursor',CASE WHEN (SELECT count(*) FROM visible)=limit_value THEN (SELECT jsonb_build_object('queued_at',queued_at,'id',run_id) FROM cursor_row) END) INTO result_value;
 RETURN result_value;END
$list$;
CREATE FUNCTION public.zasp_red_team_get_run(organization_value text,workspace_value text,environment_value text,run_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $get$
DECLARE row_value zasp_red_team_runs%ROWTYPE;attempt_value jsonb;
BEGIN IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team run rejected';END IF;SELECT * INTO STRICT row_value FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);SELECT jsonb_agg(jsonb_build_object('attempt',attempt,'verdict',verdict,'objective',objective,'behavior',behavior,'error_code',error_code,'evidence',evidence,'evidence_reference',evidence_reference,'completed_at',completed_at) ORDER BY attempt) INTO attempt_value FROM zasp_red_team_attempts WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);RETURN zasp_red_team_run_json(row_value)||jsonb_build_object('attempts',COALESCE(attempt_value,'[]'::jsonb));EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='red team run not found';END
$get$;
CREATE FUNCTION public.zasp_red_team_cancel_run(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,run_value text,expected_version_value bigint,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $cancel$
DECLARE row_value zasp_red_team_runs%ROWTYPE;intent_value jsonb;digest_value bytea;receipt_row zasp_red_team_request_receipts%ROWTYPE;result_value jsonb;
BEGIN IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(run_value) OR expected_version_value NOT BETWEEN 1 AND 999999 OR NOT zasp_valid_product_id(correlation_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team cancel rejected';END IF;intent_value:=jsonb_build_object('run_id',run_value,'expected_version',expected_version_value);digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'cancelTestRun',idempotency_value),0));SELECT * INTO receipt_row FROM zasp_red_team_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'cancelTestRun',idempotency_value);IF FOUND THEN IF receipt_row.resource_id<>run_value OR receipt_row.expected_version<>expected_version_value OR receipt_row.intent_digest<>digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team cancel replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 UPDATE zasp_red_team_runs SET version=version+1,cancel_requested=true,state=CASE WHEN state IN('queued','retryable') THEN 'cancelled' ELSE state END,completed_at=CASE WHEN state IN('queued','retryable') THEN transaction_timestamp() ELSE completed_at END,error_code=CASE WHEN state IN('queued','retryable') THEN 'cancelled' ELSE error_code END,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,version)=(organization_value,workspace_value,environment_value,run_value,expected_version_value) AND state NOT IN('complete','failed','cancelled') RETURNING * INTO row_value;IF NOT FOUND THEN IF NOT EXISTS(SELECT 1 FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='red team run not found';END IF;RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team run version conflict';END IF;result_value:=zasp_red_team_mutation_result(organization_value,workspace_value,environment_value,actor_value,'cancelTestRun',run_value,correlation_value,idempotency_value,zasp_red_team_run_json(row_value));INSERT INTO zasp_red_team_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent_digest,audit_id,correlation_id,receipt_id,result) VALUES(organization_value,workspace_value,environment_value,actor_value,'cancelTestRun',idempotency_value,run_value,expected_version_value,digest_value,result_value->>'audit_id',result_value->>'correlation_id',result_value->>'receipt_id',result_value);RETURN result_value;END
$cancel$;

CREATE FUNCTION public.zasp_red_team_claim_outbox(worker_value text,token_value bytea,lease_seconds integer,limit_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE result_value jsonb;
BEGIN IF NOT zasp_red_team_principal_ready('zasp_red_team_outbox_worker') OR length(worker_value) NOT BETWEEN 3 AND 128 OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 5 AND 900 OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team outbox claim rejected';END IF;
 WITH eligible AS (
   SELECT outbox.ctid,row_number() OVER(PARTITION BY outbox.organization_id ORDER BY outbox.available_at,outbox.created_at,outbox.outbox_id) organization_ordinal,outbox.available_at,outbox.created_at,outbox.outbox_id
   FROM zasp_red_team_outbox outbox
   WHERE outbox.topic='test-jobs' AND outbox.attempt<100 AND (outbox.state='pending' OR outbox.state='leased' AND outbox.lease_expires_at<=transaction_timestamp()) AND outbox.available_at<=transaction_timestamp()
     AND NOT EXISTS(SELECT 1 FROM zasp_red_team_outbox live WHERE live.organization_id=outbox.organization_id AND live.topic='test-jobs' AND live.state='leased' AND live.lease_expires_at>transaction_timestamp())
 ), candidates AS (
   SELECT outbox.ctid FROM zasp_red_team_outbox outbox JOIN eligible ON eligible.ctid=outbox.ctid WHERE eligible.organization_ordinal=1 ORDER BY eligible.available_at,eligible.created_at,eligible.outbox_id FOR UPDATE OF outbox SKIP LOCKED LIMIT limit_value
 ), leased AS (
   UPDATE zasp_red_team_outbox outbox SET state='leased',attempt=attempt+1,worker_id=worker_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() FROM candidates WHERE outbox.ctid=candidates.ctid RETURNING outbox.*
 ) SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'outbox_id',outbox_id,'topic',topic,'payload',payload::text,'payload_digest',encode(payload_digest,'hex'),'attempt',attempt,'lease_expires_at',lease_expires_at) ORDER BY available_at,created_at,outbox_id),'[]'::jsonb) INTO result_value FROM leased;RETURN result_value;END
$claim$;
CREATE FUNCTION public.zasp_red_team_heartbeat_outbox(organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,token_value bytea,lease_seconds integer) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
BEGIN IF NOT zasp_red_team_principal_ready('zasp_red_team_outbox_worker') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(outbox_value) OR length(worker_value) NOT BETWEEN 3 AND 128 OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 5 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team outbox heartbeat rejected';END IF;UPDATE zasp_red_team_outbox SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,outbox_id,state,worker_id,lease_token)=(organization_value,workspace_value,environment_value,outbox_value,'leased',worker_value,token_value) AND lease_expires_at>transaction_timestamp();RETURN FOUND;END
$heartbeat$;
CREATE FUNCTION public.zasp_red_team_ack_outbox(organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,token_value bytea,ack_value text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $ack$
BEGIN IF NOT zasp_red_team_principal_ready('zasp_red_team_outbox_worker') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(outbox_value) OR length(worker_value) NOT BETWEEN 3 AND 128 OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR ack_value!~'^sha256:[a-f0-9]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team outbox ack rejected';END IF;UPDATE zasp_red_team_outbox SET state='published',provider_ack=ack_value,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,outbox_id,state,worker_id,lease_token)=(organization_value,workspace_value,environment_value,outbox_value,'leased',worker_value,token_value) AND lease_expires_at>transaction_timestamp();RETURN FOUND;END
$ack$;
CREATE FUNCTION public.zasp_red_team_retry_outbox(organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,token_value bytea,retry_at_value timestamptz) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $retry$
BEGIN IF NOT zasp_red_team_principal_ready('zasp_red_team_outbox_worker') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(outbox_value) OR length(worker_value) NOT BETWEEN 3 AND 128 OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR retry_at_value IS NULL OR retry_at_value<transaction_timestamp() OR retry_at_value>transaction_timestamp()+interval '1 hour' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team outbox retry rejected';END IF;UPDATE zasp_red_team_outbox SET state=CASE WHEN attempt>=100 THEN 'failed' ELSE 'pending' END,available_at=retry_at_value,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,outbox_id,state,worker_id,lease_token)=(organization_value,workspace_value,environment_value,outbox_value,'leased',worker_value,token_value) AND lease_expires_at>transaction_timestamp();RETURN FOUND;END
$retry$;

CREATE FUNCTION public.zasp_red_team_claim_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,token_value bytea,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE run_row zasp_red_team_runs%ROWTYPE;definition_row zasp_red_team_definitions%ROWTYPE;
BEGIN IF NOT zasp_red_team_principal_ready('zasp_red_team_worker') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) OR length(worker_value) NOT BETWEEN 3 AND 128 OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 30 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team run claim rejected';END IF;
 SELECT * INTO run_row FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) FOR UPDATE;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='red team run not found';END IF;IF run_row.state IN('complete','failed','cancelled') THEN RETURN jsonb_build_object('disposition','ack_terminal');END IF;IF run_row.cancel_requested THEN UPDATE zasp_red_team_runs SET version=version+1,state='cancelled',completed_at=transaction_timestamp(),error_code='cancelled',updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);RETURN jsonb_build_object('disposition','ack_terminal');END IF;IF run_row.state='leased' AND run_row.lease_expires_at>transaction_timestamp() OR run_row.next_attempt_at>transaction_timestamp() THEN RETURN jsonb_build_object('disposition','retry_later');END IF;IF run_row.attempt>=5 THEN UPDATE zasp_red_team_runs SET version=version+1,state='failed',error_code='exhausted',completed_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);RETURN jsonb_build_object('disposition','ack_terminal');END IF;
 SELECT * INTO STRICT definition_row FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,enabled)=(organization_value,workspace_value,environment_value,run_row.definition_id,run_row.definition_version,true) AND zasp_red_team_target_valid(organization_id,workspace_id,environment_id,target_id,target_kind);
 UPDATE zasp_red_team_runs SET version=version+1,state='leased',attempt=attempt+1,worker_id=worker_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),started_at=COALESCE(started_at,transaction_timestamp()),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) RETURNING * INTO run_row;
 RETURN jsonb_build_object('disposition','claimed','run',zasp_red_team_run_json(run_row),'definition',zasp_red_team_definition_json(definition_row),'input_digest',encode(run_row.input_digest,'hex'),'lease_expires_at',run_row.lease_expires_at);
END
$claim$;
CREATE FUNCTION public.zasp_red_team_heartbeat_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,token_value bytea,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
DECLARE cancel_value boolean;
BEGIN IF NOT zasp_red_team_principal_ready('zasp_red_team_worker') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(run_value) OR length(worker_value) NOT BETWEEN 3 AND 128 OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 30 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team run heartbeat rejected';END IF;UPDATE zasp_red_team_runs SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,state,worker_id,lease_token)=(organization_value,workspace_value,environment_value,run_value,'leased',worker_value,token_value) AND lease_expires_at>transaction_timestamp() RETURNING cancel_requested INTO cancel_value;RETURN jsonb_build_object('renewed',FOUND,'cancel_requested',COALESCE(cancel_value,false));END
$heartbeat$;
CREATE FUNCTION public.zasp_red_team_finish_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,token_value bytea,input_digest_value bytea,verdict_value text,objective_value text,behavior_value text,error_value text,evidence_value jsonb,reference_value text,key_value text,version_value text,checksum_value bytea,size_value bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $finish$
DECLARE run_row zasp_red_team_runs%ROWTYPE;
BEGIN IF NOT zasp_red_team_principal_ready('zasp_red_team_worker') OR octet_length(input_digest_value)<>32 OR verdict_value NOT IN('pass','fail','engine_error') OR verdict_value IN('pass','fail') AND error_value IS NOT NULL OR verdict_value='engine_error' AND error_value NOT IN('denied','malformed','outcome_unknown','exhausted') OR length(objective_value) NOT BETWEEN 1 AND 512 OR objective_value<>btrim(objective_value) OR objective_value~'[[:cntrl:]]' OR length(behavior_value) NOT BETWEEN 1 AND 2048 OR behavior_value<>btrim(behavior_value) OR behavior_value~'[[:cntrl:]]' OR jsonb_typeof(evidence_value)<>'array' OR jsonb_array_length(evidence_value)>64 OR EXISTS(SELECT 1 FROM jsonb_array_elements(evidence_value) evidence_item WHERE jsonb_typeof(evidence_item)<>'string' OR length(evidence_item#>>'{}') NOT BETWEEN 1 AND 512 OR evidence_item#>>'{}'<>btrim(evidence_item#>>'{}') OR evidence_item#>>'{}'~'[[:cntrl:]]') OR reference_value!~'^s3://[a-z0-9][a-z0-9.-]{2,62}/organizations/' OR length(key_value) NOT BETWEEN 1 AND 1024 OR substring(reference_value FROM '^s3://[a-z0-9][a-z0-9.-]{2,62}/(.+)$') IS DISTINCT FROM key_value OR key_value IS DISTINCT FROM 'organizations/'||organization_value||'/workspaces/'||workspace_value||'/environments/'||environment_value||'/artifacts/'||run_value OR length(version_value) NOT BETWEEN 1 AND 512 OR version_value~'[[:space:][:cntrl:]]' OR octet_length(checksum_value)<>32 OR size_value NOT BETWEEN 1 AND 67108864 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team run completion rejected';END IF;
 SELECT * INTO STRICT run_row FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,worker_id,lease_token,input_digest)=(organization_value,workspace_value,environment_value,run_value,'leased',worker_value,token_value,input_digest_value) AND lease_expires_at>transaction_timestamp() FOR UPDATE;
 IF run_row.cancel_requested THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team run cancellation wins';END IF;
 INSERT INTO zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,error_code,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size) VALUES(organization_value,workspace_value,environment_value,run_value,run_row.attempt,input_digest_value,verdict_value,objective_value,behavior_value,error_value,evidence_value,reference_value,key_value,version_value,checksum_value,size_value) ON CONFLICT(organization_id,workspace_id,environment_id,run_id,attempt) DO NOTHING;
 IF NOT FOUND AND NOT EXISTS(SELECT 1 FROM zasp_red_team_attempts attempt_value WHERE (attempt_value.organization_id,attempt_value.workspace_id,attempt_value.environment_id,attempt_value.run_id,attempt_value.attempt,attempt_value.input_digest,attempt_value.verdict,attempt_value.objective,attempt_value.behavior,attempt_value.error_code,attempt_value.evidence,attempt_value.evidence_reference,attempt_value.evidence_key,attempt_value.evidence_version_id,attempt_value.evidence_checksum,attempt_value.evidence_size) IS NOT DISTINCT FROM (organization_value,workspace_value,environment_value,run_value,run_row.attempt,input_digest_value,verdict_value,objective_value,behavior_value,error_value,evidence_value,reference_value,key_value,version_value,checksum_value,size_value)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='red team attempt conflict';END IF;
 UPDATE zasp_red_team_runs SET version=version+1,state='complete',verdict=verdict_value,error_code=error_value,evidence_reference=reference_value,evidence_key=key_value,evidence_version_id=version_value,evidence_checksum=checksum_value,evidence_size=size_value,completed_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) RETURNING * INTO run_row;RETURN zasp_red_team_run_json(run_row);
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team run lease rejected';END
$finish$;
CREATE FUNCTION public.zasp_red_team_retry_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,token_value bytea,input_digest_value bytea,error_value text,retry_at_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $retry$
DECLARE run_row zasp_red_team_runs%ROWTYPE;
BEGIN IF NOT zasp_red_team_principal_ready('zasp_red_team_worker') OR error_value NOT IN('retryable','rate_limited','denied','malformed','outcome_unknown') OR retry_at_value IS NULL OR retry_at_value<transaction_timestamp() OR retry_at_value>transaction_timestamp()+interval '1 hour' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team run retry rejected';END IF;UPDATE zasp_red_team_runs SET version=version+1,state=CASE WHEN attempt>=5 THEN 'failed' ELSE 'retryable' END,error_code=CASE WHEN attempt>=5 THEN 'exhausted' ELSE error_value END,next_attempt_at=retry_at_value,completed_at=CASE WHEN attempt>=5 THEN transaction_timestamp() END,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,state,worker_id,lease_token,input_digest)=(organization_value,workspace_value,environment_value,run_value,'leased',worker_value,token_value,input_digest_value) AND lease_expires_at>transaction_timestamp() RETURNING * INTO run_row;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team run lease rejected';END IF;RETURN zasp_red_team_run_json(run_row);END
$retry$;

CREATE FUNCTION public.zasp_red_team_cancel_claimed_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,token_value bytea,input_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $cancel$
DECLARE run_row zasp_red_team_runs%ROWTYPE;
BEGIN IF NOT zasp_red_team_principal_ready('zasp_red_team_worker') OR octet_length(input_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team worker cancellation rejected';END IF;UPDATE zasp_red_team_runs SET version=version+1,state='cancelled',error_code='cancelled',completed_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,state,worker_id,lease_token,input_digest,cancel_requested)=(organization_value,workspace_value,environment_value,run_value,'leased',worker_value,token_value,input_digest_value,true) AND lease_expires_at>transaction_timestamp() RETURNING * INTO run_row;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team run lease rejected';END IF;RETURN zasp_red_team_run_json(run_row);END
$cancel$;

DO $function_owners$
DECLARE function_value regprocedure;
BEGIN
 FOREACH function_value IN ARRAY ARRAY[
  'public.zasp_red_team_register_principals(text,text,text,text)'::regprocedure,'public.zasp_red_team_principal_ready(text)'::regprocedure,'public.zasp_red_team_principals_ready()'::regprocedure,'public.zasp_red_team_definition_valid(text,text,text,jsonb,jsonb)'::regprocedure,'public.zasp_red_team_target_binding_valid(jsonb,text)'::regprocedure,'public.zasp_red_team_target_valid(text,text,text,text,text)'::regprocedure,'public.zasp_red_team_resolve_target(text,text,text,text,text)'::regprocedure,'public.zasp_red_team_definition_json(public.zasp_red_team_definitions)'::regprocedure,'public.zasp_red_team_run_json(public.zasp_red_team_runs)'::regprocedure,'public.zasp_red_team_mutation_result(text,text,text,text,text,text,text,text,jsonb)'::regprocedure,
  'public.zasp_red_team_list_definitions(text,text,text,text,integer)'::regprocedure,'public.zasp_red_team_get_definition(text,text,text,text)'::regprocedure,'public.zasp_red_team_create_definition(text,text,text,text,text,text,text,text,text,jsonb,jsonb,text)'::regprocedure,'public.zasp_red_team_update_definition(text,text,text,text,text,text,bigint,text,text,text,jsonb,jsonb,boolean,text)'::regprocedure,
  'public.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)'::regprocedure,'public.zasp_red_team_list_runs(text,text,text,timestamptz,text,integer)'::regprocedure,'public.zasp_red_team_get_run(text,text,text,text)'::regprocedure,'public.zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text)'::regprocedure,
  'public.zasp_red_team_claim_outbox(text,bytea,integer,integer)'::regprocedure,'public.zasp_red_team_heartbeat_outbox(text,text,text,text,text,bytea,integer)'::regprocedure,'public.zasp_red_team_ack_outbox(text,text,text,text,text,bytea,text)'::regprocedure,'public.zasp_red_team_retry_outbox(text,text,text,text,text,bytea,timestamptz)'::regprocedure,
  'public.zasp_red_team_claim_run(text,text,text,text,text,bytea,integer)'::regprocedure,'public.zasp_red_team_heartbeat_run(text,text,text,text,text,bytea,integer)'::regprocedure,'public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint)'::regprocedure,'public.zasp_red_team_retry_run(text,text,text,text,text,bytea,bytea,text,timestamptz)'::regprocedure,'public.zasp_red_team_cancel_claimed_run(text,text,text,text,text,bytea,bytea)'::regprocedure
 ] LOOP EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',function_value);END LOOP;
END
$function_owners$;
REVOKE ALL ON FUNCTION public.zasp_red_team_register_principals(text,text,text,text),public.zasp_red_team_principal_ready(text),public.zasp_red_team_principals_ready(),public.zasp_red_team_definition_valid(text,text,text,jsonb,jsonb),public.zasp_red_team_target_binding_valid(jsonb,text),public.zasp_red_team_target_valid(text,text,text,text,text),public.zasp_red_team_resolve_target(text,text,text,text,text),public.zasp_red_team_definition_json(public.zasp_red_team_definitions),public.zasp_red_team_run_json(public.zasp_red_team_runs),public.zasp_red_team_mutation_result(text,text,text,text,text,text,text,text,jsonb),public.zasp_red_team_list_definitions(text,text,text,text,integer),public.zasp_red_team_get_definition(text,text,text,text),public.zasp_red_team_create_definition(text,text,text,text,text,text,text,text,text,jsonb,jsonb,text),public.zasp_red_team_update_definition(text,text,text,text,text,text,bigint,text,text,text,jsonb,jsonb,boolean,text),public.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text),public.zasp_red_team_list_runs(text,text,text,timestamptz,text,integer),public.zasp_red_team_get_run(text,text,text,text),public.zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text),public.zasp_red_team_claim_outbox(text,bytea,integer,integer),public.zasp_red_team_heartbeat_outbox(text,text,text,text,text,bytea,integer),public.zasp_red_team_ack_outbox(text,text,text,text,text,bytea,text),public.zasp_red_team_retry_outbox(text,text,text,text,text,bytea,timestamptz),public.zasp_red_team_claim_run(text,text,text,text,text,bytea,integer),public.zasp_red_team_heartbeat_run(text,text,text,text,text,bytea,integer),public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint),public.zasp_red_team_retry_run(text,text,text,text,text,bytea,bytea,text,timestamptz),public.zasp_red_team_cancel_claimed_run(text,text,text,text,text,bytea,bytea) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_list_definitions(text,text,text,text,integer),public.zasp_red_team_get_definition(text,text,text,text),public.zasp_red_team_create_definition(text,text,text,text,text,text,text,text,text,jsonb,jsonb,text),public.zasp_red_team_update_definition(text,text,text,text,text,text,bigint,text,text,text,jsonb,jsonb,boolean,text),public.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text),public.zasp_red_team_list_runs(text,text,text,timestamptz,text,integer),public.zasp_red_team_get_run(text,text,text,text),public.zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_principal_ready(text),public.zasp_red_team_claim_outbox(text,bytea,integer,integer),public.zasp_red_team_heartbeat_outbox(text,text,text,text,text,bytea,integer),public.zasp_red_team_ack_outbox(text,text,text,text,text,bytea,text),public.zasp_red_team_retry_outbox(text,text,text,text,text,bytea,timestamptz) TO zasp_red_team_outbox_worker;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_principal_ready(text),public.zasp_red_team_claim_run(text,text,text,text,text,bytea,integer),public.zasp_red_team_heartbeat_run(text,text,text,text,text,bytea,integer),public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint),public.zasp_red_team_retry_run(text,text,text,text,text,bytea,bytea,text,timestamptz),public.zasp_red_team_cancel_claimed_run(text,text,text,text,text,bytea,bytea) TO zasp_red_team_worker;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_principal_ready(text),public.zasp_red_team_resolve_target(text,text,text,text,text) TO zasp_red_team_adapter;

CREATE OR REPLACE FUNCTION public.zasp_security_agent_session_isolation_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=24 AND name='security_agent_session_isolation' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value IN('security-agent-session-isolation-v1','red-team-execution-v1')) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>25) AND zasp_security_agent_session_isolation_security_ready() AND zasp_security_agent_session_isolation_live_fingerprint()=expected_fingerprint
$readiness$;

CREATE OR REPLACE FUNCTION public.zasp_effective_scope_permissions(requested_permissions jsonb,requested_role text) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $permissions$
 SELECT CASE requested_role
  WHEN 'organization_admin' THEN '["investigate_sessions","manage_api_tokens","manage_data_controls","manage_findings","manage_identity","manage_workflows","revoke_sessions","run_tests","view","view_audit","view_compliance"]'::jsonb
  WHEN 'security_admin' THEN '["investigate_sessions","manage_api_tokens","manage_data_controls","manage_findings","manage_identity","manage_workflows","revoke_sessions","run_tests","view","view_audit","view_compliance"]'::jsonb
  WHEN 'security_engineer' THEN '["investigate_sessions","manage_findings","manage_workflows","run_tests","view"]'::jsonb
  WHEN 'developer_owner' THEN '["investigate_sessions","run_tests","view"]'::jsonb
  WHEN 'compliance_viewer' THEN '["view","view_audit","view_compliance"]'::jsonb
  WHEN 'read_only_viewer' THEN '["view"]'::jsonb
  ELSE '[]'::jsonb END
$permissions$;

CREATE FUNCTION public.zasp_red_team_execution_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_security_agent_session_isolation_security_ready()
 AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_red_team_worker' AND NOT rolsuper AND NOT rolinherit AND NOT rolcanlogin AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_red_team_outbox_worker' AND NOT rolsuper AND NOT rolinherit AND NOT rolcanlogin AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_red_team_adapter' AND NOT rolsuper AND NOT rolinherit AND NOT rolcanlogin AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 AND (SELECT count(*) FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter') AND member.rolname='zasp_discovery_authority' AND membership.admin_option)=3
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE (granted.rolname IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter') OR member.rolname IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter')) AND NOT (granted.rolname IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter') AND member.rolname='zasp_discovery_authority' AND membership.admin_option) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_principal_bindings binding WHERE binding.principal_name=member.rolname AND binding.authority_role=granted.rolname))
 AND has_function_privilege('zasp_security_agent_api','public.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)','EXECUTE')
 AND has_function_privilege('zasp_security_agent_api','public.zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text)','EXECUTE')
 AND has_function_privilege('zasp_red_team_worker','public.zasp_red_team_claim_run(text,text,text,text,text,bytea,integer)','EXECUTE')
 AND has_function_privilege('zasp_red_team_worker','public.zasp_red_team_cancel_claimed_run(text,text,text,text,text,bytea,bytea)','EXECUTE')
 AND has_function_privilege('zasp_red_team_outbox_worker','public.zasp_red_team_claim_outbox(text,bytea,integer,integer)','EXECUTE')
 AND has_function_privilege('zasp_red_team_adapter','public.zasp_red_team_resolve_target(text,text,text,text,text)','EXECUTE')
 AND NOT has_table_privilege('zasp_security_agent_api','public.zasp_red_team_runs','SELECT') AND NOT has_table_privilege('zasp_security_agent_api','public.zasp_red_team_audit','SELECT') AND NOT has_table_privilege('zasp_red_team_worker','public.zasp_red_team_runs','SELECT') AND NOT has_table_privilege('zasp_red_team_adapter','public.zasp_inventory_entities','SELECT')
 AND EXISTS(SELECT 1 FROM zasp_schema_metadata marker JOIN pg_roles role_value ON role_value.rolname=marker.value WHERE marker.key='red_team_execution_prior_permissions_owner' AND role_value.rolcanlogin AND (marker.value=session_user OR EXISTS(SELECT 1 FROM zasp_discovery_principal_bindings binding WHERE binding.principal_name=marker.value AND binding.authority_role='zasp_discovery_authority')))
 AND zasp_effective_scope_permissions('[]'::jsonb,'organization_admin') ? 'run_tests' AND zasp_effective_scope_permissions('[]'::jsonb,'security_engineer') ? 'run_tests' AND zasp_effective_scope_permissions('[]'::jsonb,'developer_owner') ? 'run_tests' AND NOT zasp_effective_scope_permissions('[]'::jsonb,'read_only_viewer') ? 'run_tests'
$security$;
CREATE FUNCTION public.zasp_red_team_execution_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
  SELECT concat_ws('|','prior',zasp_security_agent_session_isolation_live_fingerprint())
  UNION ALL SELECT concat_ws('|','role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls) FROM pg_roles WHERE rolname IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter')
  UNION ALL SELECT concat_ws('|','membership',granted.rolname,member.rolname,membership.admin_option) FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter') AND member.rolname='zasp_discovery_authority'
  UNION ALL SELECT concat_ws('|','table',class.relname,owner.rolname,class.relrowsecurity,class.relforcerowsecurity,COALESCE(class.relacl::text,'')) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_red_team_%' AND class.relkind IN('r','i')
  UNION ALL SELECT concat_ws('|','column',class.relname,attribute.attname,attribute.atttypid::regtype::text,attribute.attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_red_team_%' AND attribute.attnum>0 AND NOT attribute.attisdropped
  UNION ALL SELECT concat_ws('|','constraint',class.relname,constraint_value.conname,constraint_value.contype,constraint_value.convalidated,pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_red_team_%'
  UNION ALL SELECT concat_ws('|','policy',class.relname,policy.polname,policy.polpermissive,pg_get_expr(policy.polqual,policy.polrelid),pg_get_expr(policy.polwithcheck,policy.polrelid)) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_red_team_%'
  UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_red_team_%' OR procedure.proname='zasp_effective_scope_permissions')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_red_team_execution_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=25 AND name='red_team_execution' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='red-team-execution-v1') AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>25) AND zasp_red_team_execution_security_ready() AND zasp_red_team_execution_live_fingerprint()=expected_fingerprint
$readiness$;
CREATE FUNCTION public.zasp_red_team_target_adapter_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $adapter_readiness$
 SELECT zasp_red_team_execution_readiness(expected_checksum,expected_fingerprint) AND zasp_red_team_principal_ready('zasp_red_team_adapter')
$adapter_readiness$;
DO $prior_permissions_owner$
DECLARE prior_owner text;prior_acl_canonical boolean;
BEGIN
 SELECT procedure.proowner::regrole::text,
        (SELECT count(*)=3
             AND count(*) FILTER(WHERE acl.grantee=0 AND acl.grantor=procedure.proowner AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)=1
             AND count(*) FILTER(WHERE acl.grantee=procedure.proowner AND acl.grantor=procedure.proowner AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)=1
             AND count(*) FILTER(WHERE acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api') AND acl.grantor=procedure.proowner AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)=1
           FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl)
   INTO prior_owner,prior_acl_canonical
 FROM pg_proc procedure
 WHERE procedure.oid='public.zasp_effective_scope_permissions(jsonb,text)'::regprocedure;
 IF prior_owner IS NULL OR NOT EXISTS(SELECT 1 FROM pg_roles role_value WHERE role_value.rolname=prior_owner AND role_value.rolcanlogin)
    OR NOT (prior_owner=session_user OR EXISTS(SELECT 1 FROM zasp_discovery_principal_bindings binding WHERE binding.principal_name=prior_owner AND binding.authority_role='zasp_discovery_authority')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe inherited permissions owner';
 END IF;
 IF NOT COALESCE(prior_acl_canonical,false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='noncanonical inherited permissions ACL';END IF;
 INSERT INTO public.zasp_schema_metadata(key,value) VALUES('red_team_execution_prior_permissions_owner',prior_owner);
END
$prior_permissions_owner$;
ALTER FUNCTION public.zasp_security_agent_session_isolation_readiness(text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_effective_scope_permissions(jsonb,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_effective_scope_permissions(jsonb,text) FROM PUBLIC,zasp_discovery_api;
DO $normalize_effective_permissions_acl$
BEGIN
 EXECUTE format('REVOKE ALL ON FUNCTION public.zasp_effective_scope_permissions(jsonb,text) FROM %I',session_user);
END
$normalize_effective_permissions_acl$;
SET LOCAL ROLE zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION public.zasp_effective_scope_permissions(jsonb,text) TO zasp_discovery_api;
RESET ROLE;
ALTER FUNCTION public.zasp_red_team_execution_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_red_team_execution_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_red_team_execution_readiness(text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_red_team_target_adapter_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_red_team_execution_security_ready(),public.zasp_red_team_execution_live_fingerprint(),public.zasp_red_team_execution_readiness(text,text),public.zasp_red_team_target_adapter_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_execution_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_api,zasp_red_team_worker,zasp_red_team_outbox_worker;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_target_adapter_readiness(text,text) TO zasp_red_team_adapter;

DO $product_release_evolution$
DECLARE definition text;original_definition text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'security-agent-session-isolation-v1','red-team-execution-v1');definition:=replace(definition,'release."version" = 24','release."version" = 25');definition:=replace(definition,'release."name" = ''security_agent_session_isolation''','release."name" = ''red_team_execution''');definition:=replace(definition,'later_release."version" > 24','later_release."version" > 25');IF definition=original_definition OR position('red-team-execution-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v25 compatibility evolution failed';END IF;EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'security-agent-session-isolation-v1','red-team-execution-v1');definition:=replace(replace(definition,'release."version"=24','release."version"=25'),'release."version" = 24','release."version" = 25');definition:=replace(replace(definition,'release."name"=''security_agent_session_isolation''','release."name"=''red_team_execution'''),'release."name" = ''security_agent_session_isolation''','release."name" = ''red_team_execution''');definition:=replace(replace(definition,'later."version">24','later."version">25'),'later."version" > 24','later."version" > 25');IF definition=original_definition OR position('red-team-execution-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v25 compatibility evolution failed';END IF;EXECUTE definition;
END
$product_release_evolution$;

UPDATE public.zasp_schema_metadata SET value='red-team-execution-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='security-agent-session-isolation-v1';
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('red_team_execution_fingerprint', 'bb848d5c9936143cc9251dd44410de037a382b1190e1d04069df18b0a38f669a') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
