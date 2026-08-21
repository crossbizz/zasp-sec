DO $release_guard$ BEGIN
  IF NOT zasp_inventory_readiness(
    '335ac384f2ad97e1845d910f86a71abab0a14bf2afb57b66962f0465180ac808',
    'f2e8b9fec3df4a18b15b2be0c1843bc294626902eab1ccbb18b7fa72f8157a27'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory release required';
  END IF;
END $release_guard$;

DO $product_release_evolution$ DECLARE definition text;original_definition text;BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'typed-inventory-cutover-v1','runtime-data-plane-v1');
 definition:=replace(definition,'release."version" = 14','release."version" = 15');
 definition:=replace(definition,'release."name" = ''typed_inventory_cutover''','release."name" = ''runtime_data_plane''');
 definition:=replace(definition,'later_release."version" > 14','later_release."version" > 15');
 IF definition=original_definition OR position('runtime-data-plane-v1' IN definition)=0 OR position('release."version" = 15' IN definition)=0 OR position('release."name" = ''runtime_data_plane''' IN definition)=0 OR position('later_release."version" > 15' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v15 compatibility evolution failed';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'typed-inventory-cutover-v1','runtime-data-plane-v1');
 definition:=replace(replace(definition,'release."version"=14','release."version"=15'),'release."version" = 14','release."version" = 15');
 definition:=replace(replace(definition,'release."name"=''typed_inventory_cutover''','release."name"=''runtime_data_plane'''),'release."name" = ''typed_inventory_cutover''','release."name" = ''runtime_data_plane''');
 definition:=replace(replace(definition,'later."version">14','later."version">15'),'later."version" > 14','later."version" > 15');
 IF definition=original_definition OR position('runtime-data-plane-v1' IN definition)=0 OR position('runtime_data_plane' IN definition)=0 OR position('release."version"=15' IN definition)=0 AND position('release."version" = 15' IN definition)=0 OR position('later."version">15' IN definition)=0 AND position('later."version" > 15' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v15 compatibility evolution failed';END IF;
 EXECUTE definition;
END $product_release_evolution$;

DO $runtime_roles$
DECLARE role_name text;role_value record;created_role boolean;marker_prefix text:=format('zasp-managed:runtime-data-plane-v1:database:%s:',(SELECT oid FROM pg_database WHERE datname=current_database()));
BEGIN
 FOREACH role_name IN ARRAY ARRAY['zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker','zasp_gateway_control'] LOOP
  created_role:=NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name);
  IF created_role THEN EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',role_name);END IF;
  SELECT role.oid,role.rolcanlogin,role.rolinherit,role.rolsuper,role.rolcreatedb,role.rolcreaterole,role.rolreplication,role.rolbypassrls,shobj_description(role.oid,'pg_authid') marker INTO STRICT role_value FROM pg_roles role WHERE role.rolname=role_name;
  IF role_value.rolcanlogin OR role_value.rolinherit OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR role_value.rolbypassrls
   OR role_value.marker IS NOT NULL AND role_value.marker NOT IN(marker_prefix||'created',marker_prefix||'bound')
   OR EXISTS(SELECT 1 FROM pg_auth_members membership WHERE membership.roleid=role_value.oid OR membership.member=role_value.oid)
   OR EXISTS(SELECT 1 FROM pg_class object WHERE object.relowner=role_value.oid OR EXISTS(SELECT 1 FROM aclexplode(object.relacl) acl WHERE acl.grantee=role_value.oid))
   OR EXISTS(SELECT 1 FROM pg_proc object WHERE object.proowner=role_value.oid OR EXISTS(SELECT 1 FROM aclexplode(object.proacl) acl WHERE acl.grantee=role_value.oid))
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe pre-existing runtime role';END IF;
  EXECUTE format('COMMENT ON ROLE %I IS %L',role_name,marker_prefix||CASE WHEN created_role OR role_value.marker=marker_prefix||'created' THEN 'created' ELSE 'bound' END);
  EXECUTE format('GRANT %I TO zasp_discovery_authority WITH ADMIN OPTION',role_name);
 END LOOP;
END $runtime_roles$;

CREATE TABLE public.zasp_runtime_data_plane_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 installed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 used_at timestamptz,
 legacy_tokens_revoked integer NOT NULL DEFAULT 0 CHECK(legacy_tokens_revoked>=0),
 contract_version integer NOT NULL DEFAULT 15 CHECK(contract_version=15)
);
INSERT INTO public.zasp_runtime_data_plane_state(singleton) VALUES(true);

CREATE TABLE public.zasp_runtime_sensor_mutations (
 organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
 principal_id text NOT NULL CHECK(zasp_valid_product_id(principal_id)),operation text NOT NULL CHECK(operation IN('createSensorEnrollment','updateSensor','deleteSensor','rotateSensorToken')),idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),sensor_id text NOT NULL CHECK(zasp_valid_product_id(sensor_id)),expected_version bigint NOT NULL CHECK(expected_version>=0),
 token_id text CHECK(token_id IS NULL OR zasp_valid_product_id(token_id)),token_generation bigint CHECK(token_generation IS NULL OR token_generation>0),result jsonb NOT NULL CHECK(jsonb_typeof(result)='object' AND octet_length(convert_to(result::text,'UTF8'))<=16384),created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key),
 CHECK((token_id IS NULL)=(token_generation IS NULL)),CHECK((operation IN('createSensorEnrollment','rotateSensorToken'))=(token_id IS NOT NULL))
);

CREATE TABLE public.zasp_runtime_principal_bindings (
 principal_name name PRIMARY KEY,authority_role name NOT NULL UNIQUE,
 registered_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 CHECK(authority_role::text IN('zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker','zasp_gateway_control'))
);

CREATE TABLE public.zasp_runtime_legacy_token_transitions (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,sensor_id text NOT NULL,token_id text NOT NULL,
 prior_revoked_at timestamptz,transitioned_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,token_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id,token_id) REFERENCES zasp_sensor_tokens(organization_id,workspace_id,environment_id,sensor_id,id)
);

ALTER TABLE public.zasp_sensors
 ADD COLUMN mode text NOT NULL DEFAULT 'metadata_only' CHECK(mode IN('metadata_only','full')),
 ADD COLUMN runtime_contract_version integer NOT NULL DEFAULT 15 CHECK(runtime_contract_version=15);

ALTER TABLE public.zasp_sensor_tokens
 ADD COLUMN format_version integer CHECK(format_version IS NULL OR format_version=1),
 ADD COLUMN locator_digest bytea CHECK(locator_digest IS NULL OR octet_length(locator_digest)=32),
 ADD COLUMN token_generation bigint CHECK(token_generation IS NULL OR token_generation>0),
 ADD COLUMN sensor_version_at_issue bigint CHECK(sensor_version_at_issue IS NULL OR sensor_version_at_issue>0),
 ADD COLUMN last_authenticated_at timestamptz,
 ADD COLUMN v15_issued_at timestamptz,
 ADD CONSTRAINT zasp_sensor_tokens_v15_authority CHECK(
  (format_version IS NULL AND locator_digest IS NULL AND token_generation IS NULL AND sensor_version_at_issue IS NULL AND v15_issued_at IS NULL)
  OR (format_version=1 AND locator_digest IS NOT NULL AND token_generation IS NOT NULL AND sensor_version_at_issue IS NOT NULL AND v15_issued_at IS NOT NULL)
 ),
 ADD CONSTRAINT zasp_sensor_tokens_v15_auth_time CHECK(last_authenticated_at IS NULL OR last_authenticated_at>=issued_at);

CREATE UNIQUE INDEX zasp_sensor_tokens_locator_v15_idx ON public.zasp_sensor_tokens(locator_digest) WHERE locator_digest IS NOT NULL;
CREATE UNIQUE INDEX zasp_sensor_tokens_generation_v15_idx ON public.zasp_sensor_tokens(organization_id,workspace_id,environment_id,sensor_id,token_generation) WHERE token_generation IS NOT NULL;
CREATE UNIQUE INDEX zasp_sensor_tokens_live_v15_idx ON public.zasp_sensor_tokens(organization_id,workspace_id,environment_id,sensor_id) WHERE format_version=1 AND revoked_at IS NULL;

ALTER TABLE public.zasp_gateway_enrollment_tokens
 ADD COLUMN format_version integer CHECK(format_version IS NULL OR format_version=1),
 ADD COLUMN locator_digest bytea CHECK(locator_digest IS NULL OR octet_length(locator_digest)=32),
 ADD COLUMN token_generation bigint CHECK(token_generation IS NULL OR token_generation>0),
 ADD COLUMN device_version_at_issue bigint CHECK(device_version_at_issue IS NULL OR device_version_at_issue>0),
 ADD COLUMN v15_issued_at timestamptz,
 ADD CONSTRAINT zasp_gateway_enrollment_tokens_v15_authority CHECK(
  (format_version IS NULL AND locator_digest IS NULL AND token_generation IS NULL AND device_version_at_issue IS NULL AND v15_issued_at IS NULL)
  OR (format_version=1 AND locator_digest IS NOT NULL AND token_generation IS NOT NULL AND device_version_at_issue IS NOT NULL AND v15_issued_at IS NOT NULL)
 );
CREATE UNIQUE INDEX zasp_gateway_enrollment_locator_v15_idx ON public.zasp_gateway_enrollment_tokens(locator_digest) WHERE locator_digest IS NOT NULL;
CREATE UNIQUE INDEX zasp_gateway_enrollment_generation_v15_idx ON public.zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,device_id,token_generation) WHERE token_generation IS NOT NULL;
CREATE UNIQUE INDEX zasp_gateway_enrollment_live_v15_idx ON public.zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,device_id) WHERE format_version=1 AND consumed_at IS NULL AND revoked_at IS NULL;

ALTER TABLE public.zasp_gateway_credentials
 ADD COLUMN format_version integer CHECK(format_version IS NULL OR format_version=1),
 ADD COLUMN credential_generation bigint CHECK(credential_generation IS NULL OR credential_generation>0),
 ADD COLUMN key_id text CHECK(key_id IS NULL OR key_id ~ '^[a-z][a-z0-9_-]{7,63}$'),
 ADD COLUMN algorithm text CHECK(algorithm IS NULL OR algorithm='Ed25519'),
 ADD COLUMN v15_issued_at timestamptz,
 ADD CONSTRAINT zasp_gateway_credentials_v15_authority CHECK(
  (format_version IS NULL AND credential_generation IS NULL AND key_id IS NULL AND algorithm IS NULL AND v15_issued_at IS NULL)
  OR (format_version=1 AND credential_generation IS NOT NULL AND key_id IS NOT NULL AND algorithm='Ed25519' AND octet_length(public_key)=32 AND v15_issued_at IS NOT NULL)
 );
CREATE UNIQUE INDEX zasp_gateway_credentials_id_v15_idx ON public.zasp_gateway_credentials(id) WHERE format_version=1;
CREATE UNIQUE INDEX zasp_gateway_credentials_generation_v15_idx ON public.zasp_gateway_credentials(organization_id,workspace_id,environment_id,device_id,credential_generation) WHERE credential_generation IS NOT NULL;
CREATE UNIQUE INDEX zasp_gateway_credentials_live_v15_idx ON public.zasp_gateway_credentials(organization_id,workspace_id,environment_id,device_id) WHERE format_version=1 AND revoked_at IS NULL;

CREATE TABLE public.zasp_runtime_gateway_replay_receipts (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,device_id text NOT NULL,credential_id text NOT NULL,next_floor bigint NOT NULL CHECK(next_floor>0),request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,device_id,next_floor),
 FOREIGN KEY(organization_id,workspace_id,environment_id,device_id,credential_id) REFERENCES zasp_gateway_credentials(organization_id,workspace_id,environment_id,device_id,id)
);

CREATE TABLE public.zasp_runtime_gateway_policy_bundles (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,device_id text NOT NULL,credential_id text NOT NULL,sequence bigint NOT NULL CHECK(sequence>0),policy_version bigint NOT NULL CHECK(policy_version>0),
 contract_version integer NOT NULL DEFAULT 1 CHECK(contract_version=1),key_id text NOT NULL CHECK(key_id ~ '^[a-z][a-z0-9_-]{7,63}$'),algorithm text NOT NULL CHECK(algorithm='Ed25519'),audience text NOT NULL CHECK(audience='runtime-gateway-policy'),
 issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,failure_mode text NOT NULL CHECK(failure_mode IN('open','closed')),payload_digest bytea NOT NULL CHECK(octet_length(payload_digest)=32),policies jsonb NOT NULL CHECK(jsonb_typeof(policies)='array' AND jsonb_array_length(policies)<=100),signature bytea NOT NULL CHECK(octet_length(signature)=64),envelope_digest bytea NOT NULL CHECK(octet_length(envelope_digest)=32),created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,device_id,sequence),UNIQUE(envelope_digest),
 FOREIGN KEY(organization_id,workspace_id,environment_id,device_id,credential_id) REFERENCES zasp_gateway_credentials(organization_id,workspace_id,environment_id,device_id,id),
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '24 hours')
);

CREATE TABLE public.zasp_runtime_gateway_events (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,device_id text NOT NULL,credential_id text NOT NULL,event_id text NOT NULL CHECK(zasp_valid_product_id(event_id)),sequence bigint NOT NULL CHECK(sequence>0),request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 policy_version bigint NOT NULL CHECK(policy_version>0),decision text NOT NULL CHECK(decision IN('allow','monitor','block')),action_kind text NOT NULL CHECK(action_kind IN('http','mcp')),classification jsonb NOT NULL CHECK(jsonb_typeof(classification)='object' AND octet_length(convert_to(classification::text,'UTF8'))<=16384),occurred_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,event_id),UNIQUE(organization_id,workspace_id,environment_id,device_id,sequence),
 FOREIGN KEY(organization_id,workspace_id,environment_id,device_id,credential_id) REFERENCES zasp_gateway_credentials(organization_id,workspace_id,environment_id,device_id,id)
);

CREATE TABLE public.zasp_runtime_batch_authorities (
 organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
 batch_id text NOT NULL CHECK(zasp_valid_product_id(batch_id)),sensor_id text NOT NULL CHECK(zasp_valid_product_id(sensor_id)),sensor_token_id text NOT NULL CHECK(zasp_valid_product_id(sensor_token_id)),token_generation bigint NOT NULL CHECK(token_generation>0),
 pipeline_version integer NOT NULL DEFAULT 15 CHECK(pipeline_version=15),batch_generation bigint NOT NULL CHECK(batch_generation>0),idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),content_digest bytea NOT NULL CHECK(octet_length(content_digest)=32),
 source_kind text NOT NULL CHECK(source_kind IN('tetragon','otlp')),payload_media_type text NOT NULL CHECK(length(payload_media_type) BETWEEN 1 AND 128),payload_schema_version text NOT NULL CHECK(length(payload_schema_version) BETWEEN 1 AND 64),payload_size_bytes bigint NOT NULL CHECK(payload_size_bytes BETWEEN 1 AND 67108864),event_count integer NOT NULL CHECK(event_count BETWEEN 1 AND 1000),
 raw_artifact_key text NOT NULL CHECK(length(raw_artifact_key) BETWEEN 32 AND 1024),raw_artifact_reference text,raw_artifact_version_id text,raw_artifact_checksum bytea CHECK(raw_artifact_checksum IS NULL OR octet_length(raw_artifact_checksum)=32),raw_artifact_size_bytes bigint CHECK(raw_artifact_size_bytes IS NULL OR raw_artifact_size_bytes BETWEEN 1 AND 67108864),raw_artifact_kms_key text,
 terminal_result_reference text,terminal_result_version_id text,terminal_result_digest bytea CHECK(terminal_result_digest IS NULL OR octet_length(terminal_result_digest)=32),completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32),completion_result jsonb,
 state text NOT NULL DEFAULT 'uploading' CHECK(state IN('uploading','queued','processing','succeeded','failed','unknown','quarantined')),reserved_at timestamptz NOT NULL DEFAULT transaction_timestamp(),finalized_at timestamptz,completed_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id),UNIQUE(organization_id,workspace_id,environment_id,sensor_id,idempotency_key),UNIQUE(organization_id,workspace_id,environment_id,sensor_id,batch_generation),
 FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id) REFERENCES zasp_sensors(organization_id,workspace_id,environment_id,id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id,sensor_token_id) REFERENCES zasp_sensor_tokens(organization_id,workspace_id,environment_id,sensor_id,id),
	 CHECK((state IN('uploading','unknown') AND raw_artifact_reference IS NULL AND raw_artifact_version_id IS NULL AND raw_artifact_checksum IS NULL AND raw_artifact_size_bytes IS NULL AND raw_artifact_kms_key IS NULL AND finalized_at IS NULL)
	  OR (state NOT IN('uploading','unknown') AND zasp_discovery_s3_object_reference(raw_artifact_reference) AND length(raw_artifact_version_id) BETWEEN 1 AND 1024 AND raw_artifact_checksum IS NOT NULL AND raw_artifact_size_bytes=payload_size_bytes AND length(raw_artifact_kms_key) BETWEEN 1 AND 512 AND finalized_at IS NOT NULL)),
 CHECK(completed_at IS NULL OR state IN('succeeded','failed','unknown','quarantined')),
 CHECK((state='succeeded')=(terminal_result_reference IS NOT NULL AND terminal_result_version_id IS NOT NULL AND terminal_result_digest IS NOT NULL AND completion_digest IS NOT NULL AND completion_result IS NOT NULL))
);

CREATE TABLE public.zasp_runtime_stage_work (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,batch_id text NOT NULL,batch_generation bigint NOT NULL,
 stage text NOT NULL CHECK(stage IN('archive','index','correlate','project','complete')),stage_order integer NOT NULL CHECK(stage_order BETWEEN 1 AND 5),implementation_version text NOT NULL CHECK(length(implementation_version) BETWEEN 1 AND 64),
 predecessor_digest bytea CHECK(predecessor_digest IS NULL OR octet_length(predecessor_digest)=32),input_digest bytea CHECK(input_digest IS NULL OR octet_length(input_digest)=32),state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','leased','retryable','succeeded','failed','unknown','quarantined')),
 attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),lease_owner text,lease_token text,lease_expires_at timestamptz,last_heartbeat_at timestamptz,
 effect_digest bytea CHECK(effect_digest IS NULL OR octet_length(effect_digest)=32),result_reference text,result_version_id text,result_digest bytea CHECK(result_digest IS NULL OR octet_length(result_digest)=32),last_error_class text CHECK(last_error_class IS NULL OR last_error_class IN('retryable','denied','malformed','outcome_unknown','exhausted')),
 completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32),completion_result jsonb,completed_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id,stage),UNIQUE(organization_id,workspace_id,environment_id,batch_id,stage_order),
 FOREIGN KEY(organization_id,workspace_id,environment_id,batch_id) REFERENCES zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id) ON DELETE CASCADE,
 CHECK((state='leased')=(lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
 CHECK(completed_at IS NULL OR state IN('succeeded','failed','unknown','quarantined'))
);

CREATE TABLE public.zasp_runtime_deliveries (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,batch_id text NOT NULL,batch_generation bigint NOT NULL,message_id text NOT NULL CHECK(length(message_id) BETWEEN 1 AND 512),message_digest bytea NOT NULL CHECK(octet_length(message_digest)=32),receive_count integer NOT NULL CHECK(receive_count BETWEEN 1 AND 100),
 disposition text NOT NULL CHECK(disposition IN('held','terminal','ack_pending','acked','unknown','quarantined')),lease_owner text,lease_token text,lease_expires_at timestamptz,visibility_deadline timestamptz,provider_ack_digest bytea CHECK(provider_ack_digest IS NULL OR octet_length(provider_ack_digest)=32),created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id),UNIQUE(message_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,batch_id) REFERENCES zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id) ON DELETE CASCADE,
 CHECK((disposition IN('held','ack_pending'))=(lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND visibility_deadline IS NOT NULL)),
 CHECK((disposition='acked')=(provider_ack_digest IS NOT NULL))
);

ALTER TABLE public.zasp_discovery_outbox_topic_fairness
 DROP CONSTRAINT zasp_discovery_outbox_topic_fairness_topic_check,
 ADD CONSTRAINT zasp_discovery_outbox_topic_fairness_topic_check CHECK(topic IN('discovery-jobs','runtime-events'));

CREATE TABLE public.zasp_runtime_stage_fairness (
 stage text NOT NULL CHECK(stage IN('archive','index','correlate','project','complete')),organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),last_claimed_at timestamptz NOT NULL,
 PRIMARY KEY(stage,organization_id)
);

CREATE INDEX zasp_runtime_batches_uploading_v15_idx ON public.zasp_runtime_batch_authorities(reserved_at,organization_id,batch_id) WHERE state IN('uploading','unknown');
CREATE INDEX zasp_runtime_batches_sensor_rate_v15_idx ON public.zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,sensor_id,source_kind,reserved_at);
CREATE INDEX zasp_runtime_stages_claim_v15_idx ON public.zasp_runtime_stage_work(stage,available_at,organization_id,batch_id) WHERE state IN('pending','retryable','leased');
CREATE INDEX zasp_runtime_deliveries_claim_v15_idx ON public.zasp_runtime_deliveries(updated_at,organization_id,batch_id) WHERE disposition IN('held','ack_pending','unknown');

INSERT INTO public.zasp_runtime_legacy_token_transitions(organization_id,workspace_id,environment_id,sensor_id,token_id,prior_revoked_at)
SELECT organization_id,workspace_id,environment_id,sensor_id,id,revoked_at FROM public.zasp_sensor_tokens WHERE format_version IS NULL AND revoked_at IS NULL;
UPDATE public.zasp_sensor_tokens token_value SET revoked_at=transition.transitioned_at
 FROM public.zasp_runtime_legacy_token_transitions transition
 WHERE (token_value.organization_id,token_value.workspace_id,token_value.environment_id,token_value.sensor_id,token_value.id)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.sensor_id,transition.token_id);
UPDATE public.zasp_runtime_data_plane_state SET legacy_tokens_revoked=(SELECT count(*) FROM public.zasp_runtime_legacy_token_transitions) WHERE singleton;

CREATE FUNCTION public.zasp_runtime_sensor_secret_hash(audience_value text,token_value text,generation_value bigint,salt_value bytea,secret_value bytea) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
 SELECT digest(convert_to('zasp-sensor-token-hash-v1','UTF8')||decode('00','hex')||convert_to(audience_value,'UTF8')||decode('00','hex')||convert_to(token_value,'UTF8')||decode('00','hex')||int8send(generation_value)||salt_value||secret_value,'sha256')
$$;

CREATE FUNCTION public.zasp_runtime_gateway_enrollment_secret_hash(audience_value text,enrollment_value text,generation_value bigint,salt_value bytea,secret_value bytea) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
 SELECT digest(convert_to('zasp-gateway-enrollment-token-hash-v1','UTF8')||decode('00','hex')||convert_to(audience_value,'UTF8')||decode('00','hex')||convert_to(enrollment_value,'UTF8')||decode('00','hex')||int8send(generation_value)||salt_value||secret_value,'sha256')
$$;

CREATE FUNCTION public.zasp_runtime_register_principals(migration_principal text,coordinator_principal text,archive_principal text,index_principal text,correlation_principal text,projection_principal text,gateway_principal text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE principals text[]:=ARRAY[coordinator_principal,archive_principal,index_principal,correlation_principal,projection_principal,gateway_principal];authorities text[]:=ARRAY['zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker','zasp_gateway_control'];index_value integer;role_value record;
BEGIN
 IF migration_principal<>session_user OR cardinality(ARRAY(SELECT DISTINCT unnest(ARRAY[migration_principal,coordinator_principal,archive_principal,index_principal,correlation_principal,projection_principal,gateway_principal])))<>7 OR EXISTS(SELECT 1 FROM unnest(principals) principal_value WHERE principal_value !~ '^[a-z][a-z0-9_]{2,62}$') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid runtime principals';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-runtime-principal-registration',0));
 FOR index_value IN 1..6 LOOP
  SELECT role.oid,role.rolcanlogin,role.rolinherit,role.rolsuper,role.rolcreatedb,role.rolcreaterole,role.rolreplication,role.rolbypassrls INTO role_value FROM pg_roles role WHERE role.rolname=principals[index_value];
  IF NOT FOUND OR NOT role_value.rolcanlogin OR NOT role_value.rolinherit OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR role_value.rolbypassrls OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=role_value.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>authorities[index_value]) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe runtime principal';END IF;
  EXECUTE format('GRANT %I TO %I',authorities[index_value],principals[index_value]);
  INSERT INTO zasp_runtime_principal_bindings(principal_name,authority_role) VALUES(principals[index_value],authorities[index_value]) ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role WHERE zasp_runtime_principal_bindings.authority_role=excluded.authority_role;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime principal conflict';END IF;
 END LOOP;
 RETURN true;
END $$;

CREATE FUNCTION public.zasp_runtime_principal_ready(expected_authority text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT expected_authority IN('zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker','zasp_gateway_control')
  AND EXISTS(SELECT 1 FROM zasp_runtime_principal_bindings binding JOIN pg_roles principal ON principal.rolname=binding.principal_name WHERE binding.principal_name=session_user AND binding.authority_role=expected_authority AND principal.rolcanlogin AND principal.rolinherit AND NOT principal.rolsuper AND NOT principal.rolcreatedb AND NOT principal.rolcreaterole AND NOT principal.rolreplication AND NOT principal.rolbypassrls)
  AND pg_has_role(session_user,expected_authority,'MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
$$;

CREATE FUNCTION public.zasp_runtime_principals_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT (SELECT count(*) FROM zasp_runtime_principal_bindings)=6
  AND NOT EXISTS(
   SELECT 1 FROM zasp_runtime_principal_bindings binding
   LEFT JOIN pg_roles principal ON principal.rolname=binding.principal_name
   LEFT JOIN pg_roles authority ON authority.rolname=binding.authority_role
   WHERE principal.oid IS NULL OR authority.oid IS NULL OR NOT principal.rolcanlogin OR NOT principal.rolinherit OR principal.rolsuper OR principal.rolcreatedb OR principal.rolcreaterole OR principal.rolreplication OR principal.rolbypassrls
    OR NOT pg_has_role(principal.rolname,authority.rolname,'MEMBER')
    OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=principal.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>authority.rolname)
  )
$$;

CREATE FUNCTION public.zasp_runtime_mark_used() RETURNS boolean LANGUAGE sql AS $$
 UPDATE public.zasp_runtime_data_plane_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton RETURNING true
$$;

CREATE FUNCTION public.zasp_runtime_issue_sensor_token(organization_value text,workspace_value text,environment_value text,sensor_value text,token_value text,generation_value bigint,sensor_version_value bigint,locator_digest_value bytea,salt_value bytea,token_hash_value bytea,expires_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE result_value jsonb;expected_generation bigint;existing_value zasp_sensor_tokens%ROWTYPE;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(sensor_value) OR NOT zasp_valid_product_id(token_value)
  OR generation_value<1 OR sensor_version_value<1 OR octet_length(locator_digest_value)<>32 OR octet_length(salt_value)<>32 OR octet_length(token_hash_value)<>32
  OR expires_value<=transaction_timestamp() OR expires_value>transaction_timestamp()+interval '90 days' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor credential rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,sensor_value),0));
 SELECT * INTO existing_value FROM zasp_sensor_tokens token_row WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.id)=(organization_value,workspace_value,environment_value,token_value);
 IF FOUND THEN
  IF (existing_value.sensor_id,existing_value.format_version,existing_value.token_generation,existing_value.sensor_version_at_issue,existing_value.locator_digest,existing_value.salt,existing_value.token_hash,existing_value.expires_at) IS DISTINCT FROM (sensor_value,1,generation_value,sensor_version_value,locator_digest_value,salt_value,token_hash_value,expires_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor credential conflict';END IF;
  RETURN jsonb_build_object('id',existing_value.id,'sensor_id',existing_value.sensor_id,'audience',existing_value.audience,'generation',existing_value.token_generation,'sensor_version',existing_value.sensor_version_at_issue,'issued_at',existing_value.issued_at,'expires_at',existing_value.expires_at,'replayed',true);
 END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_sensors sensor_row WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id,sensor_row.version)=(organization_value,workspace_value,environment_value,sensor_value,sensor_version_value) AND sensor_row.state IN('pending','active','degraded')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor credential rejected';END IF;
 SELECT COALESCE(max(token_row.token_generation),0)+1 INTO expected_generation FROM zasp_sensor_tokens token_row WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id)=(organization_value,workspace_value,environment_value,sensor_value) AND token_row.token_generation IS NOT NULL;
 IF generation_value<>expected_generation OR EXISTS(SELECT 1 FROM zasp_sensor_tokens token_row WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id)=(organization_value,workspace_value,environment_value,sensor_value) AND token_row.format_version=1 AND token_row.revoked_at IS NULL) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='sensor credential conflict';END IF;
 INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,audience,salt,token_hash,expires_at,format_version,locator_digest,token_generation,sensor_version_at_issue,v15_issued_at)
 VALUES(organization_value,workspace_value,environment_value,token_value,sensor_value,'event-ingest',salt_value,token_hash_value,expires_value,1,locator_digest_value,generation_value,sensor_version_value,transaction_timestamp())
 RETURNING jsonb_build_object('id',id,'sensor_id',sensor_id,'audience',audience,'generation',token_generation,'sensor_version',sensor_version_at_issue,'issued_at',issued_at,'expires_at',expires_at,'replayed',false) INTO result_value;
 PERFORM zasp_runtime_mark_used();
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_rotate_sensor_token(organization_value text,workspace_value text,environment_value text,sensor_value text,current_token_value text,replacement_token_value text,generation_value bigint,sensor_version_value bigint,locator_digest_value bytea,salt_value bytea,token_hash_value bytea,expires_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE result_value jsonb;existing_value zasp_sensor_tokens%ROWTYPE;requested_digest bytea;current_generation bigint;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(sensor_value) OR NOT zasp_valid_product_id(current_token_value) OR NOT zasp_valid_product_id(replacement_token_value)
  OR current_token_value=replacement_token_value OR generation_value<2 OR sensor_version_value<1 OR octet_length(locator_digest_value)<>32 OR octet_length(salt_value)<>32 OR octet_length(token_hash_value)<>32
  OR expires_value<=transaction_timestamp() OR expires_value>transaction_timestamp()+interval '90 days' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor credential rejected';END IF;
 requested_digest:=digest(convert_to(concat_ws(chr(31),sensor_value,current_token_value,replacement_token_value,generation_value::text,sensor_version_value::text,encode(locator_digest_value,'hex'),encode(salt_value,'hex'),encode(token_hash_value,'hex'),floor(extract(epoch FROM expires_value)*1000000)::bigint::text),'UTF8'),'sha256');
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,sensor_value),0));
 SELECT * INTO existing_value FROM zasp_sensor_tokens token_row WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id,token_row.id,token_row.rotated_from_id)=(organization_value,workspace_value,environment_value,sensor_value,replacement_token_value,current_token_value);
 IF FOUND THEN
  IF existing_value.rotation_digest<>requested_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor credential conflict';END IF;
  RETURN jsonb_build_object('id',existing_value.id,'sensor_id',existing_value.sensor_id,'audience',existing_value.audience,'generation',existing_value.token_generation,'sensor_version',existing_value.sensor_version_at_issue,'issued_at',existing_value.issued_at,'expires_at',existing_value.expires_at,'replayed',true);
 END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_sensors sensor_row WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id,sensor_row.version)=(organization_value,workspace_value,environment_value,sensor_value,sensor_version_value) AND sensor_row.state IN('pending','active','degraded')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor credential rejected';END IF;
 SELECT token_row.token_generation INTO current_generation FROM zasp_sensor_tokens token_row WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id,token_row.id)=(organization_value,workspace_value,environment_value,sensor_value,current_token_value) AND token_row.format_version=1 AND token_row.revoked_at IS NULL AND token_row.expires_at>transaction_timestamp() FOR UPDATE;
 IF NOT FOUND OR generation_value<>current_generation+1 THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor credential rejected';END IF;
 UPDATE zasp_sensor_tokens token_row SET revoked_at=transaction_timestamp() WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id,token_row.id)=(organization_value,workspace_value,environment_value,sensor_value,current_token_value);
 INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,audience,salt,token_hash,expires_at,rotated_from_id,rotation_digest,format_version,locator_digest,token_generation,sensor_version_at_issue,v15_issued_at)
 VALUES(organization_value,workspace_value,environment_value,replacement_token_value,sensor_value,'event-ingest',salt_value,token_hash_value,expires_value,current_token_value,requested_digest,1,locator_digest_value,generation_value,sensor_version_value,transaction_timestamp())
 RETURNING jsonb_build_object('id',id,'sensor_id',sensor_id,'audience',audience,'generation',token_generation,'sensor_version',sensor_version_at_issue,'issued_at',issued_at,'expires_at',expires_at,'replayed',false) INTO result_value;
 PERFORM zasp_runtime_mark_used();
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_revoke_sensor_token(organization_value text,workspace_value text,environment_value text,sensor_value text,token_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE revoked_value timestamptz;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(sensor_value) OR NOT zasp_valid_product_id(token_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor credential rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,sensor_value),0));
 UPDATE zasp_sensor_tokens token_row SET revoked_at=COALESCE(token_row.revoked_at,transaction_timestamp()) WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id,token_row.id)=(organization_value,workspace_value,environment_value,sensor_value,token_value) AND token_row.format_version=1 RETURNING token_row.revoked_at INTO revoked_value;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor credential rejected';END IF;
 PERFORM zasp_runtime_mark_used();
 RETURN jsonb_build_object('id',token_value,'revoked_at',revoked_value);
END $$;

CREATE FUNCTION public.zasp_runtime_public_sensor_value(organization_value text,workspace_value text,environment_value text,sensor_value text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT jsonb_build_object('id',sensor_row.id,'name',sensor_row.name,'kind',sensor_row.kind,'mode',sensor_row.mode,'state',sensor_row.state,'version',sensor_row.version,
  'token_expires_at',CASE WHEN token_row.expires_at IS NULL THEN NULL ELSE to_char(token_row.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,
  'last_heartbeat_at',CASE WHEN heartbeat_row.observed_at IS NULL THEN NULL ELSE to_char(heartbeat_row.observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,
  'created_at',to_char(sensor_row.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'updated_at',to_char(sensor_row.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
 FROM zasp_sensors sensor_row
 LEFT JOIN LATERAL(SELECT token_value.expires_at FROM zasp_sensor_tokens token_value WHERE (token_value.organization_id,token_value.workspace_id,token_value.environment_id,token_value.sensor_id)=(sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id) AND token_value.format_version=1 AND token_value.revoked_at IS NULL AND token_value.sensor_version_at_issue=sensor_row.version ORDER BY token_value.token_generation DESC LIMIT 1) token_row ON true
 LEFT JOIN zasp_sensor_heartbeats heartbeat_row ON (heartbeat_row.organization_id,heartbeat_row.workspace_id,heartbeat_row.environment_id,heartbeat_row.sensor_id)=(sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id)
 WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id)=(organization_value,workspace_value,environment_value,sensor_value)
$$;

CREATE FUNCTION public.zasp_runtime_public_sensor_page(organization_value text,workspace_value text,environment_value text,after_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE items_value jsonb;next_value text;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR after_value IS NOT NULL AND NOT zasp_valid_product_id(after_value) OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor query rejected';END IF;
 SELECT COALESCE(jsonb_agg(zasp_runtime_public_sensor_value(organization_value,workspace_value,environment_value,item.id) ORDER BY item.id),'[]'::jsonb),CASE WHEN count(*)=limit_value THEN max(item.id) END INTO items_value,next_value
 FROM(SELECT sensor_row.id FROM zasp_sensors sensor_row WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id)=(organization_value,workspace_value,environment_value) AND sensor_row.state<>'deleted' AND (after_value IS NULL OR sensor_row.id>after_value) ORDER BY sensor_row.id LIMIT limit_value) item;
 RETURN jsonb_build_object('items',items_value,'next_id',next_value);
END $$;

CREATE FUNCTION public.zasp_runtime_public_sensor_detail(organization_value text,workspace_value text,environment_value text,sensor_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(sensor_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor query rejected';END IF;
 SELECT zasp_runtime_public_sensor_value(organization_value,workspace_value,environment_value,sensor_value) INTO result_value FROM zasp_sensors sensor_row WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id)=(organization_value,workspace_value,environment_value,sensor_value) AND sensor_row.state<>'deleted';
 IF result_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor missing';END IF;RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_public_sensor_coverage(organization_value text,workspace_value text,environment_value text,sensor_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(sensor_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor query rejected';END IF;
 SELECT jsonb_build_object('sensor_id',sensor_row.id,'supported',sensor_row.kind IN('tetragon','otlp'),'status',CASE WHEN sensor_row.state IN('revoked','deleted') THEN 'revoked' WHEN heartbeat_row.sensor_id IS NULL THEN 'pending' WHEN heartbeat_row.observed_at<transaction_timestamp()-interval '5 minutes' THEN 'offline' ELSE heartbeat_row.status END,
  'last_heartbeat',CASE WHEN heartbeat_row.observed_at IS NULL THEN NULL ELSE to_char(heartbeat_row.observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,'kernel',COALESCE(heartbeat_row.metadata->>'kernel',''),'btf',COALESCE((heartbeat_row.metadata->>'btf')::boolean,false),'capabilities',COALESCE(heartbeat_row.metadata->'capabilities','[]'::jsonb),'event_rate',COALESCE((heartbeat_row.metadata->>'event_rate')::numeric,0),'drops',COALESCE(heartbeat_row.dropped_events,0)) INTO result_value
 FROM zasp_sensors sensor_row LEFT JOIN zasp_sensor_heartbeats heartbeat_row ON (heartbeat_row.organization_id,heartbeat_row.workspace_id,heartbeat_row.environment_id,heartbeat_row.sensor_id)=(sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id)
 WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id)=(organization_value,workspace_value,environment_value,sensor_value) AND sensor_row.state<>'deleted';
 IF result_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor missing';END IF;RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_public_sensor_token_authority(organization_value text,workspace_value text,environment_value text,sensor_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(sensor_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor query rejected';END IF;
 SELECT jsonb_build_object('generation',token_row.token_generation,'sensor_version',sensor_row.version) INTO result_value
 FROM zasp_sensors sensor_row JOIN zasp_sensor_tokens token_row ON (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id,token_row.sensor_version_at_issue)=(sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id,sensor_row.version)
 WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id)=(organization_value,workspace_value,environment_value,sensor_value) AND sensor_row.state IN('pending','active','degraded') AND token_row.format_version=1 AND token_row.revoked_at IS NULL AND token_row.expires_at>transaction_timestamp()
 ORDER BY token_row.token_generation DESC LIMIT 1;
 IF result_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor missing';END IF;RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_public_create_sensor(organization_value text,workspace_value text,environment_value text,principal_value text,sensor_value text,name_value text,kind_value text,mode_value text,idempotency_value text,request_digest_value bytea,token_value text,generation_value bigint,locator_digest_value bytea,salt_value bytea,token_hash_value bytea,expires_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE prior_value zasp_runtime_sensor_mutations%ROWTYPE;result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(principal_value) OR NOT zasp_valid_product_id(sensor_value) OR NOT zasp_valid_product_id(token_value) OR length(name_value) NOT BETWEEN 1 AND 128 OR name_value<>btrim(name_value) OR name_value ~ '[[:cntrl:]]' OR kind_value NOT IN('tetragon','otlp') OR mode_value NOT IN('metadata_only','full') OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR octet_length(request_digest_value)<>32 OR generation_value<>1 OR octet_length(locator_digest_value)<>32 OR octet_length(salt_value)<>32 OR octet_length(token_hash_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor mutation rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,principal_value,'createSensorEnrollment',idempotency_value),0));
 SELECT * INTO prior_value FROM zasp_runtime_sensor_mutations mutation WHERE (mutation.organization_id,mutation.workspace_id,mutation.environment_id,mutation.principal_id,mutation.operation,mutation.idempotency_key)=(organization_value,workspace_value,environment_value,principal_value,'createSensorEnrollment',idempotency_value);
 IF FOUND THEN IF prior_value.request_digest IS DISTINCT FROM request_digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor mutation conflict';END IF;RETURN jsonb_set(prior_value.result,'{replayed}','true'::jsonb);END IF;
 IF EXISTS(SELECT 1 FROM zasp_sensors sensor_row WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id)=(organization_value,workspace_value,environment_value,sensor_value)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor mutation conflict';END IF;
 INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,mode) VALUES(organization_value,workspace_value,environment_value,sensor_value,name_value,kind_value,mode_value);
 PERFORM zasp_runtime_issue_sensor_token(organization_value,workspace_value,environment_value,sensor_value,token_value,generation_value,1,locator_digest_value,salt_value,token_hash_value,expires_value);
 result_value:=jsonb_build_object('body',zasp_runtime_public_sensor_value(organization_value,workspace_value,environment_value,sensor_value),'token_id',token_value,'token_generation',generation_value,'token_expires_at',to_char(expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'replayed',false);
 INSERT INTO zasp_runtime_sensor_mutations(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,request_digest,sensor_id,expected_version,token_id,token_generation,result) VALUES(organization_value,workspace_value,environment_value,principal_value,'createSensorEnrollment',idempotency_value,request_digest_value,sensor_value,0,token_value,generation_value,result_value);
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_public_update_sensor(organization_value text,workspace_value text,environment_value text,principal_value text,sensor_value text,expected_version_value bigint,name_value text,mode_value text,idempotency_value text,request_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE prior_value zasp_runtime_sensor_mutations%ROWTYPE;result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(principal_value) OR NOT zasp_valid_product_id(sensor_value) OR expected_version_value<1 OR length(name_value) NOT BETWEEN 1 AND 128 OR name_value<>btrim(name_value) OR name_value ~ '[[:cntrl:]]' OR mode_value NOT IN('metadata_only','full') OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR octet_length(request_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor mutation rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,sensor_value),0));
 SELECT * INTO prior_value FROM zasp_runtime_sensor_mutations mutation WHERE (mutation.organization_id,mutation.workspace_id,mutation.environment_id,mutation.principal_id,mutation.operation,mutation.idempotency_key)=(organization_value,workspace_value,environment_value,principal_value,'updateSensor',idempotency_value);
 IF FOUND THEN IF (prior_value.request_digest,prior_value.sensor_id,prior_value.expected_version) IS DISTINCT FROM (request_digest_value,sensor_value,expected_version_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor mutation conflict';END IF;RETURN jsonb_set(prior_value.result,'{replayed}','true'::jsonb);END IF;
 UPDATE zasp_sensors sensor_row SET name=name_value,mode=mode_value,version=sensor_row.version+1,updated_at=transaction_timestamp() WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id,sensor_row.version)=(organization_value,workspace_value,environment_value,sensor_value,expected_version_value) AND sensor_row.state IN('pending','active','degraded');
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='sensor mutation conflict';END IF;
 UPDATE zasp_sensor_tokens token_row SET sensor_version_at_issue=expected_version_value+1 WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id)=(organization_value,workspace_value,environment_value,sensor_value) AND token_row.format_version=1 AND token_row.revoked_at IS NULL;
 result_value:=jsonb_build_object('body',zasp_runtime_public_sensor_value(organization_value,workspace_value,environment_value,sensor_value),'token_id',NULL,'token_generation',NULL,'token_expires_at',NULL,'replayed',false);
 INSERT INTO zasp_runtime_sensor_mutations(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,request_digest,sensor_id,expected_version,result) VALUES(organization_value,workspace_value,environment_value,principal_value,'updateSensor',idempotency_value,request_digest_value,sensor_value,expected_version_value,result_value);PERFORM zasp_runtime_mark_used();RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_public_delete_sensor(organization_value text,workspace_value text,environment_value text,principal_value text,sensor_value text,expected_version_value bigint,idempotency_value text,request_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE prior_value zasp_runtime_sensor_mutations%ROWTYPE;result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(principal_value) OR NOT zasp_valid_product_id(sensor_value) OR expected_version_value<1 OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR octet_length(request_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor mutation rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,sensor_value),0));
 SELECT * INTO prior_value FROM zasp_runtime_sensor_mutations mutation WHERE (mutation.organization_id,mutation.workspace_id,mutation.environment_id,mutation.principal_id,mutation.operation,mutation.idempotency_key)=(organization_value,workspace_value,environment_value,principal_value,'deleteSensor',idempotency_value);
 IF FOUND THEN IF (prior_value.request_digest,prior_value.sensor_id,prior_value.expected_version) IS DISTINCT FROM (request_digest_value,sensor_value,expected_version_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor mutation conflict';END IF;RETURN jsonb_set(prior_value.result,'{replayed}','true'::jsonb);END IF;
 UPDATE zasp_sensor_tokens token_row SET revoked_at=COALESCE(token_row.revoked_at,transaction_timestamp()) WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id)=(organization_value,workspace_value,environment_value,sensor_value) AND token_row.format_version=1;
 UPDATE zasp_sensors sensor_row SET state='deleted',version=sensor_row.version+1,updated_at=transaction_timestamp(),revoked_at=COALESCE(sensor_row.revoked_at,transaction_timestamp()) WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id,sensor_row.version)=(organization_value,workspace_value,environment_value,sensor_value,expected_version_value) AND sensor_row.state IN('pending','active','degraded','revoked');
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='sensor mutation conflict';END IF;
 result_value:=jsonb_build_object('body',zasp_runtime_public_sensor_value(organization_value,workspace_value,environment_value,sensor_value),'token_id',NULL,'token_generation',NULL,'token_expires_at',NULL,'replayed',false);
 INSERT INTO zasp_runtime_sensor_mutations(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,request_digest,sensor_id,expected_version,result) VALUES(organization_value,workspace_value,environment_value,principal_value,'deleteSensor',idempotency_value,request_digest_value,sensor_value,expected_version_value,result_value);PERFORM zasp_runtime_mark_used();RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_public_rotate_sensor(organization_value text,workspace_value text,environment_value text,principal_value text,sensor_value text,expected_version_value bigint,idempotency_value text,request_digest_value bytea,token_value text,generation_value bigint,locator_digest_value bytea,salt_value bytea,token_hash_value bytea,expires_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE prior_value zasp_runtime_sensor_mutations%ROWTYPE;current_token_value text;result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(principal_value) OR NOT zasp_valid_product_id(sensor_value) OR NOT zasp_valid_product_id(token_value) OR expected_version_value<1 OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR octet_length(request_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor mutation rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,sensor_value),0));
 SELECT * INTO prior_value FROM zasp_runtime_sensor_mutations mutation WHERE (mutation.organization_id,mutation.workspace_id,mutation.environment_id,mutation.principal_id,mutation.operation,mutation.idempotency_key)=(organization_value,workspace_value,environment_value,principal_value,'rotateSensorToken',idempotency_value);
 IF FOUND THEN IF (prior_value.request_digest,prior_value.sensor_id,prior_value.expected_version) IS DISTINCT FROM (request_digest_value,sensor_value,expected_version_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor mutation conflict';END IF;RETURN jsonb_set(prior_value.result,'{replayed}','true'::jsonb);END IF;
 SELECT token_row.id INTO current_token_value FROM zasp_sensor_tokens token_row JOIN zasp_sensors sensor_row ON (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id,sensor_row.version)=(token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id,expected_version_value) WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id)=(organization_value,workspace_value,environment_value,sensor_value) AND token_row.format_version=1 AND token_row.revoked_at IS NULL ORDER BY token_row.token_generation DESC LIMIT 1;
 IF current_token_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor mutation rejected';END IF;
 PERFORM zasp_runtime_rotate_sensor_token(organization_value,workspace_value,environment_value,sensor_value,current_token_value,token_value,generation_value,expected_version_value,locator_digest_value,salt_value,token_hash_value,expires_value);
 result_value:=jsonb_build_object('body',zasp_runtime_public_sensor_value(organization_value,workspace_value,environment_value,sensor_value),'token_id',token_value,'token_generation',generation_value,'token_expires_at',to_char(expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'replayed',false);
 INSERT INTO zasp_runtime_sensor_mutations(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,request_digest,sensor_id,expected_version,token_id,token_generation,result) VALUES(organization_value,workspace_value,environment_value,principal_value,'rotateSensorToken',idempotency_value,request_digest_value,sensor_value,expected_version_value,token_value,generation_value,result_value);RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_issue_gateway_enrollment(organization_value text,workspace_value text,environment_value text,enrollment_value text,device_value text,generation_value bigint,device_version_value bigint,locator_digest_value bytea,salt_value bytea,token_hash_value bytea,expires_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE result_value jsonb;expected_generation bigint;existing_value zasp_gateway_enrollment_tokens%ROWTYPE;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(enrollment_value) OR NOT zasp_valid_product_id(device_value) OR generation_value<1 OR device_version_value<1 OR octet_length(locator_digest_value)<>32 OR octet_length(salt_value)<>32 OR octet_length(token_hash_value)<>32 OR expires_value<=transaction_timestamp() OR expires_value>transaction_timestamp()+interval '24 hours' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway enrollment rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,device_value),0));
 SELECT * INTO existing_value FROM zasp_gateway_enrollment_tokens token_row WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.id)=(organization_value,workspace_value,environment_value,enrollment_value);
 IF FOUND THEN
  IF (existing_value.device_id,existing_value.format_version,existing_value.token_generation,existing_value.device_version_at_issue,existing_value.locator_digest,existing_value.salt,existing_value.token_hash,existing_value.expires_at) IS DISTINCT FROM (device_value,1,generation_value,device_version_value,locator_digest_value,salt_value,token_hash_value,expires_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='gateway enrollment conflict';END IF;
  RETURN jsonb_build_object('id',existing_value.id,'device_id',existing_value.device_id,'audience',existing_value.audience,'generation',existing_value.token_generation,'device_version',existing_value.device_version_at_issue,'issued_at',existing_value.issued_at,'expires_at',existing_value.expires_at,'replayed',true);
 END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_gateway_devices device_row WHERE (device_row.organization_id,device_row.workspace_id,device_row.environment_id,device_row.id,device_row.version)=(organization_value,workspace_value,environment_value,device_value,device_version_value) AND device_row.state IN('pending','active')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway enrollment rejected';END IF;
 SELECT COALESCE(max(token_row.token_generation),0)+1 INTO expected_generation FROM zasp_gateway_enrollment_tokens token_row WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.device_id)=(organization_value,workspace_value,environment_value,device_value) AND token_row.token_generation IS NOT NULL;
 IF generation_value<>expected_generation OR EXISTS(SELECT 1 FROM zasp_gateway_enrollment_tokens token_row WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.device_id)=(organization_value,workspace_value,environment_value,device_value) AND token_row.format_version=1 AND token_row.consumed_at IS NULL AND token_row.revoked_at IS NULL) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway enrollment conflict';END IF;
 INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at,format_version,locator_digest,token_generation,device_version_at_issue,v15_issued_at)
 VALUES(organization_value,workspace_value,environment_value,enrollment_value,device_value,'runtime-gateway-enroll',salt_value,token_hash_value,expires_value,1,locator_digest_value,generation_value,device_version_value,transaction_timestamp())
 RETURNING jsonb_build_object('id',id,'device_id',device_id,'audience',audience,'generation',token_generation,'device_version',device_version_at_issue,'issued_at',issued_at,'expires_at',expires_at,'replayed',false) INTO result_value;
 PERFORM zasp_runtime_mark_used();
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_revoke_gateway_enrollment(organization_value text,workspace_value text,environment_value text,device_value text,enrollment_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE revoked_value timestamptz;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(device_value) OR NOT zasp_valid_product_id(enrollment_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway enrollment rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,device_value),0));
 UPDATE zasp_gateway_enrollment_tokens token_row SET revoked_at=COALESCE(token_row.revoked_at,transaction_timestamp()) WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.device_id,token_row.id)=(organization_value,workspace_value,environment_value,device_value,enrollment_value) AND token_row.format_version=1 RETURNING token_row.revoked_at INTO revoked_value;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway enrollment rejected';END IF;
 PERFORM zasp_runtime_mark_used();
 RETURN jsonb_build_object('id',enrollment_value,'revoked_at',revoked_value);
END $$;

CREATE FUNCTION public.zasp_runtime_authenticate_gateway_enrollment(locator_value bytea,secret_value bytea,audience_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE locator_hash bytea;candidate_scope record;token_row zasp_gateway_enrollment_tokens%ROWTYPE;device_row zasp_gateway_devices%ROWTYPE;computed_hash bytea;
BEGIN
 IF NOT zasp_runtime_principal_ready('zasp_gateway_control') OR octet_length(locator_value)<>16 OR octet_length(secret_value)<>32 OR audience_value<>'runtime-gateway-enroll' THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway authentication rejected';END IF;
 locator_hash:=digest(locator_value,'sha256');
 SELECT token_value.organization_id,token_value.workspace_id,token_value.environment_id,token_value.device_id INTO candidate_scope FROM zasp_gateway_enrollment_tokens token_value WHERE token_value.locator_digest=locator_hash;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway authentication rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),candidate_scope.organization_id,candidate_scope.workspace_id,candidate_scope.environment_id,candidate_scope.device_id),0));
 SELECT token_value.* INTO token_row FROM zasp_gateway_enrollment_tokens token_value WHERE token_value.locator_digest=locator_hash FOR UPDATE;
 SELECT device_value.* INTO device_row FROM zasp_gateway_devices device_value WHERE (device_value.organization_id,device_value.workspace_id,device_value.environment_id,device_value.id)=(token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.device_id) FOR UPDATE;
 computed_hash:=zasp_runtime_gateway_enrollment_secret_hash(audience_value,token_row.id,token_row.token_generation,token_row.salt,secret_value);
 IF token_row.format_version<>1 OR token_row.audience<>audience_value OR token_row.revoked_at IS NOT NULL OR token_row.expires_at<=transaction_timestamp() OR device_row.state NOT IN('pending','active') OR digest(token_row.token_hash||computed_hash,'sha256')<>digest(token_row.token_hash||token_row.token_hash,'sha256') OR EXISTS(SELECT 1 FROM zasp_gateway_enrollment_tokens newer WHERE (newer.organization_id,newer.workspace_id,newer.environment_id,newer.device_id)=(token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.device_id) AND newer.token_generation>token_row.token_generation) THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway authentication rejected';END IF;
 RETURN jsonb_build_object('organization_id',token_row.organization_id,'workspace_id',token_row.workspace_id,'environment_id',token_row.environment_id,'device_id',token_row.device_id,'device_version',device_row.version,'enrollment_id',token_row.id,'token_generation',token_row.token_generation,'consumed',token_row.consumed_at IS NOT NULL,'audience',token_row.audience);
END $$;

CREATE FUNCTION public.zasp_runtime_gateway_enroll(locator_value bytea,secret_value bytea,audience_value text,credential_value text,generation_value bigint,key_id_value text,algorithm_value text,public_key_value bytea,expires_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;organization_value text;workspace_value text;environment_value text;device_value text;enrollment_value text;requested_digest bytea;existing_value zasp_gateway_credentials%ROWTYPE;expected_generation bigint;result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(credential_value) OR generation_value<1 OR key_id_value !~ '^[a-z][a-z0-9_-]{7,63}$' OR algorithm_value<>'Ed25519' OR octet_length(public_key_value)<>32 OR expires_value<=transaction_timestamp() OR expires_value>transaction_timestamp()+interval '90 days' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway enrollment rejected';END IF;
 authority_value:=zasp_runtime_authenticate_gateway_enrollment(locator_value,secret_value,audience_value);
 organization_value:=authority_value->>'organization_id';workspace_value:=authority_value->>'workspace_id';environment_value:=authority_value->>'environment_id';device_value:=authority_value->>'device_id';enrollment_value:=authority_value->>'enrollment_id';
 requested_digest:=digest(convert_to(concat_ws(chr(31),organization_value,workspace_value,environment_value,device_value,enrollment_value,credential_value,generation_value::text,key_id_value,algorithm_value,encode(public_key_value,'hex'),floor(extract(epoch FROM expires_value)*1000000)::bigint::text),'UTF8'),'sha256');
 SELECT * INTO existing_value FROM zasp_gateway_credentials credential_row WHERE (credential_row.organization_id,credential_row.workspace_id,credential_row.environment_id,credential_row.device_id,credential_row.enrollment_token_id)=(organization_value,workspace_value,environment_value,device_value,enrollment_value);
 IF FOUND THEN IF existing_value.enrollment_digest<>requested_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='gateway enrollment conflict';END IF;RETURN jsonb_build_object('id',existing_value.id,'device_id',existing_value.device_id,'credential_generation',existing_value.credential_generation,'key_id',existing_value.key_id,'algorithm',existing_value.algorithm,'audience',existing_value.audience,'issued_at',existing_value.issued_at,'expires_at',existing_value.expires_at,'replayed',true);END IF;
 IF (authority_value->>'consumed')::boolean THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway enrollment rejected';END IF;
 SELECT COALESCE(max(credential_row.credential_generation),0)+1 INTO expected_generation FROM zasp_gateway_credentials credential_row WHERE (credential_row.organization_id,credential_row.workspace_id,credential_row.environment_id,credential_row.device_id)=(organization_value,workspace_value,environment_value,device_value) AND credential_row.credential_generation IS NOT NULL;
 IF generation_value<>expected_generation OR EXISTS(SELECT 1 FROM zasp_gateway_credentials credential_row WHERE (credential_row.organization_id,credential_row.workspace_id,credential_row.environment_id,credential_row.device_id)=(organization_value,workspace_value,environment_value,device_value) AND credential_row.format_version=1 AND credential_row.revoked_at IS NULL) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway enrollment conflict';END IF;
 UPDATE zasp_gateway_enrollment_tokens token_row SET consumed_at=transaction_timestamp() WHERE (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.device_id,token_row.id)=(organization_value,workspace_value,environment_value,device_value,enrollment_value) AND token_row.consumed_at IS NULL AND token_row.revoked_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway enrollment rejected';END IF;
 INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at)
 VALUES(organization_value,workspace_value,environment_value,credential_value,device_value,enrollment_value,requested_digest,'runtime-gateway','ref:gateway/public/'||key_id_value,public_key_value,expires_value,1,generation_value,key_id_value,algorithm_value,transaction_timestamp())
 RETURNING jsonb_build_object('id',id,'device_id',device_id,'credential_generation',credential_generation,'key_id',key_id,'algorithm',algorithm,'audience',audience,'issued_at',issued_at,'expires_at',expires_at,'replayed',false) INTO result_value;
 UPDATE zasp_gateway_devices device_row SET state='active',version=device_row.version+1,updated_at=transaction_timestamp() WHERE (device_row.organization_id,device_row.workspace_id,device_row.environment_id,device_row.id)=(organization_value,workspace_value,environment_value,device_value) AND device_row.state IN('pending','active');
 PERFORM zasp_runtime_mark_used();
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_gateway_credential_authority(credential_value text,audience_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE credential_row zasp_gateway_credentials%ROWTYPE;device_row zasp_gateway_devices%ROWTYPE;
BEGIN
 IF NOT zasp_runtime_principal_ready('zasp_gateway_control') OR NOT zasp_valid_product_id(credential_value) OR audience_value<>'runtime-gateway' THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway authentication rejected';END IF;
 SELECT * INTO credential_row FROM zasp_gateway_credentials value WHERE value.id=credential_value AND value.format_version=1;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway authentication rejected';END IF;
 SELECT * INTO device_row FROM zasp_gateway_devices value WHERE (value.organization_id,value.workspace_id,value.environment_id,value.id)=(credential_row.organization_id,credential_row.workspace_id,credential_row.environment_id,credential_row.device_id);
 IF credential_row.audience<>audience_value OR credential_row.revoked_at IS NOT NULL OR credential_row.expires_at<=transaction_timestamp() OR device_row.state<>'active' OR EXISTS(SELECT 1 FROM zasp_gateway_credentials newer WHERE (newer.organization_id,newer.workspace_id,newer.environment_id,newer.device_id)=(credential_row.organization_id,credential_row.workspace_id,credential_row.environment_id,credential_row.device_id) AND newer.credential_generation>credential_row.credential_generation) THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway authentication rejected';END IF;
 RETURN jsonb_build_object('organization_id',credential_row.organization_id,'workspace_id',credential_row.workspace_id,'environment_id',credential_row.environment_id,'device_id',credential_row.device_id,'device_version',device_row.version,'replay_floor',device_row.replay_floor,'credential_id',credential_row.id,'credential_generation',credential_row.credential_generation,'key_id',credential_row.key_id,'algorithm',credential_row.algorithm,'public_key',translate(rtrim(encode(credential_row.public_key,'base64'),'='),'+/','-_'),'audience',credential_row.audience,'expires_at',credential_row.expires_at);
END $$;

CREATE FUNCTION public.zasp_runtime_gateway_advance_replay(credential_value text,expected_floor_value bigint,next_floor_value bigint,request_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;organization_value text;workspace_value text;environment_value text;device_value text;prior_digest bytea;
BEGIN
 IF expected_floor_value<0 OR next_floor_value<=expected_floor_value OR octet_length(request_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway replay rejected';END IF;
 authority_value:=zasp_runtime_gateway_credential_authority(credential_value,'runtime-gateway');organization_value:=authority_value->>'organization_id';workspace_value:=authority_value->>'workspace_id';environment_value:=authority_value->>'environment_id';device_value:=authority_value->>'device_id';
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,device_value),0));
 SELECT receipt.request_digest INTO prior_digest FROM zasp_runtime_gateway_replay_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.device_id,receipt.next_floor)=(organization_value,workspace_value,environment_value,device_value,next_floor_value);
 IF FOUND THEN IF prior_digest<>request_digest_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway replay rejected';END IF;RETURN jsonb_build_object('credential_id',credential_value,'replay_floor',next_floor_value,'replayed',true);END IF;
 UPDATE zasp_gateway_devices device_row SET replay_floor=next_floor_value,version=device_row.version+1,updated_at=transaction_timestamp() WHERE (device_row.organization_id,device_row.workspace_id,device_row.environment_id,device_row.id,device_row.replay_floor)=(organization_value,workspace_value,environment_value,device_value,expected_floor_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway replay rejected';END IF;
 INSERT INTO zasp_runtime_gateway_replay_receipts(organization_id,workspace_id,environment_id,device_id,credential_id,next_floor,request_digest) VALUES(organization_value,workspace_value,environment_value,device_value,credential_value,next_floor_value,request_digest_value);
 RETURN jsonb_build_object('credential_id',credential_value,'replay_floor',next_floor_value,'replayed',false);
END $$;

CREATE FUNCTION public.zasp_runtime_gateway_put_policy_bundle(credential_value text,sequence_value bigint,policy_version_value bigint,key_id_value text,issued_value timestamptz,expires_value timestamptz,failure_mode_value text,payload_digest_value bytea,policies_value jsonb,signature_value bytea,envelope_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;organization_value text;workspace_value text;environment_value text;device_value text;prior_value zasp_runtime_gateway_policy_bundles%ROWTYPE;latest_value zasp_runtime_gateway_policy_bundles%ROWTYPE;result_value jsonb;
BEGIN
 IF sequence_value<1 OR policy_version_value<1 OR key_id_value !~ '^[a-z][a-z0-9_-]{7,63}$' OR issued_value>transaction_timestamp()+interval '30 seconds' OR expires_value<=transaction_timestamp() OR expires_value<=issued_value OR expires_value>issued_value+interval '24 hours' OR failure_mode_value NOT IN('open','closed') OR octet_length(payload_digest_value)<>32 OR jsonb_typeof(policies_value)<>'array' OR jsonb_array_length(policies_value)>100 OR octet_length(convert_to(policies_value::text,'UTF8'))>1048576 OR octet_length(signature_value)<>64 OR octet_length(envelope_digest_value)<>32 OR EXISTS(SELECT 1 FROM jsonb_array_elements(policies_value) item WHERE jsonb_typeof(item)<>'object' OR item->>'id' IS NULL OR length(item->>'id') NOT BETWEEN 1 AND 128) OR (SELECT count(*) FROM jsonb_array_elements(policies_value))<>(SELECT count(DISTINCT item->>'id') FROM jsonb_array_elements(policies_value) item) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway policy rejected';END IF;
 authority_value:=zasp_runtime_gateway_credential_authority(credential_value,'runtime-gateway');organization_value:=authority_value->>'organization_id';workspace_value:=authority_value->>'workspace_id';environment_value:=authority_value->>'environment_id';device_value:=authority_value->>'device_id';
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,device_value,'gateway-policy'),0));
 SELECT * INTO prior_value FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id,bundle.sequence)=(organization_value,workspace_value,environment_value,device_value,sequence_value);
 IF FOUND THEN IF (prior_value.credential_id,prior_value.policy_version,prior_value.key_id,prior_value.issued_at,prior_value.expires_at,prior_value.failure_mode,prior_value.payload_digest,prior_value.policies,prior_value.signature,prior_value.envelope_digest) IS DISTINCT FROM (credential_value,policy_version_value,key_id_value,issued_value,expires_value,failure_mode_value,payload_digest_value,policies_value,signature_value,envelope_digest_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway policy rejected';END IF;RETURN jsonb_build_object('device_id',device_value,'sequence',sequence_value,'policy_version',policy_version_value,'envelope_digest',encode(envelope_digest_value,'hex'),'replayed',true);END IF;
 SELECT * INTO latest_value FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id)=(organization_value,workspace_value,environment_value,device_value) ORDER BY bundle.sequence DESC LIMIT 1;
 IF FOUND AND (sequence_value<=latest_value.sequence OR policy_version_value<latest_value.policy_version OR policy_version_value=latest_value.policy_version AND (payload_digest_value,failure_mode_value,policies_value) IS DISTINCT FROM (latest_value.payload_digest,latest_value.failure_mode,latest_value.policies)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway policy rejected';END IF;
 INSERT INTO zasp_runtime_gateway_policy_bundles(organization_id,workspace_id,environment_id,device_id,credential_id,sequence,policy_version,key_id,algorithm,audience,issued_at,expires_at,failure_mode,payload_digest,policies,signature,envelope_digest) VALUES(organization_value,workspace_value,environment_value,device_value,credential_value,sequence_value,policy_version_value,key_id_value,'Ed25519','runtime-gateway-policy',issued_value,expires_value,failure_mode_value,payload_digest_value,policies_value,signature_value,envelope_digest_value);
 result_value:=jsonb_build_object('device_id',device_value,'sequence',sequence_value,'policy_version',policy_version_value,'envelope_digest',encode(envelope_digest_value,'hex'),'replayed',false);
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_gateway_policy_bundle(credential_value text,after_sequence_value bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;bundle_value zasp_runtime_gateway_policy_bundles%ROWTYPE;
BEGIN
 IF after_sequence_value<0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway policy rejected';END IF;
 authority_value:=zasp_runtime_gateway_credential_authority(credential_value,'runtime-gateway');
 SELECT * INTO bundle_value FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id)=(authority_value->>'organization_id',authority_value->>'workspace_id',authority_value->>'environment_id',authority_value->>'device_id') AND bundle.sequence>after_sequence_value ORDER BY bundle.sequence DESC LIMIT 1;
 IF NOT FOUND THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('contract_version',bundle_value.contract_version,'key_id',bundle_value.key_id,'algorithm',bundle_value.algorithm,'audience',bundle_value.audience,'organization_id',bundle_value.organization_id,'workspace_id',bundle_value.workspace_id,'environment_id',bundle_value.environment_id,'device_id',bundle_value.device_id,'credential_id',bundle_value.credential_id,'sequence',bundle_value.sequence,'policy_version',bundle_value.policy_version,'issued_at',to_char(bundle_value.issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char(bundle_value.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'failure_mode',bundle_value.failure_mode,'payload_digest',encode(bundle_value.payload_digest,'hex'),'policies',bundle_value.policies,'signature',translate(rtrim(encode(bundle_value.signature,'base64'),'='),'+/','-_'));
END $$;

CREATE FUNCTION public.zasp_runtime_gateway_record_event(credential_value text,event_value text,expected_floor_value bigint,next_floor_value bigint,request_digest_value bytea,policy_version_value bigint,decision_value text,action_kind_value text,classification_value jsonb,occurred_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;organization_value text;workspace_value text;environment_value text;device_value text;existing_value zasp_runtime_gateway_events%ROWTYPE;canonical_digest bytea;result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(event_value) OR expected_floor_value<0 OR next_floor_value<=expected_floor_value OR octet_length(request_digest_value)<>32 OR policy_version_value<1 OR decision_value NOT IN('allow','monitor','block') OR action_kind_value NOT IN('http','mcp') OR jsonb_typeof(classification_value)<>'object'
  OR NOT classification_value ?& ARRAY['category','route_class','resource_class','outcome']
  OR classification_value-ARRAY['category','route_class','resource_class','outcome','agent_id','target_id','capability_category','capability_outcome']<>'{}'::jsonb
  OR octet_length(convert_to(classification_value::text,'UTF8'))>16384
  OR EXISTS(SELECT 1 FROM jsonb_each_text(classification_value) item WHERE length(item.value) NOT BETWEEN 1 AND 64 OR item.value<>btrim(item.value) OR item.value!~'^[a-z][a-z0-9._:-]{0,63}$')
  OR classification_value ?| ARRAY['agent_id','target_id','capability_category','capability_outcome'] AND (
   decision_value<>'block' OR NOT classification_value ?& ARRAY['agent_id','target_id','capability_category','capability_outcome']
   OR NOT zasp_valid_product_id(classification_value->>'agent_id') OR NOT zasp_valid_product_id(classification_value->>'target_id')
   OR (classification_value->>'capability_category',classification_value->>'capability_outcome') NOT IN(('data_read','read'),('data_write','write'),('action_execute','execute'),('identity_assume','assume'),('network_egress','connect'),('administration','administer'))
  )
  OR occurred_value<transaction_timestamp()-interval '24 hours' OR occurred_value>transaction_timestamp()+interval '30 seconds'
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway event rejected';END IF;
 authority_value:=zasp_runtime_gateway_credential_authority(credential_value,'runtime-gateway');organization_value:=authority_value->>'organization_id';workspace_value:=authority_value->>'workspace_id';environment_value:=authority_value->>'environment_id';device_value:=authority_value->>'device_id';
 canonical_digest:=digest(convert_to(jsonb_build_object('credential_id',credential_value,'device_id',device_value,'event_id',event_value,'expected_floor',expected_floor_value,'next_floor',next_floor_value,'policy_version',policy_version_value,'decision',decision_value,'action_kind',action_kind_value,'classification',classification_value,'occurred_at',to_char(occurred_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text,'UTF8'),'sha256');
 IF canonical_digest<>request_digest_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway event rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,device_value),0));
 SELECT * INTO existing_value FROM zasp_runtime_gateway_events event_row WHERE (event_row.organization_id,event_row.workspace_id,event_row.environment_id,event_row.event_id)=(organization_value,workspace_value,environment_value,event_value);
 IF FOUND THEN
  IF (existing_value.device_id,existing_value.credential_id,existing_value.sequence,existing_value.request_digest,existing_value.policy_version,existing_value.decision,existing_value.action_kind,existing_value.classification,existing_value.occurred_at) IS DISTINCT FROM (device_value,credential_value,next_floor_value,request_digest_value,policy_version_value,decision_value,action_kind_value,classification_value,occurred_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway event rejected';END IF;
  RETURN jsonb_build_object('event_id',event_value,'device_id',device_value,'sequence',next_floor_value,'recorded_at',existing_value.recorded_at,'replayed',true);
 END IF;
 IF classification_value ? 'agent_id' THEN
  PERFORM zasp_inventory_record_capability_evidence(organization_value,workspace_value,environment_value,classification_value->>'agent_id',classification_value->>'target_id',classification_value->>'capability_category',classification_value->>'capability_outcome','runtime_policy',event_value,occurred_value);
 END IF;
 PERFORM zasp_runtime_gateway_advance_replay(credential_value,expected_floor_value,next_floor_value,request_digest_value);
 INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) VALUES(organization_value,workspace_value,environment_value,device_value,credential_value,event_value,next_floor_value,request_digest_value,policy_version_value,decision_value,action_kind_value,classification_value,occurred_value)
 RETURNING jsonb_build_object('event_id',event_id,'device_id',device_id,'sequence',sequence,'recorded_at',recorded_at,'replayed',false) INTO result_value;
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_authenticate_sensor(locator_value bytea,secret_value bytea,audience_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE locator_hash bytea;candidate_scope record;token_row zasp_sensor_tokens%ROWTYPE;sensor_row zasp_sensors%ROWTYPE;computed_hash bytea;
BEGIN
 IF octet_length(locator_value)<>16 OR octet_length(secret_value)<>32 OR audience_value<>'event-ingest' THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='sensor authentication rejected';END IF;
 locator_hash:=digest(locator_value,'sha256');
 SELECT token_value.organization_id,token_value.workspace_id,token_value.environment_id,token_value.sensor_id INTO candidate_scope FROM zasp_sensor_tokens token_value WHERE token_value.locator_digest=locator_hash;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='sensor authentication rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),candidate_scope.organization_id,candidate_scope.workspace_id,candidate_scope.environment_id,candidate_scope.sensor_id),0));
 SELECT token_value.* INTO token_row FROM zasp_sensor_tokens token_value WHERE token_value.locator_digest=locator_hash FOR UPDATE;
 SELECT sensor_value.* INTO sensor_row FROM zasp_sensors sensor_value WHERE (sensor_value.organization_id,sensor_value.workspace_id,sensor_value.environment_id,sensor_value.id)=(token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id) FOR UPDATE;
 computed_hash:=zasp_runtime_sensor_secret_hash(audience_value,token_row.id,token_row.token_generation,token_row.salt,secret_value);
 IF token_row.format_version<>1 OR token_row.audience<>audience_value OR token_row.revoked_at IS NOT NULL OR token_row.expires_at<=transaction_timestamp()
  OR token_row.sensor_version_at_issue<>sensor_row.version OR sensor_row.state NOT IN('pending','active','degraded')
  OR digest(token_row.token_hash||computed_hash,'sha256')<>digest(token_row.token_hash||token_row.token_hash,'sha256')
  OR EXISTS(SELECT 1 FROM zasp_sensor_tokens newer WHERE (newer.organization_id,newer.workspace_id,newer.environment_id,newer.sensor_id)=(token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id) AND newer.token_generation>token_row.token_generation)
 THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='sensor authentication rejected';END IF;
 UPDATE zasp_sensor_tokens token_value SET last_authenticated_at=transaction_timestamp() WHERE (token_value.organization_id,token_value.workspace_id,token_value.environment_id,token_value.id)=(token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.id);
 PERFORM zasp_runtime_mark_used();
 RETURN jsonb_build_object('organization_id',token_row.organization_id,'workspace_id',token_row.workspace_id,'environment_id',token_row.environment_id,'sensor_id',token_row.sensor_id,'sensor_kind',sensor_row.kind,'sensor_mode',sensor_row.mode,'sensor_version',sensor_row.version,'token_id',token_row.id,'token_generation',token_row.token_generation,'audience',token_row.audience);
END $$;

CREATE FUNCTION public.zasp_runtime_sensor_heartbeat(locator_value bytea,secret_value bytea,audience_value text,sequence_value bigint,status_value text,capabilities_value jsonb,kernel_value text,btf_value boolean,event_rate_value bigint,drops_value bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;organization_value text;workspace_value text;environment_value text;sensor_value text;metadata_value jsonb;request_digest_value bytea;prior_digest bytea;prior_sequence bigint;observed_value timestamptz;
BEGIN
 IF sequence_value<0 OR status_value NOT IN('healthy','degraded') OR jsonb_typeof(capabilities_value)<>'array' OR jsonb_array_length(capabilities_value) NOT BETWEEN 1 AND 32
  OR length(kernel_value) NOT BETWEEN 1 AND 128 OR kernel_value<>btrim(kernel_value) OR kernel_value ~ '[[:cntrl:]]' OR event_rate_value NOT BETWEEN 0 AND 1000000000 OR drops_value NOT BETWEEN 0 AND 1000000000
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(capabilities_value) item WHERE jsonb_typeof(item)<>'string' OR item#>>'{}' !~ '^[a-z0-9][a-z0-9_.-]{0,95}$')
  OR (SELECT count(*) FROM jsonb_array_elements_text(capabilities_value))<>(SELECT count(DISTINCT item) FROM jsonb_array_elements_text(capabilities_value) item)
  OR capabilities_value<>(SELECT jsonb_agg(item ORDER BY item) FROM jsonb_array_elements_text(capabilities_value) item)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor heartbeat rejected';END IF;
 authority_value:=zasp_runtime_authenticate_sensor(locator_value,secret_value,audience_value);
 organization_value:=authority_value->>'organization_id';workspace_value:=authority_value->>'workspace_id';environment_value:=authority_value->>'environment_id';sensor_value:=authority_value->>'sensor_id';
 metadata_value:=jsonb_build_object('capabilities',capabilities_value,'kernel',kernel_value,'btf',btf_value,'event_rate',event_rate_value,'drops',drops_value,'schema_version','sensor-heartbeat-v1');
 request_digest_value:=digest(convert_to(jsonb_build_object('sensor_id',sensor_value,'sequence',sequence_value,'status',status_value,'dropped_events',drops_value,'metadata',metadata_value)::text,'UTF8'),'sha256');
 SELECT heartbeat.request_digest,heartbeat.sequence,heartbeat.observed_at INTO prior_digest,prior_sequence,observed_value FROM zasp_sensor_heartbeats heartbeat WHERE (heartbeat.organization_id,heartbeat.workspace_id,heartbeat.environment_id,heartbeat.sensor_id)=(organization_value,workspace_value,environment_value,sensor_value);
 IF FOUND AND prior_sequence=sequence_value THEN IF prior_digest<>request_digest_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='sensor heartbeat conflict';END IF;RETURN jsonb_build_object('sensor_id',sensor_value,'sequence',sequence_value,'observed_at',observed_value);ELSIF FOUND AND prior_sequence>sequence_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='sensor heartbeat conflict';END IF;
 INSERT INTO zasp_sensor_heartbeats(organization_id,workspace_id,environment_id,sensor_id,sequence,request_digest,status,dropped_events,metadata)
 VALUES(organization_value,workspace_value,environment_value,sensor_value,sequence_value,request_digest_value,status_value,drops_value,metadata_value)
 ON CONFLICT(organization_id,workspace_id,environment_id,sensor_id) DO UPDATE SET sequence=excluded.sequence,request_digest=excluded.request_digest,status=excluded.status,dropped_events=excluded.dropped_events,metadata=excluded.metadata,observed_at=transaction_timestamp() RETURNING observed_at INTO observed_value;
 UPDATE zasp_sensors sensor_row SET state=CASE WHEN status_value='healthy' THEN 'active' ELSE 'degraded' END,updated_at=transaction_timestamp() WHERE (sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id)=(organization_value,workspace_value,environment_value,sensor_value) AND sensor_row.state IN('pending','active','degraded');
 RETURN jsonb_build_object('sensor_id',sensor_value,'sequence',sequence_value,'observed_at',observed_value);
END $$;

CREATE FUNCTION public.zasp_runtime_reserve_batch(locator_value bytea,secret_value bytea,audience_value text,batch_value text,idempotency_value text,content_digest_value bytea,source_kind_value text,media_type_value text,schema_version_value text,payload_size_value bigint,event_count_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;organization_value text;workspace_value text;environment_value text;sensor_value text;token_value text;token_generation_value bigint;generation_value bigint;request_digest_value bytea;artifact_key_value text;prior_value zasp_runtime_batch_authorities%ROWTYPE;recent_batches bigint;recent_events bigint;recent_bytes bigint;
BEGIN
 IF NOT zasp_valid_product_id(batch_value) OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR octet_length(content_digest_value)<>32 OR source_kind_value NOT IN('tetragon','otlp') OR length(media_type_value) NOT BETWEEN 1 AND 128 OR media_type_value<>btrim(media_type_value) OR length(schema_version_value) NOT BETWEEN 1 AND 64 OR schema_version_value !~ '^[a-z0-9][a-z0-9_.-]+$' OR payload_size_value NOT BETWEEN 1 AND 67108864 OR event_count_value NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime batch rejected';END IF;
 authority_value:=zasp_runtime_authenticate_sensor(locator_value,secret_value,audience_value);
 organization_value:=authority_value->>'organization_id';workspace_value:=authority_value->>'workspace_id';environment_value:=authority_value->>'environment_id';sensor_value:=authority_value->>'sensor_id';token_value:=authority_value->>'token_id';token_generation_value:=(authority_value->>'token_generation')::bigint;
 IF authority_value->>'sensor_kind'<>source_kind_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime batch rejected';END IF;
 request_digest_value:=digest(convert_to(jsonb_build_object('sensor_id',sensor_value,'token_id',token_value,'token_generation',token_generation_value,'batch_id',batch_value,'idempotency_key',idempotency_value,'content_digest',encode(content_digest_value,'hex'),'source_kind',source_kind_value,'media_type',media_type_value,'schema_version',schema_version_value,'payload_size_bytes',payload_size_value,'event_count',event_count_value)::text,'UTF8'),'sha256');
 SELECT * INTO prior_value FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.sensor_id,authority_row.idempotency_key)=(organization_value,workspace_value,environment_value,sensor_value,idempotency_value);
 IF FOUND THEN
 IF (prior_value.batch_id,prior_value.sensor_token_id,prior_value.token_generation,prior_value.request_digest,prior_value.content_digest,prior_value.source_kind,prior_value.payload_media_type,prior_value.payload_schema_version,prior_value.payload_size_bytes,prior_value.event_count) IS DISTINCT FROM (batch_value,token_value,token_generation_value,request_digest_value,content_digest_value,source_kind_value,media_type_value,schema_version_value,payload_size_value,event_count_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime batch conflict';END IF;
  RETURN jsonb_build_object('batch_id',prior_value.batch_id,'generation',prior_value.batch_generation,'artifact_key',prior_value.raw_artifact_key,'request_digest',encode(prior_value.request_digest,'hex'),'state',prior_value.state,'replayed',true);
 END IF;
 SELECT count(*),COALESCE(sum(authority_row.event_count),0),COALESCE(sum(authority_row.payload_size_bytes),0) INTO recent_batches,recent_events,recent_bytes
 FROM zasp_runtime_batch_authorities authority_row
 WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.sensor_id,authority_row.source_kind)=(organization_value,workspace_value,environment_value,sensor_value,source_kind_value)
  AND authority_row.reserved_at>=transaction_timestamp()-interval '60 seconds';
 IF recent_batches>=600 OR recent_events+event_count_value>600000 OR recent_bytes+payload_size_value>1073741824 THEN RAISE EXCEPTION USING ERRCODE='53300',MESSAGE='runtime batch rate limited';END IF;
 SELECT COALESCE(max(authority_row.batch_generation),0)+1 INTO generation_value FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.sensor_id)=(organization_value,workspace_value,environment_value,sensor_value);
 artifact_key_value:=format('runtime/v15/%s/%s/%s/%s/%s/%s.json',organization_value,workspace_value,environment_value,sensor_value,lpad(generation_value::text,20,'0'),batch_value);
 INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key)
 VALUES(organization_value,workspace_value,environment_value,batch_value,sensor_value,token_value,token_generation_value,generation_value,idempotency_value,request_digest_value,content_digest_value,source_kind_value,media_type_value,schema_version_value,payload_size_value,event_count_value,artifact_key_value);
 RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'artifact_key',artifact_key_value,'request_digest',encode(request_digest_value,'hex'),'state','uploading','replayed',false);
END $$;

CREATE FUNCTION public.zasp_runtime_commit_reserved_batch(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,request_digest_value bytea,job_value text,outbox_value text,artifact_reference_value text,artifact_key_value text,artifact_version_value text,artifact_checksum_value bytea,artifact_size_value bigint,artifact_kms_key_value text) RETURNS jsonb LANGUAGE plpgsql SET search_path TO pg_catalog, public AS $$
DECLARE batch_row zasp_runtime_batch_authorities%ROWTYPE;event_payload jsonb;result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(batch_value) OR generation_value<1 OR octet_length(request_digest_value)<>32 OR NOT zasp_valid_product_id(job_value) OR NOT zasp_valid_product_id(outbox_value) OR NOT zasp_discovery_s3_object_reference(artifact_reference_value) OR length(artifact_key_value) NOT BETWEEN 32 AND 1024 OR right(artifact_reference_value,length(artifact_key_value)+1)<>'/'||artifact_key_value OR length(artifact_version_value) NOT BETWEEN 1 AND 1024 OR artifact_version_value<>btrim(artifact_version_value) OR octet_length(artifact_checksum_value)<>32 OR artifact_size_value NOT BETWEEN 1 AND 67108864 OR artifact_kms_key_value !~ '^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]{8,128}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime batch rejected';END IF;
 SELECT * INTO batch_row FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.batch_generation,authority_row.request_digest)=(organization_value,workspace_value,environment_value,batch_value,generation_value,request_digest_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime batch rejected';END IF;
 IF batch_row.state NOT IN('uploading','unknown') THEN
  IF batch_row.state='queued' AND (batch_row.raw_artifact_reference,batch_row.raw_artifact_key,batch_row.raw_artifact_version_id,batch_row.raw_artifact_checksum,batch_row.raw_artifact_size_bytes,batch_row.raw_artifact_kms_key) IS NOT DISTINCT FROM (artifact_reference_value,artifact_key_value,artifact_version_value,artifact_checksum_value,artifact_size_value,artifact_kms_key_value)
   AND EXISTS(SELECT 1 FROM zasp_discovery_jobs job_row WHERE (job_row.organization_id,job_row.workspace_id,job_row.environment_id,job_row.id,job_row.kind,job_row.authority_id)=(organization_value,workspace_value,environment_value,job_value,'runtime',batch_value))
   AND EXISTS(SELECT 1 FROM zasp_discovery_outbox outbox_row WHERE (outbox_row.organization_id,outbox_row.workspace_id,outbox_row.environment_id,outbox_row.id,outbox_row.topic,outbox_row.deterministic_key,outbox_row.payload_version)=(organization_value,workspace_value,environment_value,outbox_value,'runtime-events','runtime:'||batch_value,15))
  THEN RETURN jsonb_build_object('batch_id',batch_row.batch_id,'generation',batch_row.batch_generation,'state',batch_row.state,'replayed',true);END IF;
  RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime batch conflict';
 END IF;
 IF (batch_row.raw_artifact_key,batch_row.content_digest,batch_row.payload_size_bytes) IS DISTINCT FROM (artifact_key_value,artifact_checksum_value,artifact_size_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime batch conflict';END IF;
 INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version)
 VALUES(batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,batch_row.batch_id,batch_row.sensor_id,batch_row.idempotency_key,batch_row.content_digest,batch_row.event_count,artifact_reference_value,batch_row.payload_size_bytes,batch_row.payload_media_type,batch_row.payload_schema_version);
 INSERT INTO zasp_discovery_jobs(organization_id,workspace_id,environment_id,id,kind,authority_id,idempotency_key,request_digest)
 VALUES(batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,job_value,'runtime',batch_row.batch_id,batch_row.idempotency_key,batch_row.request_digest);
 INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest)
 SELECT batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,batch_row.batch_id,batch_row.batch_generation,stage_value.stage,stage_value.stage_order,stage_value.version_value,CASE WHEN stage_value.stage_order=1 THEN batch_row.content_digest ELSE NULL END
 FROM (VALUES('archive',1,'runtime-archive-v1'),('index',2,'runtime-index-v1'),('correlate',3,'runtime-correlation-v1'),('project',4,'runtime-projection-v1'),('complete',5,'runtime-complete-v1')) stage_value(stage,stage_order,version_value);
 event_payload:=jsonb_build_object('batch_id',batch_row.batch_id,'job_id',job_value,'generation',batch_row.batch_generation,'pipeline_version',15,'artifact_reference',artifact_reference_value,'artifact_key',artifact_key_value,'artifact_version_id',artifact_version_value,'artifact_checksum',encode(artifact_checksum_value,'hex'),'artifact_size_bytes',artifact_size_value,'payload_media_type',batch_row.payload_media_type,'payload_schema_version',batch_row.payload_schema_version,'event_count',batch_row.event_count,'request_digest',encode(batch_row.request_digest,'hex'));
 INSERT INTO zasp_discovery_outbox(organization_id,workspace_id,environment_id,id,topic,deterministic_key,payload_version,payload,payload_digest)
 VALUES(batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,outbox_value,'runtime-events','runtime:'||batch_row.batch_id,15,event_payload,digest(convert_to(event_payload::text,'UTF8'),'sha256'));
 UPDATE zasp_runtime_batch_authorities authority_row SET raw_artifact_reference=artifact_reference_value,raw_artifact_version_id=artifact_version_value,raw_artifact_checksum=artifact_checksum_value,raw_artifact_size_bytes=artifact_size_value,raw_artifact_kms_key=artifact_kms_key_value,state='queued',finalized_at=transaction_timestamp() WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,batch_row.batch_id);
 result_value:=jsonb_build_object('batch_id',batch_row.batch_id,'generation',batch_row.batch_generation,'state','queued','replayed',false);
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_finalize_batch(locator_value bytea,secret_value bytea,audience_value text,batch_value text,job_value text,outbox_value text,artifact_reference_value text,artifact_key_value text,artifact_version_value text,artifact_checksum_value bytea,artifact_size_value bigint,artifact_kms_key_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;batch_row zasp_runtime_batch_authorities%ROWTYPE;
BEGIN
 authority_value:=zasp_runtime_authenticate_sensor(locator_value,secret_value,audience_value);
 SELECT * INTO batch_row FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(authority_value->>'organization_id',authority_value->>'workspace_id',authority_value->>'environment_id',batch_value);
 IF NOT FOUND OR (batch_row.sensor_id,batch_row.sensor_token_id,batch_row.token_generation) IS DISTINCT FROM (authority_value->>'sensor_id',authority_value->>'token_id',(authority_value->>'token_generation')::bigint) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime batch rejected';END IF;
 RETURN zasp_runtime_commit_reserved_batch(batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,batch_row.batch_id,batch_row.batch_generation,batch_row.request_digest,job_value,outbox_value,artifact_reference_value,artifact_key_value,artifact_version_value,artifact_checksum_value,artifact_size_value,artifact_kms_key_value);
END $$;

CREATE FUNCTION public.zasp_runtime_reconcile_batch(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,request_digest_value bytea,job_value text,outbox_value text,artifact_reference_value text,artifact_key_value text,artifact_version_value text,artifact_checksum_value bytea,artifact_size_value bigint,artifact_kms_key_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE batch_row zasp_runtime_batch_authorities%ROWTYPE;completion_digest_value bytea;result_value jsonb;
BEGIN
 IF NOT zasp_discovery_principal_ready('zasp_runtime_ingest') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime reconciliation rejected';END IF;
 IF NOT zasp_discovery_s3_object_reference(artifact_reference_value) OR length(artifact_key_value) NOT BETWEEN 32 AND 1024 OR right(artifact_reference_value,length(artifact_key_value)+1)<>'/'||artifact_key_value OR length(artifact_version_value) NOT BETWEEN 1 AND 1024 OR artifact_version_value<>btrim(artifact_version_value) OR octet_length(artifact_checksum_value)<>32 OR artifact_size_value NOT BETWEEN 1 AND 67108864 OR artifact_kms_key_value !~ '^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]{8,128}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime reconciliation rejected';END IF;
 SELECT * INTO batch_row FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.batch_generation,authority_row.request_digest)=(organization_value,workspace_value,environment_value,batch_value,generation_value,request_digest_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime reconciliation rejected';END IF;
 IF batch_row.state='quarantined' AND (batch_row.raw_artifact_reference,batch_row.raw_artifact_key,batch_row.raw_artifact_version_id,batch_row.raw_artifact_checksum,batch_row.raw_artifact_size_bytes,batch_row.raw_artifact_kms_key) IS NOT DISTINCT FROM (artifact_reference_value,artifact_key_value,artifact_version_value,artifact_checksum_value,artifact_size_value,artifact_kms_key_value) THEN RETURN batch_row.completion_result;END IF;
 IF batch_row.state NOT IN('uploading','unknown','queued') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime reconciliation conflict';END IF;
 IF (batch_row.raw_artifact_key,batch_row.content_digest,batch_row.payload_size_bytes) IS DISTINCT FROM (artifact_key_value,artifact_checksum_value,artifact_size_value) THEN
  completion_digest_value:=digest(convert_to(concat_ws(chr(31),organization_value,workspace_value,environment_value,batch_value,generation_value::text,encode(request_digest_value,'hex'),artifact_reference_value,artifact_key_value,artifact_version_value,encode(artifact_checksum_value,'hex'),artifact_size_value::text,artifact_kms_key_value,'reconcile-drift'),'UTF8'),'sha256');
  result_value:=jsonb_build_object('batch_id',batch_value,'generation',generation_value,'state','quarantined','error_class','malformed','replayed',false);
  UPDATE zasp_runtime_batch_authorities authority_row SET raw_artifact_reference=artifact_reference_value,raw_artifact_key=artifact_key_value,raw_artifact_version_id=artifact_version_value,raw_artifact_checksum=artifact_checksum_value,raw_artifact_size_bytes=artifact_size_value,raw_artifact_kms_key=artifact_kms_key_value,state='quarantined',finalized_at=transaction_timestamp(),completed_at=transaction_timestamp(),completion_digest=completion_digest_value,completion_result=result_value WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(organization_value,workspace_value,environment_value,batch_value);
  RETURN result_value;
 END IF;
 RETURN zasp_runtime_commit_reserved_batch(organization_value,workspace_value,environment_value,batch_value,generation_value,request_digest_value,job_value,outbox_value,artifact_reference_value,artifact_key_value,artifact_version_value,artifact_checksum_value,artifact_size_value,artifact_kms_key_value);
END $$;

CREATE FUNCTION public.zasp_runtime_claim_outbox(topic_value text,worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE response jsonb;last_organization text;claimed_last_organization text;
BEGIN
 IF topic_value<>'runtime-events' OR length(worker_value) NOT BETWEEN 1 AND 128 OR worker_value<>btrim(worker_value) OR worker_value~'[[:cntrl:]]' OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_token_value<>btrim(lease_token_value) OR lease_token_value~'[[:cntrl:]]' OR lease_seconds NOT BETWEEN 5 AND 900 OR claim_limit NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid runtime outbox claim';END IF;
 IF NOT pg_has_role(session_user,'zasp_outbox_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime outbox authority denied';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp_runtime_outbox:'||topic_value,0));
 INSERT INTO zasp_discovery_outbox_topic_fairness(topic) VALUES(topic_value) ON CONFLICT(topic) DO NOTHING;
 SELECT last_organization_id INTO last_organization FROM zasp_discovery_outbox_topic_fairness WHERE topic=topic_value FOR UPDATE;
 UPDATE zasp_discovery_outbox SET state='exhausted',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error=COALESCE(last_error,'maximum publish attempts exhausted')
 WHERE topic=topic_value AND attempt>=100 AND (state='failed' OR state='leased' AND lease_expires_at<=transaction_timestamp());
 WITH organizations AS (
  SELECT candidate.organization_id,min(candidate.available_at) due FROM zasp_discovery_outbox candidate
  WHERE candidate.topic=topic_value AND candidate.attempt<100 AND (candidate.state IN('pending','failed') OR candidate.state='leased' AND candidate.lease_expires_at<=transaction_timestamp()) AND candidate.available_at<=transaction_timestamp()
    AND NOT EXISTS(SELECT 1 FROM zasp_discovery_outbox live WHERE live.topic=topic_value AND live.organization_id=candidate.organization_id AND live.state='leased' AND live.lease_expires_at>transaction_timestamp())
  GROUP BY candidate.organization_id
 ),ordered_organizations AS (
  SELECT organization_id,due,row_number() OVER(ORDER BY CASE WHEN last_organization IS NULL OR organization_id>last_organization THEN 0 ELSE 1 END,organization_id) fair_order
  FROM organizations ORDER BY fair_order LIMIT claim_limit
 ),picked AS (
  SELECT chosen.ctid,chosen.organization_id,chosen.created_at,chosen.id,organization.fair_order FROM ordered_organizations organization
  CROSS JOIN LATERAL (
   SELECT outbox.ctid,outbox.organization_id,outbox.created_at,outbox.id FROM zasp_discovery_outbox outbox
   WHERE outbox.organization_id=organization.organization_id AND outbox.topic=topic_value AND outbox.attempt<100
     AND (outbox.state IN('pending','failed') OR outbox.state='leased' AND outbox.lease_expires_at<=transaction_timestamp()) AND outbox.available_at<=transaction_timestamp()
   ORDER BY outbox.created_at,outbox.id LIMIT 1 FOR UPDATE SKIP LOCKED
  ) chosen
 ),claimed AS (
  UPDATE zasp_discovery_outbox outbox SET state='leased',attempt=attempt+1,lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),completion_digest=NULL,completion_result=NULL
  FROM (SELECT * FROM picked ORDER BY fair_order) candidate WHERE outbox.ctid=candidate.ctid
  RETURNING outbox.organization_id,outbox.workspace_id,outbox.environment_id,outbox.id,outbox.topic,outbox.deterministic_key,outbox.payload_version,outbox.payload,encode(outbox.payload_digest,'base64') payload_digest,outbox.attempt,outbox.lease_expires_at,candidate.fair_order
 )
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(to_jsonb(claimed)-'fair_order' ORDER BY fair_order),'[]'::jsonb)),(array_agg(organization_id ORDER BY fair_order DESC))[1] INTO response,claimed_last_organization FROM claimed;
 IF claimed_last_organization IS NOT NULL THEN UPDATE zasp_discovery_outbox_topic_fairness SET last_organization_id=claimed_last_organization,updated_at=transaction_timestamp() WHERE topic=topic_value;END IF;
 RETURN response;
END $$;

CREATE FUNCTION public.zasp_runtime_heartbeat_outbox(topic_value text,worker_value text,lease_token_value text,lease_seconds integer,expected_count integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE lease_expiration timestamptz;updated_count integer;
BEGIN
 IF topic_value<>'runtime-events' OR length(worker_value) NOT BETWEEN 1 AND 128 OR worker_value<>btrim(worker_value) OR worker_value~'[[:cntrl:]]' OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_token_value<>btrim(lease_token_value) OR lease_token_value~'[[:cntrl:]]' OR lease_seconds NOT BETWEEN 5 AND 900 OR expected_count NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid runtime outbox heartbeat';END IF;
 IF NOT pg_has_role(session_user,'zasp_outbox_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime outbox authority denied';END IF;
 lease_expiration:=transaction_timestamp()+make_interval(secs=>lease_seconds);
 UPDATE zasp_discovery_outbox SET lease_expires_at=lease_expiration WHERE topic=topic_value AND state='leased' AND lease_owner=worker_value AND lease_token=lease_token_value AND lease_expires_at>transaction_timestamp();
 GET DIAGNOSTICS updated_count=ROW_COUNT;
 IF updated_count<>expected_count THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime outbox lease set conflict';END IF;
 RETURN jsonb_build_object('id',topic_value,'lease_expires_at',to_char(lease_expiration AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'remaining_count',updated_count);
END $$;

CREATE FUNCTION public.zasp_runtime_ack_outbox(topic_value text,organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,lease_token_value text,provider_ack_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE result jsonb;remaining_count integer;
BEGIN
 IF topic_value<>'runtime-events' OR provider_ack_value !~ '^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid runtime outbox acknowledgement';END IF;
 IF NOT pg_has_role(session_user,'zasp_outbox_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime outbox authority denied';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_discovery_outbox WHERE (organization_id,workspace_id,environment_id,id,topic)=(organization_value,workspace_value,environment_value,outbox_value,topic_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime outbox lease missing';END IF;
 result:=zasp_discovery_ack_outbox(organization_value,workspace_value,environment_value,outbox_value,worker_value,lease_token_value,provider_ack_value);
 SELECT count(*) INTO remaining_count FROM zasp_discovery_outbox WHERE topic=topic_value AND state='leased' AND lease_owner=worker_value AND lease_token=lease_token_value AND lease_expires_at>transaction_timestamp();
 RETURN result||jsonb_build_object('remaining_count',remaining_count);
END $$;

CREATE FUNCTION public.zasp_runtime_retry_outbox(topic_value text,organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,lease_token_value text,retry_after_seconds integer,error_code_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE result jsonb;remaining_count integer;
BEGIN
 IF topic_value<>'runtime-events' OR retry_after_seconds NOT BETWEEN 1 AND 3600 OR error_code_value<>'queue_publish_unknown' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid runtime outbox retry';END IF;
 IF NOT pg_has_role(session_user,'zasp_outbox_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime outbox authority denied';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_discovery_outbox WHERE (organization_id,workspace_id,environment_id,id,topic)=(organization_value,workspace_value,environment_value,outbox_value,topic_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime outbox lease missing';END IF;
 result:=zasp_discovery_retry_outbox(organization_value,workspace_value,environment_value,outbox_value,worker_value,lease_token_value,retry_after_seconds,error_code_value);
 SELECT count(*) INTO remaining_count FROM zasp_discovery_outbox WHERE topic=topic_value AND state='leased' AND lease_owner=worker_value AND lease_token=lease_token_value AND lease_expires_at>transaction_timestamp();
 RETURN result||jsonb_build_object('remaining_count',remaining_count);
END $$;

CREATE FUNCTION public.zasp_runtime_claim_delivery(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,message_value text,message_digest_value bytea,receive_count_value integer,worker_value text,lease_token_value text,lease_seconds integer,visibility_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE batch_row zasp_runtime_batch_authorities%ROWTYPE;delivery_row zasp_runtime_deliveries%ROWTYPE;outbox_digest bytea;disposition_value text;replayed_value boolean:=false;lease_expires_value timestamptz;visibility_deadline_value timestamptz;
BEGIN
 IF NOT zasp_runtime_principal_ready('zasp_runtime_coordinator') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(batch_value) OR generation_value<1 OR message_value !~ '^[A-Za-z0-9_-]{1,128}$' OR octet_length(message_digest_value)<>32 OR receive_count_value NOT BETWEEN 1 AND 100 OR length(worker_value) NOT BETWEEN 1 AND 128 OR worker_value<>btrim(worker_value) OR worker_value~'[[:cntrl:]]' OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_token_value<>btrim(lease_token_value) OR lease_token_value~'[[:cntrl:]]' OR lease_seconds NOT BETWEEN 5 AND 900 OR visibility_seconds<lease_seconds OR visibility_seconds>43200 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime delivery authority rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-runtime-delivery',organization_value,workspace_value,environment_value,batch_value),0));
 SELECT * INTO batch_row FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value) FOR UPDATE;
 IF NOT FOUND OR batch_row.state='uploading' THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime delivery missing';END IF;
 SELECT outbox.payload_digest INTO outbox_digest FROM zasp_discovery_outbox outbox WHERE (outbox.organization_id,outbox.workspace_id,outbox.environment_id,outbox.topic,outbox.deterministic_key,outbox.payload_version)=(organization_value,workspace_value,environment_value,'runtime-events','runtime:'||batch_value,15);
 IF NOT FOUND OR outbox_digest IS DISTINCT FROM message_digest_value THEN
  IF batch_row.state NOT IN('succeeded','failed','unknown','quarantined') THEN UPDATE zasp_runtime_batch_authorities authority_row SET state='quarantined',completed_at=transaction_timestamp(),completion_digest=digest(convert_to(concat_ws(chr(31),organization_value,workspace_value,environment_value,batch_value,generation_value::text,message_value,encode(message_digest_value,'hex'),'delivery-drift'),'UTF8'),'sha256'),completion_result=jsonb_build_object('batch_id',batch_value,'generation',generation_value,'state','quarantined','error_class','malformed') WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(organization_value,workspace_value,environment_value,batch_value);END IF;
  RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','quarantined','replayed',false);
 END IF;
 SELECT * INTO delivery_row FROM zasp_runtime_deliveries existing WHERE (existing.organization_id,existing.workspace_id,existing.environment_id,existing.batch_id)=(organization_value,workspace_value,environment_value,batch_value) FOR UPDATE;
 IF FOUND AND (delivery_row.batch_generation,delivery_row.message_id,delivery_row.message_digest) IS DISTINCT FROM (generation_value,message_value,message_digest_value) THEN
  UPDATE zasp_runtime_deliveries existing SET disposition='quarantined',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,visibility_deadline=NULL,updated_at=transaction_timestamp() WHERE (existing.organization_id,existing.workspace_id,existing.environment_id,existing.batch_id)=(organization_value,workspace_value,environment_value,batch_value);
  UPDATE zasp_runtime_batch_authorities authority_row SET state='quarantined',completed_at=transaction_timestamp(),completion_digest=digest(convert_to(concat_ws(chr(31),organization_value,workspace_value,environment_value,batch_value,generation_value::text,message_value,encode(message_digest_value,'hex'),'delivery-drift'),'UTF8'),'sha256'),completion_result=jsonb_build_object('batch_id',batch_value,'generation',generation_value,'state','quarantined','error_class','malformed') WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(organization_value,workspace_value,environment_value,batch_value) AND authority_row.state NOT IN('succeeded','failed','unknown','quarantined');
  RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','quarantined','replayed',false);
 END IF;
 IF FOUND AND receive_count_value<delivery_row.receive_count THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime delivery conflict';END IF;
 IF FOUND AND delivery_row.disposition='acked' THEN RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','ack_terminal','replayed',true);END IF;
 IF batch_row.state='unknown' OR FOUND AND delivery_row.disposition='unknown' THEN RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','unknown','replayed',FOUND);END IF;
 IF FOUND AND delivery_row.disposition IN('held','ack_pending') AND delivery_row.lease_expires_at>transaction_timestamp() AND (delivery_row.lease_owner,delivery_row.lease_token) IS DISTINCT FROM (worker_value,lease_token_value) THEN RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','busy','replayed',false,'lease_expires_at',delivery_row.lease_expires_at);END IF;
 IF EXISTS(SELECT 1 FROM zasp_runtime_deliveries other WHERE other.organization_id=organization_value AND other.batch_id<>batch_value AND other.disposition IN('held','ack_pending') AND other.lease_expires_at>transaction_timestamp()) THEN RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','busy','replayed',false);END IF;
 disposition_value:=CASE WHEN batch_row.state IN('succeeded','failed','quarantined') THEN 'ack_pending' ELSE 'held' END;
 lease_expires_value:=transaction_timestamp()+make_interval(secs=>lease_seconds);visibility_deadline_value:=transaction_timestamp()+make_interval(secs=>visibility_seconds);
 IF FOUND THEN
  replayed_value:=delivery_row.receive_count=receive_count_value AND delivery_row.disposition=disposition_value AND (delivery_row.lease_owner,delivery_row.lease_token) IS NOT DISTINCT FROM (worker_value,lease_token_value);
  UPDATE zasp_runtime_deliveries existing SET receive_count=GREATEST(existing.receive_count,receive_count_value),disposition=disposition_value,lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=lease_expires_value,visibility_deadline=visibility_deadline_value,updated_at=transaction_timestamp() WHERE (existing.organization_id,existing.workspace_id,existing.environment_id,existing.batch_id)=(organization_value,workspace_value,environment_value,batch_value);
 ELSE
  INSERT INTO zasp_runtime_deliveries(organization_id,workspace_id,environment_id,batch_id,batch_generation,message_id,message_digest,receive_count,disposition,lease_owner,lease_token,lease_expires_at,visibility_deadline) VALUES(organization_value,workspace_value,environment_value,batch_value,generation_value,message_value,message_digest_value,receive_count_value,disposition_value,worker_value,lease_token_value,lease_expires_value,visibility_deadline_value);
 END IF;
 RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition',CASE WHEN disposition_value='held' THEN 'claimed' ELSE disposition_value END,'replayed',replayed_value,'lease_expires_at',lease_expires_value,'visibility_deadline',visibility_deadline_value,'artifact_reference',batch_row.raw_artifact_reference,'artifact_key',batch_row.raw_artifact_key,'artifact_version_id',batch_row.raw_artifact_version_id,'artifact_checksum',encode(batch_row.raw_artifact_checksum,'hex'),'artifact_size_bytes',batch_row.raw_artifact_size_bytes,'artifact_kms_key',batch_row.raw_artifact_kms_key,'request_digest',encode(batch_row.request_digest,'hex'));
END $$;

CREATE FUNCTION public.zasp_runtime_heartbeat_delivery(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,message_value text,message_digest_value bytea,worker_value text,lease_token_value text,lease_seconds integer,visibility_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE lease_expires_value timestamptz;visibility_deadline_value timestamptz;
BEGIN
 IF NOT zasp_runtime_principal_ready('zasp_runtime_coordinator') OR lease_seconds NOT BETWEEN 5 AND 900 OR visibility_seconds<lease_seconds OR visibility_seconds>43200 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime delivery authority rejected';END IF;
 lease_expires_value:=transaction_timestamp()+make_interval(secs=>lease_seconds);visibility_deadline_value:=transaction_timestamp()+make_interval(secs=>visibility_seconds);
 UPDATE zasp_runtime_deliveries delivery_row SET lease_expires_at=lease_expires_value,visibility_deadline=visibility_deadline_value,updated_at=transaction_timestamp()
  WHERE (delivery_row.organization_id,delivery_row.workspace_id,delivery_row.environment_id,delivery_row.batch_id,delivery_row.batch_generation,delivery_row.message_id,delivery_row.message_digest,delivery_row.lease_owner,delivery_row.lease_token)=(organization_value,workspace_value,environment_value,batch_value,generation_value,message_value,message_digest_value,worker_value,lease_token_value) AND delivery_row.disposition IN('held','ack_pending') AND delivery_row.lease_expires_at>transaction_timestamp() AND delivery_row.visibility_deadline>transaction_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime delivery lease missing';END IF;
 RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'lease_expires_at',lease_expires_value,'visibility_deadline',visibility_deadline_value);
END $$;

CREATE FUNCTION public.zasp_runtime_release_delivery(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,message_value text,message_digest_value bytea,worker_value text,lease_token_value text,outcome_value text,error_class_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE completion_digest_value bytea;result_value jsonb;
BEGIN
 IF NOT zasp_runtime_principal_ready('zasp_runtime_coordinator') OR outcome_value NOT IN('retryable','unknown','quarantined') OR outcome_value='retryable' AND error_class_value<>'retryable' OR outcome_value='unknown' AND error_class_value<>'outcome_unknown' OR outcome_value='quarantined' AND error_class_value NOT IN('denied','malformed') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime delivery authority rejected';END IF;
 completion_digest_value:=digest(convert_to(concat_ws(chr(31),organization_value,workspace_value,environment_value,batch_value,generation_value::text,message_value,encode(message_digest_value,'hex'),worker_value,lease_token_value,outcome_value,error_class_value),'UTF8'),'sha256');
 result_value:=jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition',outcome_value,'error_class',error_class_value);
 UPDATE zasp_runtime_deliveries delivery_row SET disposition=CASE WHEN outcome_value='retryable' THEN 'held' ELSE outcome_value END,lease_expires_at=CASE WHEN outcome_value='retryable' THEN transaction_timestamp() ELSE NULL END,visibility_deadline=CASE WHEN outcome_value='retryable' THEN transaction_timestamp() ELSE NULL END,lease_owner=CASE WHEN outcome_value='retryable' THEN delivery_row.lease_owner ELSE NULL END,lease_token=CASE WHEN outcome_value='retryable' THEN delivery_row.lease_token ELSE NULL END,updated_at=transaction_timestamp()
  WHERE (delivery_row.organization_id,delivery_row.workspace_id,delivery_row.environment_id,delivery_row.batch_id,delivery_row.batch_generation,delivery_row.message_id,delivery_row.message_digest,delivery_row.disposition,delivery_row.lease_owner,delivery_row.lease_token)=(organization_value,workspace_value,environment_value,batch_value,generation_value,message_value,message_digest_value,'held',worker_value,lease_token_value) AND delivery_row.lease_expires_at>transaction_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime delivery lease missing';END IF;
 IF outcome_value IN('unknown','quarantined') THEN UPDATE zasp_runtime_batch_authorities authority_row SET state=outcome_value,completed_at=transaction_timestamp(),completion_digest=completion_digest_value,completion_result=result_value WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value);END IF;
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_ack_delivery(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,message_value text,message_digest_value bytea,worker_value text,lease_token_value text,provider_ack_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE delivery_row zasp_runtime_deliveries%ROWTYPE;result_value jsonb;
BEGIN
 IF NOT zasp_runtime_principal_ready('zasp_runtime_coordinator') OR octet_length(provider_ack_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime delivery authority rejected';END IF;
 SELECT * INTO delivery_row FROM zasp_runtime_deliveries existing WHERE (existing.organization_id,existing.workspace_id,existing.environment_id,existing.batch_id,existing.batch_generation,existing.message_id,existing.message_digest)=(organization_value,workspace_value,environment_value,batch_value,generation_value,message_value,message_digest_value) FOR UPDATE;
 IF FOUND AND delivery_row.disposition='acked' AND delivery_row.provider_ack_digest=provider_ack_digest_value THEN RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','acked','replayed',true);END IF;
 IF NOT FOUND OR delivery_row.disposition<>'ack_pending' OR delivery_row.lease_owner<>worker_value OR delivery_row.lease_token<>lease_token_value OR delivery_row.lease_expires_at<=transaction_timestamp() OR delivery_row.visibility_deadline<=transaction_timestamp() OR NOT EXISTS(SELECT 1 FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value) AND authority_row.state IN('succeeded','failed','quarantined') AND authority_row.completion_digest IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime delivery lease missing';END IF;
 UPDATE zasp_runtime_deliveries existing SET disposition='acked',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,visibility_deadline=NULL,provider_ack_digest=provider_ack_digest_value,updated_at=transaction_timestamp() WHERE (existing.organization_id,existing.workspace_id,existing.environment_id,existing.batch_id)=(organization_value,workspace_value,environment_value,batch_value);
 RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','acked','replayed',false);
END $$;

CREATE FUNCTION public.zasp_runtime_stage_for_session() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT CASE binding.authority_role::text WHEN 'zasp_runtime_archive_worker' THEN 'archive' WHEN 'zasp_runtime_index_worker' THEN 'index' WHEN 'zasp_runtime_correlation_worker' THEN 'correlate' WHEN 'zasp_runtime_projection_worker' THEN 'project' WHEN 'zasp_runtime_coordinator' THEN 'complete' END
 FROM zasp_runtime_principal_bindings binding WHERE binding.principal_name=session_user
$$;

CREATE FUNCTION public.zasp_runtime_claim_stage(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE stage_value text;authority_value text;result_value jsonb;
BEGIN
 stage_value:=zasp_runtime_stage_for_session();
 authority_value:=CASE stage_value WHEN 'archive' THEN 'zasp_runtime_archive_worker' WHEN 'index' THEN 'zasp_runtime_index_worker' WHEN 'correlate' THEN 'zasp_runtime_correlation_worker' WHEN 'project' THEN 'zasp_runtime_projection_worker' WHEN 'complete' THEN 'zasp_runtime_coordinator' END;
 IF stage_value IS NULL OR NOT zasp_runtime_principal_ready(authority_value) OR length(worker_value) NOT BETWEEN 1 AND 128 OR worker_value<>btrim(worker_value) OR worker_value~'[[:cntrl:]]' OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_token_value<>btrim(lease_token_value) OR lease_token_value~'[[:cntrl:]]' OR lease_seconds NOT BETWEEN 5 AND 900 OR claim_limit NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime stage authority rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-runtime-stage-claim:'||stage_value,0));
 WITH exhausted AS (
  UPDATE zasp_runtime_stage_work stage_row SET state='failed',last_error_class='exhausted',completed_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_heartbeat_at=NULL,
   completion_digest=digest(convert_to(concat_ws(chr(31),stage_row.organization_id,stage_row.workspace_id,stage_row.environment_id,stage_row.batch_id,stage_row.batch_generation::text,stage_row.stage,stage_row.attempt::text,'exhausted'),'UTF8'),'sha256'),
   completion_result=jsonb_build_object('batch_id',stage_row.batch_id,'generation',stage_row.batch_generation,'stage',stage_row.stage,'state','failed','attempt',stage_row.attempt,'error_class','exhausted')
  WHERE stage_row.stage=stage_value AND stage_row.attempt>=100 AND stage_row.state IN('pending','retryable','leased') AND (stage_row.state<>'leased' OR stage_row.lease_expires_at<=transaction_timestamp())
  RETURNING stage_row.organization_id,stage_row.workspace_id,stage_row.environment_id,stage_row.batch_id,stage_row.completion_digest,stage_row.completion_result
 ),failed_batches AS (
  UPDATE zasp_runtime_batch_authorities authority_row SET state='failed',completed_at=transaction_timestamp(),completion_digest=exhausted.completion_digest,completion_result=exhausted.completion_result
  FROM exhausted WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(exhausted.organization_id,exhausted.workspace_id,exhausted.environment_id,exhausted.batch_id)
  RETURNING authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.completion_digest,authority_row.completion_result
 ),failed_legacy_batches AS (
  UPDATE zasp_runtime_batches batch_row SET state='failed',completed_at=transaction_timestamp()
  FROM failed_batches WHERE (batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,batch_row.id)=(failed_batches.organization_id,failed_batches.workspace_id,failed_batches.environment_id,failed_batches.batch_id)
  RETURNING batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,batch_row.id
 ),failed_jobs AS (
  UPDATE zasp_discovery_jobs job_row SET state='failed',last_error='exhausted',completed_at=transaction_timestamp(),updated_at=transaction_timestamp(),completion_digest=failed_batches.completion_digest,completion_result=failed_batches.completion_result
  FROM failed_batches WHERE (job_row.organization_id,job_row.workspace_id,job_row.environment_id,job_row.kind,job_row.authority_id)=(failed_batches.organization_id,failed_batches.workspace_id,failed_batches.environment_id,'runtime',failed_batches.batch_id)
  RETURNING job_row.organization_id
 )
 UPDATE zasp_runtime_deliveries delivery_row SET disposition='ack_pending',updated_at=transaction_timestamp()
 FROM failed_batches WHERE (delivery_row.organization_id,delivery_row.workspace_id,delivery_row.environment_id,delivery_row.batch_id)=(failed_batches.organization_id,failed_batches.workspace_id,failed_batches.environment_id,failed_batches.batch_id) AND delivery_row.disposition='held';
 WITH eligible AS (
  SELECT stage_row.ctid row_id,stage_row.*,row_number() OVER(PARTITION BY stage_row.organization_id ORDER BY stage_row.available_at,stage_row.batch_id) organization_rank
  FROM zasp_runtime_stage_work stage_row
  WHERE stage_row.stage=stage_value AND stage_row.attempt<100 AND stage_row.available_at<=transaction_timestamp() AND (stage_row.state IN('pending','retryable') OR stage_row.state='leased' AND stage_row.lease_expires_at<=transaction_timestamp())
   AND stage_row.input_digest IS NOT NULL
   AND EXISTS(SELECT 1 FROM zasp_runtime_deliveries delivery_row WHERE (delivery_row.organization_id,delivery_row.workspace_id,delivery_row.environment_id,delivery_row.batch_id,delivery_row.batch_generation,delivery_row.disposition)=(stage_row.organization_id,stage_row.workspace_id,stage_row.environment_id,stage_row.batch_id,stage_row.batch_generation,'held') AND delivery_row.lease_expires_at>transaction_timestamp() AND delivery_row.visibility_deadline>transaction_timestamp())
   AND (stage_row.stage_order=1 OR EXISTS(SELECT 1 FROM zasp_runtime_stage_work predecessor WHERE (predecessor.organization_id,predecessor.workspace_id,predecessor.environment_id,predecessor.batch_id,predecessor.stage_order,predecessor.state,predecessor.effect_digest)=(stage_row.organization_id,stage_row.workspace_id,stage_row.environment_id,stage_row.batch_id,stage_row.stage_order-1,'succeeded',stage_row.predecessor_digest)))
   AND NOT EXISTS(SELECT 1 FROM zasp_runtime_stage_work live_row WHERE live_row.stage=stage_value AND live_row.organization_id=stage_row.organization_id AND live_row.state='leased' AND live_row.lease_expires_at>transaction_timestamp())
 ),organizations AS (
  SELECT eligible.organization_id,min(eligible.available_at) first_available,MAX(fairness.last_claimed_at) last_claimed_at
  FROM eligible LEFT JOIN zasp_runtime_stage_fairness fairness ON (fairness.stage,fairness.organization_id)=(stage_value,eligible.organization_id)
  WHERE eligible.organization_rank=1 GROUP BY eligible.organization_id
  ORDER BY MAX(fairness.last_claimed_at) NULLS FIRST,min(eligible.available_at),eligible.organization_id LIMIT claim_limit
 ),candidates AS (
  SELECT stage_row.organization_id,stage_row.workspace_id,stage_row.environment_id,stage_row.batch_id,stage_row.stage
  FROM zasp_runtime_stage_work stage_row JOIN eligible ON stage_row.ctid=eligible.row_id JOIN organizations ON organizations.organization_id=eligible.organization_id
  WHERE eligible.organization_rank=1 ORDER BY organizations.last_claimed_at NULLS FIRST,organizations.first_available,stage_row.organization_id,stage_row.batch_id FOR UPDATE OF stage_row SKIP LOCKED
 ),claimed AS (
  UPDATE zasp_runtime_stage_work stage_row SET state='leased',attempt=stage_row.attempt+1,lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),last_heartbeat_at=transaction_timestamp(),last_error_class=NULL
  FROM candidates WHERE (stage_row.organization_id,stage_row.workspace_id,stage_row.environment_id,stage_row.batch_id,stage_row.stage)=(candidates.organization_id,candidates.workspace_id,candidates.environment_id,candidates.batch_id,candidates.stage)
  RETURNING stage_row.*
 ),fairness AS (
  INSERT INTO zasp_runtime_stage_fairness(stage,organization_id,last_claimed_at) SELECT stage_value,claimed.organization_id,transaction_timestamp() FROM claimed
  ON CONFLICT(stage,organization_id) DO UPDATE SET last_claimed_at=excluded.last_claimed_at RETURNING organization_id
 )
 SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',claimed.organization_id,'workspace_id',claimed.workspace_id,'environment_id',claimed.environment_id,'batch_id',claimed.batch_id,'generation',claimed.batch_generation,'stage',claimed.stage,'attempt',claimed.attempt,'implementation_version',claimed.implementation_version,'predecessor_digest',CASE WHEN claimed.predecessor_digest IS NULL THEN NULL ELSE encode(claimed.predecessor_digest,'hex') END,'input_digest',encode(claimed.input_digest,'hex'),'input_reference',CASE WHEN claimed.stage_order=1 THEN authority_row.raw_artifact_reference ELSE predecessor.result_reference END,'input_version_id',CASE WHEN claimed.stage_order=1 THEN authority_row.raw_artifact_version_id ELSE predecessor.result_version_id END,'lease_expires_at',claimed.lease_expires_at) ORDER BY claimed.organization_id,claimed.batch_id),'[]'::jsonb) INTO result_value
 FROM claimed JOIN zasp_runtime_batch_authorities authority_row ON (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.batch_generation)=(claimed.organization_id,claimed.workspace_id,claimed.environment_id,claimed.batch_id,claimed.batch_generation)
 LEFT JOIN zasp_runtime_stage_work predecessor ON (predecessor.organization_id,predecessor.workspace_id,predecessor.environment_id,predecessor.batch_id,predecessor.stage_order)=(claimed.organization_id,claimed.workspace_id,claimed.environment_id,claimed.batch_id,claimed.stage_order-1);
 IF stage_value='archive' AND jsonb_array_length(result_value)>0 THEN UPDATE zasp_runtime_batch_authorities authority_row SET state='processing' WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(result_value) item WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(item->>'organization_id',item->>'workspace_id',item->>'environment_id',item->>'batch_id'));END IF;
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_heartbeat_stage(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,lease_token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE stage_value text;authority_value text;expires_value timestamptz;
BEGIN
 stage_value:=zasp_runtime_stage_for_session();authority_value:=CASE stage_value WHEN 'archive' THEN 'zasp_runtime_archive_worker' WHEN 'index' THEN 'zasp_runtime_index_worker' WHEN 'correlate' THEN 'zasp_runtime_correlation_worker' WHEN 'project' THEN 'zasp_runtime_projection_worker' WHEN 'complete' THEN 'zasp_runtime_coordinator' END;
 IF stage_value IS NULL OR NOT zasp_runtime_principal_ready(authority_value) OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime stage authority rejected';END IF;
 UPDATE zasp_runtime_stage_work stage_row SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),last_heartbeat_at=transaction_timestamp()
  WHERE (stage_row.organization_id,stage_row.workspace_id,stage_row.environment_id,stage_row.batch_id,stage_row.batch_generation,stage_row.stage,stage_row.state,stage_row.lease_owner,stage_row.lease_token)=(organization_value,workspace_value,environment_value,batch_value,generation_value,stage_value,'leased',worker_value,lease_token_value) AND stage_row.lease_expires_at>transaction_timestamp() RETURNING stage_row.lease_expires_at INTO expires_value;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime stage lease missing';END IF;
 RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'stage',stage_value,'lease_expires_at',expires_value);
END $$;

CREATE FUNCTION public.zasp_runtime_finish_stage(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,lease_token_value text,attempt_value integer,input_digest_value bytea,implementation_value text,outcome_value text,effect_digest_value bytea,result_reference_value text,result_version_value text,result_digest_value bytea,error_class_value text,retry_after_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE stage_value text;authority_value text;stage_row zasp_runtime_stage_work%ROWTYPE;effective_value text;completion_digest_value bytea;result_value jsonb;
BEGIN
 stage_value:=zasp_runtime_stage_for_session();authority_value:=CASE stage_value WHEN 'archive' THEN 'zasp_runtime_archive_worker' WHEN 'index' THEN 'zasp_runtime_index_worker' WHEN 'correlate' THEN 'zasp_runtime_correlation_worker' WHEN 'project' THEN 'zasp_runtime_projection_worker' WHEN 'complete' THEN 'zasp_runtime_coordinator' END;
 IF stage_value IS NULL OR NOT zasp_runtime_principal_ready(authority_value) OR length(worker_value) NOT BETWEEN 1 AND 128 OR worker_value<>btrim(worker_value) OR worker_value~'[[:cntrl:]]' OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_token_value<>btrim(lease_token_value) OR lease_token_value~'[[:cntrl:]]' OR attempt_value NOT BETWEEN 1 AND 100 OR octet_length(input_digest_value)<>32 OR length(implementation_value) NOT BETWEEN 1 AND 64 OR implementation_value<>btrim(implementation_value) OR implementation_value~'[[:cntrl:]]' OR outcome_value NOT IN('succeeded','retryable','failed','unknown','quarantined')
  OR (outcome_value='retryable') IS DISTINCT FROM (retry_after_seconds BETWEEN 1 AND 3600)
  OR outcome_value='succeeded' AND (octet_length(effect_digest_value)<>32 OR length(result_reference_value) NOT BETWEEN 1 AND 1024 OR result_reference_value<>btrim(result_reference_value) OR result_reference_value~'[[:cntrl:]]' OR length(result_version_value) NOT BETWEEN 1 AND 1024 OR result_version_value<>btrim(result_version_value) OR result_version_value~'[[:cntrl:]]' OR octet_length(result_digest_value)<>32 OR error_class_value IS NOT NULL)
  OR outcome_value='retryable' AND error_class_value<>'retryable'
  OR outcome_value='failed' AND error_class_value NOT IN('denied','malformed','exhausted')
  OR outcome_value='unknown' AND error_class_value<>'outcome_unknown'
  OR outcome_value='quarantined' AND error_class_value NOT IN('denied','malformed')
  OR outcome_value<>'succeeded' AND (effect_digest_value IS NOT NULL OR result_reference_value IS NOT NULL OR result_version_value IS NOT NULL OR result_digest_value IS NOT NULL)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime stage completion rejected';END IF;
 completion_digest_value:=digest(convert_to(concat_ws(chr(31),organization_value,workspace_value,environment_value,batch_value,generation_value::text,stage_value,worker_value,lease_token_value,attempt_value::text,encode(input_digest_value,'hex'),implementation_value,outcome_value,COALESCE(encode(effect_digest_value,'hex'),''),COALESCE(result_reference_value,''),COALESCE(result_version_value,''),COALESCE(encode(result_digest_value,'hex'),''),COALESCE(error_class_value,''),retry_after_seconds::text),'UTF8'),'sha256');
 SELECT * INTO stage_row FROM zasp_runtime_stage_work work_row WHERE (work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id,work_row.batch_generation,work_row.stage)=(organization_value,workspace_value,environment_value,batch_value,generation_value,stage_value) FOR UPDATE;
 IF FOUND AND stage_row.completion_digest=completion_digest_value THEN RETURN stage_row.completion_result;END IF;
 IF NOT FOUND OR stage_row.state<>'leased' OR stage_row.lease_owner<>worker_value OR stage_row.lease_token<>lease_token_value OR stage_row.lease_expires_at<=transaction_timestamp() OR stage_row.attempt<>attempt_value OR stage_row.input_digest<>input_digest_value OR stage_row.implementation_version<>implementation_value THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime stage lease missing';END IF;
 effective_value:=CASE WHEN outcome_value='retryable' AND stage_row.attempt>=100 THEN 'failed' ELSE outcome_value END;
 result_value:=jsonb_build_object('batch_id',batch_value,'generation',generation_value,'stage',stage_value,'state',effective_value,'attempt',stage_row.attempt,'input_digest',encode(stage_row.input_digest,'hex'),'implementation_version',stage_row.implementation_version,'effect_digest',CASE WHEN effective_value='succeeded' THEN encode(effect_digest_value,'hex') ELSE NULL END,'result_reference',CASE WHEN effective_value='succeeded' THEN result_reference_value ELSE NULL END,'result_version_id',CASE WHEN effective_value='succeeded' THEN result_version_value ELSE NULL END,'result_digest',CASE WHEN effective_value='succeeded' THEN encode(result_digest_value,'hex') ELSE NULL END,'error_class',CASE WHEN effective_value='succeeded' THEN NULL WHEN effective_value='failed' AND stage_row.attempt>=100 THEN 'exhausted' ELSE error_class_value END);
 UPDATE zasp_runtime_stage_work work_row SET state=effective_value,available_at=CASE WHEN effective_value='retryable' THEN transaction_timestamp()+make_interval(secs=>retry_after_seconds) ELSE work_row.available_at END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_heartbeat_at=NULL,effect_digest=CASE WHEN effective_value='succeeded' THEN effect_digest_value ELSE NULL END,result_reference=CASE WHEN effective_value='succeeded' THEN result_reference_value ELSE NULL END,result_version_id=CASE WHEN effective_value='succeeded' THEN result_version_value ELSE NULL END,result_digest=CASE WHEN effective_value='succeeded' THEN result_digest_value ELSE NULL END,last_error_class=CASE WHEN effective_value='failed' AND stage_row.attempt>=100 THEN 'exhausted' ELSE error_class_value END,completion_digest=completion_digest_value,completion_result=result_value,completed_at=CASE WHEN effective_value IN('succeeded','failed','unknown','quarantined') THEN transaction_timestamp() ELSE NULL END
  WHERE (work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id,work_row.stage)=(organization_value,workspace_value,environment_value,batch_value,stage_value);
 IF effective_value='succeeded' AND stage_row.stage_order<5 THEN UPDATE zasp_runtime_stage_work next_row SET predecessor_digest=effect_digest_value,input_digest=effect_digest_value WHERE (next_row.organization_id,next_row.workspace_id,next_row.environment_id,next_row.batch_id,next_row.stage_order)=(organization_value,workspace_value,environment_value,batch_value,stage_row.stage_order+1);END IF;
 IF effective_value='succeeded' AND stage_value='complete' THEN
  UPDATE zasp_runtime_batch_authorities authority_row SET state='succeeded',terminal_result_reference=result_reference_value,terminal_result_version_id=result_version_value,terminal_result_digest=result_digest_value,completion_digest=completion_digest_value,completion_result=result_value,completed_at=transaction_timestamp() WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value);
  UPDATE zasp_runtime_batches batch_row SET state='succeeded',completed_at=transaction_timestamp() WHERE (batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,batch_row.id)=(organization_value,workspace_value,environment_value,batch_value);
  UPDATE zasp_discovery_jobs job_row SET state='succeeded',result_digest=effect_digest_value,completed_at=transaction_timestamp(),updated_at=transaction_timestamp(),completion_digest=completion_digest_value,completion_result=result_value WHERE (job_row.organization_id,job_row.workspace_id,job_row.environment_id,job_row.kind,job_row.authority_id)=(organization_value,workspace_value,environment_value,'runtime',batch_value);
  UPDATE zasp_runtime_deliveries delivery_row SET disposition='ack_pending',updated_at=transaction_timestamp() WHERE (delivery_row.organization_id,delivery_row.workspace_id,delivery_row.environment_id,delivery_row.batch_id)=(organization_value,workspace_value,environment_value,batch_value) AND delivery_row.disposition='held';
 ELSIF effective_value IN('failed','unknown','quarantined') THEN
  UPDATE zasp_runtime_batch_authorities authority_row SET state=effective_value,completion_digest=completion_digest_value,completion_result=result_value,completed_at=transaction_timestamp() WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(organization_value,workspace_value,environment_value,batch_value);
	  UPDATE zasp_runtime_batches batch_row SET state='failed',completed_at=transaction_timestamp() WHERE (batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,batch_row.id)=(organization_value,workspace_value,environment_value,batch_value);
	  UPDATE zasp_discovery_jobs job_row SET state='failed',last_error=COALESCE(error_class_value,'malformed'),completed_at=transaction_timestamp(),updated_at=transaction_timestamp(),completion_digest=completion_digest_value,completion_result=result_value WHERE (job_row.organization_id,job_row.workspace_id,job_row.environment_id,job_row.kind,job_row.authority_id)=(organization_value,workspace_value,environment_value,'runtime',batch_value);
  UPDATE zasp_runtime_deliveries delivery_row SET disposition=CASE WHEN effective_value IN('failed','quarantined') THEN 'ack_pending' ELSE 'unknown' END,lease_owner=CASE WHEN effective_value IN('failed','quarantined') THEN delivery_row.lease_owner ELSE NULL END,lease_token=CASE WHEN effective_value IN('failed','quarantined') THEN delivery_row.lease_token ELSE NULL END,lease_expires_at=CASE WHEN effective_value IN('failed','quarantined') THEN delivery_row.lease_expires_at ELSE NULL END,visibility_deadline=CASE WHEN effective_value IN('failed','quarantined') THEN delivery_row.visibility_deadline ELSE NULL END,updated_at=transaction_timestamp() WHERE (delivery_row.organization_id,delivery_row.workspace_id,delivery_row.environment_id,delivery_row.batch_id)=(organization_value,workspace_value,environment_value,batch_value) AND delivery_row.disposition='held';
 END IF;
 RETURN result_value;
END $$;

ALTER TABLE public.zasp_runtime_data_plane_state OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_sensor_mutations OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_legacy_token_transitions OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_principal_bindings OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_batch_authorities OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_stage_work OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_deliveries OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_stage_fairness OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_gateway_replay_receipts OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_gateway_policy_bundles OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_gateway_events OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_data_plane_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_data_plane_state FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_sensor_mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_sensor_mutations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_legacy_token_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_legacy_token_transitions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_principal_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_principal_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_batch_authorities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_batch_authorities FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_stage_work ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_stage_work FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_deliveries FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_stage_fairness ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_stage_fairness FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_gateway_replay_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_gateway_replay_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_gateway_policy_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_gateway_policy_bundles FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_gateway_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_gateway_events FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_runtime_data_plane_state_authority ON public.zasp_runtime_data_plane_state TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_sensor_mutations_authority ON public.zasp_runtime_sensor_mutations TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_legacy_token_transitions_authority ON public.zasp_runtime_legacy_token_transitions TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_principal_bindings_authority ON public.zasp_runtime_principal_bindings TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_batch_authorities_authority ON public.zasp_runtime_batch_authorities TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_stage_work_authority ON public.zasp_runtime_stage_work TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_deliveries_authority ON public.zasp_runtime_deliveries TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_stage_fairness_authority ON public.zasp_runtime_stage_fairness TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_gateway_replay_receipts_authority ON public.zasp_runtime_gateway_replay_receipts TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_gateway_policy_bundles_authority ON public.zasp_runtime_gateway_policy_bundles TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_gateway_events_authority ON public.zasp_runtime_gateway_events TO zasp_discovery_authority USING(true) WITH CHECK(true);

ALTER FUNCTION public.zasp_runtime_sensor_secret_hash(text,text,bigint,bytea,bytea) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_enrollment_secret_hash(text,text,bigint,bytea,bytea) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_register_principals(text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_principal_ready(text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_principals_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_mark_used() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_issue_sensor_token(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_rotate_sensor_token(text,text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_revoke_sensor_token(text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_public_sensor_value(text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_public_sensor_page(text,text,text,text,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_public_sensor_detail(text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_public_sensor_coverage(text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_public_sensor_token_authority(text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_public_update_sensor(text,text,text,text,text,bigint,text,text,text,bytea) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_public_delete_sensor(text,text,text,text,text,bigint,text,bytea) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_public_rotate_sensor(text,text,text,text,text,bigint,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_issue_gateway_enrollment(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_revoke_gateway_enrollment(text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_enroll(bytea,bytea,text,text,bigint,text,text,bytea,timestamptz) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_credential_authority(text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_advance_replay(text,bigint,bigint,bytea) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_put_policy_bundle(text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_policy_bundle(text,bigint) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_authenticate_sensor(bytea,bytea,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_sensor_heartbeat(bytea,bytea,text,bigint,text,jsonb,text,boolean,bigint,bigint) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_reconcile_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_claim_outbox(text,text,text,integer,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_heartbeat_outbox(text,text,text,integer,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_ack_outbox(text,text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_retry_outbox(text,text,text,text,text,text,text,integer,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_heartbeat_delivery(text,text,text,text,bigint,text,bytea,text,text,integer,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_release_delivery(text,text,text,text,bigint,text,bytea,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_ack_delivery(text,text,text,text,bigint,text,bytea,text,text,bytea) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_stage_for_session() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_claim_stage(text,text,integer,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_heartbeat_stage(text,text,text,text,bigint,text,text,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer) OWNER TO zasp_discovery_authority;

ALTER FUNCTION public.zasp_runtime_sensor_secret_hash(text,text,bigint,bytea,bytea) SECURITY DEFINER SET search_path TO pg_catalog, public;
ALTER FUNCTION public.zasp_runtime_gateway_enrollment_secret_hash(text,text,bigint,bytea,bytea) SECURITY DEFINER SET search_path TO pg_catalog, public;
ALTER FUNCTION public.zasp_runtime_mark_used() SECURITY DEFINER SET search_path TO pg_catalog, public;

REVOKE ALL ON TABLE public.zasp_runtime_data_plane_state,public.zasp_runtime_sensor_mutations,public.zasp_runtime_legacy_token_transitions,public.zasp_runtime_principal_bindings,public.zasp_runtime_batch_authorities,public.zasp_runtime_stage_work,public.zasp_runtime_deliveries,public.zasp_runtime_stage_fairness,public.zasp_runtime_gateway_replay_receipts,public.zasp_runtime_gateway_policy_bundles,public.zasp_runtime_gateway_events FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
REVOKE ALL ON FUNCTION public.zasp_runtime_public_sensor_value(text,text,text,text),public.zasp_runtime_public_sensor_page(text,text,text,text,integer),public.zasp_runtime_public_sensor_detail(text,text,text,text),public.zasp_runtime_public_sensor_coverage(text,text,text,text),public.zasp_runtime_public_sensor_token_authority(text,text,text,text),public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz),public.zasp_runtime_public_update_sensor(text,text,text,text,text,bigint,text,text,text,bytea),public.zasp_runtime_public_delete_sensor(text,text,text,text,text,bigint,text,bytea),public.zasp_runtime_public_rotate_sensor(text,text,text,text,text,bigint,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
REVOKE ALL ON FUNCTION public.zasp_runtime_sensor_secret_hash(text,text,bigint,bytea,bytea),public.zasp_runtime_register_principals(text,text,text,text,text,text,text),public.zasp_runtime_principal_ready(text),public.zasp_runtime_principals_ready(),public.zasp_runtime_mark_used(),public.zasp_runtime_issue_sensor_token(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz),public.zasp_runtime_rotate_sensor_token(text,text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz),public.zasp_runtime_revoke_sensor_token(text,text,text,text,text),public.zasp_runtime_authenticate_sensor(bytea,bytea,text),public.zasp_runtime_sensor_heartbeat(bytea,bytea,text,bigint,text,jsonb,text,boolean,bigint,bigint),public.zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer),public.zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text),public.zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text),public.zasp_runtime_reconcile_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text),public.zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer),public.zasp_runtime_heartbeat_delivery(text,text,text,text,bigint,text,bytea,text,text,integer,integer),public.zasp_runtime_release_delivery(text,text,text,text,bigint,text,bytea,text,text,text,text),public.zasp_runtime_ack_delivery(text,text,text,text,bigint,text,bytea,text,text,bytea),public.zasp_runtime_stage_for_session(),public.zasp_runtime_claim_stage(text,text,integer,integer),public.zasp_runtime_heartbeat_stage(text,text,text,text,bigint,text,text,integer),public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
REVOKE ALL ON FUNCTION public.zasp_runtime_gateway_enrollment_secret_hash(text,text,bigint,bytea,bytea),public.zasp_runtime_issue_gateway_enrollment(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz),public.zasp_runtime_revoke_gateway_enrollment(text,text,text,text,text),public.zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text),public.zasp_runtime_gateway_enroll(bytea,bytea,text,text,bigint,text,text,bytea,timestamptz),public.zasp_runtime_gateway_credential_authority(text,text),public.zasp_runtime_gateway_advance_replay(text,bigint,bigint,bytea),public.zasp_runtime_gateway_put_policy_bundle(text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea),public.zasp_runtime_gateway_policy_bundle(text,bigint),public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
REVOKE ALL ON FUNCTION public.zasp_runtime_claim_outbox(text,text,text,integer,integer),public.zasp_runtime_heartbeat_outbox(text,text,text,integer,integer),public.zasp_runtime_ack_outbox(text,text,text,text,text,text,text,text),public.zasp_runtime_retry_outbox(text,text,text,text,text,text,text,integer,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_principal_ready(text) TO zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_claim_stage(text,text,integer,integer),public.zasp_runtime_heartbeat_stage(text,text,text,text,bigint,text,text,integer),public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer) TO zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer),public.zasp_runtime_heartbeat_delivery(text,text,text,text,bigint,text,bytea,text,text,integer,integer),public.zasp_runtime_release_delivery(text,text,text,text,bigint,text,bytea,text,text,text,text),public.zasp_runtime_ack_delivery(text,text,text,text,bigint,text,bytea,text,text,bytea) TO zasp_runtime_coordinator;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_claim_outbox(text,text,text,integer,integer),public.zasp_runtime_heartbeat_outbox(text,text,text,integer,integer),public.zasp_runtime_ack_outbox(text,text,text,text,text,text,text,text),public.zasp_runtime_retry_outbox(text,text,text,text,text,text,text,integer,text) TO zasp_outbox_worker;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_public_sensor_page(text,text,text,text,integer),public.zasp_runtime_public_sensor_detail(text,text,text,text),public.zasp_runtime_public_sensor_coverage(text,text,text,text),public.zasp_runtime_public_sensor_token_authority(text,text,text,text),public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz),public.zasp_runtime_public_update_sensor(text,text,text,text,text,bigint,text,text,text,bytea),public.zasp_runtime_public_delete_sensor(text,text,text,text,text,bigint,text,bytea),public.zasp_runtime_public_rotate_sensor(text,text,text,text,text,bigint,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_issue_gateway_enrollment(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz),public.zasp_runtime_revoke_gateway_enrollment(text,text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_authenticate_sensor(bytea,bytea,text),public.zasp_runtime_sensor_heartbeat(bytea,bytea,text,bigint,text,jsonb,text,boolean,bigint,bigint),public.zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer),public.zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text),public.zasp_runtime_reconcile_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text) TO zasp_runtime_ingest;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text),public.zasp_runtime_gateway_enroll(bytea,bytea,text,text,bigint,text,text,bytea,timestamptz),public.zasp_runtime_gateway_credential_authority(text,text),public.zasp_runtime_gateway_advance_replay(text,bigint,bigint,bytea),public.zasp_runtime_gateway_put_policy_bundle(text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea),public.zasp_runtime_gateway_policy_bundle(text,bigint),public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz) TO zasp_gateway_control;
REVOKE EXECUTE ON FUNCTION public.zasp_discovery_issue_sensor_token(text,text,text,text,text,bytea,bytea,timestamptz),public.zasp_discovery_sensor_rotate(text,text,text,text,text,text,bytea,bytea,timestamptz),public.zasp_discovery_sensor_revoke(text,text,text,text,text) FROM zasp_discovery_api;
REVOKE EXECUTE ON FUNCTION public.zasp_discovery_sensor_heartbeat(text,text,text,text,bigint,text,bigint,jsonb),public.zasp_discovery_create_runtime_batch(text,text,text,text,text,text,text,text,bytea,integer,text,bigint,text,text) FROM zasp_runtime_ingest;
REVOKE EXECUTE ON FUNCTION public.zasp_discovery_issue_gateway_enrollment(text,text,text,text,text,bytea,bytea,timestamptz),public.zasp_discovery_revoke_gateway_enrollment(text,text,text,text,text) FROM zasp_discovery_api;
REVOKE EXECUTE ON FUNCTION public.zasp_discovery_gateway_enroll(text,text,text,text,text,text,bytea,text,text,bytea,timestamptz),public.zasp_discovery_gateway_advance_replay(text,text,text,text,bigint,bigint),public.zasp_discovery_gateway_rotate(text,text,text,text,text,text,text,bytea,timestamptz),public.zasp_discovery_gateway_revoke(text,text,text,text,text),public.zasp_discovery_put_gateway_policy(text,text,text,text,text,bigint,bytea,bytea,timestamptz,timestamptz,bigint) FROM zasp_runtime_gateway;

CREATE FUNCTION public.zasp_runtime_data_plane_live_fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 WITH semantic_object(kind,identity,definition) AS (
  SELECT 'column',table_name||'.'||column_name,concat_ws('|',data_type,udt_name,is_nullable,column_default)
   FROM information_schema.columns WHERE table_schema='public' AND table_name IN('zasp_sensors','zasp_sensor_tokens','zasp_gateway_enrollment_tokens','zasp_gateway_credentials','zasp_runtime_data_plane_state','zasp_runtime_sensor_mutations','zasp_runtime_legacy_token_transitions','zasp_runtime_principal_bindings','zasp_runtime_batch_authorities','zasp_runtime_stage_work','zasp_runtime_deliveries','zasp_runtime_stage_fairness','zasp_runtime_gateway_replay_receipts','zasp_runtime_gateway_policy_bundles','zasp_runtime_gateway_events')
  UNION ALL SELECT 'constraint',constraint_value.conrelid::regclass::text||'.'||constraint_value.conname,pg_get_constraintdef(constraint_value.oid,true) FROM pg_constraint constraint_value WHERE constraint_value.conrelid IN('public.zasp_sensors'::regclass,'public.zasp_sensor_tokens'::regclass,'public.zasp_gateway_enrollment_tokens'::regclass,'public.zasp_gateway_credentials'::regclass,'public.zasp_discovery_outbox_topic_fairness'::regclass,'public.zasp_runtime_data_plane_state'::regclass,'public.zasp_runtime_sensor_mutations'::regclass,'public.zasp_runtime_legacy_token_transitions'::regclass,'public.zasp_runtime_principal_bindings'::regclass,'public.zasp_runtime_batch_authorities'::regclass,'public.zasp_runtime_stage_work'::regclass,'public.zasp_runtime_deliveries'::regclass,'public.zasp_runtime_stage_fairness'::regclass,'public.zasp_runtime_gateway_replay_receipts'::regclass,'public.zasp_runtime_gateway_policy_bundles'::regclass,'public.zasp_runtime_gateway_events'::regclass)
  UNION ALL SELECT 'index',index_value.indexrelid::regclass::text,pg_get_indexdef(index_value.indexrelid) FROM pg_index index_value WHERE index_value.indexrelid IN('public.zasp_sensor_tokens_locator_v15_idx'::regclass,'public.zasp_sensor_tokens_generation_v15_idx'::regclass,'public.zasp_sensor_tokens_live_v15_idx'::regclass,'public.zasp_gateway_enrollment_locator_v15_idx'::regclass,'public.zasp_gateway_enrollment_generation_v15_idx'::regclass,'public.zasp_gateway_enrollment_live_v15_idx'::regclass,'public.zasp_gateway_credentials_id_v15_idx'::regclass,'public.zasp_gateway_credentials_generation_v15_idx'::regclass,'public.zasp_gateway_credentials_live_v15_idx'::regclass,'public.zasp_runtime_batches_uploading_v15_idx'::regclass,'public.zasp_runtime_batches_sensor_rate_v15_idx'::regclass,'public.zasp_runtime_stages_claim_v15_idx'::regclass,'public.zasp_runtime_deliveries_claim_v15_idx'::regclass)
  UNION ALL SELECT 'function',procedure_value.oid::regprocedure::text,pg_get_functiondef(procedure_value.oid) FROM pg_proc procedure_value JOIN pg_namespace namespace_value ON namespace_value.oid=procedure_value.pronamespace WHERE namespace_value.nspname='public' AND procedure_value.proname IN('zasp_runtime_sensor_secret_hash','zasp_runtime_gateway_enrollment_secret_hash','zasp_runtime_register_principals','zasp_runtime_principal_ready','zasp_runtime_principals_ready','zasp_runtime_mark_used','zasp_runtime_issue_sensor_token','zasp_runtime_rotate_sensor_token','zasp_runtime_revoke_sensor_token','zasp_runtime_public_sensor_value','zasp_runtime_public_sensor_page','zasp_runtime_public_sensor_detail','zasp_runtime_public_sensor_coverage','zasp_runtime_public_sensor_token_authority','zasp_runtime_public_create_sensor','zasp_runtime_public_update_sensor','zasp_runtime_public_delete_sensor','zasp_runtime_public_rotate_sensor','zasp_runtime_issue_gateway_enrollment','zasp_runtime_revoke_gateway_enrollment','zasp_runtime_authenticate_gateway_enrollment','zasp_runtime_gateway_enroll','zasp_runtime_gateway_credential_authority','zasp_runtime_gateway_advance_replay','zasp_runtime_gateway_put_policy_bundle','zasp_runtime_gateway_policy_bundle','zasp_runtime_gateway_record_event','zasp_runtime_authenticate_sensor','zasp_runtime_sensor_heartbeat','zasp_runtime_reserve_batch','zasp_runtime_commit_reserved_batch','zasp_runtime_finalize_batch','zasp_runtime_reconcile_batch','zasp_runtime_claim_outbox','zasp_runtime_heartbeat_outbox','zasp_runtime_ack_outbox','zasp_runtime_retry_outbox','zasp_runtime_claim_delivery','zasp_runtime_heartbeat_delivery','zasp_runtime_release_delivery','zasp_runtime_ack_delivery','zasp_runtime_stage_for_session','zasp_runtime_claim_stage','zasp_runtime_heartbeat_stage','zasp_runtime_finish_stage','zasp_runtime_data_plane_security_ready','zasp_runtime_data_plane_readiness')
  UNION ALL SELECT 'function_acl',procedure_value.oid::regprocedure::text,COALESCE(array_to_string(procedure_value.proacl,','),'') FROM pg_proc procedure_value JOIN pg_namespace namespace_value ON namespace_value.oid=procedure_value.pronamespace WHERE namespace_value.nspname='public' AND procedure_value.proname IN('zasp_runtime_sensor_secret_hash','zasp_runtime_gateway_enrollment_secret_hash','zasp_runtime_register_principals','zasp_runtime_principal_ready','zasp_runtime_principals_ready','zasp_runtime_mark_used','zasp_runtime_issue_sensor_token','zasp_runtime_rotate_sensor_token','zasp_runtime_revoke_sensor_token','zasp_runtime_public_sensor_value','zasp_runtime_public_sensor_page','zasp_runtime_public_sensor_detail','zasp_runtime_public_sensor_coverage','zasp_runtime_public_sensor_token_authority','zasp_runtime_public_create_sensor','zasp_runtime_public_update_sensor','zasp_runtime_public_delete_sensor','zasp_runtime_public_rotate_sensor','zasp_runtime_issue_gateway_enrollment','zasp_runtime_revoke_gateway_enrollment','zasp_runtime_authenticate_gateway_enrollment','zasp_runtime_gateway_enroll','zasp_runtime_gateway_credential_authority','zasp_runtime_gateway_advance_replay','zasp_runtime_gateway_put_policy_bundle','zasp_runtime_gateway_policy_bundle','zasp_runtime_gateway_record_event','zasp_runtime_authenticate_sensor','zasp_runtime_sensor_heartbeat','zasp_runtime_reserve_batch','zasp_runtime_commit_reserved_batch','zasp_runtime_finalize_batch','zasp_runtime_reconcile_batch','zasp_runtime_claim_outbox','zasp_runtime_heartbeat_outbox','zasp_runtime_ack_outbox','zasp_runtime_retry_outbox','zasp_runtime_claim_delivery','zasp_runtime_heartbeat_delivery','zasp_runtime_release_delivery','zasp_runtime_ack_delivery','zasp_runtime_stage_for_session','zasp_runtime_claim_stage','zasp_runtime_heartbeat_stage','zasp_runtime_finish_stage','zasp_runtime_data_plane_security_ready','zasp_runtime_data_plane_readiness')
  UNION ALL SELECT 'role',role_value.rolname,concat_ws('|',role_value.rolcanlogin::text,role_value.rolinherit::text,role_value.rolsuper::text,role_value.rolcreatedb::text,role_value.rolcreaterole::text,role_value.rolreplication::text,role_value.rolbypassrls::text) FROM pg_roles role_value WHERE role_value.rolname IN('zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker','zasp_gateway_control')
 ) SELECT encode(digest(convert_to(string_agg(kind||chr(31)||identity||chr(31)||definition,chr(30) ORDER BY kind,identity,definition),'UTF8'),'sha256'),'hex') FROM semantic_object
$$;
ALTER FUNCTION public.zasp_runtime_data_plane_live_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_data_plane_live_fingerprint() FROM PUBLIC;

CREATE FUNCTION public.zasp_runtime_data_plane_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT
  NOT EXISTS(SELECT 1 FROM pg_roles role_value WHERE role_value.rolname IN('zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker','zasp_gateway_control') AND (role_value.rolcanlogin OR role_value.rolinherit OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR role_value.rolbypassrls))
  AND (SELECT count(*) FROM pg_roles role_value WHERE role_value.rolname IN('zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker','zasp_gateway_control'))=6
  AND (SELECT count(*) FROM zasp_runtime_principal_bindings) IN(0,6)
  AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member_value ON member_value.oid=membership.member WHERE granted.rolname IN('zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker','zasp_gateway_control') AND NOT (member_value.rolname='zasp_discovery_authority' AND membership.admin_option OR NOT membership.admin_option AND EXISTS(SELECT 1 FROM zasp_runtime_principal_bindings binding WHERE binding.principal_name=member_value.rolname AND binding.authority_role=granted.rolname)))
  AND NOT EXISTS(SELECT 1 FROM pg_class class_value JOIN pg_namespace namespace_value ON namespace_value.oid=class_value.relnamespace WHERE namespace_value.nspname='public' AND class_value.relname IN('zasp_runtime_data_plane_state','zasp_runtime_sensor_mutations','zasp_runtime_legacy_token_transitions','zasp_runtime_principal_bindings','zasp_runtime_batch_authorities','zasp_runtime_stage_work','zasp_runtime_deliveries','zasp_runtime_stage_fairness','zasp_runtime_gateway_replay_receipts','zasp_runtime_gateway_policy_bundles','zasp_runtime_gateway_events') AND (class_value.relowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT class_value.relrowsecurity OR NOT class_value.relforcerowsecurity OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(class_value.relacl,acldefault('r',class_value.relowner))) acl WHERE acl.grantee<>class_value.relowner)))
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value CROSS JOIN aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE procedure_value.oid='zasp_runtime_authenticate_sensor(bytea,bytea,text)'::regprocedure AND acl.grantee=0 AND acl.privilege_type='EXECUTE')
  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_authenticate_sensor(bytea,bytea,text)','EXECUTE')
  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_sensor_heartbeat(bytea,bytea,text,bigint,text,jsonb,text,boolean,bigint,bigint)','EXECUTE')
	  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer)','EXECUTE')
	  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text)','EXECUTE')
	  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_reconcile_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text)','EXECUTE')
	  AND NOT has_function_privilege('zasp_runtime_ingest','zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text)','EXECUTE')
	  AND has_function_privilege('zasp_outbox_worker','zasp_runtime_claim_outbox(text,text,text,integer,integer)','EXECUTE')
	  AND has_function_privilege('zasp_outbox_worker','zasp_runtime_heartbeat_outbox(text,text,text,integer,integer)','EXECUTE')
	  AND has_function_privilege('zasp_outbox_worker','zasp_runtime_ack_outbox(text,text,text,text,text,text,text,text)','EXECUTE')
	  AND has_function_privilege('zasp_outbox_worker','zasp_runtime_retry_outbox(text,text,text,text,text,text,text,integer,text)','EXECUTE')
	  AND NOT has_function_privilege('zasp_runtime_coordinator','zasp_runtime_claim_outbox(text,text,text,integer,integer)','EXECUTE')
	  AND has_function_privilege('zasp_runtime_coordinator','zasp_runtime_claim_stage(text,text,integer,integer)','EXECUTE')
  AND has_function_privilege('zasp_runtime_coordinator','zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer)','EXECUTE')
  AND has_function_privilege('zasp_runtime_coordinator','zasp_runtime_heartbeat_delivery(text,text,text,text,bigint,text,bytea,text,text,integer,integer)','EXECUTE')
  AND has_function_privilege('zasp_runtime_coordinator','zasp_runtime_release_delivery(text,text,text,text,bigint,text,bytea,text,text,text,text)','EXECUTE')
  AND has_function_privilege('zasp_runtime_coordinator','zasp_runtime_ack_delivery(text,text,text,text,bigint,text,bytea,text,text,bytea)','EXECUTE')
  AND NOT has_function_privilege('zasp_runtime_archive_worker','zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer)','EXECUTE')
  AND has_function_privilege('zasp_runtime_archive_worker','zasp_runtime_claim_stage(text,text,integer,integer)','EXECUTE')
  AND has_function_privilege('zasp_runtime_index_worker','zasp_runtime_claim_stage(text,text,integer,integer)','EXECUTE')
  AND has_function_privilege('zasp_runtime_correlation_worker','zasp_runtime_claim_stage(text,text,integer,integer)','EXECUTE')
  AND has_function_privilege('zasp_runtime_projection_worker','zasp_runtime_claim_stage(text,text,integer,integer)','EXECUTE')
	  AND NOT has_function_privilege('zasp_gateway_control','zasp_runtime_claim_stage(text,text,integer,integer)','EXECUTE')
	  AND has_function_privilege('zasp_gateway_control','zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text)','EXECUTE')
	  AND has_function_privilege('zasp_gateway_control','zasp_runtime_gateway_enroll(bytea,bytea,text,text,bigint,text,text,bytea,timestamptz)','EXECUTE')
	  AND has_function_privilege('zasp_gateway_control','zasp_runtime_gateway_credential_authority(text,text)','EXECUTE')
	  AND has_function_privilege('zasp_gateway_control','zasp_runtime_gateway_advance_replay(text,bigint,bigint,bytea)','EXECUTE')
	  AND has_function_privilege('zasp_gateway_control','zasp_runtime_gateway_put_policy_bundle(text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea)','EXECUTE')
	  AND has_function_privilege('zasp_gateway_control','zasp_runtime_gateway_policy_bundle(text,bigint)','EXECUTE')
	  AND has_function_privilege('zasp_gateway_control','zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz)','EXECUTE')
	  AND NOT has_function_privilege('zasp_runtime_gateway','zasp_discovery_gateway_enroll(text,text,text,text,text,text,bytea,text,text,bytea,timestamptz)','EXECUTE')
  AND NOT has_function_privilege('zasp_runtime_ingest','zasp_discovery_sensor_heartbeat(text,text,text,text,bigint,text,bigint,jsonb)','EXECUTE')
	  AND NOT has_function_privilege('zasp_discovery_api','zasp_runtime_issue_sensor_token(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz)','EXECUTE')
	  AND has_function_privilege('zasp_discovery_api','zasp_runtime_public_sensor_page(text,text,text,text,integer)','EXECUTE')
	  AND has_function_privilege('zasp_discovery_api','zasp_runtime_public_sensor_detail(text,text,text,text)','EXECUTE')
	  AND has_function_privilege('zasp_discovery_api','zasp_runtime_public_sensor_coverage(text,text,text,text)','EXECUTE')
	  AND has_function_privilege('zasp_discovery_api','zasp_runtime_public_sensor_token_authority(text,text,text,text)','EXECUTE')
	  AND has_function_privilege('zasp_discovery_api','zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz)','EXECUTE')
	  AND has_function_privilege('zasp_discovery_api','zasp_runtime_public_update_sensor(text,text,text,text,text,bigint,text,text,text,bytea)','EXECUTE')
	  AND has_function_privilege('zasp_discovery_api','zasp_runtime_public_delete_sensor(text,text,text,text,text,bigint,text,bytea)','EXECUTE')
	  AND has_function_privilege('zasp_discovery_api','zasp_runtime_public_rotate_sensor(text,text,text,text,text,bigint,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz)','EXECUTE')
	  AND has_function_privilege('zasp_discovery_api','zasp_runtime_issue_gateway_enrollment(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz)','EXECUTE')
	  AND NOT has_function_privilege('zasp_discovery_api','zasp_discovery_issue_sensor_token(text,text,text,text,text,bytea,bytea,timestamptz)','EXECUTE')
$$;
ALTER FUNCTION public.zasp_runtime_data_plane_security_ready() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_data_plane_security_ready() FROM PUBLIC;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('runtime_data_plane_fingerprint', 'b0c6f0d29a96a61a6cb9a8753fc3cdc185184ff699eaf6515f313e378d4f2b06');
DO $schema_marker$ BEGIN UPDATE zasp_schema_metadata SET value='runtime-data-plane-v1' WHERE key='production_core_schema' AND value='typed-inventory-cutover-v1';IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime data plane schema marker drift';END IF;END $schema_marker$;

CREATE FUNCTION public.zasp_runtime_data_plane_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT length(expected_checksum)=64 AND length(expected_fingerprint)=64
  AND EXISTS(SELECT 1 FROM zasp_schema_versions release WHERE (release.version,release.name,release.checksum)=(15,'runtime_data_plane',expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions later WHERE later.version>15))
	  AND EXISTS(SELECT 1 FROM zasp_schema_versions release WHERE (release.version,release.name,release.checksum)=(14,'typed_inventory_cutover','335ac384f2ad97e1845d910f86a71abab0a14bf2afb57b66962f0465180ac808'))
	  AND EXISTS(SELECT 1 FROM zasp_schema_metadata metadata WHERE (metadata.key,metadata.value)=('typed_inventory_cutover_fingerprint','f2e8b9fec3df4a18b15b2be0c1843bc294626902eab1ccbb18b7fa72f8157a27'))
	  AND zasp_inventory_live_fingerprint()='c57785cd90102977932add5a7d7251f84bff81e9837bde32750df2404197277d'
	  AND zasp_inventory_security_ready()
  AND EXISTS(SELECT 1 FROM zasp_schema_metadata metadata WHERE (metadata.key,metadata.value)=('production_core_schema','runtime-data-plane-v1'))
  AND EXISTS(SELECT 1 FROM zasp_schema_metadata metadata WHERE (metadata.key,metadata.value)=('runtime_data_plane_fingerprint',expected_fingerprint))
  AND zasp_runtime_data_plane_live_fingerprint()=expected_fingerprint AND zasp_runtime_data_plane_security_ready()
$$;
ALTER FUNCTION public.zasp_runtime_data_plane_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_data_plane_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_data_plane_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
