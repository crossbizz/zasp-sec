-- Release v10: exact-scope discovery, runtime, gateway, and outbox authority.
CREATE FUNCTION "public"."zasp_valid_product_id"(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT value ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
$$;

CREATE FUNCTION "public"."zasp_discovery_canonical_id"(
    organization_id text, workspace_id text, environment_id text, entity_kind text, source_native_id text
) RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE hex_value text;
BEGIN
    IF NOT zasp_valid_product_id(organization_id) OR NOT zasp_valid_product_id(workspace_id)
       OR NOT zasp_valid_product_id(environment_id) OR length(entity_kind) NOT BETWEEN 1 AND 64
       OR length(source_native_id) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid canonical identity input';
    END IF;
    hex_value := encode(digest(convert_to(concat_ws(chr(31),organization_id,workspace_id,environment_id,entity_kind,source_native_id),'UTF8'),'sha256'),'hex');
    RETURN 'pid_'||substr(hex_value,1,8)||'-'||substr(hex_value,9,4)||'-4'||substr(hex_value,14,3)||'-8'||substr(hex_value,18,3)||'-'||substr(hex_value,21,12);
END;
$$;

CREATE FUNCTION "public"."zasp_reference_only"(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT jsonb_typeof(value)='object'
       AND octet_length(value::text)<=16384
       AND NOT jsonb_path_exists(value, '$.**.keyvalue() ? (@.key like_regex "(?i)(secret|password|token|credential|private.?key|session)")')
$$;

CREATE TABLE "public"."zasp_integrations" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK (zasp_valid_product_id(id)), kind text NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    connector_version text NOT NULL CHECK (length(connector_version) BETWEEN 1 AND 64),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    configuration jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (zasp_reference_only(configuration)),
    credential_reference text CHECK (credential_reference IS NULL OR credential_reference ~ '^ref:[a-z0-9][a-z0-9_./:-]{7,511}$'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','authorizing','active','degraded','disabled','deleted')),
    version bigint NOT NULL DEFAULT 1 CHECK (version>0), created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(), deleted_at timestamptz,
    PRIMARY KEY (organization_id,workspace_id,environment_id,id), CHECK (updated_at>=created_at),
    CHECK ((state='deleted')=(deleted_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_integration_connections" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    integration_id text NOT NULL, id text NOT NULL CHECK (zasp_valid_product_id(id)), provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    connection_reference text NOT NULL CHECK (connection_reference ~ '^ref:[a-z0-9][a-z0-9_./:-]{7,511}$'),
    state text NOT NULL CHECK (state IN ('pending','verified','invalid','revoked')),
    verified_at timestamptz, revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id,workspace_id,environment_id,id),
    UNIQUE (organization_id,workspace_id,environment_id,integration_id,provider),
    FOREIGN KEY (organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    CHECK ((state='verified')=(verified_at IS NOT NULL AND revoked_at IS NULL) OR state<>'verified'), CHECK (state<>'revoked' OR revoked_at IS NOT NULL)
);

CREATE TABLE "public"."zasp_discovery_schedules" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK (zasp_valid_product_id(id)), integration_id text NOT NULL,
    cadence_seconds integer NOT NULL CHECK (cadence_seconds BETWEEN 300 AND 2678400), time_zone text NOT NULL DEFAULT 'UTC' CHECK (time_zone='UTC'),
    state text NOT NULL DEFAULT 'enabled' CHECK (state IN ('enabled','disabled','deleted')), next_run_at timestamptz NOT NULL,
    lease_owner text, lease_expires_at timestamptz, last_claimed_at timestamptz, version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id,workspace_id,environment_id,id), UNIQUE (organization_id,workspace_id,environment_id,integration_id),
    FOREIGN KEY (organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    CHECK ((lease_owner IS NULL)=(lease_expires_at IS NULL)), CHECK (updated_at>=created_at)
);

CREATE TABLE "public"."zasp_discovery_syncs" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK (zasp_valid_product_id(id)), integration_id text NOT NULL, idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32), trigger_kind text NOT NULL CHECK (trigger_kind IN ('manual','schedule','retry')),
    principal_id text NOT NULL CHECK (zasp_valid_product_id(principal_id)), state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','succeeded','failed','cancelled')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 100), parser_version text NOT NULL, tool_version text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT transaction_timestamp(), started_at timestamptz, completed_at timestamptz,
    last_error text CHECK (last_error IS NULL OR length(last_error) BETWEEN 1 AND 1024), discovered_count integer NOT NULL DEFAULT 0 CHECK(discovered_count>=0),
    changed_count integer NOT NULL DEFAULT 0 CHECK(changed_count>=0), removed_count integer NOT NULL DEFAULT 0 CHECK(removed_count>=0), snapshot_id text,
    PRIMARY KEY (organization_id,workspace_id,environment_id,id), UNIQUE (organization_id,workspace_id,environment_id,integration_id,idempotency_key),
    FOREIGN KEY (organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
    CHECK (completed_at IS NULL OR completed_at>=requested_at), CHECK (started_at IS NULL OR started_at>=requested_at),
    CHECK ((state IN ('succeeded','failed','cancelled'))=(completed_at IS NOT NULL)), CHECK (state<>'succeeded' OR (snapshot_id IS NOT NULL AND last_error IS NULL)),
    CHECK (state<>'failed' OR last_error IS NOT NULL)
);

CREATE TABLE "public"."zasp_discovery_jobs" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK (zasp_valid_product_id(id)), kind text NOT NULL CHECK(kind IN ('discovery','runtime','projection')),
    authority_id text NOT NULL CHECK (zasp_valid_product_id(authority_id)), idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32), state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','leased','retryable','succeeded','failed','cancelled')),
    attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100), available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    lease_owner text, lease_token text, lease_expires_at timestamptz, result_digest bytea CHECK(result_digest IS NULL OR octet_length(result_digest)=32),
    last_error text CHECK(last_error IS NULL OR length(last_error) BETWEEN 1 AND 1024), completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id,workspace_id,environment_id,id), UNIQUE (organization_id,workspace_id,environment_id,kind,idempotency_key),
    CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (state='leased' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at>updated_at)),
    CHECK ((state IN ('succeeded','failed','cancelled'))=(completed_at IS NOT NULL)), CHECK(updated_at>=created_at)
);

CREATE TABLE "public"."zasp_discovery_snapshots" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL, sync_id text NOT NULL, generation bigint NOT NULL CHECK(generation>0),
    source text NOT NULL CHECK(length(source) BETWEEN 1 AND 64), manifest_reference text NOT NULL CHECK(manifest_reference ~ '^s3://[a-z0-9.-]+/.{1,900}$'),
    manifest_checksum bytea NOT NULL CHECK(octet_length(manifest_checksum)=32), state text NOT NULL CHECK(state IN ('candidate','complete','failed')),
    complete boolean NOT NULL, is_last_good boolean NOT NULL DEFAULT false, collected_at timestamptz NOT NULL, committed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,integration_id,generation),
    FOREIGN KEY (organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY (organization_id,workspace_id,environment_id,sync_id) REFERENCES zasp_discovery_syncs(organization_id,workspace_id,environment_id,id),
    CHECK ((state='complete')=(complete AND committed_at IS NOT NULL)), CHECK (NOT is_last_good OR state='complete')
);
CREATE UNIQUE INDEX zasp_discovery_snapshots_last_good_idx ON zasp_discovery_snapshots(organization_id,workspace_id,environment_id,integration_id) WHERE is_last_good;

ALTER TABLE zasp_discovery_syncs ADD CONSTRAINT zasp_discovery_syncs_snapshot_fk
FOREIGN KEY (organization_id,workspace_id,environment_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE "public"."zasp_discovery_cursors" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    integration_id text NOT NULL, provider text NOT NULL CHECK(length(provider) BETWEEN 1 AND 64), cursor_value text NOT NULL CHECK(length(cursor_value) BETWEEN 1 AND 4096),
    snapshot_id text NOT NULL, committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(organization_id,workspace_id,environment_id,integration_id,provider),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,workspace_id,environment_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id)
);

CREATE TABLE "public"."zasp_inventory_entities" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), kind text NOT NULL CHECK(length(kind) BETWEEN 1 AND 64),
    display_name text NOT NULL CHECK(length(display_name) BETWEEN 1 AND 256), stable_fields jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(stable_fields)='object' AND octet_length(stable_fields::text)<=65536),
    state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','tombstoned')), first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL,
    tombstoned_at timestamptz, version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), CHECK(last_seen_at>=first_seen_at), CHECK((state='tombstoned')=(tombstoned_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_inventory_source_observations" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    integration_id text NOT NULL, entity_id text NOT NULL, source_native_id text NOT NULL CHECK(length(source_native_id) BETWEEN 1 AND 1024),
    snapshot_id text NOT NULL, source_state text NOT NULL CHECK(source_state IN ('present','removed')), attributes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(attributes)='object' AND octet_length(attributes::text)<=262144),
    first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL, removed_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,integration_id,entity_id),
    UNIQUE(organization_id,workspace_id,environment_id,integration_id,source_native_id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,entity_id) REFERENCES zasp_inventory_entities(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id),
    CHECK(last_seen_at>=first_seen_at), CHECK((source_state='removed')=(removed_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_inventory_relationships" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL, snapshot_id text NOT NULL,
    from_entity_id text NOT NULL, to_entity_id text NOT NULL, kind text NOT NULL CHECK(length(kind) BETWEEN 1 AND 64),
    source_native_id text NOT NULL CHECK(length(source_native_id) BETWEEN 1 AND 1024), state text NOT NULL DEFAULT 'present' CHECK(state IN ('present','removed')),
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(attributes)='object' AND octet_length(attributes::text)<=65536),
    first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL, removed_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,integration_id,source_native_id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,from_entity_id) REFERENCES zasp_inventory_entities(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,to_entity_id) REFERENCES zasp_inventory_entities(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id),
    CHECK(from_entity_id<>to_entity_id), CHECK(last_seen_at>=first_seen_at), CHECK((state='removed')=(removed_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_inventory_evidence" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL, snapshot_id text NOT NULL, entity_id text,
    finding_id text, object_reference text NOT NULL CHECK(object_reference ~ '^s3://[a-z0-9.-]+/.{1,900}$'), checksum bytea NOT NULL CHECK(octet_length(checksum)=32),
    media_type text NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128), schema_version text NOT NULL CHECK(length(schema_version) BETWEEN 1 AND 64),
    parser_version text NOT NULL CHECK(length(parser_version) BETWEEN 1 AND 64), collected_at timestamptz NOT NULL,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,object_reference),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,entity_id) REFERENCES zasp_inventory_entities(organization_id,workspace_id,environment_id,id),
    CHECK((entity_id IS NOT NULL)::int+(finding_id IS NOT NULL)::int=1), CHECK(finding_id IS NULL OR zasp_valid_product_id(finding_id))
);

CREATE TABLE "public"."zasp_sensors" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128), kind text NOT NULL CHECK(kind IN ('tetragon','otlp')),
    state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','active','degraded','revoked','deleted')), version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(), revoked_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), CHECK(state<>'revoked' OR revoked_at IS NOT NULL), CHECK(updated_at>=created_at)
);

CREATE TABLE "public"."zasp_sensor_tokens" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), sensor_id text NOT NULL, audience text NOT NULL DEFAULT 'event-ingest' CHECK(audience='event-ingest'),
    salt bytea NOT NULL CHECK(octet_length(salt) BETWEEN 16 AND 64), token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
    issued_at timestamptz NOT NULL DEFAULT transaction_timestamp(), expires_at timestamptz NOT NULL, rotated_from_id text, revoked_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(token_hash),
    FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id) REFERENCES zasp_sensors(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,workspace_id,environment_id,rotated_from_id) REFERENCES zasp_sensor_tokens(organization_id,workspace_id,environment_id,id),
    CHECK(expires_at>issued_at)
);

CREATE TABLE "public"."zasp_sensor_heartbeats" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, sensor_id text NOT NULL,
    sequence bigint NOT NULL CHECK(sequence>=0), observed_at timestamptz NOT NULL DEFAULT transaction_timestamp(), status text NOT NULL CHECK(status IN ('healthy','degraded')),
    dropped_events bigint NOT NULL DEFAULT 0 CHECK(dropped_events>=0), metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(metadata)='object' AND octet_length(metadata::text)<=16384),
    PRIMARY KEY(organization_id,workspace_id,environment_id,sensor_id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id) REFERENCES zasp_sensors(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE
);

CREATE TABLE "public"."zasp_runtime_batches" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), sensor_id text NOT NULL, idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
    payload_digest bytea NOT NULL CHECK(octet_length(payload_digest)=32), event_count integer NOT NULL CHECK(event_count BETWEEN 1 AND 1000),
    state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','processing','succeeded','failed')), archive_reference text,
    requested_at timestamptz NOT NULL DEFAULT transaction_timestamp(), completed_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,sensor_id,idempotency_key),
    FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id) REFERENCES zasp_sensors(organization_id,workspace_id,environment_id,id),
    CHECK(archive_reference IS NULL OR archive_reference ~ '^s3://[a-z0-9.-]+/.{1,900}$'), CHECK((state IN ('succeeded','failed'))=(completed_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_runtime_stages" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, batch_id text NOT NULL,
    stage text NOT NULL CHECK(stage IN ('archive','index','correlate','risk','graph','complete')), input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
    state text NOT NULL CHECK(state IN ('pending','running','succeeded','failed')), attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),
    result_reference text, completed_at timestamptz, PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id,stage),
    FOREIGN KEY(organization_id,workspace_id,environment_id,batch_id) REFERENCES zasp_runtime_batches(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    CHECK((state='succeeded')=(completed_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_discovery_outbox" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), topic text NOT NULL CHECK(topic IN ('discovery-jobs','runtime-events','projection-work')),
    deterministic_key text NOT NULL CHECK(length(deterministic_key) BETWEEN 16 AND 256), payload_version integer NOT NULL CHECK(payload_version BETWEEN 1 AND 32),
    payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=65536), payload_digest bytea NOT NULL CHECK(octet_length(payload_digest)=32),
    state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','published','failed')), attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),
    available_at timestamptz NOT NULL DEFAULT transaction_timestamp(), lease_owner text, lease_token text, lease_expires_at timestamptz,
    provider_ack text, published_at timestamptz, last_error text CHECK(last_error IS NULL OR length(last_error) BETWEEN 1 AND 1024),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,topic,deterministic_key),
    CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (state='leased' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL)),
    CHECK((state='published')=(published_at IS NOT NULL AND provider_ack IS NOT NULL))
);

CREATE TABLE "public"."zasp_projection_work" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    snapshot_id text NOT NULL, kind text NOT NULL CHECK(kind IN ('risk','graph','search')), version text NOT NULL CHECK(length(version) BETWEEN 1 AND 64),
    input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32), state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','succeeded','failed')),
    attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100), lease_owner text, lease_expires_at timestamptz, completed_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,snapshot_id,kind,version),
    FOREIGN KEY(organization_id,workspace_id,environment_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE
);

CREATE TABLE "public"."zasp_gateway_devices" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128), state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','active','revoked','deleted')),
    replay_floor bigint NOT NULL DEFAULT 0 CHECK(replay_floor>=0), version bigint NOT NULL DEFAULT 1 CHECK(version>0), created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), revoked_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), CHECK(state<>'revoked' OR revoked_at IS NOT NULL)
);

CREATE TABLE "public"."zasp_gateway_enrollment_tokens" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), device_id text NOT NULL, audience text NOT NULL CHECK(audience='runtime-gateway-enroll'),
    salt bytea NOT NULL CHECK(octet_length(salt) BETWEEN 16 AND 64), token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
    issued_at timestamptz NOT NULL DEFAULT transaction_timestamp(), expires_at timestamptz NOT NULL, consumed_at timestamptz, revoked_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(token_hash),
    FOREIGN KEY(organization_id,workspace_id,environment_id,device_id) REFERENCES zasp_gateway_devices(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    CHECK(expires_at>issued_at), CHECK(consumed_at IS NULL OR consumed_at>=issued_at)
);

CREATE TABLE "public"."zasp_gateway_credentials" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), device_id text NOT NULL, audience text NOT NULL CHECK(audience='runtime-gateway'),
    key_reference text NOT NULL CHECK(key_reference ~ '^ref:[a-z0-9][a-z0-9_./:-]{7,511}$'), public_key bytea NOT NULL CHECK(octet_length(public_key) BETWEEN 32 AND 4096),
    issued_at timestamptz NOT NULL DEFAULT transaction_timestamp(), expires_at timestamptz NOT NULL, rotated_from_id text, revoked_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,device_id) REFERENCES zasp_gateway_devices(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,workspace_id,environment_id,rotated_from_id) REFERENCES zasp_gateway_credentials(organization_id,workspace_id,environment_id,id),
    CHECK(expires_at>issued_at)
);

CREATE TABLE "public"."zasp_gateway_policy_subscriptions" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, device_id text NOT NULL,
    policy_id text NOT NULL CHECK(zasp_valid_product_id(policy_id)), policy_version bigint NOT NULL CHECK(policy_version>0),
    policy_digest bytea NOT NULL CHECK(octet_length(policy_digest)=32), signature bytea NOT NULL CHECK(octet_length(signature) BETWEEN 32 AND 8192),
    issued_at timestamptz NOT NULL DEFAULT transaction_timestamp(), expires_at timestamptz NOT NULL, last_sequence bigint NOT NULL DEFAULT 0 CHECK(last_sequence>=0), revoked_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,device_id,policy_id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,device_id) REFERENCES zasp_gateway_devices(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    CHECK(expires_at>issued_at)
);

CREATE INDEX zasp_discovery_schedules_claim_idx ON zasp_discovery_schedules(next_run_at,organization_id,id) WHERE state='enabled' AND lease_owner IS NULL;
CREATE INDEX zasp_discovery_jobs_claim_idx ON zasp_discovery_jobs(available_at,organization_id,created_at,id) WHERE state IN ('queued','retryable');
CREATE INDEX zasp_discovery_outbox_claim_idx ON zasp_discovery_outbox(available_at,organization_id,created_at,id) WHERE state IN ('pending','failed');
CREATE INDEX zasp_inventory_entities_page_idx ON zasp_inventory_entities(organization_id,workspace_id,environment_id,id) WHERE state='active';
CREATE INDEX zasp_inventory_observations_source_idx ON zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source_state,entity_id);

CREATE FUNCTION "public"."zasp_discovery_entity_page"(organization_id text, workspace_id text, environment_id text, after_id text DEFAULT NULL, page_limit integer DEFAULT 50)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE response jsonb;
BEGIN
    IF page_limit NOT BETWEEN 1 AND 100 OR after_id IS NOT NULL AND NOT zasp_valid_product_id(after_id) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid inventory page'; END IF;
    WITH candidates AS (
        SELECT * FROM zasp_inventory_entities e WHERE e.organization_id=$1 AND e.workspace_id=$2 AND e.environment_id=$3 AND e.state='active' AND ($4 IS NULL OR e.id>$4) ORDER BY e.id LIMIT page_limit+1
    ), visible AS (SELECT * FROM candidates ORDER BY id LIMIT page_limit)
    SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('id',id,'kind',kind,'display_name',display_name,'stable_fields',stable_fields,'state',state,'first_seen_at',first_seen_at,'last_seen_at',last_seen_at,'version',version) ORDER BY id),'[]'::jsonb),
      'next_id',CASE WHEN (SELECT count(*) FROM candidates)>page_limit THEN (SELECT id FROM visible ORDER BY id DESC LIMIT 1) ELSE NULL END) INTO response FROM visible;
    RETURN response;
END; $$;

CREATE FUNCTION "public"."zasp_discovery_claim_outbox"(worker text, lease_token text, lease_seconds integer, claim_limit integer)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE response jsonb;
BEGIN
    IF length(worker) NOT BETWEEN 1 AND 128 OR length(lease_token) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 OR claim_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid outbox claim'; END IF;
    WITH organizations AS (
      SELECT organization_id,min(available_at) due FROM zasp_discovery_outbox WHERE state IN ('pending','failed') AND available_at<=transaction_timestamp() GROUP BY organization_id ORDER BY due,organization_id LIMIT claim_limit
    ), picked AS (
      SELECT DISTINCT ON (o.organization_id) o.ctid,o.organization_id,o.created_at,o.id FROM zasp_discovery_outbox o JOIN organizations g USING(organization_id)
       WHERE o.state IN ('pending','failed') AND o.available_at<=transaction_timestamp() ORDER BY o.organization_id,o.created_at,o.id FOR UPDATE OF o SKIP LOCKED
    ), claimed AS (
      UPDATE zasp_discovery_outbox o SET state='leased',attempt=attempt+1,lease_owner=worker,lease_token=$2,lease_expires_at=transaction_timestamp()+make_interval(secs=>$3)
      FROM (SELECT * FROM picked ORDER BY created_at,organization_id,id LIMIT claim_limit) p WHERE o.ctid=p.ctid
      RETURNING o.organization_id,o.workspace_id,o.environment_id,o.id,o.topic,o.deterministic_key,o.payload_version,o.payload,o.payload_digest,o.attempt,o.lease_expires_at
    ) SELECT jsonb_build_object('items',COALESCE(jsonb_agg(to_jsonb(claimed) ORDER BY organization_id,id),'[]'::jsonb)) INTO response FROM claimed;
    RETURN response;
END; $$;

CREATE FUNCTION "public"."zasp_discovery_ack_outbox"(organization_id text, workspace_id text, environment_id text, outbox_id text, worker text, lease_token text, provider_ack text)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE response jsonb;
BEGIN
    UPDATE zasp_discovery_outbox SET state='published',provider_ack=$7,published_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL
     WHERE zasp_discovery_outbox.organization_id=$1 AND zasp_discovery_outbox.workspace_id=$2 AND zasp_discovery_outbox.environment_id=$3 AND id=$4
       AND state='leased' AND lease_owner=$5 AND zasp_discovery_outbox.lease_token=$6 AND lease_expires_at>transaction_timestamp() AND length($7) BETWEEN 1 AND 512
     RETURNING jsonb_build_object('id',id,'published_at',published_at,'provider_ack',zasp_discovery_outbox.provider_ack) INTO response;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='outbox lease missing'; END IF; RETURN response;
END; $$;

CREATE FUNCTION "public"."zasp_discovery_readiness"() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM zasp_schema_versions v JOIN zasp_schema_metadata m ON m.key='production_core_schema' AND m.value='production-discovery-v1' WHERE v.version=10 AND v.name='production_discovery' AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions newer WHERE newer.version>10))
$$;

DO $rls$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['zasp_integrations','zasp_integration_connections','zasp_discovery_schedules','zasp_discovery_syncs','zasp_discovery_jobs','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_evidence','zasp_sensors','zasp_sensor_tokens','zasp_sensor_heartbeats','zasp_runtime_batches','zasp_runtime_stages','zasp_discovery_outbox','zasp_projection_work','zasp_gateway_devices','zasp_gateway_enrollment_tokens','zasp_gateway_credentials','zasp_gateway_policy_subscriptions'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('CREATE POLICY %I ON public.%I USING (organization_id=current_setting(''zasp.organization_id'',true) AND workspace_id=current_setting(''zasp.workspace_id'',true) AND environment_id=current_setting(''zasp.environment_id'',true)) WITH CHECK (organization_id=current_setting(''zasp.organization_id'',true) AND workspace_id=current_setting(''zasp.workspace_id'',true) AND environment_id=current_setting(''zasp.environment_id'',true))',table_name||'_scope',table_name);
  END LOOP;
END $rls$;

DO $migration$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'production-risk-projection-v1','production-discovery-v1'); definition:=replace(definition,'release."version" = 9','release."version" = 10');
 definition:=replace(definition,'release."name" = ''production_risk_projection''','release."name" = ''production_discovery'''); definition:=replace(definition,'later_release."version" > 9','later_release."version" > 10'); EXECUTE definition;
END $migration$;

INSERT INTO zasp_schema_metadata(key,value) VALUES ('production_discovery_fingerprint', 'b23a94a7a0bd8dcac9af0b2440f807900ddd39670ac527dda45b9d511c4fa33b');
UPDATE zasp_schema_metadata SET value='production-discovery-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='production-risk-projection-v1';
