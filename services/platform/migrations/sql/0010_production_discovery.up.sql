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

CREATE FUNCTION "public"."zasp_discovery_relationship_id"(
    organization_id text, workspace_id text, environment_id text, integration_id text, source text, relationship_kind text, source_native_id text
) RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE hex_value text;
BEGIN
    IF NOT zasp_valid_product_id(organization_id) OR NOT zasp_valid_product_id(workspace_id)
       OR NOT zasp_valid_product_id(environment_id) OR NOT zasp_valid_product_id(integration_id)
       OR length(source) NOT BETWEEN 1 AND 64 OR length(relationship_kind) NOT BETWEEN 1 AND 64
       OR length(source_native_id) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid relationship identity input';
    END IF;
    hex_value := encode(digest(convert_to(concat_ws(chr(31),organization_id,workspace_id,environment_id,integration_id,source,source_native_id),'UTF8'),'sha256'),'hex');
    RETURN 'pid_'||substr(hex_value,1,8)||'-'||substr(hex_value,9,4)||'-4'||substr(hex_value,14,3)||'-8'||substr(hex_value,18,3)||'-'||substr(hex_value,21,12);
END;
$$;

CREATE FUNCTION "public"."zasp_reference_only"(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT jsonb_typeof(value)='object'
       AND octet_length(value::text)<=16384
       AND value::text !~* '"[^"]*(secret|password|token|credential|private.?key|session)[^"]*"[[:space:]]*:'
$$;

CREATE TABLE "public"."zasp_integrations" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK (zasp_valid_product_id(id)), kind text NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    connector_version text NOT NULL CHECK (length(connector_version) BETWEEN 1 AND 64),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    configuration jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (zasp_reference_only(configuration)),
    credential_reference text CHECK (credential_reference IS NULL OR length(credential_reference) BETWEEN 12 AND 512 AND credential_reference ~ '^ref:[a-z0-9][a-z0-9_./:-]+$'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','authorizing','active','degraded','disabled','deleted')),
    version bigint NOT NULL DEFAULT 1 CHECK (version>0), created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(), deleted_at timestamptz,
    PRIMARY KEY (organization_id,workspace_id,environment_id,id), CHECK (updated_at>=created_at),
    CHECK ((state='deleted')=(deleted_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_integration_connections" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    integration_id text NOT NULL, id text NOT NULL CHECK (zasp_valid_product_id(id)), provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    connection_reference text NOT NULL CHECK (length(connection_reference) BETWEEN 12 AND 512 AND connection_reference ~ '^ref:[a-z0-9][a-z0-9_./:-]+$'),
    state text NOT NULL CHECK (state IN ('pending','verified','invalid','revoked')),
    verified_at timestamptz, revoked_at timestamptz, version bigint NOT NULL DEFAULT 1 CHECK(version>0), created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
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
    lease_owner text, lease_token text, lease_expires_at timestamptz, last_claimed_at timestamptz, completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32), completion_result jsonb, version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id,workspace_id,environment_id,id), UNIQUE (organization_id,workspace_id,environment_id,integration_id),
    FOREIGN KEY (organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)), CHECK (updated_at>=created_at)
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
    UNIQUE (organization_id,workspace_id,environment_id,integration_id,id),
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
    lease_owner text, lease_token text, lease_expires_at timestamptz, result_digest bytea CHECK(result_digest IS NULL OR octet_length(result_digest)=32), completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32), completion_result jsonb,
    last_error text CHECK(last_error IS NULL OR length(last_error) BETWEEN 1 AND 1024), completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id,workspace_id,environment_id,id), UNIQUE (organization_id,workspace_id,environment_id,kind,idempotency_key),
    UNIQUE (organization_id,workspace_id,environment_id,kind,authority_id),
    CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (state='leased' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at>updated_at)),
    CHECK ((state IN ('succeeded','failed','cancelled'))=(completed_at IS NOT NULL)), CHECK(updated_at>=created_at)
);

CREATE TABLE "public"."zasp_discovery_snapshots" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL, sync_id text NOT NULL, generation bigint NOT NULL CHECK(generation>0),
    source text NOT NULL CHECK(length(source) BETWEEN 1 AND 64), manifest_reference text NOT NULL CHECK(length(manifest_reference) BETWEEN 8 AND 1024 AND manifest_reference ~ '^s3://[a-z0-9.-]+/.+$'),
    manifest_checksum bytea NOT NULL CHECK(octet_length(manifest_checksum)=32), state text NOT NULL CHECK(state IN ('candidate','complete','failed')),
    candidate_digest bytea NOT NULL CHECK(octet_length(candidate_digest)=32), apply_result jsonb,
    complete boolean NOT NULL, is_last_good boolean NOT NULL DEFAULT false, collected_at timestamptz NOT NULL, committed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,integration_id,source,generation),
    UNIQUE(organization_id,workspace_id,environment_id,integration_id,id),
    UNIQUE(organization_id,workspace_id,environment_id,integration_id,source,id),
    FOREIGN KEY (organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY (organization_id,workspace_id,environment_id,integration_id,sync_id) REFERENCES zasp_discovery_syncs(organization_id,workspace_id,environment_id,integration_id,id),
    CHECK ((state='complete')=(complete AND committed_at IS NOT NULL)), CHECK (NOT is_last_good OR state='complete')
);
CREATE UNIQUE INDEX zasp_discovery_snapshots_last_good_idx ON zasp_discovery_snapshots(organization_id,workspace_id,environment_id,integration_id,source) WHERE is_last_good;

ALTER TABLE zasp_discovery_syncs ADD CONSTRAINT zasp_discovery_syncs_snapshot_fk
FOREIGN KEY (organization_id,workspace_id,environment_id,integration_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,integration_id,id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE "public"."zasp_discovery_cursors" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    integration_id text NOT NULL, provider text NOT NULL CHECK(length(provider) BETWEEN 1 AND 64), cursor_value text NOT NULL CHECK(length(cursor_value) BETWEEN 1 AND 4096),
    snapshot_id text NOT NULL, committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(organization_id,workspace_id,environment_id,integration_id,provider),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,integration_id,id)
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
    integration_id text NOT NULL, source text NOT NULL CHECK(length(source) BETWEEN 1 AND 64), entity_id text NOT NULL, source_native_id text NOT NULL CHECK(length(source_native_id) BETWEEN 1 AND 1024),
    snapshot_id text NOT NULL, source_state text NOT NULL CHECK(source_state IN ('present','removed')), attributes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(attributes)='object' AND octet_length(attributes::text)<=262144),
    first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL, removed_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,integration_id,source,entity_id),
    UNIQUE(organization_id,workspace_id,environment_id,integration_id,source,source_native_id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,entity_id) REFERENCES zasp_inventory_entities(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,integration_id,source,id),
    CHECK(last_seen_at>=first_seen_at), CHECK((source_state='removed')=(removed_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_inventory_relationships" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL, source text NOT NULL CHECK(length(source) BETWEEN 1 AND 64), snapshot_id text NOT NULL,
    from_entity_id text NOT NULL, to_entity_id text NOT NULL, kind text NOT NULL CHECK(length(kind) BETWEEN 1 AND 64),
    source_native_id text NOT NULL CHECK(length(source_native_id) BETWEEN 1 AND 1024), state text NOT NULL DEFAULT 'present' CHECK(state IN ('present','removed')),
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(attributes)='object' AND octet_length(attributes::text)<=65536),
    first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL, removed_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,integration_id,source,source_native_id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,from_entity_id) REFERENCES zasp_inventory_entities(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,to_entity_id) REFERENCES zasp_inventory_entities(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,integration_id,source,id),
    CHECK(from_entity_id<>to_entity_id), CHECK(last_seen_at>=first_seen_at), CHECK((state='removed')=(removed_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_inventory_evidence" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL, snapshot_id text NOT NULL, entity_id text,
    finding_id text, object_reference text NOT NULL CHECK(length(object_reference) BETWEEN 8 AND 1024 AND object_reference ~ '^s3://[a-z0-9.-]+/.+$'), checksum bytea NOT NULL CHECK(octet_length(checksum)=32),
    media_type text NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128), schema_version text NOT NULL CHECK(length(schema_version) BETWEEN 1 AND 64),
    parser_version text NOT NULL CHECK(length(parser_version) BETWEEN 1 AND 64), collected_at timestamptz NOT NULL,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,object_reference),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,integration_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,entity_id) REFERENCES zasp_inventory_entities(organization_id,workspace_id,environment_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,finding_id) REFERENCES zasp_risk_findings(organization_id,workspace_id,environment_id,id),
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
    issued_at timestamptz NOT NULL DEFAULT transaction_timestamp(), expires_at timestamptz NOT NULL, rotated_from_id text, rotation_digest bytea CHECK(rotation_digest IS NULL OR octet_length(rotation_digest)=32), revoked_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(token_hash),
    UNIQUE(organization_id,workspace_id,environment_id,sensor_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id) REFERENCES zasp_sensors(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id,rotated_from_id) REFERENCES zasp_sensor_tokens(organization_id,workspace_id,environment_id,sensor_id,id),
    CHECK(expires_at>issued_at)
);

CREATE TABLE "public"."zasp_sensor_heartbeats" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, sensor_id text NOT NULL,
    sequence bigint NOT NULL CHECK(sequence>=0), request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32), observed_at timestamptz NOT NULL DEFAULT transaction_timestamp(), status text NOT NULL CHECK(status IN ('healthy','degraded')),
    dropped_events bigint NOT NULL DEFAULT 0 CHECK(dropped_events>=0), metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(metadata)='object' AND octet_length(metadata::text)<=16384),
    PRIMARY KEY(organization_id,workspace_id,environment_id,sensor_id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id) REFERENCES zasp_sensors(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE
);

CREATE TABLE "public"."zasp_runtime_batches" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), sensor_id text NOT NULL, idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
    payload_digest bytea NOT NULL CHECK(octet_length(payload_digest)=32), event_count integer NOT NULL CHECK(event_count BETWEEN 1 AND 1000),
    payload_reference text NOT NULL CHECK(length(payload_reference) BETWEEN 8 AND 1024 AND payload_reference ~ '^s3://[a-z0-9.-]+/.+$'),
    payload_size_bytes bigint NOT NULL CHECK(payload_size_bytes BETWEEN 1 AND 67108864),
    payload_media_type text NOT NULL CHECK(length(payload_media_type) BETWEEN 1 AND 128),
    payload_schema_version text NOT NULL CHECK(length(payload_schema_version) BETWEEN 1 AND 64),
    state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','processing','succeeded','failed')), archive_reference text,
    requested_at timestamptz NOT NULL DEFAULT transaction_timestamp(), completed_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,sensor_id,idempotency_key),
    FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id) REFERENCES zasp_sensors(organization_id,workspace_id,environment_id,id),
    CHECK(archive_reference IS NULL OR length(archive_reference) BETWEEN 8 AND 1024 AND archive_reference ~ '^s3://[a-z0-9.-]+/.+$'), CHECK((state IN ('succeeded','failed'))=(completed_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_runtime_stages" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, batch_id text NOT NULL,
    stage text NOT NULL CHECK(stage IN ('archive','index','correlate','risk','graph','complete')), input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
    state text NOT NULL CHECK(state IN ('pending','running','succeeded','failed')), attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),
    result_reference text, completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32), completion_result jsonb, completed_at timestamptz, PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id,stage),
    FOREIGN KEY(organization_id,workspace_id,environment_id,batch_id) REFERENCES zasp_runtime_batches(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    CHECK((state='succeeded')=(completed_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_discovery_outbox" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), topic text NOT NULL CHECK(topic IN ('discovery-jobs','runtime-events','projection-work')),
    deterministic_key text NOT NULL CHECK(length(deterministic_key) BETWEEN 16 AND 256), payload_version integer NOT NULL CHECK(payload_version BETWEEN 1 AND 32),
    payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=65536), payload_digest bytea NOT NULL CHECK(octet_length(payload_digest)=32),
    state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','published','failed','exhausted')), attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),
    available_at timestamptz NOT NULL DEFAULT transaction_timestamp(), lease_owner text, lease_token text, lease_expires_at timestamptz,
    provider_ack text, published_at timestamptz, last_error text CHECK(last_error IS NULL OR length(last_error) BETWEEN 1 AND 1024),
    completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32), completion_result jsonb,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,topic,deterministic_key),
    UNIQUE(organization_id,workspace_id,environment_id,deterministic_key),
    CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (state='leased' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL)),
    CHECK((state='published')=(published_at IS NOT NULL AND provider_ack IS NOT NULL))
);

CREATE TABLE "public"."zasp_projection_work" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    snapshot_id text NOT NULL, kind text NOT NULL CHECK(kind IN ('risk','graph','search')), version text NOT NULL CHECK(length(version) BETWEEN 1 AND 64),
    input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32), state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','retryable','succeeded','failed','cancelled')),
    attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100), available_at timestamptz NOT NULL DEFAULT transaction_timestamp(), lease_owner text, lease_token text, lease_expires_at timestamptz, last_error text CHECK(last_error IS NULL OR length(last_error) BETWEEN 1 AND 1024), completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32), completion_result jsonb, completed_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,snapshot_id,kind,version),
    FOREIGN KEY(organization_id,workspace_id,environment_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    CHECK((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (state='leased' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL))
);

CREATE TABLE "public"."zasp_gateway_devices" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128), state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','active','revoked','deleted')),
    replay_floor bigint NOT NULL DEFAULT 0 CHECK(replay_floor>=0), version bigint NOT NULL DEFAULT 1 CHECK(version>0), created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(), revoked_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), CHECK(state<>'revoked' OR revoked_at IS NOT NULL)
);

CREATE TABLE "public"."zasp_gateway_enrollment_tokens" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), device_id text NOT NULL, audience text NOT NULL CHECK(audience='runtime-gateway-enroll'),
    salt bytea NOT NULL CHECK(octet_length(salt) BETWEEN 16 AND 64), token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
    issued_at timestamptz NOT NULL DEFAULT transaction_timestamp(), expires_at timestamptz NOT NULL, consumed_at timestamptz, revoked_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(token_hash),
    UNIQUE(organization_id,workspace_id,environment_id,device_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,device_id) REFERENCES zasp_gateway_devices(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    CHECK(expires_at>issued_at), CHECK(consumed_at IS NULL OR consumed_at>=issued_at)
);

CREATE TABLE "public"."zasp_gateway_credentials" (
    organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
    id text NOT NULL CHECK(zasp_valid_product_id(id)), device_id text NOT NULL, enrollment_token_id text, enrollment_digest bytea NOT NULL CHECK(octet_length(enrollment_digest)=32), audience text NOT NULL CHECK(audience='runtime-gateway'),
    key_reference text NOT NULL CHECK(length(key_reference) BETWEEN 12 AND 512 AND key_reference ~ '^ref:[a-z0-9][a-z0-9_./:-]+$'), public_key bytea NOT NULL CHECK(octet_length(public_key) BETWEEN 32 AND 4096),
    issued_at timestamptz NOT NULL DEFAULT transaction_timestamp(), expires_at timestamptz NOT NULL, rotated_from_id text, revoked_at timestamptz,
    PRIMARY KEY(organization_id,workspace_id,environment_id,id),
    UNIQUE(organization_id,workspace_id,environment_id,device_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,device_id) REFERENCES zasp_gateway_devices(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,workspace_id,environment_id,device_id,enrollment_token_id) REFERENCES zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,device_id,id),
    FOREIGN KEY(organization_id,workspace_id,environment_id,device_id,rotated_from_id) REFERENCES zasp_gateway_credentials(organization_id,workspace_id,environment_id,device_id,id),
    CHECK(expires_at>issued_at), CHECK((rotated_from_id IS NULL)=(enrollment_token_id IS NOT NULL))
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

CREATE INDEX zasp_discovery_schedules_claim_idx ON zasp_discovery_schedules(next_run_at,organization_id,id) WHERE state='enabled';
CREATE INDEX zasp_discovery_jobs_claim_idx ON zasp_discovery_jobs(available_at,organization_id,created_at,id) WHERE state IN ('queued','retryable','leased');
CREATE INDEX zasp_discovery_outbox_claim_idx ON zasp_discovery_outbox(available_at,organization_id,created_at,id) WHERE state IN ('pending','failed','leased');
CREATE INDEX zasp_projection_work_claim_idx ON zasp_projection_work(available_at,organization_id,snapshot_id,kind) WHERE state IN ('pending','retryable','leased');
CREATE INDEX zasp_inventory_entities_page_idx ON zasp_inventory_entities(organization_id,workspace_id,environment_id,id) WHERE state='active';
CREATE INDEX zasp_inventory_observations_source_idx ON zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,source_state,entity_id);

CREATE FUNCTION "public"."zasp_discovery_create_integration"(organization_id text,workspace_id text,environment_id text,integration_id text,integration_kind text,connector_version text,display_name text,configuration jsonb,credential_reference text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb; BEGIN
  IF NOT zasp_valid_product_id(integration_id) OR NOT zasp_reference_only(configuration) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid integration'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4),0));
  SELECT jsonb_build_object('id',i.id,'kind',i.kind,'connector_version',i.connector_version,'display_name',i.display_name,'state',i.state,'version',i.version,'created_at',i.created_at,'updated_at',i.updated_at) INTO result FROM zasp_integrations i WHERE i.organization_id=$1 AND i.workspace_id=$2 AND i.environment_id=$3 AND i.id=$4 AND i.kind=$5 AND i.connector_version=$6 AND i.display_name=$7 AND i.configuration=$8 AND i.credential_reference IS NOT DISTINCT FROM $9;
  IF FOUND THEN RETURN result;ELSIF EXISTS(SELECT 1 FROM zasp_integrations i WHERE i.organization_id=$1 AND i.workspace_id=$2 AND i.environment_id=$3 AND i.id=$4) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='integration conflict';END IF;
  INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,credential_reference)
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
  RETURNING jsonb_build_object('id',id,'kind',kind,'connector_version',zasp_integrations.connector_version,'display_name',zasp_integrations.display_name,'state',state,'version',version,'created_at',created_at,'updated_at',updated_at) INTO result;
  RETURN result;
END $$;

CREATE FUNCTION "public"."zasp_discovery_transition_integration"(p_organization_id text,p_workspace_id text,p_environment_id text,p_integration_id text,p_expected_version bigint,p_next_state text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb;BEGIN
 UPDATE zasp_integrations SET state=$6,version=version+1,updated_at=transaction_timestamp(),deleted_at=CASE WHEN $6='deleted' THEN transaction_timestamp() ELSE NULL END WHERE zasp_integrations.organization_id=$1 AND zasp_integrations.workspace_id=$2 AND zasp_integrations.environment_id=$3 AND id=$4 AND version=$5 AND (($6='authorizing' AND state='pending') OR ($6='active' AND state IN('pending','authorizing','degraded','disabled')) OR ($6='degraded' AND state IN('authorizing','active')) OR ($6='disabled' AND state IN('active','degraded')) OR ($6='deleted' AND state IN('active','degraded','disabled'))) RETURNING jsonb_build_object('id',id,'state',state,'version',version,'updated_at',updated_at) INTO result;
 IF NOT FOUND THEN SELECT jsonb_build_object('id',id,'state',state,'version',version,'updated_at',updated_at) INTO result FROM zasp_integrations WHERE zasp_integrations.organization_id=$1 AND zasp_integrations.workspace_id=$2 AND zasp_integrations.environment_id=$3 AND id=$4 AND version=$5+1 AND state=$6;END IF;IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration transition conflict';END IF;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_put_connection"(p_organization_id text,p_workspace_id text,p_environment_id text,p_connection_id text,p_integration_id text,p_provider text,p_connection_reference text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb;prior zasp_integration_connections%ROWTYPE;BEGIN PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$5,$6),0));SELECT * INTO prior FROM zasp_integration_connections c WHERE c.organization_id=$1 AND c.workspace_id=$2 AND c.environment_id=$3 AND c.integration_id=$5 AND c.provider=$6;IF FOUND THEN IF prior.id<>$4 OR prior.connection_reference<>$7 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connection conflict';END IF;RETURN jsonb_build_object('id',prior.id,'integration_id',prior.integration_id,'provider',prior.provider,'state',prior.state,'created_at',prior.created_at);END IF;INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,id,integration_id,provider,connection_reference,state) VALUES($1,$2,$3,$4,$5,$6,$7,'pending') RETURNING jsonb_build_object('id',id,'integration_id',zasp_integration_connections.integration_id,'provider',zasp_integration_connections.provider,'state',state,'created_at',created_at) INTO result;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_transition_connection"(p_organization_id text,p_workspace_id text,p_environment_id text,p_connection_id text,p_integration_id text,p_expected_version bigint,p_next_state text)
RETURNS jsonb LANGUAGE plpgsql AS $$
#variable_conflict use_column
DECLARE result jsonb;
BEGIN
 UPDATE zasp_integration_connections SET state=$7,version=version+1,updated_at=transaction_timestamp(),
 verified_at=CASE WHEN $7='verified' THEN transaction_timestamp() WHEN $7='pending' THEN NULL ELSE verified_at END,
 revoked_at=CASE WHEN $7='revoked' THEN transaction_timestamp() WHEN $7='pending' THEN NULL ELSE revoked_at END
 WHERE zasp_integration_connections.organization_id=$1 AND zasp_integration_connections.workspace_id=$2 AND zasp_integration_connections.environment_id=$3 AND id=$4 AND integration_id=$5 AND version=$6
 AND (($7='verified' AND state='pending') OR ($7='invalid' AND state IN('pending','verified')) OR ($7='revoked' AND state IN('pending','verified','invalid')) OR ($7='pending' AND state IN('invalid','revoked')))
 RETURNING jsonb_build_object('id',id,'state',state,'version',version,'updated_at',updated_at) INTO result;
 IF NOT FOUND THEN SELECT jsonb_build_object('id',id,'state',state,'version',version,'updated_at',updated_at) INTO result FROM zasp_integration_connections WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND integration_id=$5 AND version=$6+1 AND state=$7;END IF;
 IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connection transition conflict';END IF;
 RETURN result;
END $$;

CREATE FUNCTION "public"."zasp_discovery_put_schedule"(p_organization_id text,p_workspace_id text,p_environment_id text,p_schedule_id text,p_integration_id text,p_cadence_seconds integer,p_next_run_at timestamptz,expected_version bigint)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb;BEGIN PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$5),0));IF expected_version=0 THEN SELECT jsonb_build_object('id',id,'integration_id',zasp_discovery_schedules.integration_id,'state',state,'cadence_seconds',zasp_discovery_schedules.cadence_seconds,'next_run_at',zasp_discovery_schedules.next_run_at,'version',version) INTO result FROM zasp_discovery_schedules WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$5 AND id=$4 AND cadence_seconds=$6 AND next_run_at=$7;IF FOUND THEN RETURN result;ELSIF EXISTS(SELECT 1 FROM zasp_discovery_schedules WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$5) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='schedule conflict';END IF;INSERT INTO zasp_discovery_schedules(organization_id,workspace_id,environment_id,id,integration_id,cadence_seconds,next_run_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING jsonb_build_object('id',id,'integration_id',zasp_discovery_schedules.integration_id,'state',state,'cadence_seconds',zasp_discovery_schedules.cadence_seconds,'next_run_at',zasp_discovery_schedules.next_run_at,'version',version) INTO result;ELSE UPDATE zasp_discovery_schedules SET cadence_seconds=$6,next_run_at=$7,version=version+1,updated_at=transaction_timestamp() WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND integration_id=$5 AND version=$8 AND state<>'deleted' AND lease_owner IS NULL RETURNING jsonb_build_object('id',id,'integration_id',zasp_discovery_schedules.integration_id,'state',state,'cadence_seconds',zasp_discovery_schedules.cadence_seconds,'next_run_at',zasp_discovery_schedules.next_run_at,'version',version) INTO result;IF result IS NULL THEN SELECT jsonb_build_object('id',id,'integration_id',zasp_discovery_schedules.integration_id,'state',state,'cadence_seconds',zasp_discovery_schedules.cadence_seconds,'next_run_at',zasp_discovery_schedules.next_run_at,'version',version) INTO result FROM zasp_discovery_schedules WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND integration_id=$5 AND version=$8+1 AND cadence_seconds=$6 AND next_run_at=$7;END IF;END IF;IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='schedule put conflict';END IF;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_transition_schedule"(p_organization_id text,p_workspace_id text,p_environment_id text,p_schedule_id text,p_expected_version bigint,p_next_state text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb;BEGIN UPDATE zasp_discovery_schedules SET state=$6,version=version+1,updated_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND version=$5 AND (($6='enabled' AND state='disabled') OR ($6='disabled' AND state='enabled') OR ($6='deleted' AND state IN('enabled','disabled'))) RETURNING jsonb_build_object('id',id,'state',state,'version',version,'updated_at',updated_at) INTO result;IF NOT FOUND THEN SELECT jsonb_build_object('id',id,'state',state,'version',version,'updated_at',updated_at) INTO result FROM zasp_discovery_schedules WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND version=$5+1 AND state=$6;END IF;IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='schedule transition conflict';END IF;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_create_sensor"(p_organization_id text,p_workspace_id text,p_environment_id text,p_sensor_id text,p_sensor_name text,p_sensor_kind text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb;BEGIN PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4),0));SELECT jsonb_build_object('id',id,'name',name,'kind',kind,'state',state,'version',version,'created_at',created_at) INTO result FROM zasp_sensors WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND name=$5 AND kind=$6;IF FOUND THEN RETURN result;ELSIF EXISTS(SELECT 1 FROM zasp_sensors WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor conflict';END IF;INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind) VALUES($1,$2,$3,$4,$5,$6) RETURNING jsonb_build_object('id',id,'name',name,'kind',kind,'state',state,'version',version,'created_at',created_at) INTO result;RETURN result;END $$;
CREATE FUNCTION "public"."zasp_discovery_transition_sensor"(p_organization_id text,p_workspace_id text,p_environment_id text,p_sensor_id text,p_expected_version bigint,p_next_state text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb;BEGIN UPDATE zasp_sensors SET state=$6,version=version+1,updated_at=transaction_timestamp(),revoked_at=CASE WHEN $6='revoked' THEN transaction_timestamp() ELSE revoked_at END WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND version=$5 AND (($6='active' AND state IN('pending','degraded')) OR ($6='degraded' AND state='active') OR ($6='revoked' AND state IN('pending','active','degraded')) OR ($6='deleted' AND state IN('pending','revoked'))) RETURNING jsonb_build_object('id',id,'state',state,'version',version,'updated_at',updated_at) INTO result;IF NOT FOUND THEN SELECT jsonb_build_object('id',id,'state',state,'version',version,'updated_at',updated_at) INTO result FROM zasp_sensors WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND version=$5+1 AND state=$6;END IF;IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='sensor transition conflict';END IF;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_create_gateway_device"(p_organization_id text,p_workspace_id text,p_environment_id text,p_device_id text,p_device_name text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb;BEGIN PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4),0));SELECT jsonb_build_object('id',id,'name',name,'state',state,'version',version,'replay_floor',replay_floor,'created_at',created_at) INTO result FROM zasp_gateway_devices WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND name=$5;IF FOUND THEN RETURN result;ELSIF EXISTS(SELECT 1 FROM zasp_gateway_devices WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='gateway device conflict';END IF;INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name) VALUES($1,$2,$3,$4,$5) RETURNING jsonb_build_object('id',id,'name',name,'state',state,'version',version,'replay_floor',replay_floor,'created_at',created_at) INTO result;RETURN result;END $$;
CREATE FUNCTION "public"."zasp_discovery_transition_gateway_device"(p_organization_id text,p_workspace_id text,p_environment_id text,p_device_id text,p_expected_version bigint,p_next_state text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb;BEGIN UPDATE zasp_gateway_devices SET state=$6,version=version+1,updated_at=transaction_timestamp(),revoked_at=CASE WHEN $6='revoked' THEN transaction_timestamp() ELSE revoked_at END WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND version=$5 AND (($6='active' AND state='pending') OR ($6='revoked' AND state IN('pending','active')) OR ($6='deleted' AND state='revoked')) RETURNING jsonb_build_object('id',id,'state',state,'version',version,'updated_at',updated_at) INTO result;IF NOT FOUND THEN SELECT jsonb_build_object('id',id,'state',state,'version',version,'updated_at',updated_at) INTO result FROM zasp_gateway_devices WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND version=$5+1 AND state=$6;END IF;IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway device transition conflict';END IF;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_issue_gateway_enrollment"(p_organization_id text,p_workspace_id text,p_environment_id text,p_enrollment_id text,p_device_id text,p_salt bytea,p_token_hash bytea,p_expires_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb;BEGIN IF $8<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid enrollment expiry';END IF;IF NOT EXISTS(SELECT 1 FROM zasp_gateway_devices d WHERE d.organization_id=$1 AND d.workspace_id=$2 AND d.environment_id=$3 AND d.id=$5 AND d.state IN('pending','active')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway device missing';END IF;PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4),0));SELECT jsonb_build_object('id',id,'device_id',zasp_gateway_enrollment_tokens.device_id,'audience',audience,'issued_at',issued_at,'expires_at',zasp_gateway_enrollment_tokens.expires_at) INTO result FROM zasp_gateway_enrollment_tokens WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND device_id=$5 AND salt=$6 AND token_hash=$7 AND expires_at=$8;IF FOUND THEN RETURN result;ELSIF EXISTS(SELECT 1 FROM zasp_gateway_enrollment_tokens WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='enrollment token conflict';END IF;INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,'runtime-gateway-enroll',$6,$7,$8) RETURNING jsonb_build_object('id',id,'device_id',zasp_gateway_enrollment_tokens.device_id,'audience',audience,'issued_at',issued_at,'expires_at',zasp_gateway_enrollment_tokens.expires_at) INTO result;RETURN result;END $$;
CREATE FUNCTION "public"."zasp_discovery_revoke_gateway_enrollment"(p_organization_id text,p_workspace_id text,p_environment_id text,p_enrollment_id text,p_device_id text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE revoked timestamptz;BEGIN UPDATE zasp_gateway_enrollment_tokens SET revoked_at=COALESCE(revoked_at,transaction_timestamp()) WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND device_id=$5 RETURNING revoked_at INTO revoked;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='enrollment token missing';END IF;RETURN jsonb_build_object('id',$4,'revoked_at',revoked);END $$;

CREATE FUNCTION "public"."zasp_discovery_request_sync"(organization_id text,workspace_id text,environment_id text,principal_id text,integration_id text,sync_id text,job_id text,outbox_id text,idempotency_key text,request_digest bytea,trigger_kind text,parser_version text,tool_version text)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE prior_digest bytea; prior_sync text; prior_job text; prior_outbox text; event_payload jsonb;
BEGIN
  IF octet_length(request_digest)<>32 OR length(idempotency_key) NOT BETWEEN 16 AND 128 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid sync request'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$5,$9),0));
  SELECT s.request_digest,s.id,j.id,o.id INTO prior_digest,prior_sync,prior_job,prior_outbox FROM zasp_discovery_syncs s
    JOIN zasp_discovery_jobs j ON j.organization_id=s.organization_id AND j.workspace_id=s.workspace_id AND j.environment_id=s.environment_id AND j.authority_id=s.id AND j.kind='discovery'
    JOIN zasp_discovery_outbox o ON o.organization_id=s.organization_id AND o.workspace_id=s.workspace_id AND o.environment_id=s.environment_id AND o.deterministic_key='sync:'||s.id
   WHERE s.organization_id=$1 AND s.workspace_id=$2 AND s.environment_id=$3 AND s.integration_id=$5 AND s.idempotency_key=$9;
  IF FOUND THEN IF prior_digest<>$10 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='idempotency conflict'; END IF;
    RETURN jsonb_build_object('sync_id',prior_sync,'job_id',prior_job,'outbox_id',prior_outbox,'state','queued','replayed',true); END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_integrations i WHERE i.organization_id=$1 AND i.workspace_id=$2 AND i.environment_id=$3 AND i.id=$5 AND i.state IN ('active','degraded')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration missing'; END IF;
  INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$6,$5,$9,$10,$11,$4,$12,$13);
  INSERT INTO zasp_discovery_jobs(organization_id,workspace_id,environment_id,id,kind,authority_id,idempotency_key,request_digest) VALUES($1,$2,$3,$7,'discovery',$6,$9,$10);
  event_payload:=jsonb_build_object('organization_id',$1,'workspace_id',$2,'environment_id',$3,'job_id',$7,'sync_id',$6,'integration_id',$5,'request_digest',encode($10,'hex'));
  INSERT INTO zasp_discovery_outbox(organization_id,workspace_id,environment_id,id,topic,deterministic_key,payload_version,payload,payload_digest) VALUES($1,$2,$3,$8,'discovery-jobs','sync:'||$6,1,event_payload,digest(convert_to(event_payload::text,'UTF8'),'sha256'));
  RETURN jsonb_build_object('sync_id',$6,'job_id',$7,'outbox_id',$8,'state','queued','replayed',false);
END $$;

CREATE FUNCTION "public"."zasp_discovery_apply_snapshot"(organization_id text,workspace_id text,environment_id text,integration_id text,sync_id text,snapshot_id text,generation bigint,source text,manifest_reference text,manifest_checksum bytea,collected_at timestamptz,cursor_provider text,cursor_value text,entities jsonb,relationships jsonb,evidence jsonb)
RETURNS jsonb LANGUAGE plpgsql AS $$
#variable_conflict use_column
DECLARE applied_discovered_count integer; applied_changed_count integer; applied_removed_count integer; committed timestamptz:=transaction_timestamp(); requested_digest bytea; prior_digest bytea; prior_result jsonb;
BEGIN
  IF source<>cursor_provider OR jsonb_typeof(entities)<>'array' OR jsonb_typeof(relationships)<>'array' OR jsonb_typeof(evidence)<>'array' OR jsonb_array_length(entities)>10000 OR jsonb_array_length(relationships)>20000 OR jsonb_array_length(evidence)>20000 OR octet_length(manifest_checksum)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid complete snapshot'; END IF;
  requested_digest:=digest(convert_to(jsonb_build_object('integration_id',$4,'sync_id',$5,'snapshot_id',$6,'generation',$7,'source',$8,'manifest_reference',$9,'manifest_checksum',encode($10,'hex'),'collected_at_epoch_us',floor(extract(epoch FROM $11)*1000000)::bigint,'cursor_provider',$12,'cursor_value',$13,'entities',$14,'relationships',$15,'evidence',$16)::text,'UTF8'),'sha256');
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4,$8),0));
  SELECT candidate_digest,apply_result INTO prior_digest,prior_result FROM zasp_discovery_snapshots s WHERE s.organization_id=$1 AND s.workspace_id=$2 AND s.environment_id=$3 AND s.integration_id=$4 AND s.id=$6;
  IF FOUND THEN IF prior_digest<>requested_digest OR prior_result IS NULL THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='snapshot replay conflict'; END IF; RETURN prior_result; END IF;
  IF EXISTS(SELECT 1 FROM zasp_discovery_snapshots s WHERE s.organization_id=$1 AND s.workspace_id=$2 AND s.environment_id=$3 AND s.integration_id=$4 AND s.source=$8 AND s.is_last_good AND s.generation >= $7) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale snapshot generation'; END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_discovery_syncs s WHERE s.organization_id=$1 AND s.workspace_id=$2 AND s.environment_id=$3 AND s.integration_id=$4 AND s.id=$5 AND s.state IN ('queued','running')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sync missing'; END IF;
  IF EXISTS(SELECT 1 FROM jsonb_to_recordset(entities) e(id text,kind text,source_native_id text,display_name text,stable_fields jsonb,attributes jsonb) WHERE e.id<>zasp_discovery_canonical_id($1,$2,$3,e.kind,e.source_native_id) OR jsonb_typeof(e.stable_fields)<>'object' OR jsonb_typeof(e.attributes)<>'object') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='noncanonical entity'; END IF;
  IF EXISTS(SELECT source_native_id FROM jsonb_to_recordset(entities) e(id text,kind text,source_native_id text,display_name text,stable_fields jsonb,attributes jsonb) GROUP BY source_native_id HAVING count(*)>1) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='duplicate source identity'; END IF;
  WITH candidate AS (SELECT * FROM jsonb_to_recordset(entities) e(id text,kind text,source_native_id text,display_name text,stable_fields jsonb,attributes jsonb))
  SELECT count(*) FILTER (WHERE observation.entity_id IS NULL),
         count(*) FILTER (WHERE observation.entity_id IS NOT NULL AND (entity.kind IS DISTINCT FROM candidate.kind OR entity.display_name IS DISTINCT FROM candidate.display_name OR entity.stable_fields IS DISTINCT FROM candidate.stable_fields OR entity.state<>'active' OR observation.source_state<>'present' OR observation.attributes IS DISTINCT FROM candidate.attributes))
    INTO applied_discovered_count,applied_changed_count
    FROM candidate
    LEFT JOIN zasp_inventory_source_observations observation ON observation.organization_id=$1 AND observation.workspace_id=$2 AND observation.environment_id=$3 AND observation.integration_id=$4 AND observation.source=$8 AND observation.source_native_id=candidate.source_native_id
    LEFT JOIN zasp_inventory_entities entity ON entity.organization_id=$1 AND entity.workspace_id=$2 AND entity.environment_id=$3 AND entity.id=candidate.id;
  INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,candidate_digest,state,complete,is_last_good,collected_at)
  VALUES($1,$2,$3,$6,$4,$5,$7,$8,$9,$10,requested_digest,'candidate',false,false,$11);
  WITH candidate AS (SELECT * FROM jsonb_to_recordset(entities) e(id text,kind text,source_native_id text,display_name text,stable_fields jsonb,attributes jsonb))
  INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at)
  SELECT $1,$2,$3,id,kind,display_name,stable_fields,'active',committed,committed FROM candidate
  ON CONFLICT(organization_id,workspace_id,environment_id,id) DO UPDATE SET
    version=zasp_inventory_entities.version+CASE WHEN zasp_inventory_entities.kind IS DISTINCT FROM excluded.kind OR zasp_inventory_entities.display_name IS DISTINCT FROM excluded.display_name OR zasp_inventory_entities.stable_fields IS DISTINCT FROM excluded.stable_fields OR zasp_inventory_entities.state<>'active' THEN 1 ELSE 0 END,
    kind=excluded.kind,display_name=excluded.display_name,stable_fields=excluded.stable_fields,state='active',tombstoned_at=NULL,last_seen_at=committed;
  WITH candidate AS (SELECT * FROM jsonb_to_recordset(entities) e(id text,kind text,source_native_id text,display_name text,stable_fields jsonb,attributes jsonb))
  INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at)
  SELECT $1,$2,$3,$4,$8,id,source_native_id,$6,'present',attributes,committed,committed FROM candidate
  ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,source,entity_id) DO UPDATE SET source_native_id=excluded.source_native_id,snapshot_id=$6,source_state='present',attributes=excluded.attributes,last_seen_at=committed,removed_at=NULL;
  UPDATE zasp_inventory_source_observations o SET source_state='removed',removed_at=committed,last_seen_at=committed,snapshot_id=$6
   WHERE o.organization_id=$1 AND o.workspace_id=$2 AND o.environment_id=$3 AND o.integration_id=$4 AND o.source=$8 AND o.source_state='present'
     AND NOT EXISTS(SELECT 1 FROM jsonb_to_recordset(entities) e(id text) WHERE e.id=o.entity_id);
  GET DIAGNOSTICS applied_removed_count=ROW_COUNT;
  UPDATE zasp_inventory_entities entity SET state='tombstoned',tombstoned_at=committed,last_seen_at=committed,version=version+1
   WHERE entity.organization_id=$1 AND entity.workspace_id=$2 AND entity.environment_id=$3 AND entity.state='active'
     AND NOT EXISTS(SELECT 1 FROM zasp_inventory_source_observations o WHERE o.organization_id=entity.organization_id AND o.workspace_id=entity.workspace_id AND o.environment_id=entity.environment_id AND o.entity_id=entity.id AND o.source_state='present');
  IF EXISTS(SELECT 1 FROM jsonb_to_recordset(relationships) r(id text,kind text,source_native_id text,from_entity_id text,to_entity_id text,attributes jsonb) WHERE r.id<>zasp_discovery_relationship_id($1,$2,$3,$4,$8,r.kind,r.source_native_id) OR r.from_entity_id=r.to_entity_id OR NOT EXISTS(SELECT 1 FROM zasp_inventory_entities e WHERE e.organization_id=$1 AND e.workspace_id=$2 AND e.environment_id=$3 AND e.id=r.from_entity_id AND e.state='active') OR NOT EXISTS(SELECT 1 FROM zasp_inventory_entities e WHERE e.organization_id=$1 AND e.workspace_id=$2 AND e.environment_id=$3 AND e.id=r.to_entity_id AND e.state='active')) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid relationship'; END IF;
  INSERT INTO zasp_inventory_relationships(organization_id,workspace_id,environment_id,id,integration_id,source,snapshot_id,from_entity_id,to_entity_id,kind,source_native_id,state,attributes,first_seen_at,last_seen_at)
  SELECT $1,$2,$3,id,$4,$8,$6,from_entity_id,to_entity_id,kind,source_native_id,'present',attributes,committed,committed FROM jsonb_to_recordset(relationships) r(id text,kind text,source_native_id text,from_entity_id text,to_entity_id text,attributes jsonb)
  ON CONFLICT(organization_id,workspace_id,environment_id,id) DO UPDATE SET snapshot_id=$6,from_entity_id=excluded.from_entity_id,to_entity_id=excluded.to_entity_id,kind=excluded.kind,state='present',attributes=excluded.attributes,last_seen_at=committed,removed_at=NULL;
  UPDATE zasp_inventory_relationships r SET state='removed',removed_at=committed,last_seen_at=committed,snapshot_id=$6 WHERE r.organization_id=$1 AND r.workspace_id=$2 AND r.environment_id=$3 AND r.integration_id=$4 AND r.source=$8 AND r.state='present' AND NOT EXISTS(SELECT 1 FROM jsonb_to_recordset(relationships) x(id text) WHERE x.id=r.id);
  INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,finding_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at)
  SELECT $1,$2,$3,id,$4,$6,entity_id,finding_id,object_reference,decode(checksum_hex,'hex'),media_type,schema_version,parser_version,$11 FROM jsonb_to_recordset(evidence) e(id text,entity_id text,finding_id text,object_reference text,checksum_hex text,media_type text,schema_version text,parser_version text);
  UPDATE zasp_discovery_snapshots SET is_last_good=false WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4 AND source=$8 AND is_last_good;
  UPDATE zasp_discovery_snapshots SET state='complete',complete=true,is_last_good=true,committed_at=committed WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4 AND id=$6;
  INSERT INTO zasp_discovery_cursors(organization_id,workspace_id,environment_id,integration_id,provider,cursor_value,snapshot_id,committed_at) VALUES($1,$2,$3,$4,$12,$13,$6,committed) ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,provider) DO UPDATE SET cursor_value=$13,snapshot_id=$6,committed_at=committed;
  INSERT INTO zasp_projection_work(organization_id,workspace_id,environment_id,snapshot_id,kind,version,input_digest) SELECT $1,$2,$3,$6,kind,'v1',$10 FROM unnest(ARRAY['risk','graph','search']) kind;
  UPDATE zasp_discovery_syncs SET state='succeeded',snapshot_id=$6,discovered_count=applied_discovered_count,changed_count=applied_changed_count,removed_count=applied_removed_count,completed_at=committed WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4 AND id=$5;
  prior_result:=jsonb_build_object('snapshot_id',$6,'discovered_count',applied_discovered_count,'changed_count',applied_changed_count,'removed_count',applied_removed_count,'committed_at',committed);
  UPDATE zasp_discovery_snapshots SET apply_result=prior_result WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4 AND id=$6;
  RETURN prior_result;
END $$;

CREATE FUNCTION "public"."zasp_discovery_issue_sensor_token"(organization_id text,workspace_id text,environment_id text,sensor_id text,token_id text,salt bytea,token_hash bytea,expires_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb; BEGIN
 IF octet_length(salt) NOT BETWEEN 16 AND 64 OR octet_length(token_hash)<>32 OR expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid sensor token'; END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_sensors s WHERE s.organization_id=$1 AND s.workspace_id=$2 AND s.environment_id=$3 AND s.id=$4 AND s.state IN('pending','active','degraded')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor missing'; END IF;
 INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$5,$4,$6,$7,$8)
 RETURNING jsonb_build_object('id',id,'sensor_id',zasp_sensor_tokens.sensor_id,'audience',audience,'issued_at',issued_at,'expires_at',zasp_sensor_tokens.expires_at) INTO result; RETURN result;
END $$;

CREATE FUNCTION "public"."zasp_discovery_gateway_enroll"(organization_id text,workspace_id text,environment_id text,device_id text,enrollment_id text,credential_id text,token_hash bytea,audience text,key_reference text,public_key bytea,expires_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb; requested_digest bytea; prior_digest bytea; BEGIN
 IF audience<>'runtime-gateway' OR expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid gateway enrollment'; END IF;
 requested_digest:=digest(convert_to(concat_ws(chr(31),$1,$2,$3,$4,$5,$6,encode($7,'hex'),$8,$9,encode($10,'hex'),floor(extract(epoch FROM $11)*1000000)::bigint::text),'UTF8'),'sha256');
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$5),0));
 IF NOT EXISTS(SELECT 1 FROM zasp_gateway_devices d WHERE d.organization_id=$1 AND d.workspace_id=$2 AND d.environment_id=$3 AND d.id=$4 AND d.state IN('pending','active')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway device missing';END IF;
 SELECT enrollment_digest,jsonb_build_object('id',id,'device_id',zasp_gateway_credentials.device_id,'audience',zasp_gateway_credentials.audience,'issued_at',issued_at,'expires_at',zasp_gateway_credentials.expires_at) INTO prior_digest,result FROM zasp_gateway_credentials WHERE zasp_gateway_credentials.organization_id=$1 AND zasp_gateway_credentials.workspace_id=$2 AND zasp_gateway_credentials.environment_id=$3 AND zasp_gateway_credentials.device_id=$4 AND enrollment_token_id=$5;
 IF FOUND THEN IF prior_digest<>requested_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='gateway enrollment conflict'; END IF; RETURN result; END IF;
 UPDATE zasp_gateway_enrollment_tokens SET consumed_at=transaction_timestamp() WHERE zasp_gateway_enrollment_tokens.organization_id=$1 AND zasp_gateway_enrollment_tokens.workspace_id=$2 AND zasp_gateway_enrollment_tokens.environment_id=$3 AND zasp_gateway_enrollment_tokens.device_id=$4 AND id=$5 AND zasp_gateway_enrollment_tokens.token_hash=$7 AND zasp_gateway_enrollment_tokens.audience='runtime-gateway-enroll' AND consumed_at IS NULL AND revoked_at IS NULL AND zasp_gateway_enrollment_tokens.expires_at>transaction_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway enrollment missing'; END IF;
 INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at) VALUES($1,$2,$3,$6,$4,$5,requested_digest,$8,$9,$10,$11)
 RETURNING jsonb_build_object('id',id,'device_id',zasp_gateway_credentials.device_id,'audience',zasp_gateway_credentials.audience,'issued_at',issued_at,'expires_at',zasp_gateway_credentials.expires_at) INTO result;
 UPDATE zasp_gateway_devices SET state='active',version=version+1 WHERE zasp_gateway_devices.organization_id=$1 AND zasp_gateway_devices.workspace_id=$2 AND zasp_gateway_devices.environment_id=$3 AND id=$4 AND state='pending'; RETURN result;
END $$;

CREATE FUNCTION "public"."zasp_discovery_gateway_advance_replay"(organization_id text,workspace_id text,environment_id text,device_id text,expected_floor bigint,next_floor bigint)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result bigint; BEGIN
 UPDATE zasp_gateway_devices SET replay_floor=$6,version=version+1 WHERE zasp_gateway_devices.organization_id=$1 AND zasp_gateway_devices.workspace_id=$2 AND zasp_gateway_devices.environment_id=$3 AND id=$4 AND state='active' AND replay_floor=$5 AND $6>$5 RETURNING replay_floor INTO result;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway replay rejected'; END IF; RETURN to_jsonb(result);
END $$;

CREATE FUNCTION "public"."zasp_discovery_gateway_rotate"(organization_id text,workspace_id text,environment_id text,device_id text,current_id text,replacement_id text,key_reference text,public_key bytea,expires_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE requested_digest bytea;prior_digest bytea;result jsonb;BEGIN
 requested_digest:=digest(convert_to(concat_ws(chr(31),$1,$2,$3,$4,$5,$6,$7,encode($8,'hex'),floor(extract(epoch FROM $9)*1000000)::bigint::text),'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4,$5),0));
 IF NOT EXISTS(SELECT 1 FROM zasp_gateway_devices d WHERE d.organization_id=$1 AND d.workspace_id=$2 AND d.environment_id=$3 AND d.id=$4 AND d.state='active') THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway device missing';END IF;
 SELECT enrollment_digest,jsonb_build_object('id',id,'device_id',zasp_gateway_credentials.device_id,'audience',audience,'issued_at',issued_at,'expires_at',zasp_gateway_credentials.expires_at) INTO prior_digest,result FROM zasp_gateway_credentials WHERE zasp_gateway_credentials.organization_id=$1 AND zasp_gateway_credentials.workspace_id=$2 AND zasp_gateway_credentials.environment_id=$3 AND zasp_gateway_credentials.device_id=$4 AND id=$6;
 IF FOUND THEN IF prior_digest<>requested_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='gateway rotation conflict';END IF;RETURN result;END IF;
 UPDATE zasp_gateway_credentials SET revoked_at=transaction_timestamp() WHERE zasp_gateway_credentials.organization_id=$1 AND zasp_gateway_credentials.workspace_id=$2 AND zasp_gateway_credentials.environment_id=$3 AND zasp_gateway_credentials.device_id=$4 AND id=$5 AND revoked_at IS NULL AND zasp_gateway_credentials.expires_at>transaction_timestamp();IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway credential missing';END IF;
 INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_digest,audience,key_reference,public_key,expires_at,rotated_from_id) VALUES($1,$2,$3,$6,$4,requested_digest,'runtime-gateway',$7,$8,$9,$5) RETURNING jsonb_build_object('id',id,'device_id',zasp_gateway_credentials.device_id,'audience',audience,'issued_at',issued_at,'expires_at',zasp_gateway_credentials.expires_at) INTO result;RETURN result;
END $$;

CREATE FUNCTION "public"."zasp_discovery_gateway_revoke"(organization_id text,workspace_id text,environment_id text,device_id text,credential_id text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE revoked timestamptz;BEGIN UPDATE zasp_gateway_credentials SET revoked_at=COALESCE(revoked_at,transaction_timestamp()) WHERE zasp_gateway_credentials.organization_id=$1 AND zasp_gateway_credentials.workspace_id=$2 AND zasp_gateway_credentials.environment_id=$3 AND zasp_gateway_credentials.device_id=$4 AND id=$5 RETURNING revoked_at INTO revoked;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway credential missing';END IF;RETURN jsonb_build_object('id',$5,'revoked_at',revoked);END $$;

CREATE FUNCTION "public"."zasp_discovery_put_gateway_policy"(organization_id text,workspace_id text,environment_id text,device_id text,policy_id text,policy_version bigint,policy_digest bytea,signature bytea,issued_at timestamptz,expires_at timestamptz,sequence bigint)
RETURNS jsonb LANGUAGE plpgsql AS $$
#variable_conflict use_column
DECLARE prior zasp_gateway_policy_subscriptions%ROWTYPE;BEGIN
 IF octet_length($7)<>32 OR octet_length($8) NOT BETWEEN 32 AND 8192 OR $10<=$9 OR $11<0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid gateway policy';END IF;PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4,$5),0));
 IF NOT EXISTS(SELECT 1 FROM zasp_gateway_devices d WHERE d.organization_id=$1 AND d.workspace_id=$2 AND d.environment_id=$3 AND d.id=$4 AND d.state='active') THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='gateway device missing';END IF;
 SELECT * INTO prior FROM zasp_gateway_policy_subscriptions p WHERE p.organization_id=$1 AND p.workspace_id=$2 AND p.environment_id=$3 AND p.device_id=$4 AND p.policy_id=$5;
 IF FOUND THEN IF prior.last_sequence=$11 AND prior.policy_version=$6 AND prior.policy_digest=$7 AND prior.signature=$8 AND prior.issued_at=$9 AND prior.expires_at=$10 THEN RETURN jsonb_build_object('policy_id',$5,'sequence',$11);END IF;IF $11<=prior.last_sequence THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='gateway policy replay rejected';END IF;END IF;
 INSERT INTO zasp_gateway_policy_subscriptions(organization_id,workspace_id,environment_id,device_id,policy_id,policy_version,policy_digest,signature,issued_at,expires_at,last_sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(organization_id,workspace_id,environment_id,device_id,policy_id) DO UPDATE SET policy_version=$6,policy_digest=$7,signature=$8,issued_at=$9,expires_at=$10,last_sequence=$11,revoked_at=NULL;RETURN jsonb_build_object('policy_id',$5,'sequence',$11);
END $$;

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
    UPDATE zasp_discovery_outbox SET state='exhausted',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error=COALESCE(last_error,'maximum publish attempts exhausted')
      WHERE attempt>=100 AND (state='failed' OR state='leased' AND lease_expires_at<=transaction_timestamp());
    WITH organizations AS (
      SELECT organization_id,min(available_at) due FROM zasp_discovery_outbox WHERE attempt<100 AND (state IN ('pending','failed') OR state='leased' AND lease_expires_at<=transaction_timestamp()) AND available_at<=transaction_timestamp() GROUP BY organization_id ORDER BY due,organization_id LIMIT claim_limit
    ), picked AS (
      SELECT chosen.ctid,chosen.organization_id,chosen.created_at,chosen.id FROM organizations g CROSS JOIN LATERAL
       (SELECT o.ctid,o.organization_id,o.created_at,o.id FROM zasp_discovery_outbox o WHERE o.organization_id=g.organization_id
        AND o.attempt<100 AND (o.state IN ('pending','failed') OR o.state='leased' AND o.lease_expires_at<=transaction_timestamp()) AND o.available_at<=transaction_timestamp()
        ORDER BY o.created_at,o.id LIMIT 1 FOR UPDATE SKIP LOCKED) chosen
    ), claimed AS (
      UPDATE zasp_discovery_outbox o SET state='leased',attempt=attempt+1,lease_owner=worker,lease_token=$2,lease_expires_at=transaction_timestamp()+make_interval(secs=>$3),completion_digest=NULL,completion_result=NULL
      FROM (SELECT * FROM picked ORDER BY created_at,organization_id,id LIMIT claim_limit) p WHERE o.ctid=p.ctid
      RETURNING o.organization_id,o.workspace_id,o.environment_id,o.id,o.topic,o.deterministic_key,o.payload_version,o.payload,encode(o.payload_digest,'base64') AS payload_digest,o.attempt,o.lease_expires_at
    ) SELECT jsonb_build_object('items',COALESCE(jsonb_agg(to_jsonb(claimed) ORDER BY organization_id,id),'[]'::jsonb)) INTO response FROM claimed;
    RETURN response;
END; $$;

CREATE FUNCTION "public"."zasp_discovery_claim_jobs"(worker text,lease_token text,lease_seconds integer,claim_limit integer,requested_kind text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE response jsonb; BEGIN
 IF length(worker) NOT BETWEEN 1 AND 128 OR length(lease_token) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 OR claim_limit NOT BETWEEN 1 AND 100 OR requested_kind NOT IN('discovery','runtime','projection') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid job claim'; END IF;
 WITH exhausted AS (UPDATE zasp_discovery_jobs SET state='failed',last_error=COALESCE(last_error,'lease expired after maximum attempts'),completed_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE kind=requested_kind AND attempt>=5 AND state='leased' AND lease_expires_at<=transaction_timestamp() RETURNING organization_id,workspace_id,environment_id,kind,authority_id,last_error,attempt)
 UPDATE zasp_discovery_syncs s SET state='failed',attempt=e.attempt,last_error=e.last_error,completed_at=transaction_timestamp() FROM exhausted e WHERE e.kind='discovery' AND s.organization_id=e.organization_id AND s.workspace_id=e.workspace_id AND s.environment_id=e.environment_id AND s.id=e.authority_id AND s.state IN('queued','running');
 WITH organizations AS (SELECT organization_id,min(available_at) due FROM zasp_discovery_jobs WHERE kind=requested_kind AND attempt<5 AND (state IN('queued','retryable') OR state='leased' AND lease_expires_at<=transaction_timestamp()) AND available_at<=transaction_timestamp() GROUP BY organization_id ORDER BY due,organization_id LIMIT claim_limit),
 picked AS (SELECT chosen.ctid,chosen.organization_id,chosen.created_at,chosen.id FROM organizations g CROSS JOIN LATERAL (SELECT j.ctid,j.organization_id,j.created_at,j.id FROM zasp_discovery_jobs j WHERE j.organization_id=g.organization_id AND j.kind=requested_kind AND j.attempt<5 AND (j.state IN('queued','retryable') OR j.state='leased' AND j.lease_expires_at<=transaction_timestamp()) AND j.available_at<=transaction_timestamp() ORDER BY j.created_at,j.id LIMIT 1 FOR UPDATE SKIP LOCKED) chosen),
 claimed AS (UPDATE zasp_discovery_jobs j SET state='leased',attempt=attempt+1,lease_owner=worker,lease_token=$2,lease_expires_at=transaction_timestamp()+make_interval(secs=>$3),completion_digest=NULL,completion_result=NULL,updated_at=transaction_timestamp() FROM (SELECT * FROM picked ORDER BY created_at,organization_id,id LIMIT claim_limit) p WHERE j.ctid=p.ctid RETURNING j.organization_id,j.workspace_id,j.environment_id,j.id,j.kind,j.authority_id,j.attempt,j.lease_expires_at)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(to_jsonb(claimed) ORDER BY organization_id,id),'[]'::jsonb)) INTO response FROM claimed;
 UPDATE zasp_discovery_syncs s SET state='running',attempt=j.attempt,started_at=COALESCE(s.started_at,transaction_timestamp()),last_error=NULL FROM zasp_discovery_jobs j WHERE j.kind='discovery' AND j.lease_owner=worker AND j.lease_token=$2 AND s.organization_id=j.organization_id AND s.workspace_id=j.workspace_id AND s.environment_id=j.environment_id AND s.id=j.authority_id AND s.state IN('queued','running');
 RETURN response;
END $$;

CREATE FUNCTION "public"."zasp_discovery_claim_schedules"(worker text,lease_token text,lease_seconds integer,claim_limit integer)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE response jsonb; BEGIN
 IF length(worker) NOT BETWEEN 1 AND 128 OR length(lease_token) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 OR claim_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid schedule claim'; END IF;
 WITH organizations AS (SELECT organization_id,min(next_run_at) due FROM zasp_discovery_schedules WHERE state='enabled' AND next_run_at<=transaction_timestamp() AND (lease_owner IS NULL OR lease_expires_at<=transaction_timestamp()) GROUP BY organization_id ORDER BY due,organization_id LIMIT claim_limit),
 picked AS (SELECT chosen.ctid,chosen.organization_id,chosen.next_run_at,chosen.id FROM organizations g CROSS JOIN LATERAL (SELECT s.ctid,s.organization_id,s.next_run_at,s.id FROM zasp_discovery_schedules s WHERE s.organization_id=g.organization_id AND s.state='enabled' AND s.next_run_at<=transaction_timestamp() AND (s.lease_owner IS NULL OR s.lease_expires_at<=transaction_timestamp()) ORDER BY s.next_run_at,s.id LIMIT 1 FOR UPDATE SKIP LOCKED) chosen),
 claimed AS (UPDATE zasp_discovery_schedules s SET lease_owner=worker,lease_token=$2,lease_expires_at=transaction_timestamp()+make_interval(secs=>$3),last_claimed_at=transaction_timestamp(),completion_digest=NULL,completion_result=NULL,updated_at=transaction_timestamp(),version=version+1 FROM (SELECT * FROM picked ORDER BY next_run_at,organization_id,id LIMIT claim_limit) p WHERE s.ctid=p.ctid RETURNING s.organization_id,s.workspace_id,s.environment_id,s.id,s.integration_id,s.next_run_at,s.lease_expires_at)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(to_jsonb(claimed) ORDER BY organization_id,id),'[]'::jsonb)) INTO response FROM claimed; RETURN response;
END $$;

CREATE FUNCTION "public"."zasp_discovery_claim_projection_work"(worker text,lease_token text,lease_seconds integer,claim_limit integer)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE response jsonb; BEGIN
 IF length(worker) NOT BETWEEN 1 AND 128 OR length(lease_token) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 OR claim_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid projection claim'; END IF;
 UPDATE zasp_projection_work SET state='failed',last_error=COALESCE(last_error,'lease expired after maximum attempts'),completed_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE attempt>=5 AND state='leased' AND lease_expires_at<=transaction_timestamp();
 WITH organizations AS (SELECT organization_id,min(snapshot_id) first_snapshot FROM zasp_projection_work WHERE attempt<5 AND available_at<=transaction_timestamp() AND (state IN('pending','retryable') OR state='leased' AND lease_expires_at<=transaction_timestamp()) GROUP BY organization_id ORDER BY first_snapshot,organization_id LIMIT claim_limit),
 picked AS (SELECT chosen.ctid,chosen.organization_id,chosen.snapshot_id,chosen.kind FROM organizations g CROSS JOIN LATERAL (SELECT p.ctid,p.organization_id,p.snapshot_id,p.kind FROM zasp_projection_work p WHERE p.organization_id=g.organization_id AND p.attempt<5 AND p.available_at<=transaction_timestamp() AND (p.state IN('pending','retryable') OR p.state='leased' AND p.lease_expires_at<=transaction_timestamp()) ORDER BY p.snapshot_id,p.kind LIMIT 1 FOR UPDATE SKIP LOCKED) chosen),
 claimed AS (UPDATE zasp_projection_work p SET state='leased',attempt=attempt+1,lease_owner=worker,lease_token=$2,lease_expires_at=transaction_timestamp()+make_interval(secs=>$3),completion_digest=NULL,completion_result=NULL FROM (SELECT * FROM picked ORDER BY snapshot_id,organization_id,kind LIMIT claim_limit) selected WHERE p.ctid=selected.ctid RETURNING p.organization_id,p.workspace_id,p.environment_id,p.snapshot_id,p.kind,p.version,encode(p.input_digest,'base64') AS input_digest,p.attempt,p.lease_expires_at)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(to_jsonb(claimed) ORDER BY organization_id,snapshot_id,kind),'[]'::jsonb)) INTO response FROM claimed; RETURN response;
END $$;

CREATE FUNCTION "public"."zasp_discovery_complete_schedule"(p_organization_id text,p_workspace_id text,p_environment_id text,p_schedule_id text,worker text,lease_token text,outcome text,next_run_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE requested bytea;result jsonb;BEGIN IF outcome NOT IN('advanced','released','disabled') OR next_run_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid schedule completion';END IF;requested:=digest(convert_to(concat_ws(chr(31),$4,$5,$6,$7,floor(extract(epoch FROM $8)*1000000)::bigint::text),'UTF8'),'sha256');SELECT completion_result INTO result FROM zasp_discovery_schedules WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND completion_digest=requested;IF FOUND THEN RETURN result;END IF;UPDATE zasp_discovery_schedules SET state=CASE WHEN $7='disabled' THEN 'disabled' ELSE 'enabled' END,next_run_at=$8,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=transaction_timestamp(),completion_digest=requested WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND state='enabled' AND lease_owner=$5 AND zasp_discovery_schedules.lease_token=$6 AND lease_expires_at>transaction_timestamp() RETURNING jsonb_build_object('id',id,'state',state,'next_run_at',zasp_discovery_schedules.next_run_at,'version',version) INTO result;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule lease missing';END IF;UPDATE zasp_discovery_schedules SET completion_result=result WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_finish_job"(p_organization_id text,p_workspace_id text,p_environment_id text,p_job_id text,worker text,p_lease_token text,outcome text,result_digest bytea,last_error text,retry_after_seconds integer)
RETURNS jsonb LANGUAGE plpgsql AS $$
#variable_conflict use_column
DECLARE requested bytea;effective text;result jsonb;current_attempt integer;job_kind text;job_authority_id text;
BEGIN
 IF outcome NOT IN('succeeded','retryable','failed','cancelled') OR retry_after_seconds NOT BETWEEN 0 AND 3600 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid job outcome';END IF;
 requested:=digest(convert_to(concat_ws(chr(31),$4,$5,$6,$7,COALESCE(encode($8,'hex'),''),COALESCE($9,''),$10::text),'UTF8'),'sha256');
 SELECT completion_result INTO result FROM zasp_discovery_jobs WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND completion_digest=requested;IF FOUND THEN RETURN result;END IF;
 SELECT attempt,kind,authority_id INTO current_attempt,job_kind,job_authority_id FROM zasp_discovery_jobs WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND state='leased' AND lease_owner=$5 AND lease_token=$6 AND lease_expires_at>transaction_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='job lease missing';END IF;
 effective:=CASE WHEN outcome='retryable' AND current_attempt>=5 THEN 'failed' ELSE outcome END;
 result:=jsonb_build_object('id',$4,'state',effective,'attempt',current_attempt,'completed_at',CASE WHEN effective IN('succeeded','failed','cancelled') THEN transaction_timestamp() ELSE NULL END);
 UPDATE zasp_discovery_jobs SET state=effective,result_digest=$8,last_error=NULLIF($9,''),available_at=CASE WHEN effective='retryable' THEN transaction_timestamp()+make_interval(secs=>$10) ELSE available_at END,completed_at=CASE WHEN effective IN('succeeded','failed','cancelled') THEN transaction_timestamp() ELSE NULL END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,completion_digest=requested,completion_result=result,updated_at=transaction_timestamp() WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4;
 IF job_kind='discovery' AND effective IN('retryable','failed','cancelled') THEN
   UPDATE zasp_discovery_syncs SET state=CASE WHEN effective='retryable' THEN 'queued' ELSE effective END,attempt=current_attempt,last_error=NULLIF($9,''),completed_at=CASE WHEN effective IN('failed','cancelled') THEN transaction_timestamp() ELSE NULL END WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=job_authority_id AND state IN('queued','running');
 END IF;
 RETURN result;
END $$;

CREATE FUNCTION "public"."zasp_discovery_finish_projection"(p_organization_id text,p_workspace_id text,p_environment_id text,p_snapshot_id text,p_kind text,p_version text,worker text,p_lease_token text,outcome text,last_error text,retry_after_seconds integer)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE requested bytea;effective text;result jsonb;current_attempt integer;BEGIN IF outcome NOT IN('succeeded','retryable','failed','cancelled') OR retry_after_seconds NOT BETWEEN 0 AND 3600 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid projection outcome';END IF;requested:=digest(convert_to(concat_ws(chr(31),$4,$5,$6,$7,$8,$9,COALESCE($10,''),$11::text),'UTF8'),'sha256');SELECT completion_result INTO result FROM zasp_projection_work WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND snapshot_id=$4 AND zasp_projection_work.kind=$5 AND zasp_projection_work.version=$6 AND completion_digest=requested;IF FOUND THEN RETURN result;END IF;SELECT attempt INTO current_attempt FROM zasp_projection_work WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND snapshot_id=$4 AND zasp_projection_work.kind=$5 AND zasp_projection_work.version=$6 AND state='leased' AND lease_owner=$7 AND lease_token=$8 AND lease_expires_at>transaction_timestamp() FOR UPDATE;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='projection lease missing';END IF;effective:=CASE WHEN outcome='retryable' AND current_attempt>=5 THEN 'failed' ELSE outcome END;result:=jsonb_build_object('snapshot_id',$4,'kind',$5,'state',effective,'attempt',current_attempt);UPDATE zasp_projection_work SET state=effective,last_error=NULLIF($10,''),available_at=CASE WHEN effective='retryable' THEN transaction_timestamp()+make_interval(secs=>$11) ELSE available_at END,completed_at=CASE WHEN effective IN('succeeded','failed','cancelled') THEN transaction_timestamp() ELSE NULL END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,completion_digest=requested,completion_result=result WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND snapshot_id=$4 AND zasp_projection_work.kind=$5 AND zasp_projection_work.version=$6;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_ack_outbox"(organization_id text, workspace_id text, environment_id text, outbox_id text, worker text, lease_token text, provider_ack text)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE response jsonb;requested bytea;
BEGIN
    IF length($7) NOT BETWEEN 1 AND 512 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid outbox acknowledgement';END IF;
    requested:=digest(convert_to(concat_ws(chr(31),$4,$5,$6,$7),'UTF8'),'sha256');
    SELECT completion_result INTO response FROM zasp_discovery_outbox WHERE zasp_discovery_outbox.organization_id=$1 AND zasp_discovery_outbox.workspace_id=$2 AND zasp_discovery_outbox.environment_id=$3 AND id=$4 AND state='published' AND completion_digest=requested;
    IF FOUND THEN RETURN response;ELSIF EXISTS(SELECT 1 FROM zasp_discovery_outbox WHERE zasp_discovery_outbox.organization_id=$1 AND zasp_discovery_outbox.workspace_id=$2 AND zasp_discovery_outbox.environment_id=$3 AND id=$4 AND state='published') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='outbox acknowledgement conflict';END IF;
    UPDATE zasp_discovery_outbox SET state='published',provider_ack=$7,published_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,completion_digest=requested
     WHERE zasp_discovery_outbox.organization_id=$1 AND zasp_discovery_outbox.workspace_id=$2 AND zasp_discovery_outbox.environment_id=$3 AND id=$4
       AND state='leased' AND lease_owner=$5 AND zasp_discovery_outbox.lease_token=$6 AND lease_expires_at>transaction_timestamp()
     RETURNING jsonb_build_object('id',id,'published_at',published_at,'provider_ack',zasp_discovery_outbox.provider_ack) INTO response;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='outbox lease missing'; END IF;
    UPDATE zasp_discovery_outbox SET completion_result=response WHERE zasp_discovery_outbox.organization_id=$1 AND zasp_discovery_outbox.workspace_id=$2 AND zasp_discovery_outbox.environment_id=$3 AND id=$4;
    RETURN response;
END; $$;

CREATE FUNCTION "public"."zasp_discovery_retry_outbox"(organization_id text,workspace_id text,environment_id text,outbox_id text,worker text,lease_token text,retry_after_seconds integer,last_error text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE available timestamptz;requested bytea;result jsonb;BEGIN IF retry_after_seconds NOT BETWEEN 1 AND 3600 OR length(last_error) NOT BETWEEN 1 AND 1024 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid outbox retry';END IF;requested:=digest(convert_to(concat_ws(chr(31),$4,$5,$6,$7::text,$8),'UTF8'),'sha256');SELECT completion_result INTO result FROM zasp_discovery_outbox WHERE zasp_discovery_outbox.organization_id=$1 AND zasp_discovery_outbox.workspace_id=$2 AND zasp_discovery_outbox.environment_id=$3 AND id=$4 AND state='failed' AND completion_digest=requested;IF FOUND THEN RETURN result;ELSIF EXISTS(SELECT 1 FROM zasp_discovery_outbox WHERE zasp_discovery_outbox.organization_id=$1 AND zasp_discovery_outbox.workspace_id=$2 AND zasp_discovery_outbox.environment_id=$3 AND id=$4 AND state='failed' AND completion_digest IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='outbox retry conflict';END IF;UPDATE zasp_discovery_outbox SET state='failed',available_at=transaction_timestamp()+make_interval(secs=>$7),last_error=$8,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,completion_digest=requested WHERE zasp_discovery_outbox.organization_id=$1 AND zasp_discovery_outbox.workspace_id=$2 AND zasp_discovery_outbox.environment_id=$3 AND id=$4 AND state='leased' AND lease_owner=$5 AND zasp_discovery_outbox.lease_token=$6 AND lease_expires_at>transaction_timestamp() RETURNING available_at INTO available;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='outbox lease missing';END IF;result:=jsonb_build_object('id',$4,'available_at',available);UPDATE zasp_discovery_outbox SET completion_result=result WHERE zasp_discovery_outbox.organization_id=$1 AND zasp_discovery_outbox.workspace_id=$2 AND zasp_discovery_outbox.environment_id=$3 AND id=$4;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_complete_job"(organization_id text,workspace_id text,environment_id text,job_id text,worker text,lease_token text,result_digest bytea,retryable boolean,last_error text)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;
BEGIN
  result:=zasp_discovery_finish_job($1,$2,$3,$4,$5,$6,CASE WHEN $8 THEN 'retryable' ELSE 'succeeded' END,$7,$9,5);
  RETURN jsonb_build_object('id',result->>'id','state',result->>'state');
END $$;

CREATE FUNCTION "public"."zasp_discovery_complete_projection"(organization_id text,workspace_id text,environment_id text,snapshot_id text,kind text,version text,worker text,lease_token text,succeeded boolean)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;
BEGIN
  result:=zasp_discovery_finish_projection($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $9 THEN 'succeeded' ELSE 'retryable' END,NULL,5);
  RETURN jsonb_build_object('snapshot_id',result->>'snapshot_id','kind',result->>'kind','state',result->>'state');
END $$;

CREATE FUNCTION "public"."zasp_discovery_evidence_get"(organization_id text,workspace_id text,environment_id text,evidence_id text)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$ DECLARE result jsonb;BEGIN SELECT jsonb_build_object('id',id,'integration_id',integration_id,'snapshot_id',snapshot_id,'entity_id',entity_id,'finding_id',finding_id,'object_reference',object_reference,'checksum',encode(checksum,'base64'),'media_type',media_type,'schema_version',schema_version,'parser_version',parser_version,'collected_at',collected_at) INTO result FROM zasp_inventory_evidence e WHERE e.organization_id=$1 AND e.workspace_id=$2 AND e.environment_id=$3 AND id=$4;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='evidence missing';END IF;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_sensor_rotate"(organization_id text,workspace_id text,environment_id text,sensor_id text,current_id text,replacement_id text,salt bytea,token_hash bytea,expires_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE result jsonb;requested_digest bytea;prior_digest bytea;BEGIN requested_digest:=digest(convert_to(concat_ws(chr(31),$1,$2,$3,$4,$5,$6,encode($7,'hex'),encode($8,'hex'),floor(extract(epoch FROM $9)*1000000)::bigint::text),'UTF8'),'sha256');IF NOT EXISTS(SELECT 1 FROM zasp_sensors s WHERE s.organization_id=$1 AND s.workspace_id=$2 AND s.environment_id=$3 AND s.id=$4 AND s.state IN('pending','active','degraded')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor missing';END IF;PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4,$5),0));SELECT rotation_digest,jsonb_build_object('id',id,'sensor_id',zasp_sensor_tokens.sensor_id,'audience',audience,'issued_at',issued_at,'expires_at',zasp_sensor_tokens.expires_at) INTO prior_digest,result FROM zasp_sensor_tokens WHERE zasp_sensor_tokens.organization_id=$1 AND zasp_sensor_tokens.workspace_id=$2 AND zasp_sensor_tokens.environment_id=$3 AND zasp_sensor_tokens.sensor_id=$4 AND id=$6 AND rotated_from_id=$5;IF FOUND THEN IF prior_digest<>requested_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor rotation conflict';END IF;RETURN result;END IF;UPDATE zasp_sensor_tokens SET revoked_at=transaction_timestamp() WHERE zasp_sensor_tokens.organization_id=$1 AND zasp_sensor_tokens.workspace_id=$2 AND zasp_sensor_tokens.environment_id=$3 AND zasp_sensor_tokens.sensor_id=$4 AND id=$5 AND revoked_at IS NULL;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor token missing';END IF;INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at,rotated_from_id,rotation_digest) VALUES($1,$2,$3,$6,$4,$7,$8,$9,$5,requested_digest) RETURNING jsonb_build_object('id',id,'sensor_id',zasp_sensor_tokens.sensor_id,'audience',audience,'issued_at',issued_at,'expires_at',zasp_sensor_tokens.expires_at) INTO result;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_sensor_revoke"(organization_id text,workspace_id text,environment_id text,sensor_id text,token_id text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE revoked timestamptz;BEGIN UPDATE zasp_sensor_tokens SET revoked_at=COALESCE(revoked_at,transaction_timestamp()) WHERE zasp_sensor_tokens.organization_id=$1 AND zasp_sensor_tokens.workspace_id=$2 AND zasp_sensor_tokens.environment_id=$3 AND zasp_sensor_tokens.sensor_id=$4 AND id=$5 RETURNING revoked_at INTO revoked;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor token missing';END IF;RETURN jsonb_build_object('id',$5,'revoked_at',revoked);END $$;

CREATE FUNCTION "public"."zasp_discovery_sensor_heartbeat"(organization_id text,workspace_id text,environment_id text,sensor_id text,sequence bigint,status text,dropped_events bigint,metadata jsonb)
RETURNS jsonb LANGUAGE plpgsql AS $$
#variable_conflict use_column
DECLARE observed timestamptz;computed_digest bytea;prior_digest bytea;prior_sequence bigint;
BEGIN
 computed_digest:=digest(convert_to(jsonb_build_object('sensor_id',$4,'sequence',$5,'status',$6,'dropped_events',$7,'metadata',$8)::text,'UTF8'),'sha256');
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4),0));
 IF NOT EXISTS(SELECT 1 FROM zasp_sensors s WHERE s.organization_id=$1 AND s.workspace_id=$2 AND s.environment_id=$3 AND s.id=$4 AND s.state IN('pending','active','degraded')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor missing';END IF;
 SELECT h.request_digest,h.sequence,h.observed_at INTO prior_digest,prior_sequence,observed FROM zasp_sensor_heartbeats h WHERE h.organization_id=$1 AND h.workspace_id=$2 AND h.environment_id=$3 AND h.sensor_id=$4;
 IF FOUND AND prior_sequence=$5 THEN IF prior_digest<>computed_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='heartbeat replay conflict';END IF;RETURN jsonb_build_object('sensor_id',$4,'sequence',$5,'observed_at',observed);ELSIF FOUND AND prior_sequence>$5 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='heartbeat replay rejected';END IF;
 INSERT INTO zasp_sensor_heartbeats(organization_id,workspace_id,environment_id,sensor_id,sequence,request_digest,status,dropped_events,metadata) VALUES($1,$2,$3,$4,$5,computed_digest,$6,$7,$8) ON CONFLICT(organization_id,workspace_id,environment_id,sensor_id) DO UPDATE SET sequence=$5,request_digest=computed_digest,status=$6,dropped_events=$7,metadata=$8,observed_at=transaction_timestamp() RETURNING observed_at INTO observed;
 UPDATE zasp_sensors SET state=CASE WHEN $6='healthy' THEN 'active' ELSE 'degraded' END,updated_at=transaction_timestamp(),version=version+1 WHERE zasp_sensors.organization_id=$1 AND zasp_sensors.workspace_id=$2 AND zasp_sensors.environment_id=$3 AND id=$4 AND state IN('pending','active','degraded');
 RETURN jsonb_build_object('sensor_id',$4,'sequence',$5,'observed_at',observed);
END $$;

CREATE FUNCTION "public"."zasp_discovery_create_runtime_batch"(organization_id text,workspace_id text,environment_id text,sensor_id text,batch_id text,job_id text,outbox_id text,idempotency_key text,payload_digest bytea,event_count integer,payload_reference text,payload_size_bytes bigint,payload_media_type text,payload_schema_version text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE event_payload jsonb;prior zasp_runtime_batches%ROWTYPE;BEGIN IF NOT EXISTS(SELECT 1 FROM zasp_sensors s WHERE s.organization_id=$1 AND s.workspace_id=$2 AND s.environment_id=$3 AND s.id=$4 AND s.state IN('active','degraded')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sensor missing';END IF;PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4,$8),0));SELECT * INTO prior FROM zasp_runtime_batches b WHERE b.organization_id=$1 AND b.workspace_id=$2 AND b.environment_id=$3 AND b.sensor_id=$4 AND b.idempotency_key=$8;IF FOUND THEN IF prior.payload_digest<>$9 OR prior.event_count<>$10 OR prior.payload_reference<>$11 OR prior.payload_size_bytes<>$12 OR prior.payload_media_type<>$13 OR prior.payload_schema_version<>$14 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime batch conflict';END IF;RETURN jsonb_build_object('batch_id',prior.id,'replayed',true);END IF;INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version) VALUES($1,$2,$3,$5,$4,$8,$9,$10,$11,$12,$13,$14);INSERT INTO zasp_discovery_jobs(organization_id,workspace_id,environment_id,id,kind,authority_id,idempotency_key,request_digest) VALUES($1,$2,$3,$6,'runtime',$5,$8,$9);event_payload:=jsonb_build_object('organization_id',$1,'workspace_id',$2,'environment_id',$3,'batch_id',$5,'job_id',$6,'payload_reference',$11,'payload_digest',encode($9,'hex'),'payload_size_bytes',$12,'payload_media_type',$13,'payload_schema_version',$14,'event_count',$10);INSERT INTO zasp_discovery_outbox(organization_id,workspace_id,environment_id,id,topic,deterministic_key,payload_version,payload,payload_digest) VALUES($1,$2,$3,$7,'runtime-events','runtime:'||$5,1,event_payload,digest(convert_to(event_payload::text,'UTF8'),'sha256'));RETURN jsonb_build_object('batch_id',$5,'replayed',false);END $$;

CREATE FUNCTION "public"."zasp_discovery_complete_runtime_stage"(p_organization_id text,p_workspace_id text,p_environment_id text,p_batch_id text,p_stage text,p_input_digest bytea,p_succeeded boolean,p_result_reference text)
RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE stage_order text[]:=ARRAY['archive','index','correlate','risk','graph','complete'];position integer;requested_digest bytea;prior zasp_runtime_stages%ROWTYPE;result jsonb;next_attempt integer;BEGIN position:=array_position(stage_order,$5);requested_digest:=digest(convert_to(concat_ws(chr(31),$4,$5,encode($6,'hex'),$7::text,COALESCE($8,'')),'UTF8'),'sha256');PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4,$5),0));SELECT * INTO prior FROM zasp_runtime_stages s WHERE s.organization_id=$1 AND s.workspace_id=$2 AND s.environment_id=$3 AND s.batch_id=$4 AND s.stage=$5;IF FOUND THEN IF prior.completion_digest=requested_digest THEN RETURN prior.completion_result;END IF;IF prior.state='succeeded' OR prior.input_digest<>$6 OR prior.attempt>=5 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime stage conflict';END IF;next_attempt:=prior.attempt+1;ELSE next_attempt:=1;END IF;IF position IS NULL OR octet_length($6)<>32 OR position>1 AND NOT EXISTS(SELECT 1 FROM zasp_runtime_stages s WHERE s.organization_id=$1 AND s.workspace_id=$2 AND s.environment_id=$3 AND s.batch_id=$4 AND s.stage=stage_order[position-1] AND s.state='succeeded') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid runtime stage order';END IF;result:=jsonb_build_object('batch_id',$4,'stage',$5,'state',CASE WHEN $7 THEN 'succeeded' ELSE 'failed' END);INSERT INTO zasp_runtime_stages(organization_id,workspace_id,environment_id,batch_id,stage,input_digest,state,attempt,result_reference,completion_digest,completion_result,completed_at) VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $7 THEN 'succeeded' ELSE 'failed' END,next_attempt,$8,requested_digest,result,CASE WHEN $7 THEN transaction_timestamp() ELSE NULL END) ON CONFLICT(organization_id,workspace_id,environment_id,batch_id,stage) DO UPDATE SET state=excluded.state,attempt=excluded.attempt,result_reference=excluded.result_reference,completion_digest=excluded.completion_digest,completion_result=excluded.completion_result,completed_at=excluded.completed_at;UPDATE zasp_runtime_batches SET state=CASE WHEN $7 AND $5='complete' THEN 'succeeded' WHEN $7 THEN 'processing' ELSE 'failed' END,completed_at=CASE WHEN NOT $7 OR $5='complete' THEN transaction_timestamp() ELSE NULL END WHERE zasp_runtime_batches.organization_id=$1 AND zasp_runtime_batches.workspace_id=$2 AND zasp_runtime_batches.environment_id=$3 AND id=$4;RETURN result;END $$;

CREATE FUNCTION "public"."zasp_discovery_security_ready"() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN('zasp_discovery_authority','zasp_discovery_api','zasp_discovery_worker') AND (r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolbypassrls))
 AND NOT pg_has_role('zasp_discovery_api','zasp_discovery_authority','MEMBER') AND NOT pg_has_role('zasp_discovery_worker','zasp_discovery_authority','MEMBER')
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_integrations','zasp_integration_connections','zasp_discovery_schedules','zasp_discovery_syncs','zasp_discovery_jobs','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_evidence','zasp_sensors','zasp_sensor_tokens','zasp_sensor_heartbeats','zasp_runtime_batches','zasp_runtime_stages','zasp_discovery_outbox','zasp_projection_work','zasp_gateway_devices','zasp_gateway_enrollment_tokens','zasp_gateway_credentials','zasp_gateway_policy_subscriptions']) AND (c.relowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname=c.relname||'_authority' AND p.polpermissive AND p.polcmd='*' AND p.polroles=ARRAY[(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority')] AND pg_get_expr(p.polqual,p.polrelid)='true' AND pg_get_expr(p.polwithcheck,p.polrelid)='true') OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee IN(0,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api'),(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_worker')))))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_discovery_%' AND (p.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT p.prosecdef OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') OR has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE')<>(p.proname=ANY(ARRAY['zasp_discovery_readiness','zasp_discovery_create_integration','zasp_discovery_transition_integration','zasp_discovery_put_connection','zasp_discovery_transition_connection','zasp_discovery_put_schedule','zasp_discovery_transition_schedule','zasp_discovery_create_sensor','zasp_discovery_transition_sensor','zasp_discovery_create_gateway_device','zasp_discovery_transition_gateway_device','zasp_discovery_issue_gateway_enrollment','zasp_discovery_revoke_gateway_enrollment','zasp_discovery_request_sync','zasp_discovery_entity_page','zasp_discovery_evidence_get'])) OR has_function_privilege('zasp_discovery_worker',p.oid,'EXECUTE')<>(p.proname=ANY(ARRAY['zasp_discovery_readiness','zasp_discovery_apply_snapshot','zasp_discovery_claim_outbox','zasp_discovery_claim_jobs','zasp_discovery_claim_schedules','zasp_discovery_complete_schedule','zasp_discovery_claim_projection_work','zasp_discovery_finish_job','zasp_discovery_finish_projection','zasp_discovery_ack_outbox','zasp_discovery_retry_outbox','zasp_discovery_complete_job','zasp_discovery_complete_projection','zasp_discovery_issue_sensor_token','zasp_discovery_sensor_rotate','zasp_discovery_sensor_revoke','zasp_discovery_sensor_heartbeat','zasp_discovery_create_runtime_batch','zasp_discovery_complete_runtime_stage','zasp_discovery_gateway_enroll','zasp_discovery_gateway_advance_replay','zasp_discovery_gateway_rotate','zasp_discovery_gateway_revoke','zasp_discovery_put_gateway_policy']))))
$$;

CREATE FUNCTION "public"."zasp_discovery_readiness"(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE AS $$
 WITH semantic_objects AS (
   SELECT 'table'::text object_kind,class.relname::text object_identity,jsonb_build_object('row_security',class.relrowsecurity,'force_row_security',class.relforcerowsecurity,'persistence',class.relpersistence) definition FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p')
   UNION ALL SELECT 'column',class.relname||'.'||attribute.attnum||'.'||attribute.attname,jsonb_build_object('type',format_type(attribute.atttypid,attribute.atttypmod),'not_null',attribute.attnotnull,'default',COALESCE(regexp_replace(pg_get_expr(default_value.adbin,default_value.adrelid,true),E'\\s+',' ','g'),''),'identity',attribute.attidentity,'generated',attribute.attgenerated,'collation',CASE WHEN attribute.attcollation=0 THEN '' ELSE attribute.attcollation::regcollation::text END) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p') AND attribute.attnum>0 AND NOT attribute.attisdropped
   UNION ALL SELECT 'constraint',class.relname||'.'||constraint_value.conname,jsonb_build_object('type',constraint_value.contype,'definition',regexp_replace(pg_get_constraintdef(constraint_value.oid,true),E'\\s+',' ','g'),'deferrable',constraint_value.condeferrable,'deferred',constraint_value.condeferred,'validated',constraint_value.convalidated) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_'
   UNION ALL SELECT 'index',table_class.relname||'.'||index_class.relname,jsonb_build_object('definition',regexp_replace(pg_get_indexdef(index_value.indexrelid,0,true),E'\\s+',' ','g'),'unique',index_value.indisunique,'primary',index_value.indisprimary,'exclusion',index_value.indisexclusion,'valid',index_value.indisvalid,'ready',index_value.indisready) FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace namespace ON namespace.oid=table_class.relnamespace WHERE namespace.nspname='public' AND left(table_class.relname,5)='zasp_'
   UNION ALL SELECT 'function',procedure.proname||'('||pg_get_function_identity_arguments(procedure.oid)||')',jsonb_build_object('result',pg_get_function_result(procedure.oid),'language',language.lanname,'kind',procedure.prokind,'volatility',procedure.provolatile,'strict',procedure.proisstrict,'security_definer',procedure.prosecdef,'leakproof',procedure.proleakproof,'parallel',procedure.proparallel,'config',COALESCE(to_jsonb(procedure.proconfig),'[]'::jsonb),'body',regexp_replace(btrim(procedure.prosrc),E'\\s+',' ','g')) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_language language ON language.oid=procedure.prolang WHERE namespace.nspname='public' AND left(procedure.proname,5)='zasp_'
 ), live AS (SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(object_kind,object_identity,definition) ORDER BY object_kind,object_identity)::text,'[]'),'UTF8'),'sha256'),'hex') value FROM semantic_objects)
 SELECT EXISTS(SELECT 1 FROM zasp_schema_versions v JOIN zasp_schema_metadata m ON m.key='production_core_schema' AND m.value='production-discovery-v1' JOIN zasp_schema_metadata fingerprint ON fingerprint.key='production_discovery_fingerprint' AND fingerprint.value=expected_fingerprint CROSS JOIN live
 WHERE v.version=10 AND v.name='production_discovery' AND v.checksum=expected_checksum AND live.value=expected_fingerprint
 AND zasp_discovery_security_ready()
 AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions newer WHERE newer.version>10))
$$;

DO $roles$
DECLARE role_name text; unsafe boolean;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['zasp_discovery_authority','zasp_discovery_api','zasp_discovery_worker'] LOOP
    IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',role_name);
    ELSE
      SELECT rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolbypassrls INTO unsafe FROM pg_roles WHERE rolname=role_name;
      IF unsafe THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe pre-provisioned discovery role'; END IF;
    END IF;
  END LOOP;
END $roles$;
GRANT zasp_discovery_authority TO CURRENT_USER WITH ADMIN OPTION;
GRANT USAGE ON SCHEMA public TO zasp_discovery_api,zasp_discovery_worker;
GRANT SELECT ON zasp_schema_versions,zasp_schema_metadata TO zasp_discovery_authority,zasp_discovery_api,zasp_discovery_worker;

DO $rls$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['zasp_integrations','zasp_integration_connections','zasp_discovery_schedules','zasp_discovery_syncs','zasp_discovery_jobs','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_evidence','zasp_sensors','zasp_sensor_tokens','zasp_sensor_heartbeats','zasp_runtime_batches','zasp_runtime_stages','zasp_discovery_outbox','zasp_projection_work','zasp_gateway_devices','zasp_gateway_enrollment_tokens','zasp_gateway_credentials','zasp_gateway_policy_subscriptions'] LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',table_name);
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker',table_name);
    EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO zasp_discovery_authority',table_name);
    EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING (true) WITH CHECK (true)',table_name||'_authority',table_name);
  END LOOP;
END $rls$;

DO $authority$
DECLARE procedure_oid oid;
BEGIN
  FOR procedure_oid IN SELECT procedure.oid FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_discovery_%' LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, public',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);
  END LOOP;
END $authority$;

GRANT EXECUTE ON FUNCTION zasp_discovery_readiness(text,text),zasp_discovery_create_integration(text,text,text,text,text,text,text,jsonb,text),zasp_discovery_transition_integration(text,text,text,text,bigint,text),zasp_discovery_put_connection(text,text,text,text,text,text,text),zasp_discovery_transition_connection(text,text,text,text,text,bigint,text),zasp_discovery_put_schedule(text,text,text,text,text,integer,timestamptz,bigint),zasp_discovery_transition_schedule(text,text,text,text,bigint,text),zasp_discovery_create_sensor(text,text,text,text,text,text),zasp_discovery_transition_sensor(text,text,text,text,bigint,text),zasp_discovery_create_gateway_device(text,text,text,text,text),zasp_discovery_transition_gateway_device(text,text,text,text,bigint,text),zasp_discovery_issue_gateway_enrollment(text,text,text,text,text,bytea,bytea,timestamptz),zasp_discovery_revoke_gateway_enrollment(text,text,text,text,text),zasp_discovery_request_sync(text,text,text,text,text,text,text,text,text,bytea,text,text,text),zasp_discovery_entity_page(text,text,text,text,integer),zasp_discovery_evidence_get(text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_discovery_readiness(text,text),zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb),zasp_discovery_claim_outbox(text,text,integer,integer),zasp_discovery_claim_jobs(text,text,integer,integer,text),zasp_discovery_claim_schedules(text,text,integer,integer),zasp_discovery_complete_schedule(text,text,text,text,text,text,text,timestamptz),zasp_discovery_claim_projection_work(text,text,integer,integer),zasp_discovery_finish_job(text,text,text,text,text,text,text,bytea,text,integer),zasp_discovery_finish_projection(text,text,text,text,text,text,text,text,text,text,integer),zasp_discovery_ack_outbox(text,text,text,text,text,text,text),zasp_discovery_retry_outbox(text,text,text,text,text,text,integer,text),zasp_discovery_complete_job(text,text,text,text,text,text,bytea,boolean,text),zasp_discovery_complete_projection(text,text,text,text,text,text,text,text,boolean),zasp_discovery_issue_sensor_token(text,text,text,text,text,bytea,bytea,timestamptz),zasp_discovery_sensor_rotate(text,text,text,text,text,text,bytea,bytea,timestamptz),zasp_discovery_sensor_revoke(text,text,text,text,text),zasp_discovery_sensor_heartbeat(text,text,text,text,bigint,text,bigint,jsonb),zasp_discovery_create_runtime_batch(text,text,text,text,text,text,text,text,bytea,integer,text,bigint,text,text),zasp_discovery_complete_runtime_stage(text,text,text,text,text,bytea,boolean,text),zasp_discovery_gateway_enroll(text,text,text,text,text,text,bytea,text,text,bytea,timestamptz),zasp_discovery_gateway_advance_replay(text,text,text,text,bigint,bigint),zasp_discovery_gateway_rotate(text,text,text,text,text,text,text,bytea,timestamptz),zasp_discovery_gateway_revoke(text,text,text,text,text),zasp_discovery_put_gateway_policy(text,text,text,text,text,bigint,bytea,bytea,timestamptz,timestamptz,bigint) TO zasp_discovery_worker;

DO $migration$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'production-risk-projection-v1','production-discovery-v1'); definition:=replace(definition,'release."version" = 9','release."version" = 10');
 definition:=replace(definition,'release."name" = ''production_risk_projection''','release."name" = ''production_discovery'''); definition:=replace(definition,'later_release."version" > 9','later_release."version" > 10'); EXECUTE definition;
END $migration$;

INSERT INTO zasp_schema_metadata(key,value) VALUES ('production_discovery_fingerprint', '02101a20c0c57dfd36212416f24fb057379162994641295727c0d8438478a75b');
UPDATE zasp_schema_metadata SET value='production-discovery-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='production-risk-projection-v1';
