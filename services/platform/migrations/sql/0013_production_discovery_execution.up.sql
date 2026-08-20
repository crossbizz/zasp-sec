DO $release_guard$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM zasp_schema_versions release
    JOIN zasp_schema_metadata marker ON marker.key='production_core_schema' AND marker.value='reference-authorization-v1'
    WHERE release.version=12 AND release.name='reference_authorization'
      AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions later WHERE later.version>12)
  ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='reference authorization release required'; END IF;
END $release_guard$;

DO $roles$ DECLARE role_name text;role_value record;created_role boolean;marker_prefix text:=format('zasp-managed:production-discovery-execution-v1:database:%s:',(SELECT oid FROM pg_database WHERE datname=current_database()));BEGIN
  FOREACH role_name IN ARRAY ARRAY['zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker'] LOOP
    created_role:=NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=role_name);
    IF created_role THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',role_name);
    END IF;
    SELECT r.oid,r.rolcanlogin,r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolinherit,r.rolbypassrls,shobj_description(r.oid,'pg_authid') AS marker INTO STRICT role_value FROM pg_roles r WHERE r.rolname=role_name;
    IF role_value.rolcanlogin OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR role_value.rolinherit OR role_value.rolbypassrls
       OR role_value.marker IS NOT NULL AND role_value.marker NOT IN(marker_prefix||'created',marker_prefix||'bound')
       OR EXISTS(SELECT 1 FROM pg_auth_members membership WHERE membership.roleid=role_value.oid OR membership.member=role_value.oid)
       OR EXISTS(SELECT 1 FROM pg_class object WHERE object.relowner=role_value.oid OR EXISTS(SELECT 1 FROM aclexplode(object.relacl) acl WHERE acl.grantee=role_value.oid))
       OR EXISTS(SELECT 1 FROM pg_proc object WHERE object.proowner=role_value.oid OR EXISTS(SELECT 1 FROM aclexplode(object.proacl) acl WHERE acl.grantee=role_value.oid))
    THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe pre-existing execution role';
    END IF;
    EXECUTE format('COMMENT ON ROLE %I IS %L',role_name,marker_prefix||CASE WHEN created_role OR role_value.marker=marker_prefix||'created' THEN 'created' ELSE 'bound' END);
  END LOOP;
  GRANT zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker TO zasp_discovery_authority WITH ADMIN OPTION;
END $roles$;

CREATE FUNCTION public.zasp_execution_subject_valid(provider_value text,kind_value text,id_value text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE provider_value
  WHEN 'aws' THEN kind_value='aws_account' AND id_value ~ '^[0-9]{12}$'
  WHEN 'kubernetes' THEN kind_value='kubernetes_cluster' AND id_value ~ '^[a-z0-9][a-z0-9.-]{0,252}/[a-z0-9][a-z0-9._-]{0,127}$' AND id_value NOT LIKE '%..%'
  WHEN 'github' THEN kind_value='github_installation' AND id_value ~ '^[1-9][0-9]{0,15}$' AND id_value::numeric<=9007199254740992
  WHEN 'okta' THEN kind_value='okta_tenant' AND id_value ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.okta\.com$'
  ELSE false END
$$;

CREATE TABLE public.zasp_discovery_execution_principals (
  principal_name text NOT NULL CHECK(principal_name ~ '^[a-z][a-z0-9_]{2,62}$'),
  authority_role text NOT NULL CHECK(authority_role IN ('zasp_discovery_scheduler','zasp_discovery_worker','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker')),
  registered_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(principal_name), UNIQUE(authority_role)
);

ALTER TABLE public.zasp_integration_connections ADD CONSTRAINT zasp_execution_connections_parent_unique
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,id);

ALTER TABLE public.zasp_discovery_syncs ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK(version>0);
ALTER TABLE public.zasp_discovery_syncs ADD COLUMN last_error_code text CHECK(last_error_code IS NULL OR last_error_code IN('retryable','rate_limited','denied','revoked','malformed','partial','terminal','cancelled','outcome_unknown'));

ALTER TABLE public.zasp_workflow_receipts DROP CONSTRAINT zasp_workflow_receipts_resource_kind_check;
ALTER TABLE public.zasp_workflow_receipts ADD CONSTRAINT zasp_workflow_receipts_resource_kind_check
  CHECK(resource_kind IN('policy','integration','sensor','security_agent','security_agent_run','security_agent_approval','finding','integration_sync','integration_schedule'));

CREATE FUNCTION public.zasp_execution_sync_version_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF (to_jsonb(NEW)-'version') IS DISTINCT FROM (to_jsonb(OLD)-'version') THEN NEW.version:=OLD.version+1;ELSE NEW.version:=OLD.version;END IF;RETURN NEW;END $$;
CREATE TRIGGER zasp_execution_sync_version BEFORE UPDATE ON public.zasp_discovery_syncs FOR EACH ROW EXECUTE FUNCTION zasp_execution_sync_version_trigger();

CREATE TABLE public.zasp_discovery_connection_subjects (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  integration_id text NOT NULL, connection_id text NOT NULL, provider text NOT NULL CHECK(provider IN ('aws','kubernetes','github','okta')),
  subject_kind text NOT NULL CHECK(subject_kind IN ('aws_account','kubernetes_cluster','github_installation','okta_tenant')),
  subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 384), connection_version bigint NOT NULL CHECK(connection_version>0),
  configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32),
  source text NOT NULL CHECK(source IN ('upgrade','oauth','reference')), verified_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,integration_id,connection_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,connection_id)
    REFERENCES zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id) ON DELETE CASCADE
);

CREATE TABLE public.zasp_discovery_execution_quotas (
  organization_id text PRIMARY KEY CHECK(zasp_valid_product_id(organization_id)),
  max_active_jobs integer NOT NULL CHECK(max_active_jobs BETWEEN 1 AND 64), version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.zasp_discovery_generation_reservations (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  sync_id text NOT NULL, integration_id text NOT NULL, source text NOT NULL CHECK(source IN ('aws','kubernetes','github','okta')),
  generation bigint NOT NULL CHECK(generation>0), snapshot_id text NOT NULL CHECK(zasp_valid_product_id(snapshot_id)),
  reserved_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,sync_id),
  UNIQUE(organization_id,workspace_id,environment_id,snapshot_id),
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,source,generation),
  FOREIGN KEY(organization_id,workspace_id,environment_id,sync_id) REFERENCES zasp_discovery_syncs(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE
);

CREATE TABLE public.zasp_discovery_job_authorities (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  job_id text NOT NULL, sync_id text NOT NULL, integration_id text NOT NULL, connection_id text NOT NULL,
  provider text NOT NULL CHECK(provider IN ('aws','kubernetes','github','okta')),
  integration_version bigint NOT NULL CHECK(integration_version>0), connection_version bigint NOT NULL CHECK(connection_version>0),
  configuration jsonb NOT NULL CHECK(jsonb_typeof(configuration)='object'), configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32),
  subject_kind text NOT NULL, subject_id text NOT NULL, request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,job_id),
  UNIQUE(organization_id,workspace_id,environment_id,job_id,sync_id),
  UNIQUE(organization_id,workspace_id,environment_id,sync_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,job_id) REFERENCES zasp_discovery_jobs(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
  FOREIGN KEY(organization_id,workspace_id,environment_id,sync_id) REFERENCES zasp_discovery_syncs(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,connection_id) REFERENCES zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id),
  CHECK(zasp_execution_subject_valid(provider,subject_kind,subject_id))
);

CREATE TABLE public.zasp_discovery_job_checkpoints (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  job_id text NOT NULL, sync_id text NOT NULL, integration_id text NOT NULL,
  provider text NOT NULL CHECK(provider IN ('aws','kubernetes','github','okta')),
  version bigint NOT NULL CHECK(version BETWEEN 1 AND 10000),
  cursor_version text NOT NULL CHECK(cursor_version ~ '^[a-z][a-z0-9_.-]{1,63}$'),
  cursor_value text NOT NULL CHECK(length(cursor_value) BETWEEN 1 AND 2048),
  manifest_reference text NOT NULL CHECK(zasp_discovery_s3_object_reference(manifest_reference)),
  manifest_key text NOT NULL CHECK(length(manifest_key) BETWEEN 32 AND 1024),
  manifest_version_id text NOT NULL CHECK(length(manifest_version_id) BETWEEN 1 AND 1024),
  manifest_checksum bytea NOT NULL CHECK(octet_length(manifest_checksum)=32),
  manifest_size_bytes bigint NOT NULL CHECK(manifest_size_bytes BETWEEN 1 AND 536870912),
  manifest_media_type text NOT NULL CHECK(manifest_media_type='application/json'),
  manifest_schema_version text NOT NULL CHECK(manifest_schema_version ~ '^[a-z][a-z0-9_.-]{1,63}$'),
  parser_version text NOT NULL CHECK(parser_version ~ '^[a-z][a-z0-9_.-]{1,63}$'),
  tool_version text NOT NULL CHECK(tool_version ~ '^[a-z][a-z0-9_.-]{1,63}$'),
  checkpoint_digest bytea NOT NULL CHECK(octet_length(checkpoint_digest)=32),
  checkpoint_result jsonb NOT NULL CHECK(jsonb_typeof(checkpoint_result)='object'),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,job_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,job_id)
    REFERENCES zasp_discovery_jobs(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
  FOREIGN KEY(organization_id,workspace_id,environment_id,job_id,sync_id)
    REFERENCES zasp_discovery_job_authorities(organization_id,workspace_id,environment_id,job_id,sync_id) ON DELETE CASCADE
);

CREATE TABLE public.zasp_discovery_upgrade_transitions (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, integration_id text NOT NULL,
  prior_integration_state text NOT NULL, prior_integration_version bigint NOT NULL, prior_integration_updated_at timestamptz NOT NULL,
  connection_id text NOT NULL, prior_connection_state text NOT NULL, prior_connection_version bigint NOT NULL, prior_connection_verified_at timestamptz, prior_connection_updated_at timestamptz NOT NULL,
  prior_workflow_body jsonb NOT NULL, prior_workflow_version bigint NOT NULL, prior_workflow_updated_at timestamptz NOT NULL,
  audit_id text NOT NULL, correlation_id text NOT NULL, transitioned_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,integration_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,connection_id) REFERENCES zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id)
);

CREATE TABLE public.zasp_discovery_snapshot_inputs (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  snapshot_id text NOT NULL, integration_id text NOT NULL, source text NOT NULL CHECK(source IN ('aws','kubernetes','github','okta')),
  generation bigint NOT NULL CHECK(generation>0), candidate_digest bytea NOT NULL CHECK(octet_length(candidate_digest)=32),
  manifest_reference text NOT NULL CHECK(zasp_discovery_s3_object_reference(manifest_reference)),
  manifest_key text NOT NULL CHECK(length(manifest_key) BETWEEN 32 AND 1024), manifest_version_id text NOT NULL CHECK(length(manifest_version_id) BETWEEN 1 AND 1024),
  manifest_checksum bytea NOT NULL CHECK(octet_length(manifest_checksum)=32), manifest_size_bytes bigint NOT NULL CHECK(manifest_size_bytes BETWEEN 1 AND 536870912),
  manifest_media_type text NOT NULL CHECK(length(manifest_media_type) BETWEEN 1 AND 128), manifest_schema_version text NOT NULL CHECK(length(manifest_schema_version) BETWEEN 1 AND 64),
  parser_version text NOT NULL CHECK(length(parser_version) BETWEEN 1 AND 64), tool_version text NOT NULL CHECK(length(tool_version) BETWEEN 1 AND 64),
  entities jsonb NOT NULL CHECK(jsonb_typeof(entities)='array' AND octet_length(entities::text)<=67108864),
  relationships jsonb NOT NULL CHECK(jsonb_typeof(relationships)='array' AND octet_length(relationships::text)<=67108864),
  evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='array' AND octet_length(evidence::text)<=67108864),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,snapshot_id),
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id),
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,source,generation),
  FOREIGN KEY(organization_id,workspace_id,environment_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,integration_id,source,id) ON DELETE CASCADE
);

CREATE TABLE public.zasp_discovery_snapshot_projection_items (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  snapshot_id text NOT NULL, integration_id text NOT NULL, source text NOT NULL,
  section text NOT NULL CHECK(section IN ('entities','relationships','evidence')), item_id text NOT NULL CHECK(zasp_valid_product_id(item_id)), payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=1048576 AND payload->>'id'=item_id),
  PRIMARY KEY(organization_id,workspace_id,environment_id,snapshot_id,section,item_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id) REFERENCES zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id) ON DELETE CASCADE
);

CREATE TABLE public.zasp_discovery_projection_cursors (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  integration_id text NOT NULL, source text NOT NULL CHECK(source IN ('aws','kubernetes','github','okta')),
  kind text NOT NULL CHECK(kind IN ('risk','graph','search')), generation bigint NOT NULL CHECK(generation>0), snapshot_id text NOT NULL,
  input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,integration_id,source,kind),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id) REFERENCES zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id)
);

CREATE TABLE public.zasp_discovery_schedule_runs (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  schedule_id text NOT NULL, sync_id text NOT NULL, job_id text NOT NULL, lease_owner text NOT NULL, lease_token text NOT NULL,
  request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32), scheduled_for timestamptz NOT NULL, completed_at timestamptz,
  PRIMARY KEY(organization_id,workspace_id,environment_id,schedule_id,sync_id),
  UNIQUE(organization_id,workspace_id,environment_id,schedule_id,lease_token),
  FOREIGN KEY(organization_id,workspace_id,environment_id,schedule_id) REFERENCES zasp_discovery_schedules(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
  FOREIGN KEY(organization_id,workspace_id,environment_id,sync_id) REFERENCES zasp_discovery_syncs(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
  FOREIGN KEY(organization_id,workspace_id,environment_id,job_id) REFERENCES zasp_discovery_jobs(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE
);

CREATE TABLE public.zasp_discovery_projection_receipts (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  snapshot_id text NOT NULL, kind text NOT NULL CHECK(kind IN('risk','graph','search')), version text NOT NULL,
  integration_id text NOT NULL, source text NOT NULL, generation bigint NOT NULL CHECK(generation>0), input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
  driver_receipt text NOT NULL CHECK(length(driver_receipt) BETWEEN 16 AND 512), driver_digest bytea NOT NULL CHECK(octet_length(driver_digest)=32), completed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,snapshot_id,kind,version),
  FOREIGN KEY(organization_id,workspace_id,environment_id,snapshot_id,kind,version) REFERENCES zasp_projection_work(organization_id,workspace_id,environment_id,snapshot_id,kind,version) ON DELETE CASCADE,
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id) REFERENCES zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id) ON DELETE CASCADE
);

CREATE TABLE public.zasp_discovery_freshness_versions (
  organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,integration_id text NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,integration_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE
);

CREATE TABLE public.zasp_discovery_outbox_topic_fairness (
  topic text PRIMARY KEY CHECK(topic='discovery-jobs'),
  last_organization_id text CHECK(last_organization_id IS NULL OR zasp_valid_product_id(last_organization_id)),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE INDEX zasp_execution_jobs_claim_idx ON zasp_discovery_jobs(organization_id,available_at,created_at,id)
  WHERE kind='discovery' AND state IN ('queued','retryable','leased') AND attempt<5;
CREATE INDEX zasp_execution_jobs_lease_idx ON zasp_discovery_jobs(organization_id,lease_expires_at,id) WHERE kind='discovery' AND state='leased';
CREATE INDEX zasp_execution_schedules_claim_idx ON zasp_discovery_schedules(next_run_at,organization_id,id) WHERE state='enabled';
CREATE INDEX zasp_execution_schedules_lease_idx ON zasp_discovery_schedules(lease_expires_at,organization_id,id) WHERE state='enabled' AND lease_expires_at IS NOT NULL;
CREATE INDEX zasp_execution_projection_claim_idx ON zasp_projection_work(available_at,organization_id,snapshot_id,kind,version) WHERE state IN('pending','retryable','leased') AND attempt<5;
CREATE INDEX zasp_execution_outbox_topic_claim_idx ON zasp_discovery_outbox(topic,available_at,organization_id,created_at,id) WHERE state IN('pending','failed','leased') AND attempt<100;
CREATE INDEX zasp_execution_outbox_topic_live_org_idx ON zasp_discovery_outbox(topic,organization_id,lease_expires_at,id) WHERE state='leased';
CREATE INDEX zasp_execution_projection_lease_idx ON zasp_projection_work(lease_expires_at,organization_id,snapshot_id,kind,version) WHERE state='leased' AND lease_expires_at IS NOT NULL;
CREATE INDEX zasp_execution_snapshot_projection_idx ON zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,integration_id,source,generation,snapshot_id);
CREATE INDEX zasp_execution_sync_history_idx ON zasp_discovery_syncs(organization_id,workspace_id,environment_id,integration_id,requested_at DESC,id DESC);

DO $rls$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness'] LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',table_name);
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway',table_name);
    EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO zasp_discovery_authority',table_name);
    EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING (true) WITH CHECK (true)',table_name||'_authority',table_name);
  END LOOP;
END $rls$;

CREATE FUNCTION public.zasp_execution_bind_connection_subject(
  organization_value text,workspace_value text,environment_value text,integration_value text,connection_value text,
  provider_value text,kind_value text,id_value text,expected_connection_version bigint,configuration_value jsonb,source_value text
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE connection_row zasp_integration_connections%ROWTYPE;integration_row zasp_integrations%ROWTYPE;digest_value bytea;subject_row zasp_discovery_connection_subjects%ROWTYPE;
BEGIN
  IF NOT zasp_execution_subject_valid(provider_value,kind_value,id_value) OR source_value NOT IN('upgrade','oauth','reference') OR jsonb_typeof(configuration_value)<>'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid connection subject'; END IF;
  SELECT * INTO integration_row FROM zasp_integrations WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=integration_value FOR UPDATE;
  SELECT * INTO connection_row FROM zasp_integration_connections WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND integration_id=integration_value AND id=connection_value FOR UPDATE;
  digest_value:=digest(convert_to(configuration_value::text,'UTF8'),'sha256');
  IF NOT FOUND OR integration_row.id IS NULL OR integration_row.kind<>provider_value OR integration_row.configuration<>configuration_value OR integration_row.state NOT IN('active','degraded') OR connection_row.provider<>provider_value OR connection_row.state<>'verified' OR connection_row.version<>expected_connection_version THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connection subject intent changed'; END IF;
  INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source)
  VALUES(organization_value,workspace_value,environment_value,integration_value,connection_value,provider_value,kind_value,id_value,expected_connection_version,digest_value,source_value)
  ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,connection_id) DO UPDATE SET subject_kind=excluded.subject_kind,subject_id=excluded.subject_id,connection_version=excluded.connection_version,configuration_digest=excluded.configuration_digest,source=excluded.source,verified_at=transaction_timestamp()
  WHERE zasp_discovery_connection_subjects.provider=excluded.provider AND zasp_discovery_connection_subjects.connection_version<excluded.connection_version;
  SELECT * INTO subject_row FROM zasp_discovery_connection_subjects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND integration_id=integration_value AND connection_id=connection_value;
  IF subject_row.provider<>provider_value OR subject_row.subject_kind<>kind_value OR subject_row.subject_id<>id_value OR subject_row.connection_version<>expected_connection_version OR subject_row.configuration_digest<>digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connection subject conflict'; END IF;
  RETURN jsonb_build_object('integration_id',integration_value,'connection_id',connection_value,'provider',provider_value,'subject_kind',kind_value,'subject_id',id_value,'connection_version',expected_connection_version,'verified_at',subject_row.verified_at);
END $$;

CREATE FUNCTION public.zasp_execution_bump_freshness(organization_value text,workspace_value text,environment_value text,integration_value text) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE version_value bigint;
BEGIN
 INSERT INTO zasp_discovery_freshness_versions(organization_id,workspace_id,environment_id,integration_id,version)
 VALUES(organization_value,workspace_value,environment_value,integration_value,1)
 ON CONFLICT(organization_id,workspace_id,environment_id,integration_id) DO UPDATE SET version=zasp_discovery_freshness_versions.version+1,updated_at=transaction_timestamp()
 RETURNING version INTO version_value;
 RETURN version_value;
END $$;

CREATE FUNCTION public.zasp_execution_sync_body(organization_value text,workspace_value text,environment_value text,integration_value text,sync_value text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE response jsonb;
BEGIN
 SELECT jsonb_build_object(
   'id',sync.id,'integration_id',sync.integration_id,'trigger_kind',sync.trigger_kind,'status',sync.state,'attempt',sync.attempt,
   'requested_at',to_char(sync.requested_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
   'started_at',CASE WHEN sync.started_at IS NULL THEN NULL ELSE to_char(sync.started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,
   'completed_at',CASE WHEN sync.completed_at IS NULL THEN NULL ELSE to_char(sync.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,
   'discovered_count',sync.discovered_count,'changed_count',sync.changed_count,'removed_count',sync.removed_count,'snapshot_id',sync.snapshot_id,
   'last_error_code',sync.last_error_code,
   'retry_at',CASE WHEN sync.state='queued' AND sync.attempt>0 THEN (SELECT to_char(job.available_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') FROM zasp_discovery_jobs job WHERE (job.organization_id,job.workspace_id,job.environment_id,job.kind,job.authority_id)=(sync.organization_id,sync.workspace_id,sync.environment_id,'discovery',sync.id)) ELSE NULL END
 ) INTO response
 FROM zasp_discovery_syncs sync
 WHERE (sync.organization_id,sync.workspace_id,sync.environment_id,sync.integration_id,sync.id)=(organization_value,workspace_value,environment_value,integration_value,sync_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sync missing';END IF;
 RETURN response;
END $$;

CREATE FUNCTION public.zasp_execution_sync_detail(organization_value text,workspace_value text,environment_value text,integration_value text,sync_value text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE body_value jsonb;version_value bigint;
BEGIN
 body_value:=zasp_execution_sync_body(organization_value,workspace_value,environment_value,integration_value,sync_value);
 SELECT version INTO STRICT version_value FROM zasp_discovery_syncs WHERE (organization_id,workspace_id,environment_id,integration_id,id)=(organization_value,workspace_value,environment_value,integration_value,sync_value);
 RETURN jsonb_build_object('body',body_value,'version',version_value);
END $$;

CREATE FUNCTION public.zasp_execution_sync_history(organization_value text,workspace_value text,environment_value text,integration_value text,before_requested_value timestamptz,before_id_value text,page_limit integer) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE response jsonb;BEGIN IF page_limit NOT BETWEEN 1 AND 100 OR (before_requested_value IS NULL)<>(before_id_value IS NULL) OR before_id_value IS NOT NULL AND NOT zasp_valid_product_id(before_id_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid sync history cursor';END IF;IF NOT EXISTS(SELECT 1 FROM zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,integration_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration missing';END IF;WITH source AS (SELECT sync.* FROM zasp_discovery_syncs sync WHERE (sync.organization_id,sync.workspace_id,sync.environment_id,sync.integration_id)=(organization_value,workspace_value,environment_value,integration_value) AND (before_requested_value IS NULL OR (sync.requested_at,sync.id)<(before_requested_value,before_id_value)) ORDER BY sync.requested_at DESC,sync.id DESC LIMIT page_limit+1),visible AS (SELECT * FROM source ORDER BY requested_at DESC,id DESC LIMIT page_limit) SELECT jsonb_build_object('items',COALESCE(jsonb_agg(zasp_execution_sync_body(organization_value,workspace_value,environment_value,integration_value,id) ORDER BY requested_at DESC,id DESC),'[]'::jsonb),'next_requested_at',CASE WHEN (SELECT count(*) FROM source)>page_limit THEN to_char((SELECT requested_at FROM visible ORDER BY requested_at,id LIMIT 1) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') ELSE NULL END,'next_id',CASE WHEN (SELECT count(*) FROM source)>page_limit THEN (SELECT id FROM visible ORDER BY requested_at,id LIMIT 1) ELSE NULL END) INTO response FROM visible;RETURN response;END $$;

CREATE FUNCTION public.zasp_execution_schedule_body(organization_value text,workspace_value text,environment_value text,integration_value text,include_deleted boolean) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE response jsonb;BEGIN SELECT jsonb_build_object('integration_id',schedule.integration_id,'cadence_seconds',schedule.cadence_seconds,'state',schedule.state,'time_zone',schedule.time_zone,'next_run_at',CASE WHEN schedule.state='enabled' THEN to_char(schedule.next_run_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') ELSE NULL END,'version',schedule.version,'created_at',to_char(schedule.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'updated_at',to_char(schedule.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) INTO response FROM zasp_discovery_schedules schedule WHERE (schedule.organization_id,schedule.workspace_id,schedule.environment_id,schedule.integration_id)=(organization_value,workspace_value,environment_value,integration_value) AND (include_deleted OR schedule.state<>'deleted');IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule missing';END IF;RETURN response;END $$;

CREATE FUNCTION public.zasp_execution_schedule_detail(organization_value text,workspace_value text,environment_value text,integration_value text) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT zasp_execution_schedule_body(organization_value,workspace_value,environment_value,integration_value,false)
$$;

CREATE FUNCTION public.zasp_execution_last_good_freshness(organization_value text,workspace_value text,environment_value text,integration_value text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE snapshot_row zasp_discovery_snapshots%ROWTYPE;input_row zasp_discovery_snapshot_inputs%ROWTYPE;latest_sync jsonb;last_good jsonb;projection_value jsonb;version_row zasp_discovery_freshness_versions%ROWTYPE;updated_value timestamptz;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,integration_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration missing';END IF;
 SELECT * INTO version_row FROM zasp_discovery_freshness_versions WHERE (organization_id,workspace_id,environment_id,integration_id)=(organization_value,workspace_value,environment_value,integration_value);
 SELECT * INTO snapshot_row FROM zasp_discovery_snapshots WHERE (organization_id,workspace_id,environment_id,integration_id,is_last_good,state,complete)=(organization_value,workspace_value,environment_value,integration_value,true,'complete',true) ORDER BY generation DESC,id DESC LIMIT 1;
 IF FOUND THEN
   SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,integration_id,source,snapshot_id)=(organization_value,workspace_value,environment_value,integration_value,snapshot_row.source,snapshot_row.id);
   last_good:=jsonb_build_object('snapshot_id',snapshot_row.id,'collected_at',to_char(snapshot_row.collected_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'discovered_count',COALESCE((snapshot_row.apply_result->>'discovered_count')::integer,0),'changed_count',COALESCE((snapshot_row.apply_result->>'changed_count')::integer,0),'removed_count',COALESCE((snapshot_row.apply_result->>'removed_count')::integer,0));
 ELSE last_good:=NULL;END IF;
 SELECT zasp_execution_sync_body(organization_value,workspace_value,environment_value,integration_value,id) INTO latest_sync FROM zasp_discovery_syncs WHERE (organization_id,workspace_id,environment_id,integration_id)=(organization_value,workspace_value,environment_value,integration_value) ORDER BY requested_at DESC,id DESC LIMIT 1;
 SELECT jsonb_object_agg(required.kind,jsonb_build_object(
   'state',CASE WHEN input_row.snapshot_id IS NULL OR work.state IS NULL THEN 'unavailable' WHEN work.state='succeeded' AND cursor.snapshot_id=input_row.snapshot_id AND cursor.generation=input_row.generation AND cursor.input_digest=input_row.candidate_digest THEN 'current' WHEN work.state IN('pending','retryable','leased') THEN 'pending' ELSE 'degraded' END,
   'snapshot_id',CASE WHEN input_row.snapshot_id IS NOT NULL AND work.state IS NOT NULL THEN input_row.snapshot_id ELSE NULL END,
   'completed_at',CASE WHEN work.state='succeeded' AND cursor.snapshot_id=input_row.snapshot_id AND cursor.generation=input_row.generation AND cursor.input_digest=input_row.candidate_digest THEN to_char(receipt.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') WHEN work.state IN('failed','cancelled') THEN to_char(work.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') ELSE NULL END,
   'last_error_code',CASE WHEN work.state='retryable' THEN 'retryable' WHEN work.state='failed' THEN 'terminal' WHEN work.state='cancelled' THEN 'cancelled' WHEN work.state='succeeded' THEN 'outcome_unknown' ELSE NULL END
 ) ORDER BY required.kind) INTO projection_value
 FROM unnest(ARRAY['risk','graph','search']) required(kind)
 LEFT JOIN zasp_projection_work work ON input_row.snapshot_id IS NOT NULL AND (work.organization_id,work.workspace_id,work.environment_id,work.snapshot_id,work.kind)=(organization_value,workspace_value,environment_value,input_row.snapshot_id,required.kind)
 LEFT JOIN zasp_discovery_projection_cursors cursor ON (cursor.organization_id,cursor.workspace_id,cursor.environment_id,cursor.integration_id,cursor.source,cursor.kind)=(organization_value,workspace_value,environment_value,integration_value,input_row.source,required.kind)
 LEFT JOIN zasp_discovery_projection_receipts receipt ON (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.snapshot_id,receipt.kind,receipt.version)=(work.organization_id,work.workspace_id,work.environment_id,work.snapshot_id,work.kind,work.version);
 updated_value:=GREATEST(COALESCE(version_row.updated_at,'epoch'::timestamptz),COALESCE(snapshot_row.committed_at,'epoch'::timestamptz),COALESCE((SELECT max(requested_at) FROM zasp_discovery_syncs WHERE (organization_id,workspace_id,environment_id,integration_id)=(organization_value,workspace_value,environment_value,integration_value)),'epoch'::timestamptz));
 RETURN jsonb_build_object('integration_id',integration_value,'version',COALESCE(version_row.version,1),'last_good',last_good,'latest_sync',latest_sync,'projections',projection_value,'updated_at',to_char(updated_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $$;

CREATE FUNCTION public.zasp_execution_complete_reference_authorization(
  organization_value text,workspace_value text,environment_value text,principal_value text,
  integration_value text,provider_value text,connection_value text,reference_value text,
  idempotency_value text,expected_version_value bigint,configuration_value jsonb,intent_value jsonb,
  audit_value text,correlation_value text,receipt_value text,subject_kind_value text,subject_id_value text
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result_value jsonb;connection_version_value bigint;replay_value jsonb;
BEGIN
 replay_value:=zasp_workflow_replay(organization_value,workspace_value,environment_value,principal_value,'completeIntegrationReferenceAuthorization',idempotency_value,intent_value);
 IF (replay_value->>'found')::boolean THEN RETURN replay_value->'result';END IF;
 DELETE FROM zasp_discovery_connection_subjects subject
  WHERE (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id,subject.connection_id,subject.provider)=(organization_value,workspace_value,environment_value,integration_value,connection_value,provider_value)
    AND EXISTS(SELECT 1 FROM zasp_integrations integration JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id,connection.provider,connection.state)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,connection_value,provider_value,'verified') WHERE (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.kind,integration.version,integration.state)=(organization_value,workspace_value,environment_value,integration_value,provider_value,expected_version_value,'degraded'));
 UPDATE zasp_integration_connections connection SET state='pending',verified_at=NULL,updated_at=transaction_timestamp()
  WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id,connection.provider)=(organization_value,workspace_value,environment_value,integration_value,connection_value,provider_value)
    AND connection.state='verified' AND connection.version=expected_version_value
    AND EXISTS(SELECT 1 FROM zasp_integrations integration WHERE (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.kind,integration.version,integration.state)=(organization_value,workspace_value,environment_value,integration_value,provider_value,expected_version_value,'degraded'))
    AND NOT EXISTS(SELECT 1 FROM zasp_discovery_connection_subjects subject WHERE (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id,subject.connection_id)=(organization_value,workspace_value,environment_value,integration_value,connection_value));
 result_value:=zasp_complete_reference_authorization(organization_value,workspace_value,environment_value,principal_value,integration_value,provider_value,connection_value,reference_value,idempotency_value,expected_version_value,configuration_value,intent_value,audit_value,correlation_value,receipt_value);
 SELECT connection.version INTO STRICT connection_version_value FROM zasp_integration_connections connection
  WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id,connection.provider)=(organization_value,workspace_value,environment_value,integration_value,connection_value,provider_value);
 PERFORM zasp_execution_bind_connection_subject(organization_value,workspace_value,environment_value,integration_value,connection_value,provider_value,subject_kind_value,subject_id_value,connection_version_value,configuration_value,'reference');
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_execution_bind_oauth_subject_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE connection_row zasp_integration_connections%ROWTYPE;integration_row zasp_integrations%ROWTYPE;kind_value text;id_value text;existing_row zasp_discovery_connection_subjects%ROWTYPE;
BEGIN
 IF NEW.provider NOT IN('github','okta') THEN RETURN NEW;END IF;
 IF NEW.status<>'active' THEN
   DELETE FROM zasp_discovery_connection_subjects subject USING zasp_integration_connections connection
   WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider,connection.connection_reference)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.integration_id,NEW.provider,COALESCE(OLD.credential_reference,NEW.credential_reference))
     AND (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id,subject.connection_id)=(connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id);
   RETURN NEW;
 END IF;
 kind_value:=CASE NEW.provider WHEN 'github' THEN 'github_installation' ELSE 'okta_tenant' END;
 id_value:=CASE NEW.provider WHEN 'github' THEN NEW.metadata->>'installation_id' ELSE NEW.metadata->>'tenant' END;
 IF NOT zasp_execution_subject_valid(NEW.provider,kind_value,id_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid oauth connection subject';END IF;
 SELECT * INTO STRICT integration_row FROM zasp_integrations integration WHERE (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.kind)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.integration_id,NEW.provider) FOR UPDATE;
 SELECT * INTO STRICT connection_row FROM zasp_integration_connections connection WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider,connection.connection_reference,connection.state)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.integration_id,NEW.provider,NEW.credential_reference,'verified') FOR UPDATE;
 INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source)
 VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.integration_id,connection_row.id,NEW.provider,kind_value,id_value,connection_row.version,digest(convert_to(integration_row.configuration::text,'UTF8'),'sha256'),'oauth')
 ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,connection_id) DO UPDATE SET subject_kind=excluded.subject_kind,subject_id=excluded.subject_id,connection_version=excluded.connection_version,configuration_digest=excluded.configuration_digest,source=excluded.source,verified_at=transaction_timestamp()
 WHERE zasp_discovery_connection_subjects.provider=excluded.provider AND zasp_discovery_connection_subjects.connection_version<excluded.connection_version;
 SELECT * INTO STRICT existing_row FROM zasp_discovery_connection_subjects subject WHERE (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id,subject.connection_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.integration_id,connection_row.id);
 IF (existing_row.provider,existing_row.subject_kind,existing_row.subject_id,existing_row.connection_version,existing_row.configuration_digest)<>(NEW.provider,kind_value,id_value,connection_row.version,digest(convert_to(integration_row.configuration::text,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='oauth connection subject conflict';END IF;
 RETURN NEW;
END $$;

CREATE TRIGGER zasp_execution_bind_oauth_subject AFTER INSERT OR UPDATE OF status,metadata,credential_reference ON zasp_connector_credentials
FOR EACH ROW EXECUTE FUNCTION zasp_execution_bind_oauth_subject_trigger();

CREATE FUNCTION public.zasp_execution_register_principals(migration_principal text,scheduler_principal text,discovery_principal text,risk_principal text,graph_principal text,search_principal text) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE principals text[]:=ARRAY[scheduler_principal,discovery_principal,risk_principal,graph_principal,search_principal];authorities text[]:=ARRAY['zasp_discovery_scheduler','zasp_discovery_worker','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker'];index integer;role_value record;
BEGIN
 IF migration_principal<>session_user OR cardinality(ARRAY(SELECT DISTINCT unnest(ARRAY[migration_principal,scheduler_principal,discovery_principal,risk_principal,graph_principal,search_principal])))<>6 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution principals'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-execution-principal-registration',0));
 FOR index IN 1..5 LOOP
   SELECT r.oid,r.rolcanlogin,r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolinherit,r.rolbypassrls INTO role_value FROM pg_roles r WHERE r.rolname=principals[index];
   IF NOT FOUND OR NOT role_value.rolcanlogin OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR NOT role_value.rolinherit OR role_value.rolbypassrls THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe execution principal'; END IF;
   EXECUTE format('GRANT %I TO %I',authorities[index],principals[index]);
   INSERT INTO zasp_discovery_execution_principals(principal_name,authority_role) VALUES(principals[index],authorities[index]) ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role WHERE zasp_discovery_execution_principals.authority_role=excluded.authority_role;
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='execution principal conflict'; END IF;
 END LOOP;
 RETURN true;
END $$;

CREATE FUNCTION public.zasp_execution_principal_ready(expected_authority text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT expected_authority IN('zasp_discovery_scheduler','zasp_discovery_worker','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker')
 AND EXISTS(SELECT 1 FROM zasp_discovery_execution_principals p JOIN pg_roles r ON r.rolname=p.principal_name WHERE p.principal_name=session_user AND p.authority_role=expected_authority AND r.rolcanlogin AND r.rolinherit AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls)
 AND pg_has_role(session_user,expected_authority,'MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
$$;

CREATE FUNCTION public.zasp_execution_request_sync(organization_value text,workspace_value text,environment_value text,principal_value text,integration_value text,sync_value text,job_value text,outbox_value text,idempotency_value text,request_digest_value bytea,trigger_value text,parser_value text,tool_value text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE integration_row zasp_integrations%ROWTYPE;connection_row zasp_integration_connections%ROWTYPE;subject_row zasp_discovery_connection_subjects%ROWTYPE;result jsonb;authority_row zasp_discovery_job_authorities%ROWTYPE;actual_sync text;actual_job text;prior_sync boolean;
BEGIN
 IF NOT pg_has_role(session_user,'zasp_discovery_api','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_scheduler','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='sync authority denied';END IF;
 SELECT * INTO integration_row FROM zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,integration_value) AND state IN('active','degraded') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration missing';END IF;
 SELECT * INTO STRICT connection_row FROM zasp_integration_connections WHERE (organization_id,workspace_id,environment_id,integration_id,provider,state)=(organization_value,workspace_value,environment_value,integration_value,integration_row.kind,'verified') FOR SHARE;
 SELECT * INTO STRICT subject_row FROM zasp_discovery_connection_subjects WHERE (organization_id,workspace_id,environment_id,integration_id,connection_id,provider,connection_version,configuration_digest)=(organization_value,workspace_value,environment_value,integration_value,connection_row.id,integration_row.kind,connection_row.version,digest(convert_to(integration_row.configuration::text,'UTF8'),'sha256')) FOR SHARE;
 prior_sync:=EXISTS(SELECT 1 FROM zasp_discovery_syncs WHERE (organization_id,workspace_id,environment_id,integration_id,idempotency_key)=(organization_value,workspace_value,environment_value,integration_value,idempotency_value));
 result:=zasp_discovery_request_sync(organization_value,workspace_value,environment_value,principal_value,integration_value,sync_value,job_value,outbox_value,idempotency_value,request_digest_value,trigger_value,parser_value,tool_value);
 actual_sync:=result->>'sync_id';actual_job:=result->>'job_id';
 INSERT INTO zasp_discovery_job_authorities(organization_id,workspace_id,environment_id,job_id,sync_id,integration_id,connection_id,provider,integration_version,connection_version,configuration,configuration_digest,subject_kind,subject_id,request_digest)
 VALUES(organization_value,workspace_value,environment_value,actual_job,actual_sync,integration_value,connection_row.id,integration_row.kind,integration_row.version,connection_row.version,integration_row.configuration,digest(convert_to(integration_row.configuration::text,'UTF8'),'sha256'),subject_row.subject_kind,subject_row.subject_id,request_digest_value) ON CONFLICT(organization_id,workspace_id,environment_id,job_id) DO NOTHING;
 SELECT * INTO STRICT authority_row FROM zasp_discovery_job_authorities WHERE (organization_id,workspace_id,environment_id,job_id)=(organization_value,workspace_value,environment_value,actual_job);
 IF (authority_row.sync_id,authority_row.integration_id,authority_row.connection_id,authority_row.provider,authority_row.integration_version,authority_row.connection_version,authority_row.configuration,authority_row.configuration_digest,authority_row.subject_kind,authority_row.subject_id,authority_row.request_digest)<>(actual_sync,integration_value,connection_row.id,integration_row.kind,integration_row.version,connection_row.version,integration_row.configuration,digest(convert_to(integration_row.configuration::text,'UTF8'),'sha256'),subject_row.subject_kind,subject_row.subject_id,request_digest_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sync authority conflict';END IF;
 IF NOT prior_sync THEN PERFORM zasp_execution_bump_freshness(organization_value,workspace_value,environment_value,integration_value);END IF;
 RETURN result;
END $$;

CREATE FUNCTION public.zasp_execution_record_public_mutation(
 organization_value text,workspace_value text,environment_value text,principal_value text,operation_value text,idempotency_value text,
 intent_value jsonb,body_value jsonb,resource_kind_value text,resource_value text,version_value bigint,audit_value text,correlation_value text,receipt_value text
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE response jsonb;
BEGIN
 IF operation_value NOT IN('syncIntegration','putIntegrationSchedule','deleteIntegrationSchedule') OR resource_kind_value NOT IN('integration_sync','integration_schedule')
    OR NOT zasp_valid_product_id(principal_value) OR NOT zasp_valid_product_id(resource_value) OR NOT zasp_valid_product_id(audit_value)
    OR NOT zasp_valid_product_id(correlation_value) OR (receipt_value<>'' AND NOT zasp_valid_product_id(receipt_value)) OR length(idempotency_value) NOT BETWEEN 16 AND 128
    OR jsonb_typeof(intent_value)<>'object' OR jsonb_typeof(body_value)<>'object' OR version_value<1 THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid public execution mutation';
 END IF;
 response:=jsonb_build_object('body',body_value,'version',version_value,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
 INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version)
 VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,principal_value,operation_value,resource_kind_value,resource_value,version_value);
 INSERT INTO zasp_workflow_idempotency(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,request_digest,response)
 VALUES(organization_value,workspace_value,environment_value,principal_value,operation_value,idempotency_value,digest(convert_to(intent_value::text,'UTF8'),'sha256'),response-'replayed');
 IF receipt_value<>'' THEN
   INSERT INTO zasp_workflow_receipts(organization_id,workspace_id,environment_id,principal_id,receipt_id,operation,idempotency_key,intent,result,resource_kind,resource_id,resource_version,audit_id,correlation_id)
   VALUES(organization_value,workspace_value,environment_value,principal_value,receipt_value,operation_value,idempotency_value,intent_value,body_value,resource_kind_value,resource_value,version_value,audit_value,correlation_value);
 END IF;
 RETURN response;
END $$;

CREATE FUNCTION public.zasp_execution_public_request_sync(
 organization_value text,workspace_value text,environment_value text,principal_value text,integration_value text,idempotency_value text,
 expected_integration_version bigint,sync_value text,job_value text,outbox_value text,request_digest_value bytea,parser_value text,tool_value text,
 audit_value text,correlation_value text,receipt_value text
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE intent_value jsonb;replay_value jsonb;body_value jsonb;sync_version bigint;
BEGIN
 intent_value:=jsonb_build_object('scope',jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value),'integration_id',integration_value,'expected_version',expected_integration_version,'idempotency_key',idempotency_value,'body','{}'::jsonb);
 replay_value:=zasp_workflow_replay(organization_value,workspace_value,environment_value,principal_value,'syncIntegration',idempotency_value,intent_value);
 IF (replay_value->>'found')::boolean THEN RETURN replay_value->'result';END IF;
 IF expected_integration_version<1 OR octet_length(request_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid public sync intent';END IF;
 PERFORM 1 FROM zasp_integrations WHERE (organization_id,workspace_id,environment_id,id,version)=(organization_value,workspace_value,environment_value,integration_value,expected_integration_version) AND state IN('active','degraded') FOR UPDATE;
 IF NOT FOUND THEN IF EXISTS(SELECT 1 FROM zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,integration_value)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='integration version conflict';ELSE RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration missing';END IF;END IF;
 PERFORM zasp_execution_request_sync(organization_value,workspace_value,environment_value,principal_value,integration_value,sync_value,job_value,outbox_value,idempotency_value,request_digest_value,'manual',parser_value,tool_value);
 body_value:=zasp_execution_sync_body(organization_value,workspace_value,environment_value,integration_value,sync_value);
 SELECT version INTO STRICT sync_version FROM zasp_discovery_syncs WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,sync_value);
 RETURN zasp_execution_record_public_mutation(organization_value,workspace_value,environment_value,principal_value,'syncIntegration',idempotency_value,intent_value,body_value,'integration_sync',sync_value,sync_version,audit_value,correlation_value,receipt_value);
END $$;

CREATE FUNCTION public.zasp_execution_public_put_schedule(
 organization_value text,workspace_value text,environment_value text,principal_value text,integration_value text,idempotency_value text,
 expected_schedule_version bigint,cadence_value integer,state_value text,audit_value text,correlation_value text,receipt_value text
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE intent_value jsonb;replay_value jsonb;schedule_row zasp_discovery_schedules%ROWTYPE;schedule_value text;body_value jsonb;
BEGIN
 intent_value:=jsonb_build_object('scope',jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value),'integration_id',integration_value,'expected_version',expected_schedule_version,'idempotency_key',idempotency_value,'body',jsonb_build_object('cadence_seconds',cadence_value,'state',state_value));
 replay_value:=zasp_workflow_replay(organization_value,workspace_value,environment_value,principal_value,'putIntegrationSchedule',idempotency_value,intent_value);
 IF (replay_value->>'found')::boolean THEN RETURN replay_value->'result';END IF;
 IF expected_schedule_version<0 OR cadence_value NOT BETWEEN 300 AND 2678400 OR state_value NOT IN('enabled','disabled') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid public schedule intent';END IF;
 PERFORM 1 FROM zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,integration_value) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='integration missing';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,integration_value,'public-schedule'),0));
 SELECT * INTO schedule_row FROM zasp_discovery_schedules WHERE (organization_id,workspace_id,environment_id,integration_id)=(organization_value,workspace_value,environment_value,integration_value) FOR UPDATE;
 IF expected_schedule_version=0 THEN
   IF FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='schedule already exists';END IF;
   schedule_value:='pid_'||gen_random_uuid()::text;
   INSERT INTO zasp_discovery_schedules(organization_id,workspace_id,environment_id,id,integration_id,cadence_seconds,state,next_run_at)
   VALUES(organization_value,workspace_value,environment_value,schedule_value,integration_value,cadence_value,state_value,transaction_timestamp()+make_interval(secs=>cadence_value));
 ELSE
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule missing';END IF;
   IF schedule_row.version<>expected_schedule_version OR schedule_row.state='deleted' OR schedule_row.lease_owner IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='schedule version conflict';END IF;
   schedule_value:=schedule_row.id;
   UPDATE zasp_discovery_schedules SET cadence_seconds=cadence_value,state=state_value,next_run_at=transaction_timestamp()+make_interval(secs=>cadence_value),version=version+1,updated_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,schedule_value);
 END IF;
 body_value:=zasp_execution_schedule_body(organization_value,workspace_value,environment_value,integration_value,true);
 RETURN zasp_execution_record_public_mutation(organization_value,workspace_value,environment_value,principal_value,'putIntegrationSchedule',idempotency_value,intent_value,body_value,'integration_schedule',integration_value,(body_value->>'version')::bigint,audit_value,correlation_value,receipt_value);
END $$;

CREATE FUNCTION public.zasp_execution_public_delete_schedule(
 organization_value text,workspace_value text,environment_value text,principal_value text,integration_value text,idempotency_value text,
 expected_schedule_version bigint,audit_value text,correlation_value text,receipt_value text
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE intent_value jsonb;replay_value jsonb;schedule_row zasp_discovery_schedules%ROWTYPE;body_value jsonb;
BEGIN
 intent_value:=jsonb_build_object('scope',jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value),'integration_id',integration_value,'expected_version',expected_schedule_version,'idempotency_key',idempotency_value,'body','{}'::jsonb);
 replay_value:=zasp_workflow_replay(organization_value,workspace_value,environment_value,principal_value,'deleteIntegrationSchedule',idempotency_value,intent_value);
 IF (replay_value->>'found')::boolean THEN RETURN replay_value->'result';END IF;
 IF expected_schedule_version<1 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid public schedule delete';END IF;
 SELECT * INTO schedule_row FROM zasp_discovery_schedules WHERE (organization_id,workspace_id,environment_id,integration_id)=(organization_value,workspace_value,environment_value,integration_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule missing';END IF;
 IF schedule_row.version<>expected_schedule_version OR schedule_row.state='deleted' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='schedule version conflict';END IF;
 UPDATE zasp_discovery_schedules SET state='deleted',version=version+1,updated_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,schedule_row.id);
 body_value:=zasp_execution_schedule_body(organization_value,workspace_value,environment_value,integration_value,true);
 RETURN zasp_execution_record_public_mutation(organization_value,workspace_value,environment_value,principal_value,'deleteIntegrationSchedule',idempotency_value,intent_value,body_value,'integration_schedule',integration_value,(body_value->>'version')::bigint,audit_value,correlation_value,receipt_value);
END $$;

CREATE FUNCTION public.zasp_execution_terminalize_exhausted_job(organization_value text,workspace_value text,environment_value text,job_value text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE job_row zasp_discovery_jobs%ROWTYPE;input_row zasp_discovery_snapshot_inputs%ROWTYPE;terminal_state text;
BEGIN
 SELECT * INTO job_row FROM zasp_discovery_jobs WHERE (organization_id,workspace_id,environment_id,id,kind,state)=(organization_value,workspace_value,environment_value,job_value,'discovery','leased') AND attempt>=5 AND lease_expires_at<=transaction_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='exhausted discovery job missing';END IF;
 SELECT input.* INTO input_row FROM zasp_discovery_job_authorities authority JOIN zasp_discovery_generation_reservations reservation ON (reservation.organization_id,reservation.workspace_id,reservation.environment_id,reservation.sync_id,reservation.integration_id,reservation.source)=(authority.organization_id,authority.workspace_id,authority.environment_id,authority.sync_id,authority.integration_id,authority.provider) JOIN zasp_discovery_snapshot_inputs input ON (input.organization_id,input.workspace_id,input.environment_id,input.snapshot_id,input.integration_id,input.source,input.generation)=(reservation.organization_id,reservation.workspace_id,reservation.environment_id,reservation.snapshot_id,reservation.integration_id,reservation.source,reservation.generation) JOIN zasp_discovery_snapshots snapshot ON (snapshot.organization_id,snapshot.workspace_id,snapshot.environment_id,snapshot.id,snapshot.state)=(input.organization_id,input.workspace_id,input.environment_id,input.snapshot_id,'complete') JOIN zasp_discovery_syncs sync ON (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id,sync.integration_id,sync.state,sync.snapshot_id)=(authority.organization_id,authority.workspace_id,authority.environment_id,authority.sync_id,authority.integration_id,'succeeded',input.snapshot_id) WHERE (authority.organization_id,authority.workspace_id,authority.environment_id,authority.job_id)=(organization_value,workspace_value,environment_value,job_value);
 terminal_state:=CASE WHEN FOUND THEN 'succeeded' ELSE 'failed' END;
 UPDATE zasp_discovery_jobs SET state=terminal_state,result_digest=CASE WHEN terminal_state='succeeded' THEN input_row.candidate_digest ELSE result_digest END,last_error=CASE WHEN terminal_state='failed' THEN COALESCE(last_error,'lease expired after maximum attempts') ELSE NULL END,completed_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,job_value);
 UPDATE zasp_discovery_syncs SET state=terminal_state,attempt=job_row.attempt,last_error=CASE WHEN terminal_state='failed' THEN COALESCE(last_error,'lease expired after maximum attempts') ELSE NULL END,last_error_code=CASE WHEN terminal_state='failed' THEN COALESCE(last_error_code,'terminal') ELSE NULL END,completed_at=COALESCE(completed_at,transaction_timestamp()) WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,job_row.authority_id) AND (state IN('queued','running') OR terminal_state='succeeded' AND state='succeeded');
 RETURN jsonb_build_object('id',job_value,'state',terminal_state,'attempt',job_row.attempt,'completed_at',transaction_timestamp());
END $$;

CREATE FUNCTION public.zasp_execution_claim_jobs(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE response jsonb;exhausted record;
BEGIN
 IF length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 OR claim_limit NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution claim'; END IF;
 IF NOT pg_has_role(session_user,'zasp_discovery_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='execution authority denied'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-execution-job-quota-claims',0));
 FOR exhausted IN SELECT organization_id,workspace_id,environment_id,id FROM zasp_discovery_jobs WHERE kind='discovery' AND attempt>=5 AND state='leased' AND lease_expires_at<=transaction_timestamp() ORDER BY organization_id,id FOR UPDATE SKIP LOCKED LOOP
   PERFORM zasp_execution_terminalize_exhausted_job(exhausted.organization_id,exhausted.workspace_id,exhausted.environment_id,exhausted.id);
 END LOOP;
 WITH live AS (SELECT organization_id,count(*) active FROM zasp_discovery_jobs WHERE kind='discovery' AND state='leased' AND lease_expires_at>transaction_timestamp() GROUP BY organization_id),
 organizations AS (SELECT job.organization_id,min(job.available_at) due FROM zasp_discovery_jobs job LEFT JOIN live ON live.organization_id=job.organization_id LEFT JOIN zasp_discovery_execution_quotas quota ON quota.organization_id=job.organization_id WHERE job.kind='discovery' AND job.attempt<5 AND job.available_at<=transaction_timestamp() AND (job.state IN('queued','retryable') OR job.state='leased' AND job.lease_expires_at<=transaction_timestamp()) AND COALESCE(live.active,0)<COALESCE(quota.max_active_jobs,4) GROUP BY job.organization_id ORDER BY due,job.organization_id LIMIT claim_limit),
 picked AS (SELECT chosen.ctid,chosen.organization_id,chosen.created_at,chosen.id FROM organizations organization CROSS JOIN LATERAL (SELECT job.ctid,job.organization_id,job.created_at,job.id FROM zasp_discovery_jobs job WHERE job.organization_id=organization.organization_id AND job.kind='discovery' AND job.attempt<5 AND job.available_at<=transaction_timestamp() AND (job.state IN('queued','retryable') OR job.state='leased' AND job.lease_expires_at<=transaction_timestamp()) ORDER BY job.created_at,job.id LIMIT 1 FOR UPDATE SKIP LOCKED) chosen),
 claimed AS (UPDATE zasp_discovery_jobs job SET state='leased',attempt=job.attempt+1,lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),completion_digest=NULL,completion_result=NULL,updated_at=transaction_timestamp() FROM (SELECT * FROM picked ORDER BY created_at,organization_id,id LIMIT claim_limit) selected WHERE job.ctid=selected.ctid RETURNING job.organization_id,job.workspace_id,job.environment_id,job.id,job.kind,job.authority_id,job.attempt,job.lease_expires_at)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(to_jsonb(claimed) ORDER BY organization_id,id),'[]'::jsonb)) INTO response FROM claimed;
 UPDATE zasp_discovery_syncs sync SET state='running',attempt=job.attempt,started_at=COALESCE(sync.started_at,transaction_timestamp()),last_error=NULL FROM zasp_discovery_jobs job WHERE job.kind='discovery' AND job.lease_owner=worker_value AND job.lease_token=lease_token_value AND (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id)=(job.organization_id,job.workspace_id,job.environment_id,job.authority_id) AND sync.state IN('queued','running');
 INSERT INTO zasp_discovery_freshness_versions(organization_id,workspace_id,environment_id,integration_id,version)
 SELECT DISTINCT authority.organization_id,authority.workspace_id,authority.environment_id,authority.integration_id,1 FROM zasp_discovery_jobs job JOIN zasp_discovery_job_authorities authority ON (authority.organization_id,authority.workspace_id,authority.environment_id,authority.job_id)=(job.organization_id,job.workspace_id,job.environment_id,job.id) WHERE job.kind='discovery' AND job.lease_owner=worker_value AND job.lease_token=lease_token_value
 ON CONFLICT(organization_id,workspace_id,environment_id,integration_id) DO UPDATE SET version=zasp_discovery_freshness_versions.version+1,updated_at=transaction_timestamp();
 RETURN response;
END $$;

CREATE FUNCTION public.zasp_execution_claim_delivery(organization_value text,workspace_value text,environment_value text,job_value text,worker_value text,lease_token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE job_row zasp_discovery_jobs%ROWTYPE;active_count integer;maximum_active integer;response jsonb;
BEGIN
 IF length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid delivery claim';END IF;
 IF NOT pg_has_role(session_user,'zasp_discovery_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='execution authority denied';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-execution-job-quota-claims',0));
 SELECT * INTO job_row FROM zasp_discovery_jobs WHERE (organization_id,workspace_id,environment_id,id,kind)=(organization_value,workspace_value,environment_value,job_value,'discovery') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='delivery job missing';END IF;
 IF job_row.state IN('succeeded','failed','cancelled') THEN RETURN jsonb_build_object('id',job_row.id,'disposition','ack_terminal','state',job_row.state,'attempt',job_row.attempt);END IF;
 IF job_row.state='leased' AND job_row.lease_expires_at>transaction_timestamp() THEN RETURN jsonb_build_object('id',job_row.id,'disposition','busy','state',job_row.state,'attempt',job_row.attempt);END IF;
 IF job_row.attempt>=5 THEN
   response:=zasp_execution_terminalize_exhausted_job(organization_value,workspace_value,environment_value,job_value);
   RETURN jsonb_build_object('id',job_row.id,'disposition','ack_terminal','state',response->>'state','attempt',job_row.attempt);
 END IF;
 IF job_row.available_at>transaction_timestamp() THEN RETURN jsonb_build_object('id',job_row.id,'disposition','busy','state',job_row.state,'attempt',job_row.attempt);END IF;
 SELECT count(*) INTO active_count FROM zasp_discovery_jobs WHERE organization_id=organization_value AND kind='discovery' AND state='leased' AND lease_expires_at>transaction_timestamp();
 SELECT COALESCE((SELECT max_active_jobs FROM zasp_discovery_execution_quotas WHERE organization_id=organization_value),4) INTO maximum_active;
 IF active_count>=maximum_active THEN RETURN jsonb_build_object('id',job_row.id,'disposition','busy','state',job_row.state,'attempt',job_row.attempt);END IF;
 UPDATE zasp_discovery_jobs SET state='leased',attempt=attempt+1,lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),completion_digest=NULL,completion_result=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,job_value) RETURNING jsonb_build_object('id',id,'disposition','claimed','state',state,'attempt',attempt,'lease_expires_at',lease_expires_at,'authority_id',authority_id) INTO response;
 UPDATE zasp_discovery_syncs SET state='running',attempt=(response->>'attempt')::integer,started_at=COALESCE(started_at,transaction_timestamp()),last_error=NULL WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,job_row.authority_id) AND state IN('queued','running');
 RETURN response;
END $$;

CREATE FUNCTION public.zasp_execution_job_input(organization_value text,workspace_value text,environment_value text,job_value text,worker text,lease_token_value text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;sync_value text;integration_value text;source_value text;next_generation bigint;
BEGIN
 SELECT sync.id,integration.id,integration.kind INTO sync_value,integration_value,source_value FROM zasp_discovery_jobs job JOIN zasp_discovery_syncs sync ON (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id)=(job.organization_id,job.workspace_id,job.environment_id,job.authority_id) JOIN zasp_discovery_job_authorities authority ON (authority.organization_id,authority.workspace_id,authority.environment_id,authority.job_id,authority.sync_id)=(job.organization_id,job.workspace_id,job.environment_id,job.id,sync.id) JOIN zasp_integrations integration ON (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.version,integration.kind,integration.configuration)=(authority.organization_id,authority.workspace_id,authority.environment_id,authority.integration_id,authority.integration_version,authority.provider,authority.configuration)
 WHERE (job.organization_id,job.workspace_id,job.environment_id,job.id)=(organization_value,workspace_value,environment_value,job_value) AND job.kind='discovery' AND job.request_digest=authority.request_digest AND job.state='leased' AND job.lease_owner=worker AND job.lease_token=lease_token_value AND job.lease_expires_at>transaction_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='execution job input missing'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,integration_value,source_value),0));
 IF EXISTS(SELECT 1 FROM zasp_discovery_generation_reservations reservation JOIN zasp_discovery_job_authorities authority ON (authority.organization_id,authority.workspace_id,authority.environment_id,authority.sync_id)=(reservation.organization_id,reservation.workspace_id,reservation.environment_id,reservation.sync_id) JOIN zasp_discovery_jobs active_job ON (active_job.organization_id,active_job.workspace_id,active_job.environment_id,active_job.id)=(authority.organization_id,authority.workspace_id,authority.environment_id,authority.job_id) WHERE (reservation.organization_id,reservation.workspace_id,reservation.environment_id,reservation.integration_id,reservation.source)=(organization_value,workspace_value,environment_value,integration_value,source_value) AND reservation.sync_id<>sync_value AND active_job.state IN('queued','retryable','leased')) THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='collection already active';END IF;
 SELECT GREATEST(COALESCE((SELECT max(generation) FROM zasp_discovery_snapshots WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND integration_id=integration_value AND source=source_value),0),COALESCE((SELECT max(generation) FROM zasp_discovery_generation_reservations WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND integration_id=integration_value AND source=source_value),0))+1 INTO next_generation;
 INSERT INTO zasp_discovery_generation_reservations(organization_id,workspace_id,environment_id,sync_id,integration_id,source,generation,snapshot_id) VALUES(organization_value,workspace_value,environment_value,sync_value,integration_value,source_value,next_generation,'pid_'||gen_random_uuid()::text) ON CONFLICT(organization_id,workspace_id,environment_id,sync_id) DO NOTHING;
 SELECT jsonb_build_object('organization_id',job.organization_id,'workspace_id',job.workspace_id,'environment_id',job.environment_id,'job_id',job.id,'attempt',job.attempt,'lease_expires_at',job.lease_expires_at,'sync_id',sync.id,'integration_id',integration.id,'connection_id',connection.id,'provider',integration.kind,'generation',reservation.generation,'snapshot_id',reservation.snapshot_id,'collector_version','collector_v1','credential_class',CASE integration.kind WHEN 'aws' THEN 'aws_assume_role' WHEN 'kubernetes' THEN 'kubernetes_cluster' WHEN 'github' THEN 'github_installation' ELSE 'okta_refresh' END,'credential_reference',connection.connection_reference,'subject_kind',subject.subject_kind,'subject_id',subject.subject_id,'cursor_provider',COALESCE(checkpoint.provider,cursor.provider),'cursor_version',COALESCE(checkpoint.cursor_version,CASE WHEN cursor.provider IS NULL THEN NULL ELSE 'cursor_v1' END),'cursor_value',COALESCE(checkpoint.cursor_value,cursor.cursor_value),'parser_version',sync.parser_version,'tool_version',sync.tool_version,'configuration',authority.configuration)
   ||CASE WHEN checkpoint.job_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('checkpoint_version',checkpoint.version,'checkpoint_digest',encode(checkpoint.checkpoint_digest,'base64'),'checkpoint_manifest_reference',checkpoint.manifest_reference,'checkpoint_manifest_key',checkpoint.manifest_key,'checkpoint_manifest_version_id',checkpoint.manifest_version_id,'checkpoint_manifest_checksum',encode(checkpoint.manifest_checksum,'base64'),'checkpoint_manifest_size_bytes',checkpoint.manifest_size_bytes,'checkpoint_manifest_media_type',checkpoint.manifest_media_type,'checkpoint_manifest_schema_version',checkpoint.manifest_schema_version) END
 INTO result FROM zasp_discovery_jobs job JOIN zasp_discovery_syncs sync ON (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id)=(job.organization_id,job.workspace_id,job.environment_id,job.authority_id) JOIN zasp_discovery_job_authorities authority ON (authority.organization_id,authority.workspace_id,authority.environment_id,authority.job_id,authority.sync_id)=(job.organization_id,job.workspace_id,job.environment_id,job.id,sync.id) JOIN zasp_integrations integration ON (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=(sync.organization_id,sync.workspace_id,sync.environment_id,sync.integration_id) JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id,connection.provider)=(authority.organization_id,authority.workspace_id,authority.environment_id,authority.integration_id,authority.connection_id,authority.provider) JOIN zasp_discovery_connection_subjects subject ON (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id,subject.connection_id)=(connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id) LEFT JOIN zasp_discovery_cursors cursor ON (cursor.organization_id,cursor.workspace_id,cursor.environment_id,cursor.integration_id,cursor.provider)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.kind) LEFT JOIN zasp_discovery_job_checkpoints checkpoint ON (checkpoint.organization_id,checkpoint.workspace_id,checkpoint.environment_id,checkpoint.job_id,checkpoint.sync_id,checkpoint.integration_id,checkpoint.provider)=(authority.organization_id,authority.workspace_id,authority.environment_id,authority.job_id,authority.sync_id,authority.integration_id,authority.provider)
 JOIN zasp_discovery_generation_reservations reservation ON (reservation.organization_id,reservation.workspace_id,reservation.environment_id,reservation.sync_id,reservation.integration_id,reservation.source)=(sync.organization_id,sync.workspace_id,sync.environment_id,sync.id,integration.id,integration.kind)
 WHERE (job.organization_id,job.workspace_id,job.environment_id,job.id)=(organization_value,workspace_value,environment_value,job_value)
   AND job.kind='discovery' AND job.state='leased' AND job.lease_owner=worker AND job.lease_token=lease_token_value AND job.lease_expires_at>transaction_timestamp()
   AND integration.state IN('active','degraded') AND integration.version=authority.integration_version AND integration.configuration=authority.configuration AND connection.state='verified' AND connection.version=authority.connection_version AND subject.provider=authority.provider AND subject.subject_kind=authority.subject_kind AND subject.subject_id=authority.subject_id
   AND subject.connection_version=connection.version AND subject.configuration_digest=authority.configuration_digest AND authority.configuration_digest=digest(convert_to(integration.configuration::text,'UTF8'),'sha256') AND authority.request_digest=job.request_digest
   AND CASE integration.kind
     WHEN 'aws' THEN subject.subject_kind='aws_account' AND subject.subject_id=substring(integration.configuration->>'role_arn' FROM '^arn:aws:iam::([0-9]{12}):role/')
     WHEN 'github' THEN subject.subject_kind='github_installation' AND EXISTS(SELECT 1 FROM zasp_connector_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.integration_id,credential.provider,credential.credential_reference)=(connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,'github',connection.connection_reference) AND credential.status='active' AND credential.metadata->>'installation_id'=subject.subject_id)
     WHEN 'okta' THEN subject.subject_kind='okta_tenant' AND EXISTS(SELECT 1 FROM zasp_connector_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.integration_id,credential.provider,credential.credential_reference)=(connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,'okta',connection.connection_reference) AND credential.status='active' AND credential.metadata->>'tenant'=subject.subject_id)
     WHEN 'kubernetes' THEN subject.subject_kind='kubernetes_cluster'
     ELSE false END;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='execution job input missing'; END IF; RETURN result;
END $$;

CREATE FUNCTION public.zasp_execution_heartbeat_job(organization_value text,workspace_value text,environment_value text,job_value text,worker text,lease_token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE expires timestamptz;
BEGIN IF lease_seconds NOT BETWEEN 5 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution heartbeat'; END IF;
 UPDATE zasp_discovery_jobs SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,job_value) AND kind='discovery' AND state='leased' AND lease_owner=worker AND lease_token=lease_token_value AND lease_expires_at>transaction_timestamp() RETURNING lease_expires_at INTO expires;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='execution job lease missing'; END IF; RETURN jsonb_build_object('id',job_value,'lease_expires_at',expires);
END $$;

CREATE FUNCTION public.zasp_execution_checkpoint_partial(
 organization_value text,workspace_value text,environment_value text,job_value text,worker_value text,lease_token_value text,expected_version_value bigint,
 provider_value text,cursor_version_value text,cursor_value text,manifest_reference_value text,manifest_key_value text,manifest_version_value text,
 manifest_checksum_value bytea,manifest_size_value bigint,manifest_media_value text,manifest_schema_value text,parser_value text,tool_value text
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE job_row zasp_discovery_jobs%ROWTYPE;authority_row zasp_discovery_job_authorities%ROWTYPE;checkpoint_row zasp_discovery_job_checkpoints%ROWTYPE;digest_value bytea;result jsonb;next_version bigint;
BEGIN
 IF NOT pg_has_role(session_user,'zasp_discovery_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='execution authority denied';END IF;
 IF expected_version_value NOT BETWEEN 0 AND 9999 OR provider_value NOT IN('aws','kubernetes','github','okta') OR cursor_version_value !~ '^[a-z][a-z0-9_.-]{1,63}$' OR length(cursor_value) NOT BETWEEN 1 AND 2048
    OR NOT zasp_discovery_s3_object_reference(manifest_reference_value) OR length(manifest_key_value) NOT BETWEEN 32 AND 1024 OR right(manifest_reference_value,length(manifest_key_value)+1)<>'/'||manifest_key_value
    OR length(manifest_version_value) NOT BETWEEN 1 AND 1024 OR octet_length(manifest_checksum_value)<>32 OR manifest_size_value NOT BETWEEN 1 AND 536870912
    OR manifest_media_value<>'application/json' OR manifest_schema_value !~ '^[a-z][a-z0-9_.-]{1,63}$' OR parser_value !~ '^[a-z][a-z0-9_.-]{1,63}$' OR tool_value !~ '^[a-z][a-z0-9_.-]{1,63}$'
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid partial checkpoint';END IF;
 SELECT * INTO job_row FROM zasp_discovery_jobs WHERE (organization_id,workspace_id,environment_id,id,kind,state,lease_owner,lease_token)=(organization_value,workspace_value,environment_value,job_value,'discovery','leased',worker_value,lease_token_value) AND lease_expires_at>transaction_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='execution job lease missing';END IF;
 SELECT * INTO authority_row FROM zasp_discovery_job_authorities WHERE (organization_id,workspace_id,environment_id,job_id,sync_id,provider)=(organization_value,workspace_value,environment_value,job_value,job_row.authority_id,provider_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='execution job authority missing';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_discovery_syncs sync WHERE (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id,sync.integration_id,sync.parser_version,sync.tool_version)=(organization_value,workspace_value,environment_value,authority_row.sync_id,authority_row.integration_id,parser_value,tool_value) AND sync.state='running') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='partial checkpoint intent changed';END IF;
 digest_value:=digest(convert_to(jsonb_build_object('job_id',job_value,'sync_id',authority_row.sync_id,'integration_id',authority_row.integration_id,'provider',provider_value,'cursor_version',cursor_version_value,'cursor_value',cursor_value,'manifest_reference',manifest_reference_value,'manifest_key',manifest_key_value,'manifest_version_id',manifest_version_value,'manifest_checksum',encode(manifest_checksum_value,'hex'),'manifest_size_bytes',manifest_size_value,'manifest_media_type',manifest_media_value,'manifest_schema_version',manifest_schema_value,'parser_version',parser_value,'tool_version',tool_value)::text,'UTF8'),'sha256');
 SELECT * INTO checkpoint_row FROM zasp_discovery_job_checkpoints WHERE (organization_id,workspace_id,environment_id,job_id)=(organization_value,workspace_value,environment_value,job_value) FOR UPDATE;
 IF FOUND AND checkpoint_row.version=expected_version_value+1 AND checkpoint_row.checkpoint_digest=digest_value THEN RETURN checkpoint_row.checkpoint_result;END IF;
 IF FOUND AND checkpoint_row.version<>expected_version_value OR NOT FOUND AND expected_version_value<>0 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='partial checkpoint version conflict';END IF;
 next_version:=expected_version_value+1;
 result:=jsonb_build_object('id',job_value,'version',next_version,'checkpoint_digest',encode(digest_value,'base64'),'cursor_provider',provider_value,'cursor_version',cursor_version_value,'cursor_value',cursor_value,'manifest_version_id',manifest_version_value,'updated_at',to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 INSERT INTO zasp_discovery_job_checkpoints(organization_id,workspace_id,environment_id,job_id,sync_id,integration_id,provider,version,cursor_version,cursor_value,manifest_reference,manifest_key,manifest_version_id,manifest_checksum,manifest_size_bytes,manifest_media_type,manifest_schema_version,parser_version,tool_version,checkpoint_digest,checkpoint_result,updated_at)
 VALUES(organization_value,workspace_value,environment_value,job_value,authority_row.sync_id,authority_row.integration_id,provider_value,next_version,cursor_version_value,cursor_value,manifest_reference_value,manifest_key_value,manifest_version_value,manifest_checksum_value,manifest_size_value,manifest_media_value,manifest_schema_value,parser_value,tool_value,digest_value,result,transaction_timestamp())
 ON CONFLICT(organization_id,workspace_id,environment_id,job_id) DO UPDATE SET version=excluded.version,cursor_version=excluded.cursor_version,cursor_value=excluded.cursor_value,manifest_reference=excluded.manifest_reference,manifest_key=excluded.manifest_key,manifest_version_id=excluded.manifest_version_id,manifest_checksum=excluded.manifest_checksum,manifest_size_bytes=excluded.manifest_size_bytes,manifest_media_type=excluded.manifest_media_type,manifest_schema_version=excluded.manifest_schema_version,parser_version=excluded.parser_version,tool_version=excluded.tool_version,checkpoint_digest=excluded.checkpoint_digest,checkpoint_result=excluded.checkpoint_result,updated_at=excluded.updated_at;
 RETURN result;
END $$;

CREATE FUNCTION public.zasp_execution_finish_job(organization_value text,workspace_value text,environment_value text,job_value text,worker_value text,lease_token_value text,outcome_value text,result_digest_value bytea,last_error_code_value text,last_error_value text,retry_after_seconds integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;authority_row zasp_discovery_job_authorities%ROWTYPE;reservation_row zasp_discovery_generation_reservations%ROWTYPE;fresh_completion boolean;
BEGIN
 IF NOT pg_has_role(session_user,'zasp_discovery_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='execution authority denied';END IF;
 IF outcome_value='succeeded' AND last_error_code_value IS NOT NULL OR outcome_value<>'succeeded' AND last_error_code_value NOT IN('retryable','rate_limited','denied','revoked','malformed','partial','terminal','cancelled','outcome_unknown') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid discovery error code';END IF;
 SELECT authority.* INTO authority_row FROM zasp_discovery_job_authorities authority WHERE (authority.organization_id,authority.workspace_id,authority.environment_id,authority.job_id)=(organization_value,workspace_value,environment_value,job_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='execution job authority missing';END IF;
 fresh_completion:=EXISTS(SELECT 1 FROM zasp_discovery_jobs job WHERE (job.organization_id,job.workspace_id,job.environment_id,job.id,job.kind,job.state,job.lease_owner,job.lease_token)=(organization_value,workspace_value,environment_value,job_value,'discovery','leased',worker_value,lease_token_value) AND job.lease_expires_at>transaction_timestamp());
 IF outcome_value='succeeded' THEN
   SELECT * INTO reservation_row FROM zasp_discovery_generation_reservations WHERE (organization_id,workspace_id,environment_id,sync_id,integration_id,source)=(organization_value,workspace_value,environment_value,authority_row.sync_id,authority_row.integration_id,authority_row.provider);
   IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM zasp_discovery_snapshot_inputs input JOIN zasp_discovery_snapshots snapshot ON (snapshot.organization_id,snapshot.workspace_id,snapshot.environment_id,snapshot.id)=(input.organization_id,input.workspace_id,input.environment_id,input.snapshot_id) JOIN zasp_discovery_syncs sync ON (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id,sync.integration_id,sync.state,sync.snapshot_id)=(input.organization_id,input.workspace_id,input.environment_id,authority_row.sync_id,authority_row.integration_id,'succeeded',input.snapshot_id) WHERE (input.organization_id,input.workspace_id,input.environment_id,input.snapshot_id,input.integration_id,input.source,input.generation,input.candidate_digest)=(organization_value,workspace_value,environment_value,reservation_row.snapshot_id,authority_row.integration_id,authority_row.provider,reservation_row.generation,result_digest_value) AND snapshot.state='complete') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='committed snapshot required';END IF;
 END IF;
 IF outcome_value='retryable' AND last_error_code_value='partial' AND NOT EXISTS(SELECT 1 FROM zasp_discovery_job_checkpoints checkpoint WHERE (checkpoint.organization_id,checkpoint.workspace_id,checkpoint.environment_id,checkpoint.job_id,checkpoint.sync_id,checkpoint.integration_id,checkpoint.provider,checkpoint.checkpoint_digest)=(organization_value,workspace_value,environment_value,job_value,authority_row.sync_id,authority_row.integration_id,authority_row.provider,result_digest_value)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='partial checkpoint required';END IF;
 result:=zasp_discovery_finish_job(organization_value,workspace_value,environment_value,job_value,worker_value,lease_token_value,outcome_value,result_digest_value,last_error_value,retry_after_seconds);
 IF fresh_completion THEN
   UPDATE zasp_discovery_syncs SET last_error_code=CASE WHEN result->>'state'='succeeded' THEN NULL ELSE last_error_code_value END WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,authority_row.sync_id);
   PERFORM zasp_execution_bump_freshness(organization_value,workspace_value,environment_value,authority_row.integration_id);
 END IF;
 RETURN result;
END $$;

CREATE FUNCTION public.zasp_execution_claim_schedules(worker text,lease_token text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql AS $$
BEGIN IF NOT pg_has_role(session_user,'zasp_discovery_scheduler','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='scheduler authority denied'; END IF; RETURN zasp_discovery_claim_schedules(worker,lease_token,lease_seconds,claim_limit); END $$;

CREATE FUNCTION public.zasp_execution_schedule_input(organization_value text,workspace_value text,environment_value text,schedule_value text,worker text,lease_token_value text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE result jsonb;BEGIN SELECT jsonb_build_object('organization_id',schedule.organization_id,'workspace_id',schedule.workspace_id,'environment_id',schedule.environment_id,'schedule_id',schedule.id,'integration_id',schedule.integration_id,'cadence_seconds',schedule.cadence_seconds,'time_zone',schedule.time_zone,'next_run_at',schedule.next_run_at,'version',schedule.version,'lease_expires_at',schedule.lease_expires_at) INTO result FROM zasp_discovery_schedules schedule WHERE (schedule.organization_id,schedule.workspace_id,schedule.environment_id,schedule.id)=(organization_value,workspace_value,environment_value,schedule_value) AND schedule.state='enabled' AND schedule.lease_owner=worker AND schedule.lease_token=lease_token_value AND schedule.lease_expires_at>transaction_timestamp();IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule input missing';END IF;RETURN result;END $$;

CREATE FUNCTION public.zasp_execution_heartbeat_schedule(organization_value text,workspace_value text,environment_value text,schedule_value text,worker text,lease_token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE expires timestamptz;BEGIN IF lease_seconds NOT BETWEEN 5 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid schedule heartbeat';END IF;UPDATE zasp_discovery_schedules SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,schedule_value) AND state='enabled' AND lease_owner=worker AND lease_token=lease_token_value AND lease_expires_at>transaction_timestamp() RETURNING lease_expires_at INTO expires;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule lease missing';END IF;RETURN jsonb_build_object('id',schedule_value,'lease_expires_at',expires);END $$;

CREATE FUNCTION public.zasp_execution_request_scheduled_sync(organization_value text,workspace_value text,environment_value text,principal_value text,schedule_value text,worker_value text,lease_token_value text,integration_value text,sync_value text,job_value text,outbox_value text,idempotency_value text,request_digest_value bytea,parser_value text,tool_value text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE schedule_row zasp_discovery_schedules%ROWTYPE;result jsonb;
BEGIN
 IF NOT pg_has_role(session_user,'zasp_discovery_scheduler','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='scheduler authority denied';END IF;
 SELECT * INTO schedule_row FROM zasp_discovery_schedules WHERE (organization_id,workspace_id,environment_id,id,integration_id,state,lease_owner,lease_token)=(organization_value,workspace_value,environment_value,schedule_value,integration_value,'enabled',worker_value,lease_token_value) AND lease_expires_at>transaction_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule lease missing';END IF;
 result:=zasp_execution_request_sync(organization_value,workspace_value,environment_value,principal_value,integration_value,sync_value,job_value,outbox_value,idempotency_value,request_digest_value,'schedule',parser_value,tool_value);
 INSERT INTO zasp_discovery_schedule_runs(organization_id,workspace_id,environment_id,schedule_id,sync_id,job_id,lease_owner,lease_token,request_digest,scheduled_for)
 VALUES(organization_value,workspace_value,environment_value,schedule_value,result->>'sync_id',result->>'job_id',worker_value,lease_token_value,request_digest_value,schedule_row.next_run_at)
 ON CONFLICT(organization_id,workspace_id,environment_id,schedule_id,sync_id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_discovery_schedule_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.schedule_id,run.sync_id,run.job_id,run.lease_owner,run.lease_token,run.request_digest,run.scheduled_for)=(organization_value,workspace_value,environment_value,schedule_value,result->>'sync_id',result->>'job_id',worker_value,lease_token_value,request_digest_value,schedule_row.next_run_at)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='schedule run conflict';END IF;
 RETURN result;
END $$;

CREATE FUNCTION public.zasp_execution_complete_schedule(organization_value text,workspace_value text,environment_value text,schedule_value text,worker_value text,lease_token_value text,outcome_value text,next_run_value timestamptz) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;BEGIN IF NOT pg_has_role(session_user,'zasp_discovery_scheduler','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='scheduler authority denied';END IF;IF outcome_value='advanced' AND NOT EXISTS(SELECT 1 FROM zasp_discovery_schedule_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.schedule_id,run.lease_owner,run.lease_token)=(organization_value,workspace_value,environment_value,schedule_value,worker_value,lease_token_value)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='scheduled sync required';END IF;result:=zasp_discovery_complete_schedule(organization_value,workspace_value,environment_value,schedule_value,worker_value,lease_token_value,outcome_value,next_run_value);IF outcome_value='advanced' THEN UPDATE zasp_discovery_schedule_runs SET completed_at=COALESCE(completed_at,transaction_timestamp()) WHERE (organization_id,workspace_id,environment_id,schedule_id,lease_owner,lease_token)=(organization_value,workspace_value,environment_value,schedule_value,worker_value,lease_token_value);END IF;RETURN result;END $$;

CREATE FUNCTION public.zasp_execution_apply_complete_snapshot(organization_value text,workspace_value text,environment_value text,job_value text,worker_value text,lease_token_value text,integration_value text,sync_value text,snapshot_value text,generation_value bigint,source_value text,manifest_reference_value text,manifest_key_value text,manifest_version_value text,manifest_checksum_value bytea,manifest_size_value bigint,manifest_media_value text,manifest_schema_value text,collected_value timestamptz,cursor_value text,parser_value text,tool_value text,entities_value jsonb,relationships_value jsonb,evidence_value jsonb) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;digest_value bytea;input_row zasp_discovery_snapshot_inputs%ROWTYPE;authority_row zasp_discovery_job_authorities%ROWTYPE;
BEGIN
 SELECT authority.* INTO authority_row FROM zasp_discovery_jobs job JOIN zasp_discovery_job_authorities authority ON (authority.organization_id,authority.workspace_id,authority.environment_id,authority.job_id,authority.sync_id,authority.integration_id,authority.provider)=(job.organization_id,job.workspace_id,job.environment_id,job.id,job.authority_id,integration_value,source_value) JOIN zasp_discovery_generation_reservations reservation ON (reservation.organization_id,reservation.workspace_id,reservation.environment_id,reservation.sync_id,reservation.integration_id,reservation.source,reservation.generation,reservation.snapshot_id)=(authority.organization_id,authority.workspace_id,authority.environment_id,authority.sync_id,authority.integration_id,authority.provider,generation_value,snapshot_value) WHERE (job.organization_id,job.workspace_id,job.environment_id,job.id,job.kind,job.state,job.lease_owner,job.lease_token)=(organization_value,workspace_value,environment_value,job_value,'discovery','leased',worker_value,lease_token_value) AND job.lease_expires_at>transaction_timestamp() FOR UPDATE OF job;
 IF NOT FOUND OR authority_row.sync_id<>sync_value OR substring(manifest_reference_value FROM '^s3://[a-z0-9][a-z0-9.-]{2,62}/(.+)$') IS DISTINCT FROM manifest_key_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='snapshot execution authority conflict';END IF;
 IF jsonb_typeof(entities_value)<>'array' OR jsonb_typeof(relationships_value)<>'array' OR jsonb_typeof(evidence_value)<>'array' OR EXISTS(SELECT 1 FROM (SELECT value FROM jsonb_array_elements(entities_value) value UNION ALL SELECT value FROM jsonb_array_elements(relationships_value) value UNION ALL SELECT value FROM jsonb_array_elements(evidence_value) value) item WHERE jsonb_typeof(item.value)<>'object' OR NOT zasp_valid_product_id(item.value->>'id') OR octet_length(item.value::text)>1048576) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid snapshot item';END IF;
 digest_value:=digest(convert_to(jsonb_build_object('integration_id',integration_value,'sync_id',sync_value,'snapshot_id',snapshot_value,'generation',generation_value,'source',source_value,'manifest_reference',manifest_reference_value,'manifest_key',manifest_key_value,'manifest_version_id',manifest_version_value,'manifest_checksum',encode(manifest_checksum_value,'hex'),'manifest_size_bytes',manifest_size_value,'manifest_media_type',manifest_media_value,'manifest_schema_version',manifest_schema_value,'collected_at_epoch_us',floor(extract(epoch FROM collected_value)*1000000)::bigint,'cursor',cursor_value,'parser_version',parser_value,'tool_version',tool_value,'entities',entities_value,'relationships',relationships_value,'evidence',evidence_value)::text,'UTF8'),'sha256');
 result:=zasp_discovery_apply_snapshot(organization_value,workspace_value,environment_value,integration_value,sync_value,snapshot_value,generation_value,source_value,manifest_reference_value,manifest_checksum_value,collected_value,source_value,cursor_value,entities_value,relationships_value,evidence_value);
 UPDATE zasp_projection_work SET input_digest=digest_value WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value) AND state='pending' AND attempt=0;
 INSERT INTO zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,generation,candidate_digest,manifest_reference,manifest_key,manifest_version_id,manifest_checksum,manifest_size_bytes,manifest_media_type,manifest_schema_version,parser_version,tool_version,entities,relationships,evidence)
 VALUES(organization_value,workspace_value,environment_value,snapshot_value,integration_value,source_value,generation_value,digest_value,manifest_reference_value,manifest_key_value,manifest_version_value,manifest_checksum_value,manifest_size_value,manifest_media_value,manifest_schema_value,parser_value,tool_value,entities_value,relationships_value,evidence_value) ON CONFLICT(organization_id,workspace_id,environment_id,snapshot_id) DO NOTHING;
 SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value);
 IF input_row.candidate_digest<>digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='snapshot input replay conflict';END IF;
 INSERT INTO zasp_discovery_snapshot_projection_items(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,section,item_id,payload)
 SELECT organization_value,workspace_value,environment_value,snapshot_value,integration_value,source_value,section,value->>'id',value FROM (SELECT 'entities'::text section,value FROM jsonb_array_elements(entities_value) value UNION ALL SELECT 'relationships',value FROM jsonb_array_elements(relationships_value) value UNION ALL SELECT 'evidence',value FROM jsonb_array_elements(evidence_value) value) normalized ON CONFLICT DO NOTHING;
 IF (SELECT count(*) FROM zasp_discovery_snapshot_projection_items WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value))<>jsonb_array_length(entities_value)+jsonb_array_length(relationships_value)+jsonb_array_length(evidence_value) OR EXISTS(SELECT 1 FROM (SELECT 'entities'::text section,value FROM jsonb_array_elements(entities_value) value UNION ALL SELECT 'relationships',value FROM jsonb_array_elements(relationships_value) value UNION ALL SELECT 'evidence',value FROM jsonb_array_elements(evidence_value) value) expected LEFT JOIN zasp_discovery_snapshot_projection_items stored ON (stored.organization_id,stored.workspace_id,stored.environment_id,stored.snapshot_id,stored.section,stored.item_id)=(organization_value,workspace_value,environment_value,snapshot_value,expected.section,expected.value->>'id') WHERE stored.payload IS DISTINCT FROM expected.value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='snapshot projection input conflict';END IF;
 PERFORM zasp_execution_bump_freshness(organization_value,workspace_value,environment_value,integration_value);
 RETURN result||jsonb_build_object('candidate_digest',encode(digest_value,'base64'),'manifest_version_id',manifest_version_value);
END $$;

CREATE FUNCTION public.zasp_execution_snapshot_projection_page(organization_value text,workspace_value text,environment_value text,snapshot_value text,section_value text,after_id text,page_limit integer) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE input_row zasp_discovery_snapshot_inputs%ROWTYPE;response jsonb;BEGIN IF section_value NOT IN('entities','relationships','evidence') OR page_limit NOT BETWEEN 1 AND 500 OR after_id IS NOT NULL AND NOT zasp_valid_product_id(after_id) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid projection page';END IF;SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value);IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='snapshot input missing';END IF;WITH source AS (SELECT item_id,payload FROM zasp_discovery_snapshot_projection_items WHERE (organization_id,workspace_id,environment_id,snapshot_id,section)=(organization_value,workspace_value,environment_value,snapshot_value,section_value) AND (after_id IS NULL OR item_id>after_id) ORDER BY item_id LIMIT page_limit+1),visible AS (SELECT item_id,payload FROM source ORDER BY item_id LIMIT page_limit) SELECT jsonb_build_object('snapshot_id',snapshot_value,'integration_id',input_row.integration_id,'source',input_row.source,'generation',input_row.generation,'candidate_digest',encode(input_row.candidate_digest,'base64'),'manifest_reference',input_row.manifest_reference,'manifest_key',input_row.manifest_key,'manifest_version_id',input_row.manifest_version_id,'manifest_checksum',encode(input_row.manifest_checksum,'base64'),'manifest_size_bytes',input_row.manifest_size_bytes,'manifest_media_type',input_row.manifest_media_type,'manifest_schema_version',input_row.manifest_schema_version,'parser_version',input_row.parser_version,'tool_version',input_row.tool_version,'section',section_value,'items',COALESCE(jsonb_agg(payload ORDER BY item_id),'[]'::jsonb),'next_id',CASE WHEN (SELECT count(*) FROM source)>page_limit THEN (SELECT item_id FROM visible ORDER BY item_id DESC LIMIT 1) ELSE NULL END) INTO response FROM visible;RETURN response;END $$;

CREATE FUNCTION public.zasp_execution_claim_projection_work(kind_value text,worker text,lease_token text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE response jsonb;required_role text;
BEGIN
 required_role:=CASE kind_value WHEN 'risk' THEN 'zasp_projection_risk_worker' WHEN 'graph' THEN 'zasp_projection_graph_worker' WHEN 'search' THEN 'zasp_projection_search_worker' ELSE NULL END;
 IF required_role IS NULL OR NOT pg_has_role(session_user,required_role,'MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection authority denied';END IF;
 IF length(worker) NOT BETWEEN 1 AND 128 OR length(lease_token) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 OR claim_limit NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid projection claim';END IF;
 UPDATE zasp_projection_work projection SET state='failed',last_error=COALESCE(projection.last_error,'lease expired after maximum attempts'),completed_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE projection.kind=kind_value AND projection.attempt>=5 AND projection.state='leased' AND projection.lease_expires_at<=transaction_timestamp();
 WITH organizations AS (SELECT projection.organization_id,min(projection.snapshot_id) first_snapshot FROM zasp_projection_work projection WHERE projection.kind=kind_value AND projection.attempt<5 AND projection.available_at<=transaction_timestamp() AND (projection.state IN('pending','retryable') OR projection.state='leased' AND projection.lease_expires_at<=transaction_timestamp()) AND EXISTS(SELECT 1 FROM zasp_discovery_snapshot_inputs input WHERE (input.organization_id,input.workspace_id,input.environment_id,input.snapshot_id)=(projection.organization_id,projection.workspace_id,projection.environment_id,projection.snapshot_id)) GROUP BY projection.organization_id ORDER BY first_snapshot,projection.organization_id LIMIT claim_limit),
 picked AS (SELECT chosen.ctid,chosen.organization_id,chosen.snapshot_id,chosen.kind FROM organizations organization CROSS JOIN LATERAL (SELECT projection.ctid,projection.organization_id,projection.snapshot_id,projection.kind FROM zasp_projection_work projection WHERE projection.organization_id=organization.organization_id AND projection.kind=kind_value AND projection.attempt<5 AND projection.available_at<=transaction_timestamp() AND (projection.state IN('pending','retryable') OR projection.state='leased' AND projection.lease_expires_at<=transaction_timestamp()) AND EXISTS(SELECT 1 FROM zasp_discovery_snapshot_inputs input WHERE (input.organization_id,input.workspace_id,input.environment_id,input.snapshot_id)=(projection.organization_id,projection.workspace_id,projection.environment_id,projection.snapshot_id)) ORDER BY projection.snapshot_id LIMIT 1 FOR UPDATE SKIP LOCKED) chosen),
 claimed AS (UPDATE zasp_projection_work projection SET state='leased',attempt=attempt+1,lease_owner=worker,lease_token=$3,lease_expires_at=transaction_timestamp()+make_interval(secs=>$4),completion_digest=NULL,completion_result=NULL FROM (SELECT * FROM picked ORDER BY snapshot_id,organization_id LIMIT claim_limit) selected WHERE projection.ctid=selected.ctid RETURNING projection.organization_id,projection.workspace_id,projection.environment_id,projection.snapshot_id,projection.kind,projection.version,encode(projection.input_digest,'base64') AS input_digest,projection.attempt,projection.lease_expires_at)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(to_jsonb(claimed) ORDER BY organization_id,snapshot_id),'[]'::jsonb)) INTO response FROM claimed;
 RETURN response;
END $$;

CREATE FUNCTION public.zasp_execution_heartbeat_projection(organization_value text,workspace_value text,environment_value text,snapshot_value text,kind_value text,version_value text,worker_value text,lease_token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE response jsonb;required_role text;
BEGIN
 required_role:=CASE kind_value WHEN 'risk' THEN 'zasp_projection_risk_worker' WHEN 'graph' THEN 'zasp_projection_graph_worker' WHEN 'search' THEN 'zasp_projection_search_worker' ELSE NULL END;
 IF required_role IS NULL OR NOT pg_has_role(session_user,required_role,'MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection authority denied';END IF;
 IF length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid projection heartbeat';END IF;
 UPDATE zasp_projection_work SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds)
 WHERE (organization_id,workspace_id,environment_id,snapshot_id,kind,version,state,lease_owner,lease_token)=(organization_value,workspace_value,environment_value,snapshot_value,kind_value,version_value,'leased',worker_value,lease_token_value)
   AND lease_expires_at>transaction_timestamp()
 RETURNING jsonb_build_object('id',snapshot_id,'lease_expires_at',lease_expires_at) INTO response;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='projection lease missing';END IF;
 RETURN response;
END $$;

CREATE FUNCTION public.zasp_execution_advance_projection_cursor(organization_value text,workspace_value text,environment_value text,kind_value text,snapshot_value text,generation_value bigint,input_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE current_row zasp_discovery_projection_cursors%ROWTYPE;input_row zasp_discovery_snapshot_inputs%ROWTYPE;BEGIN IF kind_value NOT IN('risk','graph','search') OR octet_length(input_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid projection cursor';END IF;SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value) FOR SHARE;IF NOT FOUND OR input_row.generation<>generation_value OR input_row.candidate_digest<>input_digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='projection input conflict';END IF;SELECT * INTO current_row FROM zasp_discovery_projection_cursors WHERE (organization_id,workspace_id,environment_id,integration_id,source,kind)=(organization_value,workspace_value,environment_value,input_row.integration_id,input_row.source,kind_value) FOR UPDATE;IF FOUND AND (current_row.generation>generation_value OR current_row.generation=generation_value AND (current_row.snapshot_id<>snapshot_value OR current_row.input_digest<>input_digest_value)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale projection cursor';END IF;INSERT INTO zasp_discovery_projection_cursors(organization_id,workspace_id,environment_id,integration_id,source,kind,generation,snapshot_id,input_digest) VALUES(organization_value,workspace_value,environment_value,input_row.integration_id,input_row.source,kind_value,generation_value,snapshot_value,input_digest_value) ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,source,kind) DO UPDATE SET generation=excluded.generation,snapshot_id=excluded.snapshot_id,input_digest=excluded.input_digest,updated_at=CASE WHEN zasp_discovery_projection_cursors.generation<excluded.generation THEN transaction_timestamp() ELSE zasp_discovery_projection_cursors.updated_at END;RETURN jsonb_build_object('integration_id',input_row.integration_id,'source',input_row.source,'kind',kind_value,'snapshot_id',snapshot_value,'generation',generation_value,'input_digest',encode(input_digest_value,'base64'));END $$;

CREATE FUNCTION public.zasp_execution_projection_status(organization_value text,workspace_value text,environment_value text,snapshot_value text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE input_row zasp_discovery_snapshot_inputs%ROWTYPE;items jsonb;
BEGIN
 SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='snapshot input missing';END IF;
 SELECT jsonb_agg(jsonb_build_object('kind',required.kind,'work_state',work.state,'work_version',work.version,'work_input_digest',encode(work.input_digest,'base64'),'attempt',work.attempt,'current_snapshot_id',cursor.snapshot_id,'current_generation',cursor.generation,'current_input_digest',CASE WHEN cursor.input_digest IS NULL THEN NULL ELSE encode(cursor.input_digest,'base64') END,'current',work.state='succeeded' AND cursor.snapshot_id=input_row.snapshot_id AND cursor.generation=input_row.generation AND cursor.input_digest=input_row.candidate_digest) ORDER BY required.kind) INTO items
 FROM unnest(ARRAY['graph','risk','search']) required(kind)
 LEFT JOIN LATERAL (SELECT state,version,input_digest,attempt FROM zasp_projection_work WHERE (organization_id,workspace_id,environment_id,snapshot_id,kind)=(organization_value,workspace_value,environment_value,snapshot_value,required.kind) ORDER BY version DESC LIMIT 1) work ON true
 LEFT JOIN zasp_discovery_projection_cursors cursor ON (cursor.organization_id,cursor.workspace_id,cursor.environment_id,cursor.integration_id,cursor.source,cursor.kind)=(organization_value,workspace_value,environment_value,input_row.integration_id,input_row.source,required.kind);
 RETURN jsonb_build_object('integration_id',input_row.integration_id,'source',input_row.source,'snapshot_id',input_row.snapshot_id,'generation',input_row.generation,'input_digest',encode(input_row.candidate_digest,'base64'),'projections',items);
END $$;

CREATE FUNCTION public.zasp_execution_finish_projection(organization_value text,workspace_value text,environment_value text,snapshot_value text,kind_value text,version_value text,worker text,lease_token_value text,outcome_value text,driver_receipt_value text,driver_digest_value bytea,last_error_value text,retry_after_seconds integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;input_row zasp_discovery_snapshot_inputs%ROWTYPE;work_row zasp_projection_work%ROWTYPE;receipt_row zasp_discovery_projection_receipts%ROWTYPE;required_role text;fresh_completion boolean;
BEGIN
 required_role:=CASE kind_value WHEN 'risk' THEN 'zasp_projection_risk_worker' WHEN 'graph' THEN 'zasp_projection_graph_worker' WHEN 'search' THEN 'zasp_projection_search_worker' ELSE NULL END;
 IF required_role IS NULL OR NOT pg_has_role(session_user,required_role,'MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection authority denied';END IF;
 SELECT * INTO work_row FROM zasp_projection_work WHERE (organization_id,workspace_id,environment_id,snapshot_id,kind,version)=(organization_value,workspace_value,environment_value,snapshot_value,kind_value,version_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='projection work missing';END IF;
 fresh_completion:=work_row.state='leased' AND work_row.lease_owner=worker AND work_row.lease_token=lease_token_value AND work_row.lease_expires_at>transaction_timestamp();
 SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value) FOR SHARE;
 IF NOT FOUND OR work_row.input_digest<>input_row.candidate_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='projection input conflict';END IF;
 IF outcome_value='succeeded' THEN
   IF length(driver_receipt_value) NOT BETWEEN 16 AND 512 OR octet_length(driver_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='projection result receipt required';END IF;
   INSERT INTO zasp_discovery_projection_receipts(organization_id,workspace_id,environment_id,snapshot_id,kind,version,integration_id,source,generation,input_digest,driver_receipt,driver_digest)
   VALUES(organization_value,workspace_value,environment_value,snapshot_value,kind_value,version_value,input_row.integration_id,input_row.source,input_row.generation,input_row.candidate_digest,driver_receipt_value,driver_digest_value)
   ON CONFLICT(organization_id,workspace_id,environment_id,snapshot_id,kind,version) DO NOTHING;
   SELECT * INTO STRICT receipt_row FROM zasp_discovery_projection_receipts WHERE (organization_id,workspace_id,environment_id,snapshot_id,kind,version)=(organization_value,workspace_value,environment_value,snapshot_value,kind_value,version_value);
   IF (receipt_row.integration_id,receipt_row.source,receipt_row.generation,receipt_row.input_digest,receipt_row.driver_receipt,receipt_row.driver_digest)<>(input_row.integration_id,input_row.source,input_row.generation,input_row.candidate_digest,driver_receipt_value,driver_digest_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='projection result receipt conflict';END IF;
 ELSE
   IF driver_receipt_value<>'' OR driver_digest_value IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unexpected projection result receipt';END IF;
 END IF;
 result:=zasp_discovery_finish_projection(organization_value,workspace_value,environment_value,snapshot_value,kind_value,version_value,worker,lease_token_value,outcome_value,last_error_value,retry_after_seconds);
 IF result->>'state'='succeeded' THEN
   IF NOT EXISTS(SELECT 1 FROM zasp_discovery_projection_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.snapshot_id,receipt.kind,receipt.version,receipt.integration_id,receipt.source,receipt.generation,receipt.input_digest)=(organization_value,workspace_value,environment_value,snapshot_value,kind_value,version_value,input_row.integration_id,input_row.source,input_row.generation,input_row.candidate_digest)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='projection result receipt missing';END IF;
   PERFORM zasp_execution_advance_projection_cursor(organization_value,workspace_value,environment_value,kind_value,snapshot_value,input_row.generation,input_row.candidate_digest);
 END IF;
 IF fresh_completion THEN PERFORM zasp_execution_bump_freshness(organization_value,workspace_value,environment_value,input_row.integration_id);END IF;
 RETURN result;
END $$;

CREATE FUNCTION public.zasp_execution_claim_outbox(topic_value text,worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE response jsonb;last_organization text;claimed_last_organization text;
BEGIN
 IF topic_value<>'discovery-jobs' OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 OR claim_limit NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution outbox claim';END IF;
 IF NOT pg_has_role(session_user,'zasp_outbox_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='outbox authority denied';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp_execution_outbox:'||topic_value,0));
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

CREATE FUNCTION public.zasp_execution_heartbeat_outbox(topic_value text,worker_value text,lease_token_value text,lease_seconds integer,expected_count integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE lease_expiration timestamptz;updated_count integer;
BEGIN
 IF topic_value<>'discovery-jobs' OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 OR expected_count NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution outbox heartbeat';END IF;
 IF NOT pg_has_role(session_user,'zasp_outbox_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='outbox authority denied';END IF;
 lease_expiration:=transaction_timestamp()+make_interval(secs=>lease_seconds);
 UPDATE zasp_discovery_outbox SET lease_expires_at=lease_expiration
 WHERE topic=topic_value AND state='leased' AND lease_owner=worker_value AND lease_token=lease_token_value AND lease_expires_at>transaction_timestamp();
 GET DIAGNOSTICS updated_count=ROW_COUNT;
 IF updated_count<>expected_count THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='outbox lease set conflict';END IF;
 RETURN jsonb_build_object('id',topic_value,'lease_expires_at',to_char(lease_expiration AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'remaining_count',updated_count);
END $$;

CREATE FUNCTION public.zasp_execution_ack_outbox(topic_value text,organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,lease_token_value text,provider_ack_value text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;remaining_count integer;
BEGIN
 IF topic_value<>'discovery-jobs' OR provider_ack_value !~ '^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution outbox acknowledgement';END IF;
 IF NOT pg_has_role(session_user,'zasp_outbox_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='outbox authority denied';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_discovery_outbox WHERE (organization_id,workspace_id,environment_id,id,topic)=(organization_value,workspace_value,environment_value,outbox_value,topic_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='outbox topic lease missing';END IF;
 result:=zasp_discovery_ack_outbox(organization_value,workspace_value,environment_value,outbox_value,worker_value,lease_token_value,provider_ack_value);
 SELECT count(*) INTO remaining_count FROM zasp_discovery_outbox WHERE topic=topic_value AND state='leased' AND lease_owner=worker_value AND lease_token=lease_token_value AND lease_expires_at>transaction_timestamp();
 RETURN result||jsonb_build_object('remaining_count',remaining_count);
END $$;

CREATE FUNCTION public.zasp_execution_retry_outbox(topic_value text,organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,lease_token_value text,retry_after_seconds integer,error_code_value text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;remaining_count integer;
BEGIN
 IF topic_value<>'discovery-jobs' OR error_code_value<>'queue_publish_unknown' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution outbox retry';END IF;
 IF NOT pg_has_role(session_user,'zasp_outbox_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='outbox authority denied';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_discovery_outbox WHERE (organization_id,workspace_id,environment_id,id,topic)=(organization_value,workspace_value,environment_value,outbox_value,topic_value)) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='outbox topic lease missing';END IF;
 result:=zasp_discovery_retry_outbox(organization_value,workspace_value,environment_value,outbox_value,worker_value,lease_token_value,retry_after_seconds,error_code_value);
 SELECT count(*) INTO remaining_count FROM zasp_discovery_outbox WHERE topic=topic_value AND state='leased' AND lease_owner=worker_value AND lease_token=lease_token_value AND lease_expires_at>transaction_timestamp();
 RETURN result||jsonb_build_object('remaining_count',remaining_count);
END $$;

CREATE FUNCTION public.zasp_execution_live_fingerprint() RETURNS text LANGUAGE sql STABLE AS $$
 WITH objects AS (
  SELECT 'table'::text kind,c.relname identity,jsonb_build_object('owner',c.relowner::regrole::text,'rls',c.relrowsecurity,'force',c.relforcerowsecurity,'acl',COALESCE((SELECT jsonb_agg(jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor),'[]'::jsonb)) definition FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_discovery_syncs','zasp_workflow_receipts'])
  UNION ALL SELECT 'column',c.relname||'.'||a.attname,jsonb_build_object('type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'default',COALESCE(pg_get_expr(d.adbin,d.adrelid,true),'')) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_discovery_syncs','zasp_workflow_receipts']) AND a.attnum>0 AND NOT a.attisdropped
  UNION ALL SELECT 'constraint',c.relname||'.'||constraint_value.conname,to_jsonb(pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value JOIN pg_class c ON c.oid=constraint_value.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (c.relname LIKE 'zasp_discovery_execution_%' OR c.relname IN('zasp_discovery_connection_subjects','zasp_discovery_job_checkpoints','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_integration_connections')) AND (constraint_value.conname LIKE 'zasp_execution_%' OR c.relname<>'zasp_integration_connections')
  UNION ALL SELECT 'index',index_class.relname,to_jsonb(pg_get_indexdef(index_value.indexrelid,0,true)) FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace n ON n.oid=table_class.relnamespace WHERE n.nspname='public' AND index_class.relname LIKE 'zasp_execution_%'
  UNION ALL SELECT 'function',p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',jsonb_build_object('owner',p.proowner::regrole::text,'security',p.prosecdef,'config',COALESCE(to_jsonb(p.proconfig),'[]'::jsonb),'acl',COALESCE((SELECT jsonb_agg(jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor),'[]'::jsonb),'body',regexp_replace(btrim(p.prosrc),E'\s+',' ','g')) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND (p.proname LIKE 'zasp_execution_%' OR p.proname IN('zasp_workflow_mutate','zasp_risk_mutate','zasp_discovery_security_ready','zasp_reference_authorization_security_ready','zasp_discovery_request_sync','zasp_discovery_claim_jobs','zasp_discovery_claim_schedules','zasp_discovery_complete_schedule','zasp_discovery_finish_job','zasp_discovery_finish_projection','zasp_discovery_apply_snapshot','zasp_complete_reference_authorization')) AND p.proname NOT IN('zasp_execution_live_fingerprint','zasp_execution_readiness','zasp_execution_security_ready')
  UNION ALL SELECT 'policy',c.relname||'.'||policy.polname,jsonb_build_object('permissive',policy.polpermissive,'command',policy.polcmd,'roles',(SELECT jsonb_agg(role.rolname ORDER BY role.rolname) FROM unnest(policy.polroles) role_oid JOIN pg_roles role ON role.oid=role_oid),'using',pg_get_expr(policy.polqual,policy.polrelid),'check',pg_get_expr(policy.polwithcheck,policy.polrelid)) FROM pg_policy policy JOIN pg_class c ON c.oid=policy.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_discovery_syncs'])
  UNION ALL SELECT 'trigger',c.relname||'.'||trigger_value.tgname,jsonb_build_object('definition',regexp_replace(pg_get_triggerdef(trigger_value.oid,true),E'\s+',' ','g'),'enabled',trigger_value.tgenabled,'function',trigger_value.tgfoid::regprocedure::text) FROM pg_trigger trigger_value JOIN pg_class c ON c.oid=trigger_value.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND trigger_value.tgname LIKE 'zasp_execution_%' AND NOT trigger_value.tgisinternal
  UNION ALL SELECT 'role',r.rolname,jsonb_build_object('login',r.rolcanlogin,'inherit',r.rolinherit,'super',r.rolsuper,'createdb',r.rolcreatedb,'createrole',r.rolcreaterole,'replication',r.rolreplication,'bypassrls',r.rolbypassrls,'managed_here',shobj_description(r.oid,'pg_authid')=ANY(ARRAY[format('zasp-managed:production-discovery-execution-v1:database:%s:created',(SELECT oid FROM pg_database WHERE datname=current_database())),format('zasp-managed:production-discovery-execution-v1:database:%s:bound',(SELECT oid FROM pg_database WHERE datname=current_database()))])) FROM pg_roles r WHERE r.rolname=ANY(ARRAY['zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker'])
 ) SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(kind,identity,definition) ORDER BY kind,identity,definition)::text,'[]'),'UTF8'),'sha256'),'hex') FROM objects
$$;

CREATE FUNCTION public.zasp_execution_security_ready() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT zasp_reference_authorization_security_ready()
 AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN('zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker') AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolinherit OR rolbypassrls))
 AND (SELECT count(*) FROM pg_roles WHERE rolname IN('zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker'))=4
 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname IN('zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker') AND NOT shobj_description(r.oid,'pg_authid')=ANY(ARRAY[format('zasp-managed:production-discovery-execution-v1:database:%s:created',(SELECT oid FROM pg_database WHERE datname=current_database())),format('zasp-managed:production-discovery-execution-v1:database:%s:bound',(SELECT oid FROM pg_database WHERE datname=current_database()))]))
 AND NOT EXISTS(
   SELECT 1 FROM pg_auth_members membership
   WHERE membership.roleid IN((SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_scheduler'),(SELECT oid FROM pg_roles WHERE rolname='zasp_projection_risk_worker'),(SELECT oid FROM pg_roles WHERE rolname='zasp_projection_graph_worker'),(SELECT oid FROM pg_roles WHERE rolname='zasp_projection_search_worker'))
     AND NOT (
       membership.member=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND membership.admin_option
       OR NOT membership.admin_option AND EXISTS(SELECT 1 FROM zasp_discovery_execution_principals principal WHERE principal.principal_name=(SELECT rolname FROM pg_roles WHERE oid=membership.member) AND principal.authority_role=(SELECT rolname FROM pg_roles WHERE oid=membership.roleid))
     )
 )
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership WHERE membership.member IN((SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_scheduler'),(SELECT oid FROM pg_roles WHERE rolname='zasp_projection_risk_worker'),(SELECT oid FROM pg_roles WHERE rolname='zasp_projection_graph_worker'),(SELECT oid FROM pg_roles WHERE rolname='zasp_projection_search_worker')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_discovery_syncs']) AND (c.relowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR (SELECT count(*) FROM pg_policy policy WHERE policy.polrelid=c.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy policy WHERE policy.polrelid=c.oid AND policy.polname=c.relname||'_authority' AND policy.polcmd='*' AND policy.polroles=ARRAY[(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority')] AND pg_get_expr(policy.polqual,policy.polrelid)='true' AND pg_get_expr(policy.polwithcheck,policy.polrelid)='true') OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl WHERE acl.grantee<>c.relowner)))
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_discovery_syncs'::regclass AND conname='zasp_discovery_syncs_version_check' AND contype='c' AND convalidated AND pg_get_constraintdef(oid,true)='CHECK (version > 0)')
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_discovery_syncs'::regclass AND conname='zasp_discovery_syncs_last_error_code_check' AND contype='c' AND convalidated AND pg_get_constraintdef(oid,true)='CHECK (last_error_code IS NULL OR (last_error_code = ANY (ARRAY[''retryable''::text, ''rate_limited''::text, ''denied''::text, ''revoked''::text, ''malformed''::text, ''partial''::text, ''terminal''::text, ''cancelled''::text, ''outcome_unknown''::text])))')
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_workflow_receipts'::regclass AND conname='zasp_workflow_receipts_resource_kind_check' AND contype='c' AND convalidated AND pg_get_constraintdef(oid,true)='CHECK (resource_kind = ANY (ARRAY[''policy''::text, ''integration''::text, ''sensor''::text, ''security_agent''::text, ''security_agent_run''::text, ''security_agent_approval''::text, ''finding''::text, ''integration_sync''::text, ''integration_schedule''::text]))')
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_execution_%' AND (
   p.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT p.prosecdef OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public']
   OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee NOT IN(p.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api'),(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_worker'),(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_scheduler'),(SELECT oid FROM pg_roles WHERE rolname='zasp_projection_risk_worker'),(SELECT oid FROM pg_roles WHERE rolname='zasp_projection_graph_worker'),(SELECT oid FROM pg_roles WHERE rolname='zasp_projection_search_worker'),(SELECT oid FROM pg_roles WHERE rolname='zasp_outbox_worker')))
   OR has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE')<>(p.proname=ANY(ARRAY['zasp_execution_complete_reference_authorization','zasp_execution_public_request_sync','zasp_execution_public_put_schedule','zasp_execution_public_delete_schedule','zasp_execution_sync_detail','zasp_execution_sync_history','zasp_execution_schedule_detail','zasp_execution_last_good_freshness','zasp_execution_principal_ready','zasp_execution_readiness','zasp_execution_security_ready']))
   OR has_function_privilege('zasp_discovery_worker',p.oid,'EXECUTE')<>(p.proname=ANY(ARRAY['zasp_execution_claim_jobs','zasp_execution_claim_delivery','zasp_execution_job_input','zasp_execution_heartbeat_job','zasp_execution_checkpoint_partial','zasp_execution_finish_job','zasp_execution_apply_complete_snapshot','zasp_execution_principal_ready','zasp_execution_readiness','zasp_execution_security_ready']))
   OR has_function_privilege('zasp_discovery_scheduler',p.oid,'EXECUTE')<>(p.proname=ANY(ARRAY['zasp_execution_claim_schedules','zasp_execution_schedule_input','zasp_execution_heartbeat_schedule','zasp_execution_request_scheduled_sync','zasp_execution_complete_schedule','zasp_execution_principal_ready','zasp_execution_readiness','zasp_execution_security_ready']))
   OR has_function_privilege('zasp_projection_risk_worker',p.oid,'EXECUTE')<>(p.proname=ANY(ARRAY['zasp_execution_claim_projection_work','zasp_execution_heartbeat_projection','zasp_execution_snapshot_projection_page','zasp_execution_projection_status','zasp_execution_finish_projection','zasp_execution_principal_ready','zasp_execution_readiness','zasp_execution_security_ready']))
   OR has_function_privilege('zasp_projection_graph_worker',p.oid,'EXECUTE')<>(p.proname=ANY(ARRAY['zasp_execution_claim_projection_work','zasp_execution_heartbeat_projection','zasp_execution_snapshot_projection_page','zasp_execution_projection_status','zasp_execution_finish_projection','zasp_execution_principal_ready','zasp_execution_readiness','zasp_execution_security_ready']))
   OR has_function_privilege('zasp_projection_search_worker',p.oid,'EXECUTE')<>(p.proname=ANY(ARRAY['zasp_execution_claim_projection_work','zasp_execution_heartbeat_projection','zasp_execution_snapshot_projection_page','zasp_execution_projection_status','zasp_execution_finish_projection','zasp_execution_principal_ready','zasp_execution_readiness','zasp_execution_security_ready']))
   OR has_function_privilege('zasp_outbox_worker',p.oid,'EXECUTE')<>(p.proname=ANY(ARRAY['zasp_execution_claim_outbox','zasp_execution_heartbeat_outbox','zasp_execution_ack_outbox','zasp_execution_retry_outbox']))))
 AND EXISTS(SELECT 1 FROM pg_trigger trigger_value JOIN pg_class c ON c.oid=trigger_value.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='zasp_connector_credentials' AND trigger_value.tgname='zasp_execution_bind_oauth_subject' AND trigger_value.tgenabled='O' AND trigger_value.tgfoid='zasp_execution_bind_oauth_subject_trigger()'::regprocedure AND NOT trigger_value.tgisinternal)
 AND EXISTS(SELECT 1 FROM pg_trigger trigger_value JOIN pg_class c ON c.oid=trigger_value.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='zasp_discovery_syncs' AND trigger_value.tgname='zasp_execution_sync_version' AND trigger_value.tgenabled='O' AND trigger_value.tgfoid='zasp_execution_sync_version_trigger()'::regprocedure AND NOT trigger_value.tgisinternal)
$$;

CREATE FUNCTION public.zasp_execution_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM zasp_schema_versions release JOIN zasp_schema_metadata marker ON marker.key='production_core_schema' AND marker.value='production-discovery-execution-v1' JOIN zasp_schema_metadata fingerprint ON fingerprint.key='production_discovery_execution_fingerprint' AND fingerprint.value=expected_fingerprint WHERE release.version=13 AND release.name='production_discovery_execution' AND release.checksum=expected_checksum AND zasp_execution_live_fingerprint()=expected_fingerprint AND zasp_execution_security_ready() AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions later WHERE later.version>13))
$$;

DO $authority$ DECLARE procedure_oid oid;BEGIN FOR procedure_oid IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_execution_%' LOOP EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway',procedure_oid::regprocedure);EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',procedure_oid::regprocedure);EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, public',procedure_oid::regprocedure);EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);END LOOP;END $authority$;

GRANT EXECUTE ON FUNCTION zasp_execution_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text),zasp_execution_public_request_sync(text,text,text,text,text,text,bigint,text,text,text,bytea,text,text,text,text,text),zasp_execution_public_put_schedule(text,text,text,text,text,text,bigint,integer,text,text,text,text),zasp_execution_public_delete_schedule(text,text,text,text,text,text,bigint,text,text,text),zasp_execution_sync_detail(text,text,text,text,text),zasp_execution_sync_history(text,text,text,text,timestamptz,text,integer),zasp_execution_schedule_detail(text,text,text,text),zasp_execution_last_good_freshness(text,text,text,text),zasp_execution_principal_ready(text),zasp_execution_readiness(text,text),zasp_execution_security_ready() TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_execution_claim_jobs(text,text,integer,integer),zasp_execution_claim_delivery(text,text,text,text,text,text,integer),zasp_execution_job_input(text,text,text,text,text,text),zasp_execution_heartbeat_job(text,text,text,text,text,text,integer),zasp_execution_checkpoint_partial(text,text,text,text,text,text,bigint,text,text,text,text,text,text,bytea,bigint,text,text,text,text),zasp_execution_finish_job(text,text,text,text,text,text,text,bytea,text,text,integer),zasp_execution_apply_complete_snapshot(text,text,text,text,text,text,text,text,text,bigint,text,text,text,text,bytea,bigint,text,text,timestamptz,text,text,text,jsonb,jsonb,jsonb),zasp_execution_principal_ready(text),zasp_execution_readiness(text,text),zasp_execution_security_ready() TO zasp_discovery_worker;
GRANT EXECUTE ON FUNCTION zasp_execution_claim_schedules(text,text,integer,integer),zasp_execution_schedule_input(text,text,text,text,text,text),zasp_execution_heartbeat_schedule(text,text,text,text,text,text,integer),zasp_execution_request_scheduled_sync(text,text,text,text,text,text,text,text,text,text,text,text,bytea,text,text),zasp_execution_complete_schedule(text,text,text,text,text,text,text,timestamptz),zasp_execution_principal_ready(text),zasp_execution_readiness(text,text),zasp_execution_security_ready() TO zasp_discovery_scheduler;
GRANT EXECUTE ON FUNCTION zasp_execution_claim_projection_work(text,text,text,integer,integer),zasp_execution_heartbeat_projection(text,text,text,text,text,text,text,text,integer),zasp_execution_snapshot_projection_page(text,text,text,text,text,text,integer),zasp_execution_projection_status(text,text,text,text),zasp_execution_finish_projection(text,text,text,text,text,text,text,text,text,text,bytea,text,integer),zasp_execution_principal_ready(text),zasp_execution_readiness(text,text),zasp_execution_security_ready() TO zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker;
GRANT EXECUTE ON FUNCTION zasp_execution_claim_outbox(text,text,text,integer,integer),zasp_execution_heartbeat_outbox(text,text,text,integer,integer),zasp_execution_ack_outbox(text,text,text,text,text,text,text,text),zasp_execution_retry_outbox(text,text,text,text,text,text,text,integer,text) TO zasp_outbox_worker;
REVOKE EXECUTE ON FUNCTION zasp_execution_register_principals(text,text,text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway;
REVOKE EXECUTE ON FUNCTION zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text),zasp_discovery_request_sync(text,text,text,text,text,text,text,text,text,bytea,text,text,text),zasp_execution_bind_connection_subject(text,text,text,text,text,text,text,text,bigint,jsonb,text),zasp_execution_request_sync(text,text,text,text,text,text,text,text,text,bytea,text,text,text) FROM zasp_discovery_api;

DO $legacy_worker_split$ DECLARE definition text;worker_clause text;function_name text;start_position integer;end_position integer;BEGIN SELECT pg_get_functiondef('public.zasp_discovery_security_ready()'::regprocedure) INTO definition;start_position:=position('has_function_privilege(''zasp_discovery_worker''' IN definition);end_position:=position('has_function_privilege(''zasp_runtime_ingest''' IN definition);IF start_position=0 OR end_position<=start_position THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy discovery worker authority shape changed';END IF;worker_clause:=substring(definition FROM start_position FOR end_position-start_position);FOREACH function_name IN ARRAY ARRAY['zasp_discovery_apply_snapshot','zasp_discovery_claim_jobs','zasp_discovery_claim_schedules','zasp_discovery_complete_schedule','zasp_discovery_claim_projection_work','zasp_discovery_finish_job','zasp_discovery_finish_projection','zasp_discovery_complete_job','zasp_discovery_complete_projection'] LOOP worker_clause:=regexp_replace(worker_clause,',\s*'''||function_name||'''(?:::text)?','','g');END LOOP;definition:=overlay(definition PLACING worker_clause FROM start_position FOR end_position-start_position);EXECUTE definition;END $legacy_worker_split$;
REVOKE EXECUTE ON FUNCTION zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb),zasp_discovery_claim_jobs(text,text,integer,integer,text),zasp_discovery_claim_schedules(text,text,integer,integer),zasp_discovery_complete_schedule(text,text,text,text,text,text,text,timestamptz),zasp_discovery_claim_projection_work(text,text,integer,integer),zasp_discovery_finish_job(text,text,text,text,text,text,text,bytea,text,integer),zasp_discovery_finish_projection(text,text,text,text,text,text,text,text,text,text,integer),zasp_discovery_complete_job(text,text,text,text,text,text,bytea,boolean,text),zasp_discovery_complete_projection(text,text,text,text,text,text,text,text,boolean) FROM zasp_discovery_worker;

DO $legacy_outbox_split$ DECLARE definition text;function_name text;BEGIN
 SELECT pg_get_functiondef('public.zasp_discovery_security_ready()'::regprocedure) INTO definition;
 FOREACH function_name IN ARRAY ARRAY['zasp_discovery_claim_outbox','zasp_discovery_ack_outbox','zasp_discovery_retry_outbox'] LOOP definition:=regexp_replace(definition,',\s*'''||function_name||'''(?:::text)?','','g');END LOOP;
 EXECUTE definition;
END $legacy_outbox_split$;
REVOKE EXECUTE ON FUNCTION zasp_discovery_claim_outbox(text,text,integer,integer),zasp_discovery_ack_outbox(text,text,text,text,text,text,text),zasp_discovery_retry_outbox(text,text,text,text,text,text,integer,text) FROM zasp_outbox_worker;

DO $legacy_api_split$ DECLARE definition text;BEGIN
 SELECT pg_get_functiondef('public.zasp_discovery_security_ready()'::regprocedure) INTO definition;
 definition:=regexp_replace(definition,',\s*''zasp_discovery_request_sync''(?:::text)?','','g');
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_reference_authorization_security_ready()'::regprocedure) INTO definition;
 definition:=regexp_replace(definition,'''zasp_complete_reference_authorization\(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text\)'',\s*','','g');
 EXECUTE definition;
END $legacy_api_split$;

-- The v12 readiness function is evaluated by the migrator before this release.
-- Reparse the composed v13 readiness chain after replacing delegated v10/v12
-- security functions so the same locked transaction observes the final ACLs.
DO $execution_readiness_reparse$ DECLARE definition text;BEGIN
 SELECT pg_get_functiondef('public.zasp_execution_security_ready()'::regprocedure) INTO definition;EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_execution_readiness(text,text)'::regprocedure) INTO definition;EXECUTE definition;
END $execution_readiness_reparse$;

WITH unbound AS (
 UPDATE zasp_discovery_jobs SET state='failed',last_error='request authority unavailable after execution upgrade',completed_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp()
 WHERE kind='discovery' AND state IN('queued','retryable','leased') AND NOT EXISTS(SELECT 1 FROM zasp_discovery_job_authorities authority WHERE (authority.organization_id,authority.workspace_id,authority.environment_id,authority.job_id)=(zasp_discovery_jobs.organization_id,zasp_discovery_jobs.workspace_id,zasp_discovery_jobs.environment_id,zasp_discovery_jobs.id)) RETURNING organization_id,workspace_id,environment_id,authority_id,attempt,last_error
) UPDATE zasp_discovery_syncs sync SET state='failed',attempt=unbound.attempt,last_error=unbound.last_error,completed_at=transaction_timestamp() FROM unbound WHERE (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id)=(unbound.organization_id,unbound.workspace_id,unbound.environment_id,unbound.authority_id) AND sync.state IN('queued','running');

INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source)
SELECT integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,connection.id,'aws','aws_account',substring(integration.configuration->>'role_arn' FROM '^arn:aws:iam::([0-9]{12}):role/'),connection.version,digest(convert_to(integration.configuration::text,'UTF8'),'sha256'),'upgrade'
FROM zasp_integrations integration JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,'aws')
WHERE integration.kind='aws' AND connection.state='verified'
  AND length(integration.configuration->>'role_arn') BETWEEN 33 AND 544
  AND integration.configuration->>'role_arn' ~ '^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$';

INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source)
SELECT integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,connection.id,integration.kind,CASE integration.kind WHEN 'github' THEN 'github_installation' ELSE 'okta_tenant' END,CASE integration.kind WHEN 'github' THEN credential.metadata->>'installation_id' ELSE credential.metadata->>'tenant' END,connection.version,digest(convert_to(integration.configuration::text,'UTF8'),'sha256'),'upgrade'
FROM zasp_integrations integration JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.kind) JOIN LATERAL (SELECT credential.* FROM zasp_connector_credentials credential WHERE (credential.organization_id,credential.workspace_id,credential.environment_id,credential.integration_id,credential.provider,credential.credential_reference)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.kind,connection.connection_reference) AND credential.status='active' ORDER BY credential.version DESC,credential.id DESC LIMIT 1) credential ON true
WHERE integration.kind IN('github','okta') AND connection.state='verified' AND zasp_execution_subject_valid(integration.kind,CASE integration.kind WHEN 'github' THEN 'github_installation' ELSE 'okta_tenant' END,CASE integration.kind WHEN 'github' THEN credential.metadata->>'installation_id' ELSE credential.metadata->>'tenant' END);

INSERT INTO zasp_discovery_upgrade_transitions(organization_id,workspace_id,environment_id,integration_id,prior_integration_state,prior_integration_version,prior_integration_updated_at,connection_id,prior_connection_state,prior_connection_version,prior_connection_verified_at,prior_connection_updated_at,prior_workflow_body,prior_workflow_version,prior_workflow_updated_at,audit_id,correlation_id)
SELECT integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.state,integration.version,integration.updated_at,connection.id,connection.state,connection.version,connection.verified_at,connection.updated_at,workflow.body,workflow.version,workflow.updated_at,'pid_'||gen_random_uuid()::text,'pid_'||gen_random_uuid()::text
FROM zasp_integrations integration JOIN zasp_workflow_records workflow ON (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.id,workflow.kind)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,'integration') JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider,connection.state)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,'kubernetes','verified')
WHERE integration.kind='kubernetes' AND integration.state='active' AND workflow.body->>'status'='active' AND workflow.version=integration.version AND connection.version=integration.version AND NOT EXISTS(SELECT 1 FROM zasp_discovery_connection_subjects subject WHERE (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id));
UPDATE zasp_integrations integration SET state='degraded',version=transition.prior_integration_version+1,updated_at=transition.transitioned_at FROM zasp_discovery_upgrade_transitions transition WHERE (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.integration_id);
UPDATE zasp_integration_connections connection SET version=transition.prior_connection_version+1,updated_at=transition.transitioned_at FROM zasp_discovery_upgrade_transitions transition WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.integration_id,transition.connection_id);
UPDATE zasp_workflow_records workflow SET body=jsonb_set(jsonb_set(transition.prior_workflow_body,'{status}','"degraded"'::jsonb),'{updated_at}',to_jsonb(to_char(transition.transitioned_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),version=transition.prior_workflow_version+1,updated_at=transition.transitioned_at FROM zasp_discovery_upgrade_transitions transition WHERE (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.id,workflow.kind)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.integration_id,'integration');
INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version)
SELECT organization_id,workspace_id,environment_id,audit_id,correlation_id,'pid_00000000-0000-4000-8000-000000000013','degradeIntegrationForExecutionUpgrade','integration',integration_id,prior_integration_version+1 FROM zasp_discovery_upgrade_transitions;

DO $release_evolution$ DECLARE definition text;BEGIN SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;definition:=replace(definition,'reference-authorization-v1','production-discovery-execution-v1');definition:=replace(definition,'release."version" = 12','release."version" = 13');definition:=replace(definition,'release."name" = ''reference_authorization''','release."name" = ''production_discovery_execution''');definition:=replace(definition,'later_release."version" > 12','later_release."version" > 13');EXECUTE definition;SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO definition;definition:=replace(definition,'reference-authorization-v1','production-discovery-execution-v1');definition:=replace(replace(definition,'release."version"=12','release."version"=13'),'release."version" = 12','release."version" = 13');definition:=replace(replace(definition,'release."name"=''reference_authorization''','release."name"=''production_discovery_execution'''),'release."name" = ''reference_authorization''','release."name" = ''production_discovery_execution''');definition:=replace(replace(definition,'later."version">12','later."version">13'),'later."version" > 12','later."version" > 13');EXECUTE definition;END $release_evolution$;

INSERT INTO zasp_schema_metadata(key,value) VALUES('production_discovery_execution_fingerprint', '7e906ab12458751184f3a452158acb90b7ad2e6de24262c3ad88f173525dd27f');
UPDATE zasp_schema_metadata SET value='production-discovery-execution-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='reference-authorization-v1';
