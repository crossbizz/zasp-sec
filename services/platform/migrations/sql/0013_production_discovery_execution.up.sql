DO $release_guard$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM zasp_schema_versions release
    JOIN zasp_schema_metadata marker ON marker.key='production_core_schema' AND marker.value='reference-authorization-v1'
    WHERE release.version=12 AND release.name='reference_authorization'
      AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions later WHERE later.version>12)
  ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='reference authorization release required'; END IF;
END $release_guard$;

DO $roles$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='zasp_discovery_scheduler') THEN CREATE ROLE zasp_discovery_scheduler NOLOGIN NOINHERIT NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='zasp_projection_worker') THEN CREATE ROLE zasp_projection_worker NOLOGIN NOINHERIT NOBYPASSRLS; END IF;
  GRANT zasp_discovery_scheduler,zasp_projection_worker TO zasp_discovery_authority WITH ADMIN OPTION;
END $roles$;

CREATE TABLE public.zasp_discovery_execution_principals (
  principal_name text NOT NULL CHECK(principal_name ~ '^[a-z][a-z0-9_]{2,62}$'),
  authority_role text NOT NULL CHECK(authority_role IN ('zasp_discovery_scheduler','zasp_discovery_worker','zasp_projection_worker')),
  registered_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(principal_name), UNIQUE(authority_role)
);

ALTER TABLE public.zasp_integration_connections ADD CONSTRAINT zasp_execution_connections_parent_unique
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,id);

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
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,source,generation),
  FOREIGN KEY(organization_id,workspace_id,environment_id,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE,
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,source,snapshot_id) REFERENCES zasp_discovery_snapshots(organization_id,workspace_id,environment_id,integration_id,source,id) ON DELETE CASCADE
);

CREATE TABLE public.zasp_discovery_projection_cursors (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  kind text NOT NULL CHECK(kind IN ('risk','graph','search')), generation bigint NOT NULL CHECK(generation>0), snapshot_id text NOT NULL,
  input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,kind),
  FOREIGN KEY(organization_id,workspace_id,environment_id,snapshot_id) REFERENCES zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,snapshot_id)
);

CREATE INDEX zasp_execution_jobs_claim_idx ON zasp_discovery_jobs(organization_id,available_at,created_at,id)
  WHERE kind='discovery' AND state IN ('queued','retryable','leased') AND attempt<5;
CREATE INDEX zasp_execution_snapshot_projection_idx ON zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,integration_id,source,generation,snapshot_id);

DO $rls$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_snapshot_inputs','zasp_discovery_projection_cursors'] LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',table_name);
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_discovery_scheduler,zasp_projection_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway',table_name);
    EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO zasp_discovery_authority',table_name);
    EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING (true) WITH CHECK (true)',table_name||'_authority',table_name);
  END LOOP;
END $rls$;

CREATE FUNCTION public.zasp_execution_subject_valid(provider_value text,kind_value text,id_value text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE provider_value
  WHEN 'aws' THEN kind_value='aws_account' AND id_value ~ '^[0-9]{12}$'
  WHEN 'kubernetes' THEN kind_value='kubernetes_cluster' AND id_value ~ '^[a-z0-9][a-z0-9.-]{0,252}/[a-z0-9][a-z0-9._-]{0,127}$' AND id_value NOT LIKE '%..%'
  WHEN 'github' THEN kind_value='github_installation' AND id_value ~ '^[1-9][0-9]{0,15}$' AND id_value::numeric<=9007199254740992
  WHEN 'okta' THEN kind_value='okta_tenant' AND id_value ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.okta\.com$'
  ELSE false END
$$;

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
  ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,connection_id) DO NOTHING;
  SELECT * INTO subject_row FROM zasp_discovery_connection_subjects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND integration_id=integration_value AND connection_id=connection_value;
  IF subject_row.provider<>provider_value OR subject_row.subject_kind<>kind_value OR subject_row.subject_id<>id_value OR subject_row.connection_version<>expected_connection_version OR subject_row.configuration_digest<>digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connection subject conflict'; END IF;
  RETURN jsonb_build_object('integration_id',integration_value,'connection_id',connection_value,'provider',provider_value,'subject_kind',kind_value,'subject_id',id_value,'connection_version',expected_connection_version,'verified_at',subject_row.verified_at);
END $$;

CREATE FUNCTION public.zasp_execution_complete_reference_authorization(
  organization_value text,workspace_value text,environment_value text,principal_value text,
  integration_value text,provider_value text,connection_value text,reference_value text,
  idempotency_value text,expected_version_value bigint,configuration_value jsonb,intent_value jsonb,
  audit_value text,correlation_value text,receipt_value text,subject_kind_value text,subject_id_value text
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result_value jsonb;connection_version_value bigint;
BEGIN
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
 IF NEW.provider NOT IN('github','okta') OR NEW.status<>'active' THEN RETURN NEW;END IF;
 kind_value:=CASE NEW.provider WHEN 'github' THEN 'github_installation' ELSE 'okta_tenant' END;
 id_value:=CASE NEW.provider WHEN 'github' THEN NEW.metadata->>'installation_id' ELSE NEW.metadata->>'tenant' END;
 IF NOT zasp_execution_subject_valid(NEW.provider,kind_value,id_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid oauth connection subject';END IF;
 SELECT * INTO STRICT integration_row FROM zasp_integrations integration WHERE (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.kind)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.integration_id,NEW.provider) FOR UPDATE;
 SELECT * INTO STRICT connection_row FROM zasp_integration_connections connection WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider,connection.connection_reference,connection.state)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.integration_id,NEW.provider,NEW.credential_reference,'verified') FOR UPDATE;
 INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source)
 VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.integration_id,connection_row.id,NEW.provider,kind_value,id_value,connection_row.version,digest(convert_to(integration_row.configuration::text,'UTF8'),'sha256'),'oauth')
 ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,connection_id) DO NOTHING;
 SELECT * INTO STRICT existing_row FROM zasp_discovery_connection_subjects subject WHERE (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id,subject.connection_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.integration_id,connection_row.id);
 IF (existing_row.provider,existing_row.subject_kind,existing_row.subject_id,existing_row.connection_version,existing_row.configuration_digest)<>(NEW.provider,kind_value,id_value,connection_row.version,digest(convert_to(integration_row.configuration::text,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='oauth connection subject conflict';END IF;
 RETURN NEW;
END $$;

CREATE TRIGGER zasp_execution_bind_oauth_subject AFTER INSERT OR UPDATE OF status,metadata,credential_reference ON zasp_connector_credentials
FOR EACH ROW EXECUTE FUNCTION zasp_execution_bind_oauth_subject_trigger();

CREATE FUNCTION public.zasp_execution_register_principals(migration_principal text,scheduler_principal text,discovery_principal text,projection_principal text) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE principals text[]:=ARRAY[scheduler_principal,discovery_principal,projection_principal];authorities text[]:=ARRAY['zasp_discovery_scheduler','zasp_discovery_worker','zasp_projection_worker'];index integer;role_value record;
BEGIN
 IF migration_principal<>session_user OR cardinality(ARRAY(SELECT DISTINCT unnest(ARRAY[migration_principal,scheduler_principal,discovery_principal,projection_principal])))<>4 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution principals'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-execution-principal-registration',0));
 FOR index IN 1..3 LOOP
   SELECT r.oid,r.rolcanlogin,r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolinherit,r.rolbypassrls INTO role_value FROM pg_roles r WHERE r.rolname=principals[index];
   IF NOT FOUND OR NOT role_value.rolcanlogin OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR NOT role_value.rolinherit OR role_value.rolbypassrls THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe execution principal'; END IF;
   EXECUTE format('GRANT %I TO %I',authorities[index],principals[index]);
   INSERT INTO zasp_discovery_execution_principals(principal_name,authority_role) VALUES(principals[index],authorities[index]) ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role WHERE zasp_discovery_execution_principals.authority_role=excluded.authority_role;
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='execution principal conflict'; END IF;
 END LOOP;
 RETURN true;
END $$;

CREATE FUNCTION public.zasp_execution_principal_ready(expected_authority text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT expected_authority IN('zasp_discovery_scheduler','zasp_discovery_worker','zasp_projection_worker')
 AND EXISTS(SELECT 1 FROM zasp_discovery_execution_principals p JOIN pg_roles r ON r.rolname=p.principal_name WHERE p.principal_name=session_user AND p.authority_role=expected_authority AND r.rolcanlogin AND r.rolinherit AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls)
 AND pg_has_role(session_user,expected_authority,'MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
$$;

CREATE FUNCTION public.zasp_execution_claim_jobs(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE response jsonb;
BEGIN
 IF length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 5 AND 900 OR claim_limit NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution claim'; END IF;
 IF NOT pg_has_role(session_user,'zasp_discovery_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='execution authority denied'; END IF;
 WITH exhausted AS (UPDATE zasp_discovery_jobs SET state='failed',last_error=COALESCE(last_error,'lease expired after maximum attempts'),completed_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE kind='discovery' AND attempt>=5 AND state='leased' AND lease_expires_at<=transaction_timestamp() RETURNING organization_id,workspace_id,environment_id,authority_id,last_error,attempt)
 UPDATE zasp_discovery_syncs sync SET state='failed',attempt=exhausted.attempt,last_error=exhausted.last_error,completed_at=transaction_timestamp() FROM exhausted WHERE (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id)=(exhausted.organization_id,exhausted.workspace_id,exhausted.environment_id,exhausted.authority_id) AND sync.state IN('queued','running');
 WITH live AS (SELECT organization_id,count(*) active FROM zasp_discovery_jobs WHERE kind='discovery' AND state='leased' AND lease_expires_at>transaction_timestamp() GROUP BY organization_id),
 organizations AS (SELECT job.organization_id,min(job.available_at) due FROM zasp_discovery_jobs job LEFT JOIN live ON live.organization_id=job.organization_id LEFT JOIN zasp_discovery_execution_quotas quota ON quota.organization_id=job.organization_id WHERE job.kind='discovery' AND job.attempt<5 AND job.available_at<=transaction_timestamp() AND (job.state IN('queued','retryable') OR job.state='leased' AND job.lease_expires_at<=transaction_timestamp()) AND COALESCE(live.active,0)<COALESCE(quota.max_active_jobs,4) GROUP BY job.organization_id ORDER BY due,job.organization_id LIMIT claim_limit),
 picked AS (SELECT chosen.ctid,chosen.organization_id,chosen.created_at,chosen.id FROM organizations organization CROSS JOIN LATERAL (SELECT job.ctid,job.organization_id,job.created_at,job.id FROM zasp_discovery_jobs job WHERE job.organization_id=organization.organization_id AND job.kind='discovery' AND job.attempt<5 AND job.available_at<=transaction_timestamp() AND (job.state IN('queued','retryable') OR job.state='leased' AND job.lease_expires_at<=transaction_timestamp()) ORDER BY job.created_at,job.id LIMIT 1 FOR UPDATE SKIP LOCKED) chosen),
 claimed AS (UPDATE zasp_discovery_jobs job SET state='leased',attempt=job.attempt+1,lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),completion_digest=NULL,completion_result=NULL,updated_at=transaction_timestamp() FROM (SELECT * FROM picked ORDER BY created_at,organization_id,id LIMIT claim_limit) selected WHERE job.ctid=selected.ctid RETURNING job.organization_id,job.workspace_id,job.environment_id,job.id,job.kind,job.authority_id,job.attempt,job.lease_expires_at)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(to_jsonb(claimed) ORDER BY organization_id,id),'[]'::jsonb)) INTO response FROM claimed;
 UPDATE zasp_discovery_syncs sync SET state='running',attempt=job.attempt,started_at=COALESCE(sync.started_at,transaction_timestamp()),last_error=NULL FROM zasp_discovery_jobs job WHERE job.kind='discovery' AND job.lease_owner=worker_value AND job.lease_token=lease_token_value AND (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id)=(job.organization_id,job.workspace_id,job.environment_id,job.authority_id) AND sync.state IN('queued','running');
 RETURN response;
END $$;

CREATE FUNCTION public.zasp_execution_job_input(organization_value text,workspace_value text,environment_value text,job_value text,worker text,lease_token_value text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('organization_id',job.organization_id,'workspace_id',job.workspace_id,'environment_id',job.environment_id,'job_id',job.id,'attempt',job.attempt,'lease_expires_at',job.lease_expires_at,'sync_id',sync.id,'integration_id',integration.id,'connection_id',connection.id,'provider',integration.kind,'collector_version','collector_v1','credential_class',CASE integration.kind WHEN 'aws' THEN 'aws_assume_role' WHEN 'kubernetes' THEN 'kubernetes_cluster' WHEN 'github' THEN 'github_installation' ELSE 'okta_refresh' END,'credential_reference',connection.connection_reference,'subject_kind',subject.subject_kind,'subject_id',subject.subject_id,'cursor_provider',cursor.provider,'cursor_version',CASE WHEN cursor.provider IS NULL THEN NULL ELSE 'cursor_v1' END,'cursor_value',cursor.cursor_value,'parser_version',sync.parser_version,'tool_version',sync.tool_version,'configuration',integration.configuration)
 INTO result FROM zasp_discovery_jobs job JOIN zasp_discovery_syncs sync ON (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id)=(job.organization_id,job.workspace_id,job.environment_id,job.authority_id) JOIN zasp_integrations integration ON (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=(sync.organization_id,sync.workspace_id,sync.environment_id,sync.integration_id) JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.kind) JOIN zasp_discovery_connection_subjects subject ON (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id,subject.connection_id)=(connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id) LEFT JOIN zasp_discovery_cursors cursor ON (cursor.organization_id,cursor.workspace_id,cursor.environment_id,cursor.integration_id,cursor.provider)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,integration.kind)
 WHERE (job.organization_id,job.workspace_id,job.environment_id,job.id)=(organization_value,workspace_value,environment_value,job_value)
   AND job.kind='discovery' AND job.state='leased' AND job.lease_owner=worker AND job.lease_token=lease_token_value AND job.lease_expires_at>transaction_timestamp()
   AND integration.state IN('active','degraded') AND connection.state='verified' AND subject.provider=integration.kind
   AND subject.connection_version=connection.version AND subject.configuration_digest=digest(convert_to(integration.configuration::text,'UTF8'),'sha256')
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

CREATE FUNCTION public.zasp_execution_claim_schedules(worker text,lease_token text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql AS $$
BEGIN IF NOT pg_has_role(session_user,'zasp_discovery_scheduler','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='scheduler authority denied'; END IF; RETURN zasp_discovery_claim_schedules(worker,lease_token,lease_seconds,claim_limit); END $$;

CREATE FUNCTION public.zasp_execution_schedule_input(organization_value text,workspace_value text,environment_value text,schedule_value text,worker text,lease_token_value text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE result jsonb;BEGIN SELECT jsonb_build_object('organization_id',schedule.organization_id,'workspace_id',schedule.workspace_id,'environment_id',schedule.environment_id,'schedule_id',schedule.id,'integration_id',schedule.integration_id,'cadence_seconds',schedule.cadence_seconds,'time_zone',schedule.time_zone,'next_run_at',schedule.next_run_at,'version',schedule.version,'lease_expires_at',schedule.lease_expires_at) INTO result FROM zasp_discovery_schedules schedule WHERE (schedule.organization_id,schedule.workspace_id,schedule.environment_id,schedule.id)=(organization_value,workspace_value,environment_value,schedule_value) AND schedule.state='enabled' AND schedule.lease_owner=worker AND schedule.lease_token=lease_token_value AND schedule.lease_expires_at>transaction_timestamp();IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule input missing';END IF;RETURN result;END $$;

CREATE FUNCTION public.zasp_execution_heartbeat_schedule(organization_value text,workspace_value text,environment_value text,schedule_value text,worker text,lease_token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE expires timestamptz;BEGIN IF lease_seconds NOT BETWEEN 5 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid schedule heartbeat';END IF;UPDATE zasp_discovery_schedules SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,schedule_value) AND state='enabled' AND lease_owner=worker AND lease_token=lease_token_value AND lease_expires_at>transaction_timestamp() RETURNING lease_expires_at INTO expires;IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule lease missing';END IF;RETURN jsonb_build_object('id',schedule_value,'lease_expires_at',expires);END $$;

CREATE FUNCTION public.zasp_execution_apply_complete_snapshot(organization_value text,workspace_value text,environment_value text,integration_value text,sync_value text,snapshot_value text,generation_value bigint,source_value text,manifest_reference_value text,manifest_key_value text,manifest_version_value text,manifest_checksum_value bytea,manifest_size_value bigint,manifest_media_value text,manifest_schema_value text,collected_value timestamptz,cursor_value text,parser_value text,tool_value text,entities_value jsonb,relationships_value jsonb,evidence_value jsonb) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;digest_value bytea;input_row zasp_discovery_snapshot_inputs%ROWTYPE;
BEGIN digest_value:=digest(convert_to(jsonb_build_object('integration_id',integration_value,'sync_id',sync_value,'snapshot_id',snapshot_value,'generation',generation_value,'source',source_value,'manifest_reference',manifest_reference_value,'manifest_key',manifest_key_value,'manifest_version_id',manifest_version_value,'manifest_checksum',encode(manifest_checksum_value,'hex'),'manifest_size_bytes',manifest_size_value,'manifest_media_type',manifest_media_value,'manifest_schema_version',manifest_schema_value,'collected_at_epoch_us',floor(extract(epoch FROM collected_value)*1000000)::bigint,'cursor',cursor_value,'parser_version',parser_value,'tool_version',tool_value,'entities',entities_value,'relationships',relationships_value,'evidence',evidence_value)::text,'UTF8'),'sha256');
 result:=zasp_discovery_apply_snapshot(organization_value,workspace_value,environment_value,integration_value,sync_value,snapshot_value,generation_value,source_value,manifest_reference_value,manifest_checksum_value,collected_value,source_value,cursor_value,entities_value,relationships_value,evidence_value);
 INSERT INTO zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,generation,candidate_digest,manifest_reference,manifest_key,manifest_version_id,manifest_checksum,manifest_size_bytes,manifest_media_type,manifest_schema_version,parser_version,tool_version,entities,relationships,evidence)
 VALUES(organization_value,workspace_value,environment_value,snapshot_value,integration_value,source_value,generation_value,digest_value,manifest_reference_value,manifest_key_value,manifest_version_value,manifest_checksum_value,manifest_size_value,manifest_media_value,manifest_schema_value,parser_value,tool_value,entities_value,relationships_value,evidence_value) ON CONFLICT(organization_id,workspace_id,environment_id,snapshot_id) DO NOTHING;
 SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value);
 IF input_row.candidate_digest<>digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='snapshot input replay conflict';END IF;
 RETURN result||jsonb_build_object('candidate_digest',encode(digest_value,'base64'),'manifest_version_id',manifest_version_value);
END $$;

CREATE FUNCTION public.zasp_execution_snapshot_projection_page(organization_value text,workspace_value text,environment_value text,snapshot_value text,section_value text,after_id text,page_limit integer) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE input_row zasp_discovery_snapshot_inputs%ROWTYPE;items jsonb;response jsonb;BEGIN IF section_value NOT IN('entities','relationships','evidence') OR page_limit NOT BETWEEN 1 AND 500 OR after_id IS NOT NULL AND NOT zasp_valid_product_id(after_id) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid projection page';END IF;SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value);IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='snapshot input missing';END IF;WITH source AS (SELECT value FROM jsonb_array_elements(CASE section_value WHEN 'entities' THEN input_row.entities WHEN 'relationships' THEN input_row.relationships ELSE input_row.evidence END) value WHERE after_id IS NULL OR value->>'id'>after_id ORDER BY value->>'id' LIMIT page_limit+1),visible AS (SELECT value FROM source ORDER BY value->>'id' LIMIT page_limit) SELECT jsonb_build_object('snapshot_id',snapshot_value,'integration_id',input_row.integration_id,'source',input_row.source,'generation',input_row.generation,'candidate_digest',encode(input_row.candidate_digest,'base64'),'manifest_reference',input_row.manifest_reference,'manifest_key',input_row.manifest_key,'manifest_version_id',input_row.manifest_version_id,'manifest_checksum',encode(input_row.manifest_checksum,'base64'),'manifest_size_bytes',input_row.manifest_size_bytes,'manifest_media_type',input_row.manifest_media_type,'manifest_schema_version',input_row.manifest_schema_version,'parser_version',input_row.parser_version,'tool_version',input_row.tool_version,'section',section_value,'items',COALESCE(jsonb_agg(value ORDER BY value->>'id'),'[]'::jsonb),'next_id',CASE WHEN (SELECT count(*) FROM source)>page_limit THEN (SELECT value->>'id' FROM visible ORDER BY value->>'id' DESC LIMIT 1) ELSE NULL END) INTO response FROM visible;RETURN response;END $$;

CREATE FUNCTION public.zasp_execution_claim_projection_work(worker text,lease_token text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql AS $$
BEGIN IF NOT pg_has_role(session_user,'zasp_projection_worker','MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='projection authority denied'; END IF;RETURN zasp_discovery_claim_projection_work(worker,lease_token,lease_seconds,claim_limit);END $$;

CREATE FUNCTION public.zasp_execution_advance_projection_cursor(organization_value text,workspace_value text,environment_value text,kind_value text,snapshot_value text,generation_value bigint,input_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE current_row zasp_discovery_projection_cursors%ROWTYPE;input_row zasp_discovery_snapshot_inputs%ROWTYPE;BEGIN IF kind_value NOT IN('risk','graph','search') OR octet_length(input_digest_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid projection cursor';END IF;SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value) FOR SHARE;IF NOT FOUND OR input_row.generation<>generation_value OR input_row.candidate_digest<>input_digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='projection input conflict';END IF;SELECT * INTO current_row FROM zasp_discovery_projection_cursors WHERE (organization_id,workspace_id,environment_id,kind)=(organization_value,workspace_value,environment_value,kind_value) FOR UPDATE;IF FOUND AND (current_row.generation>generation_value OR current_row.generation=generation_value AND (current_row.snapshot_id<>snapshot_value OR current_row.input_digest<>input_digest_value)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale projection cursor';END IF;INSERT INTO zasp_discovery_projection_cursors(organization_id,workspace_id,environment_id,kind,generation,snapshot_id,input_digest) VALUES(organization_value,workspace_value,environment_value,kind_value,generation_value,snapshot_value,input_digest_value) ON CONFLICT(organization_id,workspace_id,environment_id,kind) DO UPDATE SET generation=excluded.generation,snapshot_id=excluded.snapshot_id,input_digest=excluded.input_digest,updated_at=CASE WHEN zasp_discovery_projection_cursors.generation<excluded.generation THEN transaction_timestamp() ELSE zasp_discovery_projection_cursors.updated_at END;RETURN jsonb_build_object('kind',kind_value,'snapshot_id',snapshot_value,'generation',generation_value,'input_digest',encode(input_digest_value,'base64'));END $$;

CREATE FUNCTION public.zasp_execution_finish_projection(organization_value text,workspace_value text,environment_value text,snapshot_value text,kind_value text,version_value text,worker text,lease_token_value text,outcome_value text,last_error_value text,retry_after_seconds integer) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;input_row zasp_discovery_snapshot_inputs%ROWTYPE;BEGIN result:=zasp_discovery_finish_projection(organization_value,workspace_value,environment_value,snapshot_value,kind_value,version_value,worker,lease_token_value,outcome_value,last_error_value,retry_after_seconds);IF result->>'state'='succeeded' THEN SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,snapshot_id)=(organization_value,workspace_value,environment_value,snapshot_value);PERFORM zasp_execution_advance_projection_cursor(organization_value,workspace_value,environment_value,kind_value,snapshot_value,input_row.generation,input_row.candidate_digest);END IF;RETURN result;END $$;

CREATE FUNCTION public.zasp_execution_live_fingerprint() RETURNS text LANGUAGE sql STABLE AS $$
 WITH objects AS (
  SELECT 'table'::text kind,c.relname identity,jsonb_build_object('owner',c.relowner::regrole::text,'rls',c.relrowsecurity,'force',c.relforcerowsecurity) definition FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_snapshot_inputs','zasp_discovery_projection_cursors'])
  UNION ALL SELECT 'column',c.relname||'.'||a.attnum||'.'||a.attname,jsonb_build_object('type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'default',COALESCE(pg_get_expr(d.adbin,d.adrelid,true),'')) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_snapshot_inputs','zasp_discovery_projection_cursors']) AND a.attnum>0 AND NOT a.attisdropped
  UNION ALL SELECT 'constraint',c.relname||'.'||constraint_value.conname,to_jsonb(pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value JOIN pg_class c ON c.oid=constraint_value.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (c.relname LIKE 'zasp_discovery_execution_%' OR c.relname IN('zasp_discovery_connection_subjects','zasp_discovery_snapshot_inputs','zasp_discovery_projection_cursors','zasp_integration_connections')) AND (constraint_value.conname LIKE 'zasp_execution_%' OR c.relname<>'zasp_integration_connections')
  UNION ALL SELECT 'index',index_class.relname,to_jsonb(pg_get_indexdef(index_value.indexrelid,0,true)) FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace n ON n.oid=table_class.relnamespace WHERE n.nspname='public' AND index_class.relname LIKE 'zasp_execution_%'
  UNION ALL SELECT 'function',p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',jsonb_build_object('owner',p.proowner::regrole::text,'security',p.prosecdef,'config',COALESCE(to_jsonb(p.proconfig),'[]'::jsonb),'body',regexp_replace(btrim(p.prosrc),E'\s+',' ','g')) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_execution_%' AND p.proname NOT IN('zasp_execution_live_fingerprint','zasp_execution_readiness','zasp_execution_security_ready')
  UNION ALL SELECT 'trigger',c.relname||'.'||trigger_value.tgname,jsonb_build_object('definition',regexp_replace(pg_get_triggerdef(trigger_value.oid,true),E'\s+',' ','g'),'enabled',trigger_value.tgenabled,'function',trigger_value.tgfoid::regprocedure::text) FROM pg_trigger trigger_value JOIN pg_class c ON c.oid=trigger_value.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND trigger_value.tgname='zasp_execution_bind_oauth_subject' AND NOT trigger_value.tgisinternal
 ) SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(kind,identity,definition) ORDER BY kind,identity)::text,'[]'),'UTF8'),'sha256'),'hex') FROM objects
$$;

CREATE FUNCTION public.zasp_execution_security_ready() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT zasp_reference_authorization_security_ready()
 AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_discovery_scheduler' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
 AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_projection_worker' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_snapshot_inputs','zasp_discovery_projection_cursors']) AND (c.relowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl WHERE acl.grantee<>c.relowner)))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_execution_%' AND (p.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT p.prosecdef OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee NOT IN(p.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api'),(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_worker'),(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_scheduler'),(SELECT oid FROM pg_roles WHERE rolname='zasp_projection_worker')))))
 AND EXISTS(SELECT 1 FROM pg_trigger trigger_value JOIN pg_class c ON c.oid=trigger_value.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='zasp_connector_credentials' AND trigger_value.tgname='zasp_execution_bind_oauth_subject' AND trigger_value.tgenabled='O' AND trigger_value.tgfoid='zasp_execution_bind_oauth_subject_trigger()'::regprocedure AND NOT trigger_value.tgisinternal)
$$;

CREATE FUNCTION public.zasp_execution_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM zasp_schema_versions release JOIN zasp_schema_metadata marker ON marker.key='production_core_schema' AND marker.value='production-discovery-execution-v1' JOIN zasp_schema_metadata fingerprint ON fingerprint.key='production_discovery_execution_fingerprint' AND fingerprint.value=expected_fingerprint WHERE release.version=13 AND release.name='production_discovery_execution' AND release.checksum=expected_checksum AND zasp_execution_live_fingerprint()=expected_fingerprint AND zasp_execution_security_ready() AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions later WHERE later.version>13))
$$;

DO $authority$ DECLARE procedure_oid oid;BEGIN FOR procedure_oid IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_execution_%' LOOP EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_discovery_scheduler,zasp_projection_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway',procedure_oid::regprocedure);EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',procedure_oid::regprocedure);EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, public',procedure_oid::regprocedure);EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);END LOOP;END $authority$;

GRANT EXECUTE ON FUNCTION zasp_execution_bind_connection_subject(text,text,text,text,text,text,text,text,bigint,jsonb,text),zasp_execution_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text),zasp_execution_principal_ready(text),zasp_execution_readiness(text,text),zasp_execution_security_ready() TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_execution_claim_jobs(text,text,integer,integer),zasp_execution_job_input(text,text,text,text,text,text),zasp_execution_heartbeat_job(text,text,text,text,text,text,integer),zasp_execution_apply_complete_snapshot(text,text,text,text,text,text,bigint,text,text,text,text,bytea,bigint,text,text,timestamptz,text,text,text,jsonb,jsonb,jsonb),zasp_execution_principal_ready(text),zasp_execution_readiness(text,text),zasp_execution_security_ready() TO zasp_discovery_worker;
GRANT EXECUTE ON FUNCTION zasp_execution_claim_schedules(text,text,integer,integer),zasp_execution_schedule_input(text,text,text,text,text,text),zasp_execution_heartbeat_schedule(text,text,text,text,text,text,integer),zasp_execution_principal_ready(text),zasp_execution_readiness(text,text),zasp_execution_security_ready() TO zasp_discovery_scheduler;
GRANT EXECUTE ON FUNCTION zasp_execution_claim_projection_work(text,text,integer,integer),zasp_execution_snapshot_projection_page(text,text,text,text,text,text,integer),zasp_execution_advance_projection_cursor(text,text,text,text,text,bigint,bytea),zasp_execution_finish_projection(text,text,text,text,text,text,text,text,text,text,integer),zasp_execution_principal_ready(text),zasp_execution_readiness(text,text),zasp_execution_security_ready() TO zasp_projection_worker;
REVOKE EXECUTE ON FUNCTION zasp_execution_register_principals(text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_discovery_scheduler,zasp_projection_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway;

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

UPDATE zasp_integrations integration SET state='degraded',updated_at=transaction_timestamp() WHERE integration.kind='kubernetes' AND integration.state='active' AND EXISTS(SELECT 1 FROM zasp_integration_connections connection WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,'kubernetes') AND connection.state='verified') AND NOT EXISTS(SELECT 1 FROM zasp_discovery_connection_subjects subject WHERE (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id));
UPDATE zasp_workflow_records workflow SET body=jsonb_set(jsonb_set(body,'{status}','"degraded"'::jsonb),'{updated_at}',to_jsonb(to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),updated_at=transaction_timestamp() FROM zasp_integrations integration WHERE workflow.kind='integration' AND (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.id)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id) AND integration.kind='kubernetes' AND integration.state='degraded' AND workflow.body->>'status'='active';

DO $release_evolution$ DECLARE definition text;BEGIN SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;definition:=replace(definition,'reference-authorization-v1','production-discovery-execution-v1');definition:=replace(definition,'release."version" = 12','release."version" = 13');definition:=replace(definition,'release."name" = ''reference_authorization''','release."name" = ''production_discovery_execution''');definition:=replace(definition,'later_release."version" > 12','later_release."version" > 13');EXECUTE definition;SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO definition;definition:=replace(definition,'reference-authorization-v1','production-discovery-execution-v1');definition:=replace(replace(definition,'release."version"=12','release."version"=13'),'release."version" = 12','release."version" = 13');definition:=replace(replace(definition,'release."name"=''reference_authorization''','release."name"=''production_discovery_execution'''),'release."name" = ''reference_authorization''','release."name" = ''production_discovery_execution''');definition:=replace(replace(definition,'later."version">12','later."version">13'),'later."version" > 12','later."version" > 13');EXECUTE definition;END $release_evolution$;

INSERT INTO zasp_schema_metadata(key,value) VALUES('production_discovery_execution_fingerprint', '8a464c61b9d914a887a868f04a286f09589efd0d1f578c98c465d63f7ea11491');
UPDATE zasp_schema_metadata SET value='production-discovery-execution-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='reference-authorization-v1';
