-- Release v11: durable first-party and isolated long-tail connector authorization.
CREATE OR REPLACE FUNCTION "public"."zasp_reference_only"(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT jsonb_typeof(value)='object'
       AND octet_length(value::text)<=16384
       AND (NOT value ? 'signing_secret_reference'
            OR jsonb_typeof(value->'signing_secret_reference')='string'
               AND length(value->>'signing_secret_reference') BETWEEN 12 AND 256
               AND value->>'signing_secret_reference' ~ '^secret_ref_[A-Za-z0-9][A-Za-z0-9._:/-]{0,244}$')
       AND (value-'signing_secret_reference')::text !~* '"[^"]*(secret|password|token|credential|private.?key|session)[^"]*"[[:space:]]*:'
$$;

CREATE OR REPLACE FUNCTION "public"."zasp_discovery_readiness"(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE AS $$
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
REVOKE ALL ON FUNCTION zasp_discovery_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway;
ALTER FUNCTION zasp_discovery_readiness(text,text) SECURITY DEFINER;
ALTER FUNCTION zasp_discovery_readiness(text,text) SET search_path TO pg_catalog, public;
ALTER FUNCTION zasp_discovery_readiness(text,text) OWNER TO zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_discovery_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway;

CREATE FUNCTION "public"."zasp_connector_provider_valid"(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT value IN ('aws','kubernetes','github','okta') OR value ~ '^nango:[a-z0-9][a-z0-9_-]{1,62}$'
$$;

CREATE FUNCTION "public"."zasp_connector_scopes_valid"(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE item jsonb;
BEGIN
  IF jsonb_typeof(value)<>'array' OR jsonb_array_length(value) NOT BETWEEN 1 AND 32 OR octet_length(value::text)>4096 THEN RETURN false; END IF;
  FOR item IN SELECT element.scope_value FROM jsonb_array_elements(value) AS element(scope_value) LOOP
    IF jsonb_typeof(item)<>'string' OR length(item#>>'{}') NOT BETWEEN 1 AND 128 OR item#>>'{}' !~ '^[A-Za-z0-9:_./-]+$' THEN RETURN false; END IF;
  END LOOP;
  RETURN true;
END $$;

CREATE FUNCTION "public"."zasp_connector_metadata_only"(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT jsonb_typeof(value)='object' AND octet_length(value::text)<=16384
    AND value::text !~* '"[^"]*(secret|password|access.?token|refresh.?token|private.?key|pkce.?verifier|authorization.?code)[^"]*"[[:space:]]*:'
    AND value::text !~* '(Bearer[[:space:]]|gh[pousr]_[A-Za-z0-9]|-----BEGIN[[:space:]])'
$$;

CREATE TABLE "public"."zasp_connector_oauth_attempts" (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL,
  provider text NOT NULL CHECK(provider IN ('github','okta') OR provider ~ '^nango:[a-z0-9][a-z0-9_-]{1,62}$'),
  principal_id text NOT NULL CHECK(zasp_valid_product_id(principal_id)), session_digest bytea NOT NULL CHECK(octet_length(session_digest)=32),
  state_hash bytea NOT NULL CHECK(octet_length(state_hash)=32), pkce_verifier_reference text NOT NULL CHECK(length(pkce_verifier_reference) BETWEEN 12 AND 512 AND pkce_verifier_reference ~ '^ref:[a-z0-9][a-z0-9_./:-]+$'),
  request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32), integration_version bigint NOT NULL CHECK(integration_version BETWEEN 1 AND 1000000), configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32), completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32), requested_scopes jsonb NOT NULL CHECK(zasp_connector_scopes_valid(requested_scopes)),
  return_path text NOT NULL DEFAULT '/connectors' CHECK(return_path='/connectors'),
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','consuming','succeeded','rejected','expired')),
  expires_at timestamptz NOT NULL, consumed_at timestamptz, completed_at timestamptz, connection_id text,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(state_hash),
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,connection_id) REFERENCES zasp_integration_connections(organization_id,workspace_id,environment_id,id),
  CHECK(expires_at>created_at AND expires_at<=created_at+interval '10 minutes'),
  CHECK((status='pending')=(consumed_at IS NULL AND completed_at IS NULL) OR status<>'pending'),
  CHECK(status<>'succeeded' OR (consumed_at IS NOT NULL AND completed_at IS NOT NULL AND connection_id IS NOT NULL))
);
CREATE INDEX zasp_connector_oauth_expiry_idx ON zasp_connector_oauth_attempts(status,expires_at,id);
CREATE UNIQUE INDEX zasp_connector_oauth_active_idx ON zasp_connector_oauth_attempts(organization_id,workspace_id,environment_id,integration_id,provider) WHERE status IN('pending','consuming');

CREATE TABLE "public"."zasp_connector_effects" (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL, oauth_attempt_id text,
  provider text NOT NULL CHECK(zasp_connector_provider_valid(provider)), operation text NOT NULL CHECK(operation IN ('authorize','bind','test','rotate','revoke','pkce_cleanup','nango_connect')),
  idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128), request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','unknown','succeeded','failed','reconciled')),
  connection_reference text CHECK(connection_reference IS NULL OR length(connection_reference) BETWEEN 12 AND 512 AND connection_reference ~ '^ref:[a-z0-9][a-z0-9_./:-]+$'),
  provider_subject text CHECK(provider_subject IS NULL OR length(provider_subject) BETWEEN 1 AND 256), metadata jsonb NOT NULL DEFAULT '{}' CHECK(zasp_connector_metadata_only(metadata)),
  attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100), last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{2,63}$'),
  lease_owner text, lease_token text, lease_expires_at timestamptz,
  available_at timestamptz NOT NULL DEFAULT transaction_timestamp(), created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(), resolved_at timestamptz,
  PRIMARY KEY(organization_id,workspace_id,environment_id,id),
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,provider,operation,idempotency_key),
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,oauth_attempt_id) REFERENCES zasp_connector_oauth_attempts(organization_id,workspace_id,environment_id,integration_id,id),
  CHECK((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (status='unknown' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at>updated_at)),
  CHECK((status IN ('succeeded','failed','reconciled'))=(resolved_at IS NOT NULL)),
  CHECK(status NOT IN ('succeeded','reconciled') OR operation='pkce_cleanup' AND connection_reference IS NOT NULL AND last_error_code IS NULL OR (connection_reference IS NOT NULL AND provider_subject IS NOT NULL AND last_error_code IS NULL)),
  CHECK(status<>'failed' OR last_error_code IS NOT NULL)
);
CREATE INDEX zasp_connector_effect_reconcile_idx ON zasp_connector_effects(updated_at,id) WHERE status='unknown';

CREATE TABLE "public"."zasp_connector_credentials" (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL,
  provider text NOT NULL CHECK(zasp_connector_provider_valid(provider)), credential_class text NOT NULL CHECK(credential_class IN ('aws_external_id','kubernetes_cluster_reference','github_app_reference','github_installation_reference','okta_refresh_reference','nango_connection_reference')),
  credential_reference text NOT NULL CHECK(length(credential_reference) BETWEEN 12 AND 512 AND credential_reference ~ '^ref:[a-z0-9][a-z0-9_./:-]+$'),
  version bigint NOT NULL CHECK(version BETWEEN 1 AND 1000000), status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','rotated','revoked','expired')),
  metadata jsonb NOT NULL DEFAULT '{}' CHECK(zasp_connector_metadata_only(metadata)), expires_at timestamptz, rotated_from_id text,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(), revoked_at timestamptz,
  PRIMARY KEY(organization_id,workspace_id,environment_id,id),
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,provider,credential_class,version),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,rotated_from_id) REFERENCES zasp_connector_credentials(organization_id,workspace_id,environment_id,id),
  CHECK(rotated_from_id IS NULL OR rotated_from_id<>id), CHECK(expires_at IS NULL OR expires_at>created_at), CHECK((status='revoked')=(revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX zasp_connector_credential_active_idx ON zasp_connector_credentials(organization_id,workspace_id,environment_id,integration_id,provider,credential_class) WHERE status='active';

CREATE TABLE "public"."zasp_connector_audit" (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL, oauth_attempt_id text, effect_id text,
  event_kind text NOT NULL CHECK(event_kind IN ('authorization_started','authorization_consumed','authorization_completed','authorization_rejected','effect_unknown','effect_resolved','credential_created','credential_rotated','credential_revoked','revocation_requested','revocation_completed','pkce_cleanup_started','pkce_cleanup_completed','pkce_cleanup_quarantined','quarantine_remediated')),
  principal_id text CHECK(principal_id IS NULL OR zasp_valid_product_id(principal_id)), reason_code text CHECK(reason_code IS NULL OR reason_code ~ '^[a-z][a-z0-9_]{2,63}$'),
  metadata jsonb NOT NULL DEFAULT '{}' CHECK(zasp_connector_metadata_only(metadata)), occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,oauth_attempt_id) REFERENCES zasp_connector_oauth_attempts(organization_id,workspace_id,environment_id,integration_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,effect_id) REFERENCES zasp_connector_effects(organization_id,workspace_id,environment_id,id)
);

CREATE FUNCTION "public"."zasp_connector_audit_event"(organization_value text,workspace_value text,environment_value text,integration_value text,attempt_value text,effect_value text,event_value text,principal_value text,reason_value text,metadata_value jsonb) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE audit_value text; existing zasp_connector_audit%ROWTYPE;
BEGIN
  audit_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'connector_audit',concat_ws(chr(31),integration_value,COALESCE(attempt_value,''),COALESCE(effect_value,''),event_value,COALESCE(reason_value,'')));
  INSERT INTO zasp_connector_audit(organization_id,workspace_id,environment_id,id,integration_id,oauth_attempt_id,effect_id,event_kind,principal_id,reason_code,metadata)
  VALUES(organization_value,workspace_value,environment_value,audit_value,integration_value,NULLIF(attempt_value,''),NULLIF(effect_value,''),event_value,NULLIF(principal_value,''),NULLIF(reason_value,''),metadata_value)
  ON CONFLICT(organization_id,workspace_id,environment_id,id) DO NOTHING;
  SELECT * INTO existing FROM zasp_connector_audit WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=audit_value;
  IF NOT FOUND OR existing.integration_id<>integration_value OR existing.oauth_attempt_id IS DISTINCT FROM NULLIF(attempt_value,'') OR existing.effect_id IS DISTINCT FROM NULLIF(effect_value,'') OR existing.event_kind<>event_value OR existing.principal_id IS DISTINCT FROM NULLIF(principal_value,'') OR existing.reason_code IS DISTINCT FROM NULLIF(reason_value,'') OR existing.metadata<>metadata_value THEN
    RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector audit conflict';
  END IF;
END $$;

GRANT SELECT,INSERT,UPDATE,DELETE ON zasp_workflow_records,zasp_workflow_idempotency,zasp_workflow_audit,zasp_workflow_receipts TO zasp_discovery_authority;

CREATE FUNCTION "public"."zasp_connector_workflow_mutate"(
  mutation text, requested_kind text, requested_id text,
  requested_organization_id text, requested_workspace_id text, requested_environment_id text,
  requested_principal_id text, requested_operation text, requested_idempotency_key text,
  expected_version bigint, requested_intent jsonb, requested_body jsonb, requested_audit_id text,
  requested_correlation_id text, requested_receipt_id text
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  mutation_response jsonb;
  connector_key text;
  display_name_value text;
  configuration_value jsonb;
  response_version bigint;
  typed_row zasp_integrations%ROWTYPE;
  workflow_row zasp_workflow_records%ROWTYPE;
  connection_row zasp_integration_connections%ROWTYPE;
  credential_row zasp_connector_credentials%ROWTYPE;
  revocation_effect_id text;
  revocation_digest bytea;
BEGIN
	IF requested_kind<>'integration' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='connector workflow kind rejected';
	END IF;
	IF mutation='delete' THEN
		SELECT * INTO workflow_row FROM zasp_workflow_records WHERE organization_id=requested_organization_id AND workspace_id=requested_workspace_id AND environment_id=requested_environment_id AND kind='integration' AND id=requested_id AND deleted_at IS NULL FOR UPDATE;
		IF EXISTS(SELECT 1 FROM zasp_connector_oauth_attempts WHERE organization_id=requested_organization_id AND workspace_id=requested_workspace_id AND environment_id=requested_environment_id AND integration_id=requested_id AND status IN('pending','consuming'))
		  OR EXISTS(SELECT 1 FROM zasp_connector_effects WHERE organization_id=requested_organization_id AND workspace_id=requested_workspace_id AND environment_id=requested_environment_id AND integration_id=requested_id AND operation='authorize' AND status IN('pending','unknown')) THEN
			RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector authorization unresolved';
		END IF;
    SELECT * INTO connection_row FROM zasp_integration_connections WHERE organization_id=requested_organization_id AND workspace_id=requested_workspace_id AND environment_id=requested_environment_id AND integration_id=requested_id AND state='verified' ORDER BY id LIMIT 1 FOR UPDATE;
    SELECT * INTO credential_row FROM zasp_connector_credentials WHERE organization_id=requested_organization_id AND workspace_id=requested_workspace_id AND environment_id=requested_environment_id AND integration_id=requested_id AND status='active' ORDER BY id LIMIT 1 FOR UPDATE;
    IF workflow_row.id IS NOT NULL AND (connection_row.id IS NOT NULL OR credential_row.id IS NOT NULL) THEN
      mutation_response:=zasp_workflow_mutate(
        'update',requested_kind,requested_id,requested_organization_id,requested_workspace_id,requested_environment_id,
        requested_principal_id,requested_operation,requested_idempotency_key,expected_version,requested_intent,
        jsonb_set(workflow_row.body,'{status}','"revoking"'::jsonb),requested_audit_id,requested_correlation_id,requested_receipt_id
      );
      revocation_effect_id:=zasp_discovery_canonical_id(requested_organization_id,requested_workspace_id,requested_environment_id,'connector_effect','revoke'||chr(31)||requested_id||chr(31)||requested_idempotency_key);
      revocation_digest:=digest(convert_to(jsonb_build_object('integration_id',requested_id,'provider',COALESCE(connection_row.provider,credential_row.provider),'connection_reference',COALESCE(connection_row.connection_reference,credential_row.credential_reference),'credential_version',credential_row.version)::text,'UTF8'),'sha256');
      PERFORM zasp_connector_begin_effect(requested_organization_id,requested_workspace_id,requested_environment_id,revocation_effect_id,requested_id,'',COALESCE(connection_row.provider,credential_row.provider),'revoke',requested_idempotency_key,revocation_digest);
      PERFORM zasp_connector_resolve_effect(requested_organization_id,requested_workspace_id,requested_environment_id,revocation_effect_id,'unknown',COALESCE(connection_row.connection_reference,credential_row.credential_reference),'{}'::jsonb,'revocation_requested');
      UPDATE zasp_integrations SET state='degraded',version=GREATEST(version,(mutation_response->>'version')::bigint),updated_at=transaction_timestamp() WHERE organization_id=requested_organization_id AND workspace_id=requested_workspace_id AND environment_id=requested_environment_id AND id=requested_id AND state<>'deleted';
      PERFORM zasp_connector_audit_event(requested_organization_id,requested_workspace_id,requested_environment_id,requested_id,'',revocation_effect_id,'revocation_requested',requested_principal_id,'','{}'::jsonb);
      RETURN mutation_response;
    END IF;
  END IF;
  mutation_response:=zasp_workflow_mutate(
    mutation,requested_kind,requested_id,requested_organization_id,requested_workspace_id,requested_environment_id,
    requested_principal_id,requested_operation,requested_idempotency_key,expected_version,requested_intent,
    requested_body,requested_audit_id,requested_correlation_id,requested_receipt_id
  );
  IF mutation='delete' THEN
    UPDATE zasp_integrations SET state='deleted',deleted_at=COALESCE(deleted_at,transaction_timestamp()),
      version=GREATEST(version,(mutation_response->>'version')::bigint),updated_at=CASE WHEN state='deleted' THEN updated_at ELSE transaction_timestamp() END
    WHERE organization_id=requested_organization_id AND workspace_id=requested_workspace_id AND environment_id=requested_environment_id
      AND id=requested_id AND state<>'deleted';
    IF NOT FOUND AND NOT EXISTS(SELECT 1 FROM zasp_integrations WHERE organization_id=requested_organization_id AND workspace_id=requested_workspace_id AND environment_id=requested_environment_id AND id=requested_id AND state='deleted') THEN
      RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='typed integration unavailable';
    END IF;
    RETURN mutation_response;
  END IF;
  connector_key:=requested_body->>'connector_key';
  display_name_value:=requested_body->>'name';
  configuration_value:=requested_body->'configuration';
  response_version:=(mutation_response->>'version')::bigint;
  IF connector_key IS NULL OR length(connector_key) NOT BETWEEN 1 AND 64 OR display_name_value IS NULL OR length(display_name_value) NOT BETWEEN 1 AND 128
    OR jsonb_typeof(configuration_value)<>'object' OR NOT zasp_reference_only(configuration_value) OR response_version<1 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed integration';
  END IF;
  IF mutation='create' THEN
    PERFORM zasp_discovery_create_integration(requested_organization_id,requested_workspace_id,requested_environment_id,requested_id,connector_key,'1.0.0',display_name_value,configuration_value,NULL);
  ELSIF mutation='update' THEN
    SELECT * INTO typed_row FROM zasp_integrations WHERE organization_id=requested_organization_id AND workspace_id=requested_workspace_id
      AND environment_id=requested_environment_id AND id=requested_id FOR UPDATE;
    IF NOT FOUND OR typed_row.kind<>connector_key OR typed_row.state='deleted' THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='typed integration conflict';
    END IF;
    IF typed_row.display_name<>display_name_value OR typed_row.configuration<>configuration_value OR typed_row.version<>response_version THEN
      UPDATE zasp_integrations SET display_name=display_name_value,configuration=configuration_value,version=response_version,updated_at=transaction_timestamp()
      WHERE organization_id=requested_organization_id AND workspace_id=requested_workspace_id AND environment_id=requested_environment_id AND id=requested_id;
    END IF;
  ELSE
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid connector workflow mutation';
  END IF;
  RETURN mutation_response;
END $$;

CREATE FUNCTION "public"."zasp_connector_start_oauth"(organization_value text,workspace_value text,environment_value text,attempt_value text,integration_value text,provider_value text,principal_value text,session_value bytea,state_value bytea,pkce_reference_value text,request_value bytea,scopes_value jsonb,expires_value timestamptz,integration_version_value bigint,configuration_value jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_oauth_attempts%ROWTYPE; workflow_row zasp_workflow_records%ROWTYPE; configuration_digest_value bytea;
BEGIN
	IF provider_value NOT IN ('github','okta') AND provider_value !~ '^nango:[a-z0-9][a-z0-9_-]{1,62}$' OR expires_value<=transaction_timestamp() OR expires_value>transaction_timestamp()+interval '10 minutes' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid oauth attempt'; END IF;
  SELECT * INTO workflow_row FROM zasp_workflow_records WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND kind='integration' AND id=integration_value AND deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND OR workflow_row.version<>integration_version_value OR workflow_row.body->'configuration' IS DISTINCT FROM configuration_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector authorization intent changed'; END IF;
  IF EXISTS(SELECT 1 FROM zasp_connector_oauth_attempts WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND integration_id=integration_value AND provider=provider_value AND status IN('pending','consuming') AND id<>attempt_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector authorization attempt unresolved'; END IF;
  IF EXISTS(SELECT 1 FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND integration_id=integration_value AND provider=provider_value AND operation='authorize' AND status IN('pending','unknown')) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector authorization unresolved'; END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_integrations WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=integration_value AND state IN ('pending','authorizing','active','degraded') AND (kind=provider_value OR provider_value LIKE 'nango:%') FOR UPDATE) THEN RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='integration unavailable'; END IF;
  configuration_digest_value:=digest(convert_to(configuration_value::text,'UTF8'),'sha256');
  INSERT INTO zasp_connector_oauth_attempts(organization_id,workspace_id,environment_id,id,integration_id,provider,principal_id,session_digest,state_hash,pkce_verifier_reference,request_digest,integration_version,configuration_digest,requested_scopes,expires_at)
  VALUES(organization_value,workspace_value,environment_value,attempt_value,integration_value,provider_value,principal_value,session_value,state_value,pkce_reference_value,request_value,integration_version_value,configuration_digest_value,scopes_value,expires_value) ON CONFLICT(organization_id,workspace_id,environment_id,id) DO NOTHING;
  SELECT * INTO row_value FROM zasp_connector_oauth_attempts WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=attempt_value FOR UPDATE;
  IF NOT FOUND OR row_value.integration_id<>integration_value OR row_value.provider<>provider_value OR row_value.principal_id<>principal_value OR row_value.session_digest<>session_value OR row_value.state_hash<>state_value OR row_value.pkce_verifier_reference<>pkce_reference_value OR row_value.request_digest<>request_value OR row_value.integration_version<>integration_version_value OR row_value.configuration_digest<>configuration_digest_value OR row_value.requested_scopes<>scopes_value OR row_value.expires_at<>expires_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='oauth attempt conflict'; END IF;
  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,integration_value,attempt_value,'','authorization_started',principal_value,'','{}'::jsonb);
  RETURN jsonb_build_object('id',row_value.id,'integration_id',row_value.integration_id,'provider',row_value.provider,'status',row_value.status,'expires_at',row_value.expires_at,'created_at',row_value.created_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_consume_oauth"(organization_value text,workspace_value text,environment_value text,state_value bytea,principal_value text,session_value bytea) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_oauth_attempts%ROWTYPE;
BEGIN
  SELECT * INTO row_value FROM zasp_connector_oauth_attempts WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND state_hash=state_value FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='oauth attempt unavailable'; END IF;
  IF row_value.status<>'pending' OR row_value.expires_at<=transaction_timestamp() OR row_value.principal_id<>principal_value OR row_value.session_digest<>session_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='oauth attempt rejected'; END IF;
  UPDATE zasp_connector_oauth_attempts SET status='consuming',consumed_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=row_value.id RETURNING * INTO row_value;
  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,row_value.integration_id,row_value.id,'','authorization_consumed',row_value.principal_id,'','{}'::jsonb);
  RETURN jsonb_build_object('id',row_value.id,'integration_id',row_value.integration_id,'provider',row_value.provider,'principal_id',row_value.principal_id,'pkce_verifier_reference',row_value.pkce_verifier_reference,'request_digest',encode(row_value.request_digest,'hex'),'requested_scopes',row_value.requested_scopes,'return_path',row_value.return_path,'expires_at',row_value.expires_at,'consumed_at',row_value.consumed_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_begin_effect"(organization_value text,workspace_value text,environment_value text,effect_value text,integration_value text,attempt_value text,provider_value text,operation_value text,idempotency_value text,request_value bytea) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_effects%ROWTYPE;
BEGIN
  INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,oauth_attempt_id,provider,operation,idempotency_key,request_digest)
  VALUES(organization_value,workspace_value,environment_value,effect_value,integration_value,NULLIF(attempt_value,''),provider_value,operation_value,idempotency_value,request_value) ON CONFLICT(organization_id,workspace_id,environment_id,id) DO NOTHING;
  SELECT * INTO row_value FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value FOR UPDATE;
  IF NOT FOUND OR row_value.integration_id<>integration_value OR row_value.oauth_attempt_id IS DISTINCT FROM NULLIF(attempt_value,'') OR row_value.provider<>provider_value OR row_value.operation<>operation_value OR row_value.idempotency_key<>idempotency_value OR row_value.request_digest<>request_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector effect conflict'; END IF;
  RETURN jsonb_build_object('id',row_value.id,'integration_id',row_value.integration_id,'provider',row_value.provider,'operation',row_value.operation,'status',row_value.status,'attempt',row_value.attempt,'created_at',row_value.created_at,'updated_at',row_value.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_stage_pkce_cleanup"(organization_value text,workspace_value text,environment_value text,effect_value text,integration_value text,attempt_value text,provider_value text,reference_value text,request_value bytea,available_value timestamptz,reason_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_effects%ROWTYPE;
BEGIN
  IF available_value<transaction_timestamp()-interval '1 second' OR available_value>transaction_timestamp()+interval '10 minutes 1 second' OR reason_value NOT IN('oauth_attempt_expiry','oauth_start_rejected') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid pkce cleanup'; END IF;
  INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,oauth_attempt_id,provider,operation,idempotency_key,request_digest,status,connection_reference,last_error_code,available_at)
  VALUES(organization_value,workspace_value,environment_value,effect_value,integration_value,NULLIF(attempt_value,''),provider_value,'pkce_cleanup','pkce-cleanup:'||effect_value,request_value,'unknown',reference_value,reason_value,available_value) ON CONFLICT(organization_id,workspace_id,environment_id,id) DO NOTHING;
  SELECT * INTO row_value FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value FOR UPDATE;
  IF NOT FOUND OR row_value.integration_id<>integration_value OR row_value.oauth_attempt_id IS DISTINCT FROM NULLIF(attempt_value,'') OR row_value.provider<>provider_value OR row_value.operation<>'pkce_cleanup' OR row_value.request_digest<>request_value OR row_value.connection_reference<>reference_value OR row_value.available_at<>available_value OR row_value.last_error_code<>reason_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='pkce cleanup conflict'; END IF;
  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,integration_value,attempt_value,effect_value,'pkce_cleanup_started','',reason_value,'{}'::jsonb);
  RETURN jsonb_build_object('id',row_value.id,'integration_id',row_value.integration_id,'provider',row_value.provider,'operation',row_value.operation,'status',row_value.status,'attempt',row_value.attempt,'created_at',row_value.created_at,'updated_at',row_value.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_activate_pkce_cleanup"(organization_value text,workspace_value text,environment_value text,effect_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_effects%ROWTYPE;
BEGIN
  UPDATE zasp_connector_effects SET available_at=LEAST(available_at,transaction_timestamp()),updated_at=transaction_timestamp()-interval '16 seconds' WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value AND operation='pkce_cleanup' AND status='unknown' RETURNING * INTO row_value;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='pkce cleanup unavailable'; END IF;
  RETURN jsonb_build_object('id',row_value.id,'status',row_value.status,'attempt',row_value.attempt,'updated_at',row_value.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_complete_pkce_cleanup"(organization_value text,workspace_value text,environment_value text,effect_value text,owner_value text,token_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_effects%ROWTYPE;
BEGIN
  SELECT * INTO row_value FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value AND operation='pkce_cleanup' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='pkce cleanup unavailable'; END IF;
  IF row_value.status='reconciled' THEN RETURN jsonb_build_object('id',row_value.id,'status',row_value.status,'attempt',row_value.attempt,'updated_at',row_value.updated_at); END IF;
  IF row_value.status<>'unknown' OR owner_value<>'' AND (row_value.lease_owner<>owner_value OR row_value.lease_token<>token_value OR row_value.lease_expires_at<=transaction_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pkce cleanup lease unavailable'; END IF;
  UPDATE zasp_connector_effects SET status='reconciled',last_error_code=NULL,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,resolved_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value RETURNING * INTO row_value;
  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,row_value.integration_id,COALESCE(row_value.oauth_attempt_id,''),row_value.id,'pkce_cleanup_completed','','','{}'::jsonb);
  RETURN jsonb_build_object('id',row_value.id,'status',row_value.status,'attempt',row_value.attempt,'updated_at',row_value.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_resolve_effect"(organization_value text,workspace_value text,environment_value text,effect_value text,status_value text,reference_value text,metadata_value jsonb,error_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_effects%ROWTYPE;
BEGIN
  SELECT * INTO row_value FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value FOR UPDATE;
  IF NOT FOUND OR status_value NOT IN ('unknown','failed') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid connector effect transition'; END IF;
  IF row_value.status=status_value AND row_value.connection_reference IS NOT DISTINCT FROM NULLIF(reference_value,'') AND row_value.metadata=metadata_value AND row_value.last_error_code IS NOT DISTINCT FROM NULLIF(error_value,'') THEN
    IF status_value='failed' AND row_value.oauth_attempt_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM zasp_connector_oauth_attempts WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=row_value.oauth_attempt_id AND status='rejected') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='oauth rejection conflict'; END IF;
    PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,row_value.integration_id,COALESCE(row_value.oauth_attempt_id,''),row_value.id,CASE WHEN status_value='unknown' THEN 'effect_unknown' ELSE 'authorization_rejected' END,'',error_value,metadata_value);
    RETURN jsonb_build_object('id',row_value.id,'status',row_value.status,'attempt',row_value.attempt,'updated_at',row_value.updated_at);
  END IF;
  IF row_value.status<>'pending' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector effect already resolved'; END IF;
  UPDATE zasp_connector_effects SET status=status_value,connection_reference=NULLIF(reference_value,''),metadata=metadata_value,last_error_code=NULLIF(error_value,''),resolved_at=CASE WHEN status_value='failed' THEN transaction_timestamp() END,updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value RETURNING * INTO row_value;
  IF status_value='failed' AND row_value.oauth_attempt_id IS NOT NULL THEN
    UPDATE zasp_connector_oauth_attempts SET status='rejected',completed_at=transaction_timestamp(),updated_at=transaction_timestamp()
    WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=row_value.oauth_attempt_id AND status='consuming';
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='oauth rejection conflict'; END IF;
  END IF;
  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,row_value.integration_id,COALESCE(row_value.oauth_attempt_id,''),row_value.id,CASE WHEN status_value='unknown' THEN 'effect_unknown' ELSE 'authorization_rejected' END,'',error_value,metadata_value);
  RETURN jsonb_build_object('id',row_value.id,'status',row_value.status,'attempt',row_value.attempt,'updated_at',row_value.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_claim_reconciliation"(owner_value text,lease_seconds integer,limit_value integer) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE result_value jsonb;
BEGIN
  IF length(owner_value) NOT BETWEEN 3 AND 128 OR lease_seconds NOT BETWEEN 5 AND 300 OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid reconciliation claim'; END IF;
  WITH selected AS (SELECT organization_id,workspace_id,environment_id,id FROM zasp_connector_effects WHERE status='unknown' AND attempt<100 AND available_at<=transaction_timestamp() AND updated_at<=transaction_timestamp()-interval '15 seconds' AND (lease_expires_at IS NULL OR lease_expires_at<=transaction_timestamp()) ORDER BY updated_at,id FOR UPDATE SKIP LOCKED LIMIT limit_value),
  updated AS (UPDATE zasp_connector_effects effect SET attempt=effect.attempt+1,lease_owner=owner_value,lease_token=encode(gen_random_bytes(32),'hex'),lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() FROM selected WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.id)=(selected.organization_id,selected.workspace_id,selected.environment_id,selected.id) RETURNING effect.*)
	  SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'id',id,'integration_id',integration_id,'oauth_attempt_id',oauth_attempt_id,'principal_id',(SELECT principal_id FROM zasp_connector_oauth_attempts attempt WHERE (attempt.organization_id,attempt.workspace_id,attempt.environment_id,attempt.id)=(updated.organization_id,updated.workspace_id,updated.environment_id,updated.oauth_attempt_id)),'requested_scopes',(SELECT requested_scopes FROM zasp_connector_oauth_attempts attempt WHERE (attempt.organization_id,attempt.workspace_id,attempt.environment_id,attempt.id)=(updated.organization_id,updated.workspace_id,updated.environment_id,updated.oauth_attempt_id)),'provider',provider,'operation',operation,'connection_reference',connection_reference,'idempotency_key',idempotency_key,'request_digest',encode(request_digest,'hex'),'last_error_code',last_error_code,'attempt',attempt,'lease_owner',lease_owner,'lease_token',lease_token,'lease_expires_at',lease_expires_at) ORDER BY updated_at,id),'[]'::jsonb)) INTO result_value FROM updated;
  RETURN result_value;
END $$;

CREATE FUNCTION "public"."zasp_connector_put_credential"(organization_value text,workspace_value text,environment_value text,credential_value text,integration_value text,provider_value text,class_value text,reference_value text,version_value bigint,metadata_value jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_credentials%ROWTYPE;
BEGIN
  INSERT INTO zasp_connector_credentials(organization_id,workspace_id,environment_id,id,integration_id,provider,credential_class,credential_reference,version,metadata)
  VALUES(organization_value,workspace_value,environment_value,credential_value,integration_value,provider_value,class_value,reference_value,version_value,metadata_value) ON CONFLICT(organization_id,workspace_id,environment_id,id) DO NOTHING;
  SELECT * INTO row_value FROM zasp_connector_credentials WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=credential_value FOR UPDATE;
  IF NOT FOUND OR row_value.integration_id<>integration_value OR row_value.provider<>provider_value OR row_value.credential_class<>class_value OR row_value.credential_reference<>reference_value OR row_value.version<>version_value OR row_value.metadata<>metadata_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='credential metadata conflict'; END IF;
  RETURN jsonb_build_object('id',row_value.id,'integration_id',row_value.integration_id,'provider',row_value.provider,'credential_class',row_value.credential_class,'version',row_value.version,'status',row_value.status,'expires_at',row_value.expires_at,'created_at',row_value.created_at,'updated_at',row_value.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_complete_oauth"(organization_value text,workspace_value text,environment_value text,attempt_value text,effect_value text,connection_value text,reference_value text,subject_value text,credential_value text,class_value text,metadata_value jsonb,completion_value bytea) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE attempt_row zasp_connector_oauth_attempts%ROWTYPE; effect_row zasp_connector_effects%ROWTYPE; connection_row zasp_integration_connections%ROWTYPE; workflow_row zasp_workflow_records%ROWTYPE; workflow_intent jsonb; workflow_response jsonb; workflow_audit_id text; workflow_correlation_id text; workflow_receipt_id text; workflow_key text;
BEGIN
  SELECT * INTO attempt_row FROM zasp_connector_oauth_attempts WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=attempt_value FOR UPDATE;
  SELECT * INTO effect_row FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value AND oauth_attempt_id=attempt_value FOR UPDATE;
  IF NOT FOUND OR octet_length(completion_value)<>32 OR attempt_row.status NOT IN ('consuming','succeeded') OR effect_row.status NOT IN ('pending','unknown','succeeded','reconciled') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='oauth completion unavailable'; END IF;
  IF attempt_row.status='succeeded' THEN
    IF attempt_row.completion_digest IS DISTINCT FROM completion_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='oauth completion conflict'; END IF;
    RETURN jsonb_build_object('attempt_id',attempt_row.id,'connection_id',attempt_row.connection_id,'status','succeeded','completed_at',attempt_row.completed_at);
  END IF;
  SELECT * INTO workflow_row FROM zasp_workflow_records WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND kind='integration' AND id=attempt_row.integration_id AND deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND OR workflow_row.version<>attempt_row.integration_version OR digest(convert_to((workflow_row.body->'configuration')::text,'UTF8'),'sha256')<>attempt_row.configuration_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='oauth completion intent changed'; END IF;
  INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at)
  VALUES(organization_value,workspace_value,environment_value,attempt_row.integration_id,connection_value,attempt_row.provider,reference_value,'verified',transaction_timestamp())
  ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,provider) DO UPDATE SET connection_reference=EXCLUDED.connection_reference,state='verified',verified_at=COALESCE(zasp_integration_connections.verified_at,transaction_timestamp()),revoked_at=NULL,version=zasp_integration_connections.version+1,updated_at=transaction_timestamp() WHERE zasp_integration_connections.connection_reference=EXCLUDED.connection_reference RETURNING * INTO connection_row;
  IF NOT FOUND OR connection_row.id<>connection_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connection completion conflict'; END IF;
  PERFORM zasp_connector_put_credential(organization_value,workspace_value,environment_value,credential_value,attempt_row.integration_id,attempt_row.provider,class_value,reference_value,1,metadata_value);
	  UPDATE zasp_connector_effects SET status='unknown',connection_reference=reference_value,provider_subject=subject_value,metadata=metadata_value,last_error_code='cleanup_pending',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,resolved_at=NULL,updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value;
  UPDATE zasp_connector_oauth_attempts SET status='succeeded',connection_id=connection_value,completion_digest=completion_value,completed_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=attempt_value RETURNING * INTO attempt_row;
  UPDATE zasp_workflow_records SET body=jsonb_set(jsonb_set(body,'{status}','"active"'::jsonb),'{updated_at}',to_jsonb(transaction_timestamp())),version=version+1,updated_at=transaction_timestamp()
  WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND kind='integration' AND id=attempt_row.integration_id AND deleted_at IS NULL AND body->>'status' IN('configured','pending_authorization','authorizing') RETURNING * INTO workflow_row;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='public integration completion conflict'; END IF;
  UPDATE zasp_integrations SET state='active',version=GREATEST(version,workflow_row.version),updated_at=transaction_timestamp(),deleted_at=NULL WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=attempt_row.integration_id AND state IN('pending','authorizing','degraded');
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='typed integration completion conflict'; END IF;
  workflow_key:='oauth-completion:'||attempt_row.id;
  workflow_audit_id:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'workflow_audit',workflow_key);
  workflow_correlation_id:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'workflow_correlation',workflow_key);
  workflow_receipt_id:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'workflow_receipt',workflow_key);
  workflow_intent:=jsonb_build_object('authorization_attempt_id',attempt_row.id,'integration_id',attempt_row.integration_id,'provider',attempt_row.provider);
  workflow_response:=jsonb_build_object('body',workflow_row.body,'version',workflow_row.version,'secret_generation',workflow_row.secret_generation,'audit_id',workflow_audit_id,'correlation_id',workflow_correlation_id,'receipt_id',workflow_receipt_id,'replayed',false);
  INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version)
  VALUES(organization_value,workspace_value,environment_value,workflow_audit_id,workflow_correlation_id,attempt_row.principal_id,'completeIntegrationOAuth','integration',attempt_row.integration_id,workflow_row.version);
  INSERT INTO zasp_workflow_idempotency(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,request_digest,response,receipt_semantics)
  VALUES(organization_value,workspace_value,environment_value,attempt_row.principal_id,'completeIntegrationOAuth',workflow_key,digest(convert_to(workflow_intent::text,'UTF8'),'sha256'),workflow_response,'receipt_backed');
  INSERT INTO zasp_workflow_receipts(organization_id,workspace_id,environment_id,principal_id,receipt_id,operation,idempotency_key,intent,result,resource_kind,resource_id,resource_version,audit_id,correlation_id)
  VALUES(organization_value,workspace_value,environment_value,attempt_row.principal_id,workflow_receipt_id,'completeIntegrationOAuth',workflow_key,workflow_intent,workflow_row.body,'integration',attempt_row.integration_id,workflow_row.version,workflow_audit_id,workflow_correlation_id);
	  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,attempt_row.integration_id,attempt_row.id,effect_row.id,'effect_unknown','', 'cleanup_pending','{}'::jsonb);
  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,attempt_row.integration_id,attempt_row.id,effect_row.id,'credential_created','', '',jsonb_build_object('class',class_value));
  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,attempt_row.integration_id,attempt_row.id,effect_row.id,'authorization_completed',attempt_row.principal_id,'',jsonb_build_object('connection_id',connection_value));
  RETURN jsonb_build_object('attempt_id',attempt_row.id,'connection_id',attempt_row.connection_id,'status',attempt_row.status,'completed_at',attempt_row.completed_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_complete_cleanup"(organization_value text,workspace_value text,environment_value text,effect_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE effect_row zasp_connector_effects%ROWTYPE;
BEGIN
	SELECT * INTO effect_row FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value AND operation='authorize' FOR UPDATE;
	IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='connector cleanup unavailable'; END IF;
	IF effect_row.status='reconciled' THEN
		RETURN jsonb_build_object('id',effect_row.id,'status',effect_row.status,'attempt',effect_row.attempt,'updated_at',effect_row.updated_at);
	END IF;
	IF effect_row.status<>'unknown' OR effect_row.last_error_code<>'cleanup_pending' OR NOT EXISTS(SELECT 1 FROM zasp_connector_oauth_attempts WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_row.oauth_attempt_id AND status='succeeded') THEN
		RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector cleanup conflict';
	END IF;
	UPDATE zasp_connector_effects SET status='reconciled',last_error_code=NULL,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,resolved_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value RETURNING * INTO effect_row;
	PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,effect_row.integration_id,COALESCE(effect_row.oauth_attempt_id,''),effect_row.id,'effect_resolved','','',effect_row.metadata);
	RETURN jsonb_build_object('id',effect_row.id,'status',effect_row.status,'attempt',effect_row.attempt,'updated_at',effect_row.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_complete_cleanup"(organization_value text,workspace_value text,environment_value text,effect_value text,owner_value text,token_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE effect_row zasp_connector_effects%ROWTYPE;
BEGIN
	SELECT * INTO effect_row FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value AND operation='authorize' FOR UPDATE;
	IF NOT FOUND OR effect_row.status<>'unknown' OR effect_row.last_error_code<>'cleanup_pending' OR effect_row.lease_owner<>owner_value OR effect_row.lease_token<>token_value OR effect_row.lease_expires_at<=transaction_timestamp() THEN
		RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector cleanup lease unavailable';
	END IF;
	UPDATE zasp_connector_effects SET status='reconciled',last_error_code=NULL,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,resolved_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value RETURNING * INTO effect_row;
	PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,effect_row.integration_id,COALESCE(effect_row.oauth_attempt_id,''),effect_row.id,'effect_resolved','','',effect_row.metadata);
	RETURN jsonb_build_object('id',effect_row.id,'status',effect_row.status,'attempt',effect_row.attempt,'updated_at',effect_row.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_quarantine_reconciliation"(organization_value text,workspace_value text,environment_value text,effect_value text,owner_value text,token_value text,error_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE effect_row zasp_connector_effects%ROWTYPE; workflow_row zasp_workflow_records%ROWTYPE;
BEGIN
	SELECT * INTO effect_row FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value FOR UPDATE;
	IF NOT FOUND OR effect_row.status<>'unknown' OR effect_row.attempt<>100 OR effect_row.lease_owner<>owner_value OR effect_row.lease_token<>token_value OR effect_row.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector quarantine lease unavailable'; END IF;
	IF NOT (effect_row.operation='authorize' AND error_value IN('provider_outcome_ambiguous','provider_cleanup_ambiguous') OR effect_row.operation='revoke' AND error_value='provider_revocation_ambiguous' OR effect_row.operation='pkce_cleanup' AND error_value='pkce_cleanup_ambiguous') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid connector quarantine'; END IF;
	UPDATE zasp_connector_effects SET last_error_code=error_value,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value RETURNING * INTO effect_row;
	UPDATE zasp_workflow_records SET body=jsonb_set(jsonb_set(body,'{status}','"degraded"'::jsonb),'{updated_at}',to_jsonb(transaction_timestamp())),version=version+1,updated_at=transaction_timestamp()
	WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND kind='integration' AND id=effect_row.integration_id AND deleted_at IS NULL AND body->>'status' IN('configured','pending_authorization','authorizing','active','revoking') RETURNING * INTO workflow_row;
	IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='public connector quarantine conflict'; END IF;
	UPDATE zasp_integrations SET state='degraded',version=GREATEST(version,workflow_row.version),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_row.integration_id AND state<>'deleted';
	IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='typed connector quarantine conflict'; END IF;
	PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,effect_row.integration_id,COALESCE(effect_row.oauth_attempt_id,''),effect_row.id,'effect_unknown','',error_value,'{}'::jsonb);
	RETURN jsonb_build_object('id',effect_row.id,'status',effect_row.status,'attempt',effect_row.attempt,'updated_at',effect_row.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_get_quarantine"(organization_value text,workspace_value text,environment_value text,integration_value text) RETURNS jsonb
LANGUAGE plpgsql STABLE AS $$
DECLARE effect_row zasp_connector_effects%ROWTYPE;
BEGIN
	SELECT * INTO STRICT effect_row FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND integration_id=integration_value AND (status='unknown' AND last_error_code IN('provider_outcome_ambiguous','provider_cleanup_ambiguous','provider_revocation_ambiguous','provider_revocation_remediated','pkce_cleanup_ambiguous') OR status='failed' AND last_error_code IN('provider_outcome_remediated','provider_cleanup_remediated','pkce_cleanup_remediated'));
	RETURN jsonb_build_object('id',effect_row.id,'integration_id',effect_row.integration_id,'provider',effect_row.provider,'operation',effect_row.operation,'connection_reference',effect_row.connection_reference,'status',effect_row.status,'reason',effect_row.last_error_code);
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='connector quarantine unavailable'; WHEN too_many_rows THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector quarantine ambiguous';
END $$;

CREATE FUNCTION "public"."zasp_connector_remediate_quarantine"(organization_value text,workspace_value text,environment_value text,effect_value text,integration_value text,principal_value text,acknowledgement_value text,idempotency_value text,expected_version_value bigint,intent_value jsonb,body_value jsonb,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE effect_row zasp_connector_effects%ROWTYPE; mutation_response jsonb; workflow_row zasp_workflow_records%ROWTYPE; desired_body jsonb; target_status text; remediated_reason text;
BEGIN
	IF NOT zasp_valid_product_id(integration_value) OR NOT zasp_valid_product_id(principal_value) OR acknowledgement_value NOT IN('provider_grant_revoked_manually','provider_grant_verified_absent') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid connector remediation'; END IF;
	SELECT * INTO effect_row FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value AND integration_id=integration_value AND operation IN('authorize','revoke','pkce_cleanup') FOR UPDATE;
	IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='connector quarantine unavailable'; END IF;
	SELECT * INTO workflow_row FROM zasp_workflow_records WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND kind='integration' AND id=integration_value AND deleted_at IS NULL FOR UPDATE;
	IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='public connector quarantine unavailable'; END IF;
	remediated_reason:=CASE effect_row.last_error_code WHEN 'provider_outcome_ambiguous' THEN 'provider_outcome_remediated' WHEN 'provider_cleanup_ambiguous' THEN 'provider_cleanup_remediated' WHEN 'provider_revocation_ambiguous' THEN 'provider_revocation_remediated' WHEN 'pkce_cleanup_ambiguous' THEN 'pkce_cleanup_remediated' ELSE effect_row.last_error_code END;
	target_status:=CASE WHEN effect_row.operation='revoke' THEN 'revoking' WHEN effect_row.last_error_code='provider_cleanup_ambiguous' OR effect_row.last_error_code='provider_cleanup_remediated' THEN 'active' ELSE 'pending_authorization' END;
	desired_body:=jsonb_set(workflow_row.body,'{status}',to_jsonb(target_status));
	IF effect_row.last_error_code IN('provider_outcome_remediated','provider_cleanup_remediated','pkce_cleanup_remediated','provider_revocation_remediated') THEN
		IF NOT EXISTS(SELECT 1 FROM zasp_connector_audit WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND effect_id=effect_value AND event_kind='quarantine_remediated' AND principal_id=principal_value AND reason_code=effect_row.last_error_code AND metadata=jsonb_build_object('acknowledgement',acknowledgement_value)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector remediation replay conflict'; END IF;
		RETURN zasp_workflow_mutate('update','integration',integration_value,organization_value,workspace_value,environment_value,principal_value,'remediateIntegrationAuthorization',idempotency_value,expected_version_value,intent_value,desired_body,audit_value,correlation_value,receipt_value);
	END IF;
	IF effect_row.status<>'unknown' OR effect_row.attempt<>100 OR effect_row.last_error_code NOT IN('provider_outcome_ambiguous','provider_cleanup_ambiguous','provider_revocation_ambiguous','pkce_cleanup_ambiguous') OR effect_row.lease_owner IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector remediation conflict'; END IF;
	mutation_response:=zasp_workflow_mutate('update','integration',integration_value,organization_value,workspace_value,environment_value,principal_value,'remediateIntegrationAuthorization',idempotency_value,expected_version_value,intent_value,desired_body,audit_value,correlation_value,receipt_value);
	IF effect_row.last_error_code='provider_outcome_ambiguous' THEN
		UPDATE zasp_connector_oauth_attempts SET status='rejected',completed_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_row.oauth_attempt_id AND status='consuming';
		IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector remediation attempt conflict'; END IF;
	END IF;
	UPDATE zasp_integrations SET state=CASE WHEN target_status='active' THEN 'active' WHEN target_status='revoking' THEN 'degraded' ELSE 'pending' END,version=GREATEST(version,(mutation_response->>'version')::bigint),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_row.integration_id AND state='degraded';
	IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='typed connector remediation conflict'; END IF;
	UPDATE zasp_connector_effects SET status=CASE WHEN operation='revoke' THEN 'unknown' ELSE 'failed' END,attempt=CASE WHEN operation='revoke' THEN 0 ELSE attempt END,last_error_code=remediated_reason,resolved_at=CASE WHEN operation='revoke' THEN NULL ELSE transaction_timestamp() END,available_at=CASE WHEN operation='revoke' THEN transaction_timestamp() ELSE available_at END,updated_at=CASE WHEN operation='revoke' THEN transaction_timestamp()-interval '16 seconds' ELSE transaction_timestamp() END WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value RETURNING * INTO effect_row;
	PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,effect_row.integration_id,COALESCE(effect_row.oauth_attempt_id,''),effect_row.id,'quarantine_remediated',principal_value,remediated_reason,jsonb_build_object('acknowledgement',acknowledgement_value));
	RETURN mutation_response;
END $$;

CREATE FUNCTION "public"."zasp_connector_complete_reconciliation"(organization_value text,workspace_value text,environment_value text,attempt_value text,effect_value text,owner_value text,token_value text,connection_value text,reference_value text,subject_value text,credential_value text,class_value text,metadata_value jsonb,completion_value bytea) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE effect_row zasp_connector_effects%ROWTYPE; result_value jsonb;
BEGIN
  SELECT * INTO effect_row FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value AND oauth_attempt_id=attempt_value FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='connector reconciliation unavailable'; END IF;
  IF effect_row.status IN('succeeded','reconciled') THEN
    RETURN zasp_connector_complete_oauth(organization_value,workspace_value,environment_value,attempt_value,effect_value,connection_value,reference_value,subject_value,credential_value,class_value,metadata_value,completion_value);
  END IF;
  IF effect_row.status<>'unknown' OR effect_row.lease_owner<>owner_value OR effect_row.lease_token<>token_value OR effect_row.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector reconciliation lease unavailable'; END IF;
  result_value:=zasp_connector_complete_oauth(organization_value,workspace_value,environment_value,attempt_value,effect_value,connection_value,reference_value,subject_value,credential_value,class_value,metadata_value,completion_value);
  RETURN result_value;
END $$;

CREATE FUNCTION "public"."zasp_connector_fail_reconciliation"(organization_value text,workspace_value text,environment_value text,effect_value text,owner_value text,token_value text,error_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE effect_row zasp_connector_effects%ROWTYPE;
BEGIN
  IF error_value !~ '^[a-z][a-z0-9_]{2,63}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid reconciliation failure'; END IF;
  SELECT * INTO effect_row FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value FOR UPDATE;
  IF NOT FOUND OR effect_row.status<>'unknown' OR effect_row.lease_owner<>owner_value OR effect_row.lease_token<>token_value OR effect_row.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector reconciliation lease unavailable'; END IF;
  UPDATE zasp_connector_effects SET status='failed',last_error_code=error_value,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,resolved_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value RETURNING * INTO effect_row;
  IF effect_row.oauth_attempt_id IS NOT NULL THEN
    UPDATE zasp_connector_oauth_attempts SET status='rejected',completed_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_row.oauth_attempt_id AND status='consuming';
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='oauth reconciliation failure conflict'; END IF;
  END IF;
  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,effect_row.integration_id,COALESCE(effect_row.oauth_attempt_id,''),effect_row.id,'effect_resolved','',error_value,'{}'::jsonb);
  RETURN jsonb_build_object('id',effect_row.id,'status',effect_row.status,'attempt',effect_row.attempt,'updated_at',effect_row.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_complete_revocation"(organization_value text,workspace_value text,environment_value text,effect_value text,owner_value text,token_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE effect_row zasp_connector_effects%ROWTYPE; credential_row zasp_connector_credentials%ROWTYPE; terminal_result jsonb; changed_rows integer;
BEGIN
  SELECT * INTO effect_row FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value AND operation='revoke' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='connector revocation unavailable'; END IF;
  IF effect_row.status='reconciled' THEN
    IF EXISTS(SELECT 1 FROM zasp_integrations WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_row.integration_id AND state='deleted') THEN
      RETURN jsonb_build_object('id',effect_row.id,'status',effect_row.status,'attempt',effect_row.attempt,'updated_at',effect_row.updated_at);
    END IF;
    RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector revocation replay conflict';
  END IF;
  IF effect_row.status<>'unknown' OR effect_row.lease_owner<>owner_value OR effect_row.lease_token<>token_value OR effect_row.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector revocation lease unavailable'; END IF;
  UPDATE zasp_connector_credentials SET status='revoked',revoked_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND integration_id=effect_row.integration_id AND status='active' RETURNING * INTO credential_row;
  UPDATE zasp_integration_connections SET state='revoked',revoked_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND integration_id=effect_row.integration_id AND state='verified';
  UPDATE zasp_workflow_records SET body=jsonb_set(body,'{status}','"deleted"'::jsonb),deleted_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND kind='integration' AND id=effect_row.integration_id AND deleted_at IS NULL AND body->>'status'='revoking';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='public integration revocation conflict'; END IF;
  UPDATE zasp_integrations SET state='deleted',deleted_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_row.integration_id AND state='degraded';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='typed integration revocation conflict'; END IF;
  terminal_result:=jsonb_build_object('id',effect_row.integration_id,'status','deleted');
  UPDATE zasp_workflow_idempotency SET response=jsonb_set(response,'{body}',terminal_result)
  WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value
    AND operation='deleteIntegration' AND idempotency_key=effect_row.idempotency_key AND response->'body'->>'id'=effect_row.integration_id;
  GET DIAGNOSTICS changed_rows=ROW_COUNT;
  IF changed_rows<>1 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='public integration revocation replay conflict'; END IF;
  UPDATE zasp_workflow_receipts SET result=terminal_result
  WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value
    AND operation='deleteIntegration' AND idempotency_key=effect_row.idempotency_key AND resource_id=effect_row.integration_id;
  GET DIAGNOSTICS changed_rows=ROW_COUNT;
  IF changed_rows NOT IN(0,1) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='public integration revocation receipt conflict'; END IF;
  UPDATE zasp_connector_effects SET status='reconciled',provider_subject='revoked',last_error_code=NULL,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,resolved_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value RETURNING * INTO effect_row;
  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,effect_row.integration_id,'',effect_row.id,'effect_resolved','','','{}'::jsonb);
  IF credential_row.id IS NOT NULL THEN PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,effect_row.integration_id,'',effect_row.id,'credential_revoked','','',jsonb_build_object('class',credential_row.credential_class)); END IF;
  PERFORM zasp_connector_audit_event(organization_value,workspace_value,environment_value,effect_row.integration_id,'',effect_row.id,'revocation_completed','','','{}'::jsonb);
  RETURN jsonb_build_object('id',effect_row.id,'status',effect_row.status,'attempt',effect_row.attempt,'updated_at',effect_row.updated_at);
END $$;

DO $rls$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['zasp_connector_oauth_attempts','zasp_connector_effects','zasp_connector_credentials','zasp_connector_audit'] LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',table_name); EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name); EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway',table_name); EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO zasp_discovery_authority',table_name);
    EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING (true) WITH CHECK (true)',table_name||'_authority',table_name);
  END LOOP;
END $rls$;

CREATE FUNCTION "public"."zasp_connector_security_ready"() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT zasp_discovery_security_ready()
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_connector_oauth_attempts','zasp_connector_effects','zasp_connector_credentials','zasp_connector_audit']) AND (c.relowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid)<>1 OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>c.relowner)))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_connector_%' AND (p.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT p.prosecdef OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.privilege_type='EXECUTE' AND a.grantee NOT IN(p.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api'),(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_worker')))))
$$;

CREATE FUNCTION "public"."zasp_connector_readiness"(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE AS $$
 WITH semantic_objects AS (
   SELECT 'table'::text object_kind,class.relname::text object_identity,jsonb_build_object('row_security',class.relrowsecurity,'force_row_security',class.relforcerowsecurity,'persistence',class.relpersistence) definition FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p')
   UNION ALL SELECT 'column',class.relname||'.'||attribute.attnum||'.'||attribute.attname,jsonb_build_object('type',format_type(attribute.atttypid,attribute.atttypmod),'not_null',attribute.attnotnull,'default',COALESCE(regexp_replace(pg_get_expr(default_value.adbin,default_value.adrelid,true),E'\\s+',' ','g'),''),'identity',attribute.attidentity,'generated',attribute.attgenerated,'collation',CASE WHEN attribute.attcollation=0 THEN '' ELSE attribute.attcollation::regcollation::text END) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p') AND attribute.attnum>0 AND NOT attribute.attisdropped
   UNION ALL SELECT 'constraint',class.relname||'.'||constraint_value.conname,jsonb_build_object('type',constraint_value.contype,'definition',regexp_replace(pg_get_constraintdef(constraint_value.oid,true),E'\\s+',' ','g'),'deferrable',constraint_value.condeferrable,'deferred',constraint_value.condeferred,'validated',constraint_value.convalidated) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_'
   UNION ALL SELECT 'index',table_class.relname||'.'||index_class.relname,jsonb_build_object('definition',regexp_replace(pg_get_indexdef(index_value.indexrelid,0,true),E'\\s+',' ','g'),'unique',index_value.indisunique,'primary',index_value.indisprimary,'exclusion',index_value.indisexclusion,'valid',index_value.indisvalid,'ready',index_value.indisready) FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace namespace ON namespace.oid=table_class.relnamespace WHERE namespace.nspname='public' AND left(table_class.relname,5)='zasp_'
   UNION ALL SELECT 'function',procedure.proname||'('||pg_get_function_identity_arguments(procedure.oid)||')',jsonb_build_object('result',pg_get_function_result(procedure.oid),'language',language.lanname,'kind',procedure.prokind,'volatility',procedure.provolatile,'strict',procedure.proisstrict,'security_definer',procedure.prosecdef,'leakproof',procedure.proleakproof,'parallel',procedure.proparallel,'config',COALESCE(to_jsonb(procedure.proconfig),'[]'::jsonb),'body',regexp_replace(btrim(procedure.prosrc),E'\\s+',' ','g')) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_language language ON language.oid=procedure.prolang WHERE namespace.nspname='public' AND left(procedure.proname,5)='zasp_'
 ), live AS (SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(object_kind,object_identity,definition) ORDER BY object_kind,object_identity)::text,'[]'),'UTF8'),'sha256'),'hex') value FROM semantic_objects)
 SELECT EXISTS(SELECT 1 FROM zasp_schema_versions v JOIN zasp_schema_metadata m ON m.key='production_core_schema' AND m.value='connector-authorization-v1' JOIN zasp_schema_metadata fingerprint ON fingerprint.key='connector_authorization_fingerprint' AND fingerprint.value=expected_fingerprint CROSS JOIN live WHERE v.version=11 AND v.name='connector_authorization' AND v.checksum=expected_checksum AND live.value=expected_fingerprint AND zasp_connector_security_ready() AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions newer WHERE newer.version>11))
$$;

DO $authority$ DECLARE procedure_oid oid; BEGIN
  FOR procedure_oid IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_connector_%' LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway',procedure_oid::regprocedure); EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',procedure_oid::regprocedure); EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, public',procedure_oid::regprocedure); EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);
  END LOOP;
END $authority$;
GRANT EXECUTE ON FUNCTION zasp_connector_security_ready(),zasp_connector_readiness(text,text),zasp_connector_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text),zasp_connector_start_oauth(text,text,text,text,text,text,text,bytea,bytea,text,bytea,jsonb,timestamptz,bigint,jsonb),zasp_connector_consume_oauth(text,text,text,bytea,text,bytea),zasp_connector_begin_effect(text,text,text,text,text,text,text,text,text,bytea),zasp_connector_stage_pkce_cleanup(text,text,text,text,text,text,text,text,bytea,timestamptz,text),zasp_connector_activate_pkce_cleanup(text,text,text,text),zasp_connector_complete_pkce_cleanup(text,text,text,text,text,text),zasp_connector_resolve_effect(text,text,text,text,text,text,jsonb,text),zasp_connector_put_credential(text,text,text,text,text,text,text,text,bigint,jsonb),zasp_connector_complete_oauth(text,text,text,text,text,text,text,text,text,text,jsonb,bytea),zasp_connector_complete_cleanup(text,text,text,text),zasp_connector_claim_reconciliation(text,integer,integer),zasp_connector_complete_reconciliation(text,text,text,text,text,text,text,text,text,text,text,text,jsonb,bytea),zasp_connector_quarantine_reconciliation(text,text,text,text,text,text,text),zasp_connector_get_quarantine(text,text,text,text),zasp_connector_remediate_quarantine(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text),zasp_connector_fail_reconciliation(text,text,text,text,text,text,text),zasp_connector_complete_revocation(text,text,text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_connector_security_ready(),zasp_connector_readiness(text,text),zasp_connector_claim_reconciliation(text,integer,integer),zasp_connector_complete_pkce_cleanup(text,text,text,text,text,text),zasp_connector_resolve_effect(text,text,text,text,text,text,jsonb,text),zasp_connector_complete_oauth(text,text,text,text,text,text,text,text,text,text,jsonb,bytea),zasp_connector_complete_cleanup(text,text,text,text,text,text),zasp_connector_complete_reconciliation(text,text,text,text,text,text,text,text,text,text,text,text,jsonb,bytea),zasp_connector_quarantine_reconciliation(text,text,text,text,text,text,text),zasp_connector_fail_reconciliation(text,text,text,text,text,text,text),zasp_connector_complete_revocation(text,text,text,text,text,text) TO zasp_discovery_worker;

DO $migration$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'production-discovery-v1','connector-authorization-v1'); definition:=replace(definition,'release."version" = 10','release."version" = 11'); definition:=replace(definition,'release."name" = ''production_discovery''','release."name" = ''connector_authorization'''); definition:=replace(definition,'later_release."version" > 10','later_release."version" > 11'); EXECUTE definition;
END $migration$;

DO $risk_migration$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(replace(definition,'production-risk-projection-v1','connector-authorization-v1'),'production-discovery-v1','connector-authorization-v1');
 definition:=replace(replace(replace(replace(definition,'release."version"=9','release."version"=11'),'release."version" = 9','release."version" = 11'),'release."version"=10','release."version"=11'),'release."version" = 10','release."version" = 11');
 definition:=replace(replace(definition,'release."name"=''production_risk_projection''','release."name"=''connector_authorization'''),'release."name"=''production_discovery''','release."name"=''connector_authorization''');
 definition:=replace(replace(replace(replace(definition,'later."version">9','later."version">11'),'later."version" > 9','later."version" > 11'),'later."version">10','later."version">11'),'later."version" > 10','later."version" > 11');
 IF position('connector-authorization-v1' IN definition)=0 OR position('release."version"=11' IN replace(definition,' ',''))=0 OR position('release."name"=''connector_authorization''' IN replace(definition,' ',''))=0 OR position('later."version">11' IN replace(definition,' ',''))=0 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk mutation release evolution failed';
 END IF;
 EXECUTE definition;
END $risk_migration$;

INSERT INTO zasp_schema_metadata(key,value) VALUES ('connector_authorization_fingerprint', '37dec0fda449538f50ef7b6c67455975072ab99b20ca15af56fc4845d437b4bc');
UPDATE zasp_schema_metadata SET value='a3ee9cb3bfd3e6ed0d37399817432ec9ebdc4e4a66b778d2e1b79c62f99a65f9' WHERE key='production_discovery_fingerprint' AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_discovery_release_fingerprint');
DELETE FROM zasp_schema_metadata WHERE key='production_discovery_release_fingerprint';
UPDATE zasp_schema_metadata SET value='connector-authorization-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='production-discovery-v1';
