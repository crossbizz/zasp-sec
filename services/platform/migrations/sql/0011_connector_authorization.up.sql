-- Release v11: durable first-party and isolated long-tail connector authorization.
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
  request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32), requested_scopes jsonb NOT NULL CHECK(zasp_connector_scopes_valid(requested_scopes)),
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

CREATE TABLE "public"."zasp_connector_effects" (
  organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
  id text NOT NULL CHECK(zasp_valid_product_id(id)), integration_id text NOT NULL, oauth_attempt_id text,
  provider text NOT NULL CHECK(zasp_connector_provider_valid(provider)), operation text NOT NULL CHECK(operation IN ('authorize','bind','test','rotate','revoke','nango_connect')),
  idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128), request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','unknown','succeeded','failed','reconciled')),
  connection_reference text CHECK(connection_reference IS NULL OR length(connection_reference) BETWEEN 12 AND 512 AND connection_reference ~ '^ref:[a-z0-9][a-z0-9_./:-]+$'),
  provider_subject text CHECK(provider_subject IS NULL OR length(provider_subject) BETWEEN 1 AND 256), metadata jsonb NOT NULL DEFAULT '{}' CHECK(zasp_connector_metadata_only(metadata)),
  attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100), last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{2,63}$'),
  lease_owner text, lease_token text, lease_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(), resolved_at timestamptz,
  PRIMARY KEY(organization_id,workspace_id,environment_id,id),
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,provider,operation,idempotency_key),
  UNIQUE(organization_id,workspace_id,environment_id,integration_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,oauth_attempt_id) REFERENCES zasp_connector_oauth_attempts(organization_id,workspace_id,environment_id,integration_id,id),
  CHECK((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (status='unknown' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at>updated_at)),
  CHECK((status IN ('succeeded','failed','reconciled'))=(resolved_at IS NOT NULL)),
  CHECK(status NOT IN ('succeeded','reconciled') OR (connection_reference IS NOT NULL AND provider_subject IS NOT NULL AND last_error_code IS NULL)),
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
  event_kind text NOT NULL CHECK(event_kind IN ('authorization_started','authorization_consumed','authorization_completed','authorization_rejected','effect_unknown','effect_resolved','credential_created','credential_rotated','credential_revoked')),
  principal_id text CHECK(principal_id IS NULL OR zasp_valid_product_id(principal_id)), reason_code text CHECK(reason_code IS NULL OR reason_code ~ '^[a-z][a-z0-9_]{2,63}$'),
  metadata jsonb NOT NULL DEFAULT '{}' CHECK(zasp_connector_metadata_only(metadata)), occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES zasp_integrations(organization_id,workspace_id,environment_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,oauth_attempt_id) REFERENCES zasp_connector_oauth_attempts(organization_id,workspace_id,environment_id,integration_id,id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,effect_id) REFERENCES zasp_connector_effects(organization_id,workspace_id,environment_id,id)
);

CREATE FUNCTION "public"."zasp_connector_start_oauth"(organization_value text,workspace_value text,environment_value text,attempt_value text,integration_value text,provider_value text,principal_value text,session_value bytea,state_value bytea,pkce_reference_value text,request_value bytea,scopes_value jsonb,expires_value timestamptz) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_oauth_attempts%ROWTYPE;
BEGIN
  IF provider_value NOT IN ('github','okta') AND provider_value !~ '^nango:[a-z0-9][a-z0-9_-]{1,62}$' OR expires_value<=transaction_timestamp() OR expires_value>transaction_timestamp()+interval '10 minutes' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid oauth attempt'; END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_integrations WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=integration_value AND state IN ('pending','authorizing','active','degraded') AND (kind=provider_value OR provider_value LIKE 'nango:%')) THEN RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='integration unavailable'; END IF;
  INSERT INTO zasp_connector_oauth_attempts(organization_id,workspace_id,environment_id,id,integration_id,provider,principal_id,session_digest,state_hash,pkce_verifier_reference,request_digest,requested_scopes,expires_at)
  VALUES(organization_value,workspace_value,environment_value,attempt_value,integration_value,provider_value,principal_value,session_value,state_value,pkce_reference_value,request_value,scopes_value,expires_value) ON CONFLICT(organization_id,workspace_id,environment_id,id) DO NOTHING;
  SELECT * INTO row_value FROM zasp_connector_oauth_attempts WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=attempt_value FOR UPDATE;
  IF NOT FOUND OR row_value.integration_id<>integration_value OR row_value.provider<>provider_value OR row_value.principal_id<>principal_value OR row_value.session_digest<>session_value OR row_value.state_hash<>state_value OR row_value.pkce_verifier_reference<>pkce_reference_value OR row_value.request_digest<>request_value OR row_value.requested_scopes<>scopes_value OR row_value.expires_at<>expires_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='oauth attempt conflict'; END IF;
  RETURN jsonb_build_object('id',row_value.id,'integration_id',row_value.integration_id,'provider',row_value.provider,'status',row_value.status,'expires_at',row_value.expires_at,'created_at',row_value.created_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_consume_oauth"(organization_value text,workspace_value text,environment_value text,state_value bytea,principal_value text,session_value bytea) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_oauth_attempts%ROWTYPE;
BEGIN
  SELECT * INTO row_value FROM zasp_connector_oauth_attempts WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND state_hash=state_value FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='oauth attempt unavailable'; END IF;
  IF row_value.status<>'pending' OR row_value.expires_at<=transaction_timestamp() OR row_value.principal_id<>principal_value OR row_value.session_digest<>session_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='oauth attempt rejected'; END IF;
  UPDATE zasp_connector_oauth_attempts SET status='consuming',consumed_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=row_value.id RETURNING * INTO row_value;
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

CREATE FUNCTION "public"."zasp_connector_resolve_effect"(organization_value text,workspace_value text,environment_value text,effect_value text,status_value text,reference_value text,metadata_value jsonb,error_value text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE row_value zasp_connector_effects%ROWTYPE;
BEGIN
  SELECT * INTO row_value FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value FOR UPDATE;
  IF NOT FOUND OR status_value NOT IN ('unknown','failed') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid connector effect transition'; END IF;
  IF row_value.status=status_value AND row_value.connection_reference IS NOT DISTINCT FROM NULLIF(reference_value,'') AND row_value.metadata=metadata_value AND row_value.last_error_code IS NOT DISTINCT FROM NULLIF(error_value,'') THEN RETURN jsonb_build_object('id',row_value.id,'status',row_value.status,'attempt',row_value.attempt,'updated_at',row_value.updated_at); END IF;
  IF row_value.status<>'pending' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector effect already resolved'; END IF;
  UPDATE zasp_connector_effects SET status=status_value,connection_reference=NULLIF(reference_value,''),metadata=metadata_value,last_error_code=NULLIF(error_value,''),resolved_at=CASE WHEN status_value='failed' THEN transaction_timestamp() END,updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value RETURNING * INTO row_value;
  RETURN jsonb_build_object('id',row_value.id,'status',row_value.status,'attempt',row_value.attempt,'updated_at',row_value.updated_at);
END $$;

CREATE FUNCTION "public"."zasp_connector_claim_reconciliation"(owner_value text,lease_seconds integer,limit_value integer) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE result_value jsonb;
BEGIN
  IF length(owner_value) NOT BETWEEN 3 AND 128 OR lease_seconds NOT BETWEEN 5 AND 300 OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid reconciliation claim'; END IF;
  WITH selected AS (SELECT organization_id,workspace_id,environment_id,id FROM zasp_connector_effects WHERE status='unknown' AND attempt<100 AND (lease_expires_at IS NULL OR lease_expires_at<=transaction_timestamp()) ORDER BY updated_at,id FOR UPDATE SKIP LOCKED LIMIT limit_value),
  updated AS (UPDATE zasp_connector_effects effect SET attempt=effect.attempt+1,lease_owner=owner_value,lease_token=encode(gen_random_bytes(32),'hex'),lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() FROM selected WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.id)=(selected.organization_id,selected.workspace_id,selected.environment_id,selected.id) RETURNING effect.*)
  SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'id',id,'integration_id',integration_id,'provider',provider,'operation',operation,'idempotency_key',idempotency_key,'request_digest',encode(request_digest,'hex'),'attempt',attempt,'lease_owner',lease_owner,'lease_token',lease_token,'lease_expires_at',lease_expires_at) ORDER BY updated_at,id),'[]'::jsonb)) INTO result_value FROM updated;
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

CREATE FUNCTION "public"."zasp_connector_complete_oauth"(organization_value text,workspace_value text,environment_value text,attempt_value text,effect_value text,connection_value text,reference_value text,subject_value text,credential_value text,class_value text,metadata_value jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE attempt_row zasp_connector_oauth_attempts%ROWTYPE; effect_row zasp_connector_effects%ROWTYPE; connection_row zasp_integration_connections%ROWTYPE;
BEGIN
  SELECT * INTO attempt_row FROM zasp_connector_oauth_attempts WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=attempt_value FOR UPDATE;
  SELECT * INTO effect_row FROM zasp_connector_effects WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value AND oauth_attempt_id=attempt_value FOR UPDATE;
  IF NOT FOUND OR attempt_row.status NOT IN ('consuming','succeeded') OR effect_row.status NOT IN ('pending','unknown','succeeded','reconciled') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='oauth completion unavailable'; END IF;
  IF attempt_row.status='succeeded' THEN RETURN jsonb_build_object('attempt_id',attempt_row.id,'connection_id',attempt_row.connection_id,'status','succeeded','completed_at',attempt_row.completed_at); END IF;
  INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at)
  VALUES(organization_value,workspace_value,environment_value,attempt_row.integration_id,connection_value,attempt_row.provider,reference_value,'verified',transaction_timestamp())
  ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,provider) DO UPDATE SET connection_reference=EXCLUDED.connection_reference,state='verified',verified_at=COALESCE(zasp_integration_connections.verified_at,transaction_timestamp()),revoked_at=NULL,version=zasp_integration_connections.version+1,updated_at=transaction_timestamp() WHERE zasp_integration_connections.connection_reference=EXCLUDED.connection_reference RETURNING * INTO connection_row;
  IF NOT FOUND OR connection_row.id<>connection_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connection completion conflict'; END IF;
  PERFORM zasp_connector_put_credential(organization_value,workspace_value,environment_value,credential_value,attempt_row.integration_id,attempt_row.provider,class_value,reference_value,1,metadata_value);
  UPDATE zasp_connector_effects SET status=CASE WHEN status='unknown' THEN 'reconciled' ELSE 'succeeded' END,connection_reference=reference_value,provider_subject=subject_value,metadata=metadata_value,last_error_code=NULL,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,resolved_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=effect_value;
  UPDATE zasp_connector_oauth_attempts SET status='succeeded',connection_id=connection_value,completed_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=organization_value AND workspace_id=workspace_value AND environment_id=environment_value AND id=attempt_value RETURNING * INTO attempt_row;
  RETURN jsonb_build_object('attempt_id',attempt_row.id,'connection_id',attempt_row.connection_id,'status',attempt_row.status,'completed_at',attempt_row.completed_at);
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
GRANT EXECUTE ON FUNCTION zasp_connector_security_ready(),zasp_connector_readiness(text,text),zasp_connector_start_oauth(text,text,text,text,text,text,text,bytea,bytea,text,bytea,jsonb,timestamptz),zasp_connector_consume_oauth(text,text,text,bytea,text,bytea),zasp_connector_begin_effect(text,text,text,text,text,text,text,text,text,bytea),zasp_connector_resolve_effect(text,text,text,text,text,text,jsonb,text),zasp_connector_put_credential(text,text,text,text,text,text,text,text,bigint,jsonb),zasp_connector_complete_oauth(text,text,text,text,text,text,text,text,text,text,jsonb) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_connector_security_ready(),zasp_connector_readiness(text,text),zasp_connector_claim_reconciliation(text,integer,integer),zasp_connector_resolve_effect(text,text,text,text,text,text,jsonb,text),zasp_connector_complete_oauth(text,text,text,text,text,text,text,text,text,text,jsonb) TO zasp_discovery_worker;

DO $migration$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'production-discovery-v1','connector-authorization-v1'); definition:=replace(definition,'release."version" = 10','release."version" = 11'); definition:=replace(definition,'release."name" = ''production_discovery''','release."name" = ''connector_authorization'''); definition:=replace(definition,'later_release."version" > 10','later_release."version" > 11'); EXECUTE definition;
END $migration$;

INSERT INTO zasp_schema_metadata(key,value) VALUES ('connector_authorization_fingerprint', '0b97dba5fd292116aa7fdba0f1b75cea8782fff4769a6bbaf5093deca854e40c');
UPDATE zasp_schema_metadata SET value='connector-authorization-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='production-discovery-v1';
