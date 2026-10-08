-- Captured provenance only. This module issues no task, grant, lease or effect
-- authority, and exposes no lifecycle/Ready/activation operation.
CREATE SCHEMA zasp_connector_provenance AUTHORIZATION zasp_discovery_authority;
CREATE TABLE zasp_connector_provenance.registration (
 singleton boolean PRIMARY KEY CHECK(singleton), checksum text NOT NULL CHECK(checksum ~ '^[a-f0-9]{64}$'),
 fingerprint text NOT NULL CHECK(fingerprint ~ '^[a-f0-9]{64}$')
);
CREATE TABLE zasp_connector_provenance.origins (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, effect_id text NOT NULL,
 integration_id text NOT NULL, principal_id text NOT NULL, operation_id text NOT NULL CHECK(operation_id='authorizeIntegration'),
 source_profile text NOT NULL CHECK(source_profile ~ '^[a-f0-9]{64}$'),
 source_proof_digest bytea NOT NULL CHECK(octet_length(source_proof_digest)=32),
 committed_request_digest bytea NOT NULL CHECK(octet_length(committed_request_digest)=32),
 committed_effect_digest bytea NOT NULL CHECK(octet_length(committed_effect_digest)=32),
 status text NOT NULL DEFAULT 'captured_inactive' CHECK(status='captured_inactive'),
 captured_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,effect_id),
 CHECK(public.zasp_valid_product_id(organization_id) AND public.zasp_valid_product_id(workspace_id)
  AND public.zasp_valid_product_id(environment_id) AND public.zasp_valid_product_id(effect_id)
  AND public.zasp_valid_product_id(integration_id) AND public.zasp_valid_product_id(principal_id))
);
-- Protected transient creation witness. Its xmin follows the actual current
-- subtransaction, unlike top-level txid_current(). It grants no authority and
-- is removed before a successful return; rollback removes all three writes.
CREATE TABLE zasp_connector_provenance.creation_witness (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, effect_id text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,effect_id)
);
-- No FK/trigger is installed on the immutable predecessor tables. Their
-- original catalog remains intact; the writer below checks the actual row.
CREATE FUNCTION zasp_connector_provenance.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fp$
 WITH objects AS (
 SELECT 'namespace' k,n.nspname i,jsonb_build_array(n.nspowner::regrole::text,n.nspacl::text) d FROM pg_namespace n WHERE n.nspname='zasp_connector_provenance'
 UNION ALL SELECT 'table',c.relname,jsonb_build_array(c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity,c.relpersistence) FROM pg_class c WHERE c.relnamespace='zasp_connector_provenance'::regnamespace AND c.relkind='r'
 UNION ALL SELECT 'column',c.relname||'.'||a.attnum,jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated,a.attcollation) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_connector_provenance'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT 'constraint',c.relname||'.'||x.conname,jsonb_build_array(pg_get_constraintdef(x.oid,true),x.convalidated,x.condeferrable,x.condeferred) FROM pg_constraint x JOIN pg_class c ON c.oid=x.conrelid WHERE c.relnamespace='zasp_connector_provenance'::regnamespace
 UNION ALL SELECT 'index',c.relname,jsonb_build_array(pg_get_indexdef(x.indexrelid),x.indisvalid,x.indisready) FROM pg_index x JOIN pg_class c ON c.oid=x.indexrelid WHERE c.relnamespace='zasp_connector_provenance'::regnamespace
 UNION ALL SELECT 'policy',c.relname||'.'||p.polname,jsonb_build_array(p.polcmd,p.polpermissive,p.polroles,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_connector_provenance'::regnamespace
 UNION ALL SELECT 'trigger',c.relname||'.'||t.tgname,jsonb_build_array(pg_get_triggerdef(t.oid),t.tgenabled) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_connector_provenance'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT 'function',p.oid::regprocedure::text,jsonb_build_array(pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_proc p WHERE p.pronamespace='zasp_connector_provenance'::regnamespace
 ) SELECT encode(public.digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(k,i,d) ORDER BY k,i)::text,'[]'),'UTF8'),'sha256'),'hex') FROM objects
 $fp$;
CREATE FUNCTION zasp_connector_provenance.catalog_matches(pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $catalog$
 SELECT COALESCE(pin='-- connector provenance checksum'
 AND EXISTS(SELECT 1 FROM zasp_connector_provenance.registration r WHERE r.singleton AND r.checksum=pin AND r.fingerprint=zasp_connector_provenance.fingerprint())
 AND zasp_authorization80.ready('-- authorization80 checksum')
 AND EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='public.zasp_connector_stage_pkce_cleanup(text,text,text,text,text,text,text,text,bytea,timestamptz,text)'::regprocedure
  AND encode(public.digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')='-- pkce predecessor source digest'
  AND p.proowner='zasp_discovery_authority'::regrole),false)
 $catalog$;
CREATE FUNCTION zasp_connector_provenance.capture_pkce_cleanup(envelope text,o text,w text,e text,id_value text,integration_value text,attempt_value text,provider_value text,reference_value text,request_value bytea,available_value timestamptz,reason_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $capture$
DECLARE p jsonb;result_value jsonb;n public.zasp_connector_effects;origin zasp_connector_provenance.origins;existed boolean;effect_digest bytea;witness_xid xid;row_xid xid;
BEGIN
 IF zasp_connector_provenance.catalog_matches('-- connector provenance checksum') IS NOT TRUE
 OR public.zasp_discovery_principal_ready('zasp_discovery_api') IS NOT TRUE
 OR envelope IS NULL OR octet_length(envelope)>65536 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector provenance unavailable';END IF;
 IF o IS NULL OR w IS NULL OR e IS NULL OR id_value IS NULL OR integration_value IS NULL
 OR attempt_value IS NULL OR provider_value IS NULL OR reference_value IS NULL OR request_value IS NULL
 OR available_value IS NULL OR reason_value IS NULL
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='connector enqueue input missing';END IF;
 -- The ORIGINAL signed request/credential/revision/target fence is mandatory.
 PERFORM zasp_authorization80.fence(envelope);
 p:=zasp_authorization80.context();
 IF p IS NULL OR (p->>'organization_id',p->>'workspace_id',p->>'environment_id') IS DISTINCT FROM(o,w,e)
 OR p->>'operation_id' IS DISTINCT FROM 'authorizeIntegration' OR p->>'permission' IS DISTINCT FROM 'manage_workflows'
 OR p->>'credential_kind' IS DISTINCT FROM '1' OR p->>'fresh_auth' IS DISTINCT FROM 'true'
 OR p#>>'{path_parameters,id}' IS DISTINCT FROM integration_value
 OR zasp_authorization80.allowed(o,w,e,'integration',integration_value) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector enqueue purpose rejected';END IF;
 SELECT x.* INTO n FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,id_value) FOR UPDATE;
 existed:=FOUND;
 IF existed THEN
  SELECT x.* INTO origin FROM zasp_connector_provenance.origins x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(o,w,e,id_value) FOR UPDATE;
  IF NOT FOUND OR origin.principal_id IS DISTINCT FROM p->>'principal_id' OR origin.integration_id IS DISTINCT FROM integration_value
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='existing connector source unavailable';END IF;
 ELSE
  INSERT INTO zasp_connector_provenance.creation_witness VALUES(o,w,e,id_value) RETURNING xmin INTO witness_xid;
 END IF;
 -- All original input validation, effect identity, conflict, audit and output
 -- semantics remain in the unchanged original application function.
 result_value:=public.zasp_connector_stage_pkce_cleanup(o,w,e,id_value,integration_value,attempt_value,provider_value,reference_value,request_value,available_value,reason_value);
 SELECT x.* INTO n FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,id_value) FOR UPDATE;
 IF NOT FOUND OR n.oauth_attempt_id IS DISTINCT FROM NULLIF(attempt_value,'') OR n.operation IS DISTINCT FROM 'pkce_cleanup'
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector enqueue source changed';END IF;
 -- Original native79 revision-row locking serializes genuine same-org
 -- captures. A legacy insertion not holding that lock still cannot be adopted.
 -- Both protected witness and effect must be created in this subtransaction.
 SELECT x.xmin INTO row_xid FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,id_value);
 IF NOT existed AND row_xid IS DISTINCT FROM witness_xid THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector enqueue creation unavailable';END IF;
 effect_digest:=public.digest(convert_to(jsonb_build_object('organization_id',n.organization_id,'workspace_id',n.workspace_id,'environment_id',n.environment_id,'effect_id',n.id,'integration_id',n.integration_id,'oauth_attempt_id',n.oauth_attempt_id,'provider',n.provider,'operation',n.operation,'idempotency_key',n.idempotency_key,'request_digest',encode(n.request_digest,'hex'),'reference',n.connection_reference,'available_at',n.available_at,'reason',n.last_error_code)::text,'UTF8'),'sha256');
 IF existed THEN
  IF origin.committed_request_digest IS DISTINCT FROM n.request_digest OR origin.committed_effect_digest IS DISTINCT FROM effect_digest
  THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector provenance conflict';END IF;
 ELSE
  INSERT INTO zasp_connector_provenance.origins(organization_id,workspace_id,environment_id,effect_id,integration_id,principal_id,operation_id,source_profile,source_proof_digest,committed_request_digest,committed_effect_digest)
  VALUES(o,w,e,id_value,integration_value,p->>'principal_id','authorizeIntegration','-- authorization80 checksum',public.digest(convert_to(envelope,'UTF8'),'sha256'),n.request_digest,effect_digest);
  DELETE FROM zasp_connector_provenance.creation_witness WHERE(organization_id,workspace_id,environment_id,effect_id)=(o,w,e,id_value) AND xmin=witness_xid;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector enqueue witness unavailable';END IF;
 END IF;
 IF zasp_authorization80.context() IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector enqueue proof expired';END IF;
 RETURN result_value;
END $capture$;
DO $seal$ DECLARE x record;BEGIN
 FOR x IN SELECT tablename FROM pg_tables WHERE schemaname='zasp_connector_provenance' LOOP
  EXECUTE format('ALTER TABLE zasp_connector_provenance.%I OWNER TO zasp_discovery_authority',x.tablename);
  EXECUTE format('ALTER TABLE zasp_connector_provenance.%I ENABLE ROW LEVEL SECURITY',x.tablename);
  EXECUTE format('ALTER TABLE zasp_connector_provenance.%I FORCE ROW LEVEL SECURITY',x.tablename);
  EXECUTE format('CREATE POLICY authority ON zasp_connector_provenance.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',x.tablename);
  EXECUTE format('REVOKE ALL ON TABLE zasp_connector_provenance.%I FROM PUBLIC',x.tablename);
 END LOOP;
 FOR x IN SELECT p.oid::regprocedure signature FROM pg_proc p WHERE p.pronamespace='zasp_connector_provenance'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',x.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',x.signature);
 END LOOP;
END $seal$;
REVOKE ALL ON SCHEMA zasp_connector_provenance FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_connector_provenance TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_connector_provenance.capture_pkce_cleanup(text,text,text,text,text,text,text,text,text,bytea,timestamptz,text) TO zasp_discovery_api;
