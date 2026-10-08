-- Separate supplementary connector module. The authenticated capture path is
-- usable only after catalog registration; worker authority remains inactive.
-- Original canonical79/80 and connector function definitions remain untouched.
CREATE SCHEMA zasp_connector_maintenance AUTHORIZATION zasp_discovery_authority;
CREATE TABLE zasp_connector_maintenance.registration(
 singleton boolean PRIMARY KEY CHECK(singleton),checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),
 fingerprint text NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$'),active boolean NOT NULL DEFAULT false);
CREATE TABLE zasp_connector_maintenance.tasks(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,effect_id text NOT NULL,
 integration_id text NOT NULL,operation text NOT NULL CHECK(operation IN('authorize','revoke','pkce_cleanup')),task_id text NOT NULL,principal_id text NOT NULL,grantor_id text NOT NULL,
 purpose text NOT NULL CHECK(purpose='connector_reconciliation'),
 source_profile text NOT NULL CHECK(source_profile='-- authorization80 checksum'),
 source_proof_digest bytea NOT NULL CHECK(octet_length(source_proof_digest)=32),
 committed_request_digest bytea NOT NULL CHECK(octet_length(committed_request_digest)=32),
 committed_effect_digest bytea NOT NULL CHECK(octet_length(committed_effect_digest)=32),
 captured_effect jsonb NOT NULL CHECK(public.digest(convert_to(captured_effect::text,'UTF8'),'sha256')=committed_effect_digest),
 authorized_reference text,
 state text NOT NULL CHECK(state IN('captured_inactive','active','paused_denied','settled')),
 PRIMARY KEY(organization_id,workspace_id,environment_id,effect_id),
 UNIQUE(organization_id,task_id),
 CHECK(public.zasp_valid_product_id(organization_id) AND public.zasp_valid_product_id(workspace_id)
 AND public.zasp_valid_product_id(environment_id) AND public.zasp_valid_product_id(effect_id)
 AND public.zasp_valid_product_id(integration_id) AND public.zasp_valid_product_id(task_id)
 AND public.zasp_valid_product_id(principal_id) AND public.zasp_valid_product_id(grantor_id)));
-- New authorize/revoke origins are separate from immutable PKCE receipts.
-- Only exact authenticated enqueue wrappers can invoke the private writer.
CREATE TABLE zasp_connector_maintenance.enqueue_origins(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,effect_id text NOT NULL,
 integration_id text NOT NULL,grantor_id text NOT NULL,operation text NOT NULL CHECK(operation IN('authorize','revoke')),
 source_profile text NOT NULL CHECK(source_profile='-- authorization80 checksum'),
 source_proof_digest bytea NOT NULL CHECK(octet_length(source_proof_digest)=32),
 committed_request_digest bytea NOT NULL CHECK(octet_length(committed_request_digest)=32),
 committed_effect_digest bytea NOT NULL CHECK(octet_length(committed_effect_digest)=32),
 PRIMARY KEY(organization_id,workspace_id,environment_id,effect_id));
-- Append-only authenticated enrichment history. The initial original capture
-- and its digests are never rewritten when original OAuth start associates the
-- staged cleanup effect with its freshly admitted OAuth attempt.
CREATE TABLE zasp_connector_maintenance.oauth_enrichments(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,effect_id text NOT NULL,
 oauth_attempt_id text NOT NULL,grantor_id text NOT NULL,
 source_proof_digest bytea NOT NULL CHECK(octet_length(source_proof_digest)=32),
 committed_request_digest bytea NOT NULL CHECK(octet_length(committed_request_digest)=32),
 previous_effect_digest bytea NOT NULL CHECK(octet_length(previous_effect_digest)=32),
 enriched_effect_digest bytea NOT NULL CHECK(octet_length(enriched_effect_digest)=32),
 previous_effect jsonb NOT NULL,enriched_effect jsonb NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,effect_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,effect_id) REFERENCES zasp_connector_maintenance.tasks,
 CHECK(public.digest(convert_to(previous_effect::text,'UTF8'),'sha256')=previous_effect_digest),
 CHECK(public.digest(convert_to(enriched_effect::text,'UTF8'),'sha256')=enriched_effect_digest),
 CHECK(previous_effect-'oauth_attempt_id'=enriched_effect-'oauth_attempt_id'),
 CHECK(previous_effect->'oauth_attempt_id'='null'::jsonb AND enriched_effect->>'oauth_attempt_id'=oauth_attempt_id));
CREATE TABLE zasp_connector_maintenance.creation_witness(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,effect_id text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,effect_id));
CREATE TABLE zasp_connector_maintenance.principals(
 principal_name name PRIMARY KEY,source_checksum text NOT NULL CHECK(source_checksum='-- connector maintenance checksum'),
 key_version text NOT NULL CHECK(key_version~'^[a-f0-9]{64}$'));
CREATE TABLE zasp_connector_maintenance.verifiers(
 key_version text PRIMARY KEY CHECK(key_version~'^[a-f0-9]{64}$'),
 key_material bytea NOT NULL CHECK(octet_length(key_material)=32),
 purpose text NOT NULL CHECK(purpose IN('connector-forward','connector-captured')),
 principal_name name NOT NULL REFERENCES zasp_connector_maintenance.principals);
CREATE TABLE zasp_connector_maintenance.reservations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,effect_id text NOT NULL,
 lease_owner text NOT NULL CHECK(length(lease_owner) BETWEEN 3 AND 128),lease_token text NOT NULL CHECK(lease_token~'^[a-f0-9]{64}$'),
 expires_at timestamptz NOT NULL,intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
 context_digest bytea NOT NULL CHECK(octet_length(context_digest)=32),
 state text NOT NULL CHECK(state IN('reserved','attempted','settled')),attempt integer NOT NULL CHECK(attempt BETWEEN 0 AND 100),
 captured_receipt jsonb,PRIMARY KEY(organization_id,workspace_id,environment_id,effect_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,effect_id) REFERENCES zasp_connector_maintenance.tasks);
CREATE FUNCTION zasp_connector_maintenance.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fp$
 WITH objects AS (
 SELECT 'namespace' k,n.nspname i,jsonb_build_array(n.nspowner::regrole::text,n.nspacl::text) d FROM pg_namespace n WHERE n.nspname='zasp_connector_maintenance'
 UNION ALL SELECT 'table',c.relname,jsonb_build_array(c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity,c.relpersistence) FROM pg_class c WHERE c.relnamespace='zasp_connector_maintenance'::regnamespace AND c.relkind IN('r','v')
 UNION ALL SELECT 'view',c.relname,jsonb_build_array(pg_get_viewdef(c.oid,true),c.relowner::regrole::text,c.relacl::text) FROM pg_class c WHERE c.relnamespace='zasp_connector_maintenance'::regnamespace AND c.relkind='v'
 UNION ALL SELECT 'column',c.relname||'.'||a.attnum,jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated,a.attcollation) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_connector_maintenance'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT 'constraint',c.relname||'.'||x.conname,jsonb_build_array(pg_get_constraintdef(x.oid,true),x.convalidated,x.condeferrable,x.condeferred) FROM pg_constraint x JOIN pg_class c ON c.oid=x.conrelid WHERE c.relnamespace='zasp_connector_maintenance'::regnamespace
 UNION ALL SELECT 'index',c.relname,jsonb_build_array(pg_get_indexdef(x.indexrelid),x.indisvalid,x.indisready) FROM pg_index x JOIN pg_class c ON c.oid=x.indexrelid WHERE c.relnamespace='zasp_connector_maintenance'::regnamespace
 UNION ALL SELECT 'policy',c.relname||'.'||p.polname,jsonb_build_array(p.polcmd,p.polpermissive,p.polroles,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_connector_maintenance'::regnamespace
 UNION ALL SELECT 'trigger',c.relname||'.'||t.tgname,jsonb_build_array(pg_get_triggerdef(t.oid),t.tgenabled) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_connector_maintenance'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT 'function',p.oid::regprocedure::text,jsonb_build_array(pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_proc p WHERE p.pronamespace='zasp_connector_maintenance'::regnamespace
 ) SELECT encode(public.digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(k,i,d) ORDER BY k,i)::text,'[]'),'UTF8'),'sha256'),'hex') FROM objects
 $fp$;
CREATE FUNCTION zasp_connector_maintenance.effect_snapshot(n public.zasp_connector_effects) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $effect_snapshot$
 SELECT jsonb_build_object('organization_id',n.organization_id,'workspace_id',n.workspace_id,'environment_id',n.environment_id,'effect_id',n.id,'integration_id',n.integration_id,'oauth_attempt_id',n.oauth_attempt_id,'provider',n.provider,'operation',n.operation,'idempotency_key',n.idempotency_key,'request_digest',encode(n.request_digest,'hex'),'reference',n.connection_reference,'available_at',n.available_at,'reason',n.last_error_code)
$effect_snapshot$;
CREATE FUNCTION zasp_connector_maintenance.effect_context(n public.zasp_connector_effects) RETURNS bytea LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $effect_context$
 SELECT public.digest(convert_to(jsonb_build_object('integration_id',n.integration_id,'oauth_attempt_id',n.oauth_attempt_id,'provider',n.provider,'operation',n.operation,'idempotency_key',n.idempotency_key,'request_digest',encode(n.request_digest,'hex'),'connection_reference',n.connection_reference,'last_error_code',n.last_error_code,'oauth',(SELECT jsonb_build_object('principal_id',a.principal_id,'requested_scopes',a.requested_scopes) FROM public.zasp_connector_oauth_attempts a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.id)=(n.organization_id,n.workspace_id,n.environment_id,n.oauth_attempt_id)))::text,'UTF8'),'sha256')
$effect_context$;
CREATE FUNCTION zasp_connector_maintenance.effect_matches(n public.zasp_connector_effects,t zasp_connector_maintenance.tasks) RETURNS boolean LANGUAGE sql STABLE AS $effect_matches$
 -- Availability/backoff and reason legitimately evolve under original retry
 -- semantics. All external-effect intent fields remain protected. A changed
 -- OAuth cleanup reference is admitted only when THIS native captured settle
 -- recorded that exact successful original completion, never from raw drift.
 SELECT COALESCE((zasp_connector_maintenance.effect_snapshot(n)-ARRAY['available_at','reason','reference']) IS NOT DISTINCT FROM(COALESCE((SELECT x.enriched_effect FROM zasp_connector_maintenance.oauth_enrichments x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id,x.grantor_id,x.previous_effect_digest)=(t.organization_id,t.workspace_id,t.environment_id,t.effect_id,t.grantor_id,t.committed_effect_digest)),t.captured_effect)-ARRAY['available_at','reason','reference'])
 AND n.operation=t.operation AND n.connection_reference IS NOT DISTINCT FROM CASE WHEN t.authorized_reference IS NULL THEN t.captured_effect->>'reference' ELSE t.authorized_reference END
 AND (EXISTS(SELECT 1 FROM zasp_connector_provenance.origins o WHERE t.operation='pkce_cleanup' AND(o.organization_id,o.workspace_id,o.environment_id,o.effect_id,o.integration_id,o.principal_id,o.source_profile,o.source_proof_digest,o.committed_request_digest,o.committed_effect_digest)=(t.organization_id,t.workspace_id,t.environment_id,t.effect_id,t.integration_id,t.grantor_id,t.source_profile,t.source_proof_digest,t.committed_request_digest,t.committed_effect_digest)) OR EXISTS(SELECT 1 FROM zasp_connector_maintenance.enqueue_origins o WHERE(o.organization_id,o.workspace_id,o.environment_id,o.effect_id,o.integration_id,o.grantor_id,o.operation,o.source_profile,o.source_proof_digest,o.committed_request_digest,o.committed_effect_digest)=(t.organization_id,t.workspace_id,t.environment_id,t.effect_id,t.integration_id,t.grantor_id,t.operation,t.source_profile,t.source_proof_digest,t.committed_request_digest,t.committed_effect_digest))),false)
$effect_matches$;
CREATE FUNCTION zasp_connector_maintenance.catalog_ready(pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $catalog$
 SELECT COALESCE(pin='-- connector maintenance checksum'
 AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration r WHERE r.singleton AND r.checksum=pin AND r.fingerprint=zasp_connector_maintenance.fingerprint())
 AND zasp_connector_provenance.catalog_matches('-- connector provenance checksum')
 AND zasp_authorization80.ready('-- authorization80 checksum'),false)
$catalog$;
CREATE FUNCTION zasp_connector_maintenance.caller_ready(pin text,version_value text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $caller$
 SELECT COALESCE(zasp_connector_maintenance.catalog_ready(pin)
 AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration WHERE singleton AND active)
 AND public.zasp_discovery_principal_ready('zasp_outbox_worker')
 AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.principals p JOIN zasp_connector_maintenance.verifiers v ON(v.principal_name,v.key_version)=(p.principal_name,p.key_version)
 WHERE p.principal_name=session_user AND p.source_checksum=pin AND p.key_version=version_value AND v.purpose='connector-forward'),false)
$caller$;
-- The task is created in the very same protected subtransaction as original
-- enqueue. A historical captured record cannot be retroactively delegated.
CREATE FUNCTION zasp_connector_maintenance.capture_pkce_cleanup(envelope text,o text,w text,e text,id_value text,integration_value text,attempt_value text,provider_value text,reference_value text,request_value bytea,available_value timestamptz,reason_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $capture_task$
DECLARE result_value jsonb;origin zasp_connector_provenance.origins;task zasp_connector_maintenance.tasks;p jsonb;existed boolean;witness_xid xid;task_xid xid;task_value text;principal_value text;effect_value public.zasp_connector_effects;
BEGIN
 IF zasp_connector_maintenance.catalog_ready('-- connector maintenance checksum') IS NOT TRUE
 OR public.zasp_discovery_principal_ready('zasp_discovery_api') IS NOT TRUE OR envelope IS NULL
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector task capture unavailable';END IF;
 -- Original verified credential, session, scope, revision and signature fence
 -- holds the existing79 organization row lock before the absence observation.
 PERFORM zasp_authorization80.fence(envelope);
 p:=zasp_authorization80.context();
 IF (p->>'organization_id',p->>'workspace_id',p->>'environment_id') IS DISTINCT FROM(o,w,e)
 OR p->>'operation_id' IS DISTINCT FROM 'authorizeIntegration' OR p->>'permission' IS DISTINCT FROM 'manage_workflows'
 OR p#>>'{path_parameters,id}' IS DISTINCT FROM integration_value
 OR zasp_authorization80.allowed(o,w,e,'integration',integration_value) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector task purpose rejected';END IF;
 SELECT x.* INTO origin FROM zasp_connector_provenance.origins x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(o,w,e,id_value) FOR UPDATE;
 existed:=FOUND;
 IF existed THEN
  SELECT x.* INTO task FROM zasp_connector_maintenance.tasks x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(o,w,e,id_value) FOR UPDATE;
  IF NOT FOUND OR task.grantor_id IS DISTINCT FROM p->>'principal_id'
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector task source unavailable';END IF;
 ELSE
  INSERT INTO zasp_connector_maintenance.creation_witness VALUES(o,w,e,id_value) RETURNING xmin INTO witness_xid;
 END IF;
 result_value:=zasp_connector_provenance.capture_pkce_cleanup(envelope,o,w,e,id_value,integration_value,attempt_value,provider_value,reference_value,request_value,available_value,reason_value);
 SELECT x.* INTO origin FROM zasp_connector_provenance.origins x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(o,w,e,id_value) FOR UPDATE;
 IF NOT FOUND OR origin.principal_id IS DISTINCT FROM p->>'principal_id' OR origin.integration_id IS DISTINCT FROM integration_value
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector task enqueue changed';END IF;
 IF NOT existed THEN
  -- The original protected creator proves fresh effect+origin inside its own
  -- creation context. We do NOT compare its xmin to this outer witness: an
  -- inner EXCEPTION block may own a different legitimate subtransaction. The
  -- unchanged native79 org fence serialized the absence observation; old
  -- origin-without-task already refused before this exact creator invocation.
  -- The service is the explicit bounded connector maintenance actor; membership
  -- and its delegation exist only in the composed registered projection. This
  -- is not a discovery schedule/task and never enters immutable79.current_grants.
  task_value:=public.zasp_discovery_canonical_id(o,w,e,'connector_reconciliation_task',id_value||chr(31)||encode(origin.committed_effect_digest,'hex'));
  principal_value:=public.zasp_discovery_canonical_id(o,w,e,'connector_maintenance_service',integration_value);
  SELECT * INTO STRICT effect_value FROM public.zasp_connector_effects WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,id_value);
  INSERT INTO zasp_connector_maintenance.tasks VALUES(o,w,e,id_value,integration_value,'pkce_cleanup',task_value,principal_value,origin.principal_id,'connector_reconciliation',origin.source_profile,origin.source_proof_digest,origin.committed_request_digest,origin.committed_effect_digest,zasp_connector_maintenance.effect_snapshot(effect_value),NULL,'captured_inactive') RETURNING xmin INTO task_xid;
  IF task_xid IS DISTINCT FROM witness_xid THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector task creation unavailable';END IF;
  DELETE FROM zasp_connector_maintenance.creation_witness x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(o,w,e,id_value) AND x.xmin=witness_xid;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector task witness changed';END IF;
 ELSE
  IF(task.integration_id,task.grantor_id,task.source_profile,task.source_proof_digest,task.committed_request_digest,task.committed_effect_digest)
  IS DISTINCT FROM(origin.integration_id,origin.principal_id,origin.source_profile,origin.source_proof_digest,origin.committed_request_digest,origin.committed_effect_digest)
  THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector task replay conflict';END IF;
 END IF;
 IF zasp_authorization80.context() IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector task admission expired';END IF;
 RETURN result_value;
END $capture_task$;
-- Private native creator. A protected witness made before invoking the
-- exact original enqueue is required for new rows; old originless work refuses.
CREATE FUNCTION zasp_connector_maintenance.record_created_origin(envelope text,o text,w text,e text,id_value text,operation_value text,witness_value xid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $created_origin$
DECLARE p jsonb;n public.zasp_connector_effects;receipt zasp_connector_maintenance.enqueue_origins;row_xid xid;task_xid xid;body_value jsonb;digest_value bytea;task_value text;principal_value text;BEGIN
 IF operation_value IS NULL OR operation_value NOT IN('authorize','revoke') OR zasp_connector_maintenance.catalog_ready('-- connector maintenance checksum') IS NOT TRUE OR public.zasp_discovery_principal_ready('zasp_discovery_api') IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector origin unavailable';END IF;
 p:=zasp_authorization80.context();
 SELECT * INTO STRICT n FROM public.zasp_connector_effects WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,id_value) FOR UPDATE;
 IF p IS NULL OR (p->>'organization_id',p->>'workspace_id',p->>'environment_id') IS DISTINCT FROM(o,w,e)
 OR p->>'permission' IS DISTINCT FROM 'manage_workflows'
 OR(operation_value='authorize' AND(p->>'credential_kind' IS DISTINCT FROM '1' OR p->>'fresh_auth' IS DISTINCT FROM 'true'))
 OR(operation_value='revoke' AND NOT COALESCE(p->>'credential_kind' IN('1','2'),false))
 OR p->>'operation_id' IS DISTINCT FROM(CASE operation_value WHEN 'authorize' THEN 'authorizeIntegration' ELSE 'deleteIntegration' END)
 OR p#>>'{path_parameters,id}' IS DISTINCT FROM n.integration_id OR n.operation IS DISTINCT FROM operation_value
 OR zasp_authorization80.allowed(o,w,e,'integration',n.integration_id) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector origin purpose rejected';END IF;
 body_value:=zasp_connector_maintenance.effect_snapshot(n);digest_value:=public.digest(convert_to(body_value::text,'UTF8'),'sha256');
 SELECT * INTO receipt FROM zasp_connector_maintenance.enqueue_origins WHERE(organization_id,workspace_id,environment_id,effect_id)=(o,w,e,id_value) FOR UPDATE;
 IF FOUND THEN
  IF(receipt.integration_id,receipt.grantor_id,receipt.operation,receipt.committed_request_digest) IS DISTINCT FROM(n.integration_id,p->>'principal_id',operation_value,n.request_digest)
  OR NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.tasks t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.effect_id,t.integration_id,t.grantor_id,t.operation,t.committed_effect_digest)=(o,w,e,id_value,n.integration_id,p->>'principal_id',operation_value,receipt.committed_effect_digest) AND zasp_connector_maintenance.effect_matches(n,t))
  THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector origin replay changed';END IF;
 ELSE
  SELECT xmin INTO STRICT row_xid FROM public.zasp_connector_effects WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,id_value);
  IF witness_value IS NULL OR row_xid IS DISTINCT FROM witness_value OR NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.creation_witness x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(o,w,e,id_value) AND x.xmin=witness_value)
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector origin creation unavailable';END IF;
  INSERT INTO zasp_connector_maintenance.enqueue_origins VALUES(o,w,e,id_value,n.integration_id,p->>'principal_id',operation_value,'-- authorization80 checksum',public.digest(convert_to(envelope,'UTF8'),'sha256'),n.request_digest,digest_value);
  task_value:=public.zasp_discovery_canonical_id(o,w,e,'connector_reconciliation_task',id_value||chr(31)||encode(digest_value,'hex'));
  principal_value:=public.zasp_discovery_canonical_id(o,w,e,'connector_maintenance_service',n.integration_id);
  INSERT INTO zasp_connector_maintenance.tasks VALUES(o,w,e,id_value,n.integration_id,operation_value,task_value,principal_value,p->>'principal_id','connector_reconciliation','-- authorization80 checksum',public.digest(convert_to(envelope,'UTF8'),'sha256'),n.request_digest,digest_value,body_value,NULL,'captured_inactive') RETURNING xmin INTO task_xid;
  IF task_xid IS DISTINCT FROM witness_value THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector origin task creation unavailable';END IF;
  DELETE FROM zasp_connector_maintenance.creation_witness x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(o,w,e,id_value) AND x.xmin=witness_value;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector origin witness changed';END IF;
 END IF;
END $created_origin$;
CREATE FUNCTION zasp_connector_maintenance.start_oauth(envelope text,o text,w text,e text,attempt_value text,integration_value text,provider_value text,principal_value text,session_value bytea,state_value bytea,reference_value text,request_value bytea,scopes_value jsonb,expires_value timestamptz,integration_version_value bigint,configuration_value jsonb,cleanup_value text,authorize_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $start_oauth$
DECLARE p jsonb;result_value jsonb;t zasp_connector_maintenance.tasks;witness_value xid;previous_value jsonb;BEGIN
 IF zasp_connector_maintenance.catalog_ready('-- connector maintenance checksum') IS NOT TRUE OR public.zasp_discovery_principal_ready('zasp_discovery_api') IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector OAuth capture unavailable';END IF;
 PERFORM zasp_authorization80.fence(envelope);p:=zasp_authorization80.context();
 IF p IS NULL OR(p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'operation_id',p->>'permission',p->>'credential_kind',p->>'fresh_auth') IS DISTINCT FROM(o,w,e,principal_value,'authorizeIntegration','manage_workflows','1','true')
 OR session_value IS DISTINCT FROM decode(p->>'credential_digest','hex') OR p#>>'{path_parameters,id}' IS DISTINCT FROM integration_value
 OR zasp_authorization80.allowed(o,w,e,'integration',integration_value) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector OAuth source rejected';END IF;
 SELECT * INTO t FROM zasp_connector_maintenance.tasks WHERE(organization_id,workspace_id,environment_id,effect_id)=(o,w,e,cleanup_value) FOR UPDATE;
 IF NOT FOUND THEN
  -- Preserve the supported original direct StartOAuth path while deriving its
  -- cleanup only through the exact protected creator, in this same transaction.
  PERFORM zasp_connector_maintenance.capture_pkce_cleanup(envelope,o,w,e,cleanup_value,integration_value,'',provider_value,reference_value,request_value,expires_value,'oauth_attempt_expiry');
  SELECT * INTO STRICT t FROM zasp_connector_maintenance.tasks WHERE(organization_id,workspace_id,environment_id,effect_id)=(o,w,e,cleanup_value) FOR UPDATE;
 END IF;
 IF(t.integration_id,t.operation,t.grantor_id,t.committed_request_digest) IS DISTINCT FROM(integration_value,'pkce_cleanup',principal_value,request_value)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector OAuth cleanup source changed';END IF;
 previous_value:=t.captured_effect;
 IF EXISTS(SELECT 1 FROM public.zasp_connector_effects WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,authorize_value)) THEN
  IF NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.enqueue_origins WHERE(organization_id,workspace_id,environment_id,effect_id,grantor_id,operation)=(o,w,e,authorize_value,principal_value,'authorize')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector OAuth legacy origin unavailable';END IF;
 ELSE
  INSERT INTO zasp_connector_maintenance.creation_witness VALUES(o,w,e,authorize_value) RETURNING xmin INTO witness_value;
 END IF;
 result_value:=public.zasp_connector_start_oauth(o,w,e,attempt_value,integration_value,provider_value,principal_value,session_value,state_value,reference_value,request_value,scopes_value,expires_value,integration_version_value,configuration_value,cleanup_value,authorize_value);
 PERFORM zasp_connector_maintenance.record_oauth_enrichment(envelope,o,w,e,cleanup_value,attempt_value,previous_value);
 PERFORM zasp_connector_maintenance.record_created_origin(envelope,o,w,e,authorize_value,'authorize',witness_value);
 IF zasp_authorization80.context() IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector OAuth capture expired';END IF;
 PERFORM zasp_connector_maintenance.promote_enqueued(o,w,e,ARRAY[cleanup_value,authorize_value]);
 RETURN result_value;
END $start_oauth$;
CREATE FUNCTION zasp_connector_maintenance.delete_integration(envelope text,id_value text,o text,w text,e text,actor_value text,key_value text,expected_version bigint,intent_value jsonb,body_value jsonb,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $delete_integration$
DECLARE p jsonb;result_value jsonb;effect_value text;witness_value xid;typed_version bigint;BEGIN
 IF zasp_connector_maintenance.catalog_ready('-- connector maintenance checksum') IS NOT TRUE OR public.zasp_discovery_principal_ready('zasp_discovery_api') IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector delete capture unavailable';END IF;
 -- Delete's original policy permits browser or PAT and does not require fresh
 -- auth. The ORIGINAL signed native fence retains its credential/ceiling checks.
 PERFORM zasp_authorization80.fence(envelope);p:=zasp_authorization80.context();
 IF p IS NULL OR(p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'operation_id',p->>'permission') IS DISTINCT FROM(o,w,e,actor_value,'deleteIntegration','manage_workflows')
 OR NOT COALESCE(p->>'credential_kind' IN('1','2'),false) OR p#>>'{path_parameters,id}' IS DISTINCT FROM id_value
 OR zasp_authorization80.allowed(o,w,e,'integration',id_value) IS NOT TRUE
 OR NOT COALESCE(key_value~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' AND expected_version BETWEEN 1 AND 1000000
 AND intent_value=jsonb_build_object('resource_id',id_value,'expected_version',expected_version,'body','{}'::jsonb),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector delete source rejected';END IF;
 SELECT version INTO STRICT typed_version FROM public.zasp_integrations WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,id_value) FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'targets') x WHERE(x->>'kind',x->>'id',(x->>'version')::bigint)=('integration',id_value,typed_version))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector delete target changed';END IF;
 effect_value:=public.zasp_discovery_canonical_id(o,w,e,'connector_effect','revoke'||chr(31)||id_value||chr(31)||key_value);
 IF EXISTS(SELECT 1 FROM public.zasp_connector_effects WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,effect_value)) THEN
  IF NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.enqueue_origins WHERE(organization_id,workspace_id,environment_id,effect_id,integration_id,grantor_id,operation)=(o,w,e,effect_value,id_value,actor_value,'revoke')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector delete legacy origin unavailable';END IF;
 ELSE
  INSERT INTO zasp_connector_maintenance.creation_witness VALUES(o,w,e,effect_value) RETURNING xmin INTO witness_value;
 END IF;
 -- Exact existing current connector/receipt composition; all original lease,
 -- idempotency, payload, credential and audit rules remain in that body.
 result_value:=zasp_authorization80.integration_connector_mutate('delete','integration',id_value,o,w,e,actor_value,'deleteIntegration',key_value,expected_version,intent_value,body_value,audit_value,correlation_value,receipt_value);
 IF EXISTS(SELECT 1 FROM public.zasp_connector_effects WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,effect_value)) THEN
  PERFORM zasp_connector_maintenance.record_created_origin(envelope,o,w,e,effect_value,'revoke',witness_value);
 ELSE
  -- Original no-provider delete creates no reconciliation effect. Remove its
  -- transient witness without inventing a task/origin for a nonexistent effect.
  DELETE FROM zasp_connector_maintenance.creation_witness x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(o,w,e,effect_value) AND x.xmin=witness_value;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector delete witness unavailable';END IF;
 END IF;
 IF zasp_authorization80.context() IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector delete capture expired';END IF;
 PERFORM zasp_connector_maintenance.promote_enqueued(o,w,e,ARRAY[effect_value]);
 RETURN result_value;
END $delete_integration$;
-- Private append writer: not granted to API/worker. It must run under the
-- same original signed request/org fence as the typed OAuth start wrapper.
CREATE FUNCTION zasp_connector_maintenance.record_oauth_enrichment(envelope text,o text,w text,e text,id_value text,attempt_value text,previous_value jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $enrich$
DECLARE p jsonb;t zasp_connector_maintenance.tasks;n public.zasp_connector_effects;a public.zasp_connector_oauth_attempts;next_value jsonb;BEGIN
 IF zasp_connector_maintenance.catalog_ready('-- connector maintenance checksum') IS NOT TRUE OR public.zasp_discovery_principal_ready('zasp_discovery_api') IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector enrichment unavailable';END IF;
 PERFORM zasp_authorization80.fence(envelope);p:=zasp_authorization80.context();
 IF p IS NULL OR (p->>'organization_id',p->>'workspace_id',p->>'environment_id') IS DISTINCT FROM(o,w,e)
 OR p->>'operation_id' IS DISTINCT FROM 'authorizeIntegration' OR p->>'permission' IS DISTINCT FROM 'manage_workflows'
 OR p->>'credential_kind' IS DISTINCT FROM '1' OR p->>'fresh_auth' IS DISTINCT FROM 'true'
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector enrichment purpose rejected';END IF;
 SELECT * INTO STRICT t FROM zasp_connector_maintenance.tasks WHERE(organization_id,workspace_id,environment_id,effect_id)=(o,w,e,id_value) FOR UPDATE;
 SELECT * INTO STRICT n FROM public.zasp_connector_effects WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,id_value) FOR UPDATE;
 SELECT * INTO STRICT a FROM public.zasp_connector_oauth_attempts WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,attempt_value) FOR UPDATE;
 next_value:=zasp_connector_maintenance.effect_snapshot(n);
 IF t.operation IS DISTINCT FROM 'pkce_cleanup' OR t.grantor_id IS DISTINCT FROM p->>'principal_id'
 OR p#>>'{path_parameters,id}' IS DISTINCT FROM t.integration_id
 OR (a.integration_id,a.provider,a.principal_id,a.request_digest,a.pkce_verifier_reference,a.expires_at,a.session_digest)
 IS DISTINCT FROM(t.integration_id,n.provider,t.grantor_id,t.committed_request_digest,n.connection_reference,n.available_at,decode(p->>'credential_digest','hex'))
 OR n.oauth_attempt_id IS DISTINCT FROM attempt_value
 OR(a.status IS DISTINCT FROM 'pending' AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.oauth_enrichments x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id,x.oauth_attempt_id,x.grantor_id)=(o,w,e,id_value,attempt_value,t.grantor_id)))
 OR previous_value IS DISTINCT FROM t.captured_effect
 OR previous_value->'oauth_attempt_id' IS DISTINCT FROM 'null'::jsonb
 OR previous_value-'oauth_attempt_id' IS DISTINCT FROM next_value-'oauth_attempt_id'
 OR zasp_authorization80.allowed(o,w,e,'integration',t.integration_id) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector enrichment source rejected';END IF;
 INSERT INTO zasp_connector_maintenance.oauth_enrichments VALUES(o,w,e,id_value,attempt_value,t.grantor_id,public.digest(convert_to(envelope,'UTF8'),'sha256'),t.committed_request_digest,t.committed_effect_digest,public.digest(convert_to(next_value::text,'UTF8'),'sha256'),previous_value,next_value) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.oauth_enrichments x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id,x.oauth_attempt_id,x.grantor_id,x.committed_request_digest,x.previous_effect_digest,x.previous_effect,x.enriched_effect)=(o,w,e,id_value,attempt_value,t.grantor_id,t.committed_request_digest,t.committed_effect_digest,previous_value,next_value))
 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector enrichment replay changed';END IF;
 IF zasp_authorization80.context() IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector enrichment expired';END IF;
END $enrich$;
-- Original fairness/lane/capacity selection below is compiled from the
-- unchanged original claim body. Only genuine-task eligibility, deferred
-- attempt increment and the exact protected reservation write are added.
CREATE FUNCTION zasp_connector_maintenance.reserve(q jsonb,pin text,version_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $reserve$
DECLARE result_value jsonb;available_slots integer;owner_value text;lease_seconds integer;limit_value integer;BEGIN
 IF zasp_connector_maintenance.caller_ready(pin,version_value) IS NOT TRUE OR zasp_sa_multistep_prior.closed(q,ARRAY['owner','seconds','limit']) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector reserve unavailable';END IF;
 owner_value:=q->>'owner';lease_seconds:=(q->>'seconds')::integer;limit_value:=(q->>'limit')::integer;
 IF owner_value IS NULL OR length(owner_value) NOT BETWEEN 3 AND 128 OR lease_seconds IS NULL OR lease_seconds NOT BETWEEN 5 AND 300 OR limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='connector reserve shape rejected';END IF;
 PERFORM pg_advisory_xact_lock(742516322);
 SELECT GREATEST(0,LEAST(limit_value,100-count(*)::integer)) INTO available_slots FROM public.zasp_connector_effects WHERE status='unknown' AND lease_expires_at>transaction_timestamp();
 IF available_slots=0 THEN RETURN jsonb_build_object('items','[]'::jsonb);END IF;
  WITH candidates AS (SELECT lane.provider,lane.operation,effect.organization_id,effect.workspace_id,effect.environment_id,effect.id,effect.updated_at FROM zasp_connector_effect_lane_scopes lane CROSS JOIN LATERAL (SELECT candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.id,candidate.updated_at FROM zasp_connector_effects candidate WHERE candidate.provider=lane.provider AND candidate.operation=lane.operation AND candidate.organization_id=lane.organization_id AND candidate.workspace_id=lane.workspace_id AND candidate.environment_id=lane.environment_id AND candidate.status='unknown' AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.tasks task WHERE(task.organization_id,task.workspace_id,task.environment_id,task.effect_id)=(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.id) AND task.state IN('active','paused_denied')) AND candidate.attempt<100 AND candidate.available_at<=transaction_timestamp() AND candidate.updated_at<=transaction_timestamp()-interval '15 seconds' AND (candidate.lease_expires_at IS NULL OR candidate.lease_expires_at<=transaction_timestamp()) AND NOT EXISTS(SELECT 1 FROM zasp_connector_effects live WHERE live.provider=candidate.provider AND live.operation=candidate.operation AND live.status='unknown' AND live.lease_expires_at>transaction_timestamp()) AND (candidate.operation<>'pkce_cleanup' OR candidate.oauth_attempt_id IS NULL OR NOT EXISTS(SELECT 1 FROM zasp_connector_oauth_attempts attempt WHERE (attempt.organization_id,attempt.workspace_id,attempt.environment_id,attempt.id)=(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.oauth_attempt_id) AND attempt.status='consuming')) ORDER BY candidate.updated_at,candidate.id LIMIT 1) effect),
  lane_fair AS (SELECT candidates.*,row_number() OVER(PARTITION BY provider,operation ORDER BY updated_at,id) lane_rank FROM candidates),
  fair AS (SELECT lane_fair.*,row_number() OVER(PARTITION BY organization_id,workspace_id,environment_id ORDER BY updated_at,id) organization_rank FROM lane_fair WHERE lane_rank=1),
  selected AS (SELECT effect.organization_id,effect.workspace_id,effect.environment_id,effect.id FROM zasp_connector_effects effect JOIN fair ON (fair.organization_id,fair.workspace_id,fair.environment_id,fair.id)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.id) ORDER BY fair.organization_rank,effect.updated_at,effect.id FOR UPDATE OF effect SKIP LOCKED LIMIT available_slots),
  updated AS (UPDATE zasp_connector_effects effect SET lease_owner=owner_value,lease_token=encode(gen_random_bytes(32),'hex'),lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() FROM selected WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.id)=(selected.organization_id,selected.workspace_id,selected.environment_id,selected.id) RETURNING effect.*),
 recorded AS (INSERT INTO zasp_connector_maintenance.reservations(organization_id,workspace_id,environment_id,effect_id,lease_owner,lease_token,expires_at,intent_digest,context_digest,state,attempt)
 SELECT u.organization_id,u.workspace_id,u.environment_id,u.id,u.lease_owner,u.lease_token,u.lease_expires_at,t.committed_effect_digest,zasp_connector_maintenance.effect_context(u),'reserved',u.attempt FROM updated u JOIN zasp_connector_maintenance.tasks t ON(t.organization_id,t.workspace_id,t.environment_id,t.effect_id)=(u.organization_id,u.workspace_id,u.environment_id,u.id)
 ON CONFLICT(organization_id,workspace_id,environment_id,effect_id) DO UPDATE SET lease_owner=EXCLUDED.lease_owner,lease_token=EXCLUDED.lease_token,expires_at=EXCLUDED.expires_at,intent_digest=EXCLUDED.intent_digest,context_digest=EXCLUDED.context_digest,state='reserved',attempt=EXCLUDED.attempt,captured_receipt=NULL
 RETURNING effect_id)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'id',id,'integration_id',integration_id,'oauth_attempt_id',oauth_attempt_id,'principal_id',(SELECT principal_id FROM zasp_connector_oauth_attempts attempt WHERE (attempt.organization_id,attempt.workspace_id,attempt.environment_id,attempt.id)=(updated.organization_id,updated.workspace_id,updated.environment_id,updated.oauth_attempt_id)),'requested_scopes',(SELECT requested_scopes FROM zasp_connector_oauth_attempts attempt WHERE (attempt.organization_id,attempt.workspace_id,attempt.environment_id,attempt.id)=(updated.organization_id,updated.workspace_id,updated.environment_id,updated.oauth_attempt_id)),'provider',provider,'operation',operation,'connection_reference',connection_reference,'idempotency_key',idempotency_key,'request_digest',encode(request_digest,'hex'),'intent_digest',(SELECT encode(t.committed_effect_digest,'hex') FROM zasp_connector_maintenance.tasks t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.effect_id)=(updated.organization_id,updated.workspace_id,updated.environment_id,updated.id)),'last_error_code',last_error_code,'attempt',attempt,'lease_owner',lease_owner,'lease_token',lease_token,'lease_expires_at',lease_expires_at) ORDER BY updated_at,id),'[]'::jsonb)) INTO result_value FROM updated WHERE EXISTS(SELECT 1 FROM recorded WHERE effect_id=updated.id);

 RETURN result_value;
END $reserve$;
CREATE FUNCTION zasp_connector_maintenance.recover(q jsonb,pin text,version_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $recover$
DECLARE owner_value text;lease_seconds integer;limit_value integer;n record;token_value text;error_value text;recovered_value integer:=0;body_value jsonb;body_bytes bytea;key_value bytea;org_value text;selected_scope jsonb;BEGIN
 IF zasp_connector_maintenance.caller_ready(pin,version_value) IS NOT TRUE OR zasp_sa_multistep_prior.closed(q,ARRAY['owner','seconds','limit']) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector recovery unavailable';END IF;
 owner_value:=q->>'owner';lease_seconds:=(q->>'seconds')::integer;limit_value:=(q->>'limit')::integer;
 IF owner_value IS NULL OR length(owner_value) NOT BETWEEN 3 AND 128 OR lease_seconds IS NULL OR lease_seconds NOT BETWEEN 5 AND 300 OR limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='connector recovery shape rejected';END IF;
 PERFORM pg_advisory_xact_lock(742516322);
 SELECT COALESCE(jsonb_agg(to_jsonb(selected)),'[]'::jsonb) INTO selected_scope FROM(SELECT effect.organization_id,effect.workspace_id,effect.environment_id,effect.id FROM public.zasp_connector_effects effect JOIN zasp_connector_maintenance.reservations r ON(r.organization_id,r.workspace_id,r.environment_id,r.effect_id,r.lease_owner,r.lease_token,r.expires_at,r.attempt)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.id,effect.lease_owner,effect.lease_token,effect.lease_expires_at,effect.attempt)
 WHERE r.state='attempted' AND effect.status='unknown' AND effect.attempt=100 AND effect.lease_expires_at<=transaction_timestamp()
 AND COALESCE(effect.last_error_code,'') NOT IN('provider_outcome_ambiguous','provider_cleanup_ambiguous','provider_revocation_ambiguous','pkce_cleanup_ambiguous')
 AND zasp_connector_maintenance.effect_matches(effect,(SELECT task FROM zasp_connector_maintenance.tasks task WHERE(task.organization_id,task.workspace_id,task.environment_id,task.effect_id)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.id))) IS TRUE
 ORDER BY effect.lease_expires_at,effect.id LIMIT limit_value) selected;
 FOR org_value IN SELECT DISTINCT x->>'organization_id' FROM jsonb_array_elements(selected_scope) x ORDER BY 1 LOOP
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=org_value FOR UPDATE;
 END LOOP;
 FOR n IN SELECT effect.*,r.captured_receipt FROM public.zasp_connector_effects effect JOIN zasp_connector_maintenance.reservations r ON(r.organization_id,r.workspace_id,r.environment_id,r.effect_id,r.lease_owner,r.lease_token,r.expires_at,r.attempt)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.id,effect.lease_owner,effect.lease_token,effect.lease_expires_at,effect.attempt)
 WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(selected_scope) x WHERE(x->>'organization_id',x->>'workspace_id',x->>'environment_id',x->>'id')=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.id)) AND r.state='attempted' AND effect.status='unknown' AND effect.attempt=100 AND effect.lease_expires_at<=transaction_timestamp()
 AND zasp_connector_maintenance.effect_matches(effect,(SELECT task FROM zasp_connector_maintenance.tasks task WHERE(task.organization_id,task.workspace_id,task.environment_id,task.effect_id)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.id))) IS TRUE
 AND COALESCE(effect.last_error_code,'') NOT IN('provider_outcome_ambiguous','provider_cleanup_ambiguous','provider_revocation_ambiguous','pkce_cleanup_ambiguous')
 ORDER BY effect.lease_expires_at,effect.id FOR UPDATE OF effect,r SKIP LOCKED LIMIT limit_value LOOP
  SELECT key_material INTO STRICT key_value FROM zasp_connector_maintenance.verifiers WHERE(key_version,principal_name,purpose)=(n.captured_receipt->>'version',session_user,'connector-captured');
  body_bytes:=decode(n.captured_receipt->>'body','base64');body_value:=convert_from(body_bytes,'UTF8')::jsonb;
  IF encode(public.hmac(convert_to('zasp-connector-captured-v1','UTF8')||decode('00','hex')||body_bytes,key_value,'sha256'),'hex') IS DISTINCT FROM n.captured_receipt->>'mac'
  OR zasp_sa_multistep_prior.closed(body_value,ARRAY['purpose','key_version','reference','attempt','kind','forward_digest','lease_expires_at','session_user']) IS NOT TRUE
 OR jsonb_typeof(body_value->'attempt') IS DISTINCT FROM 'number' OR body_value->>'kind' IS NULL OR body_value->>'kind' NOT IN('provider','secret_failure')
 OR body_value->>'purpose' IS DISTINCT FROM 'connector-captured' OR body_value->>'session_user' IS DISTINCT FROM session_user OR(body_value->>'attempt')::integer IS DISTINCT FROM 100
  OR(body_value#>>'{reference,effect_id}') IS DISTINCT FROM n.id OR(body_value->>'lease_expires_at')::timestamptz IS DISTINCT FROM n.lease_expires_at
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector recovery receipt rejected';END IF;
  token_value:=encode(public.gen_random_bytes(32),'hex');
  UPDATE public.zasp_connector_effects SET lease_owner=owner_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() WHERE(organization_id,workspace_id,environment_id,id)=(n.organization_id,n.workspace_id,n.environment_id,n.id);
  error_value:=CASE WHEN n.operation='pkce_cleanup' THEN 'pkce_cleanup_ambiguous' WHEN n.operation='revoke' THEN 'provider_revocation_ambiguous' WHEN n.last_error_code='cleanup_pending' THEN 'provider_cleanup_ambiguous' ELSE 'provider_outcome_ambiguous' END;
  PERFORM public.zasp_connector_quarantine_reconciliation(n.organization_id,n.workspace_id,n.environment_id,n.id,owner_value,token_value,error_value);
  UPDATE zasp_connector_maintenance.reservations SET state='settled' WHERE(organization_id,workspace_id,environment_id,effect_id)=(n.organization_id,n.workspace_id,n.environment_id,n.id);
  UPDATE zasp_connector_maintenance.tasks SET state='settled' WHERE(organization_id,workspace_id,environment_id,effect_id)=(n.organization_id,n.workspace_id,n.environment_id,n.id);
  PERFORM zasp_authorization79.touch(n.organization_id);recovered_value:=recovered_value+1;
 END LOOP;
 RETURN jsonb_build_object('recovered',recovered_value);
END $recover$;
CREATE FUNCTION zasp_connector_maintenance.revision(o text,pin text,version_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $revision$
DECLARE result_value jsonb;BEGIN
 IF zasp_connector_maintenance.caller_ready(pin,version_value) IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector caller unavailable';END IF;
 SELECT jsonb_build_object('organization_id',organization_id,'desired',desired,'applied',applied,'generation',generation,'store_id',store_id,'model_id',model_id) INTO STRICT result_value FROM zasp_authorization79.organizations WHERE organization_id=o;
 RETURN result_value;
END $revision$;
CREATE FUNCTION zasp_connector_maintenance.reference(r zasp_connector_maintenance.reservations,t zasp_connector_maintenance.tasks) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $reference$
 SELECT jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'effect_id',r.effect_id,'integration_id',t.integration_id,'lease_owner',r.lease_owner,'lease_token',r.lease_token,'intent_digest',encode(r.intent_digest,'hex'))
$reference$;
CREATE FUNCTION zasp_connector_maintenance.reserved(q jsonb,pin text,version_value text) RETURNS zasp_connector_maintenance.reservations LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $reserved$
DECLARE r zasp_connector_maintenance.reservations;t zasp_connector_maintenance.tasks;n public.zasp_connector_effects;BEGIN
 IF zasp_connector_maintenance.caller_ready(pin,version_value) IS NOT TRUE
 OR zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','effect_id','integration_id','lease_owner','lease_token','intent_digest']) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector reservation unavailable';END IF;
 -- Always acquire organization before original effect before reservation.
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR UPDATE;
 SELECT x.* INTO n FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'effect_id') FOR UPDATE;
 SELECT x.* INTO r FROM zasp_connector_maintenance.reservations x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'effect_id') FOR UPDATE;
 IF NOT FOUND OR r.state NOT IN('reserved','attempted') OR r.expires_at<=clock_timestamp()
 OR r.context_digest IS DISTINCT FROM zasp_connector_maintenance.effect_context(n)
 OR(n.lease_owner,n.lease_token,n.lease_expires_at) IS DISTINCT FROM(r.lease_owner,r.lease_token,r.expires_at)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector reservation lease lost';END IF;
 SELECT x.* INTO STRICT t FROM zasp_connector_maintenance.tasks x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
 IF zasp_connector_maintenance.reference(r,t) IS DISTINCT FROM q OR zasp_connector_maintenance.effect_matches(n,t) IS NOT TRUE OR n.integration_id IS DISTINCT FROM t.integration_id
 OR n.request_digest IS DISTINCT FROM t.committed_request_digest
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector reservation source changed';END IF;
 RETURN r;
END $reserved$;
CREATE FUNCTION zasp_connector_maintenance.source(q jsonb,pin text,version_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $source$
DECLARE r zasp_connector_maintenance.reservations;t zasp_connector_maintenance.tasks;n public.zasp_connector_effects;BEGIN
 r:=zasp_connector_maintenance.reserved(q,pin,version_value);
 SELECT * INTO STRICT t FROM zasp_connector_maintenance.tasks WHERE(organization_id,workspace_id,environment_id,effect_id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
 SELECT * INTO STRICT n FROM public.zasp_connector_effects WHERE(organization_id,workspace_id,environment_id,id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
 IF t.state NOT IN('active','paused_denied') OR n.operation NOT IN('authorize','revoke','pkce_cleanup') OR n.operation IS DISTINCT FROM t.operation OR n.attempt<>r.attempt OR n.attempt>=100
 OR NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.projection_activations a JOIN zasp_authorization79.organizations v ON(v.organization_id,v.store_id,v.model_id)=(a.organization_id,a.store_id,a.model_id) JOIN zasp_approval_maintenance.registration approval ON approval.singleton AND approval.checksum=a.approval_checksum WHERE a.organization_id=t.organization_id AND a.source_checksum=pin AND zasp_approval_maintenance.catalog_ready() IS TRUE)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector forward source unavailable';END IF;
 RETURN jsonb_build_object('profile_checksum',pin,'context_digest',encode(r.context_digest,'hex'),'reference',q,'task_id',t.task_id,'purpose',t.purpose,'grantor_id',t.grantor_id,'principal_id',t.principal_id,'source_profile',t.source_profile,'source_proof_digest',encode(t.source_proof_digest,'hex'),'committed_request_digest',encode(t.committed_request_digest,'hex'),'committed_effect_digest',encode(t.committed_effect_digest,'hex'),'operation',n.operation,'attempt',n.attempt,'lease_expires_at',r.expires_at,'session_user',session_user);
END $source$;
CREATE FUNCTION zasp_connector_maintenance.require_forward(q jsonb,envelope_value json,phase_value text,pin text,version_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $forward$
DECLARE body_bytes bytea;body_value jsonb;key_value bytea;facts_value jsonb;revision_value jsonb;BEGIN
 IF zasp_sa_multistep_prior.closed(envelope_value::jsonb,ARRAY['body','version','mac']) IS NOT TRUE OR envelope_value->>'version' IS DISTINCT FROM version_value THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector forward rejected';END IF;
 SELECT key_material INTO STRICT key_value FROM zasp_connector_maintenance.verifiers WHERE(key_version,principal_name,purpose)=(version_value,session_user,'connector-forward');
 body_bytes:=decode(envelope_value->>'body','base64');
 IF octet_length(body_bytes)>65536 OR encode(public.hmac(convert_to('zasp-connector-forward-v1','UTF8')||decode('00','hex')||body_bytes,key_value,'sha256'),'hex') IS DISTINCT FROM envelope_value->>'mac' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector forward rejected';END IF;
 body_value:=convert_from(body_bytes,'UTF8')::jsonb;
 facts_value:=zasp_connector_maintenance.source(q,pin,version_value);
 revision_value:=zasp_connector_maintenance.revision(q->>'organization_id',pin,version_value);
 IF zasp_sa_multistep_prior.closed(body_value,ARRAY['purpose','key_version','phase','facts','revision','issued_at','expires_at']) IS NOT TRUE
 OR body_value->>'purpose' IS DISTINCT FROM 'connector-forward' OR body_value->>'key_version' IS DISTINCT FROM version_value OR body_value->>'phase' IS DISTINCT FROM phase_value
 -- Go RFC3339Nano and PostgreSQL timestamptz JSON spell the same
 -- timestamp differently. Admit typed instant equality ONLY for this field;
 -- all other facts retain exact JSONB equality and every deadline fence.
 OR jsonb_typeof(body_value#>'{facts,lease_expires_at}') IS DISTINCT FROM 'string'
 OR ((body_value->'facts')-'lease_expires_at') IS DISTINCT FROM(facts_value-'lease_expires_at')
 OR (body_value#>>'{facts,lease_expires_at}')::timestamptz IS DISTINCT FROM(facts_value->>'lease_expires_at')::timestamptz
 OR body_value->'revision' IS DISTINCT FROM revision_value
 OR (revision_value->>'desired')::bigint IS DISTINCT FROM(revision_value->>'applied')::bigint
 OR jsonb_typeof(body_value->'issued_at') IS DISTINCT FROM 'number' OR jsonb_typeof(body_value->'expires_at') IS DISTINCT FROM 'number'
 OR (body_value->>'expires_at')::bigint-(body_value->>'issued_at')::bigint NOT BETWEEN 1 AND 60000
 OR (body_value->>'issued_at')::bigint>extract(epoch FROM clock_timestamp())*1000
 OR (body_value->>'expires_at')::bigint<=extract(epoch FROM clock_timestamp())*1000
 OR (body_value->>'expires_at')::bigint>(extract(epoch FROM(facts_value->>'lease_expires_at')::timestamptz)*1000)-100
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector forward rejected';END IF;
 RETURN body_value;
END $forward$;
CREATE FUNCTION zasp_connector_maintenance.release(q jsonb,denied_value boolean,pin text,version_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $release$
DECLARE r zasp_connector_maintenance.reservations;BEGIN
 r:=zasp_connector_maintenance.reserved(q,pin,version_value);
 IF denied_value IS NULL OR r.state IS DISTINCT FROM 'reserved' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector attempted reservation cannot release';END IF;
 UPDATE public.zasp_connector_effects SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE(organization_id,workspace_id,environment_id,id,lease_owner,lease_token)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id,r.lease_owner,r.lease_token) AND attempt=r.attempt;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector release lost';END IF;
 UPDATE zasp_connector_maintenance.tasks SET state=CASE WHEN denied_value THEN 'paused_denied' ELSE state END WHERE(organization_id,workspace_id,environment_id,effect_id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
 DELETE FROM zasp_connector_maintenance.reservations WHERE(organization_id,workspace_id,environment_id,effect_id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
 RETURN jsonb_build_object('transition',CASE WHEN denied_value THEN 'paused_denied' ELSE 'released' END);
END $release$;
CREATE FUNCTION zasp_connector_maintenance.begin_attempt(q jsonb,kind_value text,envelope_value json,pin text,version_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $begin$
DECLARE r zasp_connector_maintenance.reservations;forward_value jsonb;body_value json;key_value bytea;captured_version text;receipt_value jsonb;BEGIN
 IF kind_value IS NULL OR kind_value NOT IN('provider','secret_failure') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='connector attempt kind rejected';END IF;
 forward_value:=zasp_connector_maintenance.require_forward(q,envelope_value,CASE WHEN kind_value='provider' THEN 'before_provider' ELSE 'before_secret_failure' END,pin,version_value);
 r:=zasp_connector_maintenance.reserved(q,pin,version_value);
 IF r.state IS DISTINCT FROM 'reserved' OR r.attempt>=100 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector attempt already begun';END IF;
 SELECT key_version,key_material INTO STRICT captured_version,key_value FROM zasp_connector_maintenance.verifiers WHERE principal_name=session_user AND purpose='connector-captured';
 UPDATE public.zasp_connector_effects SET attempt=attempt+1,updated_at=transaction_timestamp() WHERE(organization_id,workspace_id,environment_id,id,lease_owner,lease_token)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id,r.lease_owner,r.lease_token) AND attempt=r.attempt AND status='unknown' AND lease_expires_at>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector attempt lease lost';END IF;
 body_value:=json_build_object('purpose','connector-captured','key_version',captured_version,'reference',q,'attempt',r.attempt+1,'kind',kind_value,'forward_digest',encode(public.digest(convert_to(envelope_value::text,'UTF8'),'sha256'),'hex'),'lease_expires_at',r.expires_at,'session_user',session_user);
 receipt_value:=jsonb_build_object('body',encode(convert_to(body_value::text,'UTF8'),'base64'),'version',captured_version,'mac',encode(public.hmac(convert_to('zasp-connector-captured-v1','UTF8')||decode('00','hex')||convert_to(body_value::text,'UTF8'),key_value,'sha256'),'hex'));
 UPDATE zasp_connector_maintenance.reservations SET state='attempted',attempt=attempt+1,captured_receipt=receipt_value WHERE(organization_id,workspace_id,environment_id,effect_id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
 UPDATE zasp_connector_maintenance.tasks SET state='active' WHERE(organization_id,workspace_id,environment_id,effect_id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id) AND state='paused_denied';
 RETURN jsonb_build_object('created',true,'attempt',r.attempt+1,'captured_proof',receipt_value);
END $begin$;
CREATE FUNCTION zasp_connector_maintenance.captured(q jsonb,envelope_value json,pin text,version_value text) RETURNS zasp_connector_maintenance.reservations LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $captured$
DECLARE r zasp_connector_maintenance.reservations;body_bytes bytea;body_value jsonb;key_value bytea;BEGIN
 r:=zasp_connector_maintenance.reserved(q,pin,version_value);
 IF r.state IS DISTINCT FROM 'attempted' OR r.captured_receipt IS DISTINCT FROM envelope_value::jsonb
 OR zasp_sa_multistep_prior.closed(envelope_value::jsonb,ARRAY['body','version','mac']) IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector captured receipt rejected';END IF;
 SELECT key_material INTO STRICT key_value FROM zasp_connector_maintenance.verifiers WHERE(key_version,principal_name,purpose)=(envelope_value->>'version',session_user,'connector-captured') FOR SHARE;
 body_bytes:=decode(envelope_value->>'body','base64');body_value:=convert_from(body_bytes,'UTF8')::jsonb;
 IF encode(public.hmac(convert_to('zasp-connector-captured-v1','UTF8')||decode('00','hex')||body_bytes,key_value,'sha256'),'hex') IS DISTINCT FROM envelope_value->>'mac'
 OR body_value->>'purpose' IS DISTINCT FROM 'connector-captured' OR body_value->>'session_user' IS DISTINCT FROM session_user
 OR body_value->'reference' IS DISTINCT FROM q OR(body_value->>'attempt')::integer IS DISTINCT FROM r.attempt OR(body_value->>'lease_expires_at')::timestamptz IS DISTINCT FROM r.expires_at
 OR r.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector captured receipt rejected';END IF;
 RETURN r;
END $captured$;
CREATE FUNCTION zasp_connector_maintenance.validate_captured(q jsonb,envelope_value json,pin text,version_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $validate$
BEGIN
 PERFORM zasp_connector_maintenance.captured(q,envelope_value,pin,version_value);
 IF convert_from(decode(envelope_value->>'body','base64'),'UTF8')::jsonb->>'kind' IS DISTINCT FROM 'provider' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector compensation purpose rejected';END IF;
 RETURN jsonb_build_object('valid',true);
END $validate$;
CREATE FUNCTION zasp_connector_maintenance.settle(q jsonb,envelope_value json,transition_value text,pin text,version_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $settle$
DECLARE r zasp_connector_maintenance.reservations;ref jsonb;payload jsonb;result_value jsonb;n public.zasp_connector_effects;BEGIN
 IF zasp_sa_multistep_prior.closed(q,ARRAY['reference','payload']) IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='connector settlement shape rejected';END IF;
 ref:=q->'reference';payload:=q->'payload';r:=zasp_connector_maintenance.captured(ref,envelope_value,pin,version_value);
 SELECT * INTO STRICT n FROM public.zasp_connector_effects WHERE(organization_id,workspace_id,environment_id,id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
 IF transition_value NOT IN('fail','quarantine') AND convert_from(decode(envelope_value->>'body','base64'),'UTF8')::jsonb->>'kind' IS DISTINCT FROM 'provider' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector settlement attempt rejected';END IF;
 -- Captured settlement is exact attempted-lease compensation. It deliberately
 -- does not repeat forward FGA authorization or authorize another provider call.
 IF transition_value IS NULL OR jsonb_typeof(payload) IS DISTINCT FROM 'object'
 OR transition_value IN('complete_cleanup','complete_pkce_cleanup','complete_revocation') AND payload IS DISTINCT FROM '{}'::jsonb
 OR transition_value IN('fail','quarantine') AND zasp_sa_multistep_prior.closed(payload,ARRAY['reason']) IS NOT TRUE
 OR transition_value='complete_oauth' AND zasp_sa_multistep_prior.closed(payload,ARRAY['attempt_id','effect_id','connection_id','connection_reference','provider_subject','credential_id','credential_class','metadata','completion_digest']) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='connector settlement payload rejected';END IF;
 CASE transition_value
 WHEN 'complete_oauth' THEN
  IF n.operation IS DISTINCT FROM 'authorize' OR payload->>'effect_id' IS DISTINCT FROM r.effect_id OR payload->>'attempt_id' IS DISTINCT FROM n.oauth_attempt_id THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector completion source rejected';END IF;
  result_value:=public.zasp_connector_complete_reconciliation(r.organization_id,r.workspace_id,r.environment_id,n.oauth_attempt_id,r.effect_id,r.lease_owner,r.lease_token,payload->>'connection_id',payload->>'connection_reference',payload->>'provider_subject',payload->>'credential_id',payload->>'credential_class',payload->'metadata',decode(payload->>'completion_digest','hex'));
  UPDATE zasp_connector_maintenance.reservations SET context_digest=(SELECT zasp_connector_maintenance.effect_context(effect) FROM public.zasp_connector_effects effect WHERE(effect.organization_id,effect.workspace_id,effect.environment_id,effect.id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id)) WHERE(organization_id,workspace_id,environment_id,effect_id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
  UPDATE zasp_connector_maintenance.tasks SET authorized_reference=(SELECT connection_reference FROM public.zasp_connector_effects WHERE(organization_id,workspace_id,environment_id,id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id)) WHERE(organization_id,workspace_id,environment_id,effect_id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
 WHEN 'complete_cleanup' THEN result_value:=public.zasp_connector_complete_cleanup(r.organization_id,r.workspace_id,r.environment_id,r.effect_id,r.lease_owner,r.lease_token);
 WHEN 'complete_pkce_cleanup' THEN
  IF n.operation IS DISTINCT FROM 'pkce_cleanup' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector cleanup purpose rejected';END IF;
  result_value:=public.zasp_connector_complete_pkce_cleanup(r.organization_id,r.workspace_id,r.environment_id,r.effect_id,r.lease_owner,r.lease_token);
 WHEN 'quarantine' THEN result_value:=public.zasp_connector_quarantine_reconciliation(r.organization_id,r.workspace_id,r.environment_id,r.effect_id,r.lease_owner,r.lease_token,payload->>'reason');
 WHEN 'fail' THEN result_value:=public.zasp_connector_fail_reconciliation(r.organization_id,r.workspace_id,r.environment_id,r.effect_id,r.lease_owner,r.lease_token,payload->>'reason');
 WHEN 'complete_revocation' THEN
  IF n.operation IS DISTINCT FROM 'revoke' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector revocation purpose rejected';END IF;
  result_value:=public.zasp_connector_complete_revocation(r.organization_id,r.workspace_id,r.environment_id,r.effect_id,r.lease_owner,r.lease_token);
 ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='connector settlement operation rejected';
 END CASE;
 IF r.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector settlement expired';END IF;
 IF transition_value<>'complete_oauth' THEN
  UPDATE zasp_connector_maintenance.reservations SET state='settled' WHERE(organization_id,workspace_id,environment_id,effect_id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
  UPDATE zasp_connector_maintenance.tasks SET state='settled' WHERE(organization_id,workspace_id,environment_id,effect_id)=(r.organization_id,r.workspace_id,r.environment_id,r.effect_id);
  PERFORM zasp_authorization79.touch(r.organization_id);
 END IF;
 RETURN result_value;
END $settle$;
CREATE FUNCTION zasp_connector_maintenance.workflow(q jsonb,envelope_value json,pin text,version_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $workflow$
DECLARE result_value jsonb;BEGIN
 PERFORM zasp_connector_maintenance.require_forward(q,envelope_value,'before_metadata',pin,version_value);
 SELECT jsonb_build_object('body',body,'version',version,'secret_generation',secret_generation) INTO STRICT result_value FROM public.zasp_workflow_records WHERE(organization_id,workspace_id,environment_id,kind,id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','integration',q->>'integration_id') AND deleted_at IS NULL;
 RETURN result_value;
END $workflow$;
CREATE FUNCTION zasp_connector_maintenance.register_principal(login_value name,forward_version text,captured_version text,forward_key bytea,captured_key bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $register$
BEGIN
 IF public.zasp_discovery_principal_ready('zasp_discovery_authority') IS NOT TRUE
 OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=login_value AND authority_role='zasp_outbox_worker')
 OR NOT EXISTS(SELECT 1 FROM pg_roles p WHERE p.rolname=login_value AND p.rolcanlogin AND NOT(p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls OR p.rolinherit)
 AND pg_has_role(p.oid,'zasp_outbox_worker'::regrole,'MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=p.oid AND(m.roleid<>'zasp_outbox_worker'::regrole OR m.admin_option)))
 OR forward_key IS NULL OR captured_key IS NULL OR octet_length(forward_key)<>32 OR octet_length(captured_key)<>32
 OR forward_key=captured_key OR forward_version IS DISTINCT FROM encode(public.digest(forward_key,'sha256'),'hex') OR captured_version IS DISTINCT FROM encode(public.digest(captured_key,'sha256'),'hex')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector principal registration rejected';END IF;
 INSERT INTO zasp_connector_maintenance.principals VALUES(login_value,'-- connector maintenance checksum',forward_version) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.principals WHERE(principal_name,source_checksum,key_version)=(login_value,'-- connector maintenance checksum',forward_version)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector principal registration conflict';END IF;
 INSERT INTO zasp_connector_maintenance.verifiers VALUES(forward_version,forward_key,'connector-forward',login_value),(captured_version,captured_key,'connector-captured',login_value) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.verifiers WHERE(key_version,key_material,purpose,principal_name)=(forward_version,forward_key,'connector-forward',login_value))
 OR NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.verifiers WHERE(key_version,key_material,purpose,principal_name)=(captured_version,captured_key,'connector-captured',login_value))
 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='connector verifier registration conflict';END IF;
END $register$;
-- Original authorize-preparation failures only make their own captured PKCE
-- cleanup available; they never borrow callback or background service authority.
CREATE FUNCTION zasp_connector_maintenance.handoff_pkce(envelope text,o text,w text,e text,effect_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $handoff_pkce$
DECLARE p jsonb;t zasp_connector_maintenance.tasks;n public.zasp_connector_effects;result_value jsonb;BEGIN
 IF envelope IS NULL OR public.zasp_discovery_principal_ready('zasp_discovery_api') IS NOT TRUE OR zasp_connector_maintenance.catalog_ready('-- connector maintenance checksum') IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector preparation cleanup rejected';END IF;
 PERFORM zasp_authorization80.fence(envelope);p:=zasp_authorization80.context();
 SELECT x.* INTO t FROM zasp_connector_maintenance.tasks x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(o,w,e,effect_value) FOR UPDATE;
 IF NOT FOUND OR t.operation<>'pkce_cleanup' OR(p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'operation_id',p->>'permission') IS DISTINCT FROM(o,w,e,t.grantor_id,'authorizeIntegration','manage_workflows')
 OR p#>>'{path_parameters,id}' IS DISTINCT FROM t.integration_id OR zasp_authorization80.allowed(o,w,e,'integration',t.integration_id) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector preparation cleanup purpose rejected';END IF;
 SELECT x.* INTO STRICT n FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,effect_value) FOR UPDATE;
 IF zasp_connector_maintenance.effect_matches(n,t) IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector preparation cleanup intent rejected';END IF;
 result_value:=public.zasp_connector_activate_pkce_cleanup(o,w,e,effect_value);
 PERFORM zasp_connector_maintenance.promote_enqueued(o,w,e,ARRAY[effect_value]);
 RETURN result_value;
END $handoff_pkce$;
-- Private callback reservations carry only the authenticated callback's own
-- attempt. They are not task/service grants and never authorize a new send.
CREATE TABLE zasp_connector_maintenance.callbacks(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 attempt_id text NOT NULL,integration_id text NOT NULL,principal_id text NOT NULL,
 authorize_effect_id text NOT NULL,cleanup_effect_id text NOT NULL,
 session_user_name name NOT NULL,credential_digest bytea NOT NULL CHECK(octet_length(credential_digest)=32),
 token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
 source_proof_digest bytea NOT NULL CHECK(octet_length(source_proof_digest)=32),
 expires_at timestamptz NOT NULL,
 phase text NOT NULL CHECK(phase IN('consumed','secret','secret_settled','provider','completed','cleanup','settled','rejected')),
 authorize_context bytea NOT NULL CHECK(octet_length(authorize_context)=32),
 cleanup_context bytea NOT NULL CHECK(octet_length(cleanup_context)=32),
 PRIMARY KEY(organization_id,workspace_id,environment_id,attempt_id));
CREATE FUNCTION zasp_connector_maintenance.consume_callback(envelope text,o text,w text,e text,state_value bytea,principal_value text,session_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $consume_callback$
DECLARE p jsonb;result_value jsonb;attempt public.zasp_connector_oauth_attempts;authorize public.zasp_connector_effects;cleanup public.zasp_connector_effects;token_value bytea;expiry_value timestamptz;
BEGIN
 IF envelope IS NULL OR state_value IS NULL OR octet_length(state_value)<>32 OR session_value IS NULL OR octet_length(session_value)<>32
 OR zasp_connector_maintenance.catalog_ready('-- connector maintenance checksum') IS NOT TRUE
 OR NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration WHERE singleton AND active)
 OR public.zasp_discovery_principal_ready('zasp_discovery_api') IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback capture rejected';END IF;
 PERFORM zasp_authorization80.fence(envelope);p:=zasp_authorization80.context();
 IF(p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'operation_id',p->>'permission') IS DISTINCT FROM(o,w,e,principal_value,'completeIntegrationOAuthCallback','manage_workflows')
 OR (p->>'credential_kind')::integer IS DISTINCT FROM 1 OR decode(p->>'credential_digest','hex') IS DISTINCT FROM session_value
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback purpose rejected';END IF;
 -- Original native79 fence holds the org row before all effect/attempt locks.
 SELECT a.* INTO attempt FROM public.zasp_connector_oauth_attempts a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.state_hash,a.principal_id,a.session_digest)=(o,w,e,state_value,principal_value,session_value) AND a.status='pending' AND a.expires_at>clock_timestamp();
 IF NOT FOUND OR zasp_authorization80.allowed(o,w,e,'integration',attempt.integration_id) IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback attempt rejected';END IF;
 -- Deterministic locking precedes the unchanged original consume function.
 PERFORM 1 FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.oauth_attempt_id)=(o,w,e,attempt.id) AND x.operation IN('authorize','pkce_cleanup') ORDER BY x.id FOR UPDATE;
 SELECT x.* INTO STRICT authorize FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.oauth_attempt_id,x.operation)=(o,w,e,attempt.id,'authorize');
 SELECT x.* INTO STRICT cleanup FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.oauth_attempt_id,x.operation)=(o,w,e,attempt.id,'pkce_cleanup');
 IF EXISTS(SELECT 1 FROM zasp_connector_maintenance.callbacks c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.attempt_id)=(o,w,e,attempt.id))
 OR NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.tasks t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.effect_id,t.grantor_id)=(o,w,e,authorize.id,principal_value) AND zasp_connector_maintenance.effect_matches(authorize,t))
 OR NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.tasks t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.effect_id,t.grantor_id)=(o,w,e,cleanup.id,principal_value) AND zasp_connector_maintenance.effect_matches(cleanup,t))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback origin rejected';END IF;
 result_value:=public.zasp_connector_consume_oauth(o,w,e,state_value,principal_value,session_value);
 SELECT x.* INTO STRICT authorize FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,authorize.id);
 SELECT x.* INTO STRICT cleanup FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,cleanup.id);
 token_value:=public.gen_random_bytes(32);
 expiry_value:=LEAST(attempt.expires_at,to_timestamp((p->>'expires_at')::double precision/1000),clock_timestamp()+interval '60 seconds');
 IF expiry_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback deadline rejected';END IF;
 -- Lease the two authentic effects only after unchanged consume succeeds.
 -- No background worker can claim while this captured callback is live.
 UPDATE public.zasp_connector_effects x SET lease_owner='connector-callback:'||attempt.id,lease_token=encode(token_value,'hex'),lease_expires_at=expiry_value
 WHERE(x.organization_id,x.workspace_id,x.environment_id)=(o,w,e) AND x.id IN(authorize.id,cleanup.id);
 INSERT INTO zasp_connector_maintenance.callbacks VALUES(o,w,e,attempt.id,attempt.integration_id,principal_value,authorize.id,cleanup.id,session_user,session_value,public.digest(token_value,'sha256'),public.digest(convert_to(envelope,'UTF8'),'sha256'),expiry_value,'consumed',zasp_connector_maintenance.effect_context(authorize),zasp_connector_maintenance.effect_context(cleanup));
 RETURN jsonb_build_object('consumption',result_value,'permit',encode(token_value,'hex'),'expires_at',expiry_value);
END $consume_callback$;
-- Closed callback phase/settlement dispatcher. Captured authority can only
-- finish this already-consumed attempt; it cannot refresh a forward decision.
CREATE FUNCTION zasp_connector_maintenance.callback_step(envelope text,o text,w text,e text,attempt_value text,token_value text,operation_value text,args_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $callback_step$
DECLARE c zasp_connector_maintenance.callbacks;authorize public.zasp_connector_effects;cleanup public.zasp_connector_effects;p jsonb;result_value jsonb;expected_count integer;next_phase text;remaining boolean:=true;
BEGIN
 IF token_value IS NULL OR token_value!~'^[a-f0-9]{64}$' OR operation_value IS NULL OR jsonb_typeof(args_value) IS DISTINCT FROM 'array'
 OR zasp_connector_maintenance.catalog_ready('-- connector maintenance checksum') IS NOT TRUE OR public.zasp_discovery_principal_ready('zasp_discovery_api') IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback operation rejected';END IF;
 expected_count:=CASE operation_value WHEN 'secret' THEN 0 WHEN 'provider' THEN 0 WHEN 'cleanup' THEN 0 WHEN 'activate_pkce' THEN 4 WHEN 'complete_pkce' THEN 6 WHEN 'resolve' THEN 8 WHEN 'complete_oauth' THEN 12 WHEN 'complete_cleanup' THEN 4 ELSE -1 END;
 IF expected_count<0 OR jsonb_array_length(args_value) IS DISTINCT FROM expected_count
 OR(expected_count>0 AND(args_value->>0,args_value->>1,args_value->>2) IS DISTINCT FROM(o,w,e))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback shape rejected';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback organization rejected';END IF;
 -- Read immutable IDs first, then retain the shared org/effect/receipt order.
 SELECT x.* INTO c FROM zasp_connector_maintenance.callbacks x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.attempt_id)=(o,w,e,attempt_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback receipt rejected';END IF;
 PERFORM 1 FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id)=(o,w,e) AND x.id IN(c.authorize_effect_id,c.cleanup_effect_id) ORDER BY x.id FOR UPDATE;
 SELECT x.* INTO STRICT c FROM zasp_connector_maintenance.callbacks x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.attempt_id)=(o,w,e,attempt_value) FOR UPDATE;
 SELECT x.* INTO STRICT authorize FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,c.authorize_effect_id);
 SELECT x.* INTO STRICT cleanup FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,c.cleanup_effect_id);
 IF c.session_user_name IS DISTINCT FROM session_user OR c.token_digest IS DISTINCT FROM public.digest(decode(token_value,'hex'),'sha256') OR c.expires_at<=clock_timestamp()
 OR c.phase IN('settled','rejected') OR c.authorize_context IS DISTINCT FROM zasp_connector_maintenance.effect_context(authorize) OR c.cleanup_context IS DISTINCT FROM zasp_connector_maintenance.effect_context(cleanup)
 OR(authorize.lease_owner,authorize.lease_token,authorize.lease_expires_at) IS DISTINCT FROM('connector-callback:'||attempt_value,token_value,c.expires_at)
 OR(cleanup.status<>'reconciled' AND(cleanup.lease_owner,cleanup.lease_token,cleanup.lease_expires_at) IS DISTINCT FROM('connector-callback:'||attempt_value,token_value,c.expires_at))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback captured lease rejected';END IF;
 IF operation_value IN('activate_pkce','secret','provider') THEN
  IF envelope IS NULL OR public.digest(convert_to(envelope,'UTF8'),'sha256') IS DISTINCT FROM c.source_proof_digest THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback forward proof rejected';END IF;
  PERFORM zasp_authorization80.fence(envelope);p:=zasp_authorization80.context();
  IF(p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'operation_id',p->>'permission') IS DISTINCT FROM(o,w,e,c.principal_id,'completeIntegrationOAuthCallback','manage_workflows')
  OR(p->>'credential_kind')::integer IS DISTINCT FROM 1 OR decode(p->>'credential_digest','hex') IS DISTINCT FROM c.credential_digest
  OR zasp_authorization80.allowed(o,w,e,'integration',c.integration_id) IS NOT TRUE
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback live permission rejected';END IF;
 END IF;
 next_phase:=c.phase;
 IF operation_value='secret' THEN
  IF c.phase<>'consumed' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback secret phase rejected';END IF;
  next_phase:='secret';result_value:=jsonb_build_object('ready',true);
 ELSIF operation_value='provider' THEN
  IF c.phase<>'secret_settled' OR cleanup.status<>'reconciled' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback provider phase rejected';END IF;
  next_phase:='provider';result_value:=jsonb_build_object('ready',true);
 ELSIF operation_value='cleanup' THEN
  IF c.phase<>'completed' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback cleanup phase rejected';END IF;
  next_phase:='cleanup';result_value:=jsonb_build_object('ready',true);
 ELSE
  -- Only the receipt's exact effects may use original callback operations.
  IF(operation_value IN('activate_pkce','complete_pkce') AND args_value->>3 IS DISTINCT FROM c.cleanup_effect_id)
  OR(operation_value IN('resolve','complete_cleanup') AND args_value->>3 IS DISTINCT FROM c.authorize_effect_id)
  OR(operation_value='complete_oauth' AND(args_value->>3,args_value->>4) IS DISTINCT FROM(attempt_value,c.authorize_effect_id))
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback settlement target rejected';END IF;
  -- Original unleased callback functions retain their original lease checks.
  -- Clear only OUR validated lease while both effect locks remain held.
  UPDATE public.zasp_connector_effects x SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE(x.organization_id,x.workspace_id,x.environment_id)=(o,w,e) AND x.id IN(c.authorize_effect_id,c.cleanup_effect_id);
  CASE operation_value
  WHEN 'activate_pkce' THEN
   IF c.phase<>'consumed' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback activation phase rejected';END IF;
   result_value:=public.zasp_connector_activate_pkce_cleanup(o,w,e,c.cleanup_effect_id);
  WHEN 'complete_pkce' THEN
   IF c.phase<>'secret' OR(args_value->>4,args_value->>5) IS DISTINCT FROM('','') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback secret settlement rejected';END IF;
   result_value:=public.zasp_connector_complete_pkce_cleanup(o,w,e,c.cleanup_effect_id,'','');next_phase:='secret_settled';
  WHEN 'resolve' THEN
   IF c.phase NOT IN('secret','secret_settled') OR args_value->>4 IS DISTINCT FROM 'failed' OR args_value->>5 IS DISTINCT FROM '' OR args_value->6 IS DISTINCT FROM '{}'::jsonb
   OR args_value->>7 IS NULL OR args_value->>7 NOT IN('authorization_intent_changed','verifier_unavailable','provider_invalid_request','provider_unauthorized_client','provider_access_denied','provider_unsupported_response_type','provider_invalid_scope','provider_server_error','provider_temporarily_unavailable')
   THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback rejection settlement refused';END IF;
   result_value:=public.zasp_connector_resolve_effect(o,w,e,c.authorize_effect_id,'failed','','{}'::jsonb,args_value->>7);next_phase:='rejected';remaining:=false;
  WHEN 'complete_oauth' THEN
   IF c.phase<>'provider' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback provider settlement refused';END IF;
   result_value:=public.zasp_connector_complete_oauth(o,w,e,attempt_value,c.authorize_effect_id,args_value->>5,args_value->>6,args_value->>7,args_value->>8,args_value->>9,args_value->10,decode(args_value->>11,'base64'));next_phase:='completed';
   UPDATE zasp_connector_maintenance.tasks SET authorized_reference=args_value->>6 WHERE(organization_id,workspace_id,environment_id,effect_id)=(o,w,e,c.authorize_effect_id);
  WHEN 'complete_cleanup' THEN
   IF c.phase<>'cleanup' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback final settlement refused';END IF;
   result_value:=public.zasp_connector_complete_cleanup(o,w,e,c.authorize_effect_id);next_phase:='settled';remaining:=false;
  END CASE;
  IF remaining THEN
   UPDATE public.zasp_connector_effects x SET lease_owner='connector-callback:'||attempt_value,lease_token=token_value,lease_expires_at=c.expires_at WHERE(x.organization_id,x.workspace_id,x.environment_id)=(o,w,e) AND x.id IN(c.authorize_effect_id,c.cleanup_effect_id) AND x.status<>'reconciled';
  ELSE
   UPDATE zasp_connector_maintenance.tasks SET state='settled' WHERE(organization_id,workspace_id,environment_id,effect_id)=(o,w,e,c.authorize_effect_id);
  END IF;
  IF next_phase IN('completed','settled','rejected') THEN
   UPDATE zasp_connector_maintenance.tasks SET state='settled' WHERE(organization_id,workspace_id,environment_id,effect_id)=(o,w,e,c.cleanup_effect_id) AND cleanup.status='reconciled';
   PERFORM zasp_authorization79.touch(o);
  END IF;
 END IF;
 IF c.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback lease expired';END IF;
 SELECT x.* INTO STRICT authorize FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,c.authorize_effect_id);
 SELECT x.* INTO STRICT cleanup FROM public.zasp_connector_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.id)=(o,w,e,c.cleanup_effect_id);
 UPDATE zasp_connector_maintenance.callbacks SET phase=next_phase,authorize_context=zasp_connector_maintenance.effect_context(authorize),cleanup_context=zasp_connector_maintenance.effect_context(cleanup) WHERE(organization_id,workspace_id,environment_id,attempt_id)=(o,w,e,attempt_value);
 RETURN result_value;
END $callback_step$;
-- A fixed metadata-only resolver precedes the original FGA Check. It binds
-- the original OAuth state/session/principal and an authentic enqueue receipt;
-- it neither consumes the attempt nor returns secrets/provider payloads.
CREATE FUNCTION zasp_connector_maintenance.callback_target(o text,w text,e text,principal_value text,session_id_value text,session_value bytea,state_value bytea,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $callback_target$
DECLARE attempt public.zasp_connector_oauth_attempts;task zasp_connector_maintenance.tasks;
BEGIN
 IF o IS NULL OR w IS NULL OR e IS NULL OR principal_value IS NULL OR session_id_value IS NULL
 OR session_value IS NULL OR octet_length(session_value)<>32 OR state_value IS NULL OR octet_length(state_value)<>32
 OR zasp_connector_maintenance.catalog_ready(pin) IS NOT TRUE
 OR NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration WHERE singleton AND active)
 OR public.zasp_discovery_principal_ready('zasp_discovery_api') IS NOT TRUE
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback resolution rejected';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_product_sessions s JOIN public.zasp_identity_memberships m ON(m.principal_id,m.organization_id)=(s.principal_id,s.organization_id)
 WHERE(s.organization_id,s.workspace_id,s.environment_id,s.principal_id,s.session_id,s.token_digest)=(o,w,e,principal_value,session_id_value,session_value)
 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.active
 AND EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(principal_value,o) scopes WHERE(scopes.workspace_id,scopes.environment_id)=(w,e)))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback session rejected';END IF;
 SELECT a.* INTO attempt FROM public.zasp_connector_oauth_attempts a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.state_hash,a.principal_id,a.session_digest)=(o,w,e,state_value,principal_value,session_value)
 AND a.status='pending' AND a.expires_at>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='connector callback unavailable';END IF;
 SELECT t.* INTO task FROM zasp_connector_maintenance.tasks t JOIN public.zasp_connector_effects x ON(x.organization_id,x.workspace_id,x.environment_id,x.id)=(t.organization_id,t.workspace_id,t.environment_id,t.effect_id)
 WHERE(t.organization_id,t.workspace_id,t.environment_id,t.integration_id,t.grantor_id,t.operation,x.oauth_attempt_id)=(o,w,e,attempt.integration_id,principal_value,'authorize',attempt.id)
 AND x.status='pending' AND zasp_connector_maintenance.effect_matches(x,t);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector callback provenance rejected';END IF;
 RETURN jsonb_build_object('integration_id',attempt.integration_id);
END $callback_target$;
-- A complete supplementary snapshot retains approval delivery tuples as well
-- as canonical79. It never publishes a second inventory/projection epoch.
-- PRIVATE additive definition, not an executable activation migration.
-- Insert before connector_grants in a new complete registered module source.
-- No public/runtime write or activation function is exposed by this fragment.
CREATE TABLE zasp_connector_maintenance.projection_activations(
 organization_id text PRIMARY KEY REFERENCES public.zasp_organizations(id),
 source_checksum text NOT NULL CHECK(source_checksum='-- connector maintenance checksum'),
 approval_checksum text NOT NULL CHECK(approval_checksum~'^[a-f0-9]{64}$'),
 store_id text NOT NULL CHECK(store_id~'^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
 model_id text NOT NULL CHECK(model_id~'^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
 baseline_desired bigint NOT NULL CHECK(baseline_desired>0),
 baseline_applied bigint NOT NULL CHECK(baseline_applied=baseline_desired),
 baseline_generation bigint NOT NULL CHECK(baseline_generation>0),
 withdrawal_reference text NOT NULL CHECK(withdrawal_reference~'^[a-f0-9]{64}$'));
REVOKE ALL ON zasp_connector_maintenance.projection_activations FROM PUBLIC;
-- Private future-enqueue promotion uses only a genuinely measured per-org
-- cutover record. It never fabricates that record or activates originless work.
CREATE FUNCTION zasp_connector_maintenance.promote_enqueued(o text,w text,e text,effects_value text[]) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $promote_enqueued$
DECLARE changed integer;BEGIN
 IF effects_value IS NULL OR cardinality(effects_value) NOT BETWEEN 1 AND 2 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector enqueue promotion rejected';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector enqueue organization rejected';END IF;
 IF EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration WHERE singleton AND active)
 AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.projection_activations a JOIN zasp_authorization79.organizations v ON(v.organization_id,v.store_id,v.model_id)=(a.organization_id,a.store_id,a.model_id) JOIN zasp_approval_maintenance.registration approval ON approval.singleton AND approval.checksum=a.approval_checksum
 WHERE a.organization_id=o AND a.source_checksum='-- connector maintenance checksum' AND zasp_approval_maintenance.catalog_ready() IS TRUE) THEN
  UPDATE zasp_connector_maintenance.tasks t SET state='active' WHERE(t.organization_id,t.workspace_id,t.environment_id)=(o,w,e) AND t.effect_id=ANY(effects_value) AND t.state='captured_inactive'
  AND EXISTS(SELECT 1 FROM public.zasp_connector_effects n WHERE(n.organization_id,n.workspace_id,n.environment_id,n.id)=(t.organization_id,t.workspace_id,t.environment_id,t.effect_id) AND zasp_connector_maintenance.effect_matches(n,t));
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed>0 THEN PERFORM zasp_authorization79.touch(o);END IF;
 END IF;
END $promote_enqueued$;
-- Operator-only controlled-owned activation. SQL validates native identity,
-- source and revision state; the private Go adapter (not caller supplied JSON)
-- repeats real key/model/process observations while holding this SAME79 lock.
-- A one-local-writer observation is not production fleet/restart exclusion.
CREATE FUNCTION zasp_connector_maintenance.activate_controlled_organization(o text,pin text,approval_pin text,store_value text,model_value text,withdrawal_value text,desired_value bigint,applied_value bigint,generation_value bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $controlled_activation$
DECLARE v zasp_authorization79.organizations;prior zasp_connector_maintenance.projection_activations;eligible integer;promoted integer;BEGIN
 IF zasp_authorization79.operator() IS NOT TRUE OR pin IS DISTINCT FROM '-- connector maintenance checksum'
 OR zasp_connector_maintenance.catalog_ready(pin) IS NOT TRUE OR zasp_approval_maintenance.catalog_ready() IS NOT TRUE
 OR NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE singleton AND checksum=approval_pin)
 OR withdrawal_value IS NULL OR withdrawal_value!~'^[a-f0-9]{64}$'
 OR NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.principals p JOIN zasp_connector_maintenance.verifiers f ON(f.principal_name,f.key_version,f.purpose)=(p.principal_name,p.key_version,'connector-forward')
 JOIN zasp_connector_maintenance.verifiers c ON c.principal_name=p.principal_name AND c.purpose='connector-captured'
 JOIN public.zasp_discovery_principal_bindings b ON(b.principal_name,b.authority_role)=(p.principal_name,'zasp_outbox_worker')
 WHERE p.source_checksum=pin AND octet_length(f.key_material)=32 AND octet_length(c.key_material)=32 AND f.key_material<>c.key_material)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector controlled activation rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||o,0));
 SELECT x.* INTO v FROM zasp_authorization79.organizations x WHERE x.organization_id=o FOR UPDATE;
 IF NOT FOUND OR desired_value IS NULL OR applied_value IS NULL OR generation_value IS NULL OR desired_value<1 OR desired_value<>applied_value OR generation_value<1
 OR(v.desired,v.applied,v.generation,v.store_id,v.model_id) IS DISTINCT FROM(desired_value,applied_value,generation_value,store_value,model_value)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector controlled revision changed';END IF;
 SELECT x.* INTO prior FROM zasp_connector_maintenance.projection_activations x WHERE x.organization_id=o FOR UPDATE;
 IF FOUND AND(prior.source_checksum,prior.approval_checksum,prior.store_id,prior.model_id,prior.withdrawal_reference) IS DISTINCT FROM(pin,approval_pin,store_value,model_value,withdrawal_value)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector controlled activation already bound';END IF;
 -- Captures are attributable immutable native origin receipts, not legacy rows.
 -- Preserve declined/revoked grantor work durably; every outbound effect STILL
 -- requires current grantor plus task/service FGA decisions in the executor.
 SELECT count(*) INTO eligible FROM zasp_connector_maintenance.tasks t JOIN public.zasp_connector_effects n ON(n.organization_id,n.workspace_id,n.environment_id,n.id)=(t.organization_id,t.workspace_id,t.environment_id,t.effect_id)
 WHERE t.organization_id=o AND t.state='captured_inactive' AND n.status IN('pending','unknown') AND zasp_connector_maintenance.effect_matches(n,t);
 IF eligible>20 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='connector controlled capture bound exceeded';END IF;
 INSERT INTO zasp_connector_maintenance.projection_activations VALUES(o,pin,approval_pin,store_value,model_value,desired_value,applied_value,generation_value,withdrawal_value) ON CONFLICT DO NOTHING;
 UPDATE zasp_connector_maintenance.registration SET active=true WHERE singleton;
 UPDATE zasp_connector_maintenance.tasks t SET state='active' WHERE t.organization_id=o AND t.state='captured_inactive'
 AND EXISTS(SELECT 1 FROM public.zasp_connector_effects n WHERE(n.organization_id,n.workspace_id,n.environment_id,n.id)=(t.organization_id,t.workspace_id,t.environment_id,t.effect_id) AND n.status IN('pending','unknown') AND zasp_connector_maintenance.effect_matches(n,t));
 GET DIAGNOSTICS promoted=ROW_COUNT;
 IF promoted<>eligible THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector controlled captures changed';END IF;
 IF promoted>0 OR prior.organization_id IS NULL THEN PERFORM zasp_authorization79.touch(o);END IF;
 SELECT x.* INTO STRICT v FROM zasp_authorization79.organizations x WHERE x.organization_id=o;
 IF(v.applied,v.generation,v.store_id,v.model_id) IS DISTINCT FROM(applied_value,generation_value,store_value,model_value) OR v.desired NOT IN(desired_value,desired_value+1)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='connector controlled publication changed';END IF;
 RETURN jsonb_build_object('organization_id',o,'activated',true,'origins',promoted,'desired',v.desired,'applied',v.applied,'generation',v.generation,'store_id',v.store_id,'model_id',v.model_id);
END $controlled_activation$;
-- Do not add grants for application/worker/outbox principals.
-- Existing module fingerprint includes all table definitions, ownership and ACL.
CREATE VIEW zasp_connector_maintenance.connector_grants AS
 SELECT t.organization_id,t.workspace_id,t.environment_id,'integration'::text kind,t.integration_id id,
 'service'::text principal_kind,t.principal_id,'manage_workflows'::text permission,t.task_id
 FROM zasp_connector_maintenance.tasks t
 JOIN zasp_connector_maintenance.projection_activations a ON a.organization_id=t.organization_id
 JOIN zasp_authorization79.organizations configured ON
  (configured.organization_id,configured.store_id,configured.model_id)=(a.organization_id,a.store_id,a.model_id)
 JOIN zasp_approval_maintenance.registration approval ON approval.singleton AND approval.checksum=a.approval_checksum
 JOIN public.zasp_connector_effects n ON(n.organization_id,n.workspace_id,n.environment_id,n.id)=(t.organization_id,t.workspace_id,t.environment_id,t.effect_id)
 JOIN public.zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(t.organization_id,t.grantor_id) AND m.active
 JOIN zasp_authorization79.resources r ON(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(t.organization_id,t.workspace_id,t.environment_id,'integration',t.integration_id)
 WHERE a.source_checksum='-- connector maintenance checksum' AND zasp_approval_maintenance.catalog_ready() IS TRUE AND t.state IN('active','paused_denied') AND n.status IN('pending','unknown') AND n.attempt<=100
 AND zasp_connector_maintenance.effect_matches(n,t)
 AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration WHERE singleton AND active);
CREATE VIEW zasp_connector_maintenance.projection_members AS
 SELECT * FROM zasp_approval_maintenance.projection_members
 UNION SELECT organization_id,'service'::text,principal_id,''::text FROM zasp_connector_maintenance.connector_grants;
CREATE VIEW zasp_connector_maintenance.projection_grants AS
 SELECT * FROM zasp_approval_maintenance.projection_grants
 UNION SELECT * FROM zasp_connector_maintenance.connector_grants;
DO $composed_connector_snapshot$
DECLARE d text;needle text;replacement text;n integer;
BEGIN
 -- Require the genuine complete registered approval source before composing.
 IF zasp_approval_maintenance.catalog_ready() IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='connector snapshot predecessor unavailable';END IF;
 SELECT pg_get_functiondef('zasp_authorization79.snapshot(text)'::regprocedure) INTO STRICT d;
 FOR n IN 1..4 LOOP
  CASE n
   WHEN 1 THEN needle:='FUNCTION zasp_authorization79.snapshot(o text)';replacement:='FUNCTION zasp_connector_maintenance.snapshot(o text,approval_pin text,pin text)';
   WHEN 2 THEN needle:='BEGIN';replacement:='BEGIN'||E'\n'||' IF zasp_connector_maintenance.catalog_ready(pin) IS NOT TRUE OR zasp_approval_maintenance.catalog_ready() IS NOT TRUE OR NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE singleton AND checksum=approval_pin) THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''connector snapshot profile rejected'';END IF;';
   WHEN 3 THEN needle:='FROM zasp_authorization79.members x WHERE organization_id=o';replacement:='FROM zasp_connector_maintenance.projection_members x WHERE organization_id=o';
   WHEN 4 THEN needle:='FROM zasp_authorization79.current_grants x WHERE organization_id=o';replacement:='FROM zasp_connector_maintenance.projection_grants x WHERE organization_id=o';
  END CASE;
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='connector snapshot predecessor changed';END IF;
  d:=replace(d,needle,replacement);
 END LOOP;
 EXECUTE d;
END $composed_connector_snapshot$;
CREATE FUNCTION zasp_connector_maintenance.projection_profile_state() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $profile_state$
 SELECT jsonb_build_object('active',active,'checksum',checksum,'catalog_ready',zasp_connector_maintenance.catalog_ready(checksum)) FROM zasp_connector_maintenance.registration WHERE singleton
$profile_state$;

-- All module tables remain authority-only. Role72 and every original SQL
-- consumer remain unchanged. No worker function is selected without ready.
DO $security$ DECLARE object_value record;BEGIN
 FOR object_value IN SELECT tablename FROM pg_tables WHERE schemaname='zasp_connector_maintenance' LOOP
  EXECUTE format('ALTER TABLE zasp_connector_maintenance.%I ENABLE ROW LEVEL SECURITY',object_value.tablename);
  EXECUTE format('ALTER TABLE zasp_connector_maintenance.%I FORCE ROW LEVEL SECURITY',object_value.tablename);
  EXECUTE format('CREATE POLICY authority ON zasp_connector_maintenance.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',object_value.tablename);
 END LOOP;
END $security$;
REVOKE ALL ON SCHEMA zasp_connector_maintenance FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA zasp_connector_maintenance FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zasp_connector_maintenance FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_connector_maintenance TO zasp_discovery_api,zasp_outbox_worker;
GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.capture_pkce_cleanup(text,text,text,text,text,text,text,text,text,bytea,timestamptz,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.caller_ready(text,text) TO zasp_outbox_worker;
GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.register_principal(name,text,text,bytea,bytea) TO zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.source(jsonb,text,text),zasp_connector_maintenance.revision(text,text,text),zasp_connector_maintenance.recover(jsonb,text,text),zasp_connector_maintenance.reserve(jsonb,text,text),zasp_connector_maintenance.release(jsonb,boolean,text,text),zasp_connector_maintenance.begin_attempt(jsonb,text,json,text,text),zasp_connector_maintenance.workflow(jsonb,json,text,text),zasp_connector_maintenance.settle(jsonb,json,text,text,text) TO zasp_outbox_worker;
GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.validate_captured(jsonb,json,text,text) TO zasp_outbox_worker;

GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.projection_profile_state(),zasp_connector_maintenance.snapshot(text,text,text) TO zasp_outbox_worker;

GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.projection_profile_state() TO zasp_discovery_api;
-- Fixed, credential-free profile metadata only. These existing runtime readers
-- receive no reserve, enqueue, signing, settlement or activation privilege.
GRANT USAGE ON SCHEMA zasp_connector_maintenance TO zasp_security_agent_api,zasp_security_agent_worker,zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.projection_profile_state() TO zasp_security_agent_api,zasp_security_agent_worker,zasp_temporal_executor;

GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.start_oauth(text,text,text,text,text,text,text,text,bytea,bytea,text,bytea,jsonb,timestamptz,bigint,jsonb,text,text) TO zasp_discovery_api;

GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.delete_integration(text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text) TO zasp_discovery_api;

GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.callback_target(text,text,text,text,text,bytea,bytea,text) TO zasp_discovery_api;

GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.consume_callback(text,text,text,text,bytea,text,bytea) TO zasp_discovery_api;

GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.callback_step(text,text,text,text,text,text,text,jsonb) TO zasp_discovery_api;

GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.handoff_pkce(text,text,text,text,text) TO zasp_discovery_api;

GRANT EXECUTE ON FUNCTION zasp_connector_maintenance.activate_controlled_organization(text,text,text,text,text,text,bigint,bigint,bigint) TO zasp_discovery_authority;
