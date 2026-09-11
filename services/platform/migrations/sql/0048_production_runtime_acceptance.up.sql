DO $guard$
BEGIN
 IF NOT COALESCE(public.zasp_production_runtime_candidate_authority_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=47),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_candidate_authority_fingerprint')),false) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime acceptance prerequisite rejected';
 END IF;
END
$guard$;

-- Recover prior acceptance only. Original token provenance and all incomplete
-- upload/finalization semantics stay unchanged. Authentication audit updates are
-- retained; no batch, artifact, job, stage or outbox data is written here.
CREATE FUNCTION public.zasp_runtime_lookup_acceptance(locator_value bytea,secret_value bytea,enrollment_value text,batch_value text,idempotency_value text,content_digest_value bytea,source_value text,media_value text,schema_value text,size_value bigint,count_value integer,job_value text,outbox_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $lookup$
DECLARE authority jsonb;batch_row zasp_runtime_batch_authorities%ROWTYPE;scope_bytes bytea;expected_payload jsonb;response jsonb;now_value timestamptz;
BEGIN
 IF NOT COALESCE(zasp_discovery_principal_ready('zasp_runtime_ingest') AND zasp_production_runtime_acceptance_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime acceptance principal rejected';END IF;
 IF NOT COALESCE(octet_length(locator_value)=16 AND octet_length(secret_value)=32 AND enrollment_value ~ '^[0-9a-f]{64}$' AND zasp_valid_product_id(batch_value) AND length(idempotency_value) BETWEEN 16 AND 128 AND octet_length(content_digest_value)=32 AND source_value IN('tetragon','otlp') AND media_value='application/json' AND schema_value='runtime-event-v1' AND size_value BETWEEN 1 AND 67108864 AND count_value BETWEEN 1 AND 1000 AND zasp_valid_product_id(job_value) AND zasp_valid_product_id(outbox_value),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime acceptance input rejected';END IF;
 authority:=zasp_runtime_authenticate_sensor(locator_value,secret_value,'event-ingest');
 scope_bytes:=convert_to('zasp.sensor-enrollment.v1','UTF8')||decode('00','hex')||convert_to(authority->>'organization_id','UTF8')||decode('00','hex')||convert_to(authority->>'workspace_id','UTF8')||decode('00','hex')||convert_to(authority->>'environment_id','UTF8')||decode('00','hex')||convert_to(authority->>'sensor_id','UTF8');
 IF encode(digest(scope_bytes,'sha256'),'hex') IS DISTINCT FROM enrollment_value OR authority->>'sensor_kind' IS DISTINCT FROM source_value THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='runtime acceptance enrollment rejected';END IF;
 -- Do not wait on a batch while holding sensor authority. A worker may need
 -- that sensor lock; contention is a retry, never a reason to invert locks.
 SELECT * INTO batch_row FROM zasp_runtime_batch_authorities b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.sensor_id,b.idempotency_key)=(authority->>'organization_id',authority->>'workspace_id',authority->>'environment_id',authority->>'sensor_id',idempotency_value) FOR SHARE NOWAIT;
 response:=jsonb_build_object('found',false);
 IF FOUND THEN
  IF (batch_row.batch_id,batch_row.content_digest,batch_row.source_kind,batch_row.payload_media_type,batch_row.payload_schema_version,batch_row.payload_size_bytes,batch_row.event_count) IS DISTINCT FROM (batch_value,content_digest_value,source_value,media_value,schema_value,size_value,count_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime acceptance conflict';END IF;
  IF batch_row.state NOT IN('uploading','unknown') THEN
   IF NOT COALESCE(batch_row.state IN('queued','processing','succeeded','failed','quarantined') AND batch_row.finalized_at IS NOT NULL AND batch_row.raw_artifact_checksum=content_digest_value AND batch_row.raw_artifact_size_bytes=size_value AND zasp_discovery_s3_object_reference(batch_row.raw_artifact_reference) AND right(batch_row.raw_artifact_reference,length(batch_row.raw_artifact_key)+1)='/'||batch_row.raw_artifact_key AND length(batch_row.raw_artifact_version_id) BETWEEN 1 AND 1024 AND batch_row.raw_artifact_version_id=btrim(batch_row.raw_artifact_version_id) AND batch_row.raw_artifact_kms_key ~ '^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]{8,128}$',false) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime acceptance artifact rejected';END IF;
   expected_payload:=jsonb_build_object('batch_id',batch_row.batch_id,'job_id',job_value,'generation',batch_row.batch_generation,'pipeline_version',15,'artifact_reference',batch_row.raw_artifact_reference,'artifact_key',batch_row.raw_artifact_key,'artifact_version_id',batch_row.raw_artifact_version_id,'artifact_checksum',encode(batch_row.raw_artifact_checksum,'hex'),'artifact_size_bytes',batch_row.raw_artifact_size_bytes,'payload_media_type',batch_row.payload_media_type,'payload_schema_version',batch_row.payload_schema_version,'event_count',batch_row.event_count,'request_digest',encode(batch_row.request_digest,'hex'));
   IF NOT EXISTS(SELECT 1 FROM zasp_runtime_batches b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.id,b.sensor_id,b.idempotency_key,b.payload_digest,b.event_count,b.payload_reference,b.payload_size_bytes,b.payload_media_type,b.payload_schema_version)=(batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,batch_value,batch_row.sensor_id,idempotency_value,content_digest_value,count_value,batch_row.raw_artifact_reference,size_value,media_value,schema_value))
   OR NOT EXISTS(SELECT 1 FROM zasp_discovery_jobs j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.id,j.kind,j.authority_id,j.idempotency_key,j.request_digest)=(batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,job_value,'runtime',batch_value,idempotency_value,batch_row.request_digest))
   OR NOT EXISTS(SELECT 1 FROM zasp_discovery_outbox o WHERE (o.organization_id,o.workspace_id,o.environment_id,o.id,o.topic,o.deterministic_key,o.payload_version,o.payload,o.payload_digest)=(batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,outbox_value,'runtime-events','runtime:'||batch_value,15,expected_payload,digest(convert_to(expected_payload::text,'UTF8'),'sha256')))
   OR (SELECT count(*) FROM zasp_runtime_stage_work s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.batch_id,s.batch_generation)=(batch_row.organization_id,batch_row.workspace_id,batch_row.environment_id,batch_value,batch_row.batch_generation) AND (s.stage,s.stage_order) IN(('archive',1),('index',2),('correlate',3),('project',4),('complete',5)))<>5
   THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime acceptance durable binding rejected';END IF;
   response:=jsonb_build_object('found',true,'batch_id',batch_row.batch_id,'generation',batch_row.batch_generation,'state',batch_row.state);
  END IF;
 END IF;
 -- Authentication locks are still held. Check wall time after the last query,
 -- not transaction start time, so lock waits cannot extend an expired token.
 IF NOT COALESCE(zasp_discovery_principal_ready('zasp_runtime_ingest') AND zasp_production_runtime_acceptance_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime acceptance principal expired';END IF;
 now_value:=clock_timestamp();
 IF NOT EXISTS(SELECT 1 FROM zasp_sensor_tokens t JOIN zasp_sensors s ON (s.organization_id,s.workspace_id,s.environment_id,s.id,s.version)=(t.organization_id,t.workspace_id,t.environment_id,t.sensor_id,t.sensor_version_at_issue) WHERE (t.organization_id,t.workspace_id,t.environment_id,t.sensor_id,t.id,t.token_generation)=(authority->>'organization_id',authority->>'workspace_id',authority->>'environment_id',authority->>'sensor_id',authority->>'token_id',(authority->>'token_generation')::bigint) AND t.revoked_at IS NULL AND t.expires_at>now_value AND s.state IN('pending','active','degraded')) THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='runtime acceptance credential expired';END IF;
 RETURN response;
END
$lookup$;
ALTER FUNCTION public.zasp_runtime_lookup_acceptance(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_lookup_acceptance(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_lookup_acceptance(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer,text,text,text,text) TO zasp_runtime_ingest;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 47','later_release."version" > 48'),'later."version">47','later."version">48'),'later."version" > 47','later."version" > 48');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime acceptance compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_runtime_acceptance_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_runtime_candidate_authority_security_ready()
 AND EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='public.zasp_runtime_lookup_acceptance(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer,text,text,text,text)'::regprocedure AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.is_grantable OR acl.grantee NOT IN(p.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_runtime_ingest'))))
 AND has_function_privilege('zasp_runtime_ingest','public.zasp_runtime_lookup_acceptance(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer,text,text,text,text)','EXECUTE')
$security$;
CREATE FUNCTION public.zasp_production_runtime_acceptance_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_candidate_authority_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_lookup_acceptance','zasp_production_runtime_acceptance_security_ready','zasp_production_runtime_acceptance_readiness','zasp_production_runtime_candidate_authority_readiness_v47')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_acceptance_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=48 AND name='production_runtime_acceptance' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>48) AND zasp_production_runtime_acceptance_security_ready() AND zasp_production_runtime_acceptance_live_fingerprint()=expected_fingerprint,false)
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_acceptance_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_acceptance_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_acceptance_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_acceptance_security_ready(),public.zasp_production_runtime_acceptance_live_fingerprint(),public.zasp_production_runtime_acceptance_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_acceptance_readiness(text,text) TO zasp_runtime_ingest,zasp_runtime_correlation_worker,zasp_discovery_worker,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;

ALTER FUNCTION public.zasp_production_runtime_candidate_authority_readiness(text,text) RENAME TO zasp_production_runtime_candidate_authority_readiness_v47;
CREATE FUNCTION public.zasp_production_runtime_candidate_authority_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=47 AND name='production_runtime_candidate_authority' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_candidate_authority_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_acceptance_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=48),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_acceptance_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_runtime_candidate_authority_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_candidate_authority_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_candidate_authority_readiness(text,text) TO zasp_runtime_correlation_worker,zasp_discovery_worker,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_acceptance_fingerprint', '6ab72c59e40e2b758acca94556ca378ecb61c52d8775bb8f35dae93c685bf819');
