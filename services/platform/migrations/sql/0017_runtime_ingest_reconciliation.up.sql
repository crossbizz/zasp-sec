DO $release_guard$ BEGIN
 IF NOT zasp_runtime_gateway_reconciliation_readiness(
  'e91bd4114f2a91c759aa5d02707b1060593f023cf02557e19888764ed60db35d',
  '625c5da616e2d069d35e80efbeaae60f5fd4132d8d1b5be73d0b33d5786f78be'
 ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime gateway reconciliation release required';END IF;
END $release_guard$;

CREATE TABLE public.zasp_runtime_ingest_reconciliation_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),used_at timestamptz
);
ALTER TABLE public.zasp_runtime_ingest_reconciliation_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_ingest_reconciliation_state FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_ingest_reconciliation_state OWNER TO zasp_discovery_authority;
CREATE POLICY zasp_runtime_ingest_reconciliation_state_authority ON public.zasp_runtime_ingest_reconciliation_state TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_runtime_ingest_reconciliation_state FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
INSERT INTO public.zasp_runtime_ingest_reconciliation_state(singleton) VALUES(true);

ALTER TABLE public.zasp_runtime_batch_authorities DROP CONSTRAINT zasp_runtime_batch_authorities_check;
ALTER TABLE public.zasp_runtime_batch_authorities ADD CONSTRAINT zasp_runtime_batch_authorities_check CHECK(
 (state IN('uploading','unknown') AND raw_artifact_reference IS NULL AND raw_artifact_version_id IS NULL AND raw_artifact_checksum IS NULL AND raw_artifact_size_bytes IS NULL AND raw_artifact_kms_key IS NULL AND finalized_at IS NULL)
 OR (state='quarantined' AND raw_artifact_reference IS NULL AND raw_artifact_version_id IS NULL AND raw_artifact_checksum IS NULL AND raw_artifact_size_bytes IS NULL AND raw_artifact_kms_key IS NULL AND finalized_at IS NULL)
 OR (state NOT IN('uploading','unknown') AND zasp_discovery_s3_object_reference(raw_artifact_reference) AND length(raw_artifact_version_id) BETWEEN 1 AND 1024 AND raw_artifact_checksum IS NOT NULL AND raw_artifact_size_bytes=payload_size_bytes AND length(raw_artifact_kms_key) BETWEEN 1 AND 512 AND finalized_at IS NOT NULL)
);

CREATE TABLE public.zasp_runtime_ingest_reconciliation_work (
 organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
 batch_id text NOT NULL CHECK(zasp_valid_product_id(batch_id)),batch_generation bigint NOT NULL CHECK(batch_generation>0),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','leased','retryable','succeeded','quarantined','exhausted')),attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 lease_owner text,lease_token text,lease_expires_at timestamptz,last_error_code text CHECK(last_error_code IS NULL OR last_error_code IN('not_found','dependency_unavailable','outcome_unknown','exhausted')),
 completion_worker text,completion_token_digest bytea CHECK(completion_token_digest IS NULL OR octet_length(completion_token_digest)=32),completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32),completion_result jsonb,completed_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,batch_id) REFERENCES public.zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id) ON DELETE CASCADE,
 CHECK((state='leased')=(lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
 CHECK((state IN('succeeded','quarantined'))=(completion_worker IS NOT NULL AND completion_token_digest IS NOT NULL AND completion_digest IS NOT NULL AND completion_result IS NOT NULL AND completed_at IS NOT NULL))
);
ALTER TABLE public.zasp_runtime_ingest_reconciliation_work ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_ingest_reconciliation_work FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_ingest_reconciliation_work OWNER TO zasp_discovery_authority;
CREATE POLICY zasp_runtime_ingest_reconciliation_work_authority ON public.zasp_runtime_ingest_reconciliation_work TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_runtime_ingest_reconciliation_work FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;

CREATE INDEX zasp_runtime_batches_sensor_rate_v17_idx ON public.zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,sensor_id,source_kind,reserved_at);
CREATE INDEX zasp_runtime_ingest_reconcile_claim_v17_idx ON public.zasp_runtime_ingest_reconciliation_work(available_at,organization_id,batch_id) WHERE state IN('pending','retryable','leased');

ALTER FUNCTION public.zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer) RENAME TO zasp_runtime_reserve_batch_v15_internal;
ALTER FUNCTION public.zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text) RENAME TO zasp_runtime_finalize_batch_v15_internal;
REVOKE ALL ON FUNCTION public.zasp_runtime_reserve_batch_v15_internal(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer),public.zasp_runtime_finalize_batch_v15_internal(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;

INSERT INTO public.zasp_runtime_ingest_reconciliation_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,available_at)
SELECT authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.batch_generation,GREATEST(authority_row.reserved_at+interval '30 seconds',transaction_timestamp())
FROM public.zasp_runtime_batch_authorities authority_row WHERE authority_row.state IN('uploading','unknown')
ON CONFLICT DO NOTHING;

CREATE FUNCTION public.zasp_runtime_reserve_batch_v17(locator_value bytea,secret_value bytea,audience_value text,batch_value text,idempotency_value text,content_digest_value bytea,source_kind_value text,media_type_value text,schema_version_value text,payload_size_value bigint,event_count_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;organization_value text;workspace_value text;environment_value text;sensor_value text;prior_value zasp_runtime_batch_authorities%ROWTYPE;recent_batches bigint;recent_events bigint;recent_bytes bigint;result_value jsonb;
BEGIN
 UPDATE zasp_runtime_ingest_reconciliation_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
 authority_value:=zasp_runtime_authenticate_sensor(locator_value,secret_value,audience_value);
 organization_value:=authority_value->>'organization_id';workspace_value:=authority_value->>'workspace_id';environment_value:=authority_value->>'environment_id';sensor_value:=authority_value->>'sensor_id';
 IF authority_value->>'sensor_kind'<>source_kind_value THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime batch rejected';END IF;
 SELECT * INTO prior_value FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.sensor_id,authority_row.idempotency_key)=(organization_value,workspace_value,environment_value,sensor_value,idempotency_value);
 IF NOT FOUND THEN
  SELECT count(*),COALESCE(sum(authority_row.event_count),0),COALESCE(sum(authority_row.payload_size_bytes),0) INTO recent_batches,recent_events,recent_bytes FROM zasp_runtime_batch_authorities authority_row
  WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.sensor_id,authority_row.source_kind)=(organization_value,workspace_value,environment_value,sensor_value,source_kind_value) AND authority_row.reserved_at>=transaction_timestamp()-interval '60 seconds';
  IF recent_batches>=600 OR recent_events+event_count_value>600000 OR recent_bytes+payload_size_value>1073741824 THEN RAISE EXCEPTION USING ERRCODE='53300',MESSAGE='runtime batch rate limited';END IF;
 END IF;
 result_value:=zasp_runtime_reserve_batch_v15_internal(locator_value,secret_value,audience_value,batch_value,idempotency_value,content_digest_value,source_kind_value,media_type_value,schema_version_value,payload_size_value,event_count_value);
 IF (result_value->>'state') IN('uploading','unknown') THEN
  INSERT INTO zasp_runtime_ingest_reconciliation_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,available_at)
  VALUES(organization_value,workspace_value,environment_value,batch_value,(result_value->>'generation')::bigint,transaction_timestamp()+interval '30 seconds') ON CONFLICT DO NOTHING;
 END IF;
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_reserve_batch(locator_value bytea,secret_value bytea,audience_value text,batch_value text,idempotency_value text,content_digest_value bytea,source_kind_value text,media_type_value text,schema_version_value text,payload_size_value bigint,event_count_value integer) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT zasp_runtime_reserve_batch_v17(locator_value,secret_value,audience_value,batch_value,idempotency_value,content_digest_value,source_kind_value,media_type_value,schema_version_value,payload_size_value,event_count_value)
$$;

CREATE FUNCTION public.zasp_runtime_finalize_batch_v17(locator_value bytea,secret_value bytea,audience_value text,batch_value text,job_value text,outbox_value text,artifact_reference_value text,artifact_key_value text,artifact_version_value text,artifact_checksum_value bytea,artifact_size_value bigint,artifact_kms_key_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE authority_value jsonb;result_value jsonb;work_value zasp_runtime_ingest_reconciliation_work%ROWTYPE;
BEGIN
 UPDATE zasp_runtime_ingest_reconciliation_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
 authority_value:=zasp_runtime_authenticate_sensor(locator_value,secret_value,audience_value);
 SELECT * INTO work_value FROM zasp_runtime_ingest_reconciliation_work work_row WHERE (work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id)=(authority_value->>'organization_id',authority_value->>'workspace_id',authority_value->>'environment_id',batch_value) FOR UPDATE;
 IF FOUND AND work_value.state='leased' AND work_value.lease_expires_at>transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime batch finalize leased';END IF;
 result_value:=zasp_runtime_finalize_batch_v15_internal(locator_value,secret_value,audience_value,batch_value,job_value,outbox_value,artifact_reference_value,artifact_key_value,artifact_version_value,artifact_checksum_value,artifact_size_value,artifact_kms_key_value);
 UPDATE zasp_runtime_ingest_reconciliation_work work_row SET state='succeeded',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,completion_worker='request',completion_token_digest=digest(convert_to('request','UTF8'),'sha256'),completion_digest=digest(convert_to(result_value::text,'UTF8'),'sha256'),completion_result=result_value,completed_at=transaction_timestamp()
 WHERE (work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id,work_row.batch_generation)=(authority_value->>'organization_id',authority_value->>'workspace_id',authority_value->>'environment_id',batch_value,(result_value->>'generation')::bigint) AND work_row.state NOT IN('succeeded','quarantined');
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_finalize_batch(locator_value bytea,secret_value bytea,audience_value text,batch_value text,job_value text,outbox_value text,artifact_reference_value text,artifact_key_value text,artifact_version_value text,artifact_checksum_value bytea,artifact_size_value bigint,artifact_kms_key_value text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT zasp_runtime_finalize_batch_v17(locator_value,secret_value,audience_value,batch_value,job_value,outbox_value,artifact_reference_value,artifact_key_value,artifact_version_value,artifact_checksum_value,artifact_size_value,artifact_kms_key_value)
$$;

CREATE FUNCTION public.zasp_runtime_claim_reconciliation(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE response jsonb;
BEGIN
 UPDATE zasp_runtime_ingest_reconciliation_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
 IF NOT zasp_discovery_principal_ready('zasp_runtime_ingest') OR length(worker_value) NOT BETWEEN 1 AND 128 OR worker_value<>btrim(worker_value) OR worker_value~'[[:cntrl:]]' OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_token_value<>btrim(lease_token_value) OR lease_token_value~'[[:cntrl:]]' OR lease_seconds NOT BETWEEN 60 AND 300 OR claim_limit NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime reconciliation claim rejected';END IF;
 UPDATE zasp_runtime_ingest_reconciliation_work work_row SET state='succeeded',completion_worker='observed',completion_token_digest=digest(convert_to('observed','UTF8'),'sha256'),completion_digest=digest(convert_to(authority_row.completion_result::text,'UTF8'),'sha256'),completion_result=COALESCE(authority_row.completion_result,jsonb_build_object('batch_id',authority_row.batch_id,'generation',authority_row.batch_generation,'state',authority_row.state,'replayed',true)),completed_at=transaction_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL
 FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id) AND work_row.state NOT IN('succeeded','quarantined') AND authority_row.state NOT IN('uploading','unknown');
 UPDATE zasp_runtime_ingest_reconciliation_work SET state=CASE WHEN attempt>=100 THEN 'exhausted' ELSE 'retryable' END,available_at=transaction_timestamp(),last_error_code=CASE WHEN attempt>=100 THEN 'exhausted' ELSE 'outcome_unknown' END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE state='leased' AND lease_expires_at<=transaction_timestamp();
 WITH candidates AS (
  SELECT work_row.ctid FROM zasp_runtime_ingest_reconciliation_work work_row JOIN zasp_runtime_batch_authorities authority_row USING(organization_id,workspace_id,environment_id,batch_id)
  WHERE work_row.state IN('pending','retryable') AND work_row.attempt<100 AND work_row.available_at<=transaction_timestamp() AND authority_row.state IN('uploading','unknown') ORDER BY work_row.available_at,work_row.organization_id,work_row.batch_id FOR UPDATE OF work_row SKIP LOCKED LIMIT claim_limit
 ),claimed AS (
  UPDATE zasp_runtime_ingest_reconciliation_work work_row SET state='leased',attempt=work_row.attempt+1,lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),last_error_code=NULL FROM candidates WHERE work_row.ctid=candidates.ctid
  RETURNING work_row.*
 ) SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',claimed.organization_id,'workspace_id',claimed.workspace_id,'environment_id',claimed.environment_id,'batch_id',claimed.batch_id,'generation',claimed.batch_generation,'attempt',claimed.attempt,'lease_expires_at',claimed.lease_expires_at,'request_digest',encode(authority_row.request_digest,'hex'),'artifact_key',authority_row.raw_artifact_key,'content_digest',encode(authority_row.content_digest,'hex'),'payload_size_bytes',authority_row.payload_size_bytes,'media_type',authority_row.payload_media_type,'schema_version',authority_row.payload_schema_version) ORDER BY claimed.organization_id,claimed.batch_id),'[]'::jsonb) INTO response FROM claimed JOIN zasp_runtime_batch_authorities authority_row USING(organization_id,workspace_id,environment_id,batch_id);
 RETURN response;
END $$;

CREATE FUNCTION public.zasp_runtime_release_reconciliation(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,lease_token_value text,delay_seconds integer,error_code_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE result_value jsonb;
BEGIN
 UPDATE zasp_runtime_ingest_reconciliation_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
 IF delay_seconds NOT BETWEEN 5 AND 300 OR error_code_value NOT IN('not_found','dependency_unavailable','outcome_unknown') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime reconciliation release rejected';END IF;
 UPDATE zasp_runtime_ingest_reconciliation_work work_row SET state=CASE WHEN work_row.attempt>=100 THEN 'exhausted' ELSE 'retryable' END,available_at=transaction_timestamp()+make_interval(secs=>delay_seconds),last_error_code=CASE WHEN work_row.attempt>=100 THEN 'exhausted' ELSE error_code_value END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL
 WHERE (work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id,work_row.batch_generation,work_row.lease_owner,work_row.lease_token)=(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,lease_token_value) AND work_row.state='leased' AND work_row.lease_expires_at>transaction_timestamp()
 RETURNING jsonb_build_object('batch_id',work_row.batch_id,'generation',work_row.batch_generation,'state',work_row.state,'attempt',work_row.attempt,'error_code',work_row.last_error_code,'replayed',false) INTO result_value;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime reconciliation release rejected';END IF;
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_finish_reconciliation(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,lease_token_value text,job_value text,outbox_value text,artifact_reference_value text,artifact_key_value text,artifact_version_value text,artifact_checksum_value bytea,artifact_size_value bigint,artifact_kms_key_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE work_value zasp_runtime_ingest_reconciliation_work%ROWTYPE;result_value jsonb;completion_digest_value bytea;
BEGIN
 UPDATE zasp_runtime_ingest_reconciliation_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
 completion_digest_value:=digest(convert_to(concat_ws(chr(31),organization_value,workspace_value,environment_value,batch_value,generation_value::text,worker_value,encode(digest(convert_to(lease_token_value,'UTF8'),'sha256'),'hex'),job_value,outbox_value,artifact_reference_value,artifact_key_value,artifact_version_value,encode(artifact_checksum_value,'hex'),artifact_size_value::text,artifact_kms_key_value),'UTF8'),'sha256');
 SELECT * INTO work_value FROM zasp_runtime_ingest_reconciliation_work work_row WHERE (work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id,work_row.batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime reconciliation finish rejected';END IF;
 IF work_value.state IN('succeeded','quarantined') THEN
  IF (work_value.completion_worker,work_value.completion_token_digest,work_value.completion_digest) IS DISTINCT FROM (worker_value,digest(convert_to(lease_token_value,'UTF8'),'sha256'),completion_digest_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime reconciliation finish conflict';END IF;
  RETURN work_value.completion_result||jsonb_build_object('replayed',true);
 END IF;
 IF (work_value.state,work_value.lease_owner,work_value.lease_token) IS DISTINCT FROM ('leased',worker_value,lease_token_value) OR work_value.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime reconciliation finish rejected';END IF;
 result_value:=zasp_runtime_reconcile_batch(organization_value,workspace_value,environment_value,batch_value,generation_value,(SELECT authority_row.request_digest FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(organization_value,workspace_value,environment_value,batch_value)),job_value,outbox_value,artifact_reference_value,artifact_key_value,artifact_version_value,artifact_checksum_value,artifact_size_value,artifact_kms_key_value);
 UPDATE zasp_runtime_ingest_reconciliation_work work_row SET state=CASE result_value->>'state' WHEN 'quarantined' THEN 'quarantined' ELSE 'succeeded' END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,completion_worker=worker_value,completion_token_digest=digest(convert_to(lease_token_value,'UTF8'),'sha256'),completion_digest=completion_digest_value,completion_result=result_value,completed_at=transaction_timestamp() WHERE (work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id)=(organization_value,workspace_value,environment_value,batch_value);
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_runtime_quarantine_reconciliation(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,lease_token_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE work_value zasp_runtime_ingest_reconciliation_work%ROWTYPE;batch_value_row zasp_runtime_batch_authorities%ROWTYPE;completion_digest_value bytea;result_value jsonb;
BEGIN
 UPDATE zasp_runtime_ingest_reconciliation_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
 completion_digest_value:=digest(convert_to(concat_ws(chr(31),organization_value,workspace_value,environment_value,batch_value,generation_value::text,worker_value,encode(digest(convert_to(lease_token_value,'UTF8'),'sha256'),'hex'),'artifact_drift'),'UTF8'),'sha256');
 SELECT * INTO work_value FROM zasp_runtime_ingest_reconciliation_work work_row WHERE (work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id,work_row.batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime reconciliation quarantine rejected';END IF;
 IF work_value.state='quarantined' THEN
  IF (work_value.completion_worker,work_value.completion_token_digest,work_value.completion_digest) IS DISTINCT FROM (worker_value,digest(convert_to(lease_token_value,'UTF8'),'sha256'),completion_digest_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime reconciliation quarantine conflict';END IF;
  RETURN work_value.completion_result||jsonb_build_object('replayed',true);
 END IF;
 IF (work_value.state,work_value.lease_owner,work_value.lease_token) IS DISTINCT FROM ('leased',worker_value,lease_token_value) OR work_value.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime reconciliation quarantine rejected';END IF;
 SELECT * INTO batch_value_row FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.batch_generation)=(organization_value,workspace_value,environment_value,batch_value,generation_value) FOR UPDATE;
 IF NOT FOUND OR batch_value_row.state NOT IN('uploading','unknown') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime reconciliation quarantine rejected';END IF;
 result_value:=jsonb_build_object('batch_id',batch_value,'generation',generation_value,'state','quarantined','error_class','artifact_drift','replayed',false);
 UPDATE zasp_runtime_batch_authorities authority_row SET state='quarantined',completed_at=transaction_timestamp(),completion_digest=completion_digest_value,completion_result=result_value WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id)=(organization_value,workspace_value,environment_value,batch_value);
 UPDATE zasp_runtime_ingest_reconciliation_work work_row SET state='quarantined',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,completion_worker=worker_value,completion_token_digest=digest(convert_to(lease_token_value,'UTF8'),'sha256'),completion_digest=completion_digest_value,completion_result=result_value,completed_at=transaction_timestamp(),last_error_code=NULL WHERE (work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id)=(organization_value,workspace_value,environment_value,batch_value);
 RETURN result_value;
END $$;

ALTER FUNCTION public.zasp_runtime_reserve_batch_v17(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_finalize_batch_v17(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_claim_reconciliation(text,text,integer,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_release_reconciliation(text,text,text,text,bigint,text,text,integer,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_finish_reconciliation(text,text,text,text,bigint,text,text,text,text,text,text,text,bytea,bigint,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_quarantine_reconciliation(text,text,text,text,bigint,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_reserve_batch_v17(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer),public.zasp_runtime_finalize_batch_v17(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text),public.zasp_runtime_claim_reconciliation(text,text,integer,integer),public.zasp_runtime_release_reconciliation(text,text,text,text,bigint,text,text,integer,text),public.zasp_runtime_finish_reconciliation(text,text,text,text,bigint,text,text,text,text,text,text,text,bytea,bigint,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
REVOKE ALL ON FUNCTION public.zasp_runtime_quarantine_reconciliation(text,text,text,text,bigint,text,text),public.zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer),public.zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_reserve_batch_v17(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer),public.zasp_runtime_finalize_batch_v17(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text),public.zasp_runtime_claim_reconciliation(text,text,integer,integer),public.zasp_runtime_release_reconciliation(text,text,text,text,bigint,text,text,integer,text),public.zasp_runtime_finish_reconciliation(text,text,text,text,bigint,text,text,text,text,text,text,text,bytea,bigint,text),public.zasp_runtime_quarantine_reconciliation(text,text,text,text,bigint,text,text),public.zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer),public.zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text) TO zasp_runtime_ingest;

CREATE FUNCTION public.zasp_runtime_ingest_reconciliation_live_fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 WITH semantic_object(kind,identity,definition) AS (
  SELECT 'runtime_gateway_reconciliation','live',zasp_runtime_gateway_reconciliation_live_fingerprint()
  UNION ALL SELECT 'column',table_name||'.'||column_name,concat_ws('|',data_type,udt_name,is_nullable,column_default) FROM information_schema.columns WHERE table_schema='public' AND table_name IN('zasp_runtime_ingest_reconciliation_state','zasp_runtime_ingest_reconciliation_work')
  UNION ALL SELECT 'constraint',constraint_value.conrelid::regclass::text||'.'||constraint_value.conname,pg_get_constraintdef(constraint_value.oid,true) FROM pg_constraint constraint_value WHERE constraint_value.conrelid IN('public.zasp_runtime_ingest_reconciliation_state'::regclass,'public.zasp_runtime_ingest_reconciliation_work'::regclass,'public.zasp_runtime_batch_authorities'::regclass) AND (constraint_value.conrelid<>'public.zasp_runtime_batch_authorities'::regclass OR constraint_value.conname='zasp_runtime_batch_authorities_check')
  UNION ALL SELECT 'policy',policy_value.schemaname||'.'||policy_value.tablename||'.'||policy_value.policyname,concat_ws('|',policy_value.roles::text,policy_value.cmd,policy_value.qual,policy_value.with_check) FROM pg_policies policy_value WHERE policy_value.schemaname='public' AND policy_value.tablename IN('zasp_runtime_ingest_reconciliation_state','zasp_runtime_ingest_reconciliation_work')
  UNION ALL SELECT 'index',index_value.indexrelid::regclass::text,pg_get_indexdef(index_value.indexrelid) FROM pg_index index_value WHERE index_value.indexrelid IN('public.zasp_runtime_batches_sensor_rate_v17_idx'::regclass,'public.zasp_runtime_ingest_reconcile_claim_v17_idx'::regclass)
  UNION ALL SELECT 'function',procedure_value.oid::regprocedure::text,pg_get_functiondef(procedure_value.oid) FROM pg_proc procedure_value JOIN pg_namespace namespace_value ON namespace_value.oid=procedure_value.pronamespace WHERE namespace_value.nspname='public' AND procedure_value.proname IN('zasp_runtime_reserve_batch','zasp_runtime_finalize_batch','zasp_runtime_reserve_batch_v15_internal','zasp_runtime_finalize_batch_v15_internal','zasp_runtime_reserve_batch_v17','zasp_runtime_finalize_batch_v17','zasp_runtime_claim_reconciliation','zasp_runtime_release_reconciliation','zasp_runtime_finish_reconciliation','zasp_runtime_quarantine_reconciliation','zasp_runtime_ingest_reconciliation_security_ready','zasp_runtime_ingest_reconciliation_readiness')
  UNION ALL SELECT 'function_acl',procedure_value.oid::regprocedure::text,COALESCE(array_to_string(procedure_value.proacl,','),'') FROM pg_proc procedure_value JOIN pg_namespace namespace_value ON namespace_value.oid=procedure_value.pronamespace WHERE namespace_value.nspname='public' AND procedure_value.proname IN('zasp_runtime_reserve_batch','zasp_runtime_finalize_batch','zasp_runtime_reserve_batch_v15_internal','zasp_runtime_finalize_batch_v15_internal','zasp_runtime_reserve_batch_v17','zasp_runtime_finalize_batch_v17','zasp_runtime_claim_reconciliation','zasp_runtime_release_reconciliation','zasp_runtime_finish_reconciliation','zasp_runtime_quarantine_reconciliation','zasp_runtime_ingest_reconciliation_security_ready','zasp_runtime_ingest_reconciliation_readiness')
 ) SELECT encode(digest(convert_to(string_agg(kind||chr(31)||identity||chr(31)||definition,chr(30) ORDER BY kind,identity,definition),'UTF8'),'sha256'),'hex') FROM semantic_object
$$;
ALTER FUNCTION public.zasp_runtime_ingest_reconciliation_live_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_ingest_reconciliation_live_fingerprint() FROM PUBLIC;

CREATE FUNCTION public.zasp_runtime_ingest_reconciliation_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT NOT EXISTS(SELECT 1 FROM pg_class class_value WHERE class_value.oid IN('public.zasp_runtime_ingest_reconciliation_state'::regclass,'public.zasp_runtime_ingest_reconciliation_work'::regclass) AND (class_value.relowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT class_value.relrowsecurity OR NOT class_value.relforcerowsecurity))
  AND NOT EXISTS(SELECT 1 FROM pg_class class_value CROSS JOIN aclexplode(COALESCE(class_value.relacl,acldefault('r',class_value.relowner))) acl WHERE class_value.oid IN('public.zasp_runtime_ingest_reconciliation_state'::regclass,'public.zasp_runtime_ingest_reconciliation_work'::regclass) AND acl.grantee<>class_value.relowner)
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value JOIN pg_namespace namespace_value ON namespace_value.oid=procedure_value.pronamespace WHERE namespace_value.nspname='public' AND procedure_value.proname IN('zasp_runtime_reserve_batch','zasp_runtime_finalize_batch','zasp_runtime_reserve_batch_v15_internal','zasp_runtime_finalize_batch_v15_internal','zasp_runtime_reserve_batch_v17','zasp_runtime_finalize_batch_v17','zasp_runtime_claim_reconciliation','zasp_runtime_release_reconciliation','zasp_runtime_finish_reconciliation','zasp_runtime_quarantine_reconciliation','zasp_runtime_ingest_reconciliation_live_fingerprint','zasp_runtime_ingest_reconciliation_security_ready','zasp_runtime_ingest_reconciliation_readiness') AND (procedure_value.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure_value.prosecdef OR NOT COALESCE(procedure_value.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public']))
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value CROSS JOIN aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE procedure_value.oid IN('zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer)'::regprocedure,'zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text)'::regprocedure,'zasp_runtime_reserve_batch_v17(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer)'::regprocedure,'zasp_runtime_finalize_batch_v17(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text)'::regprocedure,'zasp_runtime_claim_reconciliation(text,text,integer,integer)'::regprocedure,'zasp_runtime_release_reconciliation(text,text,text,text,bigint,text,text,integer,text)'::regprocedure,'zasp_runtime_finish_reconciliation(text,text,text,text,bigint,text,text,text,text,text,text,text,bytea,bigint,text)'::regprocedure,'zasp_runtime_quarantine_reconciliation(text,text,text,text,bigint,text,text)'::regprocedure) AND acl.grantee NOT IN(procedure_value.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_runtime_ingest')))
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value CROSS JOIN aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE procedure_value.oid IN('zasp_runtime_reserve_batch_v15_internal(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer)'::regprocedure,'zasp_runtime_finalize_batch_v15_internal(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text)'::regprocedure) AND acl.grantee<>procedure_value.proowner)
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value CROSS JOIN aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE procedure_value.oid IN('zasp_runtime_ingest_reconciliation_live_fingerprint()'::regprocedure,'zasp_runtime_ingest_reconciliation_security_ready()'::regprocedure) AND acl.grantee<>procedure_value.proowner)
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value JOIN pg_namespace namespace_value ON namespace_value.oid=procedure_value.pronamespace CROSS JOIN aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE namespace_value.nspname='public' AND procedure_value.proname='zasp_runtime_ingest_reconciliation_readiness' AND acl.grantee=0)
  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_reserve_batch_v17(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer)','EXECUTE')
  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_finalize_batch_v17(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text)','EXECUTE')
  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_claim_reconciliation(text,text,integer,integer)','EXECUTE')
  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_release_reconciliation(text,text,text,text,bigint,text,text,integer,text)','EXECUTE')
  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_finish_reconciliation(text,text,text,text,bigint,text,text,text,text,text,text,text,bytea,bigint,text)','EXECUTE')
  AND has_function_privilege('zasp_runtime_ingest','zasp_runtime_quarantine_reconciliation(text,text,text,text,bigint,text,text)','EXECUTE')
  AND NOT EXISTS(SELECT 1 FROM pg_proc procedure_value CROSS JOIN aclexplode(COALESCE(procedure_value.proacl,acldefault('f',procedure_value.proowner))) acl WHERE procedure_value.oid='zasp_runtime_claim_reconciliation(text,text,integer,integer)'::regprocedure AND acl.grantee=0)
  AND NOT has_function_privilege('zasp_runtime_worker','zasp_runtime_claim_reconciliation(text,text,integer,integer)','EXECUTE')
$$;
ALTER FUNCTION public.zasp_runtime_ingest_reconciliation_security_ready() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_ingest_reconciliation_security_ready() FROM PUBLIC;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('runtime_ingest_reconciliation_fingerprint', '4979b5ba927e71fe9bd76917f5c6566c3730f6b9ceb3f7b99cfe59d65689aa6a');

CREATE FUNCTION public.zasp_runtime_ingest_reconciliation_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT length(expected_checksum)=64 AND length(expected_fingerprint)=64
  AND EXISTS(SELECT 1 FROM zasp_schema_versions release WHERE (release.version,release.name,release.checksum)=(17,'runtime_ingest_reconciliation',expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions later WHERE later.version>17))
  AND EXISTS(SELECT 1 FROM zasp_schema_versions release WHERE (release.version,release.name,release.checksum)=(16,'runtime_gateway_reconciliation','e91bd4114f2a91c759aa5d02707b1060593f023cf02557e19888764ed60db35d'))
  AND zasp_runtime_gateway_reconciliation_security_ready()
  AND EXISTS(SELECT 1 FROM zasp_schema_metadata metadata WHERE (metadata.key,metadata.value)=('runtime_ingest_reconciliation_fingerprint',expected_fingerprint))
  AND zasp_runtime_ingest_reconciliation_live_fingerprint()=expected_fingerprint AND zasp_runtime_ingest_reconciliation_security_ready()
$$;
ALTER FUNCTION public.zasp_runtime_ingest_reconciliation_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_ingest_reconciliation_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_ingest_reconciliation_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control;
