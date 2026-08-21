DO $runtime_ingest_reconciliation_guard$ BEGIN
 IF zasp_runtime_ingest_reconciliation_live_fingerprint()<>'4979b5ba927e71fe9bd76917f5c6566c3730f6b9ceb3f7b99cfe59d65689aa6a' OR NOT zasp_runtime_ingest_reconciliation_security_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime ingest reconciliation drift blocks rollback';END IF;
 IF EXISTS(SELECT 1 FROM zasp_runtime_ingest_reconciliation_state WHERE used_at IS NOT NULL) OR EXISTS(SELECT 1 FROM zasp_runtime_ingest_reconciliation_work WHERE state='leased') THEN RAISE EXCEPTION USING ERRCODE='2BP01',MESSAGE='runtime ingest reconciliation use blocks rollback';END IF;
END $runtime_ingest_reconciliation_guard$;

DELETE FROM public.zasp_schema_metadata WHERE (key,value)=('runtime_ingest_reconciliation_fingerprint', '4979b5ba927e71fe9bd76917f5c6566c3730f6b9ceb3f7b99cfe59d65689aa6a');
DROP FUNCTION public.zasp_runtime_ingest_reconciliation_readiness(text,text);
DROP FUNCTION public.zasp_runtime_ingest_reconciliation_security_ready();
DROP FUNCTION public.zasp_runtime_ingest_reconciliation_live_fingerprint();
DROP FUNCTION public.zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer);
DROP FUNCTION public.zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text);
DROP FUNCTION public.zasp_runtime_quarantine_reconciliation(text,text,text,text,bigint,text,text);
DROP FUNCTION public.zasp_runtime_finish_reconciliation(text,text,text,text,bigint,text,text,text,text,text,text,text,bytea,bigint,text);
DROP FUNCTION public.zasp_runtime_release_reconciliation(text,text,text,text,bigint,text,text,integer,text);
DROP FUNCTION public.zasp_runtime_claim_reconciliation(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_finalize_batch_v17(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text);
DROP FUNCTION public.zasp_runtime_reserve_batch_v17(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer);
ALTER FUNCTION public.zasp_runtime_reserve_batch_v15_internal(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer) RENAME TO zasp_runtime_reserve_batch;
ALTER FUNCTION public.zasp_runtime_finalize_batch_v15_internal(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text) RENAME TO zasp_runtime_finalize_batch;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer),public.zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text) TO zasp_runtime_ingest;
ALTER TABLE public.zasp_runtime_batch_authorities DROP CONSTRAINT zasp_runtime_batch_authorities_check;
ALTER TABLE public.zasp_runtime_batch_authorities ADD CONSTRAINT zasp_runtime_batch_authorities_check CHECK(
 (state IN('uploading','unknown') AND raw_artifact_reference IS NULL AND raw_artifact_version_id IS NULL AND raw_artifact_checksum IS NULL AND raw_artifact_size_bytes IS NULL AND raw_artifact_kms_key IS NULL AND finalized_at IS NULL)
 OR (state NOT IN('uploading','unknown') AND zasp_discovery_s3_object_reference(raw_artifact_reference) AND length(raw_artifact_version_id) BETWEEN 1 AND 1024 AND raw_artifact_checksum IS NOT NULL AND raw_artifact_size_bytes=payload_size_bytes AND length(raw_artifact_kms_key) BETWEEN 1 AND 512 AND finalized_at IS NOT NULL)
);
DROP TABLE public.zasp_runtime_ingest_reconciliation_work;
DROP TABLE public.zasp_runtime_ingest_reconciliation_state;
DROP INDEX public.zasp_runtime_batches_sensor_rate_v17_idx;
