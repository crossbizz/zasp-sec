DO $runtime_ingest_reconciliation_guard$ BEGIN
 IF zasp_runtime_ingest_reconciliation_live_fingerprint()<>'32e625177b0df46e857d873c886e43aee4ea1200fb295d72ed9f0e8105f2e533' OR NOT zasp_runtime_ingest_reconciliation_security_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime ingest reconciliation drift blocks rollback';END IF;
 IF EXISTS(SELECT 1 FROM zasp_runtime_ingest_reconciliation_state WHERE used_at IS NOT NULL) OR EXISTS(SELECT 1 FROM zasp_runtime_ingest_reconciliation_work WHERE state='leased') THEN RAISE EXCEPTION USING ERRCODE='2BP01',MESSAGE='runtime ingest reconciliation use blocks rollback';END IF;
END $runtime_ingest_reconciliation_guard$;

DO $product_release_restore$ DECLARE definition text;original_definition text;BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'release."version" = 17','release."version" = 16');
 definition:=replace(definition,'release."name" = ''runtime_ingest_reconciliation''','release."name" = ''runtime_gateway_reconciliation''');
 definition:=replace(definition,'later_release."version" > 17','later_release."version" > 16');
 IF definition=original_definition OR position('release."version" = 16' IN definition)=0 OR position('release."name" = ''runtime_gateway_reconciliation''' IN definition)=0 OR position('later_release."version" > 16' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v16 compatibility restoration failed';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(replace(definition,'release."version"=17','release."version"=16'),'release."version" = 17','release."version" = 16');
 definition:=replace(replace(definition,'release."name"=''runtime_ingest_reconciliation''','release."name"=''runtime_gateway_reconciliation'''),'release."name" = ''runtime_ingest_reconciliation''','release."name" = ''runtime_gateway_reconciliation''');
 definition:=replace(replace(definition,'later."version">17','later."version">16'),'later."version" > 17','later."version" > 16');
 IF definition=original_definition OR position('runtime_gateway_reconciliation' IN definition)=0 OR position('release."version"=16' IN definition)=0 AND position('release."version" = 16' IN definition)=0 OR position('later."version">16' IN definition)=0 AND position('later."version" > 16' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v16 compatibility restoration failed';END IF;
 EXECUTE definition;
END $product_release_restore$;

DELETE FROM public.zasp_schema_metadata WHERE (key,value)=('runtime_ingest_reconciliation_fingerprint', '32e625177b0df46e857d873c886e43aee4ea1200fb295d72ed9f0e8105f2e533');
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
