-- The runner holds release, evidence and outbox locks with NOWAIT. Even a
-- pending precise stage or an unfinalized V2 reservation forbids rollback.
DO $guard$
BEGIN
 IF NOT COALESCE(public.zasp_production_runtime_precision_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=51),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false)
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_batch_authorities WHERE payload_schema_version='runtime-event-v2')
 -- The schema50 deployment uses correlation2/project1/complete1. Refuse
 -- rollback while sandbox-aware OTLP work can still need those consumers;
 -- completed schema50-compatible receipts remain independently replayable.
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_stage_work s JOIN public.zasp_runtime_batch_authorities b USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) WHERE b.source_kind='otlp' AND b.payload_schema_version='runtime-event-v1' AND s.state IN('pending','retryable','leased') AND (s.stage='correlate' AND s.implementation_version='runtime-correlation-v3' OR s.stage='project' AND s.implementation_version='runtime-projection-v2' OR s.stage='complete' AND s.implementation_version='runtime-complete-v2'))
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_stage_work WHERE stage='archive' AND implementation_version<>'runtime-archive-v1' OR stage='index' AND implementation_version<>'runtime-index-v1' OR stage='correlate' AND implementation_version NOT IN('runtime-correlation-v1','runtime-correlation-v2','runtime-correlation-v3') OR stage='project' AND implementation_version NOT IN('runtime-projection-v1','runtime-projection-v2') OR stage='complete' AND implementation_version NOT IN('runtime-complete-v1','runtime-complete-v2'))
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_candidate_snapshots WHERE convert_from(snapshot_body,'UTF8')::jsonb->>'schema' NOT IN('runtime-candidate-snapshot-v1','runtime-candidate-snapshot-v2'))
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision rollback rejected';END IF;
END $guard$;
DROP TRIGGER zasp_runtime_precision_claim_version ON public.zasp_runtime_stage_work;
DROP TRIGGER zasp_runtime_precision_search_claim ON public.zasp_runtime_sandbox_search_outbox;
DROP TRIGGER zasp_runtime_precision_stage_insert ON public.zasp_runtime_stage_work;
DROP TRIGGER zasp_runtime_precision_batch_insert ON public.zasp_runtime_batch_authorities;
DROP TRIGGER zasp_runtime_precision_reconciliation ON public.zasp_runtime_ingest_reconciliation_work;
DROP TRIGGER zasp_runtime_precision_outbox ON public.zasp_discovery_outbox;
DROP TRIGGER zasp_runtime_precision_delivery ON public.zasp_runtime_deliveries;
DROP TRIGGER zasp_runtime_precision_batch_update ON public.zasp_runtime_batch_authorities;
ALTER TABLE public.zasp_runtime_batch_authorities DROP CONSTRAINT zasp_runtime_precision_source_check;
DO $restore$
DECLARE item record;definition text;
BEGIN
 FOR item IN SELECT p.oid,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_precision_predecessor' ORDER BY p.proname LOOP
  definition:=pg_get_functiondef(item.oid);
  EXECUTE replace(definition,'FUNCTION zasp_precision_predecessor.'||item.proname||'(','FUNCTION public.'||item.proname||'(');
 END LOOP;
END $restore$;
DROP FUNCTION public.zasp_runtime_freeze_precise_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea);
DROP FUNCTION public.zasp_runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea);
DROP FUNCTION public.zasp_runtime_precise_epoch(text);
DROP FUNCTION public.zasp_runtime_precise_lineage_valid(jsonb,text);
DROP FUNCTION public.zasp_runtime_claim_stage_precision_compatible(text,text,integer,integer,text);
DROP FUNCTION public.zasp_runtime_claim_archive_v2(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_claim_index_v2(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_claim_correlation_v4(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_claim_projection_v3(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_claim_completion_v3(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_precision_claim_version_guard();
DROP FUNCTION public.zasp_runtime_precision_stage_insert_guard();
DROP FUNCTION public.zasp_runtime_precision_batch_insert_guard();
DROP FUNCTION public.zasp_runtime_precise_search_claim(text,text,integer);
DROP FUNCTION public.zasp_runtime_precision_search_claim_guard();
DROP FUNCTION public.zasp_runtime_claim_reconciliation_v2(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_precision_claim_reconciliation(text,text,integer,integer,boolean);
DROP FUNCTION public.zasp_runtime_precision_reconciliation_ready();
DROP FUNCTION public.zasp_runtime_precision_reconciliation_guard();
DROP FUNCTION public.zasp_runtime_claim_outbox_v2(text,text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_precision_claim_outbox(text,text,text,integer,integer,boolean);
DROP FUNCTION public.zasp_runtime_precision_outbox_guard();
DROP FUNCTION public.zasp_runtime_precision_delivery_guard();
DROP FUNCTION public.zasp_runtime_precision_batch_update_guard();
DROP FUNCTION public.zasp_runtime_precision_transport_ready();
DROP FUNCTION public.zasp_production_runtime_precision_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_precision_live_fingerprint();
DO $drop_saved$
DECLARE item record;
BEGIN
 FOR item IN SELECT p.oid::regprocedure::text signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_precision_predecessor' LOOP EXECUTE 'DROP FUNCTION '||item.signature;END LOOP;
END $drop_saved$;
DROP SCHEMA zasp_precision_predecessor;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_runtime_precision_checksum','production_runtime_precision_fingerprint');
DO $restored$
BEGIN
 IF public.zasp_production_runtime_sandbox_binding_live_fingerprint() IS DISTINCT FROM (SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision predecessor restoration rejected';END IF;
END $restored$;
