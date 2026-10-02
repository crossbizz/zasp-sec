-- Compatibility-first draft: export-evidence refusal must be added with the
-- export authority before this migration can be published.
DO $guard$
BEGIN
 PERFORM public.zasp_audit_exports_require_ready();
 IF EXISTS(SELECT 1 FROM public.zasp_audit_export_jobs) OR EXISTS(SELECT 1 FROM public.zasp_audit_export_idempotency) OR EXISTS(SELECT 1 FROM public.zasp_audit_export_outbox) OR EXISTS(SELECT 1 FROM public.zasp_audit_export_events) OR EXISTS(SELECT 1 FROM public.zasp_audit_export_chunks) OR EXISTS(SELECT 1 FROM public.zasp_audit_export_intents) OR EXISTS(SELECT 1 FROM public.zasp_audit_export_receipts) OR EXISTS(SELECT 1 FROM public.zasp_audit_export_retries) OR EXISTS(SELECT 1 FROM public.zasp_admin_audit WHERE action IN('audit_export.request','audit_export.complete')) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retained audit export evidence';END IF;
END $guard$;
DO $restore$
DECLARE item record;definition text;
BEGIN
 FOR item IN SELECT p.oid,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_audit_exports_predecessor' ORDER BY p.proname LOOP
  definition:=pg_get_functiondef(item.oid);
  EXECUTE replace(definition,'FUNCTION zasp_audit_exports_predecessor.'||item.proname||'(','FUNCTION public.'||item.proname||'(');
 END LOOP;
END $restore$;
DO $source_acl_restore$
DECLARE prior jsonb;
BEGIN
 SELECT before_state INTO STRICT prior FROM public.zasp_audit_export_source_acl WHERE singleton;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(prior->'grants') g WHERE g->>'grantor'=prior->>'owner' AND g->>'grantee'='zasp_discovery_authority' AND g->>'privilege'='SELECT') THEN REVOKE SELECT ON public.zasp_admin_audit FROM zasp_discovery_authority;END IF;
 IF public.zasp_audit_export_source_acl_snapshot() IS DISTINCT FROM prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export source privilege restoration rejected';END IF;
END $source_acl_restore$;
DROP TRIGGER zasp_audit_export_immutable_source_acl ON public.zasp_audit_export_source_acl;
DROP TRIGGER zasp_audit_export_immutable_policy ON public.zasp_audit_export_policies;
DROP TRIGGER zasp_audit_export_job_policy_guard ON public.zasp_audit_export_jobs;
DROP TRIGGER zasp_audit_export_completion_audit_guard ON public.zasp_admin_audit;
DROP TRIGGER zasp_audit_export_immutable_capture ON public.zasp_audit_export_events;
DROP TRIGGER zasp_audit_export_immutable_capture ON public.zasp_audit_export_chunks;
DROP TRIGGER zasp_audit_export_immutable_intent ON public.zasp_audit_export_intents;
DROP TRIGGER zasp_audit_export_immutable_receipt ON public.zasp_audit_export_receipts;
DROP TRIGGER zasp_audit_export_immutable_retry ON public.zasp_audit_export_retries;
DROP TRIGGER zasp_audit_export_outbox_guard ON public.zasp_audit_export_outbox;
DROP INDEX public.zasp_audit_export_source_scan_idx;
DO $worker_cleanup$
DECLARE binding record;
BEGIN
 FOR binding IN SELECT principal_name,authority_role FROM public.zasp_audit_export_worker_bindings LOOP EXECUTE format('REVOKE %I FROM %I',binding.authority_role,binding.principal_name);END LOOP;
 REVOKE zasp_audit_export_worker,zasp_audit_export_outbox FROM zasp_discovery_authority CASCADE;
END $worker_cleanup$;
DROP FUNCTION public.zasp_audit_export_public_capture_event(bigint,public.zasp_audit_export_public_source_v1,bigint,timestamptz);
DROP FUNCTION public.zasp_audit_export_public_page(text,text,text,text,bytea,text,jsonb,timestamptz,text,integer,text,text);
DROP FUNCTION public.zasp_audit_export_public_page_readiness(text,text);
DROP FUNCTION public.zasp_audit_export_public_item(public.zasp_audit_export_public_source_v1,bigint);
DROP VIEW public.zasp_audit_export_public_source_v1;
DO $drop_export_functions$
DECLARE item record;
BEGIN
 FOR item IN SELECT p.oid::regprocedure::text signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND starts_with(p.proname,'zasp_audit_export_') LOOP EXECUTE 'DROP FUNCTION '||item.signature;END LOOP;
END $drop_export_functions$;
DROP TABLE public.zasp_audit_export_outbox,public.zasp_audit_export_idempotency;
DROP TABLE public.zasp_audit_export_receipts;
DROP TABLE public.zasp_audit_export_retries;
DROP TABLE public.zasp_audit_export_events,public.zasp_audit_export_chunks,public.zasp_audit_export_intents;
DROP TABLE public.zasp_audit_export_jobs,public.zasp_audit_export_api_bindings;
DROP TABLE public.zasp_audit_export_current_policy;
DROP TABLE public.zasp_audit_export_policies;
DROP TABLE public.zasp_audit_export_worker_bindings;
DROP TABLE public.zasp_audit_export_source_acl;
DROP ROLE zasp_audit_export_worker;
DROP ROLE zasp_audit_export_outbox;
DROP FUNCTION public.zasp_audit_exports_require_ready();
DROP FUNCTION public.zasp_production_audit_exports_readiness(text,text);
DROP FUNCTION public.zasp_production_audit_exports_live_fingerprint();
DROP FUNCTION public.zasp_audit_exports_predecessor_releases();
DO $drop_saved$
DECLARE item record;
BEGIN
 FOR item IN SELECT p.oid::regprocedure::text signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_audit_exports_predecessor' LOOP EXECUTE 'DROP FUNCTION '||item.signature;END LOOP;
END $drop_saved$;
DROP SCHEMA zasp_audit_exports_predecessor;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_audit_exports_checksum','production_audit_exports_fingerprint');
DO $restored$
BEGIN
 IF public.zasp_production_runtime_precision_live_fingerprint() IS DISTINCT FROM (SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit exports predecessor restoration rejected';END IF;
END $restored$;
