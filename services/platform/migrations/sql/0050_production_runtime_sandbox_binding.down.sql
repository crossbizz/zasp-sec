-- The runner holds the integration and release catalog locks first. Refuse
-- contention before checking data so no observation can enter behind the guard.
LOCK TABLE public.zasp_runtime_batch_authorities,public.zasp_runtime_stage_work,public.zasp_runtime_candidate_observations,public.zasp_runtime_candidate_snapshots,public.zasp_runtime_session_events,public.zasp_runtime_session_projection_receipts,public.zasp_runtime_session_search_outbox IN ACCESS EXCLUSIVE MODE NOWAIT;
LOCK TABLE public.zasp_runtime_sandbox_search_outbox IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $guard$
BEGIN
 IF NOT COALESCE(public.zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=50),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false)
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_stage_work WHERE stage='correlate' AND implementation_version NOT IN('runtime-correlation-v1','runtime-correlation-v2'))
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_stage_work WHERE stage='project' AND implementation_version<>'runtime-projection-v1' OR stage='complete' AND implementation_version<>'runtime-complete-v1')
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_session_events WHERE sandbox_id IS NOT NULL OR sandbox_source_sensor_id IS NOT NULL)
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_candidate_observations WHERE sandbox_id IS NOT NULL)
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_sandbox_search_outbox WHERE attempt<>0 OR state<>'pending')
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_candidate_snapshots WHERE convert_from(snapshot_body,'UTF8')::jsonb->>'schema' IS DISTINCT FROM 'runtime-candidate-snapshot-v1')
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox rollback rejected';END IF;
END $guard$;

DROP TRIGGER zasp_runtime_sandbox_search_enqueue ON public.zasp_runtime_session_projection_receipts;
DROP FUNCTION public.zasp_runtime_sandbox_search_enqueue();
DROP TRIGGER zasp_runtime_legacy_search_insert_guard ON public.zasp_runtime_session_search_outbox;
DROP FUNCTION public.zasp_runtime_legacy_search_insert_guard();
DO $legacy_enqueue$
DECLARE definition text;needle text:=' IF EXISTS(SELECT 1 FROM zasp_runtime_stage_work project WHERE (project.organization_id,project.workspace_id,project.environment_id,project.batch_id,project.batch_generation)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id,NEW.batch_generation) AND project.stage=''project'' AND project.implementation_version IN(''runtime-projection-v2'',''runtime-projection-v3'')) THEN RETURN NEW;END IF;'||chr(10);
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_session_search_enqueue()'::regprocedure) INTO STRICT definition;
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy search enqueue rollback rejected';END IF;
 EXECUTE replace(definition,needle,'');
END
$legacy_enqueue$;
DROP TRIGGER zasp_runtime_sandbox_search_recovery_guard ON public.zasp_runtime_sandbox_search_outbox;
DROP FUNCTION public.zasp_runtime_sandbox_search_mutation_guard();
DROP FUNCTION public.zasp_runtime_sandbox_search_claim(text,text,integer);
DROP FUNCTION public.zasp_runtime_sandbox_search_heartbeat(text,text,text,text,bigint,text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_sandbox_search_finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer);
DROP FUNCTION public.zasp_runtime_sandbox_search_worker_ready();
DROP FUNCTION public.zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[]);
DROP FUNCTION public.zasp_runtime_sandbox_query_status(text,text,text,text);
DROP FUNCTION public.zasp_production_runtime_sandbox_search_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_sandbox_search_security_ready();
DROP TABLE public.zasp_runtime_sandbox_search_outbox;

DROP FUNCTION public.zasp_runtime_claim_correlation_v3(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_claim_projection_v2(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_claim_completion_v2(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_claim_session_stage_compatible(text,text,integer,integer,boolean);
DROP TRIGGER zasp_runtime_session_claim_version ON public.zasp_runtime_stage_work;
DROP FUNCTION public.zasp_runtime_session_claim_version_guard();
DO $session_claims$
DECLARE definition text;needle text:='WHERE stage_row.stage=stage_value AND (stage_value NOT IN(''project'',''complete'') OR stage_value=''project'' AND stage_row.implementation_version=''runtime-projection-v1'' OR stage_value=''complete'' AND stage_row.implementation_version=''runtime-complete-v1'') AND';
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean)'::regprocedure) INTO STRICT definition;
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session claim rollback rejected';END IF;
 EXECUTE replace(definition,needle,'WHERE stage_row.stage=stage_value AND');
END
$session_claims$;
DROP FUNCTION public.zasp_runtime_claim_stage_sandbox_compatible(text,text,integer,integer,boolean);
DROP FUNCTION public.zasp_runtime_freeze_sandbox_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea);
DROP FUNCTION public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea);
DROP FUNCTION public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer);
DROP FUNCTION public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text);
ALTER TABLE public.zasp_runtime_session_events DROP CONSTRAINT zasp_runtime_session_sandbox_binding_check, DROP COLUMN sandbox_id, DROP COLUMN sandbox_source_sensor_id;

CREATE OR REPLACE FUNCTION public.zasp_runtime_correlation_claim_version_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF NEW.stage='correlate' AND NEW.implementation_version<>'runtime-correlation-v1'
 AND (NEW.attempt>OLD.attempt OR (NEW.state='failed' AND NEW.last_error_class='exhausted' AND (OLD.state IN('pending','retryable') OR OLD.state='leased' AND OLD.lease_expires_at<=transaction_timestamp())))
 AND NOT COALESCE(NEW.implementation_version='runtime-correlation-v2' AND current_setting('zasp.runtime_correlation_claim_version',true)='runtime-correlation-v2' AND zasp_runtime_stage_for_session()='correlate' AND zasp_runtime_principal_ready('zasp_runtime_correlation_worker'),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime correlation claim version rejected';END IF;
 RETURN NEW;
END
$guard$;

DROP FUNCTION public.zasp_production_runtime_correlation_routing_readiness(text,text);
ALTER FUNCTION public.zasp_production_runtime_correlation_routing_readiness_v49(text,text) RENAME TO zasp_production_runtime_correlation_routing_readiness;
DROP FUNCTION public.zasp_production_runtime_sandbox_binding_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_sandbox_binding_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_sandbox_binding_security_ready();
ALTER TABLE public.zasp_runtime_candidate_observations DROP COLUMN sandbox_id;

DO $ordinal$
DECLARE definition text;needle text:='a.attname,CASE WHEN a.attrelid=''public.zasp_runtime_candidate_observations''::regclass AND a.attname=''sandbox_id'' THEN (SELECT count(*) FROM pg_attribute live WHERE live.attrelid=a.attrelid AND live.attnum>0 AND live.attnum<=a.attnum AND NOT live.attisdropped) ELSE a.attnum END,format_type';
BEGIN
 SELECT pg_get_functiondef('public.zasp_production_runtime_candidate_authority_live_fingerprint()'::regprocedure) INTO STRICT definition;
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox ordinal rollback rejected';END IF;
 EXECUTE replace(definition,needle,'a.attname,a.attnum,format_type');
END
$ordinal$;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 50','later_release."version" > 49'),'later."version">50','later."version">49'),'later."version" > 50','later."version" > 49');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_runtime_sandbox_binding_fingerprint','production_runtime_sandbox_binding_checksum');
DO $restored$
BEGIN
 IF public.zasp_production_runtime_correlation_routing_live_fingerprint() IS DISTINCT FROM (SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_correlation_routing_fingerprint')
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sandbox predecessor restoration rejected';END IF;
END
$restored$;
