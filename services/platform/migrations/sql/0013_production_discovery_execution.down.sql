DO $rollback_guard$ BEGIN
 IF zasp_execution_live_fingerprint()<>'8a464c61b9d914a887a868f04a286f09589efd0d1f578c98c465d63f7ea11491' OR NOT zasp_execution_security_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='semantic schema drift blocks rollback';END IF;
END $rollback_guard$;
DO $data_guard$ BEGIN
 IF EXISTS(SELECT 1 FROM zasp_discovery_snapshot_inputs) OR EXISTS(SELECT 1 FROM zasp_discovery_projection_cursors) OR EXISTS(SELECT 1 FROM zasp_discovery_connection_subjects WHERE source<>'upgrade') OR EXISTS(SELECT 1 FROM zasp_discovery_execution_quotas) THEN RAISE EXCEPTION USING ERRCODE='2BP01',MESSAGE='production discovery execution data blocks rollback';END IF;
END $data_guard$;

DO $release_restore$ DECLARE definition text;BEGIN SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;definition:=replace(definition,'production-discovery-execution-v1','reference-authorization-v1');definition:=replace(definition,'release."version" = 13','release."version" = 12');definition:=replace(definition,'release."name" = ''production_discovery_execution''','release."name" = ''reference_authorization''');definition:=replace(definition,'later_release."version" > 13','later_release."version" > 12');EXECUTE definition;SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO definition;definition:=replace(definition,'production-discovery-execution-v1','reference-authorization-v1');definition:=replace(replace(definition,'release."version"=13','release."version"=12'),'release."version" = 13','release."version" = 12');definition:=replace(replace(definition,'release."name"=''production_discovery_execution''','release."name"=''reference_authorization'''),'release."name" = ''production_discovery_execution''','release."name" = ''reference_authorization''');definition:=replace(replace(definition,'later."version">13','later."version">12'),'later."version" > 13','later."version" > 12');EXECUTE definition;END $release_restore$;

DROP FUNCTION zasp_execution_finish_projection(text,text,text,text,text,text,text,text,text,text,integer);
DROP FUNCTION zasp_execution_advance_projection_cursor(text,text,text,text,text,bigint,bytea);
DROP FUNCTION zasp_execution_claim_projection_work(text,text,integer,integer);
DROP FUNCTION zasp_execution_snapshot_projection_page(text,text,text,text,text,text,integer);
DROP FUNCTION zasp_execution_apply_complete_snapshot(text,text,text,text,text,text,bigint,text,text,text,text,bytea,bigint,text,text,timestamptz,text,text,text,jsonb,jsonb,jsonb);
DROP FUNCTION zasp_execution_heartbeat_schedule(text,text,text,text,text,text,integer);
DROP FUNCTION zasp_execution_schedule_input(text,text,text,text,text,text);
DROP FUNCTION zasp_execution_claim_schedules(text,text,integer,integer);
DROP FUNCTION zasp_execution_heartbeat_job(text,text,text,text,text,text,integer);
DROP FUNCTION zasp_execution_job_input(text,text,text,text,text,text);
DROP FUNCTION zasp_execution_claim_jobs(text,text,integer,integer);
DROP FUNCTION zasp_execution_principal_ready(text);
DROP FUNCTION zasp_execution_register_principals(text,text,text,text);
DROP FUNCTION zasp_execution_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text);
DROP TRIGGER zasp_execution_bind_oauth_subject ON zasp_connector_credentials;
DROP FUNCTION zasp_execution_bind_oauth_subject_trigger();
DROP FUNCTION zasp_execution_bind_connection_subject(text,text,text,text,text,text,text,text,bigint,jsonb,text);
DROP FUNCTION zasp_execution_subject_valid(text,text,text);
DROP FUNCTION zasp_execution_readiness(text,text);
DROP FUNCTION zasp_execution_security_ready();
DROP FUNCTION zasp_execution_live_fingerprint();
DROP INDEX zasp_execution_snapshot_projection_idx;
DROP INDEX zasp_execution_jobs_claim_idx;
DROP TABLE zasp_discovery_projection_cursors;
DROP TABLE zasp_discovery_snapshot_inputs;
DROP TABLE zasp_discovery_execution_quotas;
DROP TABLE zasp_discovery_connection_subjects;
DROP TABLE zasp_discovery_execution_principals;
ALTER TABLE zasp_integration_connections DROP CONSTRAINT zasp_execution_connections_parent_unique;
DELETE FROM zasp_schema_metadata WHERE key='production_discovery_execution_fingerprint';
UPDATE zasp_schema_metadata SET value='reference-authorization-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='production-discovery-execution-v1';
