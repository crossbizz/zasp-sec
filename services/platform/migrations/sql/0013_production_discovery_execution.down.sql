DO $rollback_guard$ BEGIN
 IF zasp_execution_live_fingerprint()<>'abb04c7b8d470397bdda3c6a258790b654c2b82ca8249090e6674ef864163eda' OR NOT zasp_execution_security_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='semantic schema drift blocks rollback';END IF;
END $rollback_guard$;
DO $transition_guard$ BEGIN
 IF EXISTS(SELECT 1 FROM zasp_discovery_upgrade_transitions transition LEFT JOIN zasp_integrations integration ON (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.integration_id) LEFT JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.integration_id,transition.connection_id) LEFT JOIN zasp_workflow_records workflow ON (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.id,workflow.kind)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.integration_id,'integration') LEFT JOIN zasp_workflow_audit audit ON (audit.organization_id,audit.audit_id,audit.correlation_id,audit.operation,audit.resource_id,audit.resource_version)=(transition.organization_id,transition.audit_id,transition.correlation_id,'degradeIntegrationForExecutionUpgrade',transition.integration_id,transition.prior_integration_version+1) WHERE integration.state IS DISTINCT FROM 'degraded' OR integration.version IS DISTINCT FROM transition.prior_integration_version+1 OR integration.updated_at IS DISTINCT FROM transition.transitioned_at OR connection.state IS DISTINCT FROM transition.prior_connection_state OR connection.verified_at IS DISTINCT FROM transition.prior_connection_verified_at OR connection.version IS DISTINCT FROM transition.prior_connection_version+1 OR connection.updated_at IS DISTINCT FROM transition.transitioned_at OR workflow.version IS DISTINCT FROM transition.prior_workflow_version+1 OR workflow.updated_at IS DISTINCT FROM transition.transitioned_at OR workflow.body->>'status' IS DISTINCT FROM 'degraded' OR audit.audit_id IS NULL OR EXISTS(SELECT 1 FROM zasp_discovery_connection_subjects subject WHERE (subject.organization_id,subject.workspace_id,subject.environment_id,subject.integration_id)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.integration_id))) THEN RAISE EXCEPTION USING ERRCODE='2BP01',MESSAGE='execution upgrade transition drift blocks rollback';END IF;
END $transition_guard$;
DO $data_guard$ BEGIN
 IF EXISTS(SELECT 1 FROM zasp_discovery_snapshot_inputs) OR EXISTS(SELECT 1 FROM zasp_discovery_projection_cursors) OR EXISTS(SELECT 1 FROM zasp_discovery_generation_reservations) OR EXISTS(SELECT 1 FROM zasp_discovery_job_authorities) OR EXISTS(SELECT 1 FROM zasp_discovery_connection_subjects WHERE source<>'upgrade') OR EXISTS(SELECT 1 FROM zasp_discovery_execution_quotas) OR EXISTS(SELECT 1 FROM zasp_discovery_syncs WHERE version>1) THEN RAISE EXCEPTION USING ERRCODE='2BP01',MESSAGE='production discovery execution data blocks rollback';END IF;
END $data_guard$;

UPDATE zasp_integrations integration SET state=transition.prior_integration_state,version=transition.prior_integration_version,updated_at=transition.prior_integration_updated_at FROM zasp_discovery_upgrade_transitions transition WHERE (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.integration_id);
UPDATE zasp_integration_connections connection SET state=transition.prior_connection_state,version=transition.prior_connection_version,verified_at=transition.prior_connection_verified_at,updated_at=transition.prior_connection_updated_at FROM zasp_discovery_upgrade_transitions transition WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.integration_id,transition.connection_id);
UPDATE zasp_workflow_records workflow SET body=transition.prior_workflow_body,version=transition.prior_workflow_version,updated_at=transition.prior_workflow_updated_at FROM zasp_discovery_upgrade_transitions transition WHERE (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.id,workflow.kind)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.integration_id,'integration');
DELETE FROM zasp_workflow_audit audit USING zasp_discovery_upgrade_transitions transition WHERE (audit.organization_id,audit.audit_id,audit.correlation_id,audit.operation,audit.resource_id)=(transition.organization_id,transition.audit_id,transition.correlation_id,'degradeIntegrationForExecutionUpgrade',transition.integration_id);

DO $legacy_worker_restore$ DECLARE definition text;worker_clause text;expanded text:='''zasp_discovery_principal_ready'',''zasp_discovery_apply_snapshot'',''zasp_discovery_claim_jobs'',''zasp_discovery_claim_schedules'',''zasp_discovery_complete_schedule'',''zasp_discovery_claim_projection_work'',''zasp_discovery_finish_job'',''zasp_discovery_finish_projection'',''zasp_discovery_complete_job'',''zasp_discovery_complete_projection''';start_position integer;end_position integer;BEGIN SELECT pg_get_functiondef('public.zasp_discovery_security_ready()'::regprocedure) INTO definition;start_position:=position('has_function_privilege(''zasp_discovery_worker''' IN definition);end_position:=position('has_function_privilege(''zasp_runtime_ingest''' IN definition);IF start_position=0 OR end_position<=start_position THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution discovery worker authority shape changed';END IF;worker_clause:=substring(definition FROM start_position FOR end_position-start_position);worker_clause:=replace(worker_clause,'''zasp_discovery_principal_ready''',expanded);definition:=overlay(definition PLACING worker_clause FROM start_position FOR end_position-start_position);EXECUTE definition;END $legacy_worker_restore$;
GRANT EXECUTE ON FUNCTION zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb),zasp_discovery_claim_jobs(text,text,integer,integer,text),zasp_discovery_claim_schedules(text,text,integer,integer),zasp_discovery_complete_schedule(text,text,text,text,text,text,text,timestamptz),zasp_discovery_claim_projection_work(text,text,integer,integer),zasp_discovery_finish_job(text,text,text,text,text,text,text,bytea,text,integer),zasp_discovery_finish_projection(text,text,text,text,text,text,text,text,text,text,integer),zasp_discovery_complete_job(text,text,text,text,text,text,bytea,boolean,text),zasp_discovery_complete_projection(text,text,text,text,text,text,text,text,boolean) TO zasp_discovery_worker;

DO $release_restore$ DECLARE definition text;BEGIN SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;definition:=replace(definition,'production-discovery-execution-v1','reference-authorization-v1');definition:=replace(definition,'release."version" = 13','release."version" = 12');definition:=replace(definition,'release."name" = ''production_discovery_execution''','release."name" = ''reference_authorization''');definition:=replace(definition,'later_release."version" > 13','later_release."version" > 12');EXECUTE definition;SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO definition;definition:=replace(definition,'production-discovery-execution-v1','reference-authorization-v1');definition:=replace(replace(definition,'release."version"=13','release."version"=12'),'release."version" = 13','release."version" = 12');definition:=replace(replace(definition,'release."name"=''production_discovery_execution''','release."name"=''reference_authorization'''),'release."name" = ''production_discovery_execution''','release."name" = ''reference_authorization''');definition:=replace(replace(definition,'later."version">13','later."version">12'),'later."version" > 13','later."version" > 12');EXECUTE definition;END $release_restore$;

DROP FUNCTION zasp_execution_finish_projection(text,text,text,text,text,text,text,text,text,text,integer);
DROP FUNCTION zasp_execution_advance_projection_cursor(text,text,text,text,text,bigint,bytea);
DROP FUNCTION zasp_execution_projection_status(text,text,text,text);
DROP FUNCTION zasp_execution_claim_projection_work(text,text,integer,integer);
DROP FUNCTION zasp_execution_snapshot_projection_page(text,text,text,text,text,text,integer);
DROP FUNCTION zasp_execution_apply_complete_snapshot(text,text,text,text,text,text,bigint,text,text,text,text,bytea,bigint,text,text,timestamptz,text,text,text,jsonb,jsonb,jsonb);
DROP FUNCTION zasp_execution_heartbeat_schedule(text,text,text,text,text,text,integer);
DROP FUNCTION zasp_execution_complete_schedule(text,text,text,text,text,text,text,timestamptz);
DROP FUNCTION zasp_execution_request_scheduled_sync(text,text,text,text,text,text,text,text,text,text,text,text,bytea,text,text);
DROP FUNCTION zasp_execution_schedule_input(text,text,text,text,text,text);
DROP FUNCTION zasp_execution_claim_schedules(text,text,integer,integer);
DROP FUNCTION zasp_execution_heartbeat_job(text,text,text,text,text,text,integer);
DROP FUNCTION zasp_execution_finish_job(text,text,text,text,text,text,text,bytea,text,integer);
DROP FUNCTION zasp_execution_job_input(text,text,text,text,text,text);
DROP FUNCTION zasp_execution_claim_delivery(text,text,text,text,text,text,integer);
DROP FUNCTION zasp_execution_claim_jobs(text,text,integer,integer);
DROP FUNCTION zasp_execution_principal_ready(text);
DROP FUNCTION zasp_execution_last_good_freshness(text,text,text,text);
DROP FUNCTION zasp_execution_schedule_detail(text,text,text,text,text);
DROP FUNCTION zasp_execution_sync_history(text,text,text,text,timestamptz,text,integer);
DROP FUNCTION zasp_execution_sync_detail(text,text,text,text,text);
DROP FUNCTION zasp_execution_request_sync(text,text,text,text,text,text,text,text,text,bytea,text,text,text);
DROP FUNCTION zasp_execution_register_principals(text,text,text,text);
DROP FUNCTION zasp_execution_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text);
DROP TRIGGER zasp_execution_bind_oauth_subject ON zasp_connector_credentials;
DROP FUNCTION zasp_execution_bind_oauth_subject_trigger();
DROP FUNCTION zasp_execution_bind_connection_subject(text,text,text,text,text,text,text,text,bigint,jsonb,text);
DROP FUNCTION zasp_execution_readiness(text,text);
DROP FUNCTION zasp_execution_security_ready();
DROP FUNCTION zasp_execution_live_fingerprint();
DROP INDEX zasp_execution_snapshot_projection_idx;
DROP INDEX zasp_execution_sync_history_idx;
DROP INDEX zasp_execution_projection_lease_idx;
DROP INDEX zasp_execution_projection_claim_idx;
DROP INDEX zasp_execution_schedules_lease_idx;
DROP INDEX zasp_execution_schedules_claim_idx;
DROP INDEX zasp_execution_jobs_lease_idx;
DROP INDEX zasp_execution_jobs_claim_idx;
DROP TABLE zasp_discovery_projection_cursors;
DROP TABLE zasp_discovery_snapshot_projection_items;
DROP TABLE zasp_discovery_snapshot_inputs;
DROP TABLE zasp_discovery_generation_reservations;
DROP TABLE zasp_discovery_job_authorities;
DROP FUNCTION zasp_execution_subject_valid(text,text,text);
DROP TABLE zasp_discovery_upgrade_transitions;
DROP TABLE zasp_discovery_execution_quotas;
DROP TABLE zasp_discovery_connection_subjects;
DROP TABLE zasp_discovery_execution_principals;
DROP TRIGGER zasp_execution_sync_version ON zasp_discovery_syncs;
DROP FUNCTION zasp_execution_sync_version_trigger();
ALTER TABLE zasp_discovery_syncs DROP COLUMN version;
ALTER TABLE zasp_integration_connections DROP CONSTRAINT zasp_execution_connections_parent_unique;
DELETE FROM zasp_schema_metadata WHERE key='production_discovery_execution_fingerprint';
UPDATE zasp_schema_metadata SET value='reference-authorization-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='production-discovery-execution-v1';
