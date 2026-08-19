DO $rollback_guard$
DECLARE actual_fingerprint text;
BEGIN
    WITH semantic_objects AS (
        SELECT 'table'::text object_kind,class.relname::text object_identity,jsonb_build_object('row_security',class.relrowsecurity,'force_row_security',class.relforcerowsecurity,'persistence',class.relpersistence) definition FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p')
        UNION ALL SELECT 'column',class.relname||'.'||attribute.attnum||'.'||attribute.attname,jsonb_build_object('type',format_type(attribute.atttypid,attribute.atttypmod),'not_null',attribute.attnotnull,'default',COALESCE(regexp_replace(pg_get_expr(default_value.adbin,default_value.adrelid,true),E'\\s+',' ','g'),''),'identity',attribute.attidentity,'generated',attribute.attgenerated,'collation',CASE WHEN attribute.attcollation=0 THEN '' ELSE attribute.attcollation::regcollation::text END) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p') AND attribute.attnum>0 AND NOT attribute.attisdropped
        UNION ALL SELECT 'constraint',class.relname||'.'||constraint_value.conname,jsonb_build_object('type',constraint_value.contype,'definition',regexp_replace(pg_get_constraintdef(constraint_value.oid,true),E'\\s+',' ','g'),'deferrable',constraint_value.condeferrable,'deferred',constraint_value.condeferred,'validated',constraint_value.convalidated) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_'
        UNION ALL SELECT 'index',table_class.relname||'.'||index_class.relname,jsonb_build_object('definition',regexp_replace(pg_get_indexdef(index_value.indexrelid,0,true),E'\\s+',' ','g'),'unique',index_value.indisunique,'primary',index_value.indisprimary,'exclusion',index_value.indisexclusion,'valid',index_value.indisvalid,'ready',index_value.indisready) FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace namespace ON namespace.oid=table_class.relnamespace WHERE namespace.nspname='public' AND left(table_class.relname,5)='zasp_'
        UNION ALL SELECT 'function',procedure.proname||'('||pg_get_function_identity_arguments(procedure.oid)||')',jsonb_build_object('result',pg_get_function_result(procedure.oid),'language',language.lanname,'kind',procedure.prokind,'volatility',procedure.provolatile,'strict',procedure.proisstrict,'security_definer',procedure.prosecdef,'leakproof',procedure.proleakproof,'parallel',procedure.proparallel,'config',COALESCE(to_jsonb(procedure.proconfig),'[]'::jsonb),'body',regexp_replace(btrim(procedure.prosrc),E'\\s+',' ','g')) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_language language ON language.oid=procedure.prolang WHERE namespace.nspname='public' AND left(procedure.proname,5)='zasp_'
    ) SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(object_kind,object_identity,definition) ORDER BY object_kind,object_identity)::text,'[]'),'UTF8'),'sha256'),'hex') INTO actual_fingerprint FROM semantic_objects;
    IF actual_fingerprint<>'cd8b5269417477d70b332c65689dee489ff7dfbea32734a9c56951a6bd59c287' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='semantic schema drift blocks rollback'; END IF;
END;
$rollback_guard$;

DO $data_guard$ DECLARE table_name text; populated boolean; BEGIN
  FOREACH table_name IN ARRAY ARRAY['zasp_integrations','zasp_discovery_syncs','zasp_discovery_schedules','zasp_discovery_cursors','zasp_discovery_snapshots','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_evidence','zasp_sensors','zasp_sensor_tokens','zasp_sensor_heartbeats','zasp_runtime_batches','zasp_runtime_stages','zasp_discovery_jobs','zasp_discovery_outbox','zasp_projection_work','zasp_gateway_devices','zasp_gateway_enrollment_tokens','zasp_gateway_credentials','zasp_gateway_policy_subscriptions'] LOOP
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM public.%I)',table_name) INTO populated;
    IF populated THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production discovery data blocks rollback'; END IF;
  END LOOP;
END $data_guard$;

UPDATE zasp_schema_metadata SET value='production-risk-projection-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='production-discovery-v1';
DELETE FROM zasp_schema_metadata WHERE key='production_discovery_fingerprint';

DO $migration$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'production-discovery-v1','production-risk-projection-v1'); definition:=replace(definition,'release."version" = 10','release."version" = 9');
 definition:=replace(definition,'release."name" = ''production_discovery''','release."name" = ''production_risk_projection'''); definition:=replace(definition,'later_release."version" > 10','later_release."version" > 9'); EXECUTE definition;
END $migration$;

DROP FUNCTION zasp_discovery_readiness(text,text);
DROP FUNCTION zasp_discovery_complete_runtime_stage(text,text,text,text,text,bytea,boolean,text);
DROP FUNCTION zasp_discovery_create_runtime_batch(text,text,text,text,text,text,text,text,bytea,integer);
DROP FUNCTION zasp_discovery_sensor_heartbeat(text,text,text,text,bigint,text,bigint,jsonb);
DROP FUNCTION zasp_discovery_sensor_revoke(text,text,text,text,text);
DROP FUNCTION zasp_discovery_sensor_rotate(text,text,text,text,text,text,bytea,bytea,timestamptz);
DROP FUNCTION zasp_discovery_evidence_get(text,text,text,text);
DROP FUNCTION zasp_discovery_complete_projection(text,text,text,text,text,text,text,text,boolean);
DROP FUNCTION zasp_discovery_complete_job(text,text,text,text,text,text,bytea,boolean,text);
DROP FUNCTION zasp_discovery_retry_outbox(text,text,text,text,text,text,integer,text);
DROP FUNCTION zasp_discovery_put_gateway_policy(text,text,text,text,text,bigint,bytea,bytea,timestamptz,timestamptz,bigint);
DROP FUNCTION zasp_discovery_gateway_revoke(text,text,text,text,text);
DROP FUNCTION zasp_discovery_gateway_rotate(text,text,text,text,text,text,text,bytea,timestamptz);
DROP FUNCTION zasp_discovery_gateway_advance_replay(text,text,text,text,bigint,bigint);
DROP FUNCTION zasp_discovery_gateway_enroll(text,text,text,text,text,text,bytea,text,text,bytea,timestamptz);
DROP FUNCTION zasp_discovery_issue_sensor_token(text,text,text,text,text,bytea,bytea,timestamptz);
DROP FUNCTION zasp_discovery_ack_outbox(text,text,text,text,text,text,text);
DROP FUNCTION zasp_discovery_claim_projection_work(text,text,integer,integer);
DROP FUNCTION zasp_discovery_claim_schedules(text,text,integer,integer);
DROP FUNCTION zasp_discovery_claim_jobs(text,text,integer,integer,text);
DROP FUNCTION zasp_discovery_claim_outbox(text,text,integer,integer);
DROP FUNCTION zasp_discovery_entity_page(text,text,text,text,integer);
DROP FUNCTION zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb);
DROP FUNCTION zasp_discovery_request_sync(text,text,text,text,text,text,text,text,text,bytea,text,text,text);
DROP FUNCTION zasp_discovery_create_integration(text,text,text,text,text,text,text,jsonb,text);
DROP TABLE zasp_gateway_policy_subscriptions;
DROP TABLE zasp_gateway_credentials;
DROP TABLE zasp_gateway_enrollment_tokens;
DROP TABLE zasp_gateway_devices;
DROP TABLE zasp_projection_work;
DROP TABLE zasp_discovery_outbox;
DROP TABLE zasp_runtime_stages;
DROP TABLE zasp_runtime_batches;
DROP TABLE zasp_sensor_heartbeats;
DROP TABLE zasp_sensor_tokens;
DROP TABLE zasp_sensors;
DROP TABLE zasp_inventory_evidence;
DROP TABLE zasp_inventory_relationships;
DROP TABLE zasp_inventory_source_observations;
DROP TABLE zasp_inventory_entities;
DROP TABLE zasp_discovery_cursors;
ALTER TABLE zasp_discovery_syncs DROP CONSTRAINT zasp_discovery_syncs_snapshot_fk;
DROP TABLE zasp_discovery_snapshots;
DROP TABLE zasp_discovery_jobs;
DROP TABLE zasp_discovery_syncs;
DROP TABLE zasp_discovery_schedules;
DROP TABLE zasp_integration_connections;
DROP TABLE zasp_integrations;
DROP FUNCTION zasp_reference_only(jsonb);
DROP FUNCTION zasp_discovery_relationship_id(text,text,text,text,text,text,text);
DROP FUNCTION zasp_discovery_canonical_id(text,text,text,text,text);
DROP FUNCTION zasp_valid_product_id(text);
DROP OWNED BY zasp_discovery_api;
DROP OWNED BY zasp_discovery_worker;
DROP OWNED BY zasp_discovery_authority;
DROP ROLE zasp_discovery_api;
DROP ROLE zasp_discovery_worker;
DROP ROLE zasp_discovery_authority;
