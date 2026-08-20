DO $security_guard$ BEGIN
  IF NOT zasp_connector_security_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security schema drift blocks rollback'; END IF;
END $security_guard$;

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
  IF actual_fingerprint<>'7b8b625b0f48152a1e49ae587c2673c9ea6e5af4ebb3e8e929f54dd82f643eed' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='semantic schema drift blocks rollback'; END IF;
END $rollback_guard$;

DO $data_guard$ BEGIN
  IF EXISTS(SELECT 1 FROM zasp_connector_oauth_attempts) OR EXISTS(SELECT 1 FROM zasp_connector_effects) OR EXISTS(SELECT 1 FROM zasp_connector_credentials) OR EXISTS(SELECT 1 FROM zasp_connector_audit) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='connector authorization data blocks rollback'; END IF;
END $data_guard$;

UPDATE zasp_schema_metadata SET value='production-discovery-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='connector-authorization-v1';
DELETE FROM zasp_schema_metadata WHERE key='connector_authorization_fingerprint';
DO $migration$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'connector-authorization-v1','production-discovery-v1'); definition:=replace(definition,'release."version" = 11','release."version" = 10'); definition:=replace(definition,'release."name" = ''connector_authorization''','release."name" = ''production_discovery'''); definition:=replace(definition,'later_release."version" > 11','later_release."version" > 10'); EXECUTE definition;
END $migration$;
DO $risk_migration$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'connector-authorization-v1','production-discovery-v1');
 definition:=replace(replace(definition,'release."version"=11','release."version"=10'),'release."version" = 11','release."version" = 10');
 definition:=replace(definition,'release."name"=''connector_authorization''','release."name"=''production_discovery''');
 definition:=replace(replace(definition,'later."version">11','later."version">10'),'later."version" > 11','later."version" > 10');
 IF position('production-discovery-v1' IN definition)=0 OR position('release."version"=10' IN replace(definition,' ',''))=0 OR position('release."name"=''production_discovery''' IN replace(definition,' ',''))=0 OR position('later."version">10' IN replace(definition,' ',''))=0 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk mutation rollback evolution failed';
 END IF;
 EXECUTE definition;
END $risk_migration$;
DROP FUNCTION zasp_connector_readiness(text,text);
DROP FUNCTION zasp_connector_security_ready();
DROP FUNCTION zasp_connector_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text);
DROP FUNCTION zasp_connector_complete_revocation(text,text,text,text,text,text);
DROP FUNCTION zasp_connector_fail_reconciliation(text,text,text,text,text,text,text);
DROP FUNCTION zasp_connector_remediate_quarantine(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text);
DROP FUNCTION zasp_connector_quarantine_reconciliation(text,text,text,text,text,text,text);
DROP FUNCTION zasp_connector_get_quarantine(text,text,text,text);
DROP FUNCTION zasp_connector_complete_reconciliation(text,text,text,text,text,text,text,text,text,text,text,text,jsonb,bytea);
DROP FUNCTION zasp_connector_complete_cleanup(text,text,text,text);
DROP FUNCTION zasp_connector_complete_cleanup(text,text,text,text,text,text);
DROP FUNCTION zasp_connector_complete_oauth(text,text,text,text,text,text,text,text,text,text,jsonb,bytea);
DROP FUNCTION zasp_connector_put_credential(text,text,text,text,text,text,text,text,bigint,jsonb);
DROP FUNCTION zasp_connector_claim_reconciliation(text,integer,integer);
DROP FUNCTION zasp_connector_resolve_effect(text,text,text,text,text,text,jsonb,text);
DROP FUNCTION zasp_connector_begin_effect(text,text,text,text,text,text,text,text,text,bytea);
DROP FUNCTION zasp_connector_stage_pkce_cleanup(text,text,text,text,text,text,text,text,bytea,timestamptz,text);
DROP FUNCTION zasp_connector_activate_pkce_cleanup(text,text,text,text);
DROP FUNCTION zasp_connector_complete_pkce_cleanup(text,text,text,text,text,text);
DROP FUNCTION zasp_connector_consume_oauth(text,text,text,bytea,text,bytea);
DROP FUNCTION zasp_connector_start_oauth(text,text,text,text,text,text,text,bytea,bytea,text,bytea,jsonb,timestamptz,bigint,jsonb,text,text);
DROP FUNCTION zasp_connector_audit_event(text,text,text,text,text,text,text,text,text,jsonb);
DROP TABLE zasp_connector_audit;
DROP TABLE zasp_connector_credentials;
DROP TABLE zasp_connector_effects;
DROP TABLE zasp_connector_oauth_attempts;
DROP FUNCTION zasp_connector_metadata_only(jsonb);
DROP FUNCTION zasp_connector_scopes_valid(jsonb);
DROP FUNCTION zasp_connector_provider_valid(text);
REVOKE SELECT,INSERT,UPDATE,DELETE ON zasp_workflow_records,zasp_workflow_idempotency,zasp_workflow_audit,zasp_workflow_receipts FROM zasp_discovery_authority;

CREATE OR REPLACE FUNCTION "public"."zasp_reference_only"(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT jsonb_typeof(value)='object'
       AND octet_length(value::text)<=16384
       AND value::text !~* '"[^"]*(secret|password|token|credential|private.?key|session)[^"]*"[[:space:]]*:'
$$;

CREATE OR REPLACE FUNCTION "public"."zasp_discovery_readiness"(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE AS $$
 WITH semantic_objects AS (
   SELECT 'table'::text object_kind,class.relname::text object_identity,jsonb_build_object('row_security',class.relrowsecurity,'force_row_security',class.relforcerowsecurity,'persistence',class.relpersistence) definition FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p')
   UNION ALL SELECT 'column',class.relname||'.'||attribute.attnum||'.'||attribute.attname,jsonb_build_object('type',format_type(attribute.atttypid,attribute.atttypmod),'not_null',attribute.attnotnull,'default',COALESCE(regexp_replace(pg_get_expr(default_value.adbin,default_value.adrelid,true),E'\\s+',' ','g'),''),'identity',attribute.attidentity,'generated',attribute.attgenerated,'collation',CASE WHEN attribute.attcollation=0 THEN '' ELSE attribute.attcollation::regcollation::text END) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p') AND attribute.attnum>0 AND NOT attribute.attisdropped
   UNION ALL SELECT 'constraint',class.relname||'.'||constraint_value.conname,jsonb_build_object('type',constraint_value.contype,'definition',regexp_replace(pg_get_constraintdef(constraint_value.oid,true),E'\\s+',' ','g'),'deferrable',constraint_value.condeferrable,'deferred',constraint_value.condeferred,'validated',constraint_value.convalidated) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_'
   UNION ALL SELECT 'index',table_class.relname||'.'||index_class.relname,jsonb_build_object('definition',regexp_replace(pg_get_indexdef(index_value.indexrelid,0,true),E'\\s+',' ','g'),'unique',index_value.indisunique,'primary',index_value.indisprimary,'exclusion',index_value.indisexclusion,'valid',index_value.indisvalid,'ready',index_value.indisready) FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace namespace ON namespace.oid=table_class.relnamespace WHERE namespace.nspname='public' AND left(table_class.relname,5)='zasp_'
   UNION ALL SELECT 'function',procedure.proname||'('||pg_get_function_identity_arguments(procedure.oid)||')',jsonb_build_object('result',pg_get_function_result(procedure.oid),'language',language.lanname,'kind',procedure.prokind,'volatility',procedure.provolatile,'strict',procedure.proisstrict,'security_definer',procedure.prosecdef,'leakproof',procedure.proleakproof,'parallel',procedure.proparallel,'config',COALESCE(to_jsonb(procedure.proconfig),'[]'::jsonb),'body',regexp_replace(btrim(procedure.prosrc),E'\\s+',' ','g')) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_language language ON language.oid=procedure.prolang WHERE namespace.nspname='public' AND left(procedure.proname,5)='zasp_'
 ), live AS (SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(object_kind,object_identity,definition) ORDER BY object_kind,object_identity)::text,'[]'),'UTF8'),'sha256'),'hex') value FROM semantic_objects)
 SELECT EXISTS(SELECT 1 FROM zasp_schema_versions v JOIN zasp_schema_metadata m ON m.key='production_core_schema' AND m.value='production-discovery-v1' JOIN zasp_schema_metadata schema_fingerprint ON schema_fingerprint.key='production_discovery_fingerprint' JOIN zasp_schema_metadata release_fingerprint ON release_fingerprint.key='production_discovery_release_fingerprint' CROSS JOIN live
 WHERE v.version=10 AND v.name='production_discovery' AND v.checksum=expected_checksum AND release_fingerprint.value=expected_fingerprint AND live.value=schema_fingerprint.value
 AND zasp_discovery_security_ready()
 AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions newer WHERE newer.version>10))
$$;
REVOKE ALL ON FUNCTION zasp_discovery_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway;
ALTER FUNCTION zasp_discovery_readiness(text,text) SECURITY DEFINER;
ALTER FUNCTION zasp_discovery_readiness(text,text) SET search_path TO pg_catalog, public;
ALTER FUNCTION zasp_discovery_readiness(text,text) OWNER TO zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_discovery_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway;

INSERT INTO zasp_schema_metadata(key,value) VALUES('production_discovery_release_fingerprint','a3ee9cb3bfd3e6ed0d37399817432ec9ebdc4e4a66b778d2e1b79c62f99a65f9') ON CONFLICT(key) DO UPDATE SET value=excluded.value,applied_at=transaction_timestamp();
UPDATE zasp_schema_metadata SET value='2a9343338fc5dce9de769c58e612b23e69a669c32b870b4c861e718439a8288a',applied_at=transaction_timestamp() WHERE key='production_discovery_fingerprint';
