-- Forward-owned compatibility shim used only while rolling a v11-compatible
-- v10 database into the immutable v10 down migration.
DO $normalize$
DECLARE
  discovery_checksum text;
  compatibility_fingerprint text;
  release_fingerprint text;
  definition text;
BEGIN
  SELECT checksum INTO discovery_checksum FROM zasp_schema_versions WHERE version=10 AND name='production_discovery';
  SELECT value INTO compatibility_fingerprint FROM zasp_schema_metadata WHERE key='production_discovery_fingerprint';
  SELECT value INTO release_fingerprint FROM zasp_schema_metadata WHERE key='production_discovery_release_fingerprint';
  IF release_fingerprint IS NULL THEN
    RETURN;
  END IF;
  IF release_fingerprint<>'a3ee9cb3bfd3e6ed0d37399817432ec9ebdc4e4a66b778d2e1b79c62f99a65f9'
     OR compatibility_fingerprint<>'2a9343338fc5dce9de769c58e612b23e69a669c32b870b4c861e718439a8288a'
     OR discovery_checksum IS NULL
     OR NOT zasp_discovery_readiness(discovery_checksum,release_fingerprint) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='v10 compatibility drift blocks normalization';
  END IF;

  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO definition;
  definition:=replace(definition,'production-discovery-v1','production-risk-projection-v1');
  definition:=replace(replace(definition,'release."version"=10','release."version"=9'),'release."version" = 10','release."version" = 9');
  definition:=replace(definition,'release."name"=''production_discovery''','release."name"=''production_risk_projection''');
  definition:=replace(replace(definition,'later."version">10','later."version">9'),'later."version" > 10','later."version" > 9');
  IF position('production-risk-projection-v1' IN definition)=0
     OR position('release."version"=9' IN replace(definition,' ',''))=0
     OR position('release."name"=''production_risk_projection''' IN replace(definition,' ',''))=0
     OR position('later."version">9' IN replace(definition,' ',''))=0 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk mutation compatibility normalization failed';
  END IF;
  EXECUTE definition;

  EXECUTE $readiness$
CREATE OR REPLACE FUNCTION "public"."zasp_discovery_readiness"(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE AS $$
 WITH semantic_objects AS (
   SELECT 'table'::text object_kind,class.relname::text object_identity,jsonb_build_object('row_security',class.relrowsecurity,'force_row_security',class.relforcerowsecurity,'persistence',class.relpersistence) definition FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p')
   UNION ALL SELECT 'column',class.relname||'.'||attribute.attnum||'.'||attribute.attname,jsonb_build_object('type',format_type(attribute.atttypid,attribute.atttypmod),'not_null',attribute.attnotnull,'default',COALESCE(regexp_replace(pg_get_expr(default_value.adbin,default_value.adrelid,true),E'\\s+',' ','g'),''),'identity',attribute.attidentity,'generated',attribute.attgenerated,'collation',CASE WHEN attribute.attcollation=0 THEN '' ELSE attribute.attcollation::regcollation::text END) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p') AND attribute.attnum>0 AND NOT attribute.attisdropped
   UNION ALL SELECT 'constraint',class.relname||'.'||constraint_value.conname,jsonb_build_object('type',constraint_value.contype,'definition',regexp_replace(pg_get_constraintdef(constraint_value.oid,true),E'\\s+',' ','g'),'deferrable',constraint_value.condeferrable,'deferred',constraint_value.condeferred,'validated',constraint_value.convalidated) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_'
   UNION ALL SELECT 'index',table_class.relname||'.'||index_class.relname,jsonb_build_object('definition',regexp_replace(pg_get_indexdef(index_value.indexrelid,0,true),E'\\s+',' ','g'),'unique',index_value.indisunique,'primary',index_value.indisprimary,'exclusion',index_value.indisexclusion,'valid',index_value.indisvalid,'ready',index_value.indisready) FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace namespace ON namespace.oid=table_class.relnamespace WHERE namespace.nspname='public' AND left(table_class.relname,5)='zasp_'
   UNION ALL SELECT 'function',procedure.proname||'('||pg_get_function_identity_arguments(procedure.oid)||')',jsonb_build_object('result',pg_get_function_result(procedure.oid),'language',language.lanname,'kind',procedure.prokind,'volatility',procedure.provolatile,'strict',procedure.proisstrict,'security_definer',procedure.prosecdef,'leakproof',procedure.proleakproof,'parallel',procedure.proparallel,'config',COALESCE(to_jsonb(procedure.proconfig),'[]'::jsonb),'body',regexp_replace(btrim(procedure.prosrc),E'\\s+',' ','g')) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_language language ON language.oid=procedure.prolang WHERE namespace.nspname='public' AND left(procedure.proname,5)='zasp_'
 ), live AS (SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(object_kind,object_identity,definition) ORDER BY object_kind,object_identity)::text,'[]'),'UTF8'),'sha256'),'hex') value FROM semantic_objects)
 SELECT EXISTS(SELECT 1 FROM zasp_schema_versions v JOIN zasp_schema_metadata m ON m.key='production_core_schema' AND m.value='production-discovery-v1' JOIN zasp_schema_metadata fingerprint ON fingerprint.key='production_discovery_fingerprint' AND fingerprint.value=expected_fingerprint CROSS JOIN live
 WHERE v.version=10 AND v.name='production_discovery' AND v.checksum=expected_checksum AND live.value=expected_fingerprint
 AND zasp_discovery_security_ready()
 AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions newer WHERE newer.version>10))
$$
$readiness$;
  EXECUTE 'REVOKE ALL ON FUNCTION zasp_discovery_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway';
  EXECUTE 'ALTER FUNCTION zasp_discovery_readiness(text,text) SECURITY DEFINER';
  EXECUTE 'ALTER FUNCTION zasp_discovery_readiness(text,text) SET search_path TO pg_catalog, public';
  EXECUTE 'ALTER FUNCTION zasp_discovery_readiness(text,text) OWNER TO zasp_discovery_authority';
  EXECUTE 'GRANT EXECUTE ON FUNCTION zasp_discovery_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway';

  DELETE FROM zasp_schema_metadata WHERE key='production_discovery_release_fingerprint';
  UPDATE zasp_schema_metadata SET value=release_fingerprint,applied_at=transaction_timestamp() WHERE key='production_discovery_fingerprint';
  IF NOT zasp_discovery_readiness(discovery_checksum,release_fingerprint) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='v10 release normalization failed';
  END IF;
END $normalize$;
