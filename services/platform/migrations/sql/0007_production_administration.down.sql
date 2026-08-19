DO $rollback_guard$
DECLARE
    actual_fingerprint text;
BEGIN
    WITH semantic_objects AS (
        SELECT 'table'::text AS object_kind, class.relname::text AS object_identity,
               jsonb_build_object('row_security',class.relrowsecurity,'force_row_security',class.relforcerowsecurity,'persistence',class.relpersistence) AS definition
          FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace
         WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p')
        UNION ALL
        SELECT 'column',class.relname||'.'||attribute.attnum||'.'||attribute.attname,
               jsonb_build_object('type',format_type(attribute.atttypid,attribute.atttypmod),'not_null',attribute.attnotnull,'default',COALESCE(regexp_replace(pg_get_expr(default_value.adbin,default_value.adrelid,true),E'\\s+',' ','g'),''),'identity',attribute.attidentity,'generated',attribute.attgenerated,'collation',CASE WHEN attribute.attcollation=0 THEN '' ELSE attribute.attcollation::regcollation::text END)
          FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
         WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_' AND class.relkind IN ('r','p') AND attribute.attnum>0 AND NOT attribute.attisdropped
        UNION ALL
        SELECT 'constraint',class.relname||'.'||constraint_value.conname,jsonb_build_object('type',constraint_value.contype,'definition',regexp_replace(pg_get_constraintdef(constraint_value.oid,true),E'\\s+',' ','g'),'deferrable',constraint_value.condeferrable,'deferred',constraint_value.condeferred,'validated',constraint_value.convalidated)
          FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace
         WHERE namespace.nspname='public' AND left(class.relname,5)='zasp_'
        UNION ALL
        SELECT 'index',table_class.relname||'.'||index_class.relname,jsonb_build_object('definition',regexp_replace(pg_get_indexdef(index_value.indexrelid,0,true),E'\\s+',' ','g'),'unique',index_value.indisunique,'primary',index_value.indisprimary,'exclusion',index_value.indisexclusion,'valid',index_value.indisvalid,'ready',index_value.indisready)
          FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace namespace ON namespace.oid=table_class.relnamespace
         WHERE namespace.nspname='public' AND left(table_class.relname,5)='zasp_'
        UNION ALL
        SELECT 'function',procedure.proname||'('||pg_get_function_identity_arguments(procedure.oid)||')',jsonb_build_object('result',pg_get_function_result(procedure.oid),'language',language.lanname,'kind',procedure.prokind,'volatility',procedure.provolatile,'strict',procedure.proisstrict,'security_definer',procedure.prosecdef,'leakproof',procedure.proleakproof,'parallel',procedure.proparallel,'config',COALESCE(to_jsonb(procedure.proconfig),'[]'::jsonb),'body',regexp_replace(btrim(procedure.prosrc),E'\\s+',' ','g'))
          FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_language language ON language.oid=procedure.prolang
         WHERE namespace.nspname='public' AND left(procedure.proname,5)='zasp_'
    )
    SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(object_kind,object_identity,definition) ORDER BY object_kind,object_identity)::text,'[]'),'UTF8'),'sha256'),'hex') INTO actual_fingerprint FROM semantic_objects;
    IF actual_fingerprint <> '3d4229628c82d1a32c2cf6f31e07c233595a7568dd33c79aa22b56c2fd75b703' THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='semantic schema drift blocks rollback';
    END IF;
END;
$rollback_guard$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM "public"."zasp_group_mappings")
       OR EXISTS (SELECT 1 FROM "public"."zasp_admin_idempotency")
       OR EXISTS (SELECT 1 FROM "public"."zasp_admin_audit")
       OR EXISTS (SELECT 1 FROM "public"."zasp_session_events")
       OR EXISTS (SELECT 1 FROM "public"."zasp_product_api_tokens" WHERE NOT "migration_seeded")
       OR EXISTS (SELECT 1 FROM "public"."zasp_organizations" WHERE NOT "migration_seeded")
       OR EXISTS (SELECT 1 FROM "public"."zasp_workspaces" WHERE NOT "migration_seeded")
       OR EXISTS (SELECT 1 FROM "public"."zasp_environments" WHERE NOT "migration_seeded")
       OR EXISTS (SELECT 1 FROM "public"."zasp_compliance_controls" WHERE NOT "migration_seeded")
       OR EXISTS (SELECT 1 FROM "public"."zasp_compliance_evidence" WHERE NOT "migration_seeded")
       OR EXISTS (SELECT 1 FROM "public"."zasp_data_controls" WHERE NOT "migration_seeded") THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'production administration data blocks rollback';
    END IF;
END;
$$;

UPDATE "public"."zasp_schema_metadata"
SET "value" = 'production-workflow-receipt-provenance-v3', "applied_at" = transaction_timestamp()
WHERE "key" = 'production_core_schema' AND "value" = 'production-administration-v1';

DELETE FROM "public"."zasp_schema_metadata" WHERE "key" = 'production_administration_fingerprint';

DO $migration$
DECLARE
    definition text;
BEGIN
    SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure)
      INTO definition;
    definition := replace(definition, 'production-administration-v1', 'production-workflow-receipt-provenance-v3');
    definition := replace(definition, 'release."version" = 7', 'release."version" = 6');
    definition := replace(definition, 'release."name" = ''production_administration''', 'release."name" = ''workflow_receipt_provenance''');
    definition := replace(definition, 'later_release."version" > 7', 'later_release."version" > 6');
    EXECUTE definition;
END;
$migration$;

CREATE OR REPLACE FUNCTION "public"."zasp_effective_scope_permissions"(requested_permissions jsonb, requested_role text)
RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
    SELECT COALESCE(jsonb_agg(permission ORDER BY permission), '[]'::jsonb)
      FROM jsonb_array_elements_text(requested_permissions) AS permission
     WHERE permission = 'view'
        OR permission = 'manage_workflows' AND requested_role IN ('organization_admin', 'security_admin', 'security_engineer')
$$;

DROP TABLE "public"."zasp_data_controls";
DROP TABLE "public"."zasp_compliance_evidence";
DROP TABLE "public"."zasp_compliance_controls";
DROP TABLE "public"."zasp_session_events";
DROP TABLE "public"."zasp_admin_audit";
DROP TABLE "public"."zasp_admin_idempotency";
DROP TABLE "public"."zasp_group_mappings";
DROP TABLE "public"."zasp_environments";
DROP TABLE "public"."zasp_workspaces";
DROP TABLE "public"."zasp_organizations";

ALTER TABLE "public"."zasp_product_api_tokens"
DROP CONSTRAINT "zasp_product_api_tokens_audit_id_check",
DROP CONSTRAINT "zasp_product_api_tokens_name_check",
DROP CONSTRAINT "zasp_product_api_tokens_id_check",
DROP CONSTRAINT "zasp_product_api_tokens_id_key",
DROP COLUMN "migration_seeded",
DROP COLUMN "audit_correlation_id",
DROP COLUMN "version",
DROP COLUMN "last_used_at",
DROP COLUMN "created_at",
DROP COLUMN "name",
DROP COLUMN "id";

ALTER TABLE "public"."zasp_product_sessions"
DROP CONSTRAINT "zasp_product_sessions_session_id_check",
DROP CONSTRAINT "zasp_product_sessions_session_id_key",
DROP COLUMN "version",
DROP COLUMN "session_id";

ALTER TABLE "public"."zasp_identity_memberships"
DROP CONSTRAINT "zasp_identity_memberships_role_check",
DROP COLUMN "version";
