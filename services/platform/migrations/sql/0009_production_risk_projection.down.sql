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
    IF actual_fingerprint<>'d5999a521fa7cef426fcc096b3d7f66b32e3ad6b22f864c59d326ac14849fc74' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='semantic schema drift blocks rollback'; END IF;
END;
$rollback_guard$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM "public"."zasp_risk_findings") OR EXISTS (SELECT 1 FROM "public"."zasp_risk_attack_paths")
       OR EXISTS (SELECT 1 FROM "public"."zasp_workflow_idempotency" WHERE "operation" IN ('updateFinding','acceptFindingRisk'))
       OR EXISTS (SELECT 1 FROM "public"."zasp_workflow_audit" WHERE "operation" IN ('updateFinding','acceptFindingRisk'))
       OR EXISTS (SELECT 1 FROM "public"."zasp_workflow_receipts" WHERE "resource_kind"='finding') THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk projection data blocks rollback';
    END IF;
END;
$$;

UPDATE "public"."zasp_schema_metadata" SET "value"='api-token-reveal-grants-v1',"applied_at"=transaction_timestamp()
WHERE "key"='production_core_schema' AND "value"='production-risk-projection-v1';
DELETE FROM "public"."zasp_schema_metadata" WHERE "key"='production_risk_projection_fingerprint';

DO $migration$
DECLARE definition text;
BEGIN
    SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;
    definition:=replace(definition,'production-risk-projection-v1','api-token-reveal-grants-v1');
    definition:=replace(definition,'release."version" = 9','release."version" = 8');
    definition:=replace(definition,'release."name" = ''production_risk_projection''','release."name" = ''api_token_reveal_grants''');
    definition:=replace(definition,'later_release."version" > 9','later_release."version" > 8');
    EXECUTE definition;
END;
$migration$;

DROP FUNCTION "public"."zasp_risk_mutate"(text,text,text,text,text,text,text,bigint,text,text,text,text,text);
DROP FUNCTION "public"."zasp_risk_high_path_count"(text,text,text);
DROP FUNCTION "public"."zasp_risk_break_options_get"(text,text,text,text);
DROP FUNCTION "public"."zasp_risk_attack_path_page"(text,text,text,text,integer);
DROP FUNCTION "public"."zasp_risk_attack_path_get"(text,text,text,text);
DROP FUNCTION "public"."zasp_risk_attack_path_valid"("public"."zasp_risk_attack_paths");
DROP FUNCTION "public"."zasp_risk_finding_page"(text,text,text,text,integer);
DROP FUNCTION "public"."zasp_risk_finding_get"(text,text,text,text);
DROP FUNCTION "public"."zasp_risk_finding_visible"("public"."zasp_risk_findings");

ALTER TABLE "public"."zasp_workflow_receipts" DROP CONSTRAINT "zasp_workflow_receipts_resource_kind_check";
ALTER TABLE "public"."zasp_workflow_receipts" ADD CONSTRAINT "zasp_workflow_receipts_resource_kind_check"
CHECK ("resource_kind" IN ('policy', 'integration', 'sensor', 'security_agent', 'security_agent_run', 'security_agent_approval'));

DROP TABLE "public"."zasp_risk_break_options";
DROP TABLE "public"."zasp_risk_attack_path_evidence";
DROP TABLE "public"."zasp_risk_attack_path_nodes";
DROP TABLE "public"."zasp_risk_attack_paths";
DROP TABLE "public"."zasp_risk_finding_factors";
DROP TABLE "public"."zasp_risk_finding_evidence";
DROP TABLE "public"."zasp_risk_findings";
