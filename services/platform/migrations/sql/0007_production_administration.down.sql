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
