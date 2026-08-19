DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM "public"."zasp_api_token_reveal_grants")
       OR EXISTS (SELECT 1 FROM "public"."zasp_admin_idempotency" WHERE "grant_id" IS NOT NULL OR "response" IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'API token reveal grant data blocks rollback';
    END IF;
END;
$$;

UPDATE "public"."zasp_schema_metadata"
SET "value" = 'production-administration-v1', "applied_at" = transaction_timestamp()
WHERE "key" = 'production_core_schema' AND "value" = 'api-token-reveal-grants-v1';

DELETE FROM "public"."zasp_schema_metadata" WHERE "key" = 'api_token_reveal_grants_fingerprint';

DO $migration$
DECLARE
    definition text;
BEGIN
    SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure)
      INTO definition;
    definition := replace(definition, 'api-token-reveal-grants-v1', 'production-administration-v1');
    definition := replace(definition, 'release."version" = 8', 'release."version" = 7');
    definition := replace(definition, 'release."name" = ''api_token_reveal_grants''', 'release."name" = ''production_administration''');
    definition := replace(definition, 'later_release."version" > 8', 'later_release."version" > 7');
    EXECUTE definition;
END;
$migration$;

DROP INDEX "public"."zasp_compliance_controls_keyset_idx";
DROP INDEX "public"."zasp_product_sessions_keyset_idx";
DROP INDEX "public"."zasp_product_api_tokens_keyset_idx";
DROP INDEX "public"."zasp_identity_memberships_keyset_idx";
DROP INDEX "public"."zasp_environments_keyset_idx";
DROP INDEX "public"."zasp_workspaces_keyset_idx";
DROP TABLE "public"."zasp_api_token_reveal_grants";

ALTER TABLE "public"."zasp_admin_idempotency"
DROP COLUMN "response",
DROP COLUMN "grant_id",
DROP COLUMN "environment_id",
DROP COLUMN "workspace_id";
