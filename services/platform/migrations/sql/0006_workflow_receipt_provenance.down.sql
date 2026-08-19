DO $$
DECLARE
    marker_columns integer;
    marker_constraints integer;
BEGIN
    SELECT count(*) INTO marker_columns
      FROM pg_attribute AS attribute
      JOIN pg_attrdef AS default_value
        ON default_value.adrelid = attribute.attrelid
       AND default_value.adnum = attribute.attnum
     WHERE attribute.attrelid = 'public.zasp_workflow_idempotency'::regclass
       AND attribute.attname = 'receipt_semantics'
       AND attribute.attnum > 0
       AND NOT attribute.attisdropped
       AND attribute.attnotnull
       AND format_type(attribute.atttypid, attribute.atttypmod) = 'text'
       AND pg_get_expr(default_value.adbin, default_value.adrelid, true) = '''receiptless_incompatible''::text';
    SELECT count(*) INTO marker_constraints
      FROM pg_constraint AS constraint_value
     WHERE constraint_value.conrelid = 'public.zasp_workflow_idempotency'::regclass
       AND constraint_value.conname = 'zasp_workflow_idempotency_receipt_semantics_check'
       AND constraint_value.contype = 'c'
       AND constraint_value.convalidated
       AND pg_get_constraintdef(constraint_value.oid, true) = 'CHECK (receipt_semantics = ANY (ARRAY[''receiptless_incompatible''::text, ''receipt_backed''::text]))';
    IF marker_columns <> 1 OR marker_constraints <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'workflow receipt provenance marker unavailable';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM "public"."zasp_workflow_idempotency"
         WHERE "receipt_semantics" <> 'receipt_backed'
            OR NULLIF("response" ->> 'receipt_id', '') IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'workflow receipt provenance rollback blocked';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION "public"."zasp_workflow_mutate"(
    mutation text, requested_kind text, requested_id text,
    requested_organization_id text, requested_workspace_id text, requested_environment_id text,
    requested_principal_id text, requested_operation text, requested_idempotency_key text,
    expected_version bigint, requested_intent jsonb, requested_body jsonb, requested_audit_id text,
    requested_correlation_id text, requested_receipt_id text
)
RETURNS jsonb LANGUAGE plpgsql AS $$
BEGIN
    LOCK TABLE "public"."zasp_workflow_idempotency" IN ROW EXCLUSIVE MODE;
    IF NOT EXISTS (
        SELECT 1
          FROM "public"."zasp_schema_versions" AS release
          JOIN "public"."zasp_schema_metadata" AS schema_marker
            ON schema_marker."key" = 'production_core_schema'
           AND schema_marker."value" = 'production-workflow-receipt-safety-v2'
         WHERE release."version" = 5
           AND release."name" = 'workflow_receipt_safety'
           AND NOT EXISTS (
               SELECT 1 FROM "public"."zasp_schema_versions" AS later_release
                WHERE later_release."version" > 5
           )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'workflow receipt provenance release unavailable';
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'workflow mutations unavailable at intermediate receipt provenance downgrade';
END;
$$;

ALTER TABLE "public"."zasp_workflow_idempotency"
    DROP COLUMN "receipt_semantics";

DELETE FROM "public"."zasp_schema_metadata"
 WHERE "key" = 'production_workflow_receipt_provenance_fingerprint';

UPDATE "public"."zasp_schema_metadata"
   SET "value" = 'production-workflow-receipt-safety-v2', "applied_at" = transaction_timestamp()
 WHERE "key" = 'production_core_schema'
   AND "value" = 'production-workflow-receipt-provenance-v3';
