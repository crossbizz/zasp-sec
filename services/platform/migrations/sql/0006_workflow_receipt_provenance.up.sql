DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM pg_attribute AS attribute
         WHERE attribute.attrelid = 'public.zasp_workflow_idempotency'::regclass
           AND attribute.attname = 'receipt_semantics'
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'workflow receipt provenance marker unavailable';
    END IF;
END;
$$;

ALTER TABLE "public"."zasp_workflow_idempotency"
    ADD COLUMN "receipt_semantics" text NOT NULL DEFAULT 'receiptless_incompatible';

ALTER TABLE "public"."zasp_workflow_idempotency"
    ADD CONSTRAINT "zasp_workflow_idempotency_receipt_semantics_check"
    CHECK ("receipt_semantics" IN ('receiptless_incompatible', 'receipt_backed'));

UPDATE "public"."zasp_workflow_idempotency"
   SET "receipt_semantics" = 'receipt_backed'
 WHERE NULLIF("response" ->> 'receipt_id', '') IS NOT NULL;

CREATE OR REPLACE FUNCTION "public"."zasp_workflow_mutate"(
    mutation text, requested_kind text, requested_id text,
    requested_organization_id text, requested_workspace_id text, requested_environment_id text,
    requested_principal_id text, requested_operation text, requested_idempotency_key text,
    expected_version bigint, requested_intent jsonb, requested_body jsonb, requested_audit_id text,
    requested_correlation_id text, requested_receipt_id text
)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    mutation_response jsonb;
    existing_receipt_id text;
BEGIN
    LOCK TABLE "public"."zasp_workflow_idempotency" IN ROW EXCLUSIVE MODE;
    IF NOT EXISTS (
        SELECT 1
          FROM "public"."zasp_schema_versions" AS release
          JOIN "public"."zasp_schema_metadata" AS schema_marker
            ON schema_marker."key" = 'production_core_schema'
           AND schema_marker."value" = 'production-workflow-receipt-provenance-v3'
         WHERE release."version" = 6
           AND release."name" = 'workflow_receipt_provenance'
           AND NOT EXISTS (
               SELECT 1 FROM "public"."zasp_schema_versions" AS later_release
                WHERE later_release."version" > 6
           )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'workflow receipt provenance release unavailable';
    END IF;
    IF requested_receipt_id IS NOT NULL AND requested_receipt_id <> '' AND length(requested_receipt_id) > 128 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid workflow receipt';
    END IF;
    mutation_response := "public"."zasp_workflow_mutate_v3"(
        mutation, requested_kind, requested_id,
        requested_organization_id, requested_workspace_id, requested_environment_id,
        requested_principal_id, requested_operation, requested_idempotency_key,
        expected_version, requested_intent, requested_body, requested_audit_id, requested_correlation_id
    );
    existing_receipt_id := mutation_response ->> 'receipt_id';
    IF existing_receipt_id IS NOT NULL THEN
        RETURN mutation_response;
    END IF;
    IF requested_receipt_id IS NULL OR requested_receipt_id = '' THEN
        UPDATE "public"."zasp_workflow_idempotency"
           SET "receipt_semantics" = 'receiptless_incompatible'
         WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
           AND "environment_id" = requested_environment_id AND "principal_id" = requested_principal_id
           AND "operation" = requested_operation AND "idempotency_key" = requested_idempotency_key
           AND NULLIF("response" ->> 'receipt_id', '') IS NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'workflow receipt provenance marker unavailable';
        END IF;
        RETURN mutation_response;
    END IF;
    INSERT INTO "public"."zasp_workflow_receipts" (
        "organization_id", "workspace_id", "environment_id", "principal_id", "receipt_id",
        "operation", "idempotency_key", "intent", "result", "resource_kind", "resource_id",
        "resource_version", "audit_id", "correlation_id"
    ) VALUES (
        requested_organization_id, requested_workspace_id, requested_environment_id, requested_principal_id, requested_receipt_id,
        requested_operation, requested_idempotency_key, requested_intent, mutation_response -> 'body', requested_kind, requested_id,
        (mutation_response ->> 'version')::bigint, mutation_response ->> 'audit_id', mutation_response ->> 'correlation_id'
    );
    mutation_response := mutation_response || jsonb_build_object('receipt_id', requested_receipt_id);
    UPDATE "public"."zasp_workflow_idempotency"
       SET "response" = mutation_response - 'replayed',
           "receipt_semantics" = 'receipt_backed'
     WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
       AND "environment_id" = requested_environment_id AND "principal_id" = requested_principal_id
       AND "operation" = requested_operation AND "idempotency_key" = requested_idempotency_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'workflow receipt provenance marker unavailable';
    END IF;
    RETURN mutation_response;
END;
$$;

INSERT INTO "public"."zasp_schema_metadata" ("key", "value")
VALUES ('production_workflow_receipt_provenance_fingerprint', '03887e106ff49fe7bb57c4b3fe7fed53363ec5e620c42268a5b833f1659f5196');

UPDATE "public"."zasp_schema_metadata"
   SET "value" = 'production-workflow-receipt-provenance-v3', "applied_at" = transaction_timestamp()
 WHERE "key" = 'production_core_schema'
   AND "value" = 'production-workflow-receipt-safety-v2';
