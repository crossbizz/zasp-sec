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
           AND schema_marker."value" = 'production-workflow-receipt-safety-v2'
         WHERE release."version" = 5
           AND release."name" = 'workflow_receipt_safety'
           AND NOT EXISTS (
               SELECT 1 FROM "public"."zasp_schema_versions" AS later_release
                WHERE later_release."version" > 5
           )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'workflow receipt safety release unavailable';
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
    IF existing_receipt_id IS NOT NULL OR requested_receipt_id IS NULL OR requested_receipt_id = '' THEN
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
       SET "response" = mutation_response - 'replayed'
     WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
       AND "environment_id" = requested_environment_id AND "principal_id" = requested_principal_id
       AND "operation" = requested_operation AND "idempotency_key" = requested_idempotency_key;
    RETURN mutation_response;
END;
$$;

CREATE OR REPLACE FUNCTION "public"."zasp_workflow_receipt_list"(
    requested_organization_id text, requested_workspace_id text, requested_environment_id text,
    requested_principal_id text, requested_limit integer DEFAULT 20
)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    response jsonb;
BEGIN
    IF requested_limit < 1 OR requested_limit > 50 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid workflow receipt list';
    END IF;
    SELECT jsonb_build_object('items', COALESCE(jsonb_agg(jsonb_build_object(
        'id', "receipt_id", 'operation', "operation", 'idempotency_key', "idempotency_key",
        'intent', "intent", 'result', "result", 'resource_kind', "resource_kind", 'resource_id', "resource_id",
        'resource_version', "resource_version", 'audit_id', "audit_id", 'correlation_id', "correlation_id",
        'created_at', "created_at", 'expires_at', "expires_at"
    ) ORDER BY "created_at", "receipt_id"), '[]'::jsonb)) INTO response
      FROM (
        SELECT * FROM "public"."zasp_workflow_receipts"
         WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
           AND "environment_id" = requested_environment_id AND "principal_id" = requested_principal_id
           AND "acknowledged_at" IS NULL AND "expires_at" > transaction_timestamp()
         ORDER BY "created_at", "receipt_id" LIMIT requested_limit
      ) AS visible;
    RETURN response;
END;
$$;

CREATE FUNCTION "public"."zasp_workflow_receipt_cleanup"(requested_limit integer DEFAULT 1000)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    deleted_count integer;
BEGIN
    IF requested_limit < 1 OR requested_limit > 1000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid workflow receipt cleanup';
    END IF;
    WITH expired AS (
        SELECT ctid FROM "public"."zasp_workflow_receipts"
         WHERE "expires_at" <= transaction_timestamp()
         ORDER BY "expires_at", "receipt_id"
         LIMIT requested_limit
         FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM "public"."zasp_workflow_receipts" AS receipt
         USING expired
         WHERE receipt.ctid = expired.ctid
         RETURNING 1
    )
    SELECT count(*)::integer INTO deleted_count FROM deleted;
    RETURN jsonb_build_object('deleted', deleted_count);
END;
$$;

INSERT INTO "public"."zasp_schema_metadata" ("key", "value")
VALUES ('production_workflow_receipt_safety_fingerprint', '5054e88fa5d21a4848be0c27754e61875720f88bc5437a85aca1d2dd7536ca2b');

UPDATE "public"."zasp_schema_metadata" SET "value" = 'production-workflow-receipt-safety-v2', "applied_at" = transaction_timestamp()
WHERE "key" = 'production_core_schema' AND "value" = 'production-workflow-receipts-v1';
