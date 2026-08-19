UPDATE "public"."zasp_schema_metadata" SET "value" = 'production-workflows-v1', "applied_at" = transaction_timestamp()
WHERE "key" = 'production_core_schema' AND "value" = 'production-workflow-receipts-v1';
DELETE FROM "public"."zasp_schema_metadata" WHERE "key" = 'production_workflow_receipts_fingerprint';
DROP FUNCTION "public"."zasp_workflow_receipt_acknowledge"(text, text, text, text, text);
DROP FUNCTION "public"."zasp_workflow_receipt_list"(text, text, text, text, integer);
DROP FUNCTION "public"."zasp_workflow_mutate"(text, text, text, text, text, text, text, text, text, bigint, jsonb, jsonb, text, text, text);
DROP TABLE "public"."zasp_workflow_receipts";
ALTER FUNCTION "public"."zasp_workflow_mutate_v3"(text, text, text, text, text, text, text, text, text, bigint, jsonb, jsonb, text, text)
RENAME TO "zasp_workflow_mutate";
