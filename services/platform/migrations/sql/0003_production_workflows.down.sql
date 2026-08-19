UPDATE "public"."zasp_schema_metadata" SET "value" = 'production-core-v1', "applied_at" = transaction_timestamp()
WHERE "key" = 'production_core_schema' AND "value" = 'production-workflows-v1';
DROP FUNCTION "public"."zasp_workflow_mutate"(text, text, text, text, text, text, text, text, text, bigint, jsonb, jsonb, text, text);
DROP FUNCTION "public"."zasp_workflow_replay"(text, text, text, text, text, text, jsonb);
DROP FUNCTION "public"."zasp_workflow_get"(text, text, text, text, text);
DROP FUNCTION "public"."zasp_workflow_list"(text, text, text, text, text, text);
DROP TABLE "public"."zasp_workflow_audit";
DROP TABLE "public"."zasp_workflow_idempotency";
DROP TABLE "public"."zasp_workflow_records";
ALTER TABLE "public"."zasp_product_sessions" DROP COLUMN "authenticated_at";
DROP FUNCTION "public"."zasp_effective_scope_permissions"(jsonb, text);
