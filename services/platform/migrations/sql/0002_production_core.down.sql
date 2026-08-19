DROP FUNCTION "public"."zasp_core_write"(text, text, text, text, jsonb);
DROP FUNCTION "public"."zasp_core_read"(text, text, text, text);
DROP FUNCTION "public"."zasp_session_bootstrap"(text, text, text, text);
DROP FUNCTION "public"."zasp_create_product_session"(text, text, text, text, text, text, jsonb, timestamp with time zone);
DROP TABLE "public"."zasp_core_payloads";
DROP TABLE "public"."zasp_product_api_tokens";
DROP TABLE "public"."zasp_product_sessions";
DROP TABLE "public"."zasp_schema_metadata";
