CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE "public"."zasp_schema_metadata" (
    "key" text PRIMARY KEY,
    "value" text NOT NULL,
    "applied_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp()
);

INSERT INTO "public"."zasp_schema_metadata" ("key", "value")
VALUES ('production_core_schema', 'production-core-v1');

CREATE TABLE "public"."zasp_product_sessions" (
    "token_digest" bytea PRIMARY KEY,
    "principal_id" text NOT NULL,
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "csrf_token" text NOT NULL,
    "expires_at" timestamp with time zone NOT NULL,
    "revoked_at" timestamp with time zone
);

CREATE INDEX "zasp_product_sessions_scope_idx"
ON "public"."zasp_product_sessions" ("organization_id", "workspace_id", "environment_id", "principal_id");

CREATE TABLE "public"."zasp_core_payloads" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "operation" text NOT NULL,
    "payload" jsonb NOT NULL CHECK (jsonb_typeof("payload") = 'object'),
    "updated_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "operation")
);

CREATE FUNCTION "public"."zasp_session_bootstrap"(principal text, organization_id text, workspace_id text, environment_id text)
RETURNS jsonb
LANGUAGE sql
STABLE
AS $$
    SELECT payload
    FROM "public"."zasp_core_payloads"
    WHERE "organization_id" = zasp_session_bootstrap.organization_id
      AND "workspace_id" = zasp_session_bootstrap.workspace_id
      AND "environment_id" = zasp_session_bootstrap.environment_id
      AND "operation" = 'session_bootstrap:' || principal
$$;

CREATE FUNCTION "public"."zasp_core_read"(operation text, organization_id text, workspace_id text, environment_id text)
RETURNS jsonb
LANGUAGE sql
STABLE
AS $$
    SELECT payload
    FROM "public"."zasp_core_payloads"
    WHERE "organization_id" = zasp_core_read.organization_id
      AND "workspace_id" = zasp_core_read.workspace_id
      AND "environment_id" = zasp_core_read.environment_id
      AND "operation" = zasp_core_read.operation
$$;

CREATE FUNCTION "public"."zasp_core_write"(operation text, organization_id text, workspace_id text, environment_id text, input jsonb)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    updated jsonb;
    finding_id text;
BEGIN
    IF operation !~ '^finding:pid_[0-9a-f-]+$' OR input->>'status' NOT IN ('open', 'under_review', 'resolved') THEN
        RAISE EXCEPTION 'unsupported production core mutation';
    END IF;
    finding_id := split_part(operation, ':', 2);
    UPDATE "public"."zasp_core_payloads"
       SET "payload" = jsonb_set("payload", '{status}', to_jsonb(input->>'status'), false),
           "updated_at" = transaction_timestamp()
     WHERE "organization_id" = zasp_core_write.organization_id
       AND "workspace_id" = zasp_core_write.workspace_id
       AND "environment_id" = zasp_core_write.environment_id
       AND "operation" = zasp_core_write.operation
     RETURNING "payload" INTO updated;
    IF updated IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE "public"."zasp_core_payloads"
       SET "payload" = jsonb_set("payload", '{items}', (
               SELECT COALESCE(jsonb_agg(CASE WHEN item->>'id' = finding_id THEN updated ELSE item END), '[]'::jsonb)
               FROM jsonb_array_elements("payload"->'items') AS item
           ), false),
           "updated_at" = transaction_timestamp()
     WHERE "organization_id" = zasp_core_write.organization_id
       AND "workspace_id" = zasp_core_write.workspace_id
       AND "environment_id" = zasp_core_write.environment_id
       AND "operation" = 'findings';
    RETURN updated;
END;
$$;
