ALTER TABLE "public"."zasp_admin_idempotency"
ADD COLUMN "workspace_id" text,
ADD COLUMN "environment_id" text,
ADD COLUMN "grant_id" text,
ADD COLUMN "response" jsonb;

CREATE TABLE "public"."zasp_api_token_reveal_grants" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "principal_id" text NOT NULL,
    "token_id" text NOT NULL,
    "grant_id" text NOT NULL,
    "operation" text NOT NULL CHECK ("operation" IN ('createAPIToken', 'rotateAPIToken')),
    "ciphertext" bytea,
    "nonce" bytea,
    "authentication_tag" bytea,
    "expires_at" timestamp with time zone NOT NULL,
    "acknowledged_at" timestamp with time zone,
    "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "grant_id"),
    UNIQUE ("organization_id", "token_id", "grant_id"),
    CHECK ("grant_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CHECK ("token_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CHECK (("acknowledged_at" IS NULL AND "ciphertext" IS NOT NULL AND octet_length("ciphertext") > 0 AND "nonce" IS NOT NULL AND octet_length("nonce") = 12 AND "authentication_tag" IS NOT NULL AND octet_length("authentication_tag") = 16)
        OR ("acknowledged_at" IS NOT NULL AND "ciphertext" IS NULL AND "nonce" IS NULL AND "authentication_tag" IS NULL))
);

CREATE INDEX "zasp_api_token_reveal_grants_pending_idx"
ON "public"."zasp_api_token_reveal_grants" ("organization_id", "workspace_id", "environment_id", "principal_id", "grant_id")
WHERE "acknowledged_at" IS NULL;

CREATE INDEX "zasp_workspaces_keyset_idx"
ON "public"."zasp_workspaces" ("organization_id", "id");

CREATE INDEX "zasp_environments_keyset_idx"
ON "public"."zasp_environments" ("organization_id", "workspace_id", "id");

CREATE INDEX "zasp_identity_memberships_keyset_idx"
ON "public"."zasp_identity_memberships" ("organization_id", "principal_id");

CREATE INDEX "zasp_product_api_tokens_keyset_idx"
ON "public"."zasp_product_api_tokens" ("organization_id", "workspace_id", "environment_id", "id");

CREATE INDEX "zasp_product_sessions_keyset_idx"
ON "public"."zasp_product_sessions" ("organization_id", "workspace_id", "environment_id", "session_id");

CREATE INDEX "zasp_compliance_controls_keyset_idx"
ON "public"."zasp_compliance_controls" ("organization_id", "id");

DO $migration$
DECLARE
    definition text;
BEGIN
    SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure)
      INTO definition;
    definition := replace(definition, 'production-administration-v1', 'api-token-reveal-grants-v1');
    definition := replace(definition, 'release."version" = 7', 'release."version" = 8');
    definition := replace(definition, 'release."name" = ''production_administration''', 'release."name" = ''api_token_reveal_grants''');
    definition := replace(definition, 'later_release."version" > 7', 'later_release."version" > 8');
    EXECUTE definition;
END;
$migration$;

INSERT INTO "public"."zasp_schema_metadata" ("key", "value")
VALUES ('api_token_reveal_grants_fingerprint', 'fdb58d2205257c76dd5c7c12c28002d4d17ee62350b9a862585ee8f19f466be3');

UPDATE "public"."zasp_schema_metadata"
SET "value" = 'api-token-reveal-grants-v1', "applied_at" = transaction_timestamp()
WHERE "key" = 'production_core_schema' AND "value" = 'production-administration-v1';
