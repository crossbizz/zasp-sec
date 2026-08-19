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
	"permissions" jsonb NOT NULL CHECK (jsonb_typeof("permissions") = 'array'),
    "csrf_token" text NOT NULL,
    "expires_at" timestamp with time zone NOT NULL,
    "revoked_at" timestamp with time zone
);

CREATE INDEX "zasp_product_sessions_scope_idx"
ON "public"."zasp_product_sessions" ("organization_id", "workspace_id", "environment_id", "principal_id");

CREATE TABLE "public"."zasp_authorized_scopes" (
    "principal_id" text NOT NULL,
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "label" text NOT NULL CHECK (char_length("label") BETWEEN 1 AND 128),
    "permissions" jsonb NOT NULL CHECK (jsonb_typeof("permissions") = 'array'),
	"is_default" boolean NOT NULL DEFAULT false,
    PRIMARY KEY ("principal_id", "organization_id", "workspace_id", "environment_id")
);

CREATE UNIQUE INDEX "zasp_authorized_scopes_default_idx"
ON "public"."zasp_authorized_scopes" ("principal_id", "organization_id") WHERE "is_default";

CREATE TABLE "public"."zasp_identity_memberships" (
    "principal_id" text NOT NULL,
    "organization_id" text NOT NULL,
    "organization_reference" text NOT NULL,
    "member_reference" text NOT NULL,
    "role" text NOT NULL,
    "active" boolean NOT NULL DEFAULT true,
    PRIMARY KEY ("organization_reference", "member_reference"),
    UNIQUE ("principal_id", "organization_id")
);

CREATE TABLE "public"."zasp_identity_states" (
    "state_digest" bytea PRIMARY KEY,
    "return_path" text NOT NULL CHECK (char_length("return_path") BETWEEN 1 AND 2048),
    "expires_at" timestamp with time zone NOT NULL,
    "consumed_at" timestamp with time zone
);

CREATE TABLE "public"."zasp_product_api_tokens" (
    "token_digest" bytea PRIMARY KEY,
    "principal_id" text NOT NULL,
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "permissions" jsonb NOT NULL CHECK (jsonb_typeof("permissions") = 'array'),
    "expires_at" timestamp with time zone NOT NULL,
    "revoked_at" timestamp with time zone
);

CREATE INDEX "zasp_product_api_tokens_scope_idx"
ON "public"."zasp_product_api_tokens" ("organization_id", "workspace_id", "environment_id", "principal_id");

CREATE TABLE "public"."zasp_core_payloads" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "operation" text NOT NULL,
    "payload" jsonb NOT NULL CHECK (jsonb_typeof("payload") = 'object'),
    "updated_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "operation")
);

CREATE FUNCTION "public"."zasp_create_product_session"(
    raw_token text,
    new_csrf_token text,
    new_principal_id text,
    new_organization_id text,
    new_workspace_id text,
    new_environment_id text,
    new_permissions jsonb,
    new_expires_at timestamp with time zone
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    created jsonb;
BEGIN
    IF length(raw_token) < 32 OR length(new_csrf_token) < 32 OR
       jsonb_typeof(new_permissions) <> 'array' OR
       new_expires_at <= transaction_timestamp() OR
       new_expires_at > transaction_timestamp() + interval '24 hours' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid product session';
    END IF;
    UPDATE "public"."zasp_product_sessions"
       SET "revoked_at" = transaction_timestamp()
     WHERE "principal_id" = new_principal_id
       AND "organization_id" = new_organization_id
       AND "revoked_at" IS NULL;
    INSERT INTO "public"."zasp_product_sessions" (
        "token_digest", "principal_id", "organization_id", "workspace_id", "environment_id", "permissions", "csrf_token", "expires_at"
    ) VALUES (
        digest(raw_token, 'sha256'), new_principal_id, new_organization_id, new_workspace_id, new_environment_id, new_permissions, new_csrf_token, new_expires_at
    ) RETURNING jsonb_build_object(
        'principal_id', "principal_id",
        'organization_id', "organization_id",
        'workspace_id', "workspace_id",
        'environment_id', "environment_id",
        'permissions', "permissions",
        'csrf_token', "csrf_token"
    ) INTO created;
    RETURN created;
END;
$$;

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
