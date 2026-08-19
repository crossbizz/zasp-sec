ALTER TABLE "public"."zasp_identity_memberships"
ADD COLUMN "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0),
ADD CONSTRAINT "zasp_identity_memberships_role_check" CHECK ("role" IN ('organization_admin', 'security_admin', 'security_engineer', 'developer_owner', 'compliance_viewer', 'read_only_viewer'));

ALTER TABLE "public"."zasp_product_sessions"
ADD COLUMN "session_id" text,
ADD COLUMN "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0);

UPDATE "public"."zasp_product_sessions"
SET "session_id" = 'session-' || replace(gen_random_uuid()::text, '-', '')
WHERE "session_id" IS NULL;

ALTER TABLE "public"."zasp_product_sessions"
ALTER COLUMN "session_id" SET NOT NULL,
ALTER COLUMN "session_id" SET DEFAULT ('session-' || replace(gen_random_uuid()::text, '-', '')),
ADD CONSTRAINT "zasp_product_sessions_session_id_key" UNIQUE ("session_id"),
ADD CONSTRAINT "zasp_product_sessions_session_id_check" CHECK ("session_id" ~ '^session-[a-z0-9][a-z0-9-]*$');

ALTER TABLE "public"."zasp_product_api_tokens"
ADD COLUMN "id" text,
ADD COLUMN "name" text,
ADD COLUMN "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
ADD COLUMN "last_used_at" timestamp with time zone,
ADD COLUMN "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0),
ADD COLUMN "audit_correlation_id" text,
ADD COLUMN "migration_seeded" boolean NOT NULL DEFAULT false;

UPDATE "public"."zasp_product_api_tokens"
SET "id" = 'pid_' || gen_random_uuid()::text,
    "name" = 'Imported token',
    "audit_correlation_id" = 'pid_' || gen_random_uuid()::text,
    "migration_seeded" = true
WHERE "id" IS NULL;

ALTER TABLE "public"."zasp_product_api_tokens"
ALTER COLUMN "id" SET NOT NULL,
ALTER COLUMN "id" SET DEFAULT ('pid_' || gen_random_uuid()::text),
ALTER COLUMN "name" SET NOT NULL,
ALTER COLUMN "name" SET DEFAULT 'API token',
ALTER COLUMN "audit_correlation_id" SET NOT NULL,
ALTER COLUMN "audit_correlation_id" SET DEFAULT ('pid_' || gen_random_uuid()::text),
ADD CONSTRAINT "zasp_product_api_tokens_id_key" UNIQUE ("id"),
ADD CONSTRAINT "zasp_product_api_tokens_id_check" CHECK ("id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
ADD CONSTRAINT "zasp_product_api_tokens_name_check" CHECK (char_length("name") BETWEEN 1 AND 128),
ADD CONSTRAINT "zasp_product_api_tokens_audit_id_check" CHECK ("audit_correlation_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TABLE "public"."zasp_organizations" (
    "id" text PRIMARY KEY,
    "name" text NOT NULL CHECK (char_length("name") BETWEEN 1 AND 128),
    "domain" text NOT NULL CHECK (char_length("domain") BETWEEN 3 AND 253),
    "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0),
    "migration_seeded" boolean NOT NULL DEFAULT false,
    "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp()
);

INSERT INTO "public"."zasp_organizations" ("id", "name", "domain", "migration_seeded")
SELECT DISTINCT "organization_id", "organization_reference", lower(replace("organization_reference", '_', '-')) || '.invalid', true
FROM "public"."zasp_identity_memberships";

CREATE TABLE "public"."zasp_workspaces" (
    "id" text NOT NULL,
    "organization_id" text NOT NULL,
    "name" text NOT NULL CHECK (char_length("name") BETWEEN 1 AND 128),
    "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0),
    "migration_seeded" boolean NOT NULL DEFAULT false,
    "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "id"),
    UNIQUE ("organization_id", "name")
);

INSERT INTO "public"."zasp_workspaces" ("id", "organization_id", "name", "migration_seeded")
SELECT "workspace_id", "organization_id", min("label"), true
FROM "public"."zasp_authorized_scopes"
GROUP BY "workspace_id", "organization_id";

CREATE TABLE "public"."zasp_environments" (
    "id" text NOT NULL,
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "name" text NOT NULL CHECK (char_length("name") BETWEEN 1 AND 128),
    "environment_class" text NOT NULL CHECK ("environment_class" IN ('development', 'test', 'staging', 'production')),
    "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0),
    "migration_seeded" boolean NOT NULL DEFAULT false,
    "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "workspace_id", "id"),
    UNIQUE ("organization_id", "workspace_id", "name")
);

INSERT INTO "public"."zasp_environments" ("id", "organization_id", "workspace_id", "name", "environment_class", "migration_seeded")
SELECT "environment_id", "organization_id", "workspace_id", "label",
       CASE WHEN lower("label") IN ('development', 'test', 'staging', 'production') THEN lower("label") ELSE 'production' END,
       true
FROM "public"."zasp_authorized_scopes";

CREATE TABLE "public"."zasp_group_mappings" (
    "organization_id" text NOT NULL,
    "group_reference" text NOT NULL CHECK ("group_reference" ~ '^idp-group-[A-Za-z0-9_-]+$'),
    "role" text NOT NULL CHECK ("role" IN ('organization_admin', 'security_admin', 'security_engineer', 'developer_owner', 'compliance_viewer', 'read_only_viewer')),
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0),
    "updated_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "group_reference")
);

CREATE TABLE "public"."zasp_admin_idempotency" (
    "organization_id" text NOT NULL,
    "principal_id" text NOT NULL,
    "operation" text NOT NULL CHECK ("operation" IN ('createAPIToken', 'rotateAPIToken')),
    "idempotency_key" text NOT NULL CHECK (char_length("idempotency_key") BETWEEN 16 AND 128),
    "request_digest" bytea NOT NULL CHECK (octet_length("request_digest") = 32),
    "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "principal_id", "operation", "idempotency_key")
);

CREATE TABLE "public"."zasp_admin_audit" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "id" text NOT NULL,
    "actor_id" text NOT NULL,
    "action" text NOT NULL CHECK (char_length("action") BETWEEN 1 AND 128),
    "target_id" text NOT NULL CHECK (char_length("target_id") BETWEEN 1 AND 128),
    "outcome" text NOT NULL CHECK ("outcome" IN ('succeeded', 'rejected')),
    "metadata" jsonb NOT NULL CHECK (jsonb_typeof("metadata") = 'object'),
    "occurred_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "id")
);

CREATE INDEX "zasp_admin_audit_scope_time_idx"
ON "public"."zasp_admin_audit" ("organization_id", "workspace_id", "environment_id", "occurred_at" DESC, "id" DESC);

CREATE TABLE "public"."zasp_session_events" (
    "organization_id" text NOT NULL,
    "session_id" text NOT NULL,
    "id" text NOT NULL,
    "class" text NOT NULL CHECK ("class" IN ('tool', 'runtime', 'network', 'file', 'credential', 'policy')),
    "label" text NOT NULL CHECK (char_length("label") BETWEEN 1 AND 256),
    "evidence_id" text NOT NULL CHECK (char_length("evidence_id") BETWEEN 1 AND 128),
    "source" text NOT NULL CHECK (char_length("source") BETWEEN 1 AND 64),
    "confidence" text NOT NULL CHECK ("confidence" IN ('exact', 'strong', 'probable', 'unattributed')),
    "at" timestamp with time zone NOT NULL,
    PRIMARY KEY ("organization_id", "session_id", "id")
);

CREATE INDEX "zasp_session_events_order_idx"
ON "public"."zasp_session_events" ("organization_id", "session_id", "at", "id");

CREATE TABLE "public"."zasp_compliance_controls" (
    "organization_id" text NOT NULL,
    "id" text NOT NULL,
    "framework" text NOT NULL CHECK (char_length("framework") BETWEEN 1 AND 64),
    "name" text NOT NULL CHECK (char_length("name") BETWEEN 1 AND 256),
    "fresh_until" timestamp with time zone NOT NULL,
    "migration_seeded" boolean NOT NULL DEFAULT false,
    PRIMARY KEY ("organization_id", "id")
);

CREATE TABLE "public"."zasp_compliance_evidence" (
    "organization_id" text NOT NULL,
    "control_id" text NOT NULL,
    "id" text NOT NULL,
    "asset_id" text NOT NULL CHECK (char_length("asset_id") BETWEEN 1 AND 128),
    "source" text NOT NULL CHECK (char_length("source") BETWEEN 1 AND 64),
    "at" timestamp with time zone NOT NULL,
    "migration_seeded" boolean NOT NULL DEFAULT false,
    PRIMARY KEY ("organization_id", "control_id", "id")
);

INSERT INTO "public"."zasp_compliance_controls" ("organization_id", "id", "framework", "name", "fresh_until", "migration_seeded")
SELECT "id", 'access-control', 'SOC 2', 'Logical access controls', transaction_timestamp() + interval '24 hours', true
FROM "public"."zasp_organizations";

INSERT INTO "public"."zasp_compliance_evidence" ("organization_id", "control_id", "id", "asset_id", "source", "at", "migration_seeded")
SELECT "organization_id", 'access-control', 'membership-' || substr(md5("principal_id"), 1, 16), "principal_id", 'product-membership', transaction_timestamp(), true
FROM "public"."zasp_identity_memberships";

CREATE TABLE "public"."zasp_data_controls" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "environment_class" text NOT NULL CHECK ("environment_class" IN ('development', 'test', 'staging', 'production')),
    "collection_mode" text NOT NULL CHECK ("collection_mode" IN ('metadata_only', 'extended')),
    "retention_days" integer NOT NULL CHECK ("retention_days" BETWEEN 1 AND 3650),
    "deletion_enabled" boolean NOT NULL,
    "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0),
    "migration_seeded" boolean NOT NULL DEFAULT false,
    "updated_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id"),
    CHECK ("environment_class" <> 'production' OR "collection_mode" = 'metadata_only')
);

INSERT INTO "public"."zasp_data_controls" ("organization_id", "workspace_id", "environment_id", "environment_class", "collection_mode", "retention_days", "deletion_enabled", "migration_seeded")
SELECT "organization_id", "workspace_id", "id", "environment_class", 'metadata_only', 30, true, true
FROM "public"."zasp_environments";

CREATE OR REPLACE FUNCTION "public"."zasp_effective_scope_permissions"(requested_permissions jsonb, requested_role text)
RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE requested_role
      WHEN 'organization_admin' THEN '["investigate_sessions","manage_api_tokens","manage_data_controls","manage_findings","manage_identity","manage_workflows","revoke_sessions","view","view_audit","view_compliance"]'::jsonb
      WHEN 'security_admin' THEN '["investigate_sessions","manage_api_tokens","manage_data_controls","manage_findings","manage_identity","manage_workflows","revoke_sessions","view","view_audit","view_compliance"]'::jsonb
      WHEN 'security_engineer' THEN '["investigate_sessions","manage_findings","manage_workflows","view"]'::jsonb
      WHEN 'developer_owner' THEN '["investigate_sessions","view"]'::jsonb
      WHEN 'compliance_viewer' THEN '["view","view_audit","view_compliance"]'::jsonb
      WHEN 'read_only_viewer' THEN '["view"]'::jsonb
      ELSE '[]'::jsonb
    END
$$;

DO $migration$
DECLARE
    definition text;
BEGIN
    SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure)
      INTO definition;
    definition := replace(definition, 'production-workflow-receipt-provenance-v3', 'production-administration-v1');
    definition := replace(definition, 'release."version" = 6', 'release."version" = 7');
    definition := replace(definition, 'release."name" = ''workflow_receipt_provenance''', 'release."name" = ''production_administration''');
    definition := replace(definition, 'later_release."version" > 6', 'later_release."version" > 7');
    EXECUTE definition;
END;
$migration$;

INSERT INTO "public"."zasp_schema_metadata" ("key", "value")
VALUES ('production_administration_fingerprint', '3d4229628c82d1a32c2cf6f31e07c233595a7568dd33c79aa22b56c2fd75b703');

UPDATE "public"."zasp_schema_metadata"
SET "value" = 'production-administration-v1', "applied_at" = transaction_timestamp()
WHERE "key" = 'production_core_schema' AND "value" = 'production-workflow-receipt-provenance-v3';
