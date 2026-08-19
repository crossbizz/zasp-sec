ALTER TABLE "public"."zasp_product_sessions"
ADD COLUMN "authenticated_at" timestamp with time zone;

UPDATE "public"."zasp_product_sessions"
SET "authenticated_at" = LEAST("expires_at", transaction_timestamp() - interval '6 minutes');

ALTER TABLE "public"."zasp_product_sessions"
ALTER COLUMN "authenticated_at" SET NOT NULL,
ALTER COLUMN "authenticated_at" SET DEFAULT transaction_timestamp();

CREATE FUNCTION "public"."zasp_effective_scope_permissions"(requested_permissions jsonb, requested_role text)
RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
    SELECT COALESCE(jsonb_agg(permission ORDER BY permission), '[]'::jsonb)
      FROM jsonb_array_elements_text(requested_permissions) AS permission
     WHERE permission = 'view'
        OR permission = 'manage_workflows' AND requested_role IN ('organization_admin', 'security_admin', 'security_engineer')
$$;

CREATE TABLE "public"."zasp_workflow_records" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "kind" text NOT NULL CHECK ("kind" IN ('policy', 'integration', 'sensor', 'security_agent', 'security_agent_run', 'security_agent_approval')),
    "id" text NOT NULL,
    "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0),
    "body" jsonb NOT NULL CHECK (jsonb_typeof("body") = 'object'),
    "secret_generation" bigint NOT NULL DEFAULT 0 CHECK ("secret_generation" >= 0),
    "deleted_at" timestamp with time zone,
    "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    "updated_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "kind", "id")
);

CREATE INDEX "zasp_workflow_records_list_idx"
ON "public"."zasp_workflow_records" ("organization_id", "workspace_id", "environment_id", "kind", "updated_at", "id")
WHERE "deleted_at" IS NULL;

CREATE TABLE "public"."zasp_workflow_idempotency" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "principal_id" text NOT NULL,
    "operation" text NOT NULL,
    "idempotency_key" text NOT NULL,
    "request_digest" bytea NOT NULL,
    "response" jsonb NOT NULL CHECK (jsonb_typeof("response") = 'object'),
    "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "principal_id", "operation", "idempotency_key")
);

CREATE TABLE "public"."zasp_workflow_audit" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "audit_id" text NOT NULL,
    "correlation_id" text NOT NULL,
    "principal_id" text NOT NULL,
    "operation" text NOT NULL,
    "resource_kind" text NOT NULL,
    "resource_id" text NOT NULL,
    "resource_version" bigint NOT NULL,
    "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "audit_id"),
    UNIQUE ("organization_id", "correlation_id", "operation", "resource_id")
);

CREATE FUNCTION "public"."zasp_workflow_list"(requested_kind text, requested_organization_id text, requested_workspace_id text, requested_environment_id text, parent_field text DEFAULT NULL, parent_id text DEFAULT NULL)
RETURNS jsonb LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_object('items', COALESCE(jsonb_agg("body" ORDER BY "updated_at" DESC, "id"), '[]'::jsonb))
      FROM "public"."zasp_workflow_records"
     WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
       AND "environment_id" = requested_environment_id AND "kind" = requested_kind AND "deleted_at" IS NULL
       AND (parent_field IS NULL OR "body" ->> parent_field = parent_id)
$$;

CREATE FUNCTION "public"."zasp_workflow_get"(requested_kind text, requested_id text, requested_organization_id text, requested_workspace_id text, requested_environment_id text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_object('body', "body", 'version', "version", 'secret_generation', "secret_generation")
      FROM "public"."zasp_workflow_records"
     WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
       AND "environment_id" = requested_environment_id AND "kind" = requested_kind AND "id" = requested_id AND "deleted_at" IS NULL
$$;

CREATE FUNCTION "public"."zasp_workflow_page"(requested_kind text, requested_organization_id text, requested_workspace_id text, requested_environment_id text, requested_after_id text DEFAULT NULL, requested_limit integer DEFAULT 50)
RETURNS jsonb LANGUAGE sql STABLE AS $$
    WITH candidates AS (
        SELECT "id", "body"
          FROM "public"."zasp_workflow_records"
         WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
           AND "environment_id" = requested_environment_id AND "kind" = requested_kind AND "deleted_at" IS NULL
           AND (requested_after_id IS NULL OR "id" > requested_after_id)
         ORDER BY "id"
         LIMIT requested_limit + 1
    ), visible AS (
        SELECT "id", "body" FROM candidates ORDER BY "id" LIMIT requested_limit
    )
    SELECT jsonb_build_object(
        'items', COALESCE((SELECT jsonb_agg("body" ORDER BY "id") FROM visible), '[]'::jsonb),
        'next_id', CASE WHEN (SELECT count(*) FROM candidates) > requested_limit THEN (SELECT "id" FROM visible ORDER BY "id" DESC LIMIT 1) ELSE NULL END
    )
$$;

CREATE FUNCTION "public"."zasp_workflow_replay"(
    requested_organization_id text, requested_workspace_id text, requested_environment_id text,
    requested_principal_id text, requested_operation text, requested_idempotency_key text,
    requested_intent jsonb
)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    digest_value bytea;
    prior_digest bytea;
    prior_response jsonb;
BEGIN
    IF length(requested_operation) < 1 OR length(requested_operation) > 128 OR
       length(requested_idempotency_key) < 16 OR length(requested_idempotency_key) > 128 OR
       jsonb_typeof(requested_intent) <> 'object' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid workflow replay';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31), requested_organization_id, requested_workspace_id, requested_environment_id, requested_principal_id, requested_operation, requested_idempotency_key), 0));
    digest_value := digest(convert_to(requested_intent::text, 'UTF8'), 'sha256');
    SELECT "request_digest", "response" INTO prior_digest, prior_response
      FROM "public"."zasp_workflow_idempotency"
     WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
       AND "environment_id" = requested_environment_id AND "principal_id" = requested_principal_id
       AND "operation" = requested_operation AND "idempotency_key" = requested_idempotency_key;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('found', false);
    END IF;
    IF prior_digest <> digest_value THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'idempotency conflict';
    END IF;
    RETURN jsonb_build_object('found', true, 'result', prior_response || jsonb_build_object('replayed', true));
END;
$$;

CREATE FUNCTION "public"."zasp_workflow_mutate"(
    mutation text, requested_kind text, requested_id text,
    requested_organization_id text, requested_workspace_id text, requested_environment_id text,
    requested_principal_id text, requested_operation text, requested_idempotency_key text,
    expected_version bigint, requested_intent jsonb, requested_body jsonb, requested_audit_id text, requested_correlation_id text
)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    digest_value bytea;
    prior_digest bytea;
    prior_response jsonb;
    result_body jsonb;
    result_version bigint;
    result_secret_generation bigint;
BEGIN
    IF mutation NOT IN ('create', 'update', 'delete', 'rotate_secret') OR
       requested_kind NOT IN ('policy', 'integration', 'sensor', 'security_agent', 'security_agent_run', 'security_agent_approval') OR
       length(requested_id) < 1 OR length(requested_id) > 128 OR
       length(requested_idempotency_key) < 16 OR length(requested_idempotency_key) > 128 OR
       jsonb_typeof(requested_intent) <> 'object' OR jsonb_typeof(requested_body) <> 'object' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid workflow mutation';
    END IF;

	PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31), requested_organization_id, requested_workspace_id, requested_environment_id, requested_principal_id, requested_operation, requested_idempotency_key), 0));
    digest_value := digest(convert_to(requested_intent::text, 'UTF8'), 'sha256');
    SELECT "request_digest", "response" INTO prior_digest, prior_response FROM "public"."zasp_workflow_idempotency"
     WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
       AND "environment_id" = requested_environment_id AND "principal_id" = requested_principal_id
       AND "operation" = requested_operation AND "idempotency_key" = requested_idempotency_key;
    IF FOUND THEN
        IF prior_digest <> digest_value THEN RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'idempotency conflict'; END IF;
        RETURN prior_response || jsonb_build_object('replayed', true);
    END IF;

    IF mutation = 'create' THEN
        IF requested_kind = 'policy' AND (requested_operation <> 'createPolicy' OR requested_body ->> 'rollout' <> 'draft') THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'policy must be created as draft';
        END IF;
        INSERT INTO "public"."zasp_workflow_records" ("organization_id", "workspace_id", "environment_id", "kind", "id", "body")
        VALUES (requested_organization_id, requested_workspace_id, requested_environment_id, requested_kind, requested_id, requested_body)
        RETURNING "body", "version", "secret_generation" INTO result_body, result_version, result_secret_generation;
    ELSIF mutation = 'update' THEN
        UPDATE "public"."zasp_workflow_records" AS record
           SET "body" = CASE WHEN requested_kind = 'policy' THEN requested_body - '_target_environment_id' ELSE requested_body END,
               "version" = record."version" + 1,
               "updated_at" = transaction_timestamp()
         WHERE record."organization_id" = requested_organization_id AND record."workspace_id" = requested_workspace_id AND record."environment_id" = requested_environment_id
           AND record."kind" = requested_kind AND record."id" = requested_id AND record."deleted_at" IS NULL AND record."version" = expected_version
           AND (requested_kind <> 'policy' OR
                requested_operation = 'updatePolicy' AND requested_body ->> 'rollout' = record."body" ->> 'rollout' OR
                requested_operation = 'rolloutPolicy' AND requested_body ->> '_target_environment_id' = requested_environment_id AND
                    ((record."body" ->> 'rollout' = 'draft' AND requested_body ->> 'rollout' = 'monitor') OR
                     (record."body" ->> 'rollout' = 'monitor' AND requested_body ->> 'rollout' = 'enforced')) OR
                requested_operation = 'disablePolicy' AND requested_body ->> '_target_environment_id' = requested_environment_id AND
                    record."body" ->> 'rollout' IN ('monitor', 'enforced') AND requested_body ->> 'rollout' = 'disabled')
        RETURNING record."body", record."version", record."secret_generation" INTO result_body, result_version, result_secret_generation;
    ELSIF mutation = 'delete' THEN
        UPDATE "public"."zasp_workflow_records" SET "deleted_at" = transaction_timestamp(), "version" = "version" + 1, "updated_at" = transaction_timestamp()
         WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id AND "environment_id" = requested_environment_id
           AND "kind" = requested_kind AND "id" = requested_id AND "deleted_at" IS NULL AND "version" = expected_version
        RETURNING "body", "version", "secret_generation" INTO result_body, result_version, result_secret_generation;
    ELSIF mutation = 'rotate_secret' THEN
        UPDATE "public"."zasp_workflow_records" SET "secret_generation" = "secret_generation" + 1, "version" = "version" + 1, "updated_at" = transaction_timestamp()
         WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id AND "environment_id" = requested_environment_id
           AND "kind" = requested_kind AND "id" = requested_id AND "deleted_at" IS NULL AND "version" = expected_version
        RETURNING "body", "version", "secret_generation" INTO result_body, result_version, result_secret_generation;
    END IF;

    IF result_body IS NULL THEN
        IF EXISTS (SELECT 1 FROM "public"."zasp_workflow_records" WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id AND "environment_id" = requested_environment_id AND "kind" = requested_kind AND "id" = requested_id AND "deleted_at" IS NULL) THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'workflow version conflict';
        END IF;
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'workflow record missing';
    END IF;

    prior_response := jsonb_build_object('body', result_body, 'version', result_version, 'secret_generation', result_secret_generation, 'audit_id', requested_audit_id, 'correlation_id', requested_correlation_id, 'replayed', false);
    INSERT INTO "public"."zasp_workflow_audit" ("organization_id", "workspace_id", "environment_id", "audit_id", "correlation_id", "principal_id", "operation", "resource_kind", "resource_id", "resource_version")
    VALUES (requested_organization_id, requested_workspace_id, requested_environment_id, requested_audit_id, requested_correlation_id, requested_principal_id, requested_operation, requested_kind, requested_id, result_version);
    INSERT INTO "public"."zasp_workflow_idempotency" ("organization_id", "workspace_id", "environment_id", "principal_id", "operation", "idempotency_key", "request_digest", "response")
    VALUES (requested_organization_id, requested_workspace_id, requested_environment_id, requested_principal_id, requested_operation, requested_idempotency_key, digest_value, prior_response);
    RETURN prior_response;
END;
$$;

UPDATE "public"."zasp_schema_metadata" SET "value" = 'production-workflows-v1', "applied_at" = transaction_timestamp()
WHERE "key" = 'production_core_schema' AND "value" = 'production-core-v1';
