CREATE TABLE "public"."zasp_workflow_records" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "kind" text NOT NULL CHECK ("kind" IN ('policy', 'integration', 'sensor', 'security_agent', 'security_agent_run', 'security_agent_approval', 'policy_decision')),
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

CREATE FUNCTION "public"."zasp_workflow_mutate"(
    mutation text, requested_kind text, requested_id text,
    requested_organization_id text, requested_workspace_id text, requested_environment_id text,
    requested_principal_id text, requested_operation text, requested_idempotency_key text,
    expected_version bigint, requested_body jsonb, requested_audit_id text, requested_correlation_id text
)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    digest_value bytea;
    prior_digest bytea;
    prior_response jsonb;
    result_body jsonb;
    result_version bigint;
    result_secret_generation bigint;
    approval_body jsonb;
BEGIN
    IF mutation NOT IN ('create', 'update', 'delete', 'rotate_secret', 'audit') OR
       requested_kind NOT IN ('policy', 'integration', 'sensor', 'security_agent', 'security_agent_run', 'security_agent_approval', 'policy_decision') OR
       length(requested_id) < 1 OR length(requested_id) > 128 OR
       length(requested_idempotency_key) < 16 OR length(requested_idempotency_key) > 128 OR
       jsonb_typeof(requested_body) <> 'object' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid workflow mutation';
    END IF;

    digest_value := digest(convert_to(mutation || chr(31) || requested_kind || chr(31) || requested_id || chr(31) || requested_body::text || chr(31) || expected_version::text, 'UTF8'), 'sha256');
    SELECT "request_digest", "response" INTO prior_digest, prior_response FROM "public"."zasp_workflow_idempotency"
     WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
       AND "environment_id" = requested_environment_id AND "principal_id" = requested_principal_id
       AND "operation" = requested_operation AND "idempotency_key" = requested_idempotency_key;
    IF FOUND THEN
        IF prior_digest <> digest_value THEN RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'idempotency conflict'; END IF;
        RETURN prior_response || jsonb_build_object('replayed', true);
    END IF;

    IF mutation = 'create' THEN
        IF requested_kind = 'security_agent_run' AND requested_operation = 'runSecurityAgent' THEN
            approval_body := requested_body -> '_approval';
            IF jsonb_typeof(approval_body) <> 'object' OR approval_body ->> 'id' IS NULL OR approval_body ->> 'run_id' <> requested_id THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid workflow approval';
            END IF;
            result_body := requested_body - '_approval';
            INSERT INTO "public"."zasp_workflow_records" ("organization_id", "workspace_id", "environment_id", "kind", "id", "body")
            VALUES (requested_organization_id, requested_workspace_id, requested_environment_id, requested_kind, requested_id, result_body)
            RETURNING "body", "version", "secret_generation" INTO result_body, result_version, result_secret_generation;
            approval_body := approval_body || jsonb_build_object('expires_at', to_jsonb(transaction_timestamp() + interval '15 minutes'));
            INSERT INTO "public"."zasp_workflow_records" ("organization_id", "workspace_id", "environment_id", "kind", "id", "body")
            VALUES (requested_organization_id, requested_workspace_id, requested_environment_id, 'security_agent_approval', approval_body ->> 'id', approval_body);
        ELSE
            INSERT INTO "public"."zasp_workflow_records" ("organization_id", "workspace_id", "environment_id", "kind", "id", "body")
            VALUES (requested_organization_id, requested_workspace_id, requested_environment_id, requested_kind, requested_id, requested_body)
            RETURNING "body", "version", "secret_generation" INTO result_body, result_version, result_secret_generation;
        END IF;
    ELSIF mutation = 'update' THEN
        UPDATE "public"."zasp_workflow_records" SET "body" = requested_body, "version" = "version" + 1, "updated_at" = transaction_timestamp()
         WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id AND "environment_id" = requested_environment_id
           AND "kind" = requested_kind AND "id" = requested_id AND "deleted_at" IS NULL AND "version" = expected_version
        RETURNING "body", "version", "secret_generation" INTO result_body, result_version, result_secret_generation;
        IF result_body IS NOT NULL AND requested_kind = 'security_agent_run' AND requested_operation = 'cancelSecurityAgentRun' THEN
            UPDATE "public"."zasp_workflow_records"
               SET "body" = jsonb_set(jsonb_set("body", '{state}', '"cancelled"'::jsonb, true), '{version}', to_jsonb("version" + 1), true), "version" = "version" + 1, "updated_at" = transaction_timestamp()
             WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id AND "environment_id" = requested_environment_id
               AND "kind" = 'security_agent_approval' AND "deleted_at" IS NULL AND "body" ->> 'run_id' = requested_id AND "body" ->> 'state' = 'pending';
        END IF;
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
    ELSE
        result_body := requested_body; result_version := GREATEST(expected_version, 1); result_secret_generation := 0;
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
