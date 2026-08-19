CREATE TABLE "public"."zasp_risk_findings" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "id" text NOT NULL,
    "source" text NOT NULL CHECK ("source" IN ('posture', 'prowler')),
    "rule" text CHECK ("rule" IS NULL OR length("rule") BETWEEN 1 AND 64),
    "title" text NOT NULL CHECK (length("title") BETWEEN 1 AND 256),
    "severity" text NOT NULL CHECK ("severity" IN ('critical', 'high', 'medium', 'low')),
    "status" text NOT NULL CHECK ("status" IN ('open', 'under_review', 'resolved', 'accepted')),
    "agent_id" text,
    "path_id" text,
    "compliance_context" text CHECK ("compliance_context" IS NULL OR length("compliance_context") BETWEEN 1 AND 128),
    "acceptance_reason" text CHECK ("acceptance_reason" IS NULL OR length("acceptance_reason") BETWEEN 1 AND 512),
    "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0),
    "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    "updated_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "id"),
    CHECK ("id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CHECK ("agent_id" IS NULL OR "agent_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CHECK ("path_id" IS NULL OR "path_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CHECK (("status" = 'accepted') = ("acceptance_reason" IS NOT NULL)),
    CHECK ("updated_at" >= "created_at")
);

CREATE INDEX "zasp_risk_findings_list_idx"
ON "public"."zasp_risk_findings" ("organization_id", "workspace_id", "environment_id", "id");

CREATE TABLE "public"."zasp_risk_finding_evidence" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "finding_id" text NOT NULL,
    "position" smallint NOT NULL CHECK ("position" BETWEEN 1 AND 64),
    "evidence_id" text NOT NULL CHECK ("evidence_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "finding_id", "position"),
    UNIQUE ("organization_id", "workspace_id", "environment_id", "finding_id", "evidence_id"),
    FOREIGN KEY ("organization_id", "workspace_id", "environment_id", "finding_id")
        REFERENCES "public"."zasp_risk_findings" ("organization_id", "workspace_id", "environment_id", "id") ON DELETE CASCADE
);

CREATE TABLE "public"."zasp_risk_finding_factors" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "finding_id" text NOT NULL,
    "position" smallint NOT NULL CHECK ("position" BETWEEN 1 AND 16),
    "name" text NOT NULL CHECK (length("name") BETWEEN 1 AND 64),
    "evidence_id" text NOT NULL CHECK ("evidence_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "finding_id", "position"),
    UNIQUE ("organization_id", "workspace_id", "environment_id", "finding_id", "name"),
    FOREIGN KEY ("organization_id", "workspace_id", "environment_id", "finding_id")
        REFERENCES "public"."zasp_risk_findings" ("organization_id", "workspace_id", "environment_id", "id") ON DELETE CASCADE
);

CREATE TABLE "public"."zasp_risk_attack_paths" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "id" text NOT NULL,
    "entry_id" text NOT NULL,
    "sink_id" text NOT NULL,
    "state" text NOT NULL CHECK ("state" IN ('potential', 'observed', 'verified', 'blocked')),
    "blocked_edge" smallint NOT NULL DEFAULT -1,
    "version" bigint NOT NULL DEFAULT 1 CHECK ("version" > 0),
    "created_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    "updated_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "id"),
    CHECK ("id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CHECK ("entry_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CHECK ("sink_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CHECK (("state" = 'blocked' AND "blocked_edge" BETWEEN 0 AND 6) OR ("state" <> 'blocked' AND "blocked_edge" = -1)),
    CHECK ("updated_at" >= "created_at")
);

CREATE INDEX "zasp_risk_attack_paths_list_idx"
ON "public"."zasp_risk_attack_paths" ("organization_id", "workspace_id", "environment_id", "id");

CREATE TABLE "public"."zasp_risk_attack_path_nodes" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "path_id" text NOT NULL,
    "position" smallint NOT NULL CHECK ("position" BETWEEN 1 AND 8),
    "node_id" text NOT NULL CHECK ("node_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "path_id", "position"),
    UNIQUE ("organization_id", "workspace_id", "environment_id", "path_id", "node_id"),
    FOREIGN KEY ("organization_id", "workspace_id", "environment_id", "path_id")
        REFERENCES "public"."zasp_risk_attack_paths" ("organization_id", "workspace_id", "environment_id", "id") ON DELETE CASCADE
);

CREATE TABLE "public"."zasp_risk_attack_path_evidence" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "path_id" text NOT NULL,
    "position" smallint NOT NULL CHECK ("position" BETWEEN 1 AND 16),
    "evidence_id" text NOT NULL CHECK ("evidence_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "path_id", "position"),
    UNIQUE ("organization_id", "workspace_id", "environment_id", "path_id", "evidence_id"),
    FOREIGN KEY ("organization_id", "workspace_id", "environment_id", "path_id")
        REFERENCES "public"."zasp_risk_attack_paths" ("organization_id", "workspace_id", "environment_id", "id") ON DELETE CASCADE
);

CREATE TABLE "public"."zasp_risk_break_options" (
    "organization_id" text NOT NULL,
    "workspace_id" text NOT NULL,
    "environment_id" text NOT NULL,
    "path_id" text NOT NULL,
    "rank" smallint NOT NULL CHECK ("rank" BETWEEN 1 AND 8),
    "target_id" text NOT NULL CHECK ("target_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    "evidence_id" text NOT NULL CHECK ("evidence_id" ~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    "kind" text NOT NULL CHECK ("kind" IN ('remove_node', 'enforce_policy')),
    PRIMARY KEY ("organization_id", "workspace_id", "environment_id", "path_id", "rank"),
    UNIQUE ("organization_id", "workspace_id", "environment_id", "path_id", "kind", "target_id"),
    FOREIGN KEY ("organization_id", "workspace_id", "environment_id", "path_id")
        REFERENCES "public"."zasp_risk_attack_paths" ("organization_id", "workspace_id", "environment_id", "id") ON DELETE CASCADE
);

ALTER TABLE "public"."zasp_workflow_receipts" DROP CONSTRAINT "zasp_workflow_receipts_resource_kind_check";
ALTER TABLE "public"."zasp_workflow_receipts" ADD CONSTRAINT "zasp_workflow_receipts_resource_kind_check"
CHECK ("resource_kind" IN ('policy', 'integration', 'sensor', 'security_agent', 'security_agent_run', 'security_agent_approval', 'finding'));

CREATE FUNCTION "public"."zasp_risk_attack_path_valid"(
    candidate "public"."zasp_risk_attack_paths"
)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT COALESCE(
        (SELECT count(*) BETWEEN 2 AND 8
             AND min("position")=1 AND max("position")=count(*)
             AND (array_agg("node_id" ORDER BY "position"))[1]=candidate."entry_id"
             AND (array_agg("node_id" ORDER BY "position" DESC))[1]=candidate."sink_id"
          FROM "public"."zasp_risk_attack_path_nodes"
         WHERE "organization_id"=candidate."organization_id" AND "workspace_id"=candidate."workspace_id"
           AND "environment_id"=candidate."environment_id" AND "path_id"=candidate."id")
        AND
        (SELECT count(*) BETWEEN 1 AND 16 AND min("position")=1 AND max("position")=count(*)
          FROM "public"."zasp_risk_attack_path_evidence"
         WHERE "organization_id"=candidate."organization_id" AND "workspace_id"=candidate."workspace_id"
           AND "environment_id"=candidate."environment_id" AND "path_id"=candidate."id")
        AND (candidate."state"<>'blocked' OR candidate."blocked_edge" <
            (SELECT count(*)-1 FROM "public"."zasp_risk_attack_path_nodes"
              WHERE "organization_id"=candidate."organization_id" AND "workspace_id"=candidate."workspace_id"
                AND "environment_id"=candidate."environment_id" AND "path_id"=candidate."id")),
        false
    )
$$;

CREATE FUNCTION "public"."zasp_risk_finding_get"(
    requested_id text, requested_organization_id text, requested_workspace_id text, requested_environment_id text
)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE
    finding "public"."zasp_risk_findings"%ROWTYPE;
    evidence jsonb;
    factors jsonb;
    evidence_count integer;
    factor_count integer;
BEGIN
    SELECT * INTO finding FROM "public"."zasp_risk_findings"
     WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id
       AND "environment_id"=requested_environment_id AND "id"=requested_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='risk finding missing'; END IF;
    SELECT count(*), COALESCE(jsonb_agg("evidence_id" ORDER BY "position"),'[]'::jsonb)
      INTO evidence_count, evidence
      FROM "public"."zasp_risk_finding_evidence"
     WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id
       AND "environment_id"=requested_environment_id AND "finding_id"=requested_id;
    SELECT count(*), COALESCE(jsonb_agg(jsonb_build_object('name',"name",'evidence_id',"evidence_id") ORDER BY "position"),'[]'::jsonb)
      INTO factor_count, factors
      FROM "public"."zasp_risk_finding_factors"
     WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id
       AND "environment_id"=requested_environment_id AND "finding_id"=requested_id;
    IF evidence_count NOT BETWEEN 1 AND 64 OR factor_count NOT BETWEEN 0 AND 16
       OR EXISTS (SELECT 1 FROM "public"."zasp_risk_finding_evidence" WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id AND "environment_id"=requested_environment_id AND "finding_id"=requested_id HAVING min("position")<>1 OR max("position")<>count(*))
       OR EXISTS (SELECT 1 FROM "public"."zasp_risk_finding_factors" WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id AND "environment_id"=requested_environment_id AND "finding_id"=requested_id HAVING min("position")<>1 OR max("position")<>count(*) OR count(DISTINCT "evidence_id")<>count(*)) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid stored risk finding projection';
    END IF;
    RETURN jsonb_strip_nulls(jsonb_build_object(
        'id',finding."id",'source',finding."source",'rule',finding."rule",'title',finding."title",
        'severity',finding."severity",'status',finding."status",'agent_id',finding."agent_id",'path_id',finding."path_id",
        'compliance_context',finding."compliance_context",'evidence_ids',evidence,'risk_factors',factors,
        'acceptance_reason',finding."acceptance_reason",'version',finding."version",
        'created_at',finding."created_at",'updated_at',finding."updated_at"));
END;
$$;

CREATE FUNCTION "public"."zasp_risk_finding_page"(
    requested_organization_id text, requested_workspace_id text, requested_environment_id text,
    requested_after_id text DEFAULT NULL, requested_limit integer DEFAULT 50
)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE response jsonb;
BEGIN
    IF requested_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid risk page limit'; END IF;
    WITH candidates AS (
        SELECT "id" FROM "public"."zasp_risk_findings"
         WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id
           AND "environment_id"=requested_environment_id AND (requested_after_id IS NULL OR "id">requested_after_id)
           AND ("source"<>'prowler' OR "agent_id" IS NOT NULL OR "path_id" IS NOT NULL OR "compliance_context" IS NOT NULL)
         ORDER BY "id" LIMIT requested_limit+1
    ), visible AS (SELECT "id" FROM candidates ORDER BY "id" LIMIT requested_limit)
    SELECT jsonb_build_object(
        'items',COALESCE((SELECT jsonb_agg("public"."zasp_risk_finding_get"("id",requested_organization_id,requested_workspace_id,requested_environment_id) ORDER BY "id") FROM visible),'[]'::jsonb),
        'next_id',CASE WHEN (SELECT count(*) FROM candidates)>requested_limit THEN (SELECT "id" FROM visible ORDER BY "id" DESC LIMIT 1) ELSE NULL END)
      INTO response;
    RETURN response;
END;
$$;

CREATE FUNCTION "public"."zasp_risk_attack_path_get"(
    requested_id text, requested_organization_id text, requested_workspace_id text, requested_environment_id text
)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE
    path "public"."zasp_risk_attack_paths"%ROWTYPE;
    nodes jsonb;
    evidence jsonb;
    node_count integer;
    evidence_count integer;
    first_node text;
    last_node text;
BEGIN
    SELECT * INTO path FROM "public"."zasp_risk_attack_paths" AS candidate
     WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id
       AND "environment_id"=requested_environment_id AND "id"=requested_id
       AND "public"."zasp_risk_attack_path_valid"(candidate);
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='risk path missing'; END IF;
    SELECT count(*), COALESCE(jsonb_agg("node_id" ORDER BY "position"),'[]'::jsonb),
           (array_agg("node_id" ORDER BY "position"))[1], (array_agg("node_id" ORDER BY "position" DESC))[1]
      INTO node_count,nodes,first_node,last_node FROM "public"."zasp_risk_attack_path_nodes"
     WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id
       AND "environment_id"=requested_environment_id AND "path_id"=requested_id;
    SELECT count(*), COALESCE(jsonb_agg("evidence_id" ORDER BY "position"),'[]'::jsonb)
      INTO evidence_count,evidence FROM "public"."zasp_risk_attack_path_evidence"
     WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id
       AND "environment_id"=requested_environment_id AND "path_id"=requested_id;
    RETURN jsonb_build_object('id',path."id",'entry_id',path."entry_id",'sink_id',path."sink_id",'node_ids',nodes,
        'state',path."state",'evidence_ids',evidence,'blocked_edge',path."blocked_edge",'version',path."version",
        'created_at',path."created_at",'updated_at',path."updated_at");
END;
$$;

CREATE FUNCTION "public"."zasp_risk_attack_path_page"(
    requested_organization_id text, requested_workspace_id text, requested_environment_id text,
    requested_after_id text DEFAULT NULL, requested_limit integer DEFAULT 50
)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE response jsonb;
BEGIN
    IF requested_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid risk page limit'; END IF;
    WITH candidates AS (
        SELECT "id" FROM "public"."zasp_risk_attack_paths" AS candidate
         WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id
           AND "environment_id"=requested_environment_id AND (requested_after_id IS NULL OR "id">requested_after_id)
           AND "public"."zasp_risk_attack_path_valid"(candidate)
         ORDER BY "id" LIMIT requested_limit+1
    ), visible AS (SELECT "id" FROM candidates ORDER BY "id" LIMIT requested_limit)
    SELECT jsonb_build_object(
        'items',COALESCE((SELECT jsonb_agg("public"."zasp_risk_attack_path_get"("id",requested_organization_id,requested_workspace_id,requested_environment_id) ORDER BY "id") FROM visible),'[]'::jsonb),
        'next_id',CASE WHEN (SELECT count(*) FROM candidates)>requested_limit THEN (SELECT "id" FROM visible ORDER BY "id" DESC LIMIT 1) ELSE NULL END)
      INTO response;
    RETURN response;
END;
$$;

CREATE FUNCTION "public"."zasp_risk_break_options_get"(
    requested_path_id text, requested_organization_id text, requested_workspace_id text, requested_environment_id text
)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE option_count integer; response jsonb; path_exists boolean;
BEGIN
    SELECT EXISTS(SELECT 1 FROM "public"."zasp_risk_attack_paths" AS candidate WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id AND "environment_id"=requested_environment_id AND "id"=requested_path_id AND "public"."zasp_risk_attack_path_valid"(candidate)) INTO path_exists;
    IF NOT path_exists THEN RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='risk path missing'; END IF;
    SELECT count(*), jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('path_id',"path_id",'target_id',"target_id",'evidence_id',"evidence_id",'kind',"kind",'rank',"rank") ORDER BY "rank"),'[]'::jsonb))
      INTO option_count,response FROM "public"."zasp_risk_break_options"
     WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id AND "environment_id"=requested_environment_id AND "path_id"=requested_path_id;
    IF option_count>8
       OR EXISTS (SELECT 1 FROM "public"."zasp_risk_break_options" WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id AND "environment_id"=requested_environment_id AND "path_id"=requested_path_id HAVING count(*)>0 AND (min("rank")<>1 OR max("rank")<>count(*)))
       OR EXISTS (SELECT 1 FROM "public"."zasp_risk_break_options" AS option WHERE option."organization_id"=requested_organization_id AND option."workspace_id"=requested_workspace_id AND option."environment_id"=requested_environment_id AND option."path_id"=requested_path_id AND option."kind"='remove_node' AND NOT EXISTS (SELECT 1 FROM "public"."zasp_risk_attack_path_nodes" AS node WHERE node."organization_id"=option."organization_id" AND node."workspace_id"=option."workspace_id" AND node."environment_id"=option."environment_id" AND node."path_id"=option."path_id" AND node."node_id"=option."target_id")) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid stored break options';
    END IF;
    RETURN response;
END;
$$;

CREATE FUNCTION "public"."zasp_risk_high_path_count"(
    requested_organization_id text, requested_workspace_id text, requested_environment_id text
)
RETURNS bigint LANGUAGE sql STABLE AS $$
    SELECT count(*) FROM "public"."zasp_risk_attack_paths" AS candidate
     WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id
       AND "environment_id"=requested_environment_id AND "state"<>'blocked'
       AND "public"."zasp_risk_attack_path_valid"(candidate)
$$;

CREATE FUNCTION "public"."zasp_risk_mutate"(
    requested_operation text, requested_finding_id text,
    requested_organization_id text, requested_workspace_id text, requested_environment_id text,
    requested_principal_id text, requested_idempotency_key text, expected_version bigint,
    requested_status text, requested_reason text, requested_audit_id text,
    requested_correlation_id text, requested_receipt_id text
)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    requested_intent jsonb;
    digest_value bytea;
    prior_digest bytea;
    prior_response jsonb;
    result_version bigint;
    result_body jsonb;
BEGIN
    LOCK TABLE "public"."zasp_risk_findings", "public"."zasp_workflow_idempotency", "public"."zasp_workflow_audit", "public"."zasp_workflow_receipts" IN ROW EXCLUSIVE MODE;
    IF NOT EXISTS (SELECT 1 FROM "public"."zasp_schema_versions" release JOIN "public"."zasp_schema_metadata" marker ON marker."key"='production_core_schema' AND marker."value"='production-risk-projection-v1' WHERE release."version"=9 AND release."name"='production_risk_projection' AND NOT EXISTS (SELECT 1 FROM "public"."zasp_schema_versions" later WHERE later."version">9)) THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='risk projection release unavailable';
    END IF;
    IF requested_operation NOT IN ('updateFinding','acceptFindingRisk') OR expected_version<1
       OR length(requested_idempotency_key) NOT BETWEEN 16 AND 128
       OR requested_finding_id !~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR requested_principal_id !~ '^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR requested_operation='updateFinding' AND (requested_status NOT IN ('open','under_review','resolved') OR requested_reason IS NOT NULL)
       OR requested_operation='acceptFindingRisk' AND (requested_status<>'accepted' OR length(requested_reason) NOT BETWEEN 1 AND 512) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid risk mutation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM "public"."zasp_risk_findings" WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id AND "environment_id"=requested_environment_id AND "id"=requested_finding_id) THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='risk finding missing';
    END IF;
    requested_intent := jsonb_build_object('resource_id',requested_finding_id,'expected_version',expected_version,'body',CASE WHEN requested_operation='updateFinding' THEN jsonb_build_object('status',requested_status) ELSE jsonb_build_object('reason',requested_reason) END);
    PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),requested_organization_id,requested_workspace_id,requested_environment_id,requested_principal_id,requested_operation,requested_idempotency_key),0));
    digest_value := digest(convert_to(requested_intent::text,'UTF8'),'sha256');
    SELECT "request_digest","response" INTO prior_digest,prior_response FROM "public"."zasp_workflow_idempotency"
     WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id AND "environment_id"=requested_environment_id
       AND "principal_id"=requested_principal_id AND "operation"=requested_operation AND "idempotency_key"=requested_idempotency_key;
    IF FOUND THEN
        IF prior_digest<>digest_value THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='idempotency conflict'; END IF;
        RETURN prior_response||jsonb_build_object('replayed',true);
    END IF;
    UPDATE "public"."zasp_risk_findings" SET "status"=requested_status,"acceptance_reason"=CASE WHEN requested_operation='acceptFindingRisk' THEN requested_reason ELSE NULL END,"version"="version"+1,"updated_at"=transaction_timestamp()
     WHERE "organization_id"=requested_organization_id AND "workspace_id"=requested_workspace_id AND "environment_id"=requested_environment_id AND "id"=requested_finding_id AND "version"=expected_version
     RETURNING "version" INTO result_version;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='risk finding version conflict'; END IF;
    result_body := "public"."zasp_risk_finding_get"(requested_finding_id,requested_organization_id,requested_workspace_id,requested_environment_id);
    prior_response := jsonb_build_object('body',result_body,'version',result_version,'audit_id',requested_audit_id,'correlation_id',requested_correlation_id,'replayed',false);
    IF requested_receipt_id IS NOT NULL THEN prior_response:=prior_response||jsonb_build_object('receipt_id',requested_receipt_id); END IF;
    INSERT INTO "public"."zasp_workflow_audit" ("organization_id","workspace_id","environment_id","audit_id","correlation_id","principal_id","operation","resource_kind","resource_id","resource_version") VALUES (requested_organization_id,requested_workspace_id,requested_environment_id,requested_audit_id,requested_correlation_id,requested_principal_id,requested_operation,'finding',requested_finding_id,result_version);
    INSERT INTO "public"."zasp_workflow_idempotency" ("organization_id","workspace_id","environment_id","principal_id","operation","idempotency_key","request_digest","response","receipt_semantics") VALUES (requested_organization_id,requested_workspace_id,requested_environment_id,requested_principal_id,requested_operation,requested_idempotency_key,digest_value,prior_response-'replayed',CASE WHEN requested_receipt_id IS NULL THEN 'receiptless_incompatible' ELSE 'receipt_backed' END);
    IF requested_receipt_id IS NOT NULL THEN
        INSERT INTO "public"."zasp_workflow_receipts" ("organization_id","workspace_id","environment_id","principal_id","receipt_id","operation","idempotency_key","intent","result","resource_kind","resource_id","resource_version","audit_id","correlation_id") VALUES (requested_organization_id,requested_workspace_id,requested_environment_id,requested_principal_id,requested_receipt_id,requested_operation,requested_idempotency_key,requested_intent,result_body,'finding',requested_finding_id,result_version,requested_audit_id,requested_correlation_id);
    END IF;
    RETURN prior_response;
END;
$$;

DO $migration$
DECLARE definition text;
BEGIN
    SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO definition;
    definition:=replace(definition,'api-token-reveal-grants-v1','production-risk-projection-v1');
    definition:=replace(definition,'release."version" = 8','release."version" = 9');
    definition:=replace(definition,'release."name" = ''api_token_reveal_grants''','release."name" = ''production_risk_projection''');
    definition:=replace(definition,'later_release."version" > 8','later_release."version" > 9');
    EXECUTE definition;
END;
$migration$;

INSERT INTO "public"."zasp_schema_metadata" ("key","value")
VALUES ('production_risk_projection_fingerprint', 'cd079f2f94be689b1ce89d9e55ce685f65f10595871a5362cfb76edc7410e16e');

UPDATE "public"."zasp_schema_metadata" SET "value"='production-risk-projection-v1',"applied_at"=transaction_timestamp()
WHERE "key"='production_core_schema' AND "value"='api-token-reveal-grants-v1';
