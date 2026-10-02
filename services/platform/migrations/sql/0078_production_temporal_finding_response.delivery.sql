-- Only immutable committed commands are delivered. The attempt timestamp is
-- fair scan progress, not a claim, lease, execution state or completion proof.
CREATE TABLE zasp_temporal78.start_deliveries(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 last_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),accepted_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal78.commands);
ALTER TABLE zasp_temporal78.start_deliveries OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal78.start_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal78.start_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal78.start_deliveries USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE INDEX pending_starts ON zasp_temporal78.start_deliveries(last_attempt_at,organization_id,workspace_id,environment_id,run_id) WHERE accepted_at IS NULL;

CREATE FUNCTION zasp_temporal78.pending() RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $pending$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;items jsonb:='[]';
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding start delivery unavailable';END IF;
 FOR x IN SELECT a.* FROM zasp_temporal78.start_deliveries d JOIN zasp_temporal78.run_owners a USING(organization_id,workspace_id,environment_id,run_id)
 WHERE d.accepted_at IS NULL ORDER BY d.last_attempt_at,d.organization_id,d.workspace_id,d.environment_id,d.run_id LIMIT 5 LOOP
  PERFORM zasp_temporal78.start_identity(jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'definition_version',x.definition_version,'input_digest',x.input_digest));
  UPDATE zasp_temporal78.start_deliveries SET last_attempt_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  items:=items||jsonb_build_array(jsonb_build_object('ref',jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id),'definition_version',x.definition_version,'input_digest',x.input_digest));
 END LOOP;
 RETURN items;
END $pending$;

CREATE FUNCTION zasp_temporal78.accept_start(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $accept$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;t timestamptz;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding start acceptance unavailable';END IF;
 x:=zasp_temporal78.start_identity(q);
 UPDATE zasp_temporal78.start_deliveries SET accepted_at=COALESCE(accepted_at,clock_timestamp()) WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) RETURNING accepted_at INTO t;
 IF t IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding unattempted start acknowledgement';END IF;
 RETURN jsonb_build_object('workflow_id',x.workflow_id,'accepted_at',to_char(t AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $accept$;
