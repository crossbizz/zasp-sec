-- Additive private80 profile. No canonical schema-version row.
CREATE SCHEMA zasp_temporal_single_recovery AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal_single_recovery FROM PUBLIC;
CREATE TABLE zasp_temporal_single_recovery.registration(singleton boolean PRIMARY KEY CHECK(singleton),profile text NOT NULL,checksum text NOT NULL);
CREATE TABLE zasp_temporal_single_recovery.commands(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 command_id text NOT NULL,command_digest bytea NOT NULL CHECK(octet_length(command_digest)=32),command jsonb NOT NULL CHECK(octet_length(command::text)<=65536),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),UNIQUE(organization_id,workspace_id,environment_id,command_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal74.run_owners);
CREATE TABLE zasp_temporal_single_recovery.request_receipts(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 actor_id text NOT NULL,idempotency_key text NOT NULL,audit_id text NOT NULL,correlation_id text NOT NULL,receipt_id text NOT NULL,expected_version bigint NOT NULL,
 intent jsonb NOT NULL,intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),response jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,actor_id,idempotency_key),UNIQUE(organization_id,workspace_id,environment_id,receipt_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal74.run_owners);
CREATE TABLE zasp_temporal_single_recovery.audit(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 audit_id text NOT NULL,correlation_id text NOT NULL,actor_id text NOT NULL,event_kind text NOT NULL CHECK(event_kind IN('cleanup_recovery_requested','cleanup_recovery_completed')),
 body jsonb NOT NULL,body_digest bytea NOT NULL CHECK(octet_length(body_digest)=32),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,workspace_id,environment_id,audit_id));
CREATE TABLE zasp_temporal_single_recovery.deliveries(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,command_id text NOT NULL,last_attempt_at timestamptz,accepted_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),FOREIGN KEY(organization_id,workspace_id,environment_id,command_id) REFERENCES zasp_temporal_single_recovery.commands(organization_id,workspace_id,environment_id,command_id));
CREATE TABLE zasp_temporal_single_recovery.progress(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,command_id text NOT NULL,
 status text NOT NULL CHECK(status IN('queued','pending','repair_required')),reason text NOT NULL CHECK(reason IN('queued','cleanup_pending','dependency_unavailable','evidence_conflict')),version bigint NOT NULL CHECK(version>0),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),FOREIGN KEY(organization_id,workspace_id,environment_id,command_id) REFERENCES zasp_temporal_single_recovery.commands(organization_id,workspace_id,environment_id,command_id));
CREATE TABLE zasp_temporal_single_recovery.completion_receipts(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,command_id text NOT NULL,receipt_id text NOT NULL,
 command_digest bytea NOT NULL CHECK(octet_length(command_digest)=32),evidence_digest bytea NOT NULL CHECK(octet_length(evidence_digest)=32),evidence_kind text NOT NULL,outcome text NOT NULL,completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),body jsonb NOT NULL,body_digest bytea NOT NULL CHECK(octet_length(body_digest)=32),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),UNIQUE(organization_id,workspace_id,environment_id,receipt_id),FOREIGN KEY(organization_id,workspace_id,environment_id,command_id) REFERENCES zasp_temporal_single_recovery.commands(organization_id,workspace_id,environment_id,command_id));
-- Seed before FORCE RLS. The registered migration login is not current_user
-- zasp_discovery_authority; no policy exception or extra grant is needed.
INSERT INTO zasp_temporal_single_recovery.registration VALUES(true,'production_temporal_single_test_cleanup_recovery','-- recovery checksum');
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','commands','request_receipts','audit','deliveries','progress','completion_receipts'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal_single_recovery.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal_single_recovery.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal_single_recovery.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal_single_recovery.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  IF n NOT IN('deliveries','progress') THEN EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal_single_recovery.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);END IF;
 END LOOP;
END $tables$;

CREATE FUNCTION zasp_temporal_single_recovery.start_wire(x zasp_temporal74.run_owners) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $body$
 SELECT jsonb_build_object('ref',jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id),'definition_version',x.definition_version,'input_digest',x.input_digest)
$body$;
CREATE FUNCTION zasp_temporal_single_recovery.owner(q jsonb) RETURNS zasp_temporal74.run_owners LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $body$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;r public.zasp_security_agent_runs%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;
BEGIN
 x:=zasp_temporal74.start_identity(jsonb_build_object('organization_id',q->>'organization_id','workspace_id',q->>'workspace_id','environment_id',q->>'environment_id','run_id',q->>'run_id','definition_version',q->'definition_version','input_digest',q->>'input_digest'));
 SELECT * INTO STRICT r FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR SHARE NOWAIT;
 SELECT * INTO STRICT h FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) FOR SHARE NOWAIT;
 IF (r.definition_id,r.definition_version) IS DISTINCT FROM(x.definition_id,x.definition_version)
 OR x.source_kind NOT IN('manual65','automatic73') OR x.action_key NOT IN('run_test','rerun_test')
 OR h.definition_digest IS DISTINCT FROM digest(convert_to(h.definition::text,'UTF8'),'sha256')
 OR h.definition->'allowed_actions' IS DISTINCT FROM jsonb_build_array(x.action_key)
 OR x.step_id IS DISTINCT FROM public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_step',x.run_id||chr(31)||'0')
 OR x.test_run_id IS DISTINCT FROM public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_test_run',x.run_id||chr(31)||x.step_id||chr(31)||x.action_key)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery ancestry changed';END IF;
 RETURN x;
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.obligations(x zasp_temporal74.run_owners) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $body$
 SELECT jsonb_build_object(
 'planning',(SELECT jsonb_build_object('definition_version',j.definition_version,'reservation_id',j.reservation_id,'input_digest',j.input_digest) FROM zasp_temporal74.planning_jobs j WHERE(j.organization_id,j.workspace_id,j.environment_id,j.run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)),
 'reservations',COALESCE((SELECT jsonb_agg(jsonb_build_object('attempt',p.attempt,'reservation_id',p.reservation_id,'input_digest',encode(p.input_digest,'hex'),'model',p.model,'cost_policy_version',p.cost_policy_version,'maximum_tokens',p.maximum_tokens,'maximum_cost_nano_credits',p.maximum_cost_nano_credits) ORDER BY p.attempt,p.reservation_id COLLATE "C") FROM zasp_temporal74.provider_reservations p WHERE(p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)),'[]'::jsonb),
 'effect',(SELECT jsonb_build_object('step_id',f.step_id,'generation',f.generation,'effect_key',f.effect_key,'input_digest',encode(f.input_digest,'hex'),'snapshot_digest',encode(f.snapshot_digest,'hex')) FROM zasp_temporal74.effects f WHERE(f.organization_id,f.workspace_id,f.environment_id,f.run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)),
 'invocations',COALESCE((SELECT jsonb_agg(jsonb_build_object('child',i.test_run_id,'category',i.category,'attempt',i.attempt,'effect_key',i.effect_key,'input_digest',encode(i.input_digest,'hex'),'request_digest',encode(i.request_digest,'hex'),'target_resolution_digest',encode(digest(convert_to(i.target_resolution::text,'UTF8'),'sha256'),'hex')) ORDER BY i.test_run_id COLLATE "C",i.category COLLATE "C",i.attempt) FROM zasp_temporal74.invocations i WHERE(i.organization_id,i.workspace_id,i.environment_id,i.test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id)),'[]'::jsonb))
$body$;
CREATE FUNCTION zasp_temporal_single_recovery.proof(x zasp_temporal74.run_owners) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $body$
DECLARE v jsonb;j zasp_temporal74.planning_jobs%ROWTYPE;
BEGIN
 IF EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  v:=zasp_temporal74.parent_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);RETURN jsonb_build_object('kind','parent','value',v);
 ELSIF EXISTS(SELECT 1 FROM zasp_temporal74.stops WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  v:=zasp_authorization80_worker.test74_stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);RETURN jsonb_build_object('kind','stop','value',v);
 END IF;
 SELECT * INTO j FROM zasp_temporal74.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF j.state='needs_human' THEN
  IF NOT zasp_temporal74.planning_terminal_valid(x.organization_id,x.workspace_id,x.environment_id,x.run_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery planning proof changed';END IF;
  RETURN jsonb_build_object('kind','planning_terminal','value',jsonb_build_object('definition_version',j.definition_version,'reservation_id',j.reservation_id,'input_digest',j.input_digest,'state',j.state));
 END IF;
 RETURN NULL;
END $body$;

-- recovery admission
-- recovery delivery
-- recovery settlement
-- recovery catalog source

DO $grants$ DECLARE f record;BEGIN
 FOR f IN SELECT p.oid::regprocedure::text AS signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_temporal_single_recovery' LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature);
 END LOOP;
END $grants$;
GRANT USAGE ON SCHEMA zasp_temporal_single_recovery TO zasp_security_agent_api,zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal_single_recovery.preflight(jsonb),zasp_temporal_single_recovery.admit(jsonb),zasp_temporal_single_recovery.get(text,text,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal_single_recovery.pending(),zasp_temporal_single_recovery.attempt(jsonb),zasp_temporal_single_recovery.ack(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal_single_recovery.load(jsonb),zasp_temporal_single_recovery.observe(jsonb,text),zasp_temporal_single_recovery.finish(jsonb) TO zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal_single_recovery.ready(text) TO zasp_security_agent_api,zasp_temporal_executor,zasp_temporal_compensation;
