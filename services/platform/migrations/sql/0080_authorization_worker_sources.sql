-- All finding source facts originate in a validated native admission. This
-- private validator is shared by materialization, metadata and effect fencing.
CREATE FUNCTION zasp_authorization80_worker.finding_facts(operation_value text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $facts$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;r public.zasp_security_agent_runs%ROWTYPE;g zasp_temporal78.service_grants%ROWTYPE;a zasp_authorization80_worker.associations%ROWTYPE;grantor text;principal_value text;source_hash text;p jsonb;checks jsonb;receipt_hash text;cleanup boolean:=operation_value='finding.cleanup';replay boolean:=operation_value='finding.replay';
BEGIN
 IF operation_value NOT IN('finding.prepare','finding.apply','finding.replay','finding.cleanup','finding.planning') OR NOT zasp_temporal78.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.principal_ready(CASE WHEN cleanup THEN 'zasp_temporal_compensation' ELSE 'zasp_temporal_executor' END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker source reader rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest']||CASE WHEN cleanup THEN ARRAY['reason'] ELSE ARRAY[]::text[] END) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker source reference rejected';END IF;
 x:=zasp_temporal78.start_identity(q-'reason');
 SELECT * INTO STRICT r FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR SHARE;
 principal_value:=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_definition_service',x.definition_id);
 source_hash:=encode(digest(convert_to(jsonb_build_array(x.source_kind,x.definition_id,x.definition_version,x.input_digest,encode(x.snapshot_digest,'hex'))::text,'UTF8'),'sha256'),'hex');
 SELECT * INTO a FROM zasp_authorization80_worker.associations WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF cleanup OR replay THEN
  IF a.run_id IS NULL OR(a.principal_id,a.definition_id,a.definition_version,a.finding_id,a.source_digest) IS DISTINCT FROM(principal_value,x.definition_id,x.definition_version,x.trigger_id,source_hash)
   OR NOT EXISTS(SELECT 1 FROM zasp_temporal78.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) AND NOT(cleanup AND(r.state='queued' OR EXISTS(SELECT 1 FROM zasp_temporal78.stops WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)))) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker captured cleanup unavailable';END IF;
  grantor:=a.grantor_id;checks:='[]'::jsonb;
  IF replay THEN receipt_hash:=encode(digest(convert_to(zasp_temporal78.effect_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id)::text,'UTF8'),'sha256'),'hex');END IF;
  -- Queued cancellation settles the already captured native start intent.
  -- Repeats require the immutable stop receipt, never a bare cancelled state.
  IF cleanup AND EXISTS(SELECT 1 FROM zasp_temporal78.stops WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN receipt_hash:=encode(digest(convert_to(zasp_temporal78.stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id)::text,'UTF8'),'sha256'),'hex');END IF;
 ELSE
  IF r.state NOT IN('queued','planning','waiting_approval') OR EXISTS(SELECT 1 FROM zasp_authorization80_worker.revocations WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker task inactive';END IF;
  -- Existing context validates immutable78/66/65 provenance, native definition,
  -- grantor membership/scope, target snapshot and current source controls. Its
  -- tenant body stays inside SQL; only typed authority metadata leaves here.
  PERFORM zasp_temporal78.context(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  IF x.source_kind='automatic77' THEN
   SELECT * INTO STRICT g FROM zasp_temporal78.service_grants WHERE(organization_id,workspace_id,environment_id,definition_id,definition_version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) FOR SHARE;
   principal_value:=g.principal_id;grantor:=g.grantor_id;
  ELSE grantor:=r.requested_by;END IF;
  IF operation_value='finding.apply' THEN PERFORM zasp_temporal78.current_step(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);END IF;
  checks:=jsonb_build_array(jsonb_build_object('kind','finding','id',x.trigger_id,'permission',CASE operation_value WHEN 'finding.planning' THEN 'view' ELSE 'manage_findings' END),jsonb_build_object('kind','security_agent','id',x.definition_id,'permission','manage_workflows'),jsonb_build_object('kind','security_agent_run','id',x.run_id,'permission','manage_workflows'));
 END IF;
 SELECT jsonb_build_object('plan_hash',encode(plan_hash,'hex'),'step_digest',encode(s.input_digest,'hex')) INTO p FROM public.zasp_security_agent_plans p JOIN public.zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE(p.organization_id,p.workspace_id,p.environment_id,p.run_id,s.step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);
 RETURN jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'step_id',x.step_id,'effect_id',public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_effect',x.run_id||chr(31)||x.step_id||chr(31)||x.action_key),'principal_id',principal_value,'grantor_id',grantor,'definition_id',x.definition_id,'definition_version',x.definition_version,'finding_id',x.trigger_id,'target_version',x.trigger_version,'source_digest',source_hash,'run_version',r.version,'run_state',r.state,'plan',p,'checks',checks,'session_user',session_user,'receipt_digest',receipt_hash);
END $facts$;

CREATE FUNCTION zasp_authorization80_worker.prepare_finding(q jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $prepare$
DECLARE f jsonb;a zasp_authorization80_worker.associations%ROWTYPE;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='worker preparation requires read committed';END IF;
 f:=zasp_authorization80_worker.finding_facts('finding.prepare',q);
 INSERT INTO zasp_authorization80_worker.associations(organization_id,workspace_id,environment_id,run_id,principal_id,grantor_id,definition_id,definition_version,finding_id,source_digest)
 VALUES(f->>'organization_id',f->>'workspace_id',f->>'environment_id',f->>'run_id',f->>'principal_id',f->>'grantor_id',f->>'definition_id',(f->>'definition_version')::bigint,f->>'finding_id',f->>'source_digest') ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT a FROM zasp_authorization80_worker.associations WHERE(organization_id,workspace_id,environment_id,run_id)=(f->>'organization_id',f->>'workspace_id',f->>'environment_id',f->>'run_id');
 IF(a.principal_id,a.grantor_id,a.definition_id,a.definition_version,a.finding_id,a.source_digest) IS DISTINCT FROM(f->>'principal_id',f->>'grantor_id',f->>'definition_id',(f->>'definition_version')::bigint,f->>'finding_id',f->>'source_digest') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker association changed';END IF;
 -- finding_facts retains the real run row SHARE lock until this transaction
 -- commits. An updater cannot race the initial metadata capture.
 INSERT INTO zasp_authorization80_worker.run_state VALUES(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.run_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker run capture changed';END IF;
END $prepare$;
CREATE FUNCTION zasp_authorization80_worker.finding_source(operation_value text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $source$
DECLARE f jsonb;BEGIN
 IF operation_value NOT IN('finding.apply','finding.replay','finding.cleanup','finding.planning') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker operation rejected';END IF;
 f:=zasp_authorization80_worker.finding_facts(operation_value,q);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.associations a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.principal_id,a.grantor_id,a.source_digest)=(f->>'organization_id',f->>'workspace_id',f->>'environment_id',f->>'run_id',f->>'principal_id',f->>'grantor_id',f->>'source_digest')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker association missing';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.run_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present)=(f->>'organization_id',f->>'workspace_id',f->>'environment_id',f->>'run_id',f->>'definition_id',(f->>'definition_version')::bigint,f->>'run_state',(f->>'run_version')::bigint,true)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker run capture changed';END IF;
 RETURN f;
END $source$;
CREATE FUNCTION zasp_authorization80_worker.revision(o text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $revision$
BEGIN
 IF NOT zasp_temporal78.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker revision reader rejected';END IF;
 RETURN(SELECT jsonb_build_object('organization_id',organization_id,'desired',desired,'applied',applied,'generation',generation,'store_id',store_id,'model_id',model_id) FROM zasp_authorization79.organizations WHERE organization_id=o);
END $revision$;

CREATE TRIGGER worker_revision AFTER INSERT ON zasp_authorization80_worker.associations FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,run_id,principal_id,grantor_id,definition_id,definition_version,finding_id,source_digest');
CREATE TRIGGER worker_revision BEFORE INSERT ON zasp_authorization80_worker.revocations FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,run_id');
CREATE TRIGGER worker_revision AFTER INSERT OR UPDATE OR DELETE ON zasp_authorization80_worker.run_state FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,state,run_version,present');
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON zasp_authorization80_worker.run_state FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

-- Captures only a delegation that native preparation already validated. There
-- is no new association on an arbitrary run insert or identity change.
CREATE FUNCTION zasp_authorization80_worker.capture_run() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $capture_run$
BEGIN
 IF TG_OP='DELETE' THEN
  UPDATE zasp_authorization80_worker.run_state SET present=false WHERE(organization_id,workspace_id,environment_id,run_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id);
  UPDATE zasp_authorization80_worker.test_state SET present=false WHERE(organization_id,workspace_id,environment_id,run_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id);
 ELSE
  IF(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id) IS DISTINCT FROM(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id) THEN
   UPDATE zasp_authorization80_worker.run_state SET present=false WHERE(organization_id,workspace_id,environment_id,run_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id);
   UPDATE zasp_authorization80_worker.test_state SET present=false WHERE(organization_id,workspace_id,environment_id,run_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id);
  ELSE
   UPDATE zasp_authorization80_worker.run_state SET definition_id=NEW.definition_id,definition_version=NEW.definition_version,state=NEW.state,run_version=NEW.version
    WHERE(organization_id,workspace_id,environment_id,run_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id);
   UPDATE zasp_authorization80_worker.test_state SET definition_id=NEW.definition_id,definition_version=NEW.definition_version,state=NEW.state,run_version=NEW.version
    WHERE(organization_id,workspace_id,environment_id,run_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id);
  END IF;
 END IF;
 RETURN NULL;
END $capture_run$;
CREATE TRIGGER zasp_authorization80_worker_run_capture AFTER UPDATE OR DELETE ON public.zasp_security_agent_runs FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.capture_run();
CREATE TRIGGER zasp_authorization80_worker_no_truncate BEFORE TRUNCATE ON public.zasp_security_agent_runs FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE TRIGGER zasp_authorization80_worker_source_capture BEFORE UPDATE ON public.zasp_risk_findings FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,id,version,status');
CREATE TRIGGER zasp_authorization80_worker_source_capture BEFORE UPDATE ON public.zasp_security_agent_definitions FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,definition_id,version,activation,deleted_at,body');
CREATE FUNCTION zasp_authorization80_worker.capture_grant_revocation(o text,w text,e text,d text,v bigint) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $grant_capture$
 INSERT INTO zasp_authorization80_worker.revocations(organization_id,workspace_id,environment_id,run_id)
 SELECT organization_id,workspace_id,environment_id,run_id FROM zasp_authorization80_worker.associations WHERE(organization_id,workspace_id,environment_id,definition_id,definition_version)=(o,w,e,d,v) ON CONFLICT DO NOTHING
$grant_capture$;

CREATE VIEW zasp_authorization80_worker.active_associations AS
 SELECT a.* FROM zasp_authorization80_worker.associations a JOIN zasp_authorization80_worker.run_state r USING(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version)
 JOIN public.zasp_security_agent_definitions d ON(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version)
 JOIN public.zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(a.organization_id,a.grantor_id)
 WHERE r.present AND r.state IN('queued','planning','waiting_approval','running','verifying') AND m.active AND d.deleted_at IS NULL AND d.activation IN('supervised','autonomous') AND d.body->'enabled'='true'::jsonb
 AND NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.revocations v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id))
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.grant_revocations v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.definition_id,v.definition_version)=(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version));
ALTER VIEW zasp_authorization80_worker.active_associations OWNER TO zasp_discovery_authority;
DO $views$ DECLARE d text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_views WHERE signature='zasp_authorization79.members';
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.members AS '||rtrim(d,E';\n ')||' UNION SELECT organization_id,''service''::text,principal_id,''''::text FROM zasp_authorization80_worker.active_associations';
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_views WHERE signature='zasp_authorization79.current_grants';
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.current_grants AS '||rtrim(d,E';\n ')||$grant$ UNION SELECT a.organization_id,a.workspace_id,a.environment_id,t.kind,t.id,'service'::text,a.principal_id,t.permission,a.run_id FROM zasp_authorization80_worker.active_associations a CROSS JOIN LATERAL(VALUES('finding'::text,a.finding_id,'manage_findings'::text),('finding',a.finding_id,'view'),('security_agent',a.definition_id,'manage_workflows'),('security_agent_run',a.run_id,'manage_workflows')) t(kind,id,permission)$grant$;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_views WHERE signature='zasp_authorization79.resources';
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.resources AS '||rtrim(d,E';\n ')||' UNION SELECT organization_id,workspace_id,environment_id,''security_agent_run''::text,run_id FROM zasp_authorization80_worker.run_state WHERE present';
END $views$;
