-- Ordered delegation is derived from retained66/65 admission and native61
-- context. Only identifiers, immutable hashes, and an expiry leave this reader.
CREATE TABLE zasp_authorization80_worker.ordered_associations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 principal_id text NOT NULL,grantor_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,
 definition_digest text NOT NULL,source_digest text NOT NULL,test_id text NOT NULL,test_version bigint NOT NULL,
 target_id text NOT NULL,target_kind text NOT NULL CHECK(target_kind IN('agent','tool')),target_digest text NOT NULL,
 trigger_kind text NOT NULL CHECK(trigger_kind IN('finding','attack_path')),trigger_id text NOT NULL,credential_binding_id text NOT NULL,
 snapshot_id text NOT NULL,evidence_id text NOT NULL,integration_id text NOT NULL,source text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id));
CREATE TABLE zasp_authorization80_worker.ordered_state(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 definition_id text NOT NULL,definition_version bigint NOT NULL,state text NOT NULL,run_version bigint NOT NULL,present boolean NOT NULL,
 target_current boolean NOT NULL,fresh_until timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_authorization80_worker.ordered_associations);
DO $ordered_tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['ordered_associations','ordered_state'] LOOP
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_authorization80_worker.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n);
 END LOOP;
END $ordered_tables$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_worker.ordered_associations FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON zasp_authorization80_worker.ordered_state FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE TRIGGER worker_revision AFTER INSERT ON zasp_authorization80_worker.ordered_associations FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,run_id');
CREATE TRIGGER worker_revision AFTER INSERT OR UPDATE OR DELETE ON zasp_authorization80_worker.ordered_state FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,state,run_version,present,target_current,fresh_until');

CREATE FUNCTION zasp_authorization80_worker.ordered68_facts(compensation boolean,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $ordered_facts$
DECLARE x zasp_temporal66.run_owners%ROWTYPE;r public.zasp_security_agent_runs%ROWTYPE;c zasp_temporal65.commands%ROWTYPE;
 tr public.zasp_security_agent_trigger_receipts%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;a zasp_authorization80_worker.ordered_associations%ROWTYPE;
 cv jsonb;resolution jsonb;metadata jsonb;checks jsonb;source_hash text;target_hash text;product text;expires timestamptz;k text;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered source requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF compensation IS NULL OR NOT zasp_temporal68.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.principal_ready(CASE WHEN compensation THEN 'zasp_temporal_compensation' ELSE 'zasp_temporal_executor' END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered source principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest']) OR octet_length(q::text)>4096
  OR jsonb_typeof(q->'definition_version') IS DISTINCT FROM 'number' OR NOT COALESCE(q->>'definition_version'~'^([1-9][0-9]{0,5}|1000000)$',false)
  OR jsonb_typeof(q->'input_digest') IS DISTINCT FROM 'string' OR NOT COALESCE(q->>'input_digest'~'^[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered start rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered source scope rejected';END IF;
 END LOOP;
 SELECT * INTO x FROM zasp_temporal66.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id') FOR SHARE;
 IF x.run_id IS NULL OR x.execution_owner<>'temporal' OR to_jsonb(x.definition_version) IS DISTINCT FROM q->'definition_version' OR x.input_digest IS DISTINCT FROM q->>'input_digest' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered owner changed';END IF;
 SELECT * INTO r FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR SHARE;
 IF r.run_id IS NULL OR r.definition_version<>x.definition_version OR r.lease_owner IS NOT NULL OR r.lease_token IS NOT NULL OR r.lease_expires_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered parent changed';END IF;
 SELECT * INTO c FROM zasp_temporal65.commands WHERE(organization_id,workspace_id,environment_id,run_id,kind)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,'start') FOR SHARE;
 SELECT * INTO tr FROM public.zasp_security_agent_trigger_receipts WHERE(organization_id,workspace_id,environment_id,run_id,definition_id,trigger_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,r.definition_id,r.trigger_id) FOR SHARE;
 IF c.run_id IS NULL OR c.execution_owner<>'temporal' OR(c.definition_version,c.input_digest) IS DISTINCT FROM(x.definition_version,x.input_digest)
  OR tr.run_id IS NULL OR encode(tr.trigger_digest,'hex') IS DISTINCT FROM x.input_digest OR tr.trigger_kind NOT IN('finding','attack_path')
  OR r.run_id IS DISTINCT FROM public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_run',r.definition_id||chr(31)||r.trigger_id||chr(31)||tr.trigger_version::text) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered retained start changed';END IF;
 SELECT * INTO h FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(r.organization_id,r.workspace_id,r.environment_id,r.definition_id,r.definition_version) FOR SHARE;
 IF h.definition_id IS NULL OR h.definition_digest IS DISTINCT FROM digest(convert_to(h.definition::text,'UTF8'),'sha256') OR h.definition->'allowed_actions' IS DISTINCT FROM '["create_temporary_policy","run_test"]'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered historical definition changed';END IF;
 source_hash:=encode(digest(convert_to(jsonb_build_array(x.execution_owner,r.definition_id,x.definition_version,x.input_digest,c.event_id,tr.trigger_kind,tr.trigger_id,tr.trigger_version,encode(h.definition_digest,'hex'))::text,'UTF8'),'sha256'),'hex');
 SELECT * INTO a FROM zasp_authorization80_worker.ordered_associations WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF compensation THEN
  IF a.run_id IS NULL OR(a.definition_id,a.definition_version,a.definition_digest,a.source_digest) IS DISTINCT FROM(r.definition_id,r.definition_version,encode(h.definition_digest,'hex'),source_hash)
   OR NOT EXISTS(SELECT 1 FROM zasp_temporal68.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered captured planning absent';END IF;
  metadata:=to_jsonb(a);checks:='[]'::jsonb;
 ELSE
  IF r.state NOT IN('queued','planning','waiting_approval') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered task inactive';END IF;
  cv:=zasp_sa_multistep_prior.context(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  IF cv->'definition' IS DISTINCT FROM h.definition THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered definition binding changed';END IF;
  resolution:=zasp_temporal68.test_target(x.organization_id,x.workspace_id,x.environment_id,cv->'test'->>'target_id',cv->'test'->>'target_kind',cv->'test'->>'definition_id',(cv->'test'->>'version')::bigint);
  SELECT i.product_kind,least(i.fresh_until,b.valid_until) INTO STRICT product,expires FROM public.zasp_inventory_entities i JOIN public.zasp_attack_lab_credential_bindings b ON(b.organization_id,b.workspace_id,b.environment_id,b.binding_id)=(i.organization_id,i.workspace_id,i.environment_id,resolution#>>'{comparison,credential_binding_id}') WHERE(i.organization_id,i.workspace_id,i.environment_id,i.id)=(x.organization_id,x.workspace_id,x.environment_id,cv->'test'->>'target_id') FOR SHARE OF i,b;
  IF product IS NULL OR product NOT IN('agent','tool') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered target kind rejected';END IF;
  IF expires IS NULL OR expires<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered target expired';END IF;
  target_hash:=encode(digest(convert_to(resolution::text,'UTF8'),'sha256'),'hex');
  metadata:=jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,
   'principal_id',public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_definition_service',r.definition_id),'grantor_id',r.requested_by,
   'definition_id',r.definition_id,'definition_version',r.definition_version,'definition_digest',encode(h.definition_digest,'hex'),'source_digest',source_hash,
   'test_id',cv->'test'->>'definition_id','test_version',cv->'test'->'version','target_id',cv->'test'->>'target_id','target_kind',product,'target_digest',target_hash,
   'trigger_kind',tr.trigger_kind,'trigger_id',tr.trigger_id,'credential_binding_id',resolution#>>'{comparison,credential_binding_id}',
   'snapshot_id',resolution#>>'{provenance,snapshot_id}','evidence_id',resolution#>>'{provenance,evidence_id}','integration_id',resolution#>>'{provenance,integration_id}','source',resolution#>>'{provenance,source}');
  checks:=jsonb_build_array(jsonb_build_object('kind','security_agent','id',r.definition_id,'permission','manage_workflows'),jsonb_build_object('kind','security_agent_run','id',r.run_id,'permission','manage_workflows'),jsonb_build_object('kind','test','id',cv->'test'->>'definition_id','permission','view'),jsonb_build_object('kind',product,'id',cv->'test'->>'target_id','permission','view'),jsonb_build_object('kind',tr.trigger_kind,'id',tr.trigger_id,'permission','view'));
 END IF;
 RETURN metadata||jsonb_build_object('run_state',r.state,'run_version',r.version,'checks',checks,'session_user',session_user,'fresh_until_ms',CASE WHEN compensation THEN NULL ELSE floor(extract(epoch FROM expires)*1000)::bigint END);
END $ordered_facts$;

CREATE FUNCTION zasp_authorization80_worker.prepare_ordered68(q jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $prepare_ordered$
DECLARE f jsonb;a zasp_authorization80_worker.ordered_associations%ROWTYPE;BEGIN
 f:=zasp_authorization80_worker.ordered68_facts(false,q);
 a:=jsonb_populate_record(NULL::zasp_authorization80_worker.ordered_associations,f);
 INSERT INTO zasp_authorization80_worker.ordered_associations SELECT a.* ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_associations s WHERE s=a) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered association changed';END IF;
 INSERT INTO zasp_authorization80_worker.ordered_state VALUES(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true,true,to_timestamp((f->>'fresh_until_ms')::numeric/1000)) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present,s.target_current)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true,true) AND s.fresh_until>clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered capture changed';END IF;
END $prepare_ordered$;
CREATE FUNCTION zasp_authorization80_worker.ordered68_source(compensation boolean,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $ordered_source$
DECLARE f jsonb;a zasp_authorization80_worker.ordered_associations%ROWTYPE;BEGIN
 f:=zasp_authorization80_worker.ordered68_facts(compensation,q);a:=jsonb_populate_record(NULL::zasp_authorization80_worker.ordered_associations,f);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_associations s WHERE s=a) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered association missing';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true) AND(compensation OR s.target_current AND s.fresh_until>clock_timestamp())) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered state capture changed';END IF;
 RETURN f;
END $ordered_source$;

-- Existing capture functions remain authoritative for their own families.
-- These exact scoped triggers update only already-derived ordered metadata.
CREATE FUNCTION zasp_authorization80_worker.capture_ordered_run() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $run_capture$
BEGIN
 IF TG_OP='DELETE' OR(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id) IS DISTINCT FROM(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id) THEN
  UPDATE zasp_authorization80_worker.ordered_state SET present=false WHERE(organization_id,workspace_id,environment_id,run_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id);
 ELSE
  UPDATE zasp_authorization80_worker.ordered_state SET definition_id=NEW.definition_id,definition_version=NEW.definition_version,state=NEW.state,run_version=NEW.version,
   target_current=target_current AND(OLD.definition_id,OLD.definition_version,OLD.requested_by,OLD.trigger_id) IS NOT DISTINCT FROM(NEW.definition_id,NEW.definition_version,NEW.requested_by,NEW.trigger_id)
   WHERE(organization_id,workspace_id,environment_id,run_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id);
 END IF;RETURN NULL;
END $run_capture$;
CREATE TRIGGER zasp_authorization80_worker_ordered_run AFTER UPDATE OR DELETE ON public.zasp_security_agent_runs FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.capture_ordered_run();
CREATE FUNCTION zasp_authorization80_worker.capture_ordered_target() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $target_capture$
DECLARE v jsonb:=to_jsonb(OLD);BEGIN
 IF TG_OP='UPDATE' AND v=to_jsonb(NEW) THEN RETURN NEW;END IF;
 UPDATE zasp_authorization80_worker.ordered_state s SET target_current=false FROM zasp_authorization80_worker.ordered_associations a
 WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id) AND s.target_current
 AND(a.organization_id,a.workspace_id,a.environment_id)=(v->>'organization_id',v->>'workspace_id',v->>'environment_id') AND CASE TG_TABLE_NAME
  WHEN 'zasp_red_team_definitions' THEN a.test_id=v->>'definition_id'
  WHEN 'zasp_inventory_entities' THEN a.target_id=v->>'id'
  WHEN 'zasp_inventory_evidence' THEN a.evidence_id=v->>'id'
  WHEN 'zasp_discovery_snapshots' THEN a.snapshot_id=v->>'id'
  WHEN 'zasp_inventory_source_observations' THEN(a.target_id,a.integration_id,a.source,a.snapshot_id,a.evidence_id)=(v->>'entity_id',v->>'integration_id',v->>'source',v->>'snapshot_id',v->>'evidence_id')
  WHEN 'zasp_attack_lab_credential_bindings' THEN a.credential_binding_id=v->>'binding_id'
  WHEN 'zasp_risk_findings' THEN a.trigger_kind='finding' AND a.trigger_id=v->>'id'
  WHEN 'zasp_risk_attack_paths' THEN a.trigger_kind='attack_path' AND a.trigger_id=v->>'id'
  ELSE false END;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $target_capture$;
DO $ordered_triggers$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['zasp_red_team_definitions','zasp_inventory_entities','zasp_inventory_evidence','zasp_discovery_snapshots','zasp_inventory_source_observations','zasp_attack_lab_credential_bindings','zasp_risk_findings','zasp_risk_attack_paths'] LOOP
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_ordered_target BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.capture_ordered_target()',n);
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_ordered_no_truncate BEFORE TRUNCATE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $ordered_triggers$;
CREATE FUNCTION zasp_authorization80_worker.expire_ordered_targets(o text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $ordered_expiry$
BEGIN
 IF NOT zasp_authorization79.worker() OR NOT zasp_authorization79.locked(o) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered expiry session rejected';END IF;
 UPDATE zasp_authorization80_worker.ordered_state SET target_current=false WHERE organization_id=o AND target_current AND fresh_until<=clock_timestamp();
END $ordered_expiry$;
CREATE VIEW zasp_authorization80_worker.active_ordered AS
 SELECT a.* FROM zasp_authorization80_worker.ordered_associations a JOIN zasp_authorization80_worker.ordered_state s USING(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version)
 JOIN public.zasp_security_agent_definitions d ON(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version)
 JOIN public.zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(a.organization_id,a.grantor_id)
 WHERE s.present AND s.target_current AND s.fresh_until>clock_timestamp() AND s.state IN('queued','planning','waiting_approval') AND m.active AND d.deleted_at IS NULL AND d.activation='supervised' AND d.body->'enabled'='true'::jsonb;
ALTER VIEW zasp_authorization80_worker.active_ordered OWNER TO zasp_discovery_authority;
DO $ordered_views$ DECLARE d text;BEGIN
 SELECT pg_get_viewdef('zasp_authorization79.members'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.members AS '||rtrim(d,E';\n ')||' UNION SELECT organization_id,''service''::text,principal_id,''''::text FROM zasp_authorization80_worker.active_ordered';
 SELECT pg_get_viewdef('zasp_authorization79.current_grants'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.current_grants AS '||rtrim(d,E';\n ')||$grants$ UNION SELECT a.organization_id,a.workspace_id,a.environment_id,t.kind,t.id,'service'::text,a.principal_id,t.permission,a.run_id FROM zasp_authorization80_worker.active_ordered a CROSS JOIN LATERAL(VALUES('security_agent'::text,a.definition_id,'manage_workflows'::text),('security_agent_run',a.run_id,'manage_workflows'),('test',a.test_id,'view'),(a.target_kind,a.target_id,'view'),(a.trigger_kind,a.trigger_id,'view')) t(kind,id,permission)$grants$;
 SELECT pg_get_viewdef('zasp_authorization79.resources'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.resources AS '||rtrim(d,E';\n ')||' UNION SELECT organization_id,workspace_id,environment_id,''security_agent_run''::text,run_id FROM zasp_authorization80_worker.ordered_state WHERE present';
END $ordered_views$;
