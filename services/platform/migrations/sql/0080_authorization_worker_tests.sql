-- Test-family metadata is captured only from the real74 owner/context/target.
-- It contains identifiers and hashes, never endpoint or credential references.
CREATE TABLE zasp_authorization80_worker.test_associations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 principal_id text NOT NULL,grantor_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,definition_digest text NOT NULL CHECK(definition_digest~'^[a-f0-9]{64}$'),
 source_digest text NOT NULL,test_id text NOT NULL,test_version bigint NOT NULL,target_id text NOT NULL,target_kind text NOT NULL CHECK(target_kind IN('agent','tool')),
 native_target_kind text NOT NULL,target_digest text NOT NULL,trigger_kind text NOT NULL,trigger_id text NOT NULL,
 snapshot_id text NOT NULL,evidence_id text NOT NULL,integration_id text NOT NULL,source text NOT NULL,credential_binding_id text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id));
CREATE TABLE zasp_authorization80_worker.test_state(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 definition_id text NOT NULL,definition_version bigint NOT NULL,state text NOT NULL,run_version bigint NOT NULL,present boolean NOT NULL,
 target_current boolean NOT NULL,fresh_until timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_authorization80_worker.test_associations);
DO $test_tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['test_associations','test_state'] LOOP
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_authorization80_worker.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n);
 END LOOP;
END $test_tables$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_worker.test_associations FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON zasp_authorization80_worker.test_state FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE TRIGGER worker_revision AFTER INSERT ON zasp_authorization80_worker.test_associations FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,run_id');
CREATE TRIGGER worker_revision AFTER INSERT OR UPDATE OR DELETE ON zasp_authorization80_worker.test_state FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,state,run_version,present,target_current,fresh_until');

CREATE FUNCTION zasp_authorization80_worker.test74_private_facts(compensation boolean,q jsonb,execution boolean,parent_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $test_facts$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;r public.zasp_security_agent_runs%ROWTYPE;a zasp_authorization80_worker.test_associations%ROWTYPE;g zasp_temporal74.service_grants%ROWTYPE;
 binding jsonb;resolution jsonb;principal_value text;grantor text;definition_hash text;source_hash text;target_hash text;trigger_value text;product text;expires timestamptz;checks jsonb;metadata jsonb;
BEGIN
 IF compensation IS NULL OR execution IS NULL OR NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test source reader rejected';END IF;
 IF parent_value IS NULL THEN
  IF NOT zasp_temporal68.principal_ready(CASE WHEN compensation THEN 'zasp_temporal_compensation' ELSE 'zasp_temporal_executor' END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test source role rejected';END IF;
 ELSIF compensation OR NOT execution OR NOT zasp_temporal68.adapter_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker adapter source role rejected';END IF;
 x:=zasp_temporal74.start_identity(q);
 IF parent_value IS NULL THEN
  SELECT * INTO STRICT r FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR SHARE;
 ELSE
  r:=jsonb_populate_record(NULL::public.zasp_security_agent_runs,parent_value);
  IF(r.organization_id,r.workspace_id,r.environment_id,r.run_id) IS DISTINCT FROM(x.organization_id,x.workspace_id,x.environment_id,x.run_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker adapter parent rejected';END IF;
 END IF;
 SELECT encode(definition_digest,'hex') INTO STRICT definition_hash FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) FOR SHARE;
 source_hash:=encode(digest(convert_to(jsonb_build_array(x.source_kind,x.definition_id,x.definition_version,definition_hash,x.input_digest,x.trigger_id,x.trigger_version,x.action_key,x.step_id,x.test_run_id)::text,'UTF8'),'sha256'),'hex');
 SELECT * INTO a FROM zasp_authorization80_worker.test_associations WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF compensation THEN
  IF a.run_id IS NULL OR(a.definition_id,a.definition_version,a.definition_digest,a.source_digest) IS DISTINCT FROM(x.definition_id,x.definition_version,definition_hash,source_hash)
   OR NOT execution AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker captured test planning unavailable';END IF;
  metadata:=to_jsonb(a);checks:='[]'::jsonb;
 ELSE
  IF execution AND r.state NOT IN('queued','running') OR NOT execution AND r.state NOT IN('queued','planning','waiting_approval') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test task inactive';END IF;
  IF parent_value IS NULL THEN PERFORM zasp_temporal74.context(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  ELSE PERFORM zasp_temporal74.context_parent(x.organization_id,x.workspace_id,x.environment_id,x.run_id,parent_value);END IF;
  principal_value:=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_definition_service',x.definition_id);
  grantor:=r.requested_by;
  IF x.source_kind='automatic73' THEN
   SELECT * INTO STRICT g FROM zasp_temporal74.service_grants WHERE(organization_id,workspace_id,environment_id,definition_id,definition_version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) FOR SHARE;
   principal_value:=g.principal_id;grantor:=g.grantor_id;
  END IF;
  binding:=zasp_temporal71.body21(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version);
  resolution:=zasp_temporal74.test_target(x.organization_id,x.workspace_id,x.environment_id,binding->>'target_id',binding->>'target_kind',binding->>'definition_id',(binding->>'definition_version')::bigint);
  target_hash:=encode(digest(convert_to(resolution::text,'UTF8'),'sha256'),'hex');
  SELECT i.product_kind,least(i.fresh_until,c.valid_until) INTO STRICT product,expires FROM public.zasp_inventory_entities i JOIN public.zasp_attack_lab_credential_bindings c ON(c.organization_id,c.workspace_id,c.environment_id,c.binding_id)=(i.organization_id,i.workspace_id,i.environment_id,resolution#>>'{comparison,credential_binding_id}') WHERE(i.organization_id,i.workspace_id,i.environment_id,i.id)=(x.organization_id,x.workspace_id,x.environment_id,binding->>'target_id') FOR SHARE OF i,c;
  SELECT trigger_kind INTO STRICT trigger_value FROM public.zasp_security_agent_trigger_receipts WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  IF product NOT IN('agent','tool') OR trigger_value NOT IN('manual','finding','attack_path','runtime_decision') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test target kind rejected';END IF;
  -- Runtime-decision parent mapping remains unsupported until its exact device
  -- ancestry is implemented. A source kind can never reduce the Check set.
  IF trigger_value='runtime_decision' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test trigger unsupported';END IF;
  metadata:=jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'principal_id',principal_value,'grantor_id',grantor,'definition_id',x.definition_id,'definition_version',x.definition_version,'definition_digest',definition_hash,'source_digest',source_hash,
   'test_id',binding->>'definition_id','test_version',binding->'definition_version','target_id',binding->>'target_id','target_kind',product,'native_target_kind',binding->>'target_kind','target_digest',target_hash,'trigger_kind',trigger_value,'trigger_id',x.trigger_id,
   'snapshot_id',resolution#>>'{provenance,snapshot_id}','evidence_id',resolution#>>'{provenance,evidence_id}','integration_id',resolution#>>'{provenance,integration_id}','source',resolution#>>'{provenance,source}','credential_binding_id',resolution#>>'{comparison,credential_binding_id}');
  checks:=jsonb_build_array(jsonb_build_object('kind','security_agent','id',x.definition_id,'permission','manage_workflows'),jsonb_build_object('kind','security_agent_run','id',x.run_id,'permission','manage_workflows'),jsonb_build_object('kind','test','id',binding->>'definition_id','permission','view'),jsonb_build_object('kind',product,'id',binding->>'target_id','permission','view'));
  IF execution THEN
   checks:=jsonb_build_array(checks->0,checks->1,jsonb_build_object('kind','test','id',binding->>'definition_id','permission','run_tests'),jsonb_build_object('kind',product,'id',binding->>'target_id','permission','run_tests'));
  ELSIF trigger_value IN('finding','attack_path') THEN checks:=checks||jsonb_build_array(jsonb_build_object('kind',trigger_value,'id',x.trigger_id,'permission','view'));END IF;
 END IF;
 RETURN metadata||jsonb_build_object('run_state',r.state,'run_version',r.version,'checks',checks,'session_user',session_user,'fresh_until_ms',CASE WHEN compensation THEN NULL ELSE floor(extract(epoch FROM expires)*1000)::bigint END);
END $test_facts$;

CREATE FUNCTION zasp_authorization80_worker.test74_native_facts(compensation boolean,q jsonb,execution boolean) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $native_facts$
 SELECT zasp_authorization80_worker.test74_private_facts(compensation,q,execution,NULL)
$native_facts$;

CREATE FUNCTION zasp_authorization80_worker.test74_facts(compensation boolean,q jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $planning_facts$
 SELECT zasp_authorization80_worker.test74_native_facts(compensation,q,false)
$planning_facts$;

CREATE FUNCTION zasp_authorization80_worker.prepare_test74(q jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $test_prepare$
DECLARE f jsonb;a zasp_authorization80_worker.test_associations%ROWTYPE;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='worker preparation requires read committed';END IF;
 f:=zasp_authorization80_worker.test74_facts(false,q);
 a:=jsonb_populate_record(NULL::zasp_authorization80_worker.test_associations,f);
 INSERT INTO zasp_authorization80_worker.test_associations SELECT a.* ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_associations s WHERE s=a) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker test association changed';END IF;
 INSERT INTO zasp_authorization80_worker.test_state VALUES(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true,true,to_timestamp((f->>'fresh_until_ms')::numeric/1000)) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present,s.target_current)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true,true) AND s.fresh_until>clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker test capture changed';END IF;
END $test_prepare$;

CREATE FUNCTION zasp_authorization80_worker.test74_source(compensation boolean,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $test_source$
DECLARE f jsonb;a zasp_authorization80_worker.test_associations%ROWTYPE;BEGIN
 f:=zasp_authorization80_worker.test74_facts(compensation,q);a:=jsonb_populate_record(NULL::zasp_authorization80_worker.test_associations,f);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_associations s WHERE s=a) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test association missing';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true) AND(compensation OR s.target_current AND s.fresh_until>clock_timestamp())) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker test capture changed';END IF;
 RETURN f;
END $test_source$;

CREATE FUNCTION zasp_authorization80_worker.capture_test_target() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $target_capture$
DECLARE old_value jsonb:=to_jsonb(OLD);BEGIN
 IF TG_OP='UPDATE' AND old_value=to_jsonb(NEW) THEN RETURN NEW;END IF;
 UPDATE zasp_authorization80_worker.test_state s SET target_current=false
 FROM zasp_authorization80_worker.test_associations a
 WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id) AND s.target_current
 AND(a.organization_id,a.workspace_id,a.environment_id)=(old_value->>'organization_id',old_value->>'workspace_id',old_value->>'environment_id')
 AND CASE TG_TABLE_NAME
  WHEN 'zasp_red_team_definitions' THEN a.test_id=old_value->>'definition_id'
  WHEN 'zasp_inventory_entities' THEN a.target_id=old_value->>'id'
  WHEN 'zasp_inventory_evidence' THEN a.evidence_id=old_value->>'id'
  WHEN 'zasp_discovery_snapshots' THEN a.snapshot_id=old_value->>'id'
  WHEN 'zasp_inventory_source_observations' THEN(a.target_id,a.integration_id,a.source,a.snapshot_id,a.evidence_id)=(old_value->>'entity_id',old_value->>'integration_id',old_value->>'source',old_value->>'snapshot_id',old_value->>'evidence_id')
  WHEN 'zasp_attack_lab_credential_bindings' THEN a.credential_binding_id=old_value->>'binding_id'
  ELSE false END;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $target_capture$;
DO $target_triggers$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['zasp_red_team_definitions','zasp_inventory_entities','zasp_inventory_evidence','zasp_discovery_snapshots','zasp_inventory_source_observations','zasp_attack_lab_credential_bindings'] LOOP
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_target_capture BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.capture_test_target()',n);
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_target_no_truncate BEFORE TRUNCATE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $target_triggers$;
CREATE FUNCTION zasp_authorization80_worker.expire_test_targets(o text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $expiry$
BEGIN
 IF NOT zasp_authorization79.worker() OR NOT zasp_authorization79.locked(o) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker expiry session rejected';END IF;
 UPDATE zasp_authorization80_worker.test_state SET target_current=false WHERE organization_id=o AND target_current AND fresh_until<=clock_timestamp();
END $expiry$;
CREATE FUNCTION zasp_authorization80_worker.capture_test_revocation(o text,w text,e text,d text,v bigint) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $test_revocation$
BEGIN
 IF EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_associations WHERE(organization_id,workspace_id,environment_id,definition_id,definition_version)=(o,w,e,d,v)) THEN PERFORM zasp_authorization79.touch(o);END IF;
END $test_revocation$;

CREATE VIEW zasp_authorization80_worker.active_tests AS
 SELECT a.* FROM zasp_authorization80_worker.test_associations a JOIN zasp_authorization80_worker.test_state s USING(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version)
 JOIN public.zasp_security_agent_definitions d ON(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version)
 JOIN public.zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(a.organization_id,a.grantor_id)
 WHERE s.present AND s.target_current AND s.fresh_until>clock_timestamp() AND s.state IN('queued','planning','waiting_approval','running','verifying') AND m.active AND d.deleted_at IS NULL AND d.activation IN('supervised','autonomous') AND d.body->'enabled'='true'::jsonb
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.grant_revocations v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.definition_id,v.definition_version)=(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version));
ALTER VIEW zasp_authorization80_worker.active_tests OWNER TO zasp_discovery_authority;
DO $test_views$ DECLARE d text;BEGIN
 SELECT pg_get_viewdef('zasp_authorization79.members'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.members AS '||rtrim(d,E';\n ')||' UNION SELECT organization_id,''service''::text,principal_id,''''::text FROM zasp_authorization80_worker.active_tests';
 SELECT pg_get_viewdef('zasp_authorization79.current_grants'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.current_grants AS '||rtrim(d,E';\n ')||$grant$ UNION SELECT a.organization_id,a.workspace_id,a.environment_id,t.kind,t.id,'service'::text,a.principal_id,t.permission,a.run_id FROM zasp_authorization80_worker.active_tests a CROSS JOIN LATERAL(VALUES('security_agent'::text,a.definition_id,'manage_workflows'::text),('security_agent_run',a.run_id,'manage_workflows'),('test',a.test_id,'view'),(a.target_kind,a.target_id,'view'),('test',a.test_id,'run_tests'),(a.target_kind,a.target_id,'run_tests')) t(kind,id,permission)
 UNION SELECT organization_id,workspace_id,environment_id,trigger_kind,trigger_id,'service'::text,principal_id,'view'::text,run_id FROM zasp_authorization80_worker.active_tests WHERE trigger_kind IN('finding','attack_path')$grant$;
 SELECT pg_get_viewdef('zasp_authorization79.resources'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.resources AS '||rtrim(d,E';\n ')||' UNION SELECT organization_id,workspace_id,environment_id,''security_agent_run''::text,run_id FROM zasp_authorization80_worker.test_state WHERE present';
END $test_views$;

-- Copy the already-defined closed planning proof protocol, substituting only
-- family/source identities. No native context or body is exposed by metadata.
DO $test_planning$ DECLARE d text;n text;needle text;BEGIN
 FOREACH n IN ARRAY ARRAY['planning78_source','require_planning78','planning78_recovery_result','planning78_recovery'] LOOP
  SELECT pg_get_functiondef(oid) INTO STRICT d FROM pg_proc WHERE pronamespace='zasp_authorization80_worker'::regnamespace AND proname=n;
  d:=replace(replace(replace(d,'planning78','planning74'),'zasp_temporal78.','zasp_temporal74.'),'finding.planning.','test74.planning.');
  IF n='planning78_source' THEN
   needle:=$old$ IF compensation THEN reference_value:=reference_value||jsonb_build_object('reason','workflow_failed');END IF;
 f:=zasp_authorization80_worker.finding_source(CASE WHEN compensation THEN 'finding.cleanup' ELSE 'finding.planning' END,reference_value);$old$;
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker test planning protocol changed';END IF;
   d:=replace(d,needle,' f:=zasp_authorization80_worker.test74_source(compensation,reference_value);');
  END IF;
  EXECUTE d;
 END LOOP;
END $test_planning$;
