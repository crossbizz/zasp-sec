-- Derived execution grants are separate from the immutable admission and the
-- planner's queued/planning/waiting_approval view. Real effects retain their own
-- immutable native target snapshot; this table is not a compensation resolver.
CREATE TABLE zasp_authorization80_worker.ordered_effect_scope(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,
 action_key text NOT NULL CHECK(action_key IN('create_temporary_policy','run_test')),
 device_ids jsonb NOT NULL,destination_digest text,targets_digest text,fresh_until timestamptz NOT NULL,target_current boolean NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_authorization80_worker.ordered_associations,
 CHECK(jsonb_typeof(device_ids)='array' AND CASE action_key WHEN 'create_temporary_policy' THEN jsonb_array_length(device_ids) BETWEEN 1 AND 100 AND destination_digest IS NOT NULL AND targets_digest IS NOT NULL AND destination_digest~'^[a-f0-9]{64}$' AND targets_digest~'^[a-f0-9]{64}$' ELSE device_ids='[]'::jsonb AND destination_digest IS NULL AND targets_digest IS NULL END));
ALTER TABLE zasp_authorization80_worker.ordered_effect_scope OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_authorization80_worker.ordered_effect_scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_authorization80_worker.ordered_effect_scope FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_authorization80_worker.ordered_effect_scope TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON zasp_authorization80_worker.ordered_effect_scope FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE TRIGGER worker_revision AFTER INSERT OR UPDATE OR DELETE ON zasp_authorization80_worker.ordered_effect_scope FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,run_id,step_id,action_key,device_ids,destination_digest,targets_digest,fresh_until,target_current');

CREATE FUNCTION zasp_authorization80_worker.prepare_ordered68_effect(q jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $prepare_effect$
DECLARE f jsonb;BEGIN
 -- Only a real admitted reserve identity can establish or refresh projection.
 -- The metadata reader holds organization before native budget/run/step locks.
 f:=zasp_authorization80_worker.ordered68_effect_metadata('effect.reserve',q);
 IF f#>>'{step,state}' NOT IN('authorized','executing') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered approved effect absent';END IF;
 IF f->>'ordered_action_key'='create_temporary_policy' THEN
  PERFORM zasp_sa_multistep_prior.application_current(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id');
 ELSE
  PERFORM zasp_sa_multistep_prior.test_current(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id');
 END IF;
 INSERT INTO zasp_authorization80_worker.ordered_effect_scope AS c VALUES(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id',f->>'ordered_action_key',f->'ordered_device_ids',f->>'destination_digest',f->>'ordered_targets_digest',to_timestamp((f->>'fresh_until_ms')::numeric/1000),true)
 ON CONFLICT(organization_id,workspace_id,environment_id,run_id,step_id) DO UPDATE SET device_ids=EXCLUDED.device_ids,destination_digest=EXCLUDED.destination_digest,targets_digest=EXCLUDED.targets_digest,fresh_until=EXCLUDED.fresh_until,target_current=true
 WHERE(c.action_key,c.device_ids,c.destination_digest,c.targets_digest,c.fresh_until,c.target_current) IS DISTINCT FROM(EXCLUDED.action_key,EXCLUDED.device_ids,EXCLUDED.destination_digest,EXCLUDED.targets_digest,EXCLUDED.fresh_until,true);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_effect_scope c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.step_id,c.action_key,c.device_ids,c.target_current)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id',f->>'ordered_action_key',f->'ordered_device_ids',true) AND c.fresh_until>clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered effect capture changed';END IF;
END $prepare_effect$;

CREATE FUNCTION zasp_authorization80_worker.capture_ordered_gateway() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $capture_gateway$
DECLARE old_value jsonb;new_value jsonb;BEGIN
 IF TG_OP<>'INSERT' THEN old_value:=to_jsonb(OLD);END IF;
 IF TG_OP<>'DELETE' THEN new_value:=to_jsonb(NEW);END IF;
 IF TG_OP='UPDATE' AND old_value=new_value THEN RETURN NEW;END IF;
 IF TG_OP='UPDATE' AND TG_TABLE_NAME='zasp_gateway_devices' AND old_value-ARRAY['replay_floor','version','updated_at']=new_value-ARRAY['replay_floor','version','updated_at'] THEN RETURN NEW;END IF;
 UPDATE zasp_authorization80_worker.ordered_effect_scope c SET target_current=false WHERE c.target_current AND c.action_key='create_temporary_policy'
 AND((c.organization_id,c.workspace_id,c.environment_id)=(old_value->>'organization_id',old_value->>'workspace_id',old_value->>'environment_id') OR(c.organization_id,c.workspace_id,c.environment_id)=(new_value->>'organization_id',new_value->>'workspace_id',new_value->>'environment_id'));
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $capture_gateway$;
DO $gateway_capture$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['zasp_gateway_devices','zasp_gateway_credentials'] LOOP
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_ordered_gateway BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.capture_ordered_gateway()',n);
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_ordered_no_truncate BEFORE TRUNCATE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $gateway_capture$;
CREATE FUNCTION zasp_authorization80_worker.expire_ordered_effects(o text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $effect_expiry$
BEGIN
 IF NOT zasp_authorization79.worker() OR NOT zasp_authorization79.locked(o) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered effect expiry session rejected';END IF;
 UPDATE zasp_authorization80_worker.ordered_effect_scope SET target_current=false WHERE organization_id=o AND target_current AND fresh_until<=clock_timestamp();
END $effect_expiry$;

CREATE VIEW zasp_authorization80_worker.active_ordered_effects AS
 SELECT a.*,c.step_id,c.action_key,c.device_ids FROM zasp_authorization80_worker.ordered_associations a
 JOIN zasp_authorization80_worker.ordered_state s USING(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version)
 JOIN zasp_authorization80_worker.ordered_effect_scope c USING(organization_id,workspace_id,environment_id,run_id)
 JOIN public.zasp_security_agent_definitions d ON(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version)
 JOIN public.zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(a.organization_id,a.grantor_id)
 WHERE s.present AND s.target_current AND s.fresh_until>clock_timestamp() AND s.state IN('running','verifying') AND c.target_current AND c.fresh_until>clock_timestamp() AND m.active AND d.deleted_at IS NULL AND d.activation='supervised' AND d.body->'enabled'='true'::jsonb;
ALTER VIEW zasp_authorization80_worker.active_ordered_effects OWNER TO zasp_discovery_authority;
DO $effect_views$ DECLARE d text;BEGIN
 SELECT pg_get_viewdef('zasp_authorization79.members'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.members AS '||rtrim(d,E';\n ')||' UNION SELECT organization_id,''service''::text,principal_id,''''::text FROM zasp_authorization80_worker.active_ordered_effects';
 SELECT pg_get_viewdef('zasp_authorization79.current_grants'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.current_grants AS '||rtrim(d,E';\n ')||$grants$
 UNION SELECT a.organization_id,a.workspace_id,a.environment_id,t.kind,t.id,'service'::text,a.principal_id,t.permission,a.run_id FROM zasp_authorization80_worker.active_ordered_effects a
 CROSS JOIN LATERAL(VALUES('security_agent'::text,a.definition_id,'manage_workflows'::text),('security_agent_run',a.run_id,'manage_workflows')) t(kind,id,permission)
 UNION SELECT a.organization_id,a.workspace_id,a.environment_id,'gateway_device'::text,t.id,'service'::text,a.principal_id,'manage_workflows'::text,a.run_id FROM zasp_authorization80_worker.active_ordered_effects a CROSS JOIN LATERAL jsonb_array_elements_text(a.device_ids) t(id) WHERE a.action_key='create_temporary_policy'
 UNION SELECT a.organization_id,a.workspace_id,a.environment_id,t.kind,t.id,'service'::text,a.principal_id,'run_tests'::text,a.run_id FROM zasp_authorization80_worker.active_ordered_effects a CROSS JOIN LATERAL(VALUES('test'::text,a.test_id),(a.target_kind,a.target_id)) t(kind,id) WHERE a.action_key='run_test'$grants$;
END $effect_views$;
