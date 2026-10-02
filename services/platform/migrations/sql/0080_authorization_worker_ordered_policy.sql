-- Fixed signing protocol. The phase-specific metadata/materializer,
-- proof clone and exact private native copies must land together before this
-- module is installed or any entry is granted. These are not generic signing
-- helpers: callers cannot select SQL or an arbitrary unsigned payload.
-- Authorization metadata contains only actual identities and digests. The
-- compiled bodies are disclosed separately by begin, after the signed fence.
CREATE FUNCTION zasp_authorization80_worker.ordered68_policy_metadata(operation_value text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $metadata$
DECLARE compensation boolean;delivery_value boolean;prepare_value boolean;phase_value text;f jsonb;effect_q jsonb;composition_value jsonb;
 checks jsonb:='[]'::jsonb;policy_ids jsonb:='[]'::jsonb;run_ids jsonb:='[]'::jsonb;marker jsonb;fresh_value bigint;
 t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;v zasp_temporal68.deliveries%ROWTYPE;fx zasp_temporal68.effects%ROWTYPE;
 work public.zasp_policy_deployment_work%ROWTYPE;BEGIN
 -- Preparation is an ordinary forward operation, never a signing purpose. Its
 -- composition is captured before a delivery row necessarily exists.
 prepare_value:=operation_value='ordered68.delivery.apply.prepare';
 compensation:=CASE WHEN prepare_value THEN false ELSE zasp_authorization80_worker.ordered68_policy_purpose(operation_value)='captured-compensation' END;
 delivery_value:=prepare_value OR operation_value IN('ordered68.delivery.apply.store','ordered68.delivery.cleanup.store');
 phase_value:=CASE WHEN compensation THEN 'cleanup' ELSE 'apply' END;
 IF NOT COALESCE(octet_length(q::text)<=4096 AND q->'generation'='1'::jsonb
 AND q->>'operation'=CASE WHEN prepare_value THEN 'prepare' WHEN delivery_value THEN 'store' WHEN operation_value='ordered68.cleanup.renew' THEN 'renew' ELSE 'source' END
 AND public.zasp_valid_product_id(q#>>'{payload,device_id}'),false)
 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload'])
 OR NOT zasp_sa_multistep_prior.closed(q->'payload',CASE WHEN delivery_value THEN ARRAY['device_id','phase'] WHEN operation_value='ordered68.cleanup.renew' THEN ARRAY['device_id','source_digest'] ELSE ARRAY['device_id'] END)
 OR delivery_value AND q#>>'{payload,phase}' IS DISTINCT FROM phase_value
 OR operation_value='ordered68.cleanup.renew' AND NOT COALESCE(q#>>'{payload,source_digest}'~'^sha256:[a-f0-9]{64}$',false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered signing reference rejected';END IF;
 -- Retain the admitted parent, original native effect and complete destination
 -- digest. Compensation chooses only its captured path; no forward resolver.
 effect_q:=q||jsonb_build_object('operation',CASE WHEN compensation THEN 'read' ELSE 'start' END,'payload','{}'::jsonb);
 f:=zasp_authorization80_worker.ordered68_effect_source(CASE WHEN compensation THEN 'effect.read' ELSE 'effect.start' END,effect_q);
 IF f->>'ordered_action_key' IS DISTINCT FROM 'create_temporary_policy' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signing effect rejected';END IF;
 SELECT * INTO STRICT fx FROM zasp_temporal68.effects WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation)
 =(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id',1) FOR SHARE;
 IF fx.state NOT IN('started','unknown','cleanup_pending','cleaned') OR NOT compensation AND NOT delivery_value AND fx.state NOT IN('started','unknown')
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered signing intent unavailable';END IF;
 IF compensation THEN PERFORM zasp_temporal68.cleanup_current(fx.organization_id,fx.workspace_id,fx.environment_id,fx.run_id,fx.step_id);
 ELSE PERFORM zasp_sa_multistep_prior.application_current(fx.organization_id,fx.workspace_id,fx.environment_id,fx.run_id,fx.step_id);END IF;
 SELECT * INTO t FROM public.zasp_security_agent_temporary_policy_targets
 WHERE(organization_id,workspace_id,environment_id,run_id,step_id,device_id,phase)=(fx.organization_id,fx.workspace_id,fx.environment_id,fx.run_id,fx.step_id,q#>>'{payload,device_id}',phase_value) FOR UPDATE;
 IF t.device_id IS NULL OR t.action_key IS DISTINCT FROM 'create_temporary_policy'
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(fx.snapshot->'targets') x WHERE(x->>'device_id',x->>'credential_id')=(t.device_id,t.credential_id))
 OR NOT compensation AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(fx.snapshot->'targets') x WHERE(x->>'device_id',x->'sequence',x->'policy_version')=(t.device_id,to_jsonb(t.sequence),to_jsonb(t.policy_version)))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered signing captured destination changed';END IF;
 IF compensation THEN marker:=zasp_temporal68.cleanup_marker(t);END IF;
 IF delivery_value THEN
  SELECT * INTO v FROM zasp_temporal68.deliveries
  WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation,device_id,phase)=(fx.organization_id,fx.workspace_id,fx.environment_id,fx.run_id,fx.step_id,1,t.device_id,phase_value) FOR UPDATE;
  SELECT * INTO work FROM public.zasp_policy_deployment_work WHERE(organization_id,workspace_id,environment_id,device_id)=(t.organization_id,t.workspace_id,t.environment_id,t.device_id) FOR SHARE;
  composition_value:=CASE WHEN compensation THEN zasp_temporal68.cleanup_composition(t.organization_id,t.workspace_id,t.environment_id,t.device_id,t.run_id,t.step_id) ELSE zasp_sa_multistep_prior.deployment_composition(t.organization_id,t.workspace_id,t.environment_id,t.device_id) END;
  IF t.state NOT IN('stored','verified') OR t.envelope_digest IS NULL OR t.desired_generation IS NULL
  OR work.device_id IS NULL OR work.state='leased' OR work.lease_token IS NOT NULL OR work.lease_owner IS NOT NULL OR work.lease_expires_at IS NOT NULL
  OR v.run_id IS NULL AND NOT prepare_value OR v.run_id IS NOT NULL AND(v.state NOT IN('prepared','stored','read','acknowledged')
   OR(v.source_sequence,v.source_digest,v.credential_id,v.desired_generation,v.composition) IS DISTINCT FROM(t.sequence,t.envelope_digest,t.credential_id,work.desired_generation,composition_value))
  OR v.run_id IS NULL AND prepare_value AND work.applied_generation>=work.desired_generation
  OR (CASE WHEN compensation THEN work.desired_generation<t.desired_generation ELSE work.desired_generation IS DISTINCT FROM t.desired_generation END)
  OR(compensation AND v.state<>'acknowledged' AND(marker->>'expires_at')::timestamptz<=clock_timestamp())
  OR NOT COALESCE((composition_value->>'expires_at')::timestamptz>clock_timestamp()+interval '1 minute',false)
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered signing composition changed';END IF;
  IF compensation THEN PERFORM zasp_temporal68.delivery_history(t);END IF;
  SELECT COALESCE(jsonb_agg(id ORDER BY id COLLATE "C"),'[]'::jsonb) INTO policy_ids FROM(SELECT value->>'id' id FROM jsonb_array_elements(composition_value->'persistent_sources')) p;
  SELECT COALESCE(jsonb_agg(id ORDER BY id COLLATE "C"),'[]'::jsonb) INTO run_ids FROM(SELECT DISTINCT value->>'run_id' id FROM jsonb_array_elements(composition_value->'temporary_sources')) p;
  IF jsonb_array_length(policy_ids)>100 OR jsonb_array_length(run_ids)>100
   OR NOT compensation AND jsonb_array_length(run_ids)<1
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(policy_ids||run_ids) x WHERE NOT COALESCE(public.zasp_valid_product_id(x),false))
   OR(SELECT count(*)<>count(DISTINCT x) FROM jsonb_array_elements_text(policy_ids) x)
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered signing composition identities changed';END IF;
 ELSE
  IF t.state NOT IN('planned','stored','verified') OR operation_value='ordered68.cleanup.renew' AND(t.state<>'stored'
   OR q#>>'{payload,source_digest}' IS DISTINCT FROM 'sha256:'||encode(t.envelope_digest,'hex'))
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered signing source state changed';END IF;
 END IF;
 IF NOT compensation THEN
  checks:=jsonb_build_array(jsonb_build_object('kind','security_agent','id',f->>'definition_id','permission','manage_workflows'),jsonb_build_object('kind','security_agent_run','id',f->>'run_id','permission','manage_workflows'),jsonb_build_object('kind','gateway_device','id',t.device_id,'permission','manage_workflows'))
   ||COALESCE((SELECT jsonb_agg(jsonb_build_object('kind','policy','id',x,'permission','view') ORDER BY x COLLATE "C") FROM jsonb_array_elements_text(policy_ids) x),'[]'::jsonb)
   ||COALESCE((SELECT jsonb_agg(jsonb_build_object('kind','security_agent_run','id',x,'permission','view') ORDER BY x COLLATE "C") FROM jsonb_array_elements_text(run_ids) x),'[]'::jsonb);
  fresh_value:=(f->>'fresh_until_ms')::bigint;
  IF delivery_value THEN fresh_value:=least(fresh_value,floor(extract(epoch FROM(composition_value->>'expires_at')::timestamptz)*1000)::bigint);END IF;
  f:=jsonb_set(f,'{fresh_until_ms}',to_jsonb(fresh_value));
 END IF;
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready()
 OR NOT zasp_temporal68.principal_ready(CASE WHEN compensation THEN 'zasp_temporal_compensation' ELSE 'zasp_temporal_executor' END)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signing session changed after wait';END IF;
 RETURN f||jsonb_build_object('ordered_device_ids','[]'::jsonb,'ordered_policy_device_id',t.device_id,'ordered_policy_ids',CASE WHEN compensation THEN '[]'::jsonb ELSE policy_ids END,'ordered_source_run_ids',CASE WHEN compensation THEN '[]'::jsonb ELSE run_ids END,
 'checks',checks,'execution_phase',operation_value,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),
 'signing_target_digest',encode(digest(convert_to(zasp_authorization80_worker.ordered68_row_json(t)::text,'UTF8'),'sha256'),'hex'),
 'signing_delivery_digest',CASE WHEN delivery_value AND v.run_id IS NOT NULL THEN encode(digest(convert_to(zasp_authorization80_worker.ordered68_row_json(v)::text,'UTF8'),'sha256'),'hex') ELSE NULL END,
 'signing_composition_digest',CASE WHEN delivery_value THEN encode(digest(convert_to(composition_value::text,'UTF8'),'sha256'),'hex') ELSE NULL END,
 'signing_marker_digest',CASE WHEN compensation THEN encode(digest(convert_to(marker::text,'UTF8'),'sha256'),'hex') ELSE NULL END);
END $metadata$;

-- These are derived task grants, not a caller-provided policy allowlist. Every
-- refresh comes from an admitted effect and the retained native composition.
CREATE TABLE zasp_authorization80_worker.ordered_policy_scope(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,device_id text NOT NULL,
 operation text NOT NULL CHECK(operation IN('ordered68.application.source','ordered68.delivery.apply.prepare','ordered68.delivery.apply.store')),
 policy_ids jsonb NOT NULL,source_run_ids jsonb NOT NULL,target_digest text NOT NULL,delivery_digest text,composition_digest text,
 fresh_until timestamptz NOT NULL,target_current boolean NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id,device_id,operation),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES zasp_authorization80_worker.ordered_effect_scope,
 CHECK(jsonb_typeof(policy_ids)='array' AND jsonb_array_length(policy_ids)<=100 AND jsonb_typeof(source_run_ids)='array' AND jsonb_array_length(source_run_ids)<=100
 AND target_digest~'^[a-f0-9]{64}$' AND CASE operation WHEN 'ordered68.application.source' THEN policy_ids='[]'::jsonb AND source_run_ids='[]'::jsonb AND delivery_digest IS NULL AND composition_digest IS NULL
 ELSE jsonb_array_length(source_run_ids)>0 AND(operation='ordered68.delivery.apply.prepare' AND delivery_digest IS NULL OR delivery_digest IS NOT NULL AND delivery_digest~'^[a-f0-9]{64}$') AND composition_digest IS NOT NULL AND composition_digest~'^[a-f0-9]{64}$' END));
ALTER TABLE zasp_authorization80_worker.ordered_policy_scope OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_authorization80_worker.ordered_policy_scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_authorization80_worker.ordered_policy_scope FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_authorization80_worker.ordered_policy_scope TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON zasp_authorization80_worker.ordered_policy_scope FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE TRIGGER worker_revision AFTER INSERT OR UPDATE OR DELETE ON zasp_authorization80_worker.ordered_policy_scope FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,run_id,step_id,device_id,operation,policy_ids,source_run_ids,target_digest,delivery_digest,composition_digest,fresh_until,target_current');

CREATE FUNCTION zasp_authorization80_worker.prepare_ordered68_policy(operation_value text,q jsonb) RETURNS void
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $prepare_policy$
DECLARE f jsonb;BEGIN
 IF operation_value IS NULL OR operation_value NOT IN('ordered68.application.source','ordered68.delivery.apply.prepare','ordered68.delivery.apply.store')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered forward policy projection operation rejected';END IF;
 f:=zasp_authorization80_worker.ordered68_policy_metadata(operation_value,q);
 INSERT INTO zasp_authorization80_worker.ordered_policy_scope AS c VALUES(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id',f->>'ordered_policy_device_id',operation_value,
 f->'ordered_policy_ids',f->'ordered_source_run_ids',f->>'signing_target_digest',f->>'signing_delivery_digest',f->>'signing_composition_digest',to_timestamp((f->>'fresh_until_ms')::numeric/1000),true)
 ON CONFLICT(organization_id,workspace_id,environment_id,run_id,step_id,device_id,operation) DO UPDATE SET
 policy_ids=EXCLUDED.policy_ids,source_run_ids=EXCLUDED.source_run_ids,target_digest=EXCLUDED.target_digest,delivery_digest=EXCLUDED.delivery_digest,composition_digest=EXCLUDED.composition_digest,fresh_until=EXCLUDED.fresh_until,target_current=true
 WHERE(c.policy_ids,c.source_run_ids,c.target_digest,c.delivery_digest,c.composition_digest,c.fresh_until,c.target_current)
 IS DISTINCT FROM(EXCLUDED.policy_ids,EXCLUDED.source_run_ids,EXCLUDED.target_digest,EXCLUDED.delivery_digest,EXCLUDED.composition_digest,EXCLUDED.fresh_until,true);
END $prepare_policy$;

CREATE FUNCTION zasp_authorization80_worker.ordered68_policy_source(operation_value text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $policy_source$
DECLARE f jsonb;c zasp_authorization80_worker.ordered_policy_scope%ROWTYPE;BEGIN
 f:=zasp_authorization80_worker.ordered68_policy_metadata(operation_value,q);
 IF (CASE WHEN operation_value='ordered68.delivery.apply.prepare' THEN true ELSE zasp_authorization80_worker.ordered68_policy_purpose(operation_value)='worker-forward' END) THEN
  SELECT * INTO c FROM zasp_authorization80_worker.ordered_policy_scope WHERE(organization_id,workspace_id,environment_id,run_id,step_id,device_id,operation)
   =(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id',f->>'ordered_policy_device_id',operation_value) FOR SHARE;
  IF c.run_id IS NULL OR NOT c.target_current OR c.fresh_until<=clock_timestamp()
  OR(c.policy_ids,c.source_run_ids,c.target_digest,c.delivery_digest,c.composition_digest)
  IS DISTINCT FROM(f->'ordered_policy_ids',f->'ordered_source_run_ids',f->>'signing_target_digest',f->>'signing_delivery_digest',f->>'signing_composition_digest')
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered signing projection capture changed';END IF;
 END IF;
 RETURN f;
END $policy_source$;

CREATE FUNCTION zasp_authorization80_worker.capture_ordered_policy() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $capture_policy$
DECLARE a jsonb;b jsonb;BEGIN
 IF TG_OP<>'INSERT' THEN a:=to_jsonb(OLD);END IF;
 IF TG_OP<>'DELETE' THEN b:=to_jsonb(NEW);END IF;
 IF TG_OP='UPDATE' AND a=b THEN RETURN NEW;END IF;
 IF TG_TABLE_NAME='zasp_workflow_records' AND COALESCE(a->>'kind','')<>'policy' AND COALESCE(b->>'kind','')<>'policy' THEN
  IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
 END IF;
 UPDATE zasp_authorization80_worker.ordered_policy_scope c SET target_current=false WHERE c.target_current
 AND((c.organization_id,c.workspace_id,c.environment_id)=(a->>'organization_id',a->>'workspace_id',a->>'environment_id')
 OR(c.organization_id,c.workspace_id,c.environment_id)=(b->>'organization_id',b->>'workspace_id',b->>'environment_id'))
 AND(TG_TABLE_NAME='zasp_workflow_records' AND c.operation IN('ordered68.delivery.apply.prepare','ordered68.delivery.apply.store')
 OR TG_TABLE_NAME<>'zasp_workflow_records' AND(c.device_id=a->>'device_id' OR c.device_id=b->>'device_id'));
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $capture_policy$;
DO $policy_capture$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['zasp_workflow_records','zasp_security_agent_temporary_policy_targets'] LOOP
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_ordered_policy BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.capture_ordered_policy()',n);
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_ordered_policy_no_truncate BEFORE TRUNCATE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
 CREATE TRIGGER ordered_policy_capture BEFORE INSERT OR UPDATE OR DELETE ON zasp_temporal68.deliveries FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.capture_ordered_policy();
 CREATE TRIGGER ordered_policy_no_truncate BEFORE TRUNCATE ON zasp_temporal68.deliveries FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
END $policy_capture$;

CREATE FUNCTION zasp_authorization80_worker.expire_ordered_policies(o text) RETURNS void
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $policy_expiry$
BEGIN
 IF NOT zasp_authorization79.worker() OR NOT zasp_authorization79.locked(o) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered policy expiry session rejected';END IF;
 UPDATE zasp_authorization80_worker.ordered_policy_scope SET target_current=false WHERE organization_id=o AND target_current AND fresh_until<=clock_timestamp();
END $policy_expiry$;

CREATE VIEW zasp_authorization80_worker.active_ordered_policies AS
 SELECT a.*,c.device_id,c.operation,c.policy_ids,c.source_run_ids FROM zasp_authorization80_worker.active_ordered_effects a
 JOIN zasp_authorization80_worker.ordered_policy_scope c USING(organization_id,workspace_id,environment_id,run_id,step_id)
 WHERE a.action_key='create_temporary_policy' AND c.target_current AND c.fresh_until>clock_timestamp();
ALTER VIEW zasp_authorization80_worker.active_ordered_policies OWNER TO zasp_discovery_authority;
DO $policy_views$ DECLARE d text;BEGIN
 SELECT pg_get_viewdef('zasp_authorization79.current_grants'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.current_grants AS '||rtrim(d,E';\n ')||$grants$
 UNION SELECT a.organization_id,a.workspace_id,a.environment_id,'policy'::text,t.id,'service'::text,a.principal_id,'view'::text,a.run_id FROM zasp_authorization80_worker.active_ordered_policies a CROSS JOIN LATERAL jsonb_array_elements_text(a.policy_ids) t(id)
 UNION SELECT a.organization_id,a.workspace_id,a.environment_id,'security_agent_run'::text,t.id,'service'::text,a.principal_id,'view'::text,a.run_id FROM zasp_authorization80_worker.active_ordered_policies a CROSS JOIN LATERAL jsonb_array_elements_text(a.source_run_ids) t(id)$grants$;
END $policy_views$;

INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal68.application(jsonb)'::regprocedure,'zasp_temporal68.cleanup(jsonb)'::regprocedure,'zasp_temporal68.delivery(jsonb)'::regprocedure);

-- Each copy keeps the exact native predicates and mutations but restricts the
-- request operation itself. No grant exposes these copies, and no live outer
-- function is replaced by this staging block.
DO $private_signing_bodies$ DECLARE p record;d text;old_set text;new_set text;copy_name text;expected_acl text;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions
 WHERE signature IN('zasp_temporal68.application(jsonb)','zasp_temporal68.cleanup(jsonb)','zasp_temporal68.delivery(jsonb)') LOOP
  IF p.signature='zasp_temporal68.application(jsonb)' THEN
   copy_name:='ordered68_application_source';old_set:=$ops$('read','source','complete')$ops$;new_set:=$ops$('source')$ops$;
   expected_acl:='{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority}';
  ELSIF p.signature='zasp_temporal68.cleanup(jsonb)' THEN
   copy_name:='ordered68_cleanup_source';old_set:=$ops$('prepare','read','source','renew','unknown','complete')$ops$;new_set:=$ops$('source','renew')$ops$;
   expected_acl:='{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}';
  ELSE
   copy_name:='ordered68_delivery_store';old_set:=$ops$('prepare','store','read','ack')$ops$;new_set:=$ops$('store')$ops$;
   expected_acl:='{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}';
  END IF;
  IF p.owner_name<>'zasp_discovery_authority' OR p.acl<>expected_acl THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered private signing identity changed';END IF;
  d:=zasp_authorization80_worker.ordered62_replace(p.definition,'FUNCTION '||replace(p.signature,'jsonb','q jsonb'),'FUNCTION zasp_authorization80_worker.'||copy_name||'(q jsonb)');
  d:=zasp_authorization80_worker.ordered62_replace(d,old_set,new_set);
  d:=zasp_authorization80_worker.ordered62_replace(d,$read$zasp_temporal68.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$read$,$read$zasp_authorization80_worker.ordered68_effect_read(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$read$);
  EXECUTE d;
  EXECUTE format('ALTER FUNCTION zasp_authorization80_worker.%I(jsonb) OWNER TO zasp_discovery_authority',copy_name);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_authorization80_worker.%I(jsonb) FROM PUBLIC',copy_name);
 END LOOP;
END $private_signing_bodies$;

DO $policy_proof$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.require_planning68(text,jsonb)'::regprocedure) INTO d;
 d:=zasp_authorization80_worker.ordered62_replace(d,E'BEGIN\n',E'BEGIN\n PERFORM pg_advisory_xact_lock_shared(hashtextextended(''zasp-schema-migrations'',0));\n');
 d:=replace(replace(d,'require_planning68','require_ordered68_policy'),'planning68_source','ordered68_policy_source');
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery')$old$,$new$('ordered68.application.source','ordered68.delivery.apply.store','ordered68.cleanup.source','ordered68.cleanup.renew','ordered68.delivery.cleanup.store')$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('reconcile','late_usage','recovery')$old$,$new$('ordered68.cleanup.source','ordered68.cleanup.renew','ordered68.delivery.cleanup.store')$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$proof->>'operation'='ordered68.planning.'||phase$old$,$new$proof->>'operation'=phase$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,E' RETURNS void\n',E' RETURNS jsonb\n');
 d:=zasp_authorization80_worker.ordered62_replace(d,'EXCEPTION WHEN data_exception THEN',E' RETURN proof;\nEXCEPTION WHEN data_exception THEN');
 EXECUTE d;
END $policy_proof$;

CREATE FUNCTION zasp_authorization80_worker.ordered68_policy_purpose(operation_value text) RETURNS text
 LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $purpose$
BEGIN
 CASE operation_value
 WHEN 'ordered68.application.source','ordered68.delivery.apply.store' THEN RETURN 'worker-forward';
 WHEN 'ordered68.cleanup.source','ordered68.cleanup.renew','ordered68.delivery.cleanup.store' THEN RETURN 'captured-compensation';
 ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signing operation rejected';
 END CASE;
END $purpose$;

CREATE FUNCTION zasp_authorization80_worker.ordered68_policy_proof_time(proof jsonb) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $time$
DECLARE now_ms bigint:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;BEGIN
 IF NOT COALESCE((proof->>'issued_at')::bigint<=now_ms+5000 AND(proof->>'expires_at')::bigint>now_ms
 AND(proof->>'expires_at')::bigint-(proof->>'issued_at')::bigint BETWEEN 1 AND 60000,false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signing proof expired after wait';END IF;
END $time$;

-- This private materializer consumes the same validated compact metadata as
-- the proof source, then rereads its actual native rows. No endpoint, secret or
-- fresh resolver is accepted from the caller; only the native compiled set is
-- disclosed to the local signer after begin's proof check.
CREATE FUNCTION zasp_authorization80_worker.ordered68_policy_input(operation_value text,q jsonb,key_id_value text,issued_value bigint,verified_facts jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $input$
DECLARE phase_value text;policies_value jsonb;sequence_value bigint;version_value bigint;expires_value bigint;ttl integer;old_envelope jsonb;marker jsonb;
 t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;v zasp_temporal68.deliveries%ROWTYPE;BEGIN
 -- Only begin/store call this owner-only helper, with the source equality
 -- already checked by their local proof parser. No facts cross native calls.
 phase_value:=CASE WHEN zasp_authorization80_worker.ordered68_policy_purpose(operation_value)='worker-forward' THEN 'apply' ELSE 'cleanup' END;
 SELECT * INTO STRICT t FROM public.zasp_security_agent_temporary_policy_targets
 WHERE(organization_id,workspace_id,environment_id,run_id,step_id,device_id,phase)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id',q#>>'{payload,device_id}',phase_value) FOR UPDATE;
 IF verified_facts->>'signing_target_digest' IS DISTINCT FROM encode(digest(convert_to(zasp_authorization80_worker.ordered68_row_json(t)::text,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered native signing target changed';END IF;
 IF operation_value IN('ordered68.delivery.apply.store','ordered68.delivery.cleanup.store') THEN
  SELECT * INTO STRICT v FROM zasp_temporal68.deliveries
  WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation,phase,device_id)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,1,phase_value,t.device_id) FOR UPDATE;
  IF verified_facts->>'signing_delivery_digest' IS DISTINCT FROM encode(digest(convert_to(zasp_authorization80_worker.ordered68_row_json(v)::text,'UTF8'),'sha256'),'hex')
  OR v.state NOT IN('prepared','stored','read','acknowledged')
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered native signing delivery changed';END IF;
  sequence_value:=v.sequence;version_value:=v.sequence;policies_value:=v.composition->'policies';
  expires_value:=floor(extract(epoch FROM(v.composition->>'expires_at')::timestamptz))::bigint;
  IF v.state<>'prepared' THEN old_envelope:=v.envelope;END IF;
 ELSE
  sequence_value:=t.sequence;version_value:=t.policy_version;
  IF phase_value='apply' THEN
   SELECT(plan->'steps'->0->>'ttl_seconds')::integer INTO STRICT ttl FROM public.zasp_security_agent_plans
   WHERE(organization_id,workspace_id,environment_id,run_id)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id);
   IF ttl NOT BETWEEN 60 AND 3600 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered native signing ttl changed';END IF;
   policies_value:=zasp_sa_multistep_prior.application_policies();
  ELSE ttl:=300;policies_value:='[]'::jsonb;END IF;
  expires_value:=issued_value+ttl;
  IF operation_value='ordered68.cleanup.renew' THEN
   marker:=zasp_temporal68.cleanup_marker(t);
   IF t.state<>'stored' OR q#>>'{payload,source_digest}' IS DISTINCT FROM 'sha256:'||encode(t.envelope_digest,'hex')
    OR verified_facts->>'signing_marker_digest' IS DISTINCT FROM encode(digest(convert_to(marker::text,'UTF8'),'sha256'),'hex')
   THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered captured renewal changed';END IF;
   IF(marker->>'expires_at')::timestamptz>clock_timestamp() THEN
    -- A completed renewal replays its exact signed input. The original marker
    -- has only timestamps and is not an existing renewal to replay.
    IF marker->>'key_id' IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered renewal window not reached';END IF;
    old_envelope:=marker;
   ELSIF to_timestamp(issued_value)<(marker->>'expires_at')::timestamptz THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered renewal precedes captured marker';
   END IF;
  ELSIF t.state<>'planned' THEN
   IF t.state NOT IN('stored','verified') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered source state changed';END IF;
   old_envelope:=jsonb_build_object('key_id',t.key_id,'issued_at',t.issued_at,'expires_at',t.expires_at,'policies',t.policies);
  END IF;
 END IF;
 IF old_envelope IS NOT NULL THEN
  IF old_envelope->>'key_id' IS DISTINCT FROM key_id_value OR old_envelope->'policies' IS DISTINCT FROM policies_value
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered signing replay identity changed';END IF;
  issued_value:=floor(extract(epoch FROM(old_envelope->>'issued_at')::timestamptz))::bigint;
  expires_value:=floor(extract(epoch FROM(old_envelope->>'expires_at')::timestamptz))::bigint;
 END IF;
 IF NOT COALESCE(sequence_value>0 AND version_value>0 AND issued_value<=floor(extract(epoch FROM clock_timestamp()))::bigint+5
 AND expires_value>floor(extract(epoch FROM clock_timestamp()))::bigint AND expires_value-issued_value BETWEEN 1 AND 86400
 AND jsonb_typeof(policies_value)='array' AND jsonb_array_length(policies_value)<=100,false)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered native signing input expired';END IF;
 RETURN jsonb_build_object('contract_version',1,'operation',operation_value,'decision_digest',encode(digest(convert_to(current_setting('zasp.worker_proof'),'UTF8'),'sha256'),'hex'),
 'key_id',key_id_value,'organization_id',t.organization_id,'workspace_id',t.workspace_id,'environment_id',t.environment_id,'device_id',t.device_id,
 'sequence',sequence_value,'policy_version',version_value,'issued_at',issued_value,'expires_at',expires_value,'failure_mode','closed','policies',policies_value);
END $input$;

CREATE FUNCTION zasp_authorization80_worker.ordered68_policy_begin(operation_value text,q jsonb,key_id_value text) RETURNS bytea
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $begin$
DECLARE proof jsonb;input_value jsonb;result bytea;BEGIN
 PERFORM zasp_authorization80_worker.ordered68_policy_purpose(operation_value);
 IF NOT COALESCE(key_id_value~'^[a-z][a-z0-9_-]{7,63}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered signing key rejected';END IF;
 -- The shared proof clone validates the exact original q and database session,
 -- takes organization before parent/target locks, and rechecks after its source.
 proof:=zasp_authorization80_worker.require_ordered68_policy(operation_value,q);
 input_value:=zasp_authorization80_worker.ordered68_policy_input(operation_value,q,key_id_value,floor(extract(epoch FROM clock_timestamp()))::bigint,proof->'facts');
 PERFORM zasp_authorization80_worker.ordered68_policy_proof_time(proof);
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready() OR NOT zasp_temporal68.principal_ready(CASE proof->>'purpose' WHEN 'worker-forward' THEN 'zasp_temporal_executor' WHEN 'captured-compensation' THEN 'zasp_temporal_compensation' END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signing session changed';END IF;
 result:=convert_to(zasp_sa_multistep_prior.deployment_json(input_value),'UTF8');
 IF octet_length(result) NOT BETWEEN 1 AND 1048576 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered signing input bound';END IF;
 RETURN result;
END $begin$;

CREATE FUNCTION zasp_authorization80_worker.ordered68_policy_store(operation_value text,q jsonb,key_id_value text,input_bytes bytea,envelope_bytes bytea,mac_value text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $store$
DECLARE proof jsonb;purpose_value text;k bytea;input_json json;envelope_json json;input_value jsonb;expected jsonb;env jsonb;payload jsonb;native_q jsonb;result jsonb;
 t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;message_bytes bytea;zero_byte bytea:=decode('00','hex');digest_value text;BEGIN
 purpose_value:=zasp_authorization80_worker.ordered68_policy_purpose(operation_value);
 proof:=zasp_authorization80_worker.require_ordered68_policy(operation_value,q);
 IF NOT COALESCE(octet_length(input_bytes) BETWEEN 1 AND 1048576 AND octet_length(envelope_bytes) BETWEEN 1 AND 1048576
 AND mac_value~'^[a-f0-9]{64}$' AND key_id_value~'^[a-z][a-z0-9_-]{7,63}$',false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signed store bound rejected';END IF;
 input_json:=convert_from(input_bytes,'UTF8')::json;envelope_json:=convert_from(envelope_bytes,'UTF8')::json;
 IF NOT zasp_authorization80.unique_json(input_json) OR NOT zasp_authorization80.unique_json(envelope_json)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signed store duplicate fields';END IF;
 input_value:=input_json::jsonb;env:=envelope_json::jsonb;
 IF NOT zasp_sa_multistep_prior.closed(input_value,ARRAY['contract_version','operation','decision_digest','key_id','organization_id','workspace_id','environment_id','device_id','sequence','policy_version','issued_at','expires_at','failure_mode','policies'])
 OR NOT zasp_sa_multistep_prior.closed(env,ARRAY['contract_version','key_id','algorithm','audience','organization_id','workspace_id','environment_id','device_id','sequence','policy_version','issued_at','expires_at','failure_mode','payload_digest','policies','signature'])
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signed store shape rejected';END IF;
 -- Recompute with the original issue time, not a newly sampled signing input.
 -- This reader retains actual source/sequence/composition and current/captured
 -- authority under the same transaction's locks. It performs no fresh lookup
 -- of forward credentials for captured compensation.
 expected:=zasp_authorization80_worker.ordered68_policy_input(operation_value,q,key_id_value,(input_value->>'issued_at')::bigint,proof->'facts');
 IF input_bytes IS DISTINCT FROM convert_to(zasp_sa_multistep_prior.deployment_json(expected),'UTF8')
 OR input_value->>'decision_digest' IS DISTINCT FROM encode(digest(convert_to(current_setting('zasp.worker_proof'),'UTF8'),'sha256'),'hex')
 OR env->'contract_version' IS DISTINCT FROM '1'::jsonb OR env->>'algorithm' IS DISTINCT FROM 'Ed25519' OR env->>'audience' IS DISTINCT FROM 'runtime-gateway-policy'
 OR(env->>'key_id',env->>'organization_id',env->>'workspace_id',env->>'environment_id',env->>'device_id',env->'sequence',env->'policy_version',env->>'failure_mode',env->'policies')
 IS DISTINCT FROM(key_id_value,input_value->>'organization_id',input_value->>'workspace_id',input_value->>'environment_id',input_value->>'device_id',input_value->'sequence',input_value->'policy_version',input_value->>'failure_mode',input_value->'policies')
 OR(env->>'issued_at')::timestamptz IS DISTINCT FROM to_timestamp((input_value->>'issued_at')::bigint)
 OR(env->>'expires_at')::timestamptz IS DISTINCT FROM to_timestamp((input_value->>'expires_at')::bigint)
 OR NOT COALESCE(env->>'payload_digest'~'^[a-f0-9]{64}$' AND env->>'signature'~'^[A-Za-z0-9_-]{86}$',false)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered signed input changed';END IF;
 SELECT key INTO k FROM zasp_authorization80_worker.verifiers WHERE purpose=purpose_value AND version=proof->>'key_version' FOR SHARE;
 message_bytes:=convert_to('zasp-authorization-ordered68-policy-store-v1','UTF8')||zero_byte||convert_to(purpose_value,'UTF8')||zero_byte
 ||convert_to(encode(digest(convert_to(current_setting('zasp.worker_proof'),'UTF8'),'sha256'),'hex'),'UTF8')||zero_byte
 ||convert_to(encode(digest(input_bytes,'sha256'),'hex'),'UTF8')||zero_byte||convert_to(encode(digest(envelope_bytes,'sha256'),'hex'),'UTF8');
 IF k IS NULL OR mac_value IS DISTINCT FROM encode(hmac(message_bytes,k,'sha256'),'hex')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signed store verification rejected';END IF;
 PERFORM zasp_authorization80_worker.ordered68_policy_proof_time(proof);
 digest_value:='sha256:'||encode(digest(envelope_bytes,'sha256'),'hex');
 IF operation_value IN('ordered68.delivery.apply.store','ordered68.delivery.cleanup.store') THEN
  payload:=jsonb_build_object('device_id',input_value->>'device_id','phase',CASE WHEN purpose_value='worker-forward' THEN 'apply' ELSE 'cleanup' END,'envelope',env,'digest',digest_value);
  native_q:=q||jsonb_build_object('operation','store','payload',payload);
  result:=zasp_authorization80_worker.ordered68_delivery_store(native_q);
 ELSE
  SELECT * INTO STRICT t FROM public.zasp_security_agent_temporary_policy_targets
   WHERE(organization_id,workspace_id,environment_id,run_id,step_id,device_id,phase)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id',input_value->>'device_id',CASE WHEN purpose_value='worker-forward' THEN 'apply' ELSE 'cleanup' END) FOR UPDATE;
  payload:=jsonb_build_object('device_id',t.device_id,'credential_id',t.credential_id,'sequence',env->'sequence','policy_version',env->'policy_version','key_id',key_id_value,
   'issued_at',env->>'issued_at','expires_at',env->>'expires_at','failure_mode',env->>'failure_mode','payload_digest','sha256:'||(env->>'payload_digest'),'policies',env->'policies',
   'signature',encode(decode(translate(env->>'signature','-_','+/')||'==','base64'),'base64'),'envelope_digest',digest_value);
  IF operation_value='ordered68.application.source' THEN
   result:=zasp_authorization80_worker.ordered68_application_source(q||jsonb_build_object('operation','source','payload',payload));
  ELSIF operation_value='ordered68.cleanup.source' THEN
   result:=zasp_authorization80_worker.ordered68_cleanup_source(q||jsonb_build_object('operation','source','payload',payload));
  ELSE
   result:=zasp_authorization80_worker.ordered68_cleanup_source(q||jsonb_build_object('operation','renew','payload',jsonb_build_object('source_digest',q#>>'{payload,source_digest}','envelope',payload)));
  END IF;
 END IF;
 -- Native writes can legitimately advance their own source/revision. Do not
 -- compare a prewrite revision to those writes; do reject expiry after waits.
 PERFORM zasp_authorization80_worker.ordered68_policy_proof_time(proof);
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready() OR NOT zasp_temporal68.principal_ready(CASE purpose_value WHEN 'worker-forward' THEN 'zasp_temporal_executor' WHEN 'captured-compensation' THEN 'zasp_temporal_compensation' END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signed store session changed';END IF;
 RETURN result;
EXCEPTION WHEN data_exception THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered signed store rejected';
END $store$;
