-- Canonicalize transient typed rows without changing the calling context of
-- native evidence validators. Already-captured JSON strings remain untouched.
CREATE FUNCTION zasp_authorization80_worker.ordered68_row_json(v anyelement) RETURNS jsonb
 LANGUAGE sql STABLE SET search_path=pg_catalog,public
 SET timezone='UTC' AS $ordered_row_json$ SELECT to_jsonb(v) $ordered_row_json$;

-- Effect authority is separate from planner disclosure. Keep the immutable
-- admission validator, but admit only the native execution states here.
DO $ordered_effect_facts$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.ordered68_facts(boolean,jsonb)'::regprocedure) INTO d;
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_authorization80_worker.ordered68_facts(', 'FUNCTION zasp_authorization80_worker.ordered68_effect_facts(');
 needle:=$states$r.state NOT IN('queued','planning','waiting_approval')$states$;
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,$states$r.state NOT IN('running','verifying')$states$);
 EXECUTE d;
END $ordered_effect_facts$;

-- Full native68 Block destinations, not runtime event source devices. Caller
-- holds the authorization organization lock before the retained parent locks.
-- Only opaque identities, digests and expiry leave this owner-only reader.
CREATE FUNCTION zasp_authorization80_worker.ordered68_destinations(o text,w text,e text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $destinations$
DECLARE selected jsonb;locked_value jsonb;row_value record;d public.zasp_gateway_devices%ROWTYPE;c public.zasp_gateway_credentials%ROWTYPE;
 metadata jsonb:='[]'::jsonb;expires timestamptz;BEGIN
 SELECT COALESCE(jsonb_agg(jsonb_build_object('device_id',v.id,'credential_id',k.id) ORDER BY v.id),'[]'::jsonb) INTO selected
 FROM public.zasp_gateway_devices v JOIN LATERAL(SELECT id FROM public.zasp_gateway_credentials WHERE(organization_id,workspace_id,environment_id,device_id)=(o,w,e,v.id) AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1) k ON true
 WHERE(v.organization_id,v.workspace_id,v.environment_id,v.state)=(o,w,e,'active');
 IF jsonb_array_length(selected) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered destination bound rejected';END IF;
 FOR row_value IN SELECT * FROM jsonb_to_recordset(selected) AS t(device_id text,credential_id text) ORDER BY device_id LOOP
  SELECT * INTO d FROM public.zasp_gateway_devices WHERE(organization_id,workspace_id,environment_id,id,state)=(o,w,e,row_value.device_id,'active') FOR SHARE NOWAIT;
  SELECT * INTO c FROM public.zasp_gateway_credentials WHERE(organization_id,workspace_id,environment_id,device_id,id)=(o,w,e,row_value.device_id,row_value.credential_id) AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE NOWAIT;
  IF d.id IS NULL OR c.id IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered destination changed';END IF;
  expires:=CASE WHEN expires IS NULL THEN c.expires_at ELSE least(expires,c.expires_at) END;
  -- Native gateway replay advances version with its floor on ordinary event
  -- traffic. Those bookkeeping fields do not change device authority.
  metadata:=metadata||jsonb_build_array(jsonb_build_array(d.id,encode(digest(convert_to((to_jsonb(d)-ARRAY['replay_floor','version','updated_at'])::text,'UTF8'),'sha256'),'hex'),c.id,encode(digest(convert_to(to_jsonb(c)::text,'UTF8'),'sha256'),'hex')));
 END LOOP;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('device_id',v.id,'credential_id',k.id) ORDER BY v.id),'[]'::jsonb) INTO locked_value
 FROM public.zasp_gateway_devices v JOIN LATERAL(SELECT id FROM public.zasp_gateway_credentials WHERE(organization_id,workspace_id,environment_id,device_id)=(o,w,e,v.id) AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1) k ON true
 WHERE(v.organization_id,v.workspace_id,v.environment_id,v.state)=(o,w,e,'active');
 IF selected IS DISTINCT FROM locked_value OR expires<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered selected destination changed';END IF;
 RETURN jsonb_build_object('ids',(SELECT jsonb_agg(t->'device_id' ORDER BY t->>'device_id') FROM jsonb_array_elements(selected) t),'targets_digest',encode(digest(convert_to(selected::text,'UTF8'),'sha256'),'hex'),'identity_digest',encode(digest(convert_to(metadata::text,'UTF8'),'sha256'),'hex'),'fresh_until_ms',floor(extract(epoch FROM expires)*1000)::bigint);
END $destinations$;

CREATE FUNCTION zasp_authorization80_worker.ordered68_effect_metadata(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $ordered_effect_source$
DECLARE x zasp_temporal66.run_owners%ROWTYPE;a zasp_authorization80_worker.ordered_associations%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;plan_value public.zasp_security_agent_plans%ROWTYPE;
 v zasp_temporal68.effects%ROWTYPE;f jsonb;reference_value jsonb;step_value jsonb;effect_value jsonb;destinations jsonb;checks jsonb;captured_targets jsonb;
 compensation boolean:=phase IN('effect.read','effect.unknown');BEGIN
 IF phase IS NULL OR phase NOT IN('effect.reserve','effect.start','effect.read','effect.unknown') OR octet_length(q::text)>4096
 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload'])
 OR q->'generation' IS DISTINCT FROM '1'::jsonb OR q->'payload' IS DISTINCT FROM '{}'::jsonb OR q->>'operation' IS DISTINCT FROM split_part(phase,'.',2)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered effect request rejected';END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered effect requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready() OR NOT zasp_temporal68.principal_ready(CASE WHEN compensation THEN 'zasp_temporal_compensation' ELSE 'zasp_temporal_executor' END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered effect principal rejected';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered effect organization absent';END IF;
 PERFORM zasp_sa_multistep_prior.application_lock(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id');
 SELECT * INTO x FROM zasp_temporal66.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id');
 IF x.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered effect owner absent';END IF;
 reference_value:=jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'definition_version',x.definition_version,'input_digest',x.input_digest);
 f:=zasp_authorization80_worker.ordered68_effect_facts(compensation,reference_value);
 a:=jsonb_populate_record(NULL::zasp_authorization80_worker.ordered_associations,f);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_associations s WHERE s=a) OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true) AND(compensation OR s.target_current AND s.fresh_until>clock_timestamp())) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered effect admission changed';END IF;
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q->>'step_id') FOR SHARE;
 SELECT * INTO plan_value FROM public.zasp_security_agent_plans WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR SHARE;
 IF st.step_id IS NULL OR plan_value.run_id IS NULL OR st.step_index NOT IN(0,1) OR st.action_key IS DISTINCT FROM (CASE st.step_index WHEN 0 THEN 'create_temporary_policy' ELSE 'run_test' END)
 OR plan_value.plan->'steps'->st.step_index->>'step_id' IS DISTINCT FROM st.step_id THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered effect step changed';END IF;
 PERFORM zasp_temporal68.current_plan(x.organization_id,x.workspace_id,x.environment_id,x.run_id,NOT compensation);
 SELECT * INTO v FROM zasp_temporal68.effects WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,st.step_id,1) FOR SHARE;
 IF v.run_id IS NULL AND phase<>'effect.reserve' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered captured effect absent';END IF;
 IF v.run_id IS NOT NULL THEN
  IF v.effect_key IS DISTINCT FROM zasp_temporal68.effect_identity(x.organization_id,x.workspace_id,x.environment_id,x.run_id,st.step_id,1) OR(v.input_digest,v.plan_hash,v.action_key) IS DISTINCT FROM(st.input_digest,plan_value.plan_hash,st.action_key)
  OR v.snapshot_digest IS DISTINCT FROM digest(convert_to(v.snapshot::text,'UTF8'),'sha256') OR v.snapshot->>'input_digest' IS DISTINCT FROM encode(st.input_digest,'hex') OR v.snapshot->>'plan_hash' IS DISTINCT FROM encode(plan_value.plan_hash,'hex')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_id,s.action_key,s.input_digest)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,st.step_id,st.action_key,st.input_digest))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_id,s.action_key,s.input_digest)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,st.step_id,st.action_key,st.input_digest) AND s.lease_owner IS NULL AND s.lease_token IS NULL AND s.lease_expires_at IS NULL)
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered captured effect changed';END IF;
  effect_value:=jsonb_build_object('effect_key',v.effect_key,'generation',v.generation,'state',v.state,'snapshot_digest',encode(v.snapshot_digest,'hex'));
 END IF;
 checks:='[]'::jsonb;
 IF NOT compensation THEN
  checks:=jsonb_build_array(jsonb_build_object('kind','security_agent','id',a.definition_id,'permission','manage_workflows'),jsonb_build_object('kind','security_agent_run','id',a.run_id,'permission','manage_workflows'));
  IF st.step_index=0 THEN
   destinations:=zasp_authorization80_worker.ordered68_destinations(x.organization_id,x.workspace_id,x.environment_id);
   IF v.run_id IS NOT NULL THEN
    SELECT jsonb_agg(jsonb_build_object('device_id',t->>'device_id','credential_id',t->>'credential_id') ORDER BY t->>'device_id') INTO captured_targets FROM jsonb_array_elements(v.snapshot->'targets') t;
    IF destinations->>'targets_digest' IS DISTINCT FROM encode(digest(convert_to(captured_targets::text,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered captured destinations changed';END IF;
   END IF;
   checks:=checks||(SELECT jsonb_agg(jsonb_build_object('kind','gateway_device','id',id_value,'permission','manage_workflows') ORDER BY id_value) FROM jsonb_array_elements_text(destinations->'ids') id_value);
   f:=jsonb_set(f,'{fresh_until_ms}',to_jsonb(least((f->>'fresh_until_ms')::bigint,(destinations->>'fresh_until_ms')::bigint)));
  ELSE
   checks:=checks||jsonb_build_array(jsonb_build_object('kind','test','id',a.test_id,'permission','run_tests'),jsonb_build_object('kind',a.target_kind,'id',a.target_id,'permission','run_tests'));
  END IF;
 END IF;
 step_value:=jsonb_build_object('step_id',st.step_id,'action_key',st.action_key,'state',st.state,'version',st.version,'input_digest',encode(st.input_digest,'hex'),'plan_hash',encode(plan_value.plan_hash,'hex'));
 RETURN f||jsonb_build_object('ordered_action_key',st.action_key,'ordered_device_ids',CASE WHEN compensation OR st.step_index=1 THEN '[]'::jsonb ELSE destinations->'ids' END,'checks',checks,'execution_phase',phase,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),'step',step_value,'effect',effect_value,'destination_digest',destinations->'identity_digest','ordered_targets_digest',destinations->'targets_digest');
END $ordered_effect_source$;

CREATE FUNCTION zasp_authorization80_worker.ordered68_effect_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $effect_source$
DECLARE f jsonb;c zasp_authorization80_worker.ordered_effect_scope%ROWTYPE;compensation boolean:=phase IN('effect.read','effect.unknown');BEGIN
 f:=zasp_authorization80_worker.ordered68_effect_metadata(phase,q);
 SELECT * INTO c FROM zasp_authorization80_worker.ordered_effect_scope WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id');
 IF c.run_id IS NULL OR c.action_key IS DISTINCT FROM f->>'ordered_action_key'
 OR NOT compensation AND(NOT c.target_current OR c.fresh_until<=clock_timestamp() OR(c.device_ids,c.destination_digest,c.targets_digest) IS DISTINCT FROM(f->'ordered_device_ids',f->>'destination_digest',f->>'ordered_targets_digest')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered effect projection capture changed';END IF;
 RETURN f;
END $effect_source$;

-- Copy only the current worker proof parser. Its organization-before-parent
-- order, complete lifetime check after source locks and32768-byte cap remain.
DO $ordered_effect_proof$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.require_planning68(text,jsonb)'::regprocedure) INTO d;
 d:=zasp_authorization80_worker.ordered62_replace(d,E'BEGIN\n',E'BEGIN\n PERFORM pg_advisory_xact_lock_shared(hashtextextended(''zasp-schema-migrations'',0));\n');
 d:=replace(replace(replace(d,'require_planning68','require_ordered68_effect'),'planning68_source','ordered68_effect_source'),'ordered68.planning.','ordered68.');
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery')$old$,$new$('effect.reserve','effect.start','effect.read','effect.unknown')$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('reconcile','late_usage','recovery')$old$,$new$('effect.read','effect.unknown')$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,E' RETURNS void\n',E' RETURNS jsonb\n');
 d:=zasp_authorization80_worker.ordered62_replace(d,'EXCEPTION WHEN data_exception THEN',E' RETURN proof;\nEXCEPTION WHEN data_exception THEN');
 EXECUTE d;
END $ordered_effect_proof$;

INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid='zasp_temporal68.effect(jsonb)'::regprocedure;
DO $ordered_effect_boundary$ DECLARE d text;original text;needle text;replacement text;BEGIN
 SELECT definition INTO STRICT original FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal68.effect(jsonb)' AND owner_name='zasp_discovery_authority'
 AND acl='{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}';
 -- No outer nested call uses this copy until its own exact phase fence lands.
 d:=zasp_authorization80_worker.ordered62_replace(original,'FUNCTION zasp_temporal68.effect(q jsonb)','FUNCTION zasp_authorization80_worker.ordered68_effect_read(q jsonb)');
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('reserve','start','unknown','read')$old$,$new$('read')$new$);
 EXECUTE d;
 d:=zasp_authorization80_worker.ordered62_replace(original,'DECLARE o text;', 'DECLARE worker_proof jsonb;o text;');
 d:=zasp_authorization80_worker.ordered62_replace(d,E'BEGIN\n',E'BEGIN\n worker_proof:=zasp_authorization80_worker.require_ordered68_effect(''effect.''||(q->>''operation''),q);\n');
 -- Refuse expiry/reselection between source materialization and the original
 -- reserve query. The native set is compared before any destination is added.
 needle:=$old$   FOR device IN SELECT * FROM jsonb_to_recordset(targets) AS t(device_id text,credential_id text) LOOP$old$;
 replacement:=$new$   IF worker_proof#>>'{facts,ordered_targets_digest}' IS DISTINCT FROM encode(digest(convert_to(targets::text,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered reserved destinations changed';END IF;
$new$||needle;
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,replacement);
 needle:=$old$ RETURN to_jsonb(f)||jsonb_build_object('send_permit',permit);$old$;
 replacement:=$new$ IF NOT COALESCE((worker_proof->>'issued_at')::bigint<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint+5000 AND(worker_proof->>'expires_at')::bigint>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND(worker_proof->>'expires_at')::bigint-(worker_proof->>'issued_at')::bigint BETWEEN 1 AND 60000,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered effect proof expired';END IF;
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.principal_ready(CASE worker_proof->>'purpose' WHEN 'worker-forward' THEN 'zasp_temporal_executor' WHEN 'captured-compensation' THEN 'zasp_temporal_compensation' END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered effect session changed after wait';END IF;
 IF NOT live_value THEN RETURN jsonb_build_object('run_id',f.run_id,'step_id',f.step_id,'effect_key',f.effect_key,'generation',f.generation,'state',f.state,'send_permit',false);END IF;
$new$||needle;
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,replacement);
 EXECUTE d;
END $ordered_effect_boundary$;
