-- Connected downstream Test boundaries. This module is deliberately separate
-- from planner disclosure and Block signing. No completed-receipt first settle.
CREATE FUNCTION zasp_authorization80_worker.ordered68_progress_facts(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $progress_facts$
DECLARE x zasp_temporal66.run_owners%ROWTYPE;c zasp_temporal65.commands%ROWTYPE;r public.zasp_security_agent_runs%ROWTYPE;
 tr public.zasp_security_agent_trigger_receipts%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;a zasp_authorization80_worker.ordered_associations%ROWTYPE;source_hash text;
BEGIN
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered progress executor rejected';END IF;
 SELECT * INTO x FROM zasp_temporal66.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id') FOR SHARE;
 SELECT * INTO r FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR SHARE;
 SELECT * INTO c FROM zasp_temporal65.commands WHERE(organization_id,workspace_id,environment_id,run_id,kind)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,'start') FOR SHARE;
 SELECT * INTO tr FROM public.zasp_security_agent_trigger_receipts WHERE(organization_id,workspace_id,environment_id,run_id,definition_id,trigger_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,r.definition_id,r.trigger_id) FOR SHARE;
 SELECT * INTO h FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(r.organization_id,r.workspace_id,r.environment_id,r.definition_id,r.definition_version) FOR SHARE;
 IF x.run_id IS NULL OR r.run_id IS NULL OR c.run_id IS NULL OR tr.run_id IS NULL OR h.definition_id IS NULL OR x.execution_owner<>'temporal' OR c.execution_owner<>'temporal'
 OR(c.definition_version,c.input_digest) IS DISTINCT FROM(x.definition_version,x.input_digest) OR r.definition_version IS DISTINCT FROM x.definition_version
 OR r.lease_owner IS NOT NULL OR r.lease_token IS NOT NULL OR r.lease_expires_at IS NOT NULL OR tr.trigger_kind NOT IN('finding','attack_path') OR encode(tr.trigger_digest,'hex') IS DISTINCT FROM x.input_digest
 OR r.run_id IS DISTINCT FROM public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_run',r.definition_id||chr(31)||r.trigger_id||chr(31)||tr.trigger_version::text)
 OR h.definition_digest IS DISTINCT FROM digest(convert_to(h.definition::text,'UTF8'),'sha256') OR h.definition->'allowed_actions' IS DISTINCT FROM '["create_temporary_policy","run_test"]'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered progress admission changed';END IF;
 source_hash:=encode(digest(convert_to(jsonb_build_array(x.execution_owner,r.definition_id,x.definition_version,x.input_digest,c.event_id,tr.trigger_kind,tr.trigger_id,tr.trigger_version,encode(h.definition_digest,'hex'))::text,'UTF8'),'sha256'),'hex');
 SELECT * INTO a FROM zasp_authorization80_worker.ordered_associations WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF a.run_id IS NULL OR(a.definition_id,a.definition_version,a.definition_digest,a.source_digest) IS DISTINCT FROM(r.definition_id,r.definition_version,encode(h.definition_digest,'hex'),source_hash)
 OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,r.state,r.version,true)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered progress capture changed';END IF;
 -- No test_current/application_ready here: the original progress transition
 -- owns both successor-ready and its conservative blocked branch.
 RETURN to_jsonb(a)||jsonb_build_object('run_state',r.state,'run_version',r.version,'session_user',session_user,'checks',jsonb_build_array(jsonb_build_object('kind','security_agent','id',a.definition_id,'permission','manage_workflows'),jsonb_build_object('kind','security_agent_run','id',a.run_id,'permission','manage_workflows')));
END $progress_facts$;

DO $ordered_adapter_facts$ DECLARE d text;BEGIN
 d:=pg_get_functiondef('zasp_authorization80_worker.ordered68_effect_facts(boolean,jsonb)'::regprocedure);
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_authorization80_worker.ordered68_effect_facts(', 'FUNCTION zasp_authorization80_worker.ordered68_adapter_facts(');
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$zasp_temporal68.principal_ready(CASE WHEN compensation THEN 'zasp_temporal_compensation' ELSE 'zasp_temporal_executor' END)$old$,$new$(CASE WHEN compensation THEN zasp_temporal68.principal_ready('zasp_temporal_compensation') ELSE zasp_temporal68.adapter_principal_ready() END)$new$);
 EXECUTE d;
END $ordered_adapter_facts$;

CREATE FUNCTION zasp_authorization80_worker.ordered68_test_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $test_source$
DECLARE o text;w text;e text;r text;s text;child_id text;k text;expected text;limit_value integer;captured boolean;adapter boolean;
 x zasp_temporal66.run_owners%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;pl public.zasp_security_agent_plans%ROWTYPE;
 f zasp_temporal68.effects%ROWTYPE;l public.zasp_security_agent_test_links%ROWTYPE;i zasp_temporal68.test_inputs%ROWTYPE;j zasp_temporal68.invocations%ROWTYPE;
 a zasp_authorization80_worker.ordered_associations%ROWTYPE;scope_value zasp_authorization80_worker.ordered_effect_scope%ROWTYPE;
 facts jsonb;reference_value jsonb;observations jsonb;application_value jsonb;settlement_value jsonb;checks jsonb;
BEGIN
 IF phase IS NULL OR phase NOT IN('progress','test.state','linked.read','linked.input','linked.dispatch','adapter.resolve','adapter.start','adapter.complete','test.settle','test.replay','test.stop') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered test phase rejected';END IF;
 captured:=phase IN('test.state','adapter.complete','test.replay','test.stop');adapter:=phase IN('adapter.resolve','adapter.start');
 limit_value:=CASE WHEN phase IN('test.settle','test.replay') THEN 1500000 WHEN phase LIKE 'linked.%' THEN 131072 WHEN phase LIKE 'adapter.%' THEN 8192 ELSE 4096 END;
 IF octet_length(q::text)>limit_value OR jsonb_typeof(q) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered test request rejected';END IF;
 IF phase='progress' THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','operation','actor_id','run_version','approval_version','fresh_auth_at']) OR q->>'operation' IS DISTINCT FROM 'progress' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered progress shape rejected';END IF;
 ELSIF phase='test.state' THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered test state rejected';END IF;
 ELSIF phase LIKE 'adapter.%' THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','effect_key','operation','payload','checksum','fingerprint']) OR q->>'operation' IS DISTINCT FROM split_part(phase,'.',2)
  OR NOT COALESCE(q->>'effect_key'~'^[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered adapter shape rejected';END IF;
 ELSE
  expected:=CASE phase WHEN 'test.settle' THEN 'complete' WHEN 'test.replay' THEN 'complete' WHEN 'test.stop' THEN 'stop' ELSE split_part(phase,'.',2) END;
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR q->'generation' IS DISTINCT FROM '1'::jsonb OR q->>'operation' IS DISTINCT FROM expected OR jsonb_typeof(q->'payload') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered test effect shape rejected';END IF;
 END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered test scope rejected';END IF;
 END LOOP;
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered test requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready() OR NOT(CASE WHEN adapter THEN zasp_temporal68.adapter_principal_ready() ELSE zasp_temporal68.principal_ready(CASE WHEN captured THEN 'zasp_temporal_compensation' ELSE 'zasp_temporal_executor' END) END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered test principal rejected';END IF;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered test organization absent';END IF;
 IF phase LIKE 'adapter.%' THEN
  child_id:=r;
  SELECT * INTO l FROM public.zasp_security_agent_test_links WHERE(organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,child_id);
  IF l.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered adapter child absent';END IF;
  r:=l.run_id;
 END IF;
 PERFORM zasp_sa_multistep_prior.test_lock(o,w,e,r);
 s:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'1');
 IF phase<>'test.state' AND phase NOT LIKE 'adapter.%' AND q->>'step_id' IS DISTINCT FROM s THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered test successor changed';END IF;
 SELECT * INTO x FROM zasp_temporal66.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 IF x.run_id IS NULL OR phase='test.state' AND q->'definition_version' IS DISTINCT FROM to_jsonb(x.definition_version) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered test owner changed';END IF;
 reference_value:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'definition_version',x.definition_version,'input_digest',x.input_digest);
 IF phase='progress' THEN facts:=zasp_authorization80_worker.ordered68_progress_facts(reference_value);
 ELSIF adapter THEN facts:=zasp_authorization80_worker.ordered68_adapter_facts(false,reference_value);
 ELSE facts:=zasp_authorization80_worker.ordered68_effect_facts(captured,reference_value);END IF;
 a:=jsonb_populate_record(NULL::zasp_authorization80_worker.ordered_associations,facts);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_associations v WHERE v=a) OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_state v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.run_id,v.definition_id,v.definition_version,v.state,v.run_version,v.present)=(o,w,e,r,a.definition_id,a.definition_version,facts->>'run_state',(facts->>'run_version')::bigint,true)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered test capture changed';END IF;
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR SHARE;
 SELECT * INTO pl FROM public.zasp_security_agent_plans WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 IF st.step_id IS NULL OR st.step_index<>1 OR st.action_key<>'run_test' OR pl.run_id IS NULL OR pl.plan->'steps'->1->>'step_id' IS DISTINCT FROM s THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered test plan changed';END IF;
 SELECT * INTO f FROM zasp_temporal68.effects WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,1) FOR SHARE;
 IF phase NOT IN('progress','test.state') THEN
  IF f.run_id IS NULL OR NOT zasp_temporal68.test_intent_valid(o,w,e,r,s) OR f.snapshot_digest IS DISTINCT FROM digest(convert_to(f.snapshot::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered test intent changed';END IF;
  SELECT * INTO l FROM public.zasp_security_agent_test_links WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR UPDATE;
  IF phase LIKE 'adapter.%' AND(l.test_run_id IS DISTINCT FROM child_id OR q->>'effect_key' IS DISTINCT FROM f.effect_key) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered adapter identity changed';END IF;
  SELECT * INTO i FROM zasp_temporal68.test_inputs WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  SELECT * INTO scope_value FROM zasp_authorization80_worker.ordered_effect_scope WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  IF scope_value.run_id IS NULL OR scope_value.action_key<>'run_test' OR NOT captured AND(NOT scope_value.target_current OR scope_value.fresh_until<=clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered test execution scope absent';END IF;
  IF NOT captured THEN
   PERFORM zasp_sa_multistep_prior.test_current(o,w,e,r,s);
   IF zasp_temporal68.test_target(o,w,e,l.target_id,l.target_kind,l.test_definition_id,l.test_definition_version) IS DISTINCT FROM f.snapshot->'targets'->'resolution' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered test target changed';END IF;
  END IF;
 END IF;
 IF phase='adapter.complete' THEN
  SELECT * INTO j FROM zasp_temporal68.invocations WHERE(organization_id,workspace_id,environment_id,test_run_id,category)=(o,w,e,child_id,q->'payload'->>'category') FOR UPDATE;
  IF j.test_run_id IS NULL OR j.effect_key IS DISTINCT FROM f.effect_key OR j.request_digest IS DISTINCT FROM decode(q->'payload'->>'request_digest','hex') OR j.target_resolution IS DISTINCT FROM f.snapshot->'targets'->'resolution' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered held journal changed';END IF;
 END IF;
 SELECT COALESCE(jsonb_agg(zasp_authorization80_worker.ordered68_row_json(v) ORDER BY category),'[]'::jsonb) INTO observations FROM zasp_temporal68.invocations v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.test_run_id)=(o,w,e,l.test_run_id);
 SELECT zasp_authorization80_worker.ordered68_row_json(v) INTO settlement_value FROM zasp_temporal68.test_settlements v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.run_id,v.step_id)=(o,w,e,r,s);
 IF phase='test.replay' AND settlement_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered stored settlement absent';END IF;
 -- Bind the real optional step0 application receipt without turning absence
 -- into an early refusal of native progress's blocked branch.
 SELECT jsonb_agg(zasp_authorization80_worker.ordered68_row_json(v) ORDER BY v.step_id) INTO application_value FROM public.zasp_sa_multistep_receipts v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.run_id)=(o,w,e,r) AND v.step_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'0');
 checks:=CASE WHEN captured THEN '[]'::jsonb WHEN phase='progress' THEN facts->'checks' ELSE jsonb_build_array(jsonb_build_object('kind','security_agent','id',a.definition_id,'permission','manage_workflows'),jsonb_build_object('kind','security_agent_run','id',a.run_id,'permission','manage_workflows'),jsonb_build_object('kind','test','id',a.test_id,'permission','run_tests'),jsonb_build_object('kind',a.target_kind,'id',a.target_id,'permission','run_tests')) END;
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready() OR NOT(CASE WHEN adapter THEN zasp_temporal68.adapter_principal_ready() ELSE zasp_temporal68.principal_ready(CASE WHEN captured THEN 'zasp_temporal_compensation' ELSE 'zasp_temporal_executor' END) END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered test source authority changed';END IF;
 RETURN facts||jsonb_build_object('checks',checks,'ordered_action_key','run_test','ordered_device_ids','[]'::jsonb,'execution_phase',phase,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),
 'native_digest',encode(digest(convert_to(jsonb_build_array(zasp_authorization80_worker.ordered68_row_json(st),zasp_authorization80_worker.ordered68_row_json(pl),zasp_authorization80_worker.ordered68_row_json(f),zasp_authorization80_worker.ordered68_row_json(l),zasp_authorization80_worker.ordered68_row_json(i),observations,settlement_value,application_value)::text,'UTF8'),'sha256'),'hex'));
END $test_source$;

DO $ordered_test_proof$ DECLARE d text;BEGIN
 d:=pg_get_functiondef('zasp_authorization80_worker.require_planning68(text,jsonb)'::regprocedure);
 d:=replace(replace(replace(d,'require_planning68','require_ordered68_test'),'planning68_source','ordered68_test_source'),'ordered68.planning.','ordered68.');
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery')$old$,$new$('progress','test.state','linked.read','linked.input','linked.dispatch','adapter.resolve','adapter.start','adapter.complete','test.settle','test.replay','test.stop')$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('reconcile','late_usage','recovery')$old$,$new$('test.state','adapter.complete','test.replay','test.stop')$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$zasp_temporal68.principal_ready(CASE purpose_value WHEN 'worker-forward' THEN 'zasp_temporal_executor' ELSE 'zasp_temporal_compensation' END)$old$,$new$(CASE WHEN phase IN('adapter.resolve','adapter.start') THEN zasp_temporal68.adapter_principal_ready() ELSE zasp_temporal68.principal_ready(CASE purpose_value WHEN 'worker-forward' THEN 'zasp_temporal_executor' ELSE 'zasp_temporal_compensation' END) END)$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,E'BEGIN\n',E'BEGIN\n PERFORM pg_advisory_xact_lock_shared(hashtextextended(''zasp-schema-migrations'',0));\n');
 d:=zasp_authorization80_worker.ordered62_replace(d,E' RETURNS void\n',E' RETURNS jsonb\n');
 d:=zasp_authorization80_worker.ordered62_replace(d,'EXCEPTION WHEN data_exception THEN',E' RETURN proof;\nEXCEPTION WHEN data_exception THEN');
 EXECUTE d;
END $ordered_test_proof$;

CREATE FUNCTION zasp_authorization80_worker.ordered68_test_exit(phase text,proof jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $test_exit$
DECLARE now_ms bigint;BEGIN
 IF proof->>'operation' IS DISTINCT FROM 'ordered68.'||phase OR proof->>'session_user' IS DISTINCT FROM session_user
 OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready()
 OR NOT(CASE WHEN phase IN('adapter.resolve','adapter.start') THEN zasp_temporal68.adapter_principal_ready() ELSE zasp_temporal68.principal_ready(CASE proof->>'purpose' WHEN 'worker-forward' THEN 'zasp_temporal_executor' WHEN 'captured-compensation' THEN 'zasp_temporal_compensation' END) END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered test session changed';END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF NOT COALESCE((proof->>'issued_at')::bigint<=now_ms+5000 AND(proof->>'expires_at')::bigint>now_ms AND(proof->>'expires_at')::bigint-(proof->>'issued_at')::bigint BETWEEN 1 AND 60000,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered test proof expired';END IF;
END $test_exit$;

INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal68.progress(jsonb)'::regprocedure,'zasp_temporal68.linked(jsonb)'::regprocedure,'zasp_temporal68.invocation(jsonb)'::regprocedure,'zasp_temporal68.test_settle(jsonb)'::regprocedure,'zasp_temporal68.test_stop(jsonb)'::regprocedure);

DO $ordered_test_copies$ DECLARE d text;p record;needle text;BEGIN
 -- Only linked.dispatch calls this fixed start helper, inside its own proof.
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal68.effect(jsonb)' AND owner_name='zasp_discovery_authority' AND acl='{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}';
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal68.effect(q jsonb)','FUNCTION zasp_authorization80_worker.ordered68_linked_start(q jsonb)');
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('reserve','start','unknown','read')$old$,$new$('start')$new$);
 EXECUTE d;
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN('zasp_temporal68.progress(jsonb)','zasp_temporal68.linked(jsonb)','zasp_temporal68.invocation(jsonb)','zasp_temporal68.test_settle(jsonb)','zasp_temporal68.test_stop(jsonb)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered Test predecessor owner changed';END IF;
  d:=p.definition;
  CASE p.signature
  WHEN 'zasp_temporal68.progress(jsonb)' THEN
   IF p.acl<>'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered progress predecessor ACL changed';END IF;
   d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal68.progress(q jsonb)','FUNCTION zasp_authorization80_worker.ordered68_progress_native(q jsonb)');
  WHEN 'zasp_temporal68.linked(jsonb)' THEN
   IF p.acl<>'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority}' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered linked predecessor ACL changed';END IF;
   d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal68.linked(q jsonb)','FUNCTION zasp_authorization80_worker.ordered68_linked_native(q jsonb)');
   d:=zasp_authorization80_worker.ordered62_replace(d,$old$zasp_temporal68.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$old$,$new$zasp_authorization80_worker.ordered68_effect_read(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$new$);
   d:=zasp_authorization80_worker.ordered62_replace(d,$old$zasp_temporal68.effect(q||jsonb_build_object('operation','start','payload','{}'::jsonb))$old$,$new$zasp_authorization80_worker.ordered68_linked_start(q||jsonb_build_object('operation','start','payload','{}'::jsonb))$new$);
  WHEN 'zasp_temporal68.invocation(jsonb)' THEN
   IF p.acl<>'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_red_team_adapter=X/zasp_discovery_authority}' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered invocation predecessor ACL changed';END IF;
   d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal68.invocation(q jsonb)','FUNCTION zasp_authorization80_worker.ordered68_invocation_native(q jsonb)');
   EXECUTE d;
   d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_authorization80_worker.ordered68_invocation_native(q jsonb)','FUNCTION zasp_authorization80_worker.ordered68_completion_native(q jsonb)');
   d:=zasp_authorization80_worker.ordered62_replace(d,$old$('resolve','start','complete')$old$,$new$('complete')$new$);
   needle:='zasp_temporal68.adapter_principal_ready()';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered completion principal anchors changed';END IF;
   d:=replace(d,needle,$new$zasp_temporal68.principal_ready('zasp_temporal_compensation')$new$);
   d:=zasp_authorization80_worker.ordered62_replace(d,$old$zasp_temporal68.adapter_ready(q->>'checksum',q->>'fingerprint')$old$,$new$zasp_temporal68.ready(q->>'checksum',q->>'fingerprint')$new$);
  WHEN 'zasp_temporal68.test_settle(jsonb)' THEN
   IF p.acl<>'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority}' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered settlement predecessor ACL changed';END IF;
   d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal68.test_settle(q jsonb)','FUNCTION zasp_authorization80_worker.ordered68_test_settle_native(q jsonb)');
   d:=zasp_authorization80_worker.ordered62_replace(d,$old$zasp_temporal68.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$old$,$new$zasp_authorization80_worker.ordered68_effect_read(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$new$);
  WHEN 'zasp_temporal68.test_stop(jsonb)' THEN
   IF p.acl<>'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered stop predecessor ACL changed';END IF;
   d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal68.test_stop(q jsonb)','FUNCTION zasp_authorization80_worker.ordered68_test_stop_native(q jsonb)');
   d:=zasp_authorization80_worker.ordered62_replace(d,$old$zasp_temporal68.effect(q||jsonb_build_object('operation','read'))$old$,$new$zasp_authorization80_worker.ordered68_effect_read(q||jsonb_build_object('operation','read'))$new$);
  END CASE;
  EXECUTE d;
 END LOOP;
END $ordered_test_copies$;

CREATE OR REPLACE FUNCTION zasp_temporal68.progress(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $progress$
DECLARE proof jsonb;v jsonb;BEGIN
 proof:=zasp_authorization80_worker.require_ordered68_test('progress',q);
 v:=zasp_authorization80_worker.ordered68_progress_native(q);
 PERFORM zasp_authorization80_worker.ordered68_test_exit('progress',proof);RETURN v;
END $progress$;
CREATE OR REPLACE FUNCTION zasp_temporal68.linked(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $linked$
DECLARE phase text:='linked.'||(q->>'operation');proof jsonb;v jsonb;BEGIN
 IF phase NOT IN('linked.read','linked.input','linked.dispatch') OR phase IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered linked operation rejected';END IF;
 proof:=zasp_authorization80_worker.require_ordered68_test(phase,q);
 v:=zasp_authorization80_worker.ordered68_linked_native(q);
 PERFORM zasp_authorization80_worker.ordered68_test_exit(phase,proof);RETURN v;
END $linked$;
-- Use the original dispatch request/proof for both autocommits. The private
-- read operation cannot mutate the effect or return a send permit. A later
-- normal dispatch rechecks this same proof after external artifact readback.
CREATE FUNCTION zasp_authorization80_worker.ordered68_dispatch_readback(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $dispatch_readback$
DECLARE proof jsonb;v jsonb;BEGIN
 proof:=zasp_authorization80_worker.require_ordered68_test('linked.dispatch',q);
 v:=zasp_authorization80_worker.ordered68_linked_native(q||jsonb_build_object('operation','read'));
 IF v->'send_permit' IS DISTINCT FROM 'false'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered dispatch readback permit rejected';END IF;
 PERFORM zasp_authorization80_worker.ordered68_test_exit('linked.dispatch',proof);RETURN v;
END $dispatch_readback$;
CREATE OR REPLACE FUNCTION zasp_temporal68.invocation(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $invocation$
DECLARE phase text:='adapter.'||(q->>'operation');proof jsonb;v jsonb;BEGIN
 IF phase NOT IN('adapter.resolve','adapter.start') OR phase IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered forward invocation operation rejected';END IF;
 proof:=zasp_authorization80_worker.require_ordered68_test(phase,q);
 v:=zasp_authorization80_worker.ordered68_invocation_native(q);
 PERFORM zasp_authorization80_worker.ordered68_test_exit(phase,proof);RETURN v;
END $invocation$;
CREATE FUNCTION zasp_authorization80_worker.ordered68_test_complete(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $complete$
DECLARE proof jsonb;v jsonb;l public.zasp_security_agent_test_links%ROWTYPE;j zasp_temporal68.invocations%ROWTYPE;BEGIN
 proof:=zasp_authorization80_worker.require_ordered68_test('adapter.complete',q);
 PERFORM zasp_authorization80_worker.ordered68_completion_native(q);
 SELECT * INTO STRICT l FROM public.zasp_security_agent_test_links WHERE(organization_id,workspace_id,environment_id,test_run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id');
 SELECT * INTO STRICT j FROM zasp_temporal68.invocations WHERE(organization_id,workspace_id,environment_id,test_run_id,category)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id,q#>>'{payload,category}');
 v:=jsonb_build_object('organization_id',l.organization_id,'workspace_id',l.workspace_id,'environment_id',l.environment_id,'parent_run_id',l.run_id,'test_run_id',l.test_run_id,'step_id',l.step_id,'effect_key',j.effect_key,'category',j.category,'attempt',j.attempt,'state',j.state,'request_digest',encode(j.request_digest,'hex'),'response_digest',encode(j.response_digest,'hex'),'http_status',j.http_status,'protected',j.protected,'credential_version_digest',encode(j.credential_version_digest,'hex'),'completed_at',to_char(j.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 PERFORM zasp_authorization80_worker.ordered68_test_exit('adapter.complete',proof);RETURN v;
END $complete$;
CREATE OR REPLACE FUNCTION zasp_temporal68.test_settle(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $settle$
DECLARE proof jsonb;v jsonb;BEGIN
 proof:=zasp_authorization80_worker.require_ordered68_test('test.settle',q);
 v:=zasp_authorization80_worker.ordered68_test_settle_native(q);
 PERFORM zasp_authorization80_worker.ordered68_test_exit('test.settle',proof);RETURN v;
END $settle$;
CREATE FUNCTION zasp_authorization80_worker.ordered68_test_replay(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $replay$
DECLARE proof jsonb;t zasp_temporal68.test_settlements%ROWTYPE;BEGIN
 proof:=zasp_authorization80_worker.require_ordered68_test('test.replay',q);
 IF NOT zasp_sa_multistep_prior.closed(q->'payload',ARRAY['output_manifest','output_body']) OR jsonb_typeof(q#>'{payload,output_body}') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered settlement replay shape rejected';END IF;
 PERFORM zasp_authorization80_worker.ordered68_effect_read(q||jsonb_build_object('operation','read','payload','{}'::jsonb));
 SELECT * INTO t FROM zasp_temporal68.test_settlements WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id');
 IF t.run_id IS NULL OR(t.output_manifest,t.output_body) IS DISTINCT FROM(q#>'{payload,output_manifest}',decode(q#>>'{payload,output_body}','base64')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered settlement replay changed';END IF;
 PERFORM zasp_temporal68.test_evidence(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id);
 PERFORM zasp_authorization80_worker.ordered68_test_exit('test.replay',proof);RETURN t.response;
END $replay$;
CREATE OR REPLACE FUNCTION zasp_temporal68.test_stop(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $stop$
DECLARE proof jsonb;v jsonb;BEGIN
 proof:=zasp_authorization80_worker.require_ordered68_test('test.stop',q);
 v:=zasp_authorization80_worker.ordered68_test_stop_native(q);
 PERFORM zasp_authorization80_worker.ordered68_test_exit('test.stop',proof);RETURN v;
END $stop$;
CREATE FUNCTION zasp_authorization80_worker.ordered68_test_state(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $state$
DECLARE proof jsonb;v jsonb;result_value jsonb;BEGIN
 proof:=zasp_authorization80_worker.require_ordered68_test('test.state',q);
 v:=zasp_authorization80_worker.ordered69_status_inner(q);
 SELECT jsonb_build_object('run_id',v->'run_id','definition_version',v->'definition_version','run_state',v->'run_state','effects',COALESCE((SELECT jsonb_agg(jsonb_build_object('step_id',x->'step_id','effect_key',x->'effect_key','generation',x->'generation','state',x->'state','action_key',x->'action_key')) FROM jsonb_array_elements(v->'effects') x WHERE x->>'action_key'='run_test'),'[]'::jsonb)) INTO result_value;
 PERFORM zasp_authorization80_worker.ordered68_test_exit('test.state',proof);RETURN result_value;
END $state$;

GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_test_source(text,jsonb) TO zasp_temporal_executor,zasp_temporal_compensation,zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_dispatch_readback(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_test_complete(jsonb),zasp_authorization80_worker.ordered68_test_replay(jsonb),zasp_authorization80_worker.ordered68_test_state(jsonb) TO zasp_temporal_compensation;
