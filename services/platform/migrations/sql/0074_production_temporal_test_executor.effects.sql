-- One single-test intent, with the historical child and SQS identities. A
-- durable dispatch records uncertainty; no retry creates another generation.
CREATE TABLE zasp_temporal74.effects(LIKE zasp_temporal68.effects INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE zasp_temporal74.effects DROP CONSTRAINT effects_action_key_check;
ALTER TABLE zasp_temporal74.effects ADD CHECK(action_key IN('run_test','rerun_test')),
 ADD PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id,generation),ADD UNIQUE(effect_key),
 ADD FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id);
CREATE TABLE zasp_temporal74.test_inputs(LIKE zasp_temporal68.test_inputs INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE zasp_temporal74.test_inputs ADD PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),ADD UNIQUE(organization_id,workspace_id,environment_id,test_run_id),
 ADD FOREIGN KEY(organization_id,workspace_id,environment_id,test_run_id) REFERENCES public.zasp_security_agent_test_links(organization_id,workspace_id,environment_id,test_run_id);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['effects','test_inputs'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal74.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal74.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal74.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal74.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
 END LOOP;
END $tables$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal74.test_inputs FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

INSERT INTO zasp_temporal74.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid=ANY(ARRAY[
 'zasp_temporal68.effect_identity(text,text,text,text,text,bigint)'::regprocedure,'zasp_temporal68.test_target(text,text,text,text,text,text,bigint)'::regprocedure,
 'public.zasp_security_agent_test_link_enqueue(text,text,text,text,text,text)'::regprocedure]);
DO $domain$ DECLARE d text;part text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal68.effect_identity(text,text,text,text,text,bigint)';
 EXECUTE replace(d,'zasp_temporal68.','zasp_temporal74.');
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal68.test_target(text,text,text,text,text,text,bigint)';
 EXECUTE replace(d,'zasp_temporal68.','zasp_temporal74.');
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_security_agent_test_link_enqueue(text,text,text,text,text,text)';
 part:=substring(d FROM position(' SELECT jsonb_build_object(''schema_version'',''security-agent-test-baseline-v1''' IN d));
 IF part IS NULL OR position('ORDER BY b.completed_at DESC,b.run_id DESC,a.attempt DESC LIMIT 1;' IN part)=0 THEN RAISE EXCEPTION 'single-test baseline predecessor changed';END IF;
 part:=left(part,position('ORDER BY b.completed_at DESC,b.run_id DESC,a.attempt DESC LIMIT 1;' IN part)+length('ORDER BY b.completed_at DESC,b.run_id DESC,a.attempt DESC LIMIT 1;')-1);
 EXECUTE 'CREATE FUNCTION zasp_temporal74.baseline(o text,w text,e text,binding jsonb,test_run text,baseline_cutoff timestamptz) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $baseline$ DECLARE baseline_value jsonb;BEGIN '||part||' RETURN baseline_value;END $baseline$';
END $domain$;

CREATE FUNCTION zasp_temporal74.current_step(o text,w text,e text,r text,s text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $current$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;b public.zasp_security_agent_run_budgets%ROWTYPE;a public.zasp_security_agent_approvals%ROWTYPE;cv jsonb;item jsonb;binding jsonb;authorization_value text;requester text;
BEGIN
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO p FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR UPDATE;
 SELECT * INTO b FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 cv:=zasp_temporal74.context(o,w,e,r);item:=p.plan->'steps'->0;
 binding:=zasp_temporal71.body21(o,w,e,rr.definition_id,rr.definition_version);
 authorization_value:=CASE cv->'definition'->>'autonomy' WHEN 'supervised' THEN 'approval_required' ELSE 'autonomous' END;
 IF rr.run_id IS NULL OR p.run_id IS NULL OR st.run_id IS NULL OR b.run_id IS NULL OR rr.state NOT IN('queued','running') OR b.stop_reason IS NOT NULL OR b.deadline_at<=clock_timestamp() OR b.max_steps<>1
  OR p.plan_hash IS DISTINCT FROM rr.plan_hash OR p.plan_hash IS DISTINCT FROM digest(convert_to(p.plan::text,'UTF8'),'sha256') OR p.expires_at<=clock_timestamp()
  OR (p.definition_id,p.definition_version) IS DISTINCT FROM(rr.definition_id,rr.definition_version) OR jsonb_array_length(p.plan->'steps')<>1
  OR st.step_index<>0 OR st.state NOT IN('authorized','executing') OR st.action_key NOT IN('run_test','rerun_test') OR st.authorization_result IS DISTINCT FROM authorization_value
  OR st.input_digest IS DISTINCT FROM digest(convert_to(item::text,'UTF8'),'sha256')
  OR item IS DISTINCT FROM jsonb_build_object('step_id',s,'index',0,'action',st.action_key,'target_id',binding->>'definition_id','test_definition_version',binding->'definition_version','test_target_id',binding->>'target_id','test_target_kind',binding->>'target_kind','authorization',authorization_value)
  OR NOT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,st.action_key))
  OR NOT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs j JOIN zasp_temporal74.provider_reservations x USING(organization_id,workspace_id,environment_id,run_id) WHERE (j.organization_id,j.workspace_id,j.environment_id,j.run_id,j.state)=(o,w,e,r,'admitted') AND j.input_version IS NOT NULL AND j.output_version IS NOT NULL AND x.settled_at IS NOT NULL AND x.reservation_id=j.reservation_id AND x.total_tokens<=b.max_tokens AND x.cost_nano_credits<=b.max_cost_nano_credits AND x.total_tokens=(j.result_value->'usage'->>'total_tokens')::bigint AND x.cost_nano_credits=(j.result_value->'usage'->>'cost_nano_credits')::bigint)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test current step rejected';END IF;
 SELECT * INTO a FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR SHARE;
 IF authorization_value='approval_required' THEN
  requester:=rr.requested_by;
  IF EXISTS(SELECT 1 FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id,source_kind)=(o,w,e,r,'automatic73')) THEN requester:=zasp_temporal74.authorize(o,w,e,rr.definition_id,rr.definition_version)->>'principal_id';END IF;
  IF a.run_id IS NULL OR a.state<>'approved' OR a.plan_hash IS DISTINCT FROM p.plan_hash OR a.requester_id IS DISTINCT FROM requester OR a.approver_id IS NULL OR a.approver_id=a.requester_id OR a.fresh_auth_at IS NULL OR a.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test approval unavailable';END IF;
 ELSIF a.run_id IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test unexpected approval';END IF;
END $current$;

CREATE FUNCTION zasp_temporal74.test_reserve(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $reserve$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;d public.zasp_red_team_definitions%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;item jsonb;resolution jsonb;binding jsonb;base jsonb;input_hash bytea;actor text;payload jsonb;result_value jsonb;
BEGIN
 SELECT * INTO STRICT x FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO STRICT st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state)=(o,w,e,r,s,'authorized');
 SELECT plan->'steps'->0 INTO STRICT item FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT requested_by INTO STRICT actor FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF x.source_kind='automatic73' THEN actor:=zasp_temporal74.authorize(o,w,e,x.definition_id,x.definition_version)->>'principal_id';END IF;
 SELECT * INTO d FROM public.zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,target_id,target_kind,enabled)=(o,w,e,item->>'target_id',(item->>'test_definition_version')::bigint,item->>'test_target_id',item->>'test_target_kind',true) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test target changed';END IF;
 resolution:=zasp_temporal74.test_target(o,w,e,d.target_id,d.target_kind,d.definition_id,d.version);
 binding:=jsonb_build_object('definition_id',d.definition_id,'definition_version',d.version);
 base:=zasp_temporal74.baseline(o,w,e,binding,x.test_run_id,clock_timestamp());
 input_hash:=digest(convert_to(jsonb_build_object('definition_id',d.definition_id,'definition_version',d.version,'run_id',x.test_run_id)::text,'UTF8'),'sha256');
 INSERT INTO public.zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest) VALUES(o,w,e,x.test_run_id,d.definition_id,d.version,actor,input_hash) RETURNING * INTO child;
 payload:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',x.test_run_id,'definition_id',d.definition_id,'definition_version',d.version,'input_digest',encode(input_hash,'hex'));
 INSERT INTO public.zasp_red_team_outbox(organization_id,workspace_id,environment_id,outbox_id,deterministic_key,payload,payload_digest) VALUES(o,w,e,public.zasp_discovery_canonical_id(o,w,e,'red_team_outbox',x.test_run_id),'test-jobs:'||x.test_run_id,payload,digest(convert_to(payload::text,'UTF8'),'sha256'));
 result_value:=public.zasp_red_team_mutation_result(o,w,e,actor,'runTest',x.test_run_id,x.test_run_id,'agent-step:'||x.test_run_id,public.zasp_red_team_run_json(child));
 INSERT INTO public.zasp_red_team_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent_digest,audit_id,correlation_id,receipt_id,result) VALUES(o,w,e,actor,'runTest','agent-step:'||x.test_run_id,x.test_run_id,d.version,input_hash,result_value->>'audit_id',result_value->>'correlation_id',result_value->>'receipt_id',result_value);
 INSERT INTO public.zasp_security_agent_test_links(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,test_definition_id,test_definition_version,test_run_id,target_id,target_kind,test_categories,baseline,result)
 VALUES(o,w,e,r,s,x.action_key,st.input_digest,d.definition_id,d.version,x.test_run_id,d.target_id,d.target_kind,d.categories,base,jsonb_build_object('test_run_id',x.test_run_id,'definition_id',d.definition_id,'definition_version',d.version,'state','pending','replayed',false));
 RETURN jsonb_build_object('step',item,'test_run_id',x.test_run_id,'input_digest',encode(input_hash,'hex'),'resolution',resolution);
END $reserve$;

CREATE FUNCTION zasp_temporal74.effect(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $effect$
DECLARE o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';r text:=q->>'run_id';s text:=q->>'step_id';op text:=q->>'operation';k text;live_value boolean;permit boolean:=false;snapshot_value jsonb;targets jsonb;
 rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;f zasp_temporal74.effects%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='single-test effect requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='single-test catalog unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR octet_length(q::text)>4096 OR q->'generation' IS DISTINCT FROM '1'::jsonb OR q->'payload' IS DISTINCT FROM '{}'::jsonb OR NOT COALESCE(op IN('reserve','start','unknown','read'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test effect request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id','step_id'] LOOP IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test effect scope rejected';END IF;END LOOP;
 live_value:=op IN('reserve','start');
 IF NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR NOT live_value AND zasp_temporal68.principal_ready('zasp_temporal_compensation')) OR NOT zasp_temporal74.is_owned(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test effect authority rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO STRICT st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR UPDATE;
 IF live_value THEN PERFORM zasp_temporal74.current_step(o,w,e,r,s);END IF;
 SELECT * INTO f FROM zasp_temporal74.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,1) FOR UPDATE;
 IF NOT FOUND THEN
  IF op<>'reserve' OR st.state<>'authorized' OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) OR EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test effect reservation unavailable';END IF;
  INSERT INTO public.zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest) VALUES(o,w,e,r,s,st.action_key,st.input_digest);
  INSERT INTO public.zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,attempt) VALUES(o,w,e,r,s,st.action_key,st.input_digest,'pending',1);
  targets:=zasp_temporal74.test_reserve(o,w,e,r,s);
  snapshot_value:=jsonb_build_object('plan_hash',encode(rr.plan_hash,'hex'),'input_digest',encode(st.input_digest,'hex'),'targets',targets);
  INSERT INTO zasp_temporal74.effects VALUES(o,w,e,r,s,1,zasp_temporal74.effect_identity(o,w,e,r,s,1),st.action_key,st.input_digest,rr.plan_hash,snapshot_value,digest(convert_to(snapshot_value::text,'UTF8'),'sha256'),'reserved',NULL,NULL) RETURNING * INTO f;
  UPDATE public.zasp_security_agent_steps SET state='executing',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  UPDATE public.zasp_security_agent_runs SET state='running',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 END IF;
 IF f.effect_key IS DISTINCT FROM zasp_temporal74.effect_identity(o,w,e,r,s,1) OR (f.input_digest,f.plan_hash,f.action_key) IS DISTINCT FROM(st.input_digest,rr.plan_hash,st.action_key) OR f.snapshot_digest IS DISTINCT FROM digest(convert_to(f.snapshot::text,'UTF8'),'sha256') OR f.snapshot->>'plan_hash' IS DISTINCT FROM encode(rr.plan_hash,'hex') OR f.snapshot->>'input_digest' IS DISTINCT FROM encode(st.input_digest,'hex')
 OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(o,w,e,r,s,f.action_key,f.input_digest) AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(o,w,e,r,s,f.action_key,f.input_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test effect identity changed';END IF;
 IF op='start' AND f.state='reserved' THEN
  IF NOT EXISTS(SELECT 1 FROM zasp_temporal74.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test immutable input absent';END IF;
  UPDATE zasp_temporal74.effects SET state='started',started_at=clock_timestamp() WHERE effect_key=f.effect_key RETURNING * INTO f;
  UPDATE public.zasp_security_agent_effects SET state='unknown_outcome',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);permit:=true;
 ELSIF op='unknown' THEN
  IF f.state NOT IN('started','unknown') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test effect not sent';END IF;
  UPDATE zasp_temporal74.effects SET state='unknown' WHERE effect_key=f.effect_key RETURNING * INTO f;
 END IF;
 IF live_value THEN PERFORM zasp_temporal74.current_step(o,w,e,r,s);END IF;
 IF NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='single-test catalog changed';END IF;
 RETURN to_jsonb(f)||jsonb_build_object('send_permit',permit);
END $effect$;
