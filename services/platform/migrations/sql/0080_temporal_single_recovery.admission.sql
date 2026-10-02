CREATE FUNCTION zasp_temporal_single_recovery.human(q jsonb,mutate boolean,current_version boolean,revision_delta bigint) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $body$
DECLARE p jsonb:=zasp_authorization80.context();o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';r text:=q->>'run_id';a text:=q->>'actor_id';v bigint;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR revision_delta IS NULL OR revision_delta NOT BETWEEN 0 AND 4 THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='recovery isolation rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal_single_recovery.ready('-- recovery checksum') OR p IS NULL OR NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false)
 OR NOT COALESCE(zasp_authorization80.read_request(o,w,e,CASE WHEN mutate THEN ARRAY['requestSingleTestCleanupRecovery'] ELSE ARRAY['getSingleTestCleanupRecovery'] END,CASE WHEN mutate THEN 'manage_workflows' ELSE 'view' END,false,a)
 AND p->'collection'='false'::jsonb AND p#>>'{path_parameters,id}'=r AND jsonb_array_length(p->'targets')=1 AND jsonb_array_length(p->'allowed')=1 AND zasp_authorization80.allowed(o,w,e,'security_agent_run',r),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current recovery authority required';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations x WHERE x.organization_id=o AND(x.desired,x.applied,x.generation,x.store_id,x.model_id)=((p#>>'{revision,desired}')::bigint+revision_delta,(p#>>'{revision,applied}')::bigint,(p#>>'{revision,generation}')::bigint,p#>>'{revision,store_id}',p#>>'{revision,model_id}') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery authorization revision changed';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 IF mutate THEN PERFORM zasp_temporal74.manager(o,w,e,a);END IF;
 SELECT version INTO v FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF v IS NULL OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'targets') t WHERE(t->>'organization_id',t->>'workspace_id',t->>'environment_id',t->>'kind',t->>'id',COALESCE(NULLIF(t->>'source_id',''),t->>'id'))=(o,w,e,'security_agent_run',r,r) AND(NOT current_version OR(t->>'version')::bigint=v)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery target unavailable';END IF;
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery proof expired';END IF;
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.human(q jsonb,mutate boolean,current_version boolean) RETURNS void LANGUAGE sql VOLATILE SET search_path TO pg_catalog,public AS $body$
 SELECT zasp_temporal_single_recovery.human(q,mutate,current_version,0)
$body$;
CREATE FUNCTION zasp_temporal_single_recovery.validate_request(q jsonb) RETURNS void LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $body$
DECLARE k text;
BEGIN
 IF octet_length(q::text)>4096 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','actor_id','expected_version','definition_version','input_digest','idempotency_key','diagnostic','stop_original','audit_id','correlation_id','receipt_id']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery request shape rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id','actor_id','audit_id','correlation_id','receipt_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery identity rejected';END IF;
 END LOOP;
 IF NOT COALESCE(jsonb_typeof(q->'expected_version')='number' AND(q->>'expected_version')~'^[1-9][0-9]{0,5}$' AND jsonb_typeof(q->'definition_version')='number' AND(q->>'definition_version')~'^[1-9][0-9]{0,6}$' AND(q->>'definition_version')::bigint<=1000000 AND jsonb_typeof(q->'input_digest')='string' AND(q->>'input_digest')~'^[a-f0-9]{64}$' AND jsonb_typeof(q->'idempotency_key')='string' AND(q->>'idempotency_key')~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' AND q->'diagnostic'='"history_unavailable"'::jsonb AND q->'stop_original'='true'::jsonb AND q->>'audit_id'<>q->>'correlation_id' AND q->>'audit_id'<>q->>'receipt_id' AND q->>'correlation_id'<>q->>'receipt_id',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery intent rejected';END IF;
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.replay(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $body$
DECLARE rc zasp_temporal_single_recovery.request_receipts%ROWTYPE;v jsonb;
BEGIN
 SELECT * INTO rc FROM zasp_temporal_single_recovery.request_receipts WHERE(organization_id,workspace_id,environment_id,actor_id,idempotency_key)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'actor_id',q->>'idempotency_key');
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF rc.intent IS DISTINCT FROM q-ARRAY['audit_id','correlation_id','receipt_id'] OR rc.intent_digest IS DISTINCT FROM digest(convert_to(rc.intent::text,'UTF8'),'sha256') OR NOT EXISTS(SELECT 1 FROM zasp_temporal_single_recovery.audit a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.audit_id,a.actor_id,a.correlation_id,a.event_kind,a.body,a.body_digest)=(rc.organization_id,rc.workspace_id,rc.environment_id,rc.run_id,rc.audit_id,rc.actor_id,rc.correlation_id,'cleanup_recovery_requested',rc.intent,rc.intent_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery idempotency conflict';END IF;
 v:=zasp_temporal_single_recovery.value(rc.organization_id,rc.workspace_id,rc.environment_id,rc.run_id);
 IF rc.response->'body'->>'run_id' IS DISTINCT FROM rc.run_id OR rc.response->>'audit_id' IS DISTINCT FROM rc.audit_id OR rc.response->>'receipt_id' IS DISTINCT FROM rc.receipt_id OR rc.response->>'correlation_id' IS DISTINCT FROM rc.correlation_id OR rc.response->'replayed' IS DISTINCT FROM 'false'::jsonb OR rc.response->'body'->'command' IS DISTINCT FROM v->'command' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery receipt changed';END IF;
 RETURN rc.response||jsonb_build_object('replayed',true);
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.preflight(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;v bigint;rc jsonb;
BEGIN
 PERFORM zasp_temporal_single_recovery.validate_request(q);PERFORM zasp_temporal_single_recovery.human(q,true,false);
 x:=zasp_temporal_single_recovery.owner(q);rc:=zasp_temporal_single_recovery.replay(q);
 SELECT version INTO STRICT v FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF rc IS NULL THEN
  PERFORM zasp_temporal_single_recovery.human(q,true,true);
  IF v<>(q->>'expected_version')::bigint OR EXISTS(SELECT 1 FROM zasp_temporal_single_recovery.commands WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery parent changed';END IF;
 END IF;
 PERFORM zasp_temporal_single_recovery.human(q,true,rc IS NULL);
 RETURN jsonb_build_object('start',zasp_temporal_single_recovery.start_wire(x),'run_version',v,'workflow_id',x.workflow_id,'replay',rc);
END $body$;
CREATE FUNCTION zasp_temporal_single_recovery.admit(a jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$
DECLARE q jsonb:=a-'observation';ob jsonb:=a->'observation';x zasp_temporal74.run_owners%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;ci zasp_temporal74.control_intents%ROWTYPE;verified zasp_temporal74.run_owners%ROWTYPE;capture_row record;proof jsonb;binding jsonb;result_value jsonb;cmd jsonb;cid text;ck text;ca text;cr text;intent jsonb;at_value timestamptz;observed timestamptz;definition_hash bytea;revision_delta bigint:=0;
BEGIN
 IF octet_length(a::text)>8192 OR NOT(a?'observation') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery admission shape rejected';END IF;
 PERFORM zasp_temporal_single_recovery.validate_request(q);PERFORM zasp_temporal_single_recovery.human(q,true,false);
 -- The human fence already holds a parent SHARE lock. Never wait in inverse
 -- budget order, or on another fenced request upgrading that same parent.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||(q->>'organization_id'),0)) THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='recovery busy';END IF;
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id') FOR UPDATE NOWAIT;
 x:=zasp_temporal_single_recovery.owner(q);result_value:=zasp_temporal_single_recovery.replay(q);IF result_value IS NOT NULL THEN PERFORM zasp_temporal_single_recovery.human(q,true,false);RETURN result_value;END IF;
 PERFORM zasp_temporal_single_recovery.human(q,true,true);
 IF rr.version<>(q->>'expected_version')::bigint OR EXISTS(SELECT 1 FROM zasp_temporal_single_recovery.commands WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery version or ownership changed';END IF;
 IF NOT COALESCE(ob?'run_id' AND zasp_sa_multistep_prior.closed(ob-'run_id',ARRAY['workflow_id','status','observed_at']),false) OR NOT COALESCE(ob->>'workflow_id'=x.workflow_id AND jsonb_typeof(ob->'observed_at')='string' AND(ob->>'observed_at')~'Z$' AND(ob->>'status'='absent' AND ob->'run_id'='null'::jsonb OR ob->>'status'='closed' AND jsonb_typeof(ob->'run_id')='string' AND length(ob->>'run_id') BETWEEN 1 AND 256),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery observation rejected';END IF;
 observed:=(ob->>'observed_at')::timestamptz;IF observed<clock_timestamp()-interval '30 seconds' OR observed>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery observation expired';END IF;
 cid:=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'single_test_cleanup_recovery',x.run_id);
 proof:=zasp_temporal_single_recovery.proof(x);
 IF proof IS NULL OR zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id) THEN
  IF rr.state IN('queued','planning','waiting_approval','running','verifying') THEN
   -- Base79 always captures the run state change. The installed worker
   -- captures change only when their already-derived row exists. Lock and
   -- count those exact rows before cancel_core takes the same lock order.
   revision_delta:=1;
   FOR capture_row IN SELECT definition_id,definition_version,state,run_version FROM zasp_authorization80_worker.run_state WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE LOOP
    IF(capture_row.definition_id,capture_row.definition_version,capture_row.state,capture_row.run_version) IS DISTINCT FROM(rr.definition_id,rr.definition_version,rr.state,rr.version) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery captured state changed';END IF;revision_delta:=revision_delta+1;
   END LOOP;
   FOR capture_row IN SELECT definition_id,definition_version,state,run_version FROM zasp_authorization80_worker.test_state WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE LOOP
    IF(capture_row.definition_id,capture_row.definition_version,capture_row.state,capture_row.run_version) IS DISTINCT FROM(rr.definition_id,rr.definition_version,rr.state,rr.version) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery captured state changed';END IF;revision_delta:=revision_delta+1;
   END LOOP;
   FOR capture_row IN SELECT definition_id,definition_version,state,run_version FROM zasp_authorization80_worker.ordered_state WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE LOOP
    IF(capture_row.definition_id,capture_row.definition_version,capture_row.state,capture_row.run_version) IS DISTINCT FROM(rr.definition_id,rr.definition_version,rr.state,rr.version) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery captured state changed';END IF;revision_delta:=revision_delta+1;
   END LOOP;
   ck:='str:'||encode(digest(convert_to(cid||chr(31)||'cancel-v1','UTF8'),'sha256'),'hex');
   ca:=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'single_test_recovery_cancel_audit',cid);cr:=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'single_test_recovery_cancel_receipt',cid);
   result_value:=zasp_temporal74.cancel_core(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q->>'actor_id',ck,rr.version,ca,q->>'correlation_id',cr);
   PERFORM zasp_temporal74.record_control(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q->>'actor_id','cancelSecurityAgentRun',ck);
   SELECT * INTO STRICT ci FROM zasp_temporal74.control_intents WHERE(organization_id,workspace_id,environment_id,run_id,actor_id,operation,idempotency_key)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q->>'actor_id','cancelSecurityAgentRun',ck);
   verified:=zasp_temporal74.decision_owner(ci);
   IF verified IS DISTINCT FROM x OR result_value->>'id' IS DISTINCT FROM x.run_id OR result_value->>'state' IS DISTINCT FROM 'cancelled' OR result_value->'version' IS DISTINCT FROM to_jsonb(rr.version+1) OR result_value->'replayed' IS DISTINCT FROM 'false'::jsonb OR result_value->>'audit_id' IS DISTINCT FROM ca OR result_value->>'receipt_id' IS DISTINCT FROM cr OR result_value->>'correlation_id' IS DISTINCT FROM q->>'correlation_id' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='native cancellation proof rejected';END IF;
  ELSIF rr.state='cancelled' AND proof IS NULL THEN
   SELECT * INTO STRICT ci FROM zasp_temporal74.control_intents WHERE(organization_id,workspace_id,environment_id,run_id,operation)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,'cancelSecurityAgentRun');verified:=zasp_temporal74.decision_owner(ci);
   IF verified IS DISTINCT FROM x THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='native stop owner changed';END IF;
  ELSIF proof IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='native stop proof required';END IF;
  IF ci.control_id IS NOT NULL THEN binding:=jsonb_build_object('kind','cancel','receipt_id',ci.receipt_id,'audit_id',ci.audit_id,'digest',encode(ci.response_digest,'hex'));
  ELSE binding:=jsonb_build_object('kind',proof->>'kind','receipt_id',NULL,'audit_id',NULL,'digest',encode(digest(convert_to(proof::text,'UTF8'),'sha256'),'hex'));END IF;
  SELECT definition_digest INTO STRICT definition_hash FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version);
  cmd:=jsonb_build_object('format','single-test-cleanup-command-v1','start',zasp_temporal_single_recovery.start_wire(x),'command_id',cid,'workflow_id',x.workflow_id,'definition_id',x.definition_id,'definition_digest',encode(definition_hash,'hex'),'step_id',x.step_id,'child_run_id',x.test_run_id,'admitted_parent_version',rr.version,'stop_binding',binding,'obligations',zasp_temporal_single_recovery.obligations(x));
  IF octet_length(cmd::text)>65536 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='recovery metadata bound exceeded';END IF;
  INSERT INTO zasp_temporal_single_recovery.commands VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,cid,digest(convert_to(cmd::text,'UTF8'),'sha256'),cmd,clock_timestamp());
  INSERT INTO zasp_temporal_single_recovery.deliveries VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,cid,NULL,NULL);
  INSERT INTO zasp_temporal_single_recovery.progress VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,cid,'queued','queued',1,clock_timestamp());
 END IF;
 intent:=q-ARRAY['audit_id','correlation_id','receipt_id'];at_value:=clock_timestamp();
 INSERT INTO zasp_temporal_single_recovery.audit VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q->>'audit_id',q->>'correlation_id',q->>'actor_id','cleanup_recovery_requested',intent,digest(convert_to(intent::text,'UTF8'),'sha256'),at_value);
 -- value_without_request handles the proof-complete/no-command case here;
 -- subsequent GET validates this immutable request receipt too.
 result_value:=jsonb_build_object('body',zasp_temporal_single_recovery.value_without_request(x,q->>'receipt_id',at_value),'audit_id',q->>'audit_id','correlation_id',q->>'correlation_id','receipt_id',q->>'receipt_id','replayed',false);
 INSERT INTO zasp_temporal_single_recovery.request_receipts VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q->>'actor_id',q->>'idempotency_key',q->>'audit_id',q->>'correlation_id',q->>'receipt_id',(q->>'expected_version')::bigint,intent,digest(convert_to(intent::text,'UTF8'),'sha256'),result_value,at_value);
 PERFORM zasp_temporal_single_recovery.human(q,true,false,revision_delta);RETURN result_value;
END $body$;
