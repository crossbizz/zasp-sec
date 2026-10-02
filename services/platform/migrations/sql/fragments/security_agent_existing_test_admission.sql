-- Shared scoped evidence identity. It is private: API and worker wrappers have
-- separate registered principals and cannot impersonate each other.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_trigger(o text,w text,e text,k text,t text,s text,v bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $trigger$
DECLARE version_value bigint;digest_value bytea;event_row public.zasp_runtime_gateway_events%ROWTYPE;expiry_value timestamptz;
BEGIN
 IF k='finding' THEN
  SELECT version INTO version_value FROM public.zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,id,status,rule)=(o,w,e,t,'open',s) AND (v=0 OR version=v) FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test trigger changed';END IF;
  digest_value:=digest(convert_to(jsonb_build_object('kind','finding','id',t,'version',version_value)::text,'UTF8'),'sha256');
 ELSIF k='attack_path' THEN
  SELECT p.version INTO version_value FROM public.zasp_risk_attack_paths p WHERE (organization_id,workspace_id,environment_id,id,state)=(o,w,e,t,s) AND state IN('observed','verified') AND (v=0 OR version=v) AND public.zasp_risk_attack_path_valid(p) FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test trigger changed';END IF;
  digest_value:=digest(convert_to(jsonb_build_object('kind','attack_path','id',t,'version',version_value,'state',s)::text,'UTF8'),'sha256');
 ELSIF k='runtime_decision' THEN
  SELECT event.* INTO event_row FROM public.zasp_runtime_gateway_events event
  JOIN public.zasp_gateway_devices device ON (device.organization_id,device.workspace_id,device.environment_id,device.id,device.state)=(event.organization_id,event.workspace_id,event.environment_id,event.device_id,'active')
  JOIN public.zasp_gateway_credentials credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id,credential.id)=(event.organization_id,event.workspace_id,event.environment_id,event.device_id,event.credential_id)
  WHERE (event.organization_id,event.workspace_id,event.environment_id,event.classification->>'session_id',event.decision,event.classification->>'outcome')=(o,w,e,t,'block',s)
   AND event.occurred_at>=clock_timestamp()-interval '5 minutes' AND event.occurred_at<=clock_timestamp()
   AND event.event_id=(SELECT newest.event_id FROM public.zasp_runtime_gateway_events newest WHERE (newest.organization_id,newest.workspace_id,newest.environment_id,newest.classification->>'session_id',newest.decision,newest.classification->>'outcome')=(o,w,e,t,'block',s) AND newest.occurred_at<=clock_timestamp() ORDER BY newest.occurred_at DESC,newest.sequence DESC,newest.event_id DESC LIMIT 1)
   AND credential.revoked_at IS NULL AND credential.expires_at>clock_timestamp()
   AND credential.id=(SELECT c.id FROM public.zasp_gateway_credentials c WHERE (c.organization_id,c.workspace_id,c.environment_id,c.device_id)=(o,w,e,event.device_id) AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp() ORDER BY c.issued_at DESC,c.id DESC LIMIT 1)
  ORDER BY event.occurred_at DESC,event.sequence DESC,event.event_id DESC LIMIT 1 FOR SHARE OF event,device,credential;
  IF NOT FOUND OR v<>0 AND event_row.sequence<>v THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test runtime trigger changed';END IF;
  version_value:=event_row.sequence;
  SELECT expires_at INTO expiry_value FROM public.zasp_gateway_credentials WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,event_row.credential_id) AND revoked_at IS NULL;
  IF expiry_value IS NULL OR expiry_value<=clock_timestamp() OR event_row.occurred_at<clock_timestamp()-interval '5 minutes' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test runtime trigger expired';END IF;
  digest_value:=digest(convert_to(jsonb_build_object('kind','runtime_decision','session_id',t,'device_id',event_row.device_id,'event_id',event_row.event_id,'sequence',version_value,'request_digest','sha256:'||encode(event_row.request_digest,'hex'))::text,'UTF8'),'sha256');
 ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='existing test trigger unsupported';
 END IF;
 RETURN jsonb_build_object('version',version_value,'digest',encode(digest_value,'hex'));
END
$trigger$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_trigger(text,text,text,text,text,text,bigint) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_trigger(text,text,text,text,text,text,bigint) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_admit(o text,w text,e text,d text,v bigint,k text,t text,tv bigint,r text,actor_value text,audit_value text,correlation_value text,automatic_value boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $admit$
DECLARE definition_row public.zasp_security_agent_definitions%ROWTYPE;prior public.zasp_security_agent_trigger_receipts%ROWTYPE;run_row public.zasp_security_agent_runs%ROWTYPE;
 binding_value jsonb;trigger_value jsonb;created_value boolean:=false;action_value text;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(d) AND public.zasp_valid_product_id(t) AND public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND v BETWEEN 1 AND 1000000 AND tv>=0,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='existing test admission rejected';END IF;
 -- The same organization guard used by budget claim precedes all work rows.
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 INSERT INTO public.zasp_security_agent_org_admissions(organization_id) VALUES(o) ON CONFLICT DO NOTHING;
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 SELECT * INTO definition_row FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) AND deleted_at IS NULL FOR SHARE;
 IF NOT FOUND OR definition_row.activation NOT IN('supervised','autonomous') OR definition_row.body->>'autonomy' IS DISTINCT FROM definition_row.activation OR definition_row.body->'enabled' IS DISTINCT FROM 'true'::jsonb OR definition_row.body->>'trigger_kind' IS DISTINCT FROM k THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test admission definition changed';END IF;
 action_value:=definition_row.body->'allowed_actions'->>0;
 binding_value:=public.zasp_production_security_agent_run_context_test_binding(o,w,e,d,v);
 IF action_value NOT IN('run_test','rerun_test') OR definition_row.body->'allowed_actions' IS DISTINCT FROM jsonb_build_array(action_value) OR definition_row.body->>'verification_kind' IS DISTINCT FROM 'test_run' OR NOT (definition_row.body->>'max_ai_cost_nano_credits' ~ '^[0-9]{1,13}$') OR (definition_row.body->>'max_ai_cost_nano_credits')::bigint NOT BETWEEN 1 AND 1000000000000 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test admission configuration changed';END IF;
 PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,action_value);
 trigger_value:=public.zasp_production_security_agent_existing_tests_trigger(o,w,e,k,t,definition_row.body->>'trigger_source',tv);
 SELECT * INTO prior FROM public.zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_version)=(o,w,e,d,t,(trigger_value->>'version')::bigint) FOR SHARE;
 IF FOUND THEN
  SELECT * INTO run_row FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,prior.run_id) FOR SHARE;
  IF NOT FOUND OR run_row.definition_id<>d OR run_row.definition_version<>v OR prior.trigger_kind<>k OR prior.trigger_digest IS DISTINCT FROM decode(trigger_value->>'digest','hex') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='existing test trigger intent conflict';END IF;
 ELSE
  IF (SELECT count(*) FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND state IN('queued','planning','waiting_approval','running','verifying','contained')) >= (definition_row.body->>'concurrency_limit')::integer THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test concurrency unavailable';END IF;
  -- Every prerequisite lock has completed before this final wall-clock check.
  IF public.zasp_production_security_agent_run_context_test_binding(o,w,e,d,v) IS DISTINCT FROM binding_value OR public.zasp_production_security_agent_existing_tests_trigger(o,w,e,k,t,definition_row.body->>'trigger_source',(trigger_value->>'version')::bigint) IS DISTINCT FROM trigger_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test admission authority changed';END IF;
  INSERT INTO public.zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) VALUES(o,w,e,d,t,k,(trigger_value->>'version')::bigint,decode(trigger_value->>'digest','hex'),r);
  INSERT INTO public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES(o,w,e,r,d,v,t,actor_value,'queued') RETURNING * INTO run_row;
  created_value:=true;
 END IF;
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body)
 VALUES(o,w,e,audit_value,correlation_value,run_row.run_id,actor_value,CASE WHEN created_value THEN 'run_queued' ELSE 'run_deduplicated' END,decode(trigger_value->>'digest','hex'),jsonb_build_object('run_id',run_row.run_id,'definition_id',d,'definition_version',v,'trigger_kind',k,'trigger_id',t,'trigger_version',trigger_value->'version','automatic',automatic_value,'action',action_value));
 PERFORM public.zasp_production_security_agent_run_context_test_binding(o,w,e,d,v);
 IF public.zasp_production_security_agent_existing_tests_trigger(o,w,e,k,t,definition_row.body->>'trigger_source',(trigger_value->>'version')::bigint) IS DISTINCT FROM trigger_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test admission expired';END IF;
 UPDATE public.zasp_security_agent_execution_state SET used_at=coalesce(used_at,clock_timestamp()) WHERE singleton;
 IF public.zasp_production_security_agent_run_context_test_binding(o,w,e,d,v) IS DISTINCT FROM binding_value OR public.zasp_production_security_agent_existing_tests_trigger(o,w,e,k,t,definition_row.body->>'trigger_source',(trigger_value->>'version')::bigint) IS DISTINCT FROM trigger_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test admission expired after final write';END IF;
 RETURN jsonb_build_object('id',run_row.run_id,'agent_id',d,'state',run_row.state,'evidence_ids',jsonb_build_array(t),'definition_version',v,'version',run_row.version,'created',created_value,'replayed',NOT created_value);
END
$admit$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_admit(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_admit(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_run(o text,w text,e text,d text,actor_value text,key_value text,v bigint,r text,k text,t text,audit_value text,correlation_value text,receipt_value text,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $run$
DECLARE result_value jsonb;intent_value jsonb;intent_digest bytea;prior public.zasp_security_agent_request_receipts%ROWTYPE;definition_body jsonb;kind_value text;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test admission release unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(actor_value) AND public.zasp_valid_product_id(receipt_value) AND length(key_value) BETWEEN 16 AND 128 AND key_value ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$' AND k IN('finding','attack_path','session'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='existing test run rejected';END IF;
 SELECT body INTO definition_body FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND deleted_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='existing test run scope denied';END IF;
 IF NOT definition_body ? 'existing_test' AND NOT definition_body->'allowed_actions' ?| ARRAY['run_test','rerun_test'] THEN
  RETURN public.zasp_security_agent_run_v24(o,w,e,d,actor_value,key_value,v,r,k,t,audit_value,correlation_value,receipt_value);
 END IF;
 kind_value:=CASE k WHEN 'session' THEN 'runtime_decision' ELSE k END;
 intent_value:=jsonb_build_object('definition_id',d,'expected_version',v,'trigger_kind',k,'trigger_id',t);
 intent_digest:=digest(convert_to(intent_value::text,'UTF8'),'sha256');
 -- Order matches shared admission before idempotency/work locks.
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,actor_value,'runSecurityAgent',key_value),0));
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor_value,'runSecurityAgent',key_value);
 IF FOUND THEN
  IF prior.resource_id<>d OR prior.expected_version<>v OR prior.intent_digest<>intent_digest OR prior.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='existing test run replay conflict';END IF;
  -- Replay validates current authority without writing another audit receipt.
  PERFORM 1 FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) AND deleted_at IS NULL AND activation IN('supervised','autonomous') FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test run definition changed';END IF;
  PERFORM public.zasp_production_security_agent_run_context_test_binding(o,w,e,d,v);
  PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,definition_body->'allowed_actions'->>0);
  IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_trigger_receipts tr WHERE (tr.organization_id,tr.workspace_id,tr.environment_id,tr.definition_id,tr.run_id,tr.trigger_id,tr.trigger_kind)=(o,w,e,d,prior.response->>'id',t,kind_value) AND public.zasp_production_security_agent_existing_tests_trigger(o,w,e,kind_value,t,definition_body->>'trigger_source',0)=jsonb_build_object('version',tr.trigger_version,'digest',encode(tr.trigger_digest,'hex'))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test run trigger changed';END IF;
  PERFORM public.zasp_production_security_agent_run_context_test_binding(o,w,e,d,v);
  RETURN prior.response||jsonb_build_object('replayed',true);
 END IF;
 result_value:=(public.zasp_production_security_agent_existing_tests_admit(o,w,e,d,v,kind_value,t,0,r,actor_value,audit_value,correlation_value,false)-'created')||jsonb_build_object('audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value);
 INSERT INTO public.zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id) VALUES(o,w,e,actor_value,'runSecurityAgent',key_value,d,v,intent_value,intent_digest,result_value,audit_value,correlation_value,receipt_value);
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test admission release unavailable';END IF;
 PERFORM public.zasp_production_security_agent_run_context_test_binding(o,w,e,d,v);
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_trigger_receipts tr WHERE (tr.organization_id,tr.workspace_id,tr.environment_id,tr.definition_id,tr.run_id,tr.trigger_id,tr.trigger_kind)=(o,w,e,d,result_value->>'id',t,kind_value) AND public.zasp_production_security_agent_existing_tests_trigger(o,w,e,kind_value,t,definition_body->>'trigger_source',tr.trigger_version)=jsonb_build_object('version',tr.trigger_version,'digest',encode(tr.trigger_digest,'hex'))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test admission changed after receipt';END IF;
 RETURN result_value;
END
$run$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text,text,text) TO zasp_security_agent_api;

-- Snapshot-only selection, never admission authority. Filter stable disabled,
-- stale or malformed bindings before LIMIT, without taking work-row locks
-- ahead of the organization guard. The shared core repeats all checks locked.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_candidate_binding(o text,w text,e text,b jsonb,a text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $candidate_binding$
 SELECT coalesce(
  a IN('supervised','autonomous') AND b->>'autonomy'=a AND b->'enabled'='true'::jsonb
  AND b->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) AND b->>'verification_kind'='test_run'
  AND jsonb_typeof(b->'existing_test')='object' AND b->'existing_test' ?& ARRAY['definition_id','definition_version'] AND (b->'existing_test')-ARRAY['definition_id','definition_version']='{}'::jsonb
  AND jsonb_typeof(b->'existing_test'->'definition_id')='string' AND jsonb_typeof(b->'existing_test'->'definition_version')='number'
  AND CASE WHEN b->>'max_ai_cost_nano_credits' ~ '^[0-9]{1,13}$' THEN (b->>'max_ai_cost_nano_credits')::bigint BETWEEN 1 AND 1000000000000 ELSE false END
  AND (SELECT count(*)=3 FROM public.zasp_security_agent_kill_switches s WHERE s.execution_enabled AND ((s.organization_id,s.workspace_id,s.environment_id,s.action_key)=('*','*','*','*') OR (s.organization_id,s.workspace_id,s.environment_id)=(o,w,e) AND s.action_key IN('*',b->'allowed_actions'->>0)))
  AND EXISTS(
   SELECT 1 FROM public.zasp_red_team_definitions test
   JOIN public.zasp_environments environment ON (environment.organization_id,environment.workspace_id,environment.id,environment.environment_class)=(test.organization_id,test.workspace_id,test.environment_id,test.safety->>'environment')
   JOIN public.zasp_inventory_entities target ON (target.organization_id,target.workspace_id,target.environment_id,target.id)=(test.organization_id,test.workspace_id,test.environment_id,test.target_id)
   JOIN public.zasp_attack_lab_credential_bindings credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.target_id,credential.credential_reference,credential.credential_class)=(test.organization_id,test.workspace_id,test.environment_id,test.target_id,target.winning_attributes->'red_team'->>'credential_reference',test.safety->>'credential_class')
   WHERE (test.organization_id,test.workspace_id,test.environment_id,test.definition_id)=(o,w,e,b->'existing_test'->>'definition_id') AND test.version::text=b->'existing_test'->>'definition_version' AND test.enabled
    AND environment.environment_class IN('development','test','staging') AND target.state='active' AND target.fresh_until>clock_timestamp()
    AND credential.state='active' AND credential.valid_until>clock_timestamp()
    AND public.zasp_red_team_safety_authorized(o,w,e,test.target_id,test.target_kind,test.safety)),false)
$candidate_binding$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_candidate_binding(text,text,text,jsonb,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_candidate_binding(text,text,text,jsonb,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_schedule(worker_value text,limit_value integer,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $schedule$
DECLARE candidate record;result_value jsonb;created_value integer:=0;run_value text;prior_count integer;admissions_value jsonb:='[]'::jsonb;admitted_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent principal unavailable';END IF;
 IF NOT COALESCE(length(worker_value) BETWEEN 1 AND 128 AND limit_value BETWEEN 1 AND 25,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='existing test schedule rejected';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test admission release unavailable';END IF;
 FOR candidate IN
  SELECT d.organization_id o,d.workspace_id w,d.environment_id e,d.definition_id d,d.version v,d.body->>'trigger_kind' k,x.id t,x.version tv
  FROM public.zasp_security_agent_definitions d CROSS JOIN LATERAL (
   SELECT f.id,f.version FROM public.zasp_risk_findings f WHERE (f.organization_id,f.workspace_id,f.environment_id)=(d.organization_id,d.workspace_id,d.environment_id) AND d.body->>'trigger_kind'='finding' AND f.status='open' AND f.rule=d.body->>'trigger_source'
   UNION ALL SELECT p.id,p.version FROM public.zasp_risk_attack_paths p WHERE (p.organization_id,p.workspace_id,p.environment_id)=(d.organization_id,d.workspace_id,d.environment_id) AND d.body->>'trigger_kind'='attack_path' AND p.state=d.body->>'trigger_source' AND p.state IN('observed','verified') AND public.zasp_risk_attack_path_valid(p)
   UNION ALL SELECT ev.classification->>'session_id',ev.sequence FROM public.zasp_runtime_gateway_events ev
    JOIN public.zasp_gateway_devices device ON (device.organization_id,device.workspace_id,device.environment_id,device.id,device.state)=(ev.organization_id,ev.workspace_id,ev.environment_id,ev.device_id,'active')
    JOIN public.zasp_gateway_credentials credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.device_id,credential.id)=(ev.organization_id,ev.workspace_id,ev.environment_id,ev.device_id,ev.credential_id)
    WHERE (ev.organization_id,ev.workspace_id,ev.environment_id)=(d.organization_id,d.workspace_id,d.environment_id) AND d.body->>'trigger_kind'='runtime_decision' AND ev.decision='block' AND ev.classification->>'outcome'=d.body->>'trigger_source' AND ev.occurred_at>=clock_timestamp()-interval '5 minutes' AND ev.occurred_at<=clock_timestamp() AND public.zasp_valid_product_id(ev.classification->>'session_id')
    AND credential.revoked_at IS NULL AND credential.expires_at>clock_timestamp()
    AND credential.id=(SELECT c.id FROM public.zasp_gateway_credentials c WHERE (c.organization_id,c.workspace_id,c.environment_id,c.device_id)=(d.organization_id,d.workspace_id,d.environment_id,ev.device_id) AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp() ORDER BY c.issued_at DESC,c.id DESC LIMIT 1)
    AND ev.event_id=(SELECT newest.event_id FROM public.zasp_runtime_gateway_events newest WHERE (newest.organization_id,newest.workspace_id,newest.environment_id,newest.classification->>'session_id',newest.decision,newest.classification->>'outcome')=(d.organization_id,d.workspace_id,d.environment_id,ev.classification->>'session_id','block',d.body->>'trigger_source') AND newest.occurred_at<=clock_timestamp() ORDER BY newest.occurred_at DESC,newest.sequence DESC,newest.event_id DESC LIMIT 1)
  ) x
  WHERE d.deleted_at IS NULL AND d.activation IN('supervised','autonomous') AND d.body->'enabled'='true'::jsonb AND d.body ? 'existing_test'
   AND public.zasp_production_security_agent_existing_tests_candidate_binding(d.organization_id,d.workspace_id,d.environment_id,d.body,d.activation)
   AND (SELECT count(*) FROM public.zasp_security_agent_runs active_run WHERE (active_run.organization_id,active_run.workspace_id,active_run.environment_id,active_run.definition_id)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id) AND active_run.state IN('queued','planning','waiting_approval','running','verifying','contained'))<(d.body->>'concurrency_limit')::integer
   AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_trigger_receipts tr WHERE (tr.organization_id,tr.workspace_id,tr.environment_id,tr.definition_id,tr.trigger_id,tr.trigger_version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,x.id,x.version))
  -- Scan work is capped independently of successful admissions. A refused
  -- candidate must not consume the entire caller's successful-work allowance.
  ORDER BY d.organization_id,d.workspace_id,d.environment_id,d.definition_id,x.id,x.version DESC LIMIT least(100,limit_value*4)
 LOOP
  EXIT WHEN created_value>=limit_value;
  BEGIN
   -- Skip contended organizations before entering the blocking shared core.
   CONTINUE WHEN NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||candidate.o,0));
   run_value:=public.zasp_discovery_canonical_id(candidate.o,candidate.w,candidate.e,'security_agent_run',concat_ws(chr(31),candidate.d,candidate.v,candidate.k,candidate.t,candidate.tv));
   result_value:=public.zasp_production_security_agent_existing_tests_admit(candidate.o,candidate.w,candidate.e,candidate.d,candidate.v,candidate.k,candidate.t,candidate.tv,run_value,worker_value,public.zasp_discovery_canonical_id(candidate.o,candidate.w,candidate.e,'security_agent_audit',run_value),public.zasp_discovery_canonical_id(candidate.o,candidate.w,candidate.e,'security_agent_correlation',run_value),true);
   IF (result_value->>'created')::boolean THEN
    created_value:=created_value+1;
    admissions_value:=admissions_value||jsonb_build_array(jsonb_build_object('o',candidate.o,'w',candidate.w,'e',candidate.e,'d',candidate.d,'v',candidate.v,'r',run_value));
   END IF;
  EXCEPTION WHEN SQLSTATE '40001' OR SQLSTATE '42501' OR SQLSTATE '55000' OR SQLSTATE '23505' THEN
   -- A stale candidate rolls back its whole subtransaction, including receipts.
   CONTINUE;
  END;
 END LOOP;
 IF created_value<limit_value THEN
  prior_count:=(public.zasp_security_agent_schedule_triggers_v33(worker_value,limit_value-created_value)->>'created')::integer;
  IF prior_count IS NULL OR prior_count<0 OR prior_count>limit_value-created_value THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test scheduler bound violated';END IF;
  created_value:=created_value+prior_count;
 END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test admission release unavailable';END IF;
 -- Later candidates and the delegated legacy scheduler can block after an
 -- earlier test admission. Revalidate every new test run at the commit edge.
 FOR admitted_value IN SELECT value FROM jsonb_array_elements(admissions_value) LOOP
  PERFORM public.zasp_production_security_agent_run_context_test_binding(admitted_value->>'o',admitted_value->>'w',admitted_value->>'e',admitted_value->>'d',(admitted_value->>'v')::bigint);
  IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_trigger_receipts tr JOIN public.zasp_security_agent_definitions d ON (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=(tr.organization_id,tr.workspace_id,tr.environment_id,tr.definition_id)
   WHERE (tr.organization_id,tr.workspace_id,tr.environment_id,tr.definition_id,tr.run_id)=(admitted_value->>'o',admitted_value->>'w',admitted_value->>'e',admitted_value->>'d',admitted_value->>'r')
    AND public.zasp_production_security_agent_existing_tests_trigger(tr.organization_id,tr.workspace_id,tr.environment_id,tr.trigger_kind,tr.trigger_id,d.body->>'trigger_source',tr.trigger_version)=jsonb_build_object('version',tr.trigger_version,'digest',encode(tr.trigger_digest,'hex'))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test scheduled admission changed before commit';END IF;
 END LOOP;
 RETURN jsonb_build_object('created',created_value);
END
$schedule$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_schedule(text,integer,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_schedule(text,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_schedule(text,integer,text,text) TO zasp_security_agent_worker;
