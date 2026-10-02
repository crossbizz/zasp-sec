-- Separate domain evidence. The shared public budget remains the quota owner;
-- neither new table has a legacy lease or an Activity-attempt identity.
CREATE TABLE zasp_temporal68.provider_reservations(LIKE public.zasp_security_agent_provider_reservations INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE zasp_temporal68.provider_reservations DROP COLUMN worker_id,DROP COLUMN lease_token_digest,
 ADD released_at timestamptz,
 ADD CHECK(released_at IS NULL OR released_at>=reserved_at AND settled_at IS NULL AND output_digest IS NULL AND prompt_tokens IS NULL AND completion_tokens IS NULL AND total_tokens IS NULL AND cost_nano_credits IS NULL),
 ADD PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,attempt),
 ADD UNIQUE(organization_id,workspace_id,environment_id,run_id,reservation_id),
 ADD FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id),
 ADD CHECK(attempt=1);
CREATE TABLE zasp_temporal68.admissions(LIKE zasp_sa_multistep_prior.admissions INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE zasp_temporal68.admissions DROP COLUMN lease_token_digest,DROP COLUMN lease_expires_at,
 ADD PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 ADD FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_sa_multistep_runs(organization_id,workspace_id,environment_id,run_id),
 ADD FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,attempt) REFERENCES zasp_temporal68.provider_reservations(organization_id,workspace_id,environment_id,run_id,attempt);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal68.admissions FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
ALTER TABLE zasp_temporal68.planning_jobs
 ADD request_body text,ADD request_digest text,ADD lookup_request jsonb,ADD pricing_bound jsonb,ADD input_version text,
 ADD raw_result text,ADD result_value jsonb,ADD provider_digest text,ADD output_body text,ADD output_digest text,ADD output_version text,ADD receipt jsonb;
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['provider_reservations','admissions'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal68.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal68.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal68.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal68.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
 END LOOP;
END $tables$;

-- These complete predecessor bodies were checked by67 before the cutover.
-- Keep pricing payload/account/version validation and public plan evidence,
-- replacing the principal and evidence association at the explicit68 boundary.
DO $extract$ DECLARE d text;BEGIN
 d:=pg_get_functiondef('zasp_sa_multistep_prior.pricing_lookup(text,text,jsonb)'::regprocedure);
 d:=replace(d,'FUNCTION zasp_sa_multistep_prior.pricing_lookup(', 'FUNCTION zasp_temporal68.pricing_lookup(');
 d:=replace(d,$old$public.zasp_security_agent_principal_ready('zasp_security_agent_worker')$old$,$new$zasp_temporal68.principal_ready('zasp_temporal_executor')$new$);
 EXECUTE d;
 d:=pg_get_functiondef('zasp_sa_multistep_prior.admit(text,text,jsonb)'::regprocedure);
 d:=replace(d,'FUNCTION zasp_sa_multistep_prior.admit(', 'FUNCTION zasp_temporal68.admit(');
 d:=replace(d,'zasp_sa_multistep_prior.admissions','zasp_temporal68.admissions');
 d:=replace(d,'public.zasp_security_agent_provider_reservations','zasp_temporal68.provider_reservations');
 d:=replace(d,$old$public.zasp_security_agent_principal_ready('zasp_security_agent_worker')$old$,$new$zasp_temporal68.principal_ready('zasp_temporal_executor')$new$);
 d:=replace(d,$old$'worker_id','lease_token',$old$,'');
 d:=replace(d,$old$length(request_value->>'lease_token')<16 OR $old$,'');
 d:=replace(d,$old$prior.request IS DISTINCT FROM request_value-'lease_token' OR prior.lease_token_digest IS DISTINCT FROM digest(convert_to(request_value->>'lease_token','UTF8'),'sha256')
   OR prior.lease_expires_at<=clock_timestamp()$old$,$new$prior.request IS DISTINCT FROM request_value$new$);
 d:=replace(d,$old$ OR rr.lease_owner IS DISTINCT FROM request_value->>'worker_id'
   OR rr.lease_token IS DISTINCT FROM request_value->>'lease_token' OR rr.lease_expires_at IS NULL OR rr.lease_expires_at<=clock_timestamp()$old$,$new$ OR NOT zasp_temporal66.is_temporal(o,w,e,r) OR rr.lease_token IS NOT NULL OR rr.lease_owner IS NOT NULL OR rr.lease_expires_at IS NOT NULL$new$);
 d:=replace(d,$old$(usage.input_digest,usage.output_digest,usage.model,usage.worker_id,usage.lease_token_digest)$old$,$new$(usage.input_digest,usage.output_digest,usage.model)$new$);
 d:=replace(d,$old$(input_hash,output_hash,request_value->>'model',request_value->>'worker_id',digest(convert_to(request_value->>'lease_token','UTF8'),'sha256'))$old$,$new$(input_hash,output_hash,request_value->>'model')$new$);
 d:=replace(d,$old$request_value->>'worker_id'$old$,'session_user');
 d:=replace(d,$old$attempt,request,lease_token_digest,lease_expires_at,response)$old$,$new$attempt,request,response)$new$);
 d:=replace(d,$old$rr.attempt,request_value-'lease_token',usage.lease_token_digest,rr.lease_expires_at,response_value)$old$,$new$rr.attempt,request_value,response_value)$new$);
 d:=replace(d,$old$
  OR (CASE WHEN replay THEN prior.lease_expires_at ELSE rr.lease_expires_at END)<=clock_timestamp()$old$,'');
 d:=replace(d,$old$(organization_id,workspace_id,environment_id,run_id,state,lease_owner,lease_token,attempt,version)=(o,w,e,r,'planning',session_user,request_value->>'lease_token',rr.attempt,rr.version) AND lease_expires_at>clock_timestamp()$old$,$new$(organization_id,workspace_id,environment_id,run_id,state,attempt,version)=(o,w,e,r,'planning',rr.attempt,rr.version) AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL$new$);
 -- No lease-bearing request or private evidence may survive extraction.
 IF strpos(d,'lease_token_digest')>0 OR strpos(d,'prior.lease_expires_at')>0 OR strpos(d,$token$->>'lease_token'$token$)>0 OR strpos(d,$worker$'worker_id'$worker$)>0 THEN RAISE EXCEPTION 'domain admission extraction incomplete';END IF;
 EXECUTE d;
END $extract$;

CREATE FUNCTION zasp_temporal68.planning_terminal(o text,w text,e text,r text,reason_value text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $terminal$
DECLARE body_value jsonb;audit_value text;dispatch_state text;
BEGIN
 SELECT state INTO STRICT dispatch_state FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 UPDATE public.zasp_security_agent_runs SET state='needs_human',last_error_code=reason_value,version=CASE WHEN state='needs_human' THEN version ELSE version+1 END,completed_at=COALESCE(completed_at,clock_timestamp()),updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 UPDATE zasp_temporal68.planning_jobs SET state='needs_human' WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT jsonb_build_object('job',to_jsonb(j),'reservation',(SELECT to_jsonb(p) FROM zasp_temporal68.provider_reservations p WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id,p.attempt)=(o,w,e,r,1)),'reason',reason_value,'dispatch_state',dispatch_state) INTO body_value FROM zasp_temporal68.planning_jobs j WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 audit_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_planning_terminal',r);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,audit_value,r,session_user,'temporal_planning_terminal',digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
END $terminal$;

CREATE FUNCTION zasp_temporal68.planning_terminal_valid(o text,w text,e text,r text) RETURNS boolean LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $valid$
DECLARE a public.zasp_security_agent_audit%ROWTYPE;j zasp_temporal68.planning_jobs%ROWTYPE;p zasp_temporal68.provider_reservations%ROWTYPE;
BEGIN
 SELECT * INTO j FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO p FROM zasp_temporal68.provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1);
 SELECT * INTO a FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'temporal_planning_terminal');
 IF EXISTS(SELECT 1 FROM zasp_temporal68.planning_late_usage WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN
  IF NOT zasp_temporal68.late_usage_valid(o,w,e,r) THEN RETURN false;END IF;
  -- The first terminal evidence remains authoritative for what was known at
  -- that instant. The separate immutable ledger proves the later charge.
  p:=jsonb_populate_record(NULL::zasp_temporal68.provider_reservations,a.body->'reservation');
 END IF;
 RETURN COALESCE(j.state='needs_human' AND a.audit_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_planning_terminal',r) AND a.correlation_id=a.audit_id AND a.event_digest=digest(convert_to(a.body::text,'UTF8'),'sha256')
  AND a.body=jsonb_build_object('job',to_jsonb(j),'reservation',CASE WHEN p.run_id IS NULL THEN 'null'::jsonb ELSE to_jsonb(p) END,'reason',(SELECT last_error_code FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)),'dispatch_state',a.body->>'dispatch_state')
  AND j.input_digest='sha256:'||encode(digest(convert_to(j.input_body,'UTF8'),'sha256'),'hex') AND j.input_body=j.context_value::text
  AND CASE WHEN a.body->>'reason'='planner_not_sent' THEN j.raw_result IS NULL AND j.result_value IS NULL AND j.provider_digest IS NULL AND j.output_body IS NULL AND j.output_digest IS NULL
   AND (a.body->>'dispatch_state'='loaded' AND j.lookup_request IS NULL AND j.pricing_bound IS NULL AND j.request_body IS NULL AND j.request_digest IS NULL AND j.input_version IS NULL AND p.run_id IS NULL
    OR a.body->>'dispatch_state'='prepared' AND j.lookup_request IS NOT NULL AND j.pricing_bound IS NOT NULL AND j.input_version IS NOT NULL AND p.released_at IS NOT NULL AND p.settled_at IS NULL AND p.output_digest IS NULL AND p.total_tokens IS NULL AND p.cost_nano_credits IS NULL)
   ELSE a.body->>'dispatch_state' IN('started','completed','settled','artifacts') AND p.released_at IS NULL
    AND (j.raw_result IS NULL AND p.settled_at IS NULL AND p.total_tokens IS NULL AND p.cost_nano_credits IS NULL OR j.raw_result IS NOT NULL AND j.provider_digest='sha256:'||encode(digest(convert_to(j.raw_result,'UTF8'),'sha256'),'hex') AND j.result_value=zasp_sa_multistep_prior.planning_result(j.raw_result,j.lookup_request->>'model',j.context_value)
     AND (j.result_value->'usage'='null'::jsonb AND p.settled_at IS NULL OR j.result_value->'usage'<>'null'::jsonb AND p.settled_at IS NOT NULL AND (p.total_tokens,p.cost_nano_credits)=((j.result_value->'usage'->>'total_tokens')::bigint,(j.result_value->'usage'->>'cost_nano_credits')::bigint))) END,false);
END $valid$;

CREATE FUNCTION zasp_temporal68.recover_plan(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $recover$
DECLARE o text;w text;e text;r text;k text;j zasp_temporal68.planning_jobs%ROWTYPE;p zasp_temporal68.provider_reservations%ROWTYPE;b public.zasp_security_agent_run_budgets%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;cv jsonb;body_value text;reason_value text:='execution_authority_lost';
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='executor recovery requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')) OR NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor planning recovery unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','operation','payload']) OR q->>'operation' IS DISTINCT FROM 'reconcile' OR octet_length(q::text)>131072 OR NOT(zasp_sa_multistep_prior.closed(q->'payload',ARRAY[]::text[]) OR zasp_sa_multistep_prior.closed(q->'payload',ARRAY['raw']) AND jsonb_typeof(q->'payload'->'raw')='string' AND octet_length(q->'payload'->>'raw') BETWEEN 1 AND 65536) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor planning recovery request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor recovery scope rejected';END IF;
 END LOOP;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 SELECT * INTO b FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO j FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO p FROM zasp_temporal68.provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1) FOR UPDATE;
 IF NOT zasp_temporal66.is_temporal(o,w,e,r) OR j.state NOT IN('loaded','prepared','started','completed','settled','artifacts','needs_human') OR j.run_id IS NULL OR (j.lookup_request IS NULL) IS DISTINCT FROM (p.run_id IS NULL) OR q->'definition_version' IS DISTINCT FROM to_jsonb(j.definition_version)
  OR rr.lease_owner IS NOT NULL OR rr.lease_token IS NOT NULL OR rr.lease_expires_at IS NOT NULL OR rr.plan_hash IS NOT NULL OR (b.started_at,b.deadline_at) IS DISTINCT FROM(j.budget_started_at,j.budget_deadline_at)
  OR (b.definition_id,b.definition_version,b.max_steps,b.max_tokens,b.max_cost_nano_credits,b.concurrency_limit) IS DISTINCT FROM(rr.definition_id,rr.definition_version,2,(j.context_value->'definition'->>'ai_token_budget')::bigint,(j.context_value->'definition'->>'max_ai_cost_nano_credits')::bigint,(j.context_value->'definition'->>'concurrency_limit')::integer)
  OR b.deadline_at IS DISTINCT FROM b.started_at+make_interval(secs=>(j.context_value->'definition'->>'max_duration_seconds')::integer)
  OR j.lookup_request IS NOT NULL AND (p.input_digest,p.reservation_id,p.model) IS DISTINCT FROM(decode(substr(j.input_digest,8),'hex'),j.reservation_id,j.lookup_request->>'model') OR j.input_digest IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(j.input_body,'UTF8'),'sha256'),'hex') OR j.input_body IS DISTINCT FROM j.context_value::text THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor recovery intent changed';END IF;
 IF j.state='needs_human' THEN
  IF NOT zasp_temporal68.planning_terminal_valid(o,w,e,r) OR q->'payload'<>'{}'::jsonb AND q->'payload'->>'raw' IS DISTINCT FROM j.raw_result THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor terminal replay conflict';END IF;
  RETURN to_jsonb(j);
 END IF;
 IF j.state IN('loaded','prepared') THEN
  IF q->'payload'<>'{}'::jsonb OR j.raw_result IS NOT NULL OR p.settled_at IS NOT NULL OR p.released_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='unstarted recovery evidence rejected';END IF;
  IF j.state='prepared' THEN UPDATE zasp_temporal68.provider_reservations SET released_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1);END IF;
  PERFORM zasp_temporal68.planning_terminal(o,w,e,r,'planner_not_sent');
  IF NOT zasp_temporal68.planning_terminal_valid(o,w,e,r) OR NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='unstarted terminal evidence rejected';END IF;
  SELECT * INTO j FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  RETURN to_jsonb(j);
 END IF;
 IF q->'payload'<>'{}'::jsonb THEN
  IF j.state='started' THEN
   cv:=zasp_sa_multistep_prior.planning_result(q->'payload'->>'raw',j.lookup_request->>'model',j.context_value);body_value:=jsonb_build_object('raw',q->'payload'->>'raw','candidate',cv->'candidate')::text;
   UPDATE zasp_temporal68.planning_jobs SET state='completed',raw_result=q->'payload'->>'raw',result_value=cv,provider_digest='sha256:'||encode(digest(convert_to(q->'payload'->>'raw','UTF8'),'sha256'),'hex'),output_body=body_value,output_digest='sha256:'||encode(digest(convert_to(body_value,'UTF8'),'sha256'),'hex') WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO j;
  ELSIF j.raw_result IS DISTINCT FROM q->'payload'->>'raw' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor retained provider response changed';END IF;
 END IF;
 IF b.deadline_at<=clock_timestamp() THEN reason_value:='budget_deadline_exceeded';END IF;
 cv:=j.result_value->'usage';
 IF cv IS NULL OR cv='null'::jsonb THEN reason_value:='budget_usage_unknown';
 ELSE
  IF j.provider_digest IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(j.raw_result,'UTF8'),'sha256'),'hex') OR j.result_value IS DISTINCT FROM zasp_sa_multistep_prior.planning_result(j.raw_result,j.lookup_request->>'model',j.context_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor recovery provider evidence changed';END IF;
  IF p.settled_at IS NULL THEN UPDATE zasp_temporal68.provider_reservations SET settled_at=clock_timestamp(),output_digest=decode(substr(j.provider_digest,8),'hex'),prompt_tokens=(cv->>'prompt_tokens')::bigint,completion_tokens=(cv->>'completion_tokens')::bigint,total_tokens=(cv->>'total_tokens')::bigint,cost_nano_credits=(cv->>'cost_nano_credits')::bigint WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1);END IF;
  IF (cv->>'total_tokens')::bigint>least(p.maximum_tokens,b.max_tokens) THEN reason_value:='budget_tokens_exceeded';ELSIF (cv->>'cost_nano_credits')::bigint>least(p.maximum_cost_nano_credits,b.max_cost_nano_credits) THEN reason_value:='budget_cost_exceeded';END IF;
 END IF;
 IF reason_value LIKE 'budget_%' THEN UPDATE public.zasp_security_agent_run_budgets SET stop_reason=reason_value WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);END IF;
 PERFORM zasp_temporal68.planning_terminal(o,w,e,r,reason_value);
 IF NOT zasp_temporal68.planning_terminal_valid(o,w,e,r) OR NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor planning recovery evidence changed';END IF;
 SELECT * INTO j FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 RETURN to_jsonb(j);
END $recover$;

CREATE FUNCTION zasp_temporal68.plan(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $planning$
DECLARE o text;w text;e text;r text;op text;payload jsonb;job zasp_temporal68.planning_jobs%ROWTYPE;
 rr public.zasp_security_agent_runs%ROWTYPE;b public.zasp_security_agent_run_budgets%ROWTYPE;reservation zasp_temporal68.provider_reservations%ROWTYPE;
 selection jsonb;body_value text;bound_value jsonb;cv jsonb;reason text;receipt_value jsonb;send_value boolean:=false;
BEGIN
 IF q->>'operation'='reconcile' THEN RETURN zasp_temporal68.recover_plan(q);END IF;
 IF q->>'operation'='late_usage' THEN RETURN zasp_temporal68.record_late_usage(q);END IF;
 IF q->>'operation'='load' THEN RETURN zasp_temporal68.load_plan(q);END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='executor planning requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') OR NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor planning unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','operation','payload']) OR octet_length(q::text)>524288
  OR q->>'operation' NOT IN('prepare','start','result','settle','artifacts','admit') OR jsonb_typeof(q->'payload')<>'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor planning request rejected';END IF;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';op:=q->>'operation';payload:=q->'payload';
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 SELECT * INTO b FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO job FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND OR NOT zasp_temporal66.is_temporal(o,w,e,r) OR q->'definition_version' IS DISTINCT FROM to_jsonb(job.definition_version)
  OR rr.lease_owner IS NOT NULL OR rr.lease_token IS NOT NULL OR rr.lease_expires_at IS NOT NULL
  OR NOT(rr.state='planning' AND rr.version=job.run_version OR op='admit' AND job.state='admitted' AND rr.state='waiting_approval' AND rr.version=job.run_version+1)
  OR b.run_id IS NULL OR b.stop_reason IS NOT NULL OR b.deadline_at<=clock_timestamp() OR (b.started_at,b.deadline_at) IS DISTINCT FROM (job.budget_started_at,job.budget_deadline_at)
  OR (b.definition_id,b.definition_version,b.max_steps,b.max_tokens,b.max_cost_nano_credits,b.concurrency_limit) IS DISTINCT FROM (rr.definition_id,rr.definition_version,2,(job.context_value->'definition'->>'ai_token_budget')::bigint,(job.context_value->'definition'->>'max_ai_cost_nano_credits')::bigint,(job.context_value->'definition'->>'concurrency_limit')::integer)
  OR zasp_sa_multistep_prior.context(o,w,e,r) IS DISTINCT FROM job.context_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor planning authority changed';END IF;
 SELECT * INTO reservation FROM zasp_temporal68.provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1) FOR UPDATE;
 IF op IN('start','settle','admit') AND payload<>'{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor planning unexpected payload';END IF;
 IF op='prepare' THEN
  IF NOT zasp_sa_multistep_prior.closed(payload,ARRAY['pricing','input_version']) OR jsonb_typeof(payload->'input_version')<>'string' OR length(payload->>'input_version') NOT BETWEEN 1 AND 1024 OR payload->>'input_version'!~'^[!-~]+$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor input artifact rejected';END IF;
  selection:=payload->'pricing';body_value:=zasp_sa_multistep_prior.planning_body(job.context_value,selection);
  selection:=selection||jsonb_build_object('body',body_value,'body_digest','sha256:'||encode(digest(convert_to(body_value,'UTF8'),'sha256'),'hex'));
  IF (selection->>'organization_id',selection->>'workspace_id',selection->>'environment_id') IS DISTINCT FROM (o,w,e) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor pricing scope rejected';END IF;
  bound_value:=zasp_temporal68.pricing_lookup('-- release61 checksum','-- release61 fingerprint',selection);
  IF job.state='loaded' THEN
   IF reservation.run_id IS NOT NULL OR (bound_value->>'maximum_tokens')::bigint>b.max_tokens OR (bound_value->>'maximum_cost_nano_credits')::bigint>b.max_cost_nano_credits THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor pricing exceeds budget';END IF;
   INSERT INTO zasp_temporal68.provider_reservations(organization_id,workspace_id,environment_id,run_id,attempt,reservation_id,input_digest,model,cost_policy_version,cost_unit,maximum_tokens,maximum_cost_nano_credits)
    VALUES(o,w,e,r,1,job.reservation_id,decode(substring(job.input_digest FROM 8),'hex'),selection->>'model',bound_value->>'cost_policy_version','openrouter_credit',(bound_value->>'maximum_tokens')::bigint,(bound_value->>'maximum_cost_nano_credits')::bigint);
   UPDATE zasp_temporal68.planning_jobs SET state='prepared',request_body=body_value,request_digest=selection->>'body_digest',lookup_request=selection,pricing_bound=bound_value,input_version=payload->>'input_version' WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO job;
  ELSIF job.lookup_request IS DISTINCT FROM selection OR job.input_version IS DISTINCT FROM payload->>'input_version' OR job.pricing_bound IS DISTINCT FROM bound_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor intent conflict';END IF;
 END IF;
 IF job.lookup_request IS NOT NULL THEN
  IF job.request_body IS DISTINCT FROM zasp_sa_multistep_prior.planning_body(job.context_value,job.lookup_request) OR job.request_digest IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(job.request_body,'UTF8'),'sha256'),'hex') OR job.pricing_bound IS DISTINCT FROM zasp_temporal68.pricing_lookup('-- release61 checksum','-- release61 fingerprint',job.lookup_request) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor pricing drift';END IF;
  SELECT * INTO reservation FROM zasp_temporal68.provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1) FOR UPDATE;
  IF (reservation.reservation_id,reservation.input_digest,reservation.model,reservation.cost_policy_version,reservation.maximum_tokens,reservation.maximum_cost_nano_credits) IS DISTINCT FROM (job.reservation_id,decode(substring(job.input_digest FROM 8),'hex'),job.lookup_request->>'model',job.pricing_bound->>'cost_policy_version',(job.pricing_bound->>'maximum_tokens')::bigint,(job.pricing_bound->>'maximum_cost_nano_credits')::bigint) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor reservation drift';END IF;
  IF reservation.settled_at IS NOT NULL AND (reservation.output_digest,reservation.prompt_tokens,reservation.completion_tokens,reservation.total_tokens,reservation.cost_nano_credits) IS DISTINCT FROM (decode(substring(job.provider_digest FROM 8),'hex'),(job.result_value->'usage'->>'prompt_tokens')::bigint,(job.result_value->'usage'->>'completion_tokens')::bigint,(job.result_value->'usage'->>'total_tokens')::bigint,(job.result_value->'usage'->>'cost_nano_credits')::bigint) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor settlement differs from provider evidence';END IF;
 END IF;
 IF op='start' THEN
  IF job.state='prepared' THEN UPDATE zasp_temporal68.planning_jobs SET state='started' WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO job;send_value:=true;
  ELSIF job.state<>'started' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor send unavailable';END IF;
 ELSIF op='result' THEN
  IF NOT zasp_sa_multistep_prior.closed(payload,ARRAY['raw']) OR jsonb_typeof(payload->'raw')<>'string' OR octet_length(payload->>'raw') NOT BETWEEN 1 AND 65536 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor result rejected';END IF;
  IF job.state='started' THEN
   cv:=zasp_sa_multistep_prior.planning_result(payload->>'raw',job.lookup_request->>'model',job.context_value);body_value:=jsonb_build_object('raw',payload->>'raw','candidate',cv->'candidate')::text;
   UPDATE zasp_temporal68.planning_jobs SET state='completed',raw_result=payload->>'raw',result_value=cv,provider_digest='sha256:'||encode(digest(convert_to(payload->>'raw','UTF8'),'sha256'),'hex'),output_body=body_value,output_digest='sha256:'||encode(digest(convert_to(body_value,'UTF8'),'sha256'),'hex') WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO job;
  ELSIF job.raw_result IS DISTINCT FROM payload->>'raw' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor result immutable';END IF;
 ELSIF op='settle' THEN
  IF job.state NOT IN('completed','settled','artifacts') OR job.result_value IS DISTINCT FROM zasp_sa_multistep_prior.planning_result(job.raw_result,job.lookup_request->>'model',job.context_value) OR job.provider_digest IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(job.raw_result,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor settlement unavailable';END IF;
  IF job.state='completed' THEN
   cv:=job.result_value->'usage';
   IF cv='null'::jsonb THEN reason:='budget_usage_unknown';ELSE
    UPDATE zasp_temporal68.provider_reservations SET settled_at=clock_timestamp(),output_digest=decode(substring(job.provider_digest FROM 8),'hex'),prompt_tokens=(cv->>'prompt_tokens')::bigint,completion_tokens=(cv->>'completion_tokens')::bigint,total_tokens=(cv->>'total_tokens')::bigint,cost_nano_credits=(cv->>'cost_nano_credits')::bigint WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1);
    IF (cv->>'total_tokens')::bigint>least(reservation.maximum_tokens,b.max_tokens) THEN reason:='budget_tokens_exceeded';ELSIF (cv->>'cost_nano_credits')::bigint>least(reservation.maximum_cost_nano_credits,b.max_cost_nano_credits) THEN reason:='budget_cost_exceeded';END IF;
   END IF;
   UPDATE zasp_temporal68.planning_jobs SET state='settled' WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO job;
   IF reason IS NOT NULL OR job.result_value->'candidate'='null'::jsonb THEN
    IF reason IS NOT NULL THEN UPDATE public.zasp_security_agent_run_budgets SET stop_reason=reason WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);END IF;
    PERFORM zasp_temporal68.planning_terminal(o,w,e,r,coalesce(reason,'planner_rejected'));
    SELECT * INTO job FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
   END IF;
  END IF;
 ELSIF op='artifacts' THEN
  IF job.state NOT IN('settled','artifacts') OR NOT zasp_sa_multistep_prior.closed(payload,ARRAY['input_version','output_version','output_digest']) OR payload->>'input_version' IS DISTINCT FROM job.input_version OR payload->>'output_digest' IS DISTINCT FROM job.output_digest OR jsonb_typeof(payload->'output_version')<>'string' OR length(payload->>'output_version') NOT BETWEEN 1 AND 1024 OR payload->>'output_version'!~'^[!-~]+$' OR job.output_version IS NOT NULL AND job.output_version IS DISTINCT FROM payload->>'output_version' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor artifact conflict';END IF;
  UPDATE zasp_temporal68.planning_jobs SET state='artifacts',output_version=payload->>'output_version' WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO job;
 ELSIF op='admit' THEN
  IF job.state NOT IN('artifacts','admitted') OR job.output_digest IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(job.output_body,'UTF8'),'sha256'),'hex') OR job.output_body IS DISTINCT FROM jsonb_build_object('raw',job.raw_result,'candidate',job.result_value->'candidate')::text THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor immutable result unavailable';END IF;
  receipt_value:=zasp_temporal68.admit('-- release61 checksum','-- release61 fingerprint',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'definition_id',rr.definition_id,'definition_version',rr.definition_version,'trigger_id',rr.trigger_id,'attempt',1,'run_version',job.run_version,'input_digest',job.input_digest,'output_digest',job.provider_digest,'model',job.lookup_request->>'model','policy_version',job.lookup_request->>'request_policy_version','candidate',job.result_value->'candidate'));
  UPDATE zasp_temporal68.planning_jobs SET state='admitted',receipt=receipt_value WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO job;
 END IF;
 IF b.deadline_at<=clock_timestamp() OR zasp_sa_multistep_prior.context(o,w,e,r) IS DISTINCT FROM job.context_value OR NOT zasp_temporal68.current_ready() OR job.lookup_request IS NOT NULL AND job.pricing_bound IS DISTINCT FROM zasp_temporal68.pricing_lookup('-- release61 checksum','-- release61 fingerprint',job.lookup_request) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor planning authority expired after wait';END IF;
 IF op='admit' THEN RETURN job.receipt;END IF;
 IF op='start' THEN RETURN to_jsonb(job)||jsonb_build_object('send_permit',send_value);END IF;
 RETURN to_jsonb(job);
END $planning$;
