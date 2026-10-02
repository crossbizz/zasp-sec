-- A later authentic response must not rewrite what the unknown terminal
-- record said. One append-only association authorizes one reservation charge.
CREATE TABLE zasp_temporal68.planning_late_usage(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 response_id text NOT NULL CHECK(length(response_id) BETWEEN 1 AND 256 AND response_id~'^[!-~]+$'),
 credential_digest text NOT NULL CHECK(credential_digest~'^sha256:[a-f0-9]{64}$'),
 body jsonb NOT NULL CHECK(jsonb_typeof(body)='object' AND octet_length(body::text)<=262144),
 body_digest bytea NOT NULL CHECK(octet_length(body_digest)=32),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),UNIQUE(credential_digest,response_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal68.planning_jobs(organization_id,workspace_id,environment_id,run_id));
ALTER TABLE zasp_temporal68.planning_late_usage OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal68.planning_late_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal68.planning_late_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal68.planning_late_usage USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal68.planning_late_usage FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

CREATE FUNCTION zasp_temporal68.late_usage_valid(o text,w text,e text,r text) RETURNS boolean LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $valid$
DECLARE l zasp_temporal68.planning_late_usage%ROWTYPE;j zasp_temporal68.planning_jobs%ROWTYPE;p zasp_temporal68.provider_reservations%ROWTYPE;
 a public.zasp_security_agent_audit%ROWTYPE;later public.zasp_security_agent_audit%ROWTYPE;association jsonb;cv jsonb;original jsonb;raw text;
BEGIN
 SELECT * INTO l FROM zasp_temporal68.planning_late_usage WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO j FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO p FROM zasp_temporal68.provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1);
 SELECT * INTO a FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'temporal_planning_terminal');
 SELECT * INTO later FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'temporal_planning_late_usage');
 raw:=l.body->>'raw';association:=l.body->'association';original:=a.body->'reservation';
 IF l.run_id IS NULL OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 65536 OR NOT zasp_sa_multistep_prior.closed(l.body,ARRAY['raw','association','terminal_digest','reservation','usage'])
  OR NOT zasp_sa_multistep_prior.closed(association,ARRAY['request_digest','credential_digest','reservation_id','response_id','response_digest']) THEN RETURN false;END IF;
 cv:=zasp_sa_multistep_prior.planning_result(raw,j.lookup_request->>'model',j.context_value);
 RETURN COALESCE(j.state='needs_human' AND a.body->'job'=to_jsonb(j) AND a.event_digest=digest(convert_to(a.body::text,'UTF8'),'sha256')
  AND l.body_digest=digest(convert_to(l.body::text,'UTF8'),'sha256') AND l.body->>'terminal_digest'=encode(a.event_digest,'hex')
  AND later.audit_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_planning_late_usage',r) AND later.correlation_id=later.audit_id AND later.body=l.body AND later.event_digest=l.body_digest
  AND association->>'request_digest'=j.request_digest AND j.request_digest='sha256:'||encode(digest(convert_to(j.request_body,'UTF8'),'sha256'),'hex')
  AND association->>'credential_digest'=j.lookup_request->>'credential_digest' AND association->>'credential_digest'=l.credential_digest
  AND association->>'reservation_id'=j.reservation_id AND p.reservation_id=j.reservation_id
  AND association->>'response_id'=l.response_id AND (raw::jsonb)->>'id'=l.response_id
  AND association->>'response_digest'='sha256:'||encode(digest(convert_to(raw,'UTF8'),'sha256'),'hex')
  AND original->'settled_at'='null'::jsonb AND original->'total_tokens'='null'::jsonb AND original->'cost_nano_credits'='null'::jsonb
  AND to_jsonb(p)-ARRAY['settled_at','output_digest','prompt_tokens','completion_tokens','total_tokens','cost_nano_credits']=original-ARRAY['settled_at','output_digest','prompt_tokens','completion_tokens','total_tokens','cost_nano_credits']
  AND l.body->'reservation'=to_jsonb(p) AND cv->'usage'<>'null'::jsonb AND l.body->'usage'=cv->'usage' AND p.settled_at IS NOT NULL AND p.released_at IS NULL
  AND (p.prompt_tokens,p.completion_tokens,p.total_tokens,p.cost_nano_credits)=((cv->'usage'->>'prompt_tokens')::bigint,(cv->'usage'->>'completion_tokens')::bigint,(cv->'usage'->>'total_tokens')::bigint,(cv->'usage'->>'cost_nano_credits')::bigint)
  AND p.output_digest=digest(convert_to(raw,'UTF8'),'sha256')
  AND (j.raw_result IS NULL OR (j.raw_result::jsonb)-'usage'=(raw::jsonb)-'usage' AND j.result_value->'usage'='null'::jsonb),false);
END $valid$;

CREATE FUNCTION zasp_temporal68.record_late_usage(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $late$
DECLARE o text;w text;e text;r text;k text;payload jsonb;raw text;cv jsonb;body_value jsonb;audit_value text;
 j zasp_temporal68.planning_jobs%ROWTYPE;p zasp_temporal68.provider_reservations%ROWTYPE;l zasp_temporal68.planning_late_usage%ROWTYPE;a public.zasp_security_agent_audit%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='late usage requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')) OR NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='late usage principal unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','operation','payload']) OR q->>'operation' IS DISTINCT FROM 'late_usage' OR octet_length(q::text)>131072
  OR NOT zasp_sa_multistep_prior.closed(q->'payload',ARRAY['raw','request_digest','credential_digest','reservation_id','response_id','response_digest']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='late usage request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='late usage scope rejected';END IF;
 END LOOP;
 payload:=q->'payload';
 FOREACH k IN ARRAY ARRAY['raw','request_digest','credential_digest','reservation_id','response_id','response_digest'] LOOP
  IF jsonb_typeof(payload->k) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='late usage association rejected';END IF;
 END LOOP;
 raw:=payload->>'raw';
 IF octet_length(raw) NOT BETWEEN 1 AND 65536 OR length(payload->>'response_id') NOT BETWEEN 1 AND 256 OR payload->>'response_id'!~'^[!-~]+$'
  OR payload->>'response_digest' IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(raw,'UTF8'),'sha256'),'hex')
  OR jsonb_typeof(raw::jsonb) IS DISTINCT FROM 'object' OR jsonb_typeof((raw::jsonb)->'id') IS DISTINCT FROM 'string' OR (raw::jsonb)->>'id' IS DISTINCT FROM payload->>'response_id'
  OR (SELECT count(*)<>count(DISTINCT key) FROM json_each(raw::json)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='late provider response rejected';END IF;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 PERFORM 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO j FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF j.run_id IS NULL OR j.state<>'needs_human' OR q->'definition_version' IS DISTINCT FROM to_jsonb(j.definition_version)
  OR payload->>'request_digest' IS DISTINCT FROM j.request_digest OR payload->>'credential_digest' IS DISTINCT FROM j.lookup_request->>'credential_digest' OR payload->>'reservation_id' IS DISTINCT FROM j.reservation_id THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='late usage original association rejected';END IF;
 -- This retains the full owner/budget/run/terminal checks and cannot create a
 -- new terminal snapshot: the explicit state check above requires one already.
 PERFORM zasp_temporal68.recover_plan(q||jsonb_build_object('operation','reconcile','payload','{}'::jsonb));
 SELECT * INTO l FROM zasp_temporal68.planning_late_usage WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF FOUND THEN
  IF l.body->>'raw' IS DISTINCT FROM raw OR l.body->'association' IS DISTINCT FROM payload-'raw' OR NOT zasp_temporal68.late_usage_valid(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='late usage immutable conflict';END IF;
  RETURN to_jsonb(j);
 END IF;
 SELECT * INTO p FROM zasp_temporal68.provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1) FOR UPDATE;
 SELECT * INTO a FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'temporal_planning_terminal');
 cv:=zasp_sa_multistep_prior.planning_result(raw,j.lookup_request->>'model',j.context_value);
 IF p.run_id IS NULL OR p.settled_at IS NOT NULL OR p.released_at IS NOT NULL OR cv->'usage' IS NULL OR cv->'usage'='null'::jsonb OR j.raw_result IS NOT NULL AND ((j.raw_result::jsonb)-'usage' IS DISTINCT FROM (raw::jsonb)-'usage' OR j.result_value->'usage' IS DISTINCT FROM 'null'::jsonb) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='late known usage unavailable';END IF;
 UPDATE zasp_temporal68.provider_reservations SET settled_at=clock_timestamp(),output_digest=digest(convert_to(raw,'UTF8'),'sha256'),prompt_tokens=(cv->'usage'->>'prompt_tokens')::bigint,completion_tokens=(cv->'usage'->>'completion_tokens')::bigint,total_tokens=(cv->'usage'->>'total_tokens')::bigint,cost_nano_credits=(cv->'usage'->>'cost_nano_credits')::bigint WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,1) RETURNING * INTO p;
 body_value:=jsonb_build_object('raw',raw,'association',payload-'raw','terminal_digest',encode(a.event_digest,'hex'),'reservation',to_jsonb(p),'usage',cv->'usage');
 INSERT INTO zasp_temporal68.planning_late_usage VALUES(o,w,e,r,payload->>'response_id',payload->>'credential_digest',body_value,digest(convert_to(body_value::text,'UTF8'),'sha256'));
 audit_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_planning_late_usage',r);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,audit_value,r,session_user,'temporal_planning_late_usage',digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
 IF NOT zasp_temporal68.planning_terminal_valid(o,w,e,r) OR NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='late usage evidence rejected';END IF;
 RETURN to_jsonb(j);
END $late$;
