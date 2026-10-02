-- Worker-only extension; canonical schema remains release61.
SET LOCAL lock_timeout='3s';
SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));
DO $predecessor$
BEGIN
 IF NOT COALESCE(zasp_ordered_public62.ready('-- public62 checksum','-- public62 fingerprint'),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker predecessor unavailable';END IF;
END $predecessor$;
CREATE SCHEMA zasp_ordered_worker63 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_ordered_worker63 FROM PUBLIC;
CREATE TABLE zasp_ordered_worker63.registration (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),
 fingerprint text NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$')
);
ALTER TABLE zasp_ordered_worker63.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_ordered_worker63.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_ordered_worker63.registration FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_ordered_worker63.registration USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_ordered_worker63.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_sa_multistep_prior.immutable_admission();
REVOKE ALL ON zasp_ordered_worker63.registration FROM PUBLIC;
CREATE TABLE zasp_ordered_worker63.dispatch_leases (
 dispatch_id text PRIMARY KEY CHECK(public.zasp_valid_product_id(dispatch_id)),
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 worker_id text NOT NULL CHECK(worker_id~'^[A-Za-z0-9_.-]{1,128}$'),
 token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
 version bigint NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 1000000),
 state text NOT NULL CHECK(state IN('active','recovery_deferred','reconciled')),
 lease_expires_at timestamptz NOT NULL,
 request jsonb NOT NULL CHECK(octet_length(request::text)<=4096),
 item jsonb NOT NULL CHECK(octet_length(item::text)<=4096),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(organization_id,workspace_id,environment_id,run_id),
 UNIQUE(worker_id,token_digest),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id)
);
ALTER TABLE zasp_ordered_worker63.dispatch_leases OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_ordered_worker63.dispatch_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_ordered_worker63.dispatch_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_ordered_worker63.dispatch_leases USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON zasp_ordered_worker63.dispatch_leases FROM PUBLIC;
CREATE FUNCTION zasp_ordered_worker63.fingerprint() RETURNS text
 LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_ordered_worker63'
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,''),replace(replace(pg_get_functiondef(p.oid),'-- worker63 checksum','<extension-checksum>'),'-- worker63 fingerprint','<extension-fingerprint>')) FROM pg_proc p WHERE p.pronamespace='zasp_ordered_worker63'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.relnamespace='zasp_ordered_worker63'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_ordered_worker63'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_ordered_worker63'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_ordered_worker63'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_ordered_worker63'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_ordered_worker63'::regnamespace
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION zasp_ordered_worker63.ready(c text,f text) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- worker63 checksum' AND f='-- worker63 fingerprint'
 AND zasp_ordered_public62.ready('-- public62 checksum','-- public62 fingerprint')
 AND (SELECT count(*)=1 FROM zasp_ordered_worker63.registration)
 AND EXISTS(SELECT 1 FROM zasp_ordered_worker63.registration WHERE singleton AND checksum=c AND fingerprint=f)
 AND zasp_ordered_worker63.fingerprint()=f,false)
$ready$;
-- Select only a unique current account policy. Pricing lookup remains the
-- authoritative check of its digest, account lineage and prepared request.
CREATE FUNCTION zasp_ordered_worker63.pricing(o text,w text,e text,planner jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $pricing$
DECLARE p zasp_sa_multistep_prior.pricing_policies%ROWTYPE;a zasp_sa_multistep_prior.pricing_accounts%ROWTYPE;result_value jsonb;matches integer:=0;
BEGIN
 FOR p IN SELECT DISTINCT ON(policy_id) * FROM zasp_sa_multistep_prior.pricing_policies
  WHERE (organization_id,workspace_id,environment_id)=(o,w,e) ORDER BY policy_id,version DESC LOOP
  IF p.policy_digest IS DISTINCT FROM zasp_sa_multistep_prior.pricing_digest(p) OR NOT zasp_sa_multistep_prior.pricing_policy_valid(p.policy) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker pricing drift';END IF;
  IF p.disabled OR (p.policy->>'effective_at')::timestamptz>clock_timestamp() OR (p.policy->>'expires_at')::timestamptz<=clock_timestamp()
   OR (p.policy->'provider',p.policy->'model',p.policy->'request_policy_version',p.policy->'request_token_limit',p.policy->'credential_digest') IS DISTINCT FROM (planner->'provider',planner->'model',planner->'request_policy_version',planner->'request_token_limit',planner->'credential_digest') THEN CONTINUE;END IF;
  SELECT * INTO a FROM zasp_sa_multistep_prior.pricing_accounts WHERE (organization_id,workspace_id,environment_id,account_id)=(o,w,e,p.account_id) ORDER BY version DESC LIMIT 1;
  IF a.account_id IS NULL OR a.version<>p.account_version OR (a.provider,a.account_profile,a.credential_reference,a.credential_digest) IS DISTINCT FROM (p.policy->>'provider',p.policy->>'account_profile',p.policy->>'credential_reference',p.policy->>'credential_digest') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker account drift';END IF;
  matches:=matches+1;
  result_value:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'provider',p.policy->'provider','model',p.policy->'model','account_profile',p.policy->'account_profile','cost_unit','openrouter_credit','credential_reference',p.policy->'credential_reference','credential_digest',p.policy->'credential_digest','request_policy_version',p.policy->'request_policy_version','request_token_limit',p.policy->'request_token_limit','policy_id',p.policy_id,'policy_version',p.version,'policy_digest',p.policy_digest,'account_id',a.account_id,'account_version',a.version);
 END LOOP;
 IF matches<>1 THEN RETURN NULL;END IF;
 RETURN result_value;
END $pricing$;

CREATE FUNCTION zasp_ordered_worker63.eligible(o text,w text,e text,r text,planner jsonb) RETURNS boolean
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $eligible$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;
BEGIN
   IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'ordered_public_triggered'))
    AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs x JOIN public.zasp_security_agent_definition_versions h ON (h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (h.definition->'max_steps'='2'::jsonb OR h.definition->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb))
    AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,resource_id)=(o,w,e,r) AND response->'contract_version'='62'::jsonb) THEN RETURN false;END IF;

 PERFORM zasp_ordered_public62.history(o,w,e,r);
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF rr.state<>'queued' OR rr.available_at>clock_timestamp() THEN RETURN false;END IF;
   IF rr.version<>1 OR rr.attempt<>0 OR rr.plan_hash IS NOT NULL OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
    OR EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
    OR EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
    OR EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker queued authority contradictory';END IF;

 RETURN zasp_ordered_worker63.pricing(o,w,e,planner) IS NOT NULL;
END $eligible$;

CREATE FUNCTION zasp_ordered_worker63.handoff(state_value jsonb) RETURNS boolean
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $handoff$
BEGIN
 IF state_value->>'run_state' IN('failed','inconclusive') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker aggregate authority contradictory';END IF;
 IF state_value->'admitted'='true'::jsonb THEN PERFORM zasp_ordered_public62.project_core(state_value->>'organization_id',state_value->>'workspace_id',state_value->>'environment_id',state_value->>'run_id',true);END IF;
 IF state_value->'stop_required' IS DISTINCT FROM 'false'::jsonb OR state_value->'planning'->>'state' NOT IN('admitted','needs_human') THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(state_value->'steps') s WHERE s->>'effect_state'='leased' AND (s->>'lease_expires_at')::timestamptz<=clock_timestamp()) THEN RETURN false;END IF;
 RETURN state_value->>'run_state' IN('waiting_approval','contained','remediated','needs_human','cancelled')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(state_value->'steps') s WHERE s->>'effect_state'='leased' AND (s->>'lease_expires_at')::timestamptz>clock_timestamp());
END $handoff$;

CREATE FUNCTION zasp_ordered_worker63.recovery_class(o text,w text,e text,r text) RETURNS text
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $recovery$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;job zasp_sa_multistep_prior.planning_jobs%ROWTYPE;state_value jsonb;stop_value boolean:=false;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 PERFORM zasp_ordered_public62.history(o,w,e,r);
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO job FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 IF job.run_id IS NULL OR rr.state IN('failed','inconclusive') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker recovery authority contradictory';END IF;
 IF job.state<>'admitted' THEN
  IF rr.state NOT IN('planning','needs_human') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker recovery parent contradictory';END IF;
  RETURN CASE WHEN job.lease_expires_at<=clock_timestamp() THEN 'reconcile' ELSE 'waiting' END;
 END IF;
 -- This prefilter uses the pinned readers without repeating catalog readiness
 -- for each skipped row. The top-level boundary already holds readiness locks;
 -- selected rows still receive the full orchestration read before mutation.
 PERFORM zasp_sa_multistep_prior.transition_lock(o,w,e,r);
 PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,false);
 SELECT rr.state IN('waiting_approval','running','verifying') AND rr.completed_at IS NULL AND (
  (SELECT count(*)<>4 OR NOT COALESCE(bool_and(execution_enabled),false) FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*','create_temporary_policy','run_test'))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND (stop_reason IS NOT NULL OR deadline_at IS NULL OR deadline_at<=clock_timestamp()))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND expires_at<=clock_timestamp())
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index)=(o,w,e,r,0) AND state IN('failed','inconclusive','cancelled'))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state IN('known_failure','unknown_outcome','cleanup_failed','cleaned'))) INTO stop_value;
 IF NOT stop_value THEN stop_value:=zasp_sa_multistep_prior.orchestration_stop_required(o,w,e,r);END IF;
 state_value:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'run_state',rr.state,'admitted',true,'planning',jsonb_build_object('state',job.state),'stop_required',stop_value,
  'steps',COALESCE((SELECT jsonb_agg(jsonb_build_object('effect_state',state,'lease_expires_at',lease_expires_at)) FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state='leased'),'[]'::jsonb));
 RETURN CASE WHEN zasp_ordered_worker63.handoff(state_value) THEN 'handoff' ELSE 'waiting' END;
END $recovery$;

CREATE FUNCTION zasp_ordered_worker63.dispatch(q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $dispatch$
DECLARE op text:=q->>'operation';k text;o text;w text;e text;r text;token bytea;selection jsonb;state_value jsonb;job_value jsonb;body_value text;item_value jsonb;outcome text;expires timestamptz;did text;
 candidate record;rr public.zasp_security_agent_runs%ROWTYPE;job zasp_sa_multistep_prior.planning_jobs%ROWTYPE;d zasp_ordered_worker63.dispatch_leases%ROWTYPE;
BEGIN
 IF op='claim' THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['operation','worker_id','lease_token','lease_seconds','limit','planner']) OR q->'limit' IS DISTINCT FROM '1'::jsonb
   OR NOT zasp_sa_multistep_prior.closed(q->'planner',ARRAY['provider','model','request_policy_version','request_token_limit','credential_digest'])
   OR q->'planner'->'provider' IS DISTINCT FROM '"openrouter"'::jsonb OR q->'planner'->'model' IS DISTINCT FROM '"openai/gpt-5-mini"'::jsonb
   OR q->'planner'->'request_policy_version' IS DISTINCT FROM '"security-agent-planner-v1"'::jsonb
   OR jsonb_typeof(q->'planner'->'credential_digest') IS DISTINCT FROM 'string' OR NOT COALESCE(q->'planner'->>'credential_digest'~'^sha256:[a-f0-9]{64}$',false)
   OR jsonb_typeof(q->'planner'->'request_token_limit') IS DISTINCT FROM 'number' OR NOT COALESCE(q->'planner'->>'request_token_limit'~'^[1-9][0-9]{0,3}$',false)
   OR (q->'planner'->>'request_token_limit')::integer>4096 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker planner rejected';END IF;
 ELSIF op='heartbeat' THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['operation','worker_id','lease_token','dispatch_id','run_version','dispatch_version','lease_seconds']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker heartbeat rejected';END IF;
 ELSIF op IN('finish','abandon') THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['operation','worker_id','lease_token','dispatch_id','run_version','dispatch_version']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker mutation rejected';END IF;
 ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker operation rejected';END IF;
 IF jsonb_typeof(q->'worker_id') IS DISTINCT FROM 'string' OR NOT COALESCE(q->>'worker_id'~'^[A-Za-z0-9_.-]{1,128}$',false)
  OR jsonb_typeof(q->'lease_token') IS DISTINCT FROM 'string' OR NOT COALESCE(q->>'lease_token'~'^[A-Za-z0-9_.-]{16,128}$',false) OR q->>'lease_token'~'^0+$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker lease identity rejected';END IF;
 IF op IN('claim','heartbeat') AND (jsonb_typeof(q->'lease_seconds') IS DISTINCT FROM 'number' OR NOT COALESCE(q->>'lease_seconds'~'^[1-9][0-9]{1,2}$',false) OR (q->>'lease_seconds')::integer NOT BETWEEN 30 AND 300) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker lease duration rejected';END IF;
 IF op<>'claim' THEN
  IF jsonb_typeof(q->'dispatch_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>'dispatch_id'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker dispatch rejected';END IF;
  FOREACH k IN ARRAY ARRAY['run_version','dispatch_version'] LOOP
   IF jsonb_typeof(q->k) IS DISTINCT FROM 'number' OR NOT COALESCE(q->>k~'^([1-9][0-9]{0,5}|1000000)$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker version rejected';END IF;
  END LOOP;
 END IF;
 token:=digest(convert_to(q->>'lease_token','UTF8'),'sha256');
 -- Serial global selection is bounded, with schema then organization-first
 -- predecessor locking. No row lock is taken before organization admission.
 PERFORM pg_advisory_xact_lock(hashtextextended('ordered-worker63-dispatch',0));
 IF op='claim' THEN
  SELECT * INTO d FROM zasp_ordered_worker63.dispatch_leases WHERE worker_id=q->>'worker_id' AND token_digest=token;
  IF FOUND AND d.state='active' AND d.lease_expires_at>clock_timestamp() THEN
   PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||d.organization_id,0));
   PERFORM zasp_ordered_public62.history(d.organization_id,d.workspace_id,d.environment_id,d.run_id);
   IF d.request IS DISTINCT FROM q-'lease_token' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker replay conflict';END IF;
   SELECT * INTO job FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id) FOR SHARE;
   selection:=zasp_ordered_worker63.pricing(d.organization_id,d.workspace_id,d.environment_id,q->'planner');
   IF job.run_id IS NULL OR (job.worker_id,job.lease_token_digest) IS DISTINCT FROM (d.worker_id,d.token_digest)
    OR job.lease_expires_at<=clock_timestamp() OR job.input_body IS DISTINCT FROM job.context_value::text OR job.input_digest IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(job.input_body,'UTF8'),'sha256'),'hex')
    OR (selection-ARRAY['organization_id','workspace_id','environment_id']) IS DISTINCT FROM d.item->'pricing'
    OR job.lookup_request IS NOT NULL AND (job.lookup_request-ARRAY['body','body_digest']) IS DISTINCT FROM selection THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker replay authority changed';END IF;
   RETURN jsonb_build_object('contract_version',63,'outcome','claimed','item',d.item);
  END IF;
  -- An expired dispatch never adopts or extends its predecessor's live lease.
  -- Reconciliation retains release61 needs-human evidence, never resends.
  -- Classify before either bounded window. An approved run without a
  -- separate executor lease stays owned and cannot starve planning recovery.
  -- Each call mutates at most one oldest candidate from each class.
  FOR candidate IN
   WITH classified AS MATERIALIZED (
    SELECT x.*,zasp_ordered_worker63.recovery_class(x.organization_id,x.workspace_id,x.environment_id,x.run_id) AS recovery_class
    FROM zasp_ordered_worker63.dispatch_leases x
    WHERE x.state IN('active','recovery_deferred') AND (x.state='recovery_deferred' OR x.lease_expires_at<=clock_timestamp())
   ), planning_window AS (
    SELECT * FROM classified WHERE recovery_class='reconcile' ORDER BY created_at,dispatch_id LIMIT 100
   ), handoff_window AS (
    SELECT * FROM classified WHERE recovery_class='handoff' ORDER BY created_at,dispatch_id LIMIT 100
   )
   SELECT * FROM (
    (SELECT * FROM planning_window ORDER BY created_at,dispatch_id LIMIT 1)
    UNION ALL
    (SELECT * FROM handoff_window ORDER BY created_at,dispatch_id LIMIT 1)
   ) selected ORDER BY created_at,dispatch_id LOOP
   o:=candidate.organization_id;w:=candidate.workspace_id;e:=candidate.environment_id;r:=candidate.run_id;
   PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
   PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
   SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
   SELECT * INTO job FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
   PERFORM zasp_ordered_public62.history(o,w,e,r);
   IF job.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker recovery job absent';END IF;
   IF candidate.recovery_class='handoff' AND job.state='admitted' THEN
    state_value:=zasp_sa_multistep_prior.orchestration_state('-- release61 checksum','-- release61 fingerprint',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'worker_id',q->>'worker_id','lease_token',q->>'lease_token','deployment_worker_id',q->>'worker_id','deployment_lease_token',q->>'lease_token'));
    IF zasp_ordered_worker63.handoff(state_value) THEN
     DELETE FROM zasp_ordered_worker63.dispatch_leases WHERE dispatch_id=candidate.dispatch_id;
    END IF;
   END IF;
   IF candidate.recovery_class='reconcile' AND job.lease_expires_at<=clock_timestamp() AND rr.state IN('planning','needs_human') AND job.state<>'admitted' THEN
    PERFORM zasp_sa_multistep_prior.planning('-- release61 checksum','-- release61 fingerprint',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'worker_id',q->>'worker_id','lease_token',q->>'lease_token','operation','reconcile','payload','{}'::jsonb));
    UPDATE zasp_ordered_worker63.dispatch_leases SET state='reconciled',version=version+1 WHERE dispatch_id=candidate.dispatch_id;
   END IF;
  END LOOP;
  FOR candidate IN SELECT x.organization_id,x.workspace_id,x.environment_id,x.run_id FROM public.zasp_security_agent_runs x WHERE x.state='queued' AND x.available_at<=clock_timestamp() AND zasp_ordered_worker63.eligible(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q->'planner') ORDER BY x.created_at,x.organization_id,x.workspace_id,x.environment_id,x.run_id LIMIT 100 LOOP
   o:=candidate.organization_id;w:=candidate.workspace_id;e:=candidate.environment_id;r:=candidate.run_id;
   -- Any retained ordered marker requires intact history; relabeling a current
   -- definition or deleting just one retained marker cannot hide corruption.
   IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'ordered_public_triggered'))
    AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs x JOIN public.zasp_security_agent_definition_versions h ON (h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (h.definition->'max_steps'='2'::jsonb OR h.definition->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb))
    AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,resource_id)=(o,w,e,r) AND response->'contract_version'='62'::jsonb) THEN CONTINUE;END IF;
   PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
   PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
   SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
   PERFORM zasp_ordered_public62.history(o,w,e,r);
   IF rr.state<>'queued' THEN CONTINUE;END IF;
   IF rr.version<>1 OR rr.attempt<>0 OR rr.plan_hash IS NOT NULL OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
    OR EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
    OR EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
    OR EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker queued authority contradictory';END IF;
   selection:=zasp_ordered_worker63.pricing(o,w,e,q->'planner');
   IF selection IS NULL THEN CONTINUE;END IF;
   PERFORM zasp_ordered_public62.definition(o,w,e,rr.definition_id,rr.definition_version,true);
   job_value:=zasp_sa_multistep_prior.planning('-- release61 checksum','-- release61 fingerprint',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'worker_id',q->>'worker_id','lease_token',q->>'lease_token','operation','claim','payload','{}'::jsonb));
   IF job_value->>'state' IS DISTINCT FROM 'claimed' OR job_value->>'run_id' IS DISTINCT FROM r OR job_value->'run_version' IS DISTINCT FROM '2'::jsonb OR job_value->>'worker_id' IS DISTINCT FROM q->>'worker_id' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker planning claim mismatch';END IF;
   body_value:=zasp_sa_multistep_prior.planning_body(job_value->'context_value',selection);
   PERFORM zasp_sa_multistep_prior.pricing_lookup('-- release61 checksum','-- release61 fingerprint',selection||jsonb_build_object('body',body_value,'body_digest','sha256:'||encode(digest(convert_to(body_value,'UTF8'),'sha256'),'hex')));
   expires:=clock_timestamp()+make_interval(secs=>(q->>'lease_seconds')::integer);
   did:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_dispatch63',r);
   item_value:=jsonb_build_object('dispatch_id',did,'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'definition_id',rr.definition_id,'definition_version',rr.definition_version,'run_version',2,'state','planning','dispatch_version',1,'lease_expires_at',to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'pricing',selection-ARRAY['organization_id','workspace_id','environment_id']);
   INSERT INTO zasp_ordered_worker63.dispatch_leases(dispatch_id,organization_id,workspace_id,environment_id,run_id,worker_id,token_digest,state,lease_expires_at,request,item) VALUES(did,o,w,e,r,q->>'worker_id',token,'active',expires,q-'lease_token',item_value);
   PERFORM zasp_ordered_public62.history(o,w,e,r);
   RETURN jsonb_build_object('contract_version',63,'outcome','claimed','item',item_value);
  END LOOP;
  RETURN jsonb_build_object('contract_version',63,'outcome','empty','item',NULL);
 END IF;
 SELECT * INTO d FROM zasp_ordered_worker63.dispatch_leases WHERE dispatch_id=q->>'dispatch_id';
 IF NOT FOUND OR d.state<>'active' OR (d.worker_id,d.token_digest,d.version) IS DISTINCT FROM (q->>'worker_id',token,(q->>'dispatch_version')::bigint) OR d.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker ownership changed';END IF;
 o:=d.organization_id;w:=d.workspace_id;e:=d.environment_id;r:=d.run_id;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO job FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 PERFORM zasp_ordered_public62.history(o,w,e,r);
 IF rr.version IS DISTINCT FROM (q->>'run_version')::bigint OR job.run_id IS NULL OR d.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker run changed';END IF;
 state_value:=zasp_sa_multistep_prior.orchestration_state('-- release61 checksum','-- release61 fingerprint',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'worker_id',q->>'worker_id','lease_token',q->>'lease_token','deployment_worker_id',q->>'worker_id','deployment_lease_token',q->>'lease_token'));
 IF d.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker lease expired after authority wait';END IF;
 IF op='heartbeat' THEN
  expires:=greatest(d.lease_expires_at,clock_timestamp()+make_interval(secs=>(q->>'lease_seconds')::integer));
  item_value:=d.item||jsonb_build_object('run_version',rr.version,'state',rr.state,'dispatch_version',d.version+1,'lease_expires_at',to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  UPDATE zasp_ordered_worker63.dispatch_leases SET version=version+1,lease_expires_at=expires,item=item_value WHERE dispatch_id=d.dispatch_id;
  outcome:='extended';
 ELSIF op='finish' THEN
  IF job.state NOT IN('admitted','needs_human') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker planning recovery unresolved';END IF;
  IF NOT zasp_ordered_worker63.handoff(state_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker handoff unavailable';END IF;
  DELETE FROM zasp_ordered_worker63.dispatch_leases WHERE dispatch_id=d.dispatch_id;
  outcome:='finished';
 ELSE
  IF job.state NOT IN('claimed','prepared','started','completed','settled','artifacts','needs_human') OR rr.state NOT IN('planning','needs_human') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker abandon unavailable';END IF;
  IF job.lease_expires_at<=clock_timestamp() THEN
   PERFORM zasp_sa_multistep_prior.planning('-- release61 checksum','-- release61 fingerprint',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'worker_id',q->>'worker_id','lease_token',q->>'lease_token','operation','reconcile','payload','{}'::jsonb));
   outcome:='reconciled';
  ELSE outcome:='recovery_deferred';END IF;
  UPDATE zasp_ordered_worker63.dispatch_leases SET state=outcome,version=version+1 WHERE dispatch_id=d.dispatch_id;
 END IF;
 RETURN jsonb_build_object('contract_version',63,'outcome',outcome,'item',item_value);
END $dispatch$;
CREATE FUNCTION zasp_ordered_worker63.worker(c text,f text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $worker$
DECLARE response_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='worker requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 LOCK TABLE zasp_ordered_public62.registration IN SHARE MODE;
 LOCK TABLE zasp_ordered_worker63.registration IN SHARE MODE;
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker principal rejected';END IF;
 IF NOT zasp_ordered_worker63.ready(c,f) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker release unavailable';END IF;
 IF q IS NULL OR octet_length(q::text)>4096 OR jsonb_typeof(q) IS DISTINCT FROM 'object' OR jsonb_typeof(q->'operation') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker request rejected';END IF;
 IF q->>'operation'='ready' THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['operation']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker ready rejected';END IF;
  response_value:=jsonb_build_object('contract_version',63,'ready',true);
 ELSE response_value:=zasp_ordered_worker63.dispatch(q);END IF;
 IF response_value IS NULL OR octet_length(response_value::text)>8192 OR NOT zasp_ordered_worker63.ready(c,f) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker authority changed';END IF;
 IF response_value->'item' IS NOT NULL AND response_value->'item'<>'null'::jsonb AND (response_value->'item'->>'lease_expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker returned lease expired';END IF;
 RETURN response_value;
END $worker$;
DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_ordered_worker63'::regnamespace LOOP EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);END LOOP;
END $owners$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zasp_ordered_worker63 FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_ordered_worker63 TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_ordered_worker63.worker(text,text,jsonb) TO zasp_security_agent_worker;
