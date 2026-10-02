-- This extension is dormant until separately registered principals call it.
-- The installer validates the complete reviewed67 catalog before this DDL.
SET LOCAL lock_timeout='3s';
CREATE ROLE zasp_temporal_executor NOLOGIN;
CREATE ROLE zasp_temporal_compensation NOLOGIN;
CREATE ROLE zasp_temporal_accounting NOLOGIN;
CREATE SCHEMA zasp_temporal68 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal68 FROM PUBLIC;
CREATE TABLE zasp_temporal68.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal68.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
CREATE TABLE zasp_temporal68.principals(authority text PRIMARY KEY CHECK(authority IN('zasp_temporal_executor','zasp_temporal_compensation')),principal name NOT NULL UNIQUE);
CREATE TABLE zasp_temporal68.planning_jobs(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 definition_version bigint NOT NULL,run_version bigint NOT NULL,state text NOT NULL CHECK(state IN('loaded','prepared','started','completed','settled','artifacts','admitted','needs_human')),
 budget_started_at timestamptz NOT NULL,budget_deadline_at timestamptz NOT NULL,
 context_value jsonb NOT NULL,input_body text NOT NULL,input_digest text NOT NULL,
 input_artifact_id text NOT NULL,output_artifact_id text NOT NULL,reservation_id text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id));
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions','principals','planning_jobs'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal68.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal68.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal68.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal68.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  IF n<>'planning_jobs' THEN EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal68.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);END IF;
 END LOOP;
END $tables$;

CREATE FUNCTION zasp_temporal68.principal_ready(a text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $principal$
 SELECT COALESCE(a IN('zasp_temporal_executor','zasp_temporal_compensation') AND EXISTS(
  SELECT 1 FROM zasp_temporal68.principals b JOIN pg_roles p ON p.rolname=b.principal JOIN pg_roles r ON r.rolname=b.authority
  WHERE b.authority=a AND b.principal=session_user AND p.rolcanlogin AND p.rolinherit
   AND NOT(p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls)
   AND NOT(r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
   AND EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=p.oid AND m.roleid=r.oid AND NOT m.admin_option)
   AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=p.oid AND (m.roleid<>r.oid OR m.admin_option))),false)
$principal$;

CREATE FUNCTION zasp_temporal68.adapter_principal_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $adapter$
 SELECT public.zasp_red_team_principal_ready('zasp_red_team_adapter') AND EXISTS(
  SELECT 1 FROM pg_roles p JOIN pg_roles r ON r.rolname='zasp_red_team_adapter'
  WHERE p.rolname=session_user AND p.rolcanlogin AND p.rolinherit
   AND NOT(p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls)
   AND NOT(r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
   AND EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=p.oid AND m.roleid=r.oid AND NOT m.admin_option)
   AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=p.oid AND (m.roleid<>r.oid OR m.admin_option))
   AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid))
$adapter$;

-- Only the authenticated migration principal can bind exact runtime logins.
CREATE FUNCTION zasp_temporal68.register_principals(executor_name text,compensation_name text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $register$
DECLARE n text;a text;p pg_roles%ROWTYPE;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));
 IF NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority')
  OR NOT zasp_temporal68.current_ready() OR executor_name=compensation_name THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor principal registration rejected';END IF;
 FOREACH a IN ARRAY ARRAY['zasp_temporal_executor','zasp_temporal_compensation'] LOOP
  n:=CASE a WHEN 'zasp_temporal_executor' THEN executor_name ELSE compensation_name END;
  SELECT * INTO p FROM pg_roles WHERE rolname=n;
  IF NOT FOUND OR n!~'^[a-z][a-z0-9_]{2,62}$' OR NOT p.rolcanlogin OR NOT p.rolinherit
   OR p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls
   OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=p.oid AND (roleid<>a::regrole OR admin_option))
   OR EXISTS(SELECT 1 FROM zasp_temporal68.principals WHERE authority=a AND principal<>n) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor login rejected';END IF;
  INSERT INTO zasp_temporal68.principals VALUES(a,n) ON CONFLICT DO NOTHING;
  EXECUTE format('GRANT %I TO %I',a,n);
 END LOOP;
END $register$;

INSERT INTO zasp_temporal68.predecessor_functions
 SELECT s,pg_get_functiondef(p.oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM unnest(ARRAY[
 'zasp_temporal66.legacy_visible(text,text,text,text)','zasp_temporal67.ready(text,text)','zasp_temporal67.base_ready()',
 'zasp_sa_multistep_prior.planning(text,text,jsonb)','public.zasp_security_agent_claim_budgeted_runs(text,text,integer,integer)',
 'zasp_sa_multistep_prior.transition_current(text,text,text,text,boolean)','zasp_ordered_public62.project_core(text,text,text,text,boolean)',
 'zasp_sa_multistep_prior.transition(text,text,jsonb)',
 'public.zasp_sa_multistep_readiness(text,text)']) s JOIN pg_proc p ON p.oid=s::regprocedure;

CREATE OR REPLACE FUNCTION zasp_temporal66.legacy_visible(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $visible$
 SELECT NOT zasp_temporal66.is_temporal(o,w,e,r) OR public.zasp_security_agent_principal_ready('zasp_security_agent_api')
  OR zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')
  OR zasp_temporal68.adapter_principal_ready()
$visible$;

-- The count owner has no login or members and owns only this count function.
-- It has SELECT only, and the sole runtime-visible result is a number. The
-- restrictive fence still hides all Temporal rows from old worker selectors.
GRANT USAGE ON SCHEMA zasp_temporal68 TO zasp_temporal_accounting;
GRANT USAGE ON SCHEMA zasp_temporal66 TO zasp_temporal_accounting;
GRANT EXECUTE ON FUNCTION zasp_temporal66.legacy_visible(text,text,text,text) TO zasp_temporal_accounting;
GRANT SELECT ON public.zasp_security_agent_runs,public.zasp_security_agent_run_budgets TO zasp_temporal_accounting;
CREATE POLICY temporal68_count ON public.zasp_security_agent_runs FOR SELECT TO zasp_temporal_accounting USING(true);
CREATE POLICY temporal68_count ON public.zasp_security_agent_run_budgets FOR SELECT TO zasp_temporal_accounting USING(true);
ALTER POLICY zasp_temporal66_owner ON public.zasp_security_agent_runs USING(current_user='zasp_temporal_accounting' OR zasp_temporal66.legacy_visible(organization_id,workspace_id,environment_id,run_id));
CREATE FUNCTION zasp_temporal68.active_count(o text,kind text,limit_value integer) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $count$
DECLARE result_value bigint;BEGIN
 IF NOT (public.zasp_security_agent_principal_ready('zasp_security_agent_worker') OR public.zasp_security_agent_principal_ready('zasp_security_agent_api') OR zasp_temporal68.principal_ready('zasp_temporal_executor'))
  OR kind NOT IN('planning','budget') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='shared admission count rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 SELECT count(*) INTO result_value FROM public.zasp_security_agent_runs r LEFT JOIN public.zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id)
 WHERE r.organization_id=o AND CASE kind
 WHEN 'planning' THEN r.state IN('planning','running','verifying','waiting_approval')
 WHEN 'budget' THEN b.run_id IS NOT NULL AND b.stop_reason IS NULL AND r.state IN('queued','planning','waiting_approval','running','verifying','contained') AND (limit_value IS NULL OR b.concurrency_limit=limit_value)
 ELSE false END;
 RETURN result_value;
END $count$;

-- Exact-source transformations consume the registered predecessor, retaining
-- each admission predicate. No old selector receives cross-owner row access.
DO $shared$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal68.predecessor_functions WHERE signature='zasp_sa_multistep_prior.planning(text,text,jsonb)';
 needle:=$needle$(SELECT count(*) FROM public.zasp_security_agent_runs WHERE organization_id=o AND state IN('planning','running','verifying','waiting_approval'))$needle$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'planning count predecessor rejected';END IF;
 EXECUTE replace(d,needle,$replace$zasp_temporal68.active_count(o,'planning',NULL)$replace$);
 SELECT definition INTO STRICT d FROM zasp_temporal68.predecessor_functions WHERE signature='public.zasp_security_agent_claim_budgeted_runs(text,text,integer,integer)';
 needle:=$needle$SELECT count(*),min(b.concurrency_limit) INTO active_count,active_limit
     FROM zasp_security_agent_run_budgets b JOIN zasp_security_agent_runs r
      USING(organization_id,workspace_id,environment_id,run_id)
     WHERE b.organization_id=organization_value AND b.stop_reason IS NULL
      AND r.state IN('queued','planning','waiting_approval','running','verifying','contained')$needle$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'budget count predecessor rejected';END IF;
 EXECUTE replace(d,needle,$replace$SELECT zasp_temporal68.active_count(organization_value,'budget',NULL),
      (SELECT min(v) FROM generate_series(1,10) v WHERE zasp_temporal68.active_count(organization_value,'budget',v)>0) INTO active_count,active_limit$replace$);
END $shared$;

CREATE FUNCTION zasp_temporal68.load_plan(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $plan$
DECLARE o text;w text;e text;r text;k text;rr public.zasp_security_agent_runs%ROWTYPE;b public.zasp_security_agent_run_budgets%ROWTYPE;job zasp_temporal68.planning_jobs%ROWTYPE;tr public.zasp_security_agent_trigger_receipts%ROWTYPE;cv jsonb;now_value timestamptz;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='executor requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') OR NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor authority unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','operation']) OR q->>'operation'<>'load'
  OR q->>'definition_version'!~'^([1-9][0-9]{0,5}|1000000)$' OR jsonb_typeof(q->'definition_version')<>'number' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor plan request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP
  IF jsonb_typeof(q->k)<>'string' OR NOT public.zasp_valid_product_id(q->>k) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor scope rejected';END IF;
 END LOOP;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 SELECT * INTO b FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND OR rr.definition_version<>(q->>'definition_version')::bigint OR NOT zasp_temporal66.is_temporal(o,w,e,r)
  OR rr.lease_token IS NOT NULL OR rr.lease_owner IS NOT NULL OR rr.lease_expires_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor run unavailable';END IF;
 SELECT * INTO job FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN
  IF rr.state<>'queued' OR rr.attempt<>0 OR rr.version<>1 OR rr.available_at>clock_timestamp() OR rr.plan_hash IS NOT NULL OR b.run_id IS NOT NULL
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor run not fresh';END IF;
  SELECT * INTO tr FROM public.zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,trigger_id)=(o,w,e,r,rr.definition_id,rr.trigger_id) FOR SHARE;
  IF NOT FOUND OR r<>public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',rr.definition_id||chr(31)||rr.trigger_id||chr(31)||tr.trigger_version::text) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor trigger identity rejected';END IF;
  UPDATE public.zasp_security_agent_runs SET state='planning',attempt=1,version=2 WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO rr;
  cv:=zasp_sa_multistep_prior.context(o,w,e,r);
  IF octet_length(cv::text)>65536 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor input too large';END IF;
  IF zasp_temporal68.active_count(o,'planning',NULL)>(cv->'definition'->>'concurrency_limit')::integer THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor concurrency exceeded';END IF;
  now_value:=clock_timestamp();
  INSERT INTO public.zasp_security_agent_org_admissions(organization_id) VALUES(o) ON CONFLICT DO NOTHING;
  INSERT INTO public.zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,deadline_at,max_steps,max_tokens,max_cost_nano_credits,concurrency_limit)
   VALUES(o,w,e,r,rr.definition_id,rr.definition_version,now_value,now_value+make_interval(secs=>(cv->'definition'->>'max_duration_seconds')::integer),2,(cv->'definition'->>'ai_token_budget')::bigint,(cv->'definition'->>'max_ai_cost_nano_credits')::bigint,(cv->'definition'->>'concurrency_limit')::integer) RETURNING * INTO b;
  INSERT INTO zasp_temporal68.planning_jobs VALUES(o,w,e,r,rr.definition_version,rr.version,'loaded',b.started_at,b.deadline_at,cv,cv::text,'sha256:'||encode(digest(convert_to(cv::text,'UTF8'),'sha256'),'hex'),public.zasp_discovery_canonical_id(o,w,e,'security_agent_planning_input',r),public.zasp_discovery_canonical_id(o,w,e,'security_agent_planning_output',r),public.zasp_discovery_canonical_id(o,w,e,'security_agent_planning_reservation',r)) RETURNING * INTO job;
 END IF;
 IF rr.state<>'planning' OR rr.version<>job.run_version OR b.stop_reason IS NOT NULL OR b.deadline_at<=clock_timestamp()
  OR zasp_sa_multistep_prior.context(o,w,e,r) IS DISTINCT FROM job.context_value OR NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor planning authority changed';END IF;
 RETURN to_jsonb(job);
END $plan$;

-- executor68 planning
-- executor68 late usage

-- executor68 effects

-- executor68 linked

-- executor68 settlement

-- executor68 application

-- executor68 delivery

-- executor68 cleanup

-- All callers retain their authenticated entry and established scope/row lock
-- order. Immutable66 ownership selects the exact evidence relation. Legacy
-- callers keep their saved complete61 validator, including provider receipts.
DO $current$ DECLARE d text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal68.predecessor_functions WHERE signature='zasp_sa_multistep_prior.transition_current(text,text,text,text,boolean)';
 EXECUTE replace(d,'FUNCTION zasp_sa_multistep_prior.transition_current(', 'FUNCTION zasp_temporal68.legacy_current(');
 d:=replace(d,'FUNCTION zasp_sa_multistep_prior.transition_current(', 'FUNCTION zasp_temporal68.current_plan(');
 d:=replace(d,'zasp_sa_multistep_prior.admissions','zasp_temporal68.admissions');
 EXECUTE replace(d,'public.zasp_security_agent_provider_reservations','zasp_temporal68.provider_reservations');
END $current$;
CREATE OR REPLACE FUNCTION zasp_sa_multistep_prior.transition_current(o text,w text,e text,r text,live_value boolean) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $current$
BEGIN
 IF zasp_temporal66.is_temporal(o,w,e,r) THEN PERFORM zasp_temporal68.current_plan(o,w,e,r,live_value);
 ELSE PERFORM zasp_temporal68.legacy_current(o,w,e,r,live_value);END IF;
END $current$;

-- Copy the complete reviewed transition, retaining its row order, current
-- approvals, receipts and replay evidence. Only the executor's scoped
-- progress/stop surface is granted; API decisions keep their original entry.
DO $progress$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal68.predecessor_functions WHERE signature='zasp_sa_multistep_prior.transition(text,text,jsonb)';
 d:=replace(d,'FUNCTION zasp_sa_multistep_prior.transition(', 'FUNCTION zasp_temporal68.progress_transition(');
 needle:=' IF NOT COALESCE(op IN(''progress'',''stop'',''approve'',''reject'',''cancel''),false)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'executor progress predecessor rejected';END IF;
 d:=replace(d,needle,' IF NOT COALESCE(op IN(''progress'',''stop''),false)');
 needle:='public.zasp_security_agent_principal_ready(role_value)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION 'executor progress principal predecessor rejected';END IF;
 d:=replace(d,needle,'(zasp_temporal68.principal_ready(''zasp_temporal_executor'') OR op=''stop'' AND zasp_temporal68.principal_ready(''zasp_temporal_compensation''))');
 d:=replace(d,'public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value)','zasp_temporal68.current_ready()');
 needle:=' PERFORM zasp_sa_multistep_prior.transition_lock(o,w,e,r);';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'executor progress lock predecessor rejected';END IF;
 d:=replace(d,needle,E' IF NOT zasp_temporal66.is_temporal(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''executor progress owner rejected'';END IF;\n'||needle);
 EXECUTE d;
END $progress$;
CREATE FUNCTION zasp_temporal68.progress(q jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $progress$
 SELECT zasp_temporal68.progress_transition(NULL,NULL,q)
$progress$;
CREATE FUNCTION zasp_temporal68.planning_present(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $present$
 SELECT CASE WHEN zasp_temporal66.is_temporal(o,w,e,r)
 THEN EXISTS(SELECT 1 FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
 ELSE EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) END
$present$;
DO $project$ DECLARE d text;needle text;first_value integer;last_value integer;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal68.predecessor_functions WHERE signature='zasp_ordered_public62.project_core(text,text,text,text,boolean)';
 EXECUTE replace(d,'FUNCTION zasp_ordered_public62.project_core(', 'FUNCTION zasp_temporal68.legacy_project(');
 d:=replace(d,'FUNCTION zasp_ordered_public62.project_core(', 'FUNCTION zasp_temporal68.project(');
 needle:='EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'public planning predecessor rejected';END IF;
 d:=replace(d,needle,'zasp_temporal68.planning_present(o,w,e,r)');
 needle:=' IF NOT admitted THEN';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION 'public terminal predecessor rejected';END IF;
 d:=replace(d,needle,E' IF NOT admitted AND rr.state=''needs_human'' AND EXISTS(SELECT 1 FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) AND NOT zasp_temporal68.planning_terminal_valid(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE=''40001'',MESSAGE=''public executor planning terminal evidence unavailable'';END IF;\n'||needle);
 d:=replace(d,'cleanup zasp_sa_multistep_prior.cleanups%ROWTYPE;','cleanup zasp_temporal68.cleanups%ROWTYPE;');
 first_value:=strpos(d,'  SELECT * INTO cleanup FROM zasp_sa_multistep_prior.cleanups');
 last_value:=strpos(d,'  live_value:=NOT terminal');
 IF first_value=0 OR last_value<=first_value OR strpos(d,'public ordered completed receipt unavailable')=0 THEN RAISE EXCEPTION 'public cleanup predecessor rejected';END IF;
 d:=substr(d,1,first_value-1)||E'  cleanup:=zasp_temporal68.cleanup_projection(o,w,e,r,predecessor);\n  IF NOT terminal AND application THEN\n   IF retained_value THEN retained_live:=zasp_ordered_public62.retained_application(o,w,e,r);\n   ELSIF NOT zasp_sa_multistep_prior.application_ready(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE=''40001'',MESSAGE=''public executor application unavailable'';END IF;\n  END IF;\n'||substr(d,last_value);
 -- Existing public retryable means unresolved compensation. Do not invent a
 -- public leased state for durable Temporal ownership.
 d:=replace(d,'COALESCE(cleanup.state,CASE WHEN application','COALESCE(CASE WHEN cleanup.state IN(''pending'',''unknown'') THEN ''retryable'' ELSE cleanup.state END,CASE WHEN application');
 d:=replace(d,'cleanup:=zasp_temporal68.cleanup_projection(o,w,e,r,predecessor);','cleanup:=zasp_temporal68.cleanup_projection(o,w,e,r,predecessor); IF terminal AND application AND cleanup.run_id IS NULL THEN PERFORM zasp_ordered_public62.retained_application(o,w,e,r);END IF;');
 d:=replace(d,'  live_value:=NOT terminal',E'  IF terminal AND EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE (organization_id,workspace_id,environment_id,run_id,action_key)=(o,w,e,r,''run_test'')) THEN PERFORM zasp_temporal68.test_terminal_evidence(o,w,e,r,public.zasp_discovery_canonical_id(o,w,e,''security_agent_step'',r||chr(31)||''1''));END IF;\n  live_value:=NOT terminal');
 EXECUTE d;
END $project$;
CREATE OR REPLACE FUNCTION zasp_ordered_public62.project_core(o text,w text,e text,r text,retained_value boolean) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $project$
BEGIN
 IF zasp_temporal66.is_temporal(o,w,e,r) THEN RETURN zasp_temporal68.project(o,w,e,r,retained_value);
 ELSE RETURN zasp_temporal68.legacy_project(o,w,e,r,retained_value);END IF;
END $project$;

-- General retained-state read for reusable executor operations. It neither
-- reclaims a lease nor refreshes requester permission for a new effect.
CREATE FUNCTION zasp_temporal68.status(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $status$
DECLARE o text;w text;e text;r text;k text;rr public.zasp_security_agent_runs%ROWTYPE;j zasp_temporal68.planning_jobs%ROWTYPE;projection jsonb;effects_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='executor status requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')) OR NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor status principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version']) OR octet_length(q::text)>4096 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor status request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor status scope rejected';END IF;
 END LOOP;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND OR NOT zasp_temporal66.is_temporal(o,w,e,r) OR q->'definition_version' IS DISTINCT FROM to_jsonb(rr.definition_version) OR rr.lease_owner IS NOT NULL OR rr.lease_token IS NOT NULL OR rr.lease_expires_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor status identity rejected';END IF;
 projection:=zasp_temporal68.project(o,w,e,r,true);
 SELECT * INTO j FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY step_id),'[]'::jsonb) INTO effects_value FROM zasp_temporal68.effects x WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor status catalog changed';END IF;
 RETURN jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'definition_version',rr.definition_version,'run_state',rr.state,'run_version',rr.version,'admitted',projection->'admitted','planning',CASE WHEN j.run_id IS NULL THEN 'null'::jsonb ELSE to_jsonb(j) END,'effects',effects_value,'projection',projection);
END $status$;

-- New post-transition pins are independent of all retained historical pins.
DO $readiness$ DECLARE d text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal68.predecessor_functions WHERE signature='zasp_temporal67.base_ready()';
 d:=replace(d,'FUNCTION zasp_temporal67.base_ready()', 'FUNCTION zasp_temporal68.base_ready()');
 EXECUTE replace(d,'b8b6e336ec72fa1b056c5e8a2f65cdd8275e9bbaee498ef1064d5f90133cf191','-- executor68 base fingerprint');
 SELECT definition INTO STRICT d FROM zasp_temporal68.predecessor_functions WHERE signature='zasp_temporal67.ready(text,text)';
 d:=replace(d,'FUNCTION zasp_temporal67.ready(', 'FUNCTION zasp_temporal68.predecessor_ready(');
 d:=replace(d,'zasp_temporal67.base_ready()', 'zasp_temporal68.base_ready()');
 EXECUTE replace(d,'zasp_temporal67.fingerprint() IS DISTINCT FROM f','zasp_temporal67.fingerprint() IS DISTINCT FROM ''-- executor68 domain fingerprint''');
END $readiness$;
CREATE FUNCTION zasp_temporal68.current_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $current$
 BEGIN RETURN zasp_temporal68.ready('-- executor68 checksum','-- executor68 fingerprint');END
$current$;
CREATE OR REPLACE FUNCTION zasp_temporal67.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- domain67 checksum' AND f='-- domain67 fingerprint' AND zasp_temporal68.current_ready(),false)
$ready$;
CREATE OR REPLACE FUNCTION public.zasp_sa_multistep_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(expected_checksum='-- release61 checksum' AND expected_fingerprint='-- release61 fingerprint' AND zasp_temporal68.current_ready(),false)
$ready$;
CREATE FUNCTION zasp_temporal68.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_temporal68'
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,''),replace(replace(replace(replace(pg_get_functiondef(p.oid),'-- executor68 checksum','<checksum>'),'-- executor68 fingerprint','<fingerprint>'),'-- executor68 base fingerprint','<base-fingerprint>'),'-- executor68 domain fingerprint','<domain-fingerprint>')) FROM pg_proc p WHERE p.pronamespace='zasp_temporal68'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.relnamespace='zasp_temporal68'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal68'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal68'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal68'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal68'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal68'::regnamespace
 UNION ALL SELECT concat_ws('|','foreign-key-trigger',k.conrelid::regclass::text,k.conname,k.confrelid::regclass::text,t.tgrelid::regclass::text,t.tgconstrrelid::regclass::text,t.tgfoid::regprocedure::text,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,t.tgnargs,encode(t.tgargs,'hex'),t.tgattr::text,COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal68'::regnamespace
 UNION ALL SELECT concat_ws('|','saved',signature,definition,owner_name,acl) FROM zasp_temporal68.predecessor_functions
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION zasp_temporal68.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- executor68 checksum' AND f='-- executor68 fingerprint'
 AND (SELECT count(*)=1 FROM zasp_temporal68.registration) AND EXISTS(SELECT 1 FROM zasp_temporal68.registration WHERE checksum=c AND fingerprint=f)
 AND zasp_temporal68.fingerprint()=f AND zasp_temporal68.predecessor_ready('-- domain67 checksum','-- domain67 fingerprint')
 AND (SELECT count(*)=3 AND bool_and(NOT(rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) FROM pg_roles WHERE rolname IN('zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting'))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid='zasp_temporal_accounting'::regrole OR member IN('zasp_temporal_executor'::regrole,'zasp_temporal_compensation'::regrole,'zasp_temporal_accounting'::regrole)),false)
$ready$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal68'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
ALTER FUNCTION zasp_temporal68.active_count(text,text,integer) OWNER TO zasp_temporal_accounting;
GRANT EXECUTE ON FUNCTION zasp_temporal68.active_count(text,text,integer) TO zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_temporal68.principal_ready(text) TO zasp_temporal_accounting;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_principal_ready(text) TO zasp_temporal_accounting;
GRANT USAGE ON SCHEMA zasp_temporal68 TO zasp_temporal_executor,zasp_temporal_compensation,zasp_security_agent_api,zasp_security_agent_worker;
GRANT USAGE ON SCHEMA zasp_temporal68 TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal68.invocation(jsonb),zasp_temporal68.adapter_ready(text,text) TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal68.standalone_resolve(text,text,text,text,text,text,text,text,text,text) TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal68.plan(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal68.status(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal68.effect(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal68.linked(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal68.test_settle(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal68.test_stop(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal68.progress(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal68.application(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal68.delivery(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal68.cleanup(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal68.ready(text,text) TO zasp_temporal_executor,zasp_temporal_compensation,zasp_security_agent_api,zasp_security_agent_worker;
-- SECURITY DEFINER registration needs role-grant authority but exposes no role
-- creation or arbitrary grants. Its owner already owns migration registration.
GRANT zasp_temporal_executor,zasp_temporal_compensation TO zasp_discovery_authority WITH ADMIN OPTION;
