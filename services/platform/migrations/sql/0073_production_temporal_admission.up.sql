-- Admission checkpoint only. No new executor or ownership transfer is installed.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal73 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal73 FROM PUBLIC;
CREATE TABLE zasp_temporal73.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal73.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
CREATE TABLE zasp_temporal73.admissions(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 definition_id text NOT NULL,definition_version bigint NOT NULL,trigger_id text NOT NULL,trigger_version bigint NOT NULL,trigger_digest bytea NOT NULL,
 execution_owner text NOT NULL CHECK(execution_owner='retained_single_action'),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id));
CREATE TABLE zasp_temporal73.commands(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision=1),kind text NOT NULL CHECK(kind='start'),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,revision),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal73.admissions(organization_id,workspace_id,environment_id,run_id));
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions','admissions','commands'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal73.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal73.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal73.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal73.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal73.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;

CREATE FUNCTION zasp_temporal73.ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
BEGIN RETURN COALESCE(c='-- admission73 checksum' AND f='-- admission73 fingerprint'
 AND zasp_temporal72.ready('-- discovery72 checksum','-- discovery72 fingerprint')
 AND (SELECT count(*)=1 FROM zasp_temporal73.registration)
 AND EXISTS(SELECT 1 FROM zasp_temporal73.registration WHERE checksum=c AND fingerprint=f)
 AND zasp_temporal73.fingerprint()=f,false);END $ready$;
CREATE FUNCTION zasp_temporal73.current_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal73.ready('-- admission73 checksum','-- admission73 fingerprint')
$ready$;
CREATE FUNCTION zasp_temporal73.client_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal73.ready(c,f) AND public.zasp_sa_export_principal_ready('zasp_security_agent_worker')
$ready$;

-- This narrow role already has all-owner SELECT through installed68. It has no
-- members and cannot execute mutations. The count never depends on leases.
CREATE FUNCTION zasp_temporal73.unresolved(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $unresolved$
 SELECT EXISTS(SELECT 1 FROM zasp_temporal68.effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (x.state IN('started','unknown','cleanup_pending') OR x.action_key='create_temporary_policy' AND x.state='verified'))
 OR EXISTS(SELECT 1 FROM zasp_temporal68.cleanups x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state<>'cleaned')
 OR EXISTS(SELECT 1 FROM zasp_temporal68.provider_reservations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL AND x.released_at IS NULL)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state IN('leased','unknown_outcome','cleanup_pending','cleanup_failed'))
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_controls x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state<>'disabled')
 OR EXISTS(SELECT 1 FROM public.zasp_sa_attack_lab_links x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL)
 OR EXISTS(SELECT 1 FROM public.zasp_sa_export_links x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (x.reconcile_state<>'settled' OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.state)=(o,w,e,x.test_run_id,'started'))))
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_webhook_deliveries x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (x.settlement_state<>'settled' OR x.state IN('dispatching','uncertain')))
$unresolved$;
CREATE FUNCTION zasp_temporal73.active_count(o text,w text,e text,d text) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $count$
BEGIN
 IF NOT (public.zasp_security_agent_principal_ready('zasp_security_agent_worker') OR public.zasp_security_agent_principal_ready('zasp_security_agent_api') OR zasp_temporal68.principal_ready('zasp_temporal_executor')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='admission accounting principal rejected';END IF;
 RETURN (SELECT count(*) FROM public.zasp_security_agent_runs r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.definition_id)=(o,w,e,d) AND (r.state IN('queued','planning','waiting_approval','running','verifying','contained') OR zasp_temporal73.unresolved(r.organization_id,r.workspace_id,r.environment_id,r.run_id)));
END $count$;

-- The row boundary covers callers outside the selector too. Try-lock rather
-- than wait here because older callers may already hold a definition lock.
CREATE FUNCTION zasp_temporal73.capacity_guard() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $capacity$
DECLARE bound_value integer;BEGIN
 IF NEW.state='simulated' THEN RETURN NEW;END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='admission requires read committed';END IF;
 IF NOT zasp_temporal73.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='admission release unavailable';END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||NEW.organization_id,0)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='admission organization busy';END IF;
 SELECT (body->>'concurrency_limit')::integer INTO bound_value FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,NEW.definition_version) AND deleted_at IS NULL FOR SHARE;
 IF bound_value IS NULL OR bound_value<1 OR zasp_temporal73.active_count(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id)>=bound_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='admission definition capacity unavailable';END IF;
 RETURN NEW;
END $capacity$;
CREATE TRIGGER zasp_temporal73_capacity BEFORE INSERT ON public.zasp_security_agent_runs FOR EACH ROW EXECUTE FUNCTION zasp_temporal73.capacity_guard();

-- Copy only the two installed scheduling/admission bodies. Every original
-- eligibility, source identity, authority recheck and delegated family stays.
INSERT INTO zasp_temporal73.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal70.body02(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)'::regprocedure,'zasp_temporal70.body14(text,integer,text,text)'::regprocedure);
DO $copies$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal73.predecessor_functions WHERE signature='zasp_temporal70.body02(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)';
 d:=replace(d,'FUNCTION zasp_temporal70.body02(','FUNCTION zasp_temporal73.admit(');
 needle:=$needle$(SELECT count(*) FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND state IN('queued','planning','waiting_approval','running','verifying','contained'))$needle$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'admission count source rejected';END IF;
 d:=replace(d,needle,'zasp_temporal73.active_count(o,w,e,d)');
 needle:='  created_value:=true;';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'admission capture source rejected';END IF;
 d:=replace(d,needle,$capture$
  INSERT INTO zasp_temporal73.admissions VALUES(o,w,e,r,d,v,t,(trigger_value->>'version')::bigint,decode(trigger_value->>'digest','hex'),'retained_single_action');
  INSERT INTO zasp_temporal73.commands VALUES(o,w,e,r,1,'start');
  created_value:=true;$capture$);
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_temporal73.predecessor_functions WHERE signature='zasp_temporal70.body14(text,integer,text,text)';
 d:=replace(d,'FUNCTION zasp_temporal70.body14(','FUNCTION zasp_temporal73.schedule_body(');
 d:=replace(d,'zasp_temporal70.body02(','zasp_temporal73.admit(');
 needle:=$needle$(SELECT count(*) FROM public.zasp_security_agent_runs active_run WHERE (active_run.organization_id,active_run.workspace_id,active_run.environment_id,active_run.definition_id)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id) AND active_run.state IN('queued','planning','waiting_approval','running','verifying','contained'))$needle$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'candidate count source rejected';END IF;
 EXECUTE replace(d,needle,'zasp_temporal73.active_count(d.organization_id,d.workspace_id,d.environment_id,d.definition_id)');
END $copies$;
CREATE FUNCTION zasp_temporal73.schedule(worker_value text,limit_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $schedule$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 IF NOT zasp_temporal73.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='admission release unavailable';END IF;
 RETURN zasp_temporal73.schedule_body(worker_value,limit_value,expected_checksum,expected_fingerprint);
END $schedule$;
DO $fingerprint$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal70.fingerprint()'::regprocedure) INTO d;
 d:=replace(d,'zasp_temporal70','zasp_temporal73');
 d:=replace(d,'-- compatibility70 checksum','-- admission73 checksum');
 d:=replace(d,'-- compatibility70 fingerprint','-- admission73 fingerprint');
 d:=replace(d,'UNION ALL SELECT concat_ws(''|'',''saved''', $tracking$UNION ALL SELECT concat_ws('|','capacity-trigger',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_temporal73_capacity'
 UNION ALL SELECT concat_ws('|','saved'$tracking$);
 EXECUTE d;
END $fingerprint$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal73'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
ALTER FUNCTION zasp_temporal73.active_count(text,text,text,text) OWNER TO zasp_temporal_accounting;
GRANT USAGE ON SCHEMA zasp_temporal73 TO zasp_temporal_accounting,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal73.active_count(text,text,text,text) TO zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_temporal73.unresolved(text,text,text,text) TO zasp_temporal_accounting;
GRANT EXECUTE ON FUNCTION zasp_temporal73.client_ready(text,text),zasp_temporal73.schedule(text,integer,text,text) TO zasp_security_agent_worker;
