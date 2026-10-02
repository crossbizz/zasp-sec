-- Only the specialized automatic test selector moves here. Historical SQL is
-- preserved; current74 grants and73 capacity/start capture remain authoritative.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal75 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal75 FROM PUBLIC;
CREATE TABLE zasp_temporal75.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal75.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
CREATE TABLE zasp_temporal75.configuration(
 revision bigint PRIMARY KEY CHECK(revision BETWEEN 1 AND 1000000),schema_version integer NOT NULL CHECK(schema_version=1),
 cadence_seconds integer NOT NULL CHECK(cadence_seconds BETWEEN 1 AND 86400),enabled boolean NOT NULL,
 installed_by name NOT NULL,installed_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE zasp_temporal75.admissions(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 configuration_revision bigint NOT NULL REFERENCES zasp_temporal75.configuration(revision),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal73.admissions(organization_id,workspace_id,environment_id,run_id));
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions','configuration','admissions'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal75.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal75.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal75.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal75.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal75.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;
CREATE FUNCTION zasp_temporal75.ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
BEGIN RETURN COALESCE(c='-- selector75 checksum' AND f='-- selector75 fingerprint'
 AND zasp_temporal74.ready('-- test74 checksum','-- test74 fingerprint')
 AND (SELECT count(*)=1 FROM zasp_temporal75.registration) AND EXISTS(SELECT 1 FROM zasp_temporal75.registration WHERE checksum=c AND fingerprint=f)
 AND zasp_temporal75.fingerprint()=f,false);END $ready$;
CREATE FUNCTION zasp_temporal75.current_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal75.ready('-- selector75 checksum','-- selector75 fingerprint')
$ready$;
CREATE FUNCTION zasp_temporal75.require_executor() RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $principal$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='selector requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal75.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='selector principal rejected';END IF;
END $principal$;
CREATE FUNCTION zasp_temporal75.configure(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $configure$
DECLARE prior zasp_temporal75.configuration%ROWTYPE;r bigint;c integer;BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') OR NOT zasp_temporal75.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='selector configuration principal rejected';END IF;
 IF NOT COALESCE(jsonb_typeof(q)='object' AND q?&ARRAY['revision','cadence_seconds','enabled'] AND q-ARRAY['revision','cadence_seconds','enabled']='{}'::jsonb
  AND jsonb_typeof(q->'revision')='number' AND q->>'revision'~'^[1-9][0-9]{0,6}$' AND jsonb_typeof(q->'cadence_seconds')='number' AND q->>'cadence_seconds'~'^[1-9][0-9]{0,4}$' AND jsonb_typeof(q->'enabled')='boolean',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='selector configuration rejected';END IF;
 r:=(q->>'revision')::bigint;c:=(q->>'cadence_seconds')::integer;
 IF r>1000000 OR c>86400 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='selector bounds rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('test-selector75-configuration',0));
 SELECT * INTO prior FROM zasp_temporal75.configuration ORDER BY revision DESC LIMIT 1;
 IF prior.revision=r AND (prior.cadence_seconds,prior.enabled)=(c,(q->>'enabled')::boolean) THEN RETURN q;END IF;
 IF r<>COALESCE(prior.revision,0)+1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='selector revision changed';END IF;
 INSERT INTO zasp_temporal75.configuration VALUES(r,1,c,(q->>'enabled')::boolean,session_user,clock_timestamp());
 RETURN q;
END $configure$;
CREATE FUNCTION zasp_temporal75.desired(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $desired$
DECLARE c zasp_temporal75.configuration%ROWTYPE;d public.zasp_security_agent_definitions%ROWTYPE;BEGIN
 PERFORM zasp_temporal75.require_executor();
 IF NOT COALESCE(jsonb_typeof(q)='object' AND q?&ARRAY['organization_id','workspace_id','environment_id','definition_id'] AND q-ARRAY['organization_id','workspace_id','environment_id','definition_id']='{}'::jsonb
 AND public.zasp_valid_product_id(q->>'organization_id') AND public.zasp_valid_product_id(q->>'workspace_id') AND public.zasp_valid_product_id(q->>'environment_id') AND public.zasp_valid_product_id(q->>'definition_id'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='selector scope rejected';END IF;
 SELECT * INTO c FROM zasp_temporal75.configuration ORDER BY revision DESC LIMIT 1;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='selector configuration missing';END IF;
 SELECT * INTO d FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'definition_id');
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='selector definition absent';END IF;
 RETURN jsonb_build_object('ref',q,'revision',c.revision,'schema_version',c.schema_version,'cadence_seconds',c.cadence_seconds,'enabled',c.enabled AND d.deleted_at IS NULL AND d.activation IN('supervised','autonomous') AND d.body->'enabled'='true'::jsonb AND d.body->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb));
END $desired$;
CREATE FUNCTION zasp_temporal75.references(after_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $refs$
BEGIN
 PERFORM zasp_temporal75.require_executor();
 IF after_value IS NULL OR limit_value NOT BETWEEN 1 AND 100 OR NOT EXISTS(SELECT 1 FROM zasp_temporal75.configuration) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='selector scan rejected';END IF;
 -- Include disabled/deleted and previously granted definitions so reconciliation
 -- pauses existing Schedules. This scans configuration, never source occurrences.
 RETURN (SELECT COALESCE(jsonb_agg(q ORDER BY k),'[]'::jsonb) FROM (
 SELECT concat_ws('/',d.organization_id,d.workspace_id,d.environment_id,d.definition_id) k,jsonb_build_object('organization_id',d.organization_id,'workspace_id',d.workspace_id,'environment_id',d.environment_id,'definition_id',d.definition_id) q
 FROM public.zasp_security_agent_definitions d WHERE (d.body->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) OR EXISTS(SELECT 1 FROM zasp_temporal74.service_grants g WHERE(g.organization_id,g.workspace_id,g.environment_id,g.definition_id)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id)))
 AND concat_ws('/',d.organization_id,d.workspace_id,d.environment_id,d.definition_id)>after_value
 ORDER BY k LIMIT limit_value) rows);
END $refs$;

CREATE FUNCTION zasp_temporal75.binding(o text,w text,e text,d text,v bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $binding$
BEGIN RETURN zasp_temporal74.authorize(o,w,e,d,v)->'test';END $binding$;
-- A retained registered worker cannot bypass new ownership through73 or70.
-- Human/manual routes keep their own current permission and receipt checks.
CREATE FUNCTION zasp_temporal75.owner_guard() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
DECLARE d public.zasp_security_agent_definitions%ROWTYPE;g jsonb;BEGIN
 SELECT * INTO d FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,NEW.definition_version);
 IF d.body->'allowed_actions' NOT IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) OR NEW.state='simulated' THEN RETURN NEW;END IF;
 IF public.zasp_security_agent_principal_ready('zasp_security_agent_worker') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='specialized selector owned by Temporal';END IF;
 IF zasp_temporal68.principal_ready('zasp_temporal_executor') THEN
  PERFORM zasp_temporal75.require_executor();
  g:=zasp_temporal74.authorize(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,NEW.definition_version);
  IF NEW.requested_by IS DISTINCT FROM g->>'principal_id' OR (SELECT enabled FROM zasp_temporal75.configuration ORDER BY revision DESC LIMIT 1) IS DISTINCT FROM true THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='selector current authority rejected';END IF;
 END IF;
 RETURN NEW;
END $guard$;
CREATE TRIGGER zasp_temporal75_owner BEFORE INSERT ON public.zasp_security_agent_runs FOR EACH ROW EXECUTE FUNCTION zasp_temporal75.owner_guard();
-- Ownership starts in the admission transaction, before asynchronous74 takeover.
-- Existing unmarked parents retain their installed owner's visibility rules.
CREATE FUNCTION zasp_temporal75.visible(o text,w text,e text,r text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $visible$
DECLARE privileged boolean;BEGIN
 privileged:=public.zasp_security_agent_principal_ready('zasp_security_agent_api') OR zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation');
 -- This predicate is callable for RLS expression initialization. Refuse an
 -- unregistered login before looking up any marker; it is not a read API.
 IF NOT privileged AND NOT EXISTS(SELECT 1 FROM (
  SELECT principal_name,authority_role FROM public.zasp_security_agent_principal_bindings
  UNION ALL SELECT principal_name,authority_role FROM public.zasp_discovery_principal_bindings
  UNION ALL SELECT principal_name,authority_role FROM public.zasp_red_team_principal_bindings
  UNION ALL SELECT principal_name,authority_role FROM public.zasp_attack_lab_principal_bindings
  UNION ALL SELECT principal_name,authority_role FROM public.zasp_recovery_principal_bindings
  UNION ALL SELECT principal_name,authority_role FROM public.zasp_policy_deployment_principal_bindings
  UNION ALL SELECT principal_name,authority_role FROM public.zasp_sa_attack_lab_principals
  UNION ALL SELECT principal_name,authority_role FROM public.zasp_audit_export_worker_bindings
  UNION ALL SELECT principal_name,authority_role FROM public.zasp_compliance_worker_bindings
  UNION ALL SELECT principal_name,authority_role FROM public.zasp_runtime_principal_bindings
  UNION ALL SELECT principal_name,'zasp_security_agent_webhook_worker' FROM public.zasp_sa_webhook_principals
 ) b JOIN pg_roles p ON p.rolname=b.principal_name JOIN pg_roles a ON a.rolname=b.authority_role
 WHERE b.principal_name=session_user AND p.rolcanlogin AND p.rolinherit AND NOT(p.rolsuper OR p.rolbypassrls OR p.rolcreaterole OR p.rolcreatedb OR p.rolreplication)
 AND EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=p.oid AND m.roleid=a.oid AND NOT m.admin_option))
 AND NOT public.zasp_security_agent_action_principal_ready() THEN RETURN false;END IF;
 RETURN privileged OR NOT EXISTS(SELECT 1 FROM zasp_temporal75.admissions WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r));
END
$visible$;
CREATE POLICY zasp_temporal75_owner ON public.zasp_security_agent_runs AS RESTRICTIVE
 USING(CASE WHEN current_user IN('zasp_temporal_accounting','zasp_temporal74_parent_lock') THEN true ELSE zasp_temporal75.visible(organization_id,workspace_id,environment_id,run_id) END)
 WITH CHECK(zasp_temporal75.visible(organization_id,workspace_id,environment_id,run_id));

INSERT INTO zasp_temporal75.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN('zasp_temporal73.admit(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)'::regprocedure,'zasp_temporal73.schedule_body(text,integer,text,text)'::regprocedure);
DO $copies$ DECLARE d text;legacy text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal75.predecessor_functions WHERE signature='zasp_temporal73.admit(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)';
 d:=replace(d,'FUNCTION zasp_temporal73.admit(','FUNCTION zasp_temporal75.admit_body(');
 IF position('zasp_temporal70.body15(' IN d)=0 THEN RAISE EXCEPTION 'selector binding source changed';END IF;
 d:=replace(d,'zasp_temporal70.body15(','zasp_temporal75.binding(');
 needle:='  created_value:=true;';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'selector ownership capture source changed';END IF;
 d:=replace(d,needle,$capture$
  INSERT INTO zasp_temporal75.admissions SELECT o,w,e,r,revision FROM zasp_temporal75.configuration ORDER BY revision DESC LIMIT 1;
  created_value:=true;$capture$);
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_temporal75.predecessor_functions WHERE signature='zasp_temporal73.schedule_body(text,integer,text,text)';
 legacy:=replace(d,'FUNCTION zasp_temporal73.schedule_body(','FUNCTION zasp_temporal75.retained_body(');
 needle:='WHERE d.deleted_at IS NULL';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'selector candidate source changed';END IF;
 EXECUTE replace(legacy,needle,'WHERE false AND d.deleted_at IS NULL');
 d:=replace(d,'FUNCTION zasp_temporal73.schedule_body(worker_value text,','FUNCTION zasp_temporal75.select_body(scope_o text,scope_w text,scope_e text,scope_d text,worker_value text,');
 d:=replace(d,needle,'WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=(scope_o,scope_w,scope_e,scope_d) AND d.deleted_at IS NULL');
 d:=replace(d,'public.zasp_security_agent_principal_ready(''zasp_security_agent_worker'')','zasp_temporal68.principal_ready(''zasp_temporal_executor'')');
 d:=replace(d,'zasp_temporal73.admit(','zasp_temporal75.admit_body(');
 d:=replace(d,'zasp_temporal70.body15(','zasp_temporal75.binding(');
 needle:='IF created_value<limit_value THEN';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'selector delegation source changed';END IF;
 d:=replace(d,needle,'IF false THEN');
 EXECUTE d;
END $copies$;
CREATE FUNCTION zasp_temporal75.retained_schedule(worker_value text,limit_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $retained$
BEGIN
 PERFORM zasp_temporal70.require_worker();
 IF NOT zasp_temporal75.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='selector ownership catalog unavailable';END IF;
 RETURN zasp_temporal75.retained_body(worker_value,limit_value,expected_checksum,expected_fingerprint);
END $retained$;
CREATE FUNCTION zasp_temporal75.admit(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $admit$
DECLARE r jsonb:=q->'ref';d jsonb;g jsonb;v bigint;result_value jsonb;BEGIN
 PERFORM zasp_temporal75.require_executor();
 IF NOT COALESCE(q?&ARRAY['ref','revision'] AND q-ARRAY['ref','revision']='{}'::jsonb AND jsonb_typeof(q->'revision')='number' AND q->>'revision'~'^[1-9][0-9]{0,6}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='selector request rejected';END IF;
 -- Configuration changes serialize before admission. No transaction crosses a
 -- Temporal RPC; reconciliation uses a different scoped session advisory lock.
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('test-selector75-configuration',0));
 d:=zasp_temporal75.desired(r);
 IF d->'enabled'<>'true'::jsonb OR d->'revision' IS DISTINCT FROM q->'revision' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='selector current configuration rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||(r->>'organization_id'),0));
 SELECT version INTO v FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id)=(r->>'organization_id',r->>'workspace_id',r->>'environment_id',r->>'definition_id') FOR SHARE;
 g:=zasp_temporal74.authorize(r->>'organization_id',r->>'workspace_id',r->>'environment_id',r->>'definition_id',v);
 result_value:=zasp_temporal75.select_body(r->>'organization_id',r->>'workspace_id',r->>'environment_id',r->>'definition_id',g->>'principal_id',25,'01920b296d2ebbc4b84c6e714edaf50d6265d630e577bd26297755a15289fa00','2c324e78917f97feee14f915b397efbb92a183d47afd7473139dd0691cf0bb04');
 PERFORM zasp_temporal74.authorize(r->>'organization_id',r->>'workspace_id',r->>'environment_id',r->>'definition_id',v);
 RETURN result_value;
END $admit$;
DO $fingerprint$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal70.fingerprint()'::regprocedure) INTO d;
 d:=replace(d,'zasp_temporal70','zasp_temporal75');
 d:=replace(d,'-- compatibility70 checksum','-- selector75 checksum');
 d:=replace(d,'-- compatibility70 fingerprint','-- selector75 fingerprint');
 d:=replace(d,'UNION ALL SELECT concat_ws(''|'',''saved''', $tracking$UNION ALL SELECT concat_ws('|','owner-trigger',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_temporal75_owner'
 UNION ALL SELECT concat_ws('|','owner-policy',p.polrelid::regclass::text,p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p WHERE p.polname='zasp_temporal75_owner' AND p.polrelid='public.zasp_security_agent_runs'::regclass
 UNION ALL SELECT concat_ws('|','saved'$tracking$);
 EXECUTE d;
END $fingerprint$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure signature FROM pg_proc WHERE pronamespace='zasp_temporal75'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
GRANT USAGE ON SCHEMA zasp_temporal75 TO zasp_temporal_executor,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal75.ready(text,text) TO zasp_temporal_executor,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal75.desired(jsonb),zasp_temporal75.references(text,integer),zasp_temporal75.admit(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal75.retained_schedule(text,integer,text,text) TO zasp_security_agent_worker;
-- Only this non-mutating RLS predicate needs expression-initialization access.
-- Schema access and every other helper remain private or explicitly scoped.
GRANT EXECUTE ON FUNCTION zasp_temporal75.visible(text,text,text,text) TO PUBLIC;
