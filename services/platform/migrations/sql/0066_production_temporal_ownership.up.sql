-- Staged ownership and admission only. No runtime role can activate a route.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal66 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal66 FROM PUBLIC;
CREATE TABLE zasp_temporal66.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal66.admission_routes(
 organization_id text NOT NULL CHECK(public.zasp_valid_product_id(organization_id)),workspace_id text NOT NULL CHECK(public.zasp_valid_product_id(workspace_id)),environment_id text NOT NULL CHECK(public.zasp_valid_product_id(environment_id)),
 execution_owner text NOT NULL CHECK(execution_owner IN('legacy','temporal')),PRIMARY KEY(organization_id,workspace_id,environment_id));
CREATE TABLE zasp_temporal66.run_owners(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 execution_owner text NOT NULL CHECK(execution_owner IN('legacy','temporal')),definition_version bigint NOT NULL,input_digest text NOT NULL CHECK(input_digest~'^[a-f0-9]{64}$'),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id));
CREATE TABLE zasp_temporal66.retired_authorities(schema_name text PRIMARY KEY CHECK(schema_name IN('zasp_ordered_worker63','zasp_ordered_scheduler64')),original_fingerprint text NOT NULL,retired_fingerprint text NOT NULL);

CREATE FUNCTION zasp_temporal66.immutable() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $immutable$
BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Temporal authority is immutable';END $immutable$;
DO $tables$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['registration','admission_routes','run_owners','retired_authorities'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal66.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal66.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal66.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal66.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal66.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal66.immutable()',n);
 END LOOP;
END $tables$;

-- Retire only obsolete extension entry grants. Their tables, leases, bodies,
-- checksums and evidence remain. Old readiness intentionally becomes false.
DO $retire$ DECLARE n text;before_value text;after_value text;p record; BEGIN
 FOREACH n IN ARRAY ARRAY['zasp_ordered_worker63','zasp_ordered_scheduler64'] LOOP
  IF to_regnamespace(n) IS NULL THEN CONTINUE;END IF;
  IF n='zasp_ordered_worker63' THEN
   IF NOT zasp_ordered_worker63.ready('-- worker63 checksum','-- worker63 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker retirement predecessor rejected';END IF;
   before_value:='-- worker63 fingerprint';
  ELSE
   -- Worker63 has already been retired. Validate64's own immutable catalog
   -- and registration without asking its now-retired predecessor to run.
   IF (SELECT count(*) FROM zasp_ordered_scheduler64.registration)<>1 OR NOT EXISTS(SELECT 1 FROM zasp_ordered_scheduler64.registration WHERE checksum='-- scheduler64 checksum' AND fingerprint='-- scheduler64 fingerprint') OR zasp_ordered_scheduler64.fingerprint()<>'-- scheduler64 fingerprint' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler retirement predecessor rejected';END IF;
   before_value:='-- scheduler64 fingerprint';
  END IF;
  FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace=to_regnamespace(n) LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zasp_security_agent_worker',p.signature);
  END LOOP;
  EXECUTE format('SELECT %I.fingerprint()',n) INTO after_value;
  INSERT INTO zasp_temporal66.retired_authorities VALUES(n,before_value,after_value);
 END LOOP;
END $retire$;

CREATE FUNCTION zasp_temporal66.is_temporal(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $owner$
 SELECT EXISTS(SELECT 1 FROM zasp_temporal66.run_owners WHERE (organization_id,workspace_id,environment_id,run_id,execution_owner)=(o,w,e,r,'temporal'))
$owner$;

-- SECURITY DEFINER keeps current_user at the domain authority. session_user
-- remains the real login, so old worker/action/deployment sessions are hidden.
-- API decisions keep their existing SQL authorization. P3B needs a separate,
-- narrowly bound executor principal; reusing the old worker is not sufficient.
CREATE FUNCTION zasp_temporal66.legacy_visible(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $visible$
 SELECT NOT zasp_temporal66.is_temporal(o,w,e,r) OR public.zasp_security_agent_principal_ready('zasp_security_agent_api')
$visible$;
CREATE POLICY zasp_temporal66_owner ON public.zasp_security_agent_runs AS RESTRICTIVE USING(zasp_temporal66.legacy_visible(organization_id,workspace_id,environment_id,run_id)) WITH CHECK(zasp_temporal66.legacy_visible(organization_id,workspace_id,environment_id,run_id));
CREATE POLICY zasp_temporal66_owner ON public.zasp_security_agent_effects AS RESTRICTIVE USING(zasp_temporal66.legacy_visible(organization_id,workspace_id,environment_id,run_id)) WITH CHECK(zasp_temporal66.legacy_visible(organization_id,workspace_id,environment_id,run_id));

-- Backstop even privileged writes: Temporal ownership never carries old lease
-- authority. Neither a GUC nor a supplied token can bypass this guard.
CREATE FUNCTION zasp_temporal66.lease_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
DECLARE row_value jsonb:=to_jsonb(NEW);BEGIN
 IF zasp_temporal66.is_temporal(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id) AND
  (row_value->>'lease_owner' IS NOT NULL OR row_value->>'lease_token' IS NOT NULL OR row_value->>'lease_expires_at' IS NOT NULL OR row_value->>'state'='leased') THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Temporal run rejects legacy execution authority';
 END IF;
 RETURN NEW;
END $guard$;
CREATE TRIGGER zasp_temporal66_lease BEFORE INSERT OR UPDATE ON public.zasp_security_agent_runs FOR EACH ROW EXECUTE FUNCTION zasp_temporal66.lease_guard();
CREATE TRIGGER zasp_temporal66_lease BEFORE INSERT OR UPDATE ON public.zasp_security_agent_effects FOR EACH ROW EXECUTE FUNCTION zasp_temporal66.lease_guard();

CREATE FUNCTION zasp_temporal66.capture_owner() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $capture$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;owner_value text;existing zasp_temporal66.run_owners%ROWTYPE;
BEGIN
 IF NOT zasp_temporal66.ready('-- owner66 checksum','-- owner66 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Temporal ownership unavailable';END IF;
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id) FOR UPDATE;
 SELECT * INTO existing FROM zasp_temporal66.run_owners WHERE (organization_id,workspace_id,environment_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id);
 IF NEW.kind='start' AND NOT FOUND THEN
  owner_value:='legacy';
  -- Never transfer a historical or already-claimed run. Admission and owner
  -- selection commit together, under the same run lock as legacy claims.
  IF rr.state='queued' AND rr.version=1 AND rr.attempt=0 AND rr.lease_owner IS NULL AND rr.lease_token IS NULL AND rr.lease_expires_at IS NULL AND rr.plan_hash IS NULL
   AND NOT EXISTS(SELECT 1 FROM zasp_temporal65.commands WHERE (organization_id,workspace_id,environment_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id))
   AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id)) THEN
   SELECT execution_owner INTO owner_value FROM zasp_temporal66.admission_routes WHERE (organization_id,workspace_id,environment_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id) FOR SHARE;
  END IF;
  INSERT INTO zasp_temporal66.run_owners VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id,COALESCE(owner_value,'legacy'),NEW.definition_version,NEW.input_digest) RETURNING * INTO existing;
 END IF;
 IF existing.run_id IS NOT NULL AND existing.definition_version<>NEW.definition_version THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Temporal owner version conflict';END IF;
 NEW.execution_owner:=COALESCE(existing.execution_owner,'legacy');
 RETURN NEW;
END $capture$;
CREATE TRIGGER zasp_temporal66_capture BEFORE INSERT ON zasp_temporal65.commands FOR EACH ROW EXECUTE FUNCTION zasp_temporal66.capture_owner();

-- Exact61 already validates the full manual58 function definition. Copy its
-- business body; change only the entry name and registered readiness boundary.
DO $facade$ DECLARE d text;needle text:='public.zasp_sa_export_readiness(expected_checksum,expected_fingerprint)';BEGIN
 d:=pg_get_functiondef('public.zasp_sa_manual_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text)'::regprocedure);
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='manual facade predecessor rejected';END IF;
 d:=replace(d,'FUNCTION public.zasp_sa_manual_run(','FUNCTION zasp_temporal66.manual_run(');
 EXECUTE replace(d,needle,'zasp_temporal66.ready(expected_checksum,expected_fingerprint)');
END $facade$;

DO $read_facades$ DECLARE d text;needle text;BEGIN
 d:=pg_get_functiondef('public.zasp_production_security_agent_existing_tests_run_context(text,text,text,text,text,text)'::regprocedure);
 needle:='public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='read facade predecessor rejected';END IF;
 d:=replace(d,'FUNCTION public.zasp_production_security_agent_existing_tests_run_context(','FUNCTION zasp_temporal66.run_context(');
 EXECUTE replace(d,needle,'zasp_temporal66.ready(expected_checksum,expected_fingerprint)');
 d:=pg_get_functiondef('public.zasp_sa_attack_lab_cancel_parent(text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure);
 needle:='public.zasp_sa_attack_lab_readiness(expected_checksum,expected_fingerprint)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='cancel facade predecessor rejected';END IF;
 d:=replace(d,'FUNCTION public.zasp_sa_attack_lab_cancel_parent(','FUNCTION zasp_temporal66.cancel_parent(');
 EXECUTE replace(d,needle,'zasp_temporal66.ready(expected_checksum,expected_fingerprint)');
END $read_facades$;

CREATE FUNCTION zasp_temporal66.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_temporal66'
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,''),replace(replace(pg_get_functiondef(p.oid),'-- owner66 checksum','<checksum>'),'-- owner66 fingerprint','<fingerprint>')) FROM pg_proc p WHERE p.pronamespace='zasp_temporal66'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.relnamespace='zasp_temporal66'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),'')) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal66'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal66'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal66'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relnamespace::regnamespace::text,c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal66'::regnamespace OR p.polname='zasp_temporal66_owner'
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND (c.relnamespace='zasp_temporal66'::regnamespace OR t.tgname IN('zasp_temporal66_lease','zasp_temporal66_capture'))
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION zasp_temporal66.ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
DECLARE n text;retired zasp_temporal66.retired_authorities%ROWTYPE;actual text;BEGIN
 IF c IS DISTINCT FROM '-- owner66 checksum' OR f IS DISTINCT FROM '-- owner66 fingerprint' OR (SELECT count(*) FROM zasp_temporal66.registration)<>1 OR NOT EXISTS(SELECT 1 FROM zasp_temporal66.registration WHERE checksum=c AND fingerprint=f) OR zasp_temporal66.fingerprint() IS DISTINCT FROM f
  OR NOT zasp_ordered_public62.ready('-- public62 checksum','-- public62 fingerprint') OR NOT zasp_temporal65.ready('-- outbox65 checksum','-- outbox65 fingerprint') THEN RETURN false;END IF;
 FOREACH n IN ARRAY ARRAY['zasp_ordered_worker63','zasp_ordered_scheduler64'] LOOP
  SELECT * INTO retired FROM zasp_temporal66.retired_authorities WHERE schema_name=n;
  IF (to_regnamespace(n) IS NOT NULL) IS DISTINCT FROM FOUND THEN RETURN false;END IF;
  IF NOT FOUND THEN CONTINUE;END IF;
  IF retired.original_fingerprint IS DISTINCT FROM (CASE n WHEN 'zasp_ordered_worker63' THEN '-- worker63 fingerprint' ELSE '-- scheduler64 fingerprint' END) THEN RETURN false;END IF;
  EXECUTE format('SELECT %I.fingerprint()',n) INTO actual;
  IF actual IS DISTINCT FROM retired.retired_fingerprint OR EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace=to_regnamespace(n) AND has_function_privilege('zasp_security_agent_worker',oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END $ready$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal66'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
REVOKE ALL ON ALL TABLES IN SCHEMA zasp_temporal66 FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_temporal66 TO zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal66.ready(text,text) TO zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal66.manual_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal66.run_context(text,text,text,text,text,text),zasp_temporal66.cancel_parent(text,text,text,text,text,text,bigint,text,text,text,text,text) TO zasp_security_agent_api;
