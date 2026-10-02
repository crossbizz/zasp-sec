CREATE TABLE zasp_temporal67.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL,predecessor text NOT NULL CHECK(predecessor IN('clean60','registered61','registered66')),outbox_predecessor text NOT NULL CHECK(outbox_predecessor IN('legacy60','ordered62')));
CREATE TABLE zasp_temporal67.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
CREATE FUNCTION zasp_temporal67.immutable() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $immutable$
BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Temporal domain authority is immutable';END $immutable$;
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal67.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal67.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal67.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal67.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal67.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;

-- Runner checked the full exact62/65/66 catalogs before this change. Retain
-- original definitions and ACLs; the compiled67 fingerprint binds this data.
INSERT INTO zasp_temporal67.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_ordered_public62.ready(text,text)'::regprocedure,'zasp_temporal65.ready(text,text)'::regprocedure,'zasp_temporal66.ready(text,text)'::regprocedure,'zasp_ordered_public62.mutate(text,text,jsonb)'::regprocedure);

CREATE FUNCTION zasp_temporal67.current_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $current$
BEGIN RETURN zasp_temporal67.ready('-- domain67 checksum','-- domain67 fingerprint');END
$current$;

-- Existing wire identities remain valid only through this registered cutover.
-- They cannot authorize a drifted catalog: each calls the full67 boundary.
CREATE OR REPLACE FUNCTION zasp_ordered_public62.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- public62 checksum' AND f='-- public62 fingerprint' AND zasp_temporal67.current_ready(),false)
$ready$;
CREATE OR REPLACE FUNCTION zasp_temporal65.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- outbox65 checksum' AND f='-- outbox65 fingerprint' AND zasp_temporal67.current_ready(),false)
$ready$;
CREATE OR REPLACE FUNCTION zasp_temporal66.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- owner66 checksum' AND f='-- owner66 fingerprint' AND zasp_temporal67.current_ready(),false)
$ready$;

CREATE FUNCTION zasp_temporal67.decision_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- release61 checksum' AND f='-- release61 fingerprint' AND zasp_temporal67.current_ready(),false)
$ready$;
DO $decisions$ DECLARE d text;BEGIN
 d:=pg_get_functiondef('zasp_sa_multistep_prior.transition(text,text,jsonb)'::regprocedure);
 d:=replace(d,'FUNCTION zasp_sa_multistep_prior.transition(', 'FUNCTION zasp_temporal67.api_transition(');
 EXECUTE replace(d,'public.zasp_sa_multistep_readiness(', 'zasp_temporal67.decision_ready(');
 d:=pg_get_functiondef('zasp_ordered_public62.mutate(text,text,jsonb)'::regprocedure);
 EXECUTE replace(d,'zasp_sa_multistep_prior.transition(', 'zasp_temporal67.api_transition(');
END $decisions$;

CREATE FUNCTION zasp_temporal67.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_temporal67'
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,''),replace(replace(replace(pg_get_functiondef(p.oid),'-- domain67 checksum','<checksum>'),'-- domain67 fingerprint','<fingerprint>'),'-- domain67 base fingerprint','<base-fingerprint>')) FROM pg_proc p WHERE p.pronamespace='zasp_temporal67'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.relnamespace='zasp_temporal67'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal67'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal67'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal67'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal67'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal67'::regnamespace
 UNION ALL SELECT concat_ws('|','saved',signature,definition,owner_name,acl) FROM zasp_temporal67.predecessor_functions
 UNION ALL SELECT 'public62|'||zasp_ordered_public62.fingerprint()
 UNION ALL SELECT 'outbox65|'||zasp_temporal65.fingerprint()
 UNION ALL SELECT 'owner66|'||zasp_temporal66.fingerprint()
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION zasp_temporal67.ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
DECLARE n text;retired zasp_temporal66.retired_authorities%ROWTYPE;actual text;BEGIN
 IF c IS DISTINCT FROM '-- domain67 checksum' OR f IS DISTINCT FROM '-- domain67 fingerprint'
  OR (SELECT count(*) FROM zasp_temporal67.registration)<>1 OR NOT EXISTS(SELECT 1 FROM zasp_temporal67.registration WHERE checksum=c AND fingerprint=f)
  OR NOT zasp_temporal67.base_ready() OR zasp_temporal67.fingerprint() IS DISTINCT FROM f
  OR (SELECT count(*) FROM zasp_ordered_public62.registration)<>1 OR NOT EXISTS(SELECT 1 FROM zasp_ordered_public62.registration WHERE checksum='-- public62 checksum' AND fingerprint='-- public62 fingerprint')
  OR (SELECT count(*) FROM zasp_temporal65.registration)<>1 OR NOT EXISTS(SELECT 1 FROM zasp_temporal65.registration x JOIN zasp_temporal67.registration y ON x.predecessor=y.outbox_predecessor WHERE x.checksum='-- outbox65 checksum' AND x.fingerprint='-- outbox65 fingerprint')
  OR (SELECT count(*) FROM zasp_temporal66.registration)<>1 OR NOT EXISTS(SELECT 1 FROM zasp_temporal66.registration WHERE checksum='-- owner66 checksum' AND fingerprint='-- owner66 fingerprint') THEN RETURN false;END IF;
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
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal67'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
REVOKE ALL ON ALL TABLES IN SCHEMA zasp_temporal67 FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_temporal67 TO zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal67.ready(text,text) TO zasp_security_agent_api,zasp_security_agent_worker;
