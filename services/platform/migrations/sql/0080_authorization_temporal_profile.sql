-- Explicit composed profile. Base79/80 and historical Temporal pins stay intact.
CREATE SCHEMA zasp_authorization80_temporal AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_authorization80_temporal FROM PUBLIC;
CREATE TABLE zasp_authorization80_temporal.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL,profile_name text NOT NULL DEFAULT 'canonical61-temporal78-authorization79-80-v1' CHECK(profile_name='canonical61-temporal78-authorization79-80-v1'));
CREATE TABLE zasp_authorization80_temporal.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
INSERT INTO zasp_authorization80_temporal.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal72.domain_catalog()'::regprocedure,'zasp_temporal72.fingerprint()'::regprocedure,'zasp_temporal68.ready(text,text)'::regprocedure,'zasp_temporal68.fingerprint()'::regprocedure);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions'] LOOP
  EXECUTE format('ALTER TABLE zasp_authorization80_temporal.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_temporal.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_temporal.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_authorization80_temporal.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_temporal.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;

-- The only two installation shapes. Runtime guard always requests final=true.
CREATE FUNCTION zasp_authorization80_temporal.triggers_ready(final boolean) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $triggers$
 WITH expected(relation_name,columns_value) AS(VALUES
 ('zasp_integrations','organization_id,workspace_id,environment_id,id,state,deleted_at'),
 ('zasp_integration_connections','organization_id,workspace_id,environment_id,integration_id,state,verified_at,revoked_at'),
 ('zasp_discovery_syncs','organization_id,workspace_id,environment_id,id,integration_id,principal_id,trigger_kind,state'),
 ('zasp_inventory_entities',CASE WHEN final THEN 'organization_id,workspace_id,environment_id,product_kind,id,state' ELSE 'organization_id,workspace_id,environment_id,kind,id,state' END))
 SELECT COALESCE((SELECT count(*)=4 AND bool_and(
  t.tgenabled='O' AND t.tgtype=31 AND NOT t.tgisinternal AND NOT t.tgdeferrable AND NOT t.tginitdeferred
  AND t.tgconstraint=0 AND t.tgconstrrelid=0 AND t.tgconstrindid=0 AND t.tgnargs=2 AND t.tgattr=''::int2vector AND t.tgqual IS NULL AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
  AND t.tgfoid='zasp_authorization79.capture()'::regprocedure
  AND t.tgargs=convert_to('organization_id','UTF8')||decode('00','hex')||convert_to(x.columns_value,'UTF8')||decode('00','hex'))
  FROM expected x JOIN pg_class c ON c.relnamespace='public'::regnamespace AND c.relname=x.relation_name JOIN pg_trigger t ON t.tgrelid=c.oid AND t.tgname='zasp_authorization79_capture')
 AND EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='zasp_authorization79.capture()'::regprocedure
  AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}'),false)
$triggers$;

-- Clone full retained queries, with exact-count substitutions. Domain function
-- itself remains untouched. No other trigger/table/ACL/category is projected.
DO $projection$ DECLARE d text;needle text;BEGIN
 IF (SELECT count(*) FROM zasp_authorization80_temporal.predecessor_functions)<>4 OR EXISTS(SELECT 1 FROM zasp_authorization80_temporal.predecessor_functions WHERE owner_name<>'zasp_discovery_authority') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='composed predecessor identity rejected';END IF;
 SELECT definition INTO STRICT d FROM zasp_authorization80_temporal.predecessor_functions WHERE signature='zasp_temporal68.fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal68.fingerprint()', 'FUNCTION zasp_authorization80_temporal.projected68()');
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='composed68 fingerprint source rejected';END IF;
 d:=replace(d,needle,$self68$CASE WHEN p.oid IN('zasp_temporal68.ready(text,text)'::regprocedure,'zasp_temporal68.fingerprint()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_temporal.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$self68$);
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_authorization80_temporal.predecessor_functions WHERE signature='zasp_temporal72.domain_catalog()';
 d:=replace(d,'FUNCTION zasp_temporal72.domain_catalog()', 'FUNCTION zasp_authorization80_temporal.projected_domain()');
 needle:='WHERE NOT t.tgisinternal';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='composed domain source rejected';END IF;
 d:=replace(d,needle,needle||$exclude$ AND NOT(t.tgname='zasp_authorization79_capture' AND t.tgrelid IN('public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_syncs'::regclass,'public.zasp_inventory_entities'::regclass))$exclude$);
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_authorization80_temporal.predecessor_functions WHERE signature='zasp_temporal72.fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal72.fingerprint()', 'FUNCTION zasp_authorization80_temporal.projected72()');
 needle:='zasp_temporal72.domain_catalog()';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='composed domain fingerprint source rejected';END IF;
 d:=replace(d,needle,'zasp_authorization80_temporal.projected_domain()');
 needle:='pg_get_functiondef(p.oid)';
 --72 hashes its own function row plus precision and bulk handoffs. Project its
 -- self row only; every handoff expression still evaluates live definitions.
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>3 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='composed self fingerprint source rejected';END IF;
 d:=replace(d,needle,$self$CASE WHEN p.oid='zasp_temporal72.fingerprint()'::regprocedure THEN(SELECT definition FROM zasp_authorization80_temporal.predecessor_functions WHERE signature='zasp_temporal72.fingerprint()') ELSE pg_get_functiondef(p.oid) END$self$);
 EXECUTE d;
END $projection$;
DO $bootstrap_owners$ DECLARE p regprocedure;BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_authorization80_temporal'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p);
 END LOOP;
END $bootstrap_owners$;

-- profile catalogs
CREATE FUNCTION zasp_authorization80_temporal.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fingerprint$
 WITH facts(v) AS(
 SELECT concat_ws('|','schema',nspowner::regrole::text,nspacl::text) FROM pg_namespace WHERE nspname='zasp_authorization80_temporal'
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner::regrole::text,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_temporal'::regnamespace OR p.oid IN('zasp_temporal72.fingerprint()'::regprocedure,'zasp_temporal72.domain_catalog()'::regprocedure,'zasp_temporal68.ready(text,text)'::regprocedure,'zasp_temporal68.fingerprint()'::regprocedure,'zasp_authorization79.capture()'::regprocedure)
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',p.polrelid::regclass::text,p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND(c.relnamespace='zasp_authorization80_temporal'::regnamespace OR t.tgname='zasp_authorization79_capture' AND t.tgrelid IN('public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_syncs'::regclass,'public.zasp_inventory_entities'::regclass))
 UNION ALL SELECT concat_ws('|','saved',signature,definition,owner_name,acl) FROM zasp_authorization80_temporal.predecessor_functions
 ) SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$fingerprint$;

CREATE FUNCTION zasp_authorization80_temporal.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $catalog$
 SELECT COALESCE((SELECT count(*)=1 FROM zasp_authorization80_temporal.registration)
 AND EXISTS(SELECT 1 FROM zasp_authorization80_temporal.registration WHERE checksum='-- profile checksum' AND fingerprint=zasp_authorization80_temporal.fingerprint())
 AND zasp_authorization79.ready('-- profile79 checksum')
 AND EXISTS(SELECT 1 FROM zasp_authorization80.registration WHERE checksum='-- profile80 checksum' AND fingerprint=zasp_authorization80.fingerprint())
 AND(SELECT count(*)=1 AND bool_and(singleton AND name='canonical61-temporal78-authorization79-80-v1') FROM zasp_authorization80.runtime_profile)
 AND zasp_authorization80.runtime_audit_ready()
 AND zasp_authorization80_temporal.triggers_ready(true),false)
$catalog$;
CREATE FUNCTION zasp_authorization80_temporal.ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ready$
 SELECT zasp_authorization80_temporal.catalog_ready()
 AND zasp_temporal78.ready('-- profile78 checksum','-- profile78 fingerprint')
 AND zasp_authorization80.ready('-- profile80 checksum')
$ready$;
DO $owners$ DECLARE p regprocedure;BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_authorization80_temporal'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p);
 END LOOP;
END $owners$;

-- profile activate
-- Admission is independent of both projected fingerprint outputs. The original
--68 predicate is preserved in full and its source is pinned by this profile.
DO $admission$ DECLARE d text;needle text:='SELECT COALESCE(';BEGIN
 SELECT definition INTO STRICT d FROM zasp_authorization80_temporal.predecessor_functions WHERE signature='zasp_temporal68.ready(text,text)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='composed68 readiness source rejected';END IF;
 EXECUTE replace(d,needle,needle||'zasp_authorization80_temporal.catalog_ready() AND ');
END $admission$;
CREATE OR REPLACE FUNCTION zasp_temporal68.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 SELECT zasp_authorization80_temporal.projected68()
$fingerprint$;
CREATE OR REPLACE FUNCTION zasp_temporal72.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_authorization80_temporal.catalog_ready() THEN zasp_authorization80_temporal.projected72() ELSE NULL END
$fingerprint$;
