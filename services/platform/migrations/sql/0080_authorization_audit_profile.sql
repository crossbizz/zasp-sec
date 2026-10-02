-- Explicit guarded profile, assembled separately from80 to keep checksums acyclic.
CREATE SCHEMA zasp_authorization80_audit AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_authorization80_audit FROM PUBLIC;
CREATE TABLE zasp_authorization80_audit.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_authorization80_audit.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
INSERT INTO zasp_authorization80_audit.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN(
 'zasp_sa_attack_lab_prior.audit_fingerprint()'::regprocedure,'zasp_sa_attack_lab_prior.budget_fingerprint()'::regprocedure,
 'zasp_sa_attack_lab_prior.run_context_fingerprint()'::regprocedure,'zasp_sa_attack_lab_prior.existing_tests_fingerprint()'::regprocedure,
 'zasp_sa_attack_lab_prior.compliance_fingerprint()'::regprocedure,'public.zasp_sa_attack_lab_live_fingerprint()'::regprocedure);
CREATE FUNCTION zasp_authorization80_audit.immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='audit profile immutable';END $$;
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions'] LOOP
  EXECUTE format('ALTER TABLE zasp_authorization80_audit.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_audit.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_audit.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_authorization80_audit.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_audit.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80_audit.immutable()',n);
 END LOOP;
END $tables$;

-- The trigger observes the actual native writer, never request labels or GUCs.
CREATE FUNCTION zasp_authorization80_audit.write_guard() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_NARGS<>1 OR TG_LEVEL<>'STATEMENT' OR TG_WHEN<>'BEFORE' OR TG_RELID<>'public.zasp_admin_audit'::regclass THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='audit writer contract rejected';
 END IF;
 IF current_user=TG_ARGV[0] AND EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
  JOIN public.zasp_discovery_principal_bindings b ON b.principal_name=r.rolname AND b.authority_role='zasp_discovery_authority'
  WHERE c.oid=TG_RELID AND r.rolname=TG_ARGV[0] AND r.rolcanlogin) THEN RETURN NULL;END IF;
 IF current_user='zasp_discovery_authority' AND TG_OP='INSERT' AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND NOT(rolcanlogin OR rolsuper OR rolbypassrls)) THEN RETURN NULL;END IF;
 RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked audit writer required';
END $$;
CREATE FUNCTION zasp_authorization80_audit.guard_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE((SELECT count(*)=1 AND bool_and(
  c.relowner=b.principal_name::regrole AND r.rolcanlogin AND c.relkind='r' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
  AND t.tgenabled='O' AND t.tgtype=62 AND NOT t.tgisinternal AND NOT t.tgdeferrable AND NOT t.tginitdeferred
  AND t.tgconstraint=0 AND t.tgconstrrelid=0 AND t.tgconstrindid=0 AND t.tgnargs=1 AND t.tgattr=''::int2vector AND t.tgqual IS NULL AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
  AND t.tgfoid='zasp_authorization80_audit.write_guard()'::regprocedure AND t.tgargs=convert_to(b.principal_name,'UTF8')||decode('00','hex'))
  FROM pg_class c JOIN pg_trigger t ON t.tgrelid=c.oid AND t.tgname='zasp_authorization80_audit_write_guard'
  JOIN public.zasp_discovery_principal_bindings b ON b.authority_role='zasp_discovery_authority'
  JOIN pg_roles r ON r.rolname=b.principal_name WHERE c.oid='public.zasp_admin_audit'::regclass)
 AND EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='zasp_authorization80_audit.write_guard()'::regprocedure AND p.proowner='zasp_discovery_authority'::regrole AND NOT p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}')
 AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_discovery_authority' AND NOT(rolcanlogin OR rolsuper OR rolbypassrls))
 AND public.zasp_audit_export_source_acl_ready(),false)
$$;

-- Preserve every retained query. Only the new exact validated trigger and the
-- public57 self-definition are projected; original five private functions stay live.
DO $projection$ DECLARE n text;d text;needle text;previous text;BEGIN
 IF(SELECT count(*) FROM zasp_authorization80_audit.predecessor_functions)<>6 OR EXISTS(SELECT 1 FROM zasp_authorization80_audit.predecessor_functions WHERE owner_name<>'zasp_discovery_authority') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit predecessor identity rejected';END IF;
 FOREACH n IN ARRAY ARRAY['audit_fingerprint','budget_fingerprint','run_context_fingerprint','existing_tests_fingerprint','compliance_fingerprint'] LOOP
  SELECT definition INTO STRICT d FROM zasp_authorization80_audit.predecessor_functions WHERE signature='zasp_sa_attack_lab_prior.'||n||'()';
  d:=replace(d,'FUNCTION zasp_sa_attack_lab_prior.'||n||'()', 'FUNCTION zasp_authorization80_audit.'||n||'()');
  IF n='audit_fingerprint' THEN
   needle:='AND NOT t.tgisinternal';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit trigger query shape rejected';END IF;
   d:=replace(d,needle,needle||$exclude$ AND NOT(t.tgrelid='public.zasp_admin_audit'::regclass AND t.tgname='zasp_authorization80_audit_write_guard' AND t.tgfoid='zasp_authorization80_audit.write_guard()'::regprocedure AND zasp_authorization80_audit.guard_ready())$exclude$);
  ELSE
   needle:='zasp_sa_attack_lab_prior.'||previous||'()';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit ancestor query shape rejected';END IF;
   d:=replace(d,needle,'zasp_authorization80_audit.'||previous||'()');
  END IF;
  EXECUTE d;previous:=n;
 END LOOP;
 SELECT definition INTO STRICT d FROM zasp_authorization80_audit.predecessor_functions WHERE signature='zasp_sa_attack_lab_live_fingerprint()';
 d:=replace(d,'FUNCTION public.zasp_sa_attack_lab_live_fingerprint()', 'FUNCTION zasp_authorization80_audit.projected57()');
 needle:='zasp_sa_attack_lab_prior.compliance_fingerprint()';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit57 ancestor rejected';END IF;
 d:=replace(d,needle,'zasp_authorization80_audit.compliance_fingerprint()');
 needle:='public.zasp_sa_attack_lab_function_identity(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit57 self identity rejected';END IF;
 d:=replace(d,needle,$self$CASE WHEN p.oid='public.zasp_sa_attack_lab_live_fingerprint()'::regprocedure THEN(SELECT replace(replace(definition,'-- audit57 checksum','<compiled-checksum>'),'-- audit57 fingerprint','<compiled-fingerprint>') FROM zasp_authorization80_audit.predecessor_functions WHERE signature='zasp_sa_attack_lab_live_fingerprint()') ELSE public.zasp_sa_attack_lab_function_identity(p.oid) END$self$);
 EXECUTE d;
END $projection$;
DO $guard_install$ DECLARE owner_name text;BEGIN
 SELECT b.principal_name INTO STRICT owner_name FROM public.zasp_discovery_principal_bindings b JOIN pg_class c ON c.oid='public.zasp_admin_audit'::regclass AND c.relowner=b.principal_name::regrole JOIN pg_roles r ON r.rolname=b.principal_name AND r.rolcanlogin WHERE b.authority_role='zasp_discovery_authority';
 IF owner_name IS DISTINCT FROM current_user OR NOT public.zasp_audit_export_source_acl_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit source owner rejected';END IF;
 EXECUTE format('CREATE TRIGGER zasp_authorization80_audit_write_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.zasp_admin_audit FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80_audit.write_guard(%L)',owner_name);
END $guard_install$;

CREATE FUNCTION zasp_authorization80_audit.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS(
 SELECT concat_ws('|','schema',nspowner::regrole::text,nspacl::text) FROM pg_namespace WHERE nspname='zasp_authorization80_audit'
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner::regrole::text,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_audit'::regnamespace OR p.oid IN(SELECT to_regprocedure(signature) FROM zasp_authorization80_audit.predecessor_functions)
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_audit'::regnamespace OR c.oid='public.zasp_admin_audit'::regclass
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,a.attcollation::regcollation::text,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE(c.relnamespace='zasp_authorization80_audit'::regnamespace OR c.oid='public.zasp_admin_audit'::regclass) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80_audit'::regnamespace OR c.oid='public.zasp_admin_audit'::regclass
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_authorization80_audit'::regnamespace OR c.oid='public.zasp_admin_audit'::regclass
 UNION ALL SELECT concat_ws('|','policy',p.polrelid::regclass::text,p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80_audit'::regnamespace OR c.oid='public.zasp_admin_audit'::regclass
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid),t.tgfoid::regprocedure::text) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND(c.relnamespace='zasp_authorization80_audit'::regnamespace OR c.oid='public.zasp_admin_audit'::regclass)
 UNION ALL SELECT concat_ws('|','saved',signature,definition,owner_name,acl) FROM zasp_authorization80_audit.predecessor_functions
 ) SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_authorization80_audit.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE((SELECT count(*)=1 FROM zasp_authorization80_audit.registration)
 AND EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE checksum='-- audit profile checksum' AND fingerprint=zasp_authorization80_audit.fingerprint())
 AND EXISTS(SELECT 1 FROM zasp_authorization80.registration WHERE checksum='-- audit80 checksum' AND fingerprint=zasp_authorization80.fingerprint())
 AND(SELECT count(*)=1 AND bool_and(singleton AND audit_mode='source52-canonical61-audit-v1') FROM zasp_authorization80.runtime_profile)
 AND zasp_authorization80_audit.guard_ready()
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=52 AND checksum='-- audit52 checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_audit_exports_fingerprint' AND value='-- audit52 fingerprint')
 AND(SELECT count(*)=6 FROM zasp_authorization80_audit.predecessor_functions)
 AND NOT EXISTS(SELECT 1 FROM zasp_authorization80_audit.predecessor_functions s LEFT JOIN pg_proc p ON p.oid=to_regprocedure(s.signature) WHERE s.signature<>'zasp_sa_attack_lab_live_fingerprint()' AND(p.oid IS NULL OR pg_get_functiondef(p.oid)<>s.definition OR p.proowner::regrole::text<>s.owner_name OR COALESCE(p.proacl::text,'')<>s.acl)),false)
$$;
DO $owners$ DECLARE p regprocedure;BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_authorization80_audit'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p);
 END LOOP;
END $owners$;

-- Production requires the guarded composed profile. API callers receive only
-- this boolean contract, never private registration/table access.
CREATE FUNCTION zasp_authorization80_audit.production_ready(expected80 text,expected_audit text,key_version text,api_authority text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE composed_ready boolean;
BEGIN
 IF expected80 IS DISTINCT FROM '-- audit80 checksum' OR expected_audit IS DISTINCT FROM '-- audit profile checksum'
 OR NOT COALESCE(key_version~'^[a-f0-9]{64}$',false)
 OR NOT COALESCE(api_authority IN('zasp_discovery_api','zasp_security_agent_api'),false)
 THEN RETURN false;END IF;
 IF api_authority='zasp_discovery_api' THEN
  IF NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api'),false) THEN RETURN false;END IF;
 ELSE
  IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RETURN false;END IF;
 END IF;
 IF NOT COALESCE((SELECT count(*)=1 AND bool_and(singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode='source52-canonical61-audit-v1') FROM zasp_authorization80.runtime_profile),false)
 OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE checksum=expected_audit)
 OR NOT zasp_authorization80_audit.catalog_ready()
 OR to_regprocedure('zasp_authorization80_temporal.ready()') IS NULL
 THEN RETURN false;END IF;
 EXECUTE 'SELECT zasp_authorization80_temporal.ready()' INTO composed_ready;
 RETURN COALESCE(composed_ready AND zasp_authorization80.key_ready(key_version),false);
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
ALTER FUNCTION zasp_authorization80_audit.production_ready(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80_audit.production_ready(text,text,text,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_authorization80_audit TO zasp_discovery_api,zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_authorization80_audit.production_ready(text,text,text,text) TO zasp_discovery_api,zasp_security_agent_api;

-- audit profile activate
CREATE OR REPLACE FUNCTION public.zasp_sa_attack_lab_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $$
 SELECT CASE WHEN zasp_authorization80_audit.catalog_ready() THEN zasp_authorization80_audit.projected57() ELSE NULL END
$$;
