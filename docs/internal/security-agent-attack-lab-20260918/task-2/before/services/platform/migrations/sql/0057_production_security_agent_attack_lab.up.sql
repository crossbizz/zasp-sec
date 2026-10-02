DO $guard$
BEGIN
 IF NOT public.zasp_compliance_readiness('-- attack lab predecessor checksum','-- attack lab predecessor fingerprint') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab predecessor unavailable';
 END IF;
END $guard$;
CREATE SCHEMA zasp_sa_attack_lab_prior AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_sa_attack_lab_prior FROM PUBLIC;

-- Exact original definitions/owners/ACLs are restored only on unused rollback.
CREATE TABLE zasp_sa_attack_lab_prior.functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl jsonb NOT NULL);
ALTER TABLE zasp_sa_attack_lab_prior.functions OWNER TO zasp_discovery_authority;
REVOKE ALL ON zasp_sa_attack_lab_prior.functions FROM PUBLIC;
CREATE FUNCTION public.zasp_sa_attack_lab_save(signature_value text) RETURNS void LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $save$
DECLARE p pg_proc%ROWTYPE;
BEGIN
 SELECT * INTO STRICT p FROM pg_proc WHERE oid=('public.'||signature_value)::regprocedure;
 INSERT INTO zasp_sa_attack_lab_prior.functions SELECT signature_value,pg_get_functiondef(p.oid),p.proowner::regrole::text,
  COALESCE((SELECT jsonb_agg(jsonb_build_object('grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'grantable',a.is_grantable) ORDER BY a.ordinality) FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) WITH ORDINALITY a WHERE a.privilege_type='EXECUTE'),'[]');
END $save$;
REVOKE ALL ON FUNCTION public.zasp_sa_attack_lab_save(text) FROM PUBLIC;

DO $compatibility$
DECLARE signature_value text;definition_value text;name_value text;needle text;occurrences integer;
BEGIN
 FOREACH signature_value IN ARRAY ARRAY[
 'zasp_compliance_readiness(text,text)',
 'zasp_production_security_agent_existing_tests_readiness(text,text)',
 'zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',
 'zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)',
 'zasp_production_security_agent_attack_path_security_ready()',
 'zasp_production_workflow_compatibility_security_ready()'] LOOP
  PERFORM public.zasp_sa_attack_lab_save(signature_value);
  definition_value:=pg_get_functiondef(('public.'||signature_value)::regprocedure);
  name_value:=split_part(signature_value,'(',1);
  IF name_value IN('zasp_compliance_readiness','zasp_production_security_agent_existing_tests_readiness') THEN
   IF strpos(definition_value,'count(*)=56')=0 OR strpos(definition_value,'version>56')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab predecessor rejected';END IF;
   definition_value:=replace(replace(definition_value,'count(*)=56','count(*)=57'),'version>56','version>57');
   IF name_value='zasp_compliance_readiness' THEN
    EXECUTE replace(replace(definition_value,'FUNCTION public.zasp_compliance_readiness(','FUNCTION zasp_sa_attack_lab_prior.predecessor_ready('),'public.zasp_compliance_live_fingerprint()=expected_fingerprint','true');
    ALTER FUNCTION zasp_sa_attack_lab_prior.predecessor_ready(text,text) OWNER TO zasp_discovery_authority;
    REVOKE ALL ON FUNCTION zasp_sa_attack_lab_prior.predecessor_ready(text,text) FROM PUBLIC;
    definition_value:=replace(definition_value,'public.zasp_compliance_live_fingerprint()=expected_fingerprint','public.zasp_sa_attack_lab_guard()');
   END IF;
  ELSE
   occurrences:=0;
   FOREACH needle IN ARRAY ARRAY['later_release."version" > 56','later."version">56','later."version" > 56'] LOOP
    occurrences:=occurrences+(length(definition_value)-length(replace(definition_value,needle,'')))/length(needle);
    definition_value:=replace(definition_value,needle,replace(needle,'56','57'));
   END LOOP;
   IF occurrences<>(CASE WHEN name_value IN('zasp_workflow_mutate','zasp_risk_mutate') THEN 1 ELSE 3 END) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab compatibility rejected';END IF;
  END IF;
  PERFORM set_config('check_function_bodies','off',true);
  EXECUTE definition_value;
 END LOOP;
 PERFORM set_config('check_function_bodies','on',true);
END $compatibility$;

-- The old embedded releases are untouched. Clone their fingerprint ancestry
-- excluding only this release's two additional metadata entries.
DO $ancestry$
DECLARE definition_value text;name_value text;signature_value text;
BEGIN
 FOREACH name_value IN ARRAY ARRAY['audit_fingerprint','budget_fingerprint','run_context_fingerprint','existing_tests_fingerprint'] LOOP
  definition_value:=pg_get_functiondef(('zasp_compliance_predecessor.'||name_value||'()')::regprocedure);
  definition_value:=replace(definition_value,'zasp_compliance_predecessor.','zasp_sa_attack_lab_prior.');
  IF name_value='audit_fingerprint' THEN
   IF strpos(definition_value,'''production_compliance_checksum'',''production_compliance_fingerprint''')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab ancestry rejected';END IF;
   definition_value:=replace(definition_value,'''production_compliance_checksum'',''production_compliance_fingerprint''','''production_compliance_checksum'',''production_compliance_fingerprint'',''production_security_agent_attack_lab_checksum'',''production_security_agent_attack_lab_fingerprint''');
  END IF;
  EXECUTE definition_value;
  EXECUTE format('ALTER FUNCTION zasp_sa_attack_lab_prior.%I() OWNER TO zasp_discovery_authority',name_value);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_sa_attack_lab_prior.%I() FROM PUBLIC',name_value);
 END LOOP;
 definition_value:=pg_get_functiondef('public.zasp_compliance_live_fingerprint()'::regprocedure);
 definition_value:=replace(definition_value,'FUNCTION public.zasp_compliance_live_fingerprint(','FUNCTION zasp_sa_attack_lab_prior.compliance_fingerprint(');
 definition_value:=replace(definition_value,'zasp_compliance_predecessor.existing_tests_fingerprint()','zasp_sa_attack_lab_prior.existing_tests_fingerprint()');
 EXECUTE definition_value;
 ALTER FUNCTION zasp_sa_attack_lab_prior.compliance_fingerprint() OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_sa_attack_lab_prior.compliance_fingerprint() FROM PUBLIC;
END $ancestry$;

-- attack lab admission fragment
-- attack lab definition fragment
-- attack lab planner fragment
-- attack lab links fragment

CREATE ROLE zasp_security_agent_attack_lab_reconciler NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT zasp_security_agent_attack_lab_reconciler TO zasp_discovery_authority WITH ADMIN OPTION;
CREATE TABLE public.zasp_sa_attack_lab_principals(principal_name text PRIMARY KEY CHECK(principal_name ~ '^[a-z][a-z0-9_]{2,62}$' AND NOT starts_with(principal_name,'zasp_')),authority_role text NOT NULL UNIQUE CHECK(authority_role='zasp_security_agent_attack_lab_reconciler'));
ALTER TABLE public.zasp_sa_attack_lab_principals OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_sa_attack_lab_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_sa_attack_lab_principals FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_sa_attack_lab_principals_authority ON public.zasp_sa_attack_lab_principals TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_sa_attack_lab_principals FROM PUBLIC;
CREATE FUNCTION public.zasp_sa_attack_lab_role_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $roles$
 SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_security_agent_attack_lab_reconciler' AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolconfig IS NULL)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_sa_attack_lab_principals b LEFT JOIN pg_roles r ON r.rolname=b.principal_name WHERE r.oid IS NULL OR NOT r.rolcanlogin OR NOT r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR NOT pg_has_role(r.oid,b.authority_role,'MEMBER') OR EXISTS(SELECT 1 FROM pg_roles a WHERE starts_with(a.rolname,'zasp_') AND a.oid<>r.oid AND a.rolname<>b.authority_role AND pg_has_role(r.oid,a.oid,'MEMBER')))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname='zasp_security_agent_attack_lab_reconciler')
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.roleid JOIN pg_roles p ON p.oid=m.member WHERE a.rolname='zasp_security_agent_attack_lab_reconciler' AND NOT(p.rolname='zasp_discovery_authority' AND m.admin_option OR EXISTS(SELECT 1 FROM public.zasp_sa_attack_lab_principals b WHERE b.principal_name=p.rolname AND b.authority_role=a.rolname AND NOT m.admin_option AND m.inherit_option AND NOT m.set_option)))
 AND EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.roleid JOIN pg_roles p ON p.oid=m.member WHERE a.rolname='zasp_security_agent_attack_lab_reconciler' AND p.rolname='zasp_discovery_authority' AND m.admin_option)
$roles$;
CREATE FUNCTION public.zasp_sa_attack_lab_register_reconciler(principal_value text,expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $register$
DECLARE r pg_roles%ROWTYPE;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') OR NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='attack lab registration rejected';END IF;
 IF NOT COALESCE(principal_value ~ '^[a-z][a-z0-9_]{2,62}$' AND NOT starts_with(principal_value,'zasp_'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='attack lab principal rejected';END IF;
 LOCK TABLE public.zasp_sa_attack_lab_principals IN EXCLUSIVE MODE;
 IF NOT public.zasp_sa_attack_lab_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab release unavailable';END IF;
 SELECT * INTO r FROM pg_roles WHERE rolname=principal_value;
 IF NOT FOUND OR NOT r.rolcanlogin OR NOT r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolconfig IS NOT NULL OR EXISTS(SELECT 1 FROM pg_roles a WHERE starts_with(a.rolname,'zasp_') AND a.oid<>r.oid AND a.rolname<>'zasp_security_agent_attack_lab_reconciler' AND pg_has_role(r.oid,a.oid,'MEMBER')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='attack lab principal rejected';END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_sa_attack_lab_principals WHERE principal_name<>principal_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='attack lab principal already registered';END IF;
 EXECUTE format('GRANT zasp_security_agent_attack_lab_reconciler TO %I WITH INHERIT TRUE, SET FALSE',principal_value);
 INSERT INTO public.zasp_sa_attack_lab_principals VALUES(principal_value,'zasp_security_agent_attack_lab_reconciler') ON CONFLICT DO NOTHING;
 IF NOT public.zasp_sa_attack_lab_role_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='attack lab role unavailable';END IF;
 RETURN true;
END $register$;

CREATE FUNCTION public.zasp_sa_attack_lab_function_identity(value oid) RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $identity$
 SELECT replace(replace(pg_get_functiondef(value),'-- compiled attack lab checksum','<compiled-checksum>'),'-- compiled attack lab fingerprint','<compiled-fingerprint>')
$identity$;
CREATE FUNCTION public.zasp_sa_attack_lab_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_sa_attack_lab_prior.compliance_fingerprint())
 UNION ALL SELECT concat_ws('|','saved',signature,definition,owner_name,acl::text) FROM zasp_sa_attack_lab_prior.functions
 UNION ALL SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_sa_attack_lab_prior'
 UNION ALL SELECT concat_ws('|','saved-table',c.relowner::regrole::text,COALESCE(c.relacl::text,''),c.relrowsecurity,c.relforcerowsecurity,
 (SELECT string_agg(concat_ws(':',a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),'')),',' ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT string_agg(k.conname||':'||pg_get_constraintdef(k.oid),',' ORDER BY k.conname) FROM pg_constraint k WHERE k.conrelid=c.oid)) FROM pg_class c WHERE c.oid='zasp_sa_attack_lab_prior.functions'::regclass
 UNION ALL SELECT concat_ws('|','function',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),public.zasp_sa_attack_lab_function_identity(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_sa_attack_lab_prior' OR n.nspname='public' AND starts_with(p.proname,'zasp_sa_attack_lab_')
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_sa_attack_lab_') AND c.relkind='r'
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE n.nspname='public' AND starts_with(c.relname,'zasp_sa_attack_lab_') AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid)) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE starts_with(c.relname,'zasp_sa_attack_lab_')
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE starts_with(c.relname,'zasp_sa_attack_lab_')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_sa_attack_lab_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(expected_checksum='-- compiled attack lab checksum' AND expected_fingerprint='-- compiled attack lab fingerprint'
 AND (SELECT count(*)=57 FROM public.zasp_schema_versions) AND NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version<1 OR version>57)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_budgets_predecessor_releases() p LEFT JOIN public.zasp_schema_versions r USING(version) WHERE r.name IS DISTINCT FROM p.name OR r.checksum IS DISTINCT FROM p.checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=56 AND name='production_compliance' AND checksum='-- attack lab predecessor checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_compliance_fingerprint' AND value='-- attack lab predecessor fingerprint')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=57 AND name='production_security_agent_attack_lab' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_attack_lab_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_attack_lab_fingerprint' AND value=expected_fingerprint)
 AND zasp_sa_attack_lab_prior.predecessor_ready('-- attack lab predecessor checksum','-- attack lab predecessor fingerprint')
 AND public.zasp_sa_attack_lab_role_ready()
 AND public.zasp_sa_attack_lab_live_fingerprint()=expected_fingerprint,false)
$ready$;
CREATE FUNCTION public.zasp_sa_attack_lab_guard() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
 SELECT public.zasp_sa_attack_lab_readiness('-- compiled attack lab checksum','-- compiled attack lab fingerprint')
$guard$;

DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname,'zasp_sa_attack_lab_') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p);
 END LOOP;
END $owners$;
GRANT EXECUTE ON FUNCTION public.zasp_sa_attack_lab_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
GRANT EXECUTE ON FUNCTION public.zasp_sa_attack_lab_readiness(text,text) TO zasp_security_agent_attack_lab_reconciler;
GRANT EXECUTE ON FUNCTION public.zasp_sa_attack_lab_register_reconciler(text,text,text) TO zasp_discovery_authority;
DROP FUNCTION public.zasp_sa_attack_lab_save(text);
