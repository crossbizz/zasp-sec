-- New authority, not a re-registration of release61. The two scope helpers
-- retain the scope table owner because SELECT FOR SHARE requires its rights.
CREATE SCHEMA zasp_temporal67 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal67 FROM PUBLIC;

CREATE FUNCTION zasp_temporal67.scope_authority_ready() RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $scope$
 SELECT count(*)=2 AND COALESCE(bool_and(p.proowner=c.relowner
  AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b WHERE b.authority_role='zasp_discovery_authority' AND b.principal_name=c.relowner::regrole::text)
  AND p.proacl IS NOT NULL
  AND (SELECT count(*)=2 AND bool_and(a.grantor=c.relowner AND NOT a.is_grantable
      AND a.privilege_type='EXECUTE' AND a.grantee IN(c.relowner,'zasp_discovery_authority'::regrole))
       AND count(DISTINCT a.grantee)=2 FROM aclexplode(p.proacl) a)),false)
 FROM pg_proc p CROSS JOIN pg_class c
 WHERE c.oid='public.zasp_authorized_scopes'::regclass
 AND p.oid IN('zasp_sa_multistep_prior.lock_scope(text,text,text,text)'::regprocedure,
             'zasp_sa_multistep_prior.pricing_lock_scope(text,text,text,text)'::regprocedure)
$scope$;

-- Keep every historical catalog category and function definition. Only the
-- owner/ACL display of the two explicitly checked helpers gets a symbolic
-- identity in this NEW fingerprint. No historical function is replaced.
DO $portable$ DECLARE d text;predicate text;BEGIN
 d:=pg_get_functiondef('public.zasp_sa_multistep_registered_live_fingerprint()'::regprocedure);
 d:=replace(d,'FUNCTION public.zasp_sa_multistep_registered_live_fingerprint()', 'FUNCTION zasp_temporal67.base_fingerprint()');
 predicate:='p.oid IN(''zasp_sa_multistep_prior.lock_scope(text,text,text,text)''::regprocedure,''zasp_sa_multistep_prior.pricing_lock_scope(text,text,text,text)''::regprocedure)';
 d:=replace(d,'p.proowner::regrole::text','CASE WHEN '||predicate||' THEN ''<scope-owner>'' ELSE p.proowner::regrole::text END');
 d:=replace(d,$needle$COALESCE(p.proacl::text,'')$needle$,'CASE WHEN '||predicate||' THEN ''<scope-owner>:EXECUTE,<domain-authority>:EXECUTE'' ELSE COALESCE(p.proacl::text,'''') END');
 EXECUTE d;
END $portable$;

CREATE FUNCTION zasp_temporal67.base_ready() RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $base$
 SELECT COALESCE(zasp_temporal67.scope_authority_ready()
 AND (SELECT count(*)=61 FROM public.zasp_schema_versions)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version<1 OR version>61)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND name='production_security_agent_multistep' AND checksum='-- release61 checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_multistep_checksum' AND value='-- release61 checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_multistep_fingerprint' AND value='-- release61 fingerprint')
 AND to_regclass('public.zasp_sa_multistep_metadata') IS NULL
 AND zasp_sa_multistep_prior.predecessor_ready('-- release60 checksum','-- release60 fingerprint')
 AND zasp_temporal67.base_fingerprint()='-- domain67 base fingerprint',false)
$base$;

DO $ownership$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal67'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $ownership$;
