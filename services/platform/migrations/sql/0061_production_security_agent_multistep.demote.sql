-- Runner has serialized schema admission before any evidence/table locks.
DO $guard$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='multistep rollback requires read committed isolation';END IF;
 PERFORM public.zasp_sa_multistep_assert_unused();
 IF NOT public.zasp_sa_multistep_readiness('-- compiled multistep checksum','-- registered multistep fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='multistep registered drift refuses rollback';END IF;
END $guard$;
CREATE TABLE public.zasp_sa_multistep_metadata (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),
 fingerprint text NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$')
);
ALTER TABLE public.zasp_sa_multistep_metadata OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_sa_multistep_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_sa_multistep_metadata FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON public.zasp_sa_multistep_metadata USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON public.zasp_sa_multistep_metadata FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
INSERT INTO public.zasp_sa_multistep_metadata(singleton,checksum,fingerprint) VALUES(true,'-- compiled multistep checksum','-- compiled multistep fingerprint');
DO $restore$
DECLARE saved record;grant_value jsonb;grantee text;
BEGIN
 PERFORM set_config('check_function_bodies','off',true);
 FOR saved IN SELECT * FROM zasp_sa_multistep_prior.functions ORDER BY signature LOOP
  EXECUTE saved.definition;
  EXECUTE format('ALTER FUNCTION %s OWNER TO %I',saved.signature,saved.owner_name);
  FOR grantee IN SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid=saved.signature::regprocedure LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',saved.signature,CASE WHEN grantee='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(grantee) END);
  END LOOP;
  FOR grant_value IN SELECT value FROM jsonb_array_elements(saved.acl) LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %s%s',saved.signature,CASE WHEN grant_value->>'grantee'='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(grant_value->>'grantee') END,CASE WHEN (grant_value->>'grantable')::boolean THEN ' WITH GRANT OPTION' ELSE '' END);
  END LOOP;
 END LOOP;
 PERFORM set_config('check_function_bodies','on',true);
END $restore$;
DROP FUNCTION public.zasp_sa_multistep_registered_live_fingerprint();
DROP SCHEMA zasp_sa_multistep_prior CASCADE;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_security_agent_multistep_checksum','production_security_agent_multistep_fingerprint');
