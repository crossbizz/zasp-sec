SET LOCAL lock_timeout='3s';
SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));
LOCK TABLE public.zasp_discovery_schedules IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.zasp_discovery_schedule_runs IN ACCESS EXCLUSIVE MODE;
DO $rollback$
DECLARE saved record;grant_value jsonb;p regprocedure;grantee text;
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_discovery_schedule_runs WHERE rebind_generation>0 OR completion_digest IS NOT NULL OR completion_result IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='schedule replay durable evidence retained';END IF;
 PERFORM set_config('check_function_bodies','off',true);
 FOR saved IN SELECT * FROM zasp_schedule_replay_prior.functions ORDER BY signature LOOP
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
 ALTER TABLE public.zasp_discovery_schedule_runs DROP CONSTRAINT zasp_discovery_schedule_runs_occurrence_key,DROP COLUMN rebind_generation,DROP COLUMN completion_digest,DROP COLUMN completion_result;
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname,'zasp_discovery_schedule_replay_') LOOP EXECUTE format('DROP FUNCTION %s',p);END LOOP;
END $rollback$;
DROP SCHEMA zasp_schedule_replay_prior CASCADE;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_discovery_schedule_replay_checksum','production_discovery_schedule_replay_fingerprint');
