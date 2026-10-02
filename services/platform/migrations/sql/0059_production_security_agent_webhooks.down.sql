DO $rollback$
DECLARE saved record;grant_value jsonb;p regprocedure;grantee text;
BEGIN
 LOCK TABLE public.zasp_security_agent_webhook_deliveries IN ACCESS EXCLUSIVE MODE NOWAIT;
 LOCK TABLE public.zasp_sa_webhook_planner_inputs IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_webhook_deliveries) OR EXISTS(SELECT 1 FROM public.zasp_sa_webhook_planner_inputs) OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions WHERE definition->'allowed_actions' ? 'send_response_webhook') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='webhook durable evidence retained';END IF;
 DROP TRIGGER zasp_webhook_immutable ON public.zasp_security_agent_webhook_deliveries;
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='public'::regnamespace AND (starts_with(proname,'zasp_sa_webhook_') OR proname LIKE '%security_agent_webhook%') LOOP EXECUTE format('DROP FUNCTION %s',p);END LOOP;
 DROP TABLE public.zasp_sa_webhook_keys;
 DROP TABLE public.zasp_security_agent_webhook_deliveries;
 DROP TABLE public.zasp_sa_webhook_planner_inputs;
 DROP TABLE public.zasp_sa_webhook_principals;
 FOR saved IN SELECT * FROM zasp_sa_webhook_prior.functions ORDER BY signature LOOP
  EXECUTE saved.definition;
  EXECUTE format('ALTER FUNCTION %s OWNER TO %I',saved.signature,saved.owner_name);
  FOR grantee IN SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid=saved.signature::regprocedure LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',saved.signature,CASE WHEN grantee='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(grantee) END);
  END LOOP;
  FOR grant_value IN SELECT value FROM jsonb_array_elements(saved.acl) LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %s%s',saved.signature,CASE WHEN grant_value->>'grantee'='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(grant_value->>'grantee') END,CASE WHEN (grant_value->>'grantable')::boolean THEN ' WITH GRANT OPTION' ELSE '' END);
  END LOOP;
 END LOOP;
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='public'::regnamespace AND (starts_with(proname,'zasp_sa_webhook_') OR proname LIKE '%security_agent_webhook%') LOOP EXECUTE format('DROP FUNCTION %s',p);END LOOP;
END $rollback$;
DROP SCHEMA zasp_sa_webhook_prior CASCADE;
DROP ROLE zasp_security_agent_webhook_worker;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_security_agent_webhooks_checksum','production_security_agent_webhooks_fingerprint');
