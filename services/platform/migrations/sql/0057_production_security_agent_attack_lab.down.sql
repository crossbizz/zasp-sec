DO $rollback$
DECLARE saved record;grant_value jsonb;p regprocedure;grantee text;
BEGIN
 -- Control mutations lock switches before writing their request receipt.
 -- Hold both through the guard and restoration to prevent a late enable.
 LOCK TABLE public.zasp_security_agent_kill_switches,public.zasp_security_agent_request_receipts IN ACCESS EXCLUSIVE MODE;
 LOCK TABLE public.zasp_security_agent_definitions,public.zasp_security_agent_definition_versions,public.zasp_security_agent_plans,public.zasp_security_agent_approvals,public.zasp_security_agent_effects,public.zasp_sa_attack_lab_links IN ACCESS EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions WHERE body->'allowed_actions' ? 'start_attack_lab')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions WHERE definition->'allowed_actions' ? 'start_attack_lab')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE plan->'verification'->>'kind'='attack_lab_run')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE action_key='start_attack_lab')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE action_key='start_attack_lab')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_kill_switches WHERE action_key='start_attack_lab')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts WHERE operation='setSecurityAgentExecutionControl' AND resource_id='action:start_attack_lab')
 OR EXISTS(SELECT 1 FROM public.zasp_sa_attack_lab_links) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab release history retained';END IF;
 FOR saved IN SELECT * FROM zasp_sa_attack_lab_prior.functions ORDER BY signature LOOP
  EXECUTE saved.definition;
  EXECUTE format('ALTER FUNCTION public.%s OWNER TO %I',saved.signature,saved.owner_name);
  FOR grantee IN SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid=('public.'||saved.signature)::regprocedure LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION public.%s FROM %s',saved.signature,CASE WHEN grantee='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(grantee) END);
  END LOOP;
  FOR grant_value IN SELECT value FROM jsonb_array_elements(saved.acl) LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO %s%s',saved.signature,CASE WHEN grant_value->>'grantee'='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(grant_value->>'grantee') END,CASE WHEN (grant_value->>'grantable')::boolean THEN ' WITH GRANT OPTION' ELSE '' END);
  END LOOP;
 END LOOP;
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname,'zasp_sa_attack_lab_') LOOP EXECUTE format('DROP FUNCTION %s',p);END LOOP;
END $rollback$;
DROP TABLE public.zasp_sa_attack_lab_links;
DROP TABLE public.zasp_sa_attack_lab_principals;
DROP ROLE zasp_security_agent_attack_lab_reconciler;
DROP SCHEMA zasp_sa_attack_lab_prior CASCADE;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_security_agent_attack_lab_checksum','production_security_agent_attack_lab_fingerprint');
