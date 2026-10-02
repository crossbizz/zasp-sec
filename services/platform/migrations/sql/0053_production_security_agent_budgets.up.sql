DO $predecessor$
BEGIN
 IF NOT COALESCE(public.zasp_production_audit_exports_readiness('-- budget predecessor checksum','-- budget predecessor fingerprint'),false) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='budget release predecessor rejected';
 END IF;
END
$predecessor$;

CREATE SCHEMA zasp_security_agent_budgets_predecessor AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_security_agent_budgets_predecessor FROM PUBLIC;
DO $save$
DECLARE item record;definition text;constraint_value text;
BEGIN
 FOR item IN SELECT p.oid,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='public' AND (starts_with(p.proname,'zasp_security_agent_') OR p.proname IN('zasp_workflow_mutate','zasp_risk_mutate','zasp_policy_deployment_store_temporary_source','zasp_production_security_agent_attack_path_security_ready','zasp_production_workflow_compatibility_security_ready','zasp_production_audit_exports_readiness')) ORDER BY p.proname,p.oid LOOP
  definition:=pg_get_functiondef(item.oid);
  EXECUTE replace(definition,'FUNCTION public.'||item.proname||'(','FUNCTION zasp_security_agent_budgets_predecessor.'||item.proname||'(');
  EXECUTE format('ALTER FUNCTION zasp_security_agent_budgets_predecessor.%I(%s) OWNER TO zasp_discovery_authority',item.proname,pg_get_function_identity_arguments(item.oid));
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_security_agent_budgets_predecessor.%I(%s) FROM PUBLIC',item.proname,pg_get_function_identity_arguments(item.oid));
 END LOOP;
 SELECT pg_get_constraintdef(oid) INTO STRICT constraint_value FROM pg_constraint WHERE conrelid='public.zasp_security_agent_planner_receipts'::regclass AND conname='zasp_security_agent_planner_receipts_outcome_check';
 EXECUTE format('CREATE FUNCTION zasp_security_agent_budgets_predecessor.saved_outcome_constraint() RETURNS text LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS %L','SELECT '||quote_literal(constraint_value)||'::text');
 ALTER FUNCTION zasp_security_agent_budgets_predecessor.saved_outcome_constraint() OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_security_agent_budgets_predecessor.saved_outcome_constraint() FROM PUBLIC;
END
$save$;

-- budget admission fragment
-- budget starts fragment
-- budget release fragment
