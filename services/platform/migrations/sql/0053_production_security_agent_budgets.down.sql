-- Retained budget authority cannot be represented by the predecessor runtime.
-- No implicit deletion, refund, or reset of history is permitted on rollback.
SELECT public.zasp_security_agent_budget_assert_rollback_empty();

DO $restore$
DECLARE item record;definition text;
BEGIN
 FOR item IN SELECT p.oid,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_security_agent_budgets_predecessor' AND p.proname NOT IN('saved_outcome_constraint','zasp_production_audit_exports_live_fingerprint') ORDER BY p.proname,p.oid LOOP
  definition:=pg_get_functiondef(item.oid);
  EXECUTE replace(definition,'FUNCTION zasp_security_agent_budgets_predecessor.'||item.proname||'(','FUNCTION public.'||item.proname||'(');
 END LOOP;
 ALTER TABLE public.zasp_security_agent_planner_receipts DROP CONSTRAINT zasp_security_agent_planner_receipts_outcome_check;
 EXECUTE 'ALTER TABLE public.zasp_security_agent_planner_receipts ADD CONSTRAINT zasp_security_agent_planner_receipts_outcome_check '||zasp_security_agent_budgets_predecessor.saved_outcome_constraint();
END
$restore$;

DO $remove_functions$
DECLARE item record;
BEGIN
 FOR item IN SELECT p.oid,p.proname,pg_get_function_identity_arguments(p.oid) AS arguments,n.nspname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='zasp_security_agent_budgets_predecessor' OR n.nspname='public' AND (starts_with(p.proname,'zasp_security_agent_budget') OR starts_with(p.proname,'zasp_production_security_agent_budgets') OR p.proname='zasp_security_agent_claim_budgeted_runs') ORDER BY n.nspname,p.proname LOOP
  EXECUTE format('DROP FUNCTION %I.%I(%s)',item.nspname,item.proname,item.arguments);
 END LOOP;
END
$remove_functions$;
DROP TABLE public.zasp_security_agent_step_reservations;
DROP TABLE public.zasp_security_agent_provider_reservations;
DROP TABLE public.zasp_security_agent_run_budgets;
DROP TABLE public.zasp_security_agent_org_admissions;
DROP SCHEMA zasp_security_agent_budgets_predecessor;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_security_agent_budgets_checksum','production_security_agent_budgets_fingerprint');
