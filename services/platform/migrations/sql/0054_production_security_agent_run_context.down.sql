--54 adds read projection only. Retained53 budget history stays intact.
DROP INDEX public.zasp_security_agent_activity_audit_v54_idx;
DROP INDEX public.zasp_security_agent_activity_trigger_v54_idx;
DROP INDEX public.zasp_security_agent_activity_plan_v54_idx;
DO $restore$
DECLARE item record;definition text;
BEGIN
 FOR item IN SELECT p.oid,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_run_context_predecessor' AND p.proname NOT IN('audit_fingerprint','budget_fingerprint') ORDER BY p.proname,p.oid LOOP
  definition:=pg_get_functiondef(item.oid);
  EXECUTE replace(definition,'FUNCTION zasp_run_context_predecessor.'||item.proname||'(','FUNCTION public.'||item.proname||'(');
 END LOOP;
END
$restore$;
DROP FUNCTION public.zasp_security_agent_run_context_v54(text,text,text,text);
DO $remove$
DECLARE item record;
BEGIN
 FOR item IN SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid) arguments FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_run_context_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_production_security_agent_run_context') ORDER BY n.nspname,p.proname LOOP
  EXECUTE format('DROP FUNCTION %I.%I(%s)',item.nspname,item.proname,item.arguments);
 END LOOP;
END
$remove$;
DROP SCHEMA zasp_run_context_predecessor;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_security_agent_run_context_checksum','production_security_agent_run_context_fingerprint');
