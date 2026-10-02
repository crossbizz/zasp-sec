-- Unpublished55: used definitions/links require forward repair, even terminal.
-- All retained tables use the discovery authority's unrestricted policy.
DO $authority$
BEGIN
 IF NOT pg_has_role(current_user,'zasp_discovery_authority','USAGE') THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='existing test rollback authority unavailable';
 END IF;
END
$authority$;
LOCK TABLE public.zasp_workflow_records,public.zasp_security_agent_definitions,
 public.zasp_security_agent_definition_versions,public.zasp_security_agent_test_links,public.zasp_security_agent_test_invocations,
 public.zasp_security_agent_global_control_receipts,public.zasp_security_agent_kill_switches,public.zasp_security_agent_audit
 IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $unused$
BEGIN
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(
  (SELECT value FROM public.zasp_schema_metadata WHERE key='production_security_agent_existing_tests_checksum'),
  (SELECT value FROM public.zasp_schema_metadata WHERE key='production_security_agent_existing_tests_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global operator rollback release unavailable';
 END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_global_control_receipts)
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,event_kind)=('*','*','*','kill_switch_changed')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global operator history retained; forward repair required';
 END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links)
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations)
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions WHERE definition ? 'existing_test')
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions WHERE body ? 'existing_test')
  OR EXISTS(SELECT 1 FROM public.zasp_workflow_records WHERE kind='security_agent' AND body ? 'existing_test') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test history retained; forward repair required';
 END IF;
END
$unused$;
DO $restore_global$
DECLARE item record;
BEGIN
 FOR item IN SELECT * FROM zasp_existing_tests_predecessor.global_control_triggers ORDER BY relation_name LOOP
  EXECUTE format('DROP TRIGGER %I ON public.%I',item.trigger_name,item.relation_name);
  EXECUTE item.definition;
  EXECUTE format('ALTER TABLE public.%I %s TRIGGER %I',item.relation_name,CASE item.enabled WHEN 'O' THEN 'ENABLE' WHEN 'D' THEN 'DISABLE' WHEN 'R' THEN 'ENABLE REPLICA' WHEN 'A' THEN 'ENABLE ALWAYS' END,item.trigger_name);
 END LOOP;
END
$restore_global$;
DROP FUNCTION public.zasp_production_security_agent_existing_tests_global_intent(public.zasp_security_agent_global_control_receipts);
DROP TABLE public.zasp_security_agent_global_control_receipts;
DROP TABLE zasp_existing_tests_predecessor.global_control_triggers;
DROP POLICY global_operator_binding ON public.zasp_discovery_principal_bindings;
DROP POLICY global_operator_control_read ON public.zasp_security_agent_kill_switches;
DROP POLICY global_operator_control_write ON public.zasp_security_agent_kill_switches;
DROP POLICY global_operator_audit_read ON public.zasp_security_agent_audit;
DROP POLICY global_operator_audit_write ON public.zasp_security_agent_audit;
REVOKE ALL ON public.zasp_security_agent_kill_switches,public.zasp_security_agent_audit FROM zasp_security_agent_global_operator;
REVOKE UPDATE(execution_enabled,version,updated_by,updated_at) ON public.zasp_security_agent_kill_switches FROM zasp_security_agent_global_operator;
REVOKE SELECT(principal_name,authority_role) ON public.zasp_discovery_principal_bindings FROM zasp_security_agent_global_operator;
REVOKE ALL ON SCHEMA public FROM zasp_security_agent_global_operator;
DO $restore$
DECLARE item record; source_value text;
BEGIN
 FOR item IN SELECT p.oid,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='zasp_existing_tests_predecessor' AND p.proname NOT IN('audit_fingerprint','budget_fingerprint','run_context_fingerprint') ORDER BY p.proname,p.oid LOOP
  source_value:=pg_get_functiondef(item.oid);
  EXECUTE replace(source_value,'FUNCTION zasp_existing_tests_predecessor.'||item.proname||'(','FUNCTION public.'||item.proname||'(');
 END LOOP;
END
$restore$;
DROP FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_test_link_enqueue(text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_test_enqueue_core(text,text,text,text,text,text,bigint,text,text);
DROP TABLE public.zasp_security_agent_test_invocations;
DROP TABLE public.zasp_security_agent_test_links;
DO $remove$
DECLARE item record;
BEGIN
 FOR item IN SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid) arguments FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='zasp_existing_tests_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_production_security_agent_existing_tests') ORDER BY n.nspname,p.proname LOOP
  EXECUTE format('DROP FUNCTION %I.%I(%s)',item.nspname,item.proname,item.arguments);
 END LOOP;
END
$remove$;
DROP SCHEMA zasp_existing_tests_predecessor;
DROP ROLE zasp_security_agent_global_operator;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_security_agent_existing_tests_checksum','production_security_agent_existing_tests_fingerprint');
