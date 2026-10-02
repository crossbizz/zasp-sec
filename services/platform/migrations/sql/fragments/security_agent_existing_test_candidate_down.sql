-- Owned-fixture rollback only. Not a registered release55 down migration.
-- Freeze writers in the workflow -> definition -> history order used by draft
-- mutation before deciding whether old code can safely regain authority.
LOCK TABLE public.zasp_workflow_records, public.zasp_security_agent_definitions,
 public.zasp_security_agent_definition_versions, public.zasp_security_agent_test_links
 IN ACCESS EXCLUSIVE MODE;
DO $unused$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links)
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions WHERE definition ? 'existing_test')
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions WHERE body ? 'existing_test')
  OR EXISTS(SELECT 1 FROM public.zasp_workflow_records WHERE kind='security_agent' AND body ? 'existing_test') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test history retained; forward repair required';
 END IF;
END
$unused$;
DO $restore$
DECLARE signature_value text; source_value text;
BEGIN
 FOREACH signature_value IN ARRAY ARRAY[
  'zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)',
  'zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'
 ] LOOP
  SELECT pg_get_functiondef(('zasp_existing_tests_predecessor.'||signature_value)::regprocedure) INTO STRICT source_value;
  EXECUTE replace(source_value,'FUNCTION zasp_existing_tests_predecessor.','FUNCTION public.');
 END LOOP;
END
$restore$;
DROP FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_test_link_enqueue(text,text,text,text,text,text);
DROP FUNCTION public.zasp_production_security_agent_existing_tests_authorize_step(text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_test_enqueue_core(text,text,text,text,text,text,bigint,text,text);
DROP TABLE public.zasp_security_agent_test_links;
DROP FUNCTION zasp_existing_tests_predecessor.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text);
DROP FUNCTION zasp_existing_tests_predecessor.zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text);
DROP SCHEMA zasp_existing_tests_predecessor;
