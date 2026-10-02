-- Refuse, never delete retained evidence or its deletion audit correlation.
DO $jobs_down$
DECLARE signature_value text;r record;
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_compliance_export_jobs) OR EXISTS(SELECT 1 FROM public.zasp_compliance_export_grants) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance retained evidence blocks downgrade';END IF;
 FOR signature_value IN SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND (starts_with(p.proname,'zasp_compliance_export_') OR p.proname IN('zasp_compliance_register_workers','zasp_compliance_require','zasp_compliance_worker_security_ready','zasp_compliance_jobs_catalog')) ORDER BY p.proname LOOP
  -- Public row helpers depend on the job row type, but functions have no
  -- catalog dependency on PL/pgSQL callees. Tables are dropped only afterward.
  EXECUTE format('DROP FUNCTION %s',signature_value);
 END LOOP;
 FOR r IN SELECT * FROM public.zasp_compliance_worker_bindings LOOP EXECUTE format('REVOKE %I FROM %I',r.authority_role,r.principal_name);END LOOP;
END $jobs_down$;
DROP TABLE public.zasp_compliance_export_grants;
DROP TABLE public.zasp_compliance_export_jobs;
DROP TABLE public.zasp_compliance_export_scopes;
DROP TABLE public.zasp_compliance_export_policy;
DROP TABLE public.zasp_compliance_worker_bindings;
REVOKE zasp_compliance_worker,zasp_compliance_cleanup FROM zasp_discovery_authority;
DROP ROLE zasp_compliance_worker;
DROP ROLE zasp_compliance_cleanup;
DO $restore$
DECLARE signature_value text; definition_value text; name_value text;
BEGIN
 FOREACH signature_value IN ARRAY ARRAY[
 'zasp_production_security_agent_existing_tests_readiness(text,text)',
 'zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',
 'zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)',
 'zasp_production_security_agent_attack_path_security_ready()',
 'zasp_production_workflow_compatibility_security_ready()'] LOOP
  name_value:=split_part(signature_value,'(',1);
  definition_value:=pg_get_functiondef(('zasp_compliance_predecessor.'||signature_value)::regprocedure);
  EXECUTE replace(definition_value,'FUNCTION zasp_compliance_predecessor.'||name_value||'(','FUNCTION public.'||name_value||'(');
 END LOOP;
END $restore$;
DROP FUNCTION public.zasp_compliance_read(text,text,text,text,bytea,text,jsonb,text,text);
DROP FUNCTION public.zasp_compliance_api_ready(text,text);
DROP FUNCTION public.zasp_compliance_authorize(text,text,text,text,bytea);
DROP FUNCTION public.zasp_compliance_sources(text,text,text);
DROP FUNCTION public.zasp_compliance_configuration(text,text,text);
DROP FUNCTION public.zasp_compliance_mappings();
DROP FUNCTION public.zasp_compliance_valid_target(text,text);
DROP FUNCTION public.zasp_compliance_readiness(text,text);
DROP FUNCTION public.zasp_compliance_live_fingerprint();
DROP FUNCTION public.zasp_compliance_function_identity(oid);
DROP FUNCTION zasp_compliance_predecessor.zasp_production_security_agent_existing_tests_readiness(text,text);
DROP FUNCTION zasp_compliance_predecessor.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text);
DROP FUNCTION zasp_compliance_predecessor.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text);
DROP FUNCTION zasp_compliance_predecessor.zasp_production_security_agent_attack_path_security_ready();
DROP FUNCTION zasp_compliance_predecessor.zasp_production_workflow_compatibility_security_ready();
DROP FUNCTION zasp_compliance_predecessor.existing_tests_fingerprint();
DROP FUNCTION zasp_compliance_predecessor.run_context_fingerprint();
DROP FUNCTION zasp_compliance_predecessor.budget_fingerprint();
DROP FUNCTION zasp_compliance_predecessor.audit_fingerprint();
DROP SCHEMA zasp_compliance_predecessor;
DELETE FROM public.zasp_schema_metadata WHERE key IN('production_compliance_checksum','production_compliance_fingerprint');
