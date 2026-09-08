DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>35)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_integration_webhook_fingerprint' AND value='b9456ee67062bae82d7ddd8d277a4c4d8e137801fd5e95e06657eaf524d67b81')
 OR NOT public.zasp_production_integration_webhook_security_ready()
 OR public.zasp_production_integration_webhook_live_fingerprint()<>'b9456ee67062bae82d7ddd8d277a4c4d8e137801fd5e95e06657eaf524d67b81'
 OR EXISTS(SELECT 1 FROM public.zasp_integration_webhook_tests) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration webhook rollback rejected';
 END IF;
END
$guard$;

DROP FUNCTION public.zasp_production_integration_setup_readiness(text,text);
ALTER FUNCTION public.zasp_production_integration_setup_readiness_v34(text,text) RENAME TO zasp_production_integration_setup_readiness;
REVOKE ALL ON FUNCTION public.zasp_production_integration_setup_readiness(text,text) FROM PUBLIC;
DROP FUNCTION public.zasp_production_integration_webhook_readiness(text,text);
DROP FUNCTION public.zasp_production_integration_webhook_live_fingerprint();
DROP FUNCTION public.zasp_production_integration_webhook_security_ready();
DROP FUNCTION public.zasp_integration_webhook_test_reserve(text,text,text,text,text,bigint,text,text,text,text,text,integer);
DROP FUNCTION public.zasp_integration_webhook_test_complete(text,text,text,text,text,text,boolean);
DROP FUNCTION public.zasp_integration_webhook_test_status(text,text,text,text);
DROP FUNCTION public.zasp_integration_webhook_test_public(public.zasp_integration_webhook_tests);
DROP TABLE public.zasp_integration_webhook_tests;

DO $compatibility$
DECLARE definition text; prior text; function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 35','later_release."version" > 34'),'later."version">35','later."version">34'),'later."version" > 35','later."version" > 34');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='integration webhook compatibility restoration rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_integration_webhook_fingerprint';
