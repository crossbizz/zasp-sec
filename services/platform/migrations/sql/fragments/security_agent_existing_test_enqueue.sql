-- Unregistered release55 candidate. No worker dispatch or application grant to
-- the core is introduced here. Full55 readiness/rollback remains required.
DO $predecessor$
BEGIN
 IF NOT COALESCE(public.zasp_production_security_agent_run_context_readiness('-- existing test predecessor checksum','-- existing test predecessor fingerprint'),false) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test predecessor rejected';
 END IF;
END
$predecessor$;

CREATE SCHEMA zasp_existing_tests_predecessor AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_existing_tests_predecessor FROM PUBLIC;
DO $extract$
DECLARE definition text;guard_value text:='NOT zasp_security_agent_principal_ready(''zasp_security_agent_api'') OR ';
BEGIN
 SELECT pg_get_functiondef('public.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)'::regprocedure) INTO STRICT definition;
 IF (length(definition)-length(replace(definition,guard_value,'')))/length(guard_value)<>1
  OR position('zasp_red_team_safety_authorized(organization_id,workspace_id,environment_id,target_id,target_kind,safety)' IN definition)=0 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test enqueue source rejected';
 END IF;
 -- Save the exact original body for the release55 rollback installer. Its
 -- owner/ACL do not change when CREATE OR REPLACE installs the public wrapper.
 EXECUTE replace(definition,'FUNCTION public.zasp_red_team_run_test(','FUNCTION zasp_existing_tests_predecessor.zasp_red_team_run_test(');
 ALTER FUNCTION zasp_existing_tests_predecessor.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text) OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_existing_tests_predecessor.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text) FROM PUBLIC;
 definition:=replace(definition,'FUNCTION public.zasp_red_team_run_test(','FUNCTION public.zasp_security_agent_test_enqueue_core(');
 definition:=replace(definition,guard_value,'');
 EXECUTE definition;
 ALTER FUNCTION public.zasp_security_agent_test_enqueue_core(text,text,text,text,text,text,bigint,text,text) OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION public.zasp_security_agent_test_enqueue_core(text,text,text,text,text,text,bigint,text,text) FROM PUBLIC;
END
$extract$;

CREATE OR REPLACE FUNCTION public.zasp_red_team_run_test(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,definition_value text,definition_version_value bigint,run_value text,correlation_value text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public
AS $api_run$
BEGIN
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team run rejected';
 END IF;
 RETURN public.zasp_security_agent_test_enqueue_core(organization_value,workspace_value,environment_value,actor_value,idempotency_value,definition_value,definition_version_value,run_value,correlation_value);
END
$api_run$;
