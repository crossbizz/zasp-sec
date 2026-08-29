DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>29)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_home_attention_fingerprint' AND value='45a16f5d9eb8265c606796bea9d096bee4edb10826284e9e169a4bd911d9d93c')
     OR NOT public.zasp_production_home_attention_security_ready()
     OR public.zasp_production_home_attention_live_fingerprint()<>'45a16f5d9eb8265c606796bea9d096bee4edb10826284e9e169a4bd911d9d93c' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='home attention rollback rejected';
  END IF;
END
$guard$;

REVOKE ALL ON FUNCTION public.zasp_policy_deployment_execution_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_runtime_gateway,zasp_policy_deployment_worker;
DROP FUNCTION public.zasp_policy_deployment_execution_readiness(text,text);
ALTER FUNCTION public.zasp_policy_deployment_execution_readiness_v28(text,text) RENAME TO zasp_policy_deployment_execution_readiness;
GRANT EXECUTE ON FUNCTION public.zasp_policy_deployment_execution_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_runtime_gateway,zasp_policy_deployment_worker;

DROP FUNCTION public.zasp_production_home_attention_readiness(text,text);
DROP FUNCTION public.zasp_production_home_attention_live_fingerprint();
DROP FUNCTION public.zasp_production_home_attention_security_ready();
REVOKE ALL ON FUNCTION public.zasp_inventory_home_summary(text,text,text) FROM PUBLIC,zasp_discovery_api;
DROP FUNCTION public.zasp_inventory_home_summary(text,text,text);
DROP FUNCTION public.zasp_inventory_home_summary_v29(text,text,text);
ALTER FUNCTION public.zasp_inventory_home_summary_v28(text,text,text) RENAME TO zasp_inventory_home_summary;
GRANT EXECUTE ON FUNCTION public.zasp_inventory_home_summary(text,text,text) TO zasp_discovery_api;
DELETE FROM public.zasp_schema_metadata WHERE key='production_home_attention_fingerprint';
