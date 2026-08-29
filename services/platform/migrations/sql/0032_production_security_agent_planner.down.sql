DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>32)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_planner_fingerprint' AND value='08cc739df90088092ed3f1a0535843c54c3d5115570bf3f95314ae39dfaeed58')
     OR NOT public.zasp_production_security_agent_planner_security_ready()
     OR public.zasp_production_security_agent_planner_live_fingerprint()<>'08cc739df90088092ed3f1a0535843c54c3d5115570bf3f95314ae39dfaeed58' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent planner rollback rejected';
  END IF;
  IF EXISTS(SELECT 1 FROM public.zasp_security_agent_planner_receipts) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='planner receipts block rollback';END IF;
END
$guard$;

REVOKE ALL ON FUNCTION public.zasp_production_workflow_compatibility_readiness(text,text) FROM PUBLIC,zasp_security_agent_api;
DROP FUNCTION public.zasp_production_workflow_compatibility_readiness(text,text);
ALTER FUNCTION public.zasp_production_workflow_compatibility_readiness_v31(text,text) RENAME TO zasp_production_workflow_compatibility_readiness;
GRANT EXECUTE ON FUNCTION public.zasp_production_workflow_compatibility_readiness(text,text) TO zasp_security_agent_api;

REVOKE ALL ON FUNCTION public.zasp_production_security_agent_planner_readiness(text,text) FROM PUBLIC,zasp_security_agent_worker;
DROP FUNCTION public.zasp_production_security_agent_planner_readiness(text,text);
DROP FUNCTION public.zasp_production_security_agent_planner_live_fingerprint();
DROP FUNCTION public.zasp_production_security_agent_planner_security_ready();
REVOKE ALL ON FUNCTION public.zasp_security_agent_fail_planner(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text) FROM PUBLIC,zasp_security_agent_worker;
REVOKE ALL ON FUNCTION public.zasp_security_agent_accept_planner_candidate(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamptz,text,text) FROM PUBLIC,zasp_security_agent_worker;
REVOKE ALL ON FUNCTION public.zasp_security_agent_planner_context(text,text,text,text,text,text) FROM PUBLIC,zasp_security_agent_worker;
DROP FUNCTION public.zasp_security_agent_fail_planner(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text);
DROP FUNCTION public.zasp_security_agent_accept_planner_candidate(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamptz,text,text);
DROP FUNCTION public.zasp_security_agent_planner_context(text,text,text,text,text,text);
DROP TABLE public.zasp_security_agent_planner_receipts;
DELETE FROM public.zasp_schema_metadata WHERE key='production_security_agent_planner_fingerprint';
