DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>32)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_planner_fingerprint' AND value='a8fe47482d379bb501fbfdd9d28caddedb460e81942e11606500ea5ac2263bdd')
     OR NOT public.zasp_production_security_agent_planner_security_ready()
     OR public.zasp_production_security_agent_planner_live_fingerprint()<>'a8fe47482d379bb501fbfdd9d28caddedb460e81942e11606500ea5ac2263bdd' THEN
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

DO $compatibility$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'later_release."version" > 32','later_release."version" > 31');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v31 compatibility restoration failed';END IF;
  EXECUTE definition;
  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(replace(definition,'later."version">32','later."version">31'),'later."version" > 32','later."version" > 31');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v31 compatibility restoration failed';END IF;
  EXECUTE definition;
END
$compatibility$;

CREATE OR REPLACE FUNCTION public.zasp_production_workflow_compatibility_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_approval_notification_security_ready()
 AND position('later_release."version" > 31' IN pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure))>0
 AND (position('later."version">31' IN pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure))>0
      OR position('later."version" > 31' IN pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure))>0)
$security$;
