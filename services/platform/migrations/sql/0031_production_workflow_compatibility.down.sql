DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>31)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_workflow_compatibility_fingerprint' AND value='c80d1d4f013685c7e1401dd8a33b7aea44bc60e7516e60bcc779342ca17b1197')
     OR NOT public.zasp_production_workflow_compatibility_security_ready()
     OR public.zasp_production_workflow_compatibility_live_fingerprint()<>'c80d1d4f013685c7e1401dd8a33b7aea44bc60e7516e60bcc779342ca17b1197' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow compatibility rollback rejected';
  END IF;
END
$guard$;

REVOKE ALL ON FUNCTION public.zasp_production_approval_notification_readiness(text,text) FROM PUBLIC,zasp_security_agent_api;
DROP FUNCTION public.zasp_production_approval_notification_readiness(text,text);
ALTER FUNCTION public.zasp_production_approval_notification_readiness_v30(text,text) RENAME TO zasp_production_approval_notification_readiness;
GRANT EXECUTE ON FUNCTION public.zasp_production_approval_notification_readiness(text,text) TO zasp_security_agent_api;

DO $compatibility$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'later_release."version" > 31','later_release."version" > 28');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v30 compatibility restore failed';END IF;
  EXECUTE definition;
  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(replace(definition,'later."version">31','later."version">28'),'later."version" > 31','later."version" > 28');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v30 compatibility restore failed';END IF;
  EXECUTE definition;
END
$compatibility$;

DROP FUNCTION public.zasp_production_workflow_compatibility_readiness(text,text);
DROP FUNCTION public.zasp_production_workflow_compatibility_live_fingerprint();
DROP FUNCTION public.zasp_production_workflow_compatibility_security_ready();
DELETE FROM public.zasp_schema_metadata WHERE key='production_workflow_compatibility_fingerprint';
