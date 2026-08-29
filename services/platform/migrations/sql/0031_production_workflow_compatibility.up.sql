DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>30)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=30 AND name='production_approval_notification' AND checksum='6959f9bd74427f9b8f018fccb85958989be91bae1be426b0d9988a3699d5e3d6')
     OR NOT public.zasp_production_approval_notification_readiness('6959f9bd74427f9b8f018fccb85958989be91bae1be426b0d9988a3699d5e3d6','38492f1a329e45c28f2cd982d59b952e5ba42963e7921e8d1711a7a4a2541a58') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production_approval_notification prerequisite rejected';
  END IF;
END
$guard$;

DO $compatibility$
DECLARE definition text;original_definition text;
BEGIN
  SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(definition,'later_release."version" > 28','later_release."version" > 31');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v31 compatibility evolution failed';END IF;
  EXECUTE definition;
  SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
  original_definition:=definition;
  definition:=replace(replace(definition,'later."version">28','later."version">31'),'later."version" > 28','later."version" > 31');
  IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v31 compatibility evolution failed';END IF;
  EXECUTE definition;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_workflow_compatibility_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_approval_notification_security_ready()
 AND position('later_release."version" > 31' IN pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure))>0
 AND (position('later."version">31' IN pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure))>0
      OR position('later."version" > 31' IN pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure))>0)
$security$;

CREATE FUNCTION public.zasp_production_workflow_compatibility_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
  SELECT concat_ws('|','prior',zasp_production_approval_notification_live_fingerprint())
  UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_workflow_mutate','zasp_risk_mutate')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_production_workflow_compatibility_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=31 AND name='production_workflow_compatibility' AND checksum=expected_checksum)
 AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>31)
 AND zasp_production_workflow_compatibility_security_ready() AND zasp_production_workflow_compatibility_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_workflow_compatibility_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_workflow_compatibility_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_workflow_compatibility_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_workflow_compatibility_security_ready(),public.zasp_production_workflow_compatibility_live_fingerprint(),public.zasp_production_workflow_compatibility_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
GRANT EXECUTE ON FUNCTION public.zasp_production_workflow_compatibility_readiness(text,text) TO zasp_security_agent_api;

ALTER FUNCTION public.zasp_production_approval_notification_readiness(text,text) RENAME TO zasp_production_approval_notification_readiness_v30;
REVOKE ALL ON FUNCTION public.zasp_production_approval_notification_readiness_v30(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
CREATE FUNCTION public.zasp_production_approval_notification_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=30 AND name='production_approval_notification' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_approval_notification_fingerprint' AND value=expected_fingerprint)
 AND zasp_production_workflow_compatibility_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=31 AND name='production_workflow_compatibility'),(SELECT value FROM zasp_schema_metadata WHERE key='production_workflow_compatibility_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_approval_notification_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_approval_notification_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_approval_notification_readiness(text,text) TO zasp_security_agent_api;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_workflow_compatibility_fingerprint', 'c80d1d4f013685c7e1401dd8a33b7aea44bc60e7516e60bcc779342ca17b1197') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
