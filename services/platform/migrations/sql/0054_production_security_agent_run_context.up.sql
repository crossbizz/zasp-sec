DO $predecessor$
BEGIN
 IF NOT COALESCE(public.zasp_production_security_agent_budgets_readiness('-- run context predecessor checksum','-- run context predecessor fingerprint'),false) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='run context predecessor rejected';
 END IF;
END
$predecessor$;

CREATE SCHEMA zasp_run_context_predecessor AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_run_context_predecessor FROM PUBLIC;
DO $save$
DECLARE signature text;identity regprocedure;definition text;function_name text;
BEGIN
 FOREACH signature IN ARRAY ARRAY['zasp_production_audit_exports_readiness(text,text)','zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','zasp_production_security_agent_attack_path_security_ready()','zasp_production_workflow_compatibility_security_ready()'] LOOP
  identity:=('public.'||signature)::regprocedure;
  function_name:=split_part(signature,'(',1);
  definition:=pg_get_functiondef(identity);
  EXECUTE replace(definition,'FUNCTION public.'||function_name||'(','FUNCTION zasp_run_context_predecessor.'||function_name||'(');
  EXECUTE format('ALTER FUNCTION zasp_run_context_predecessor.%s OWNER TO zasp_discovery_authority',signature);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_run_context_predecessor.%s FROM PUBLIC',signature);
 END LOOP;
END
$save$;

DO $compatibility_limits$
DECLARE signature text;definition text;needle text;expected integer;occurrences integer;
BEGIN
 FOREACH signature IN ARRAY ARRAY['zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','zasp_production_security_agent_attack_path_security_ready()','zasp_production_workflow_compatibility_security_ready()'] LOOP
  definition:=pg_get_functiondef(('public.'||signature)::regprocedure);
  occurrences:=0;
  expected:=CASE WHEN split_part(signature,'(',1) IN('zasp_workflow_mutate','zasp_risk_mutate') THEN 1 ELSE 3 END;
  FOREACH needle IN ARRAY ARRAY['later_release."version" > 53','later."version">53','later."version" > 53'] LOOP
   occurrences:=occurrences+(length(definition)-length(replace(definition,needle,'')))/length(needle);
   definition:=replace(definition,needle,replace(needle,'53','54'));
  END LOOP;
  IF occurrences<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='run context compatibility predecessor rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility_limits$;

-- Preserve every predecessor's identity. Private copies extend metadata
-- exclusions for54, without weakening the historical public53 gate.
DO $fingerprint_base$
DECLARE definition text;needle text;
BEGIN
 definition:=pg_get_functiondef('zasp_security_agent_budgets_predecessor.zasp_production_audit_exports_live_fingerprint()'::regprocedure);
 needle:='''production_security_agent_budgets_checksum'',''production_security_agent_budgets_fingerprint''';
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='run context fingerprint predecessor rejected';END IF;
 definition:=replace(definition,needle,needle||',''production_security_agent_run_context_checksum'',''production_security_agent_run_context_fingerprint''');
 definition:=replace(definition,'FUNCTION zasp_security_agent_budgets_predecessor.zasp_production_audit_exports_live_fingerprint(','FUNCTION zasp_run_context_predecessor.audit_fingerprint(');
 EXECUTE definition;
 ALTER FUNCTION zasp_run_context_predecessor.audit_fingerprint() OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_run_context_predecessor.audit_fingerprint() FROM PUBLIC;
 definition:=pg_get_functiondef('public.zasp_production_security_agent_budgets_live_fingerprint()'::regprocedure);
 definition:=replace(definition,'FUNCTION public.zasp_production_security_agent_budgets_live_fingerprint(','FUNCTION zasp_run_context_predecessor.budget_fingerprint(');
 definition:=replace(definition,'zasp_security_agent_budgets_predecessor.zasp_production_audit_exports_live_fingerprint()','zasp_run_context_predecessor.audit_fingerprint()');
 EXECUTE definition;
 ALTER FUNCTION zasp_run_context_predecessor.budget_fingerprint() OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_run_context_predecessor.budget_fingerprint() FROM PUBLIC;
END
$fingerprint_base$;

-- run context projection fragment

CREATE FUNCTION public.zasp_production_security_agent_run_context_function_identity(function_value oid)
 RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $identity$
 SELECT CASE WHEN function_value=to_regprocedure('public.zasp_production_security_agent_run_context_readiness(text,text)')
 THEN regexp_replace(pg_get_functiondef(function_value),$$expected_(checksum|fingerprint) = '[a-f0-9]{64}'$$,$$expected_\1 = '<compiled-pin>'$$,'g')
 ELSE pg_get_functiondef(function_value) END
$identity$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_function_identity(oid) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_function_identity(oid) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_run_context_live_fingerprint()
 RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_run_context_predecessor.budget_fingerprint())
 UNION ALL SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_run_context_predecessor'
 UNION ALL SELECT concat_ws('|','activity-index',c.relname,c.relowner::regrole::text,i.indisvalid,i.indisready,i.indislive,pg_get_indexdef(i.indexrelid)) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_security_agent_activity_')
 UNION ALL SELECT concat_ws('|','function',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),
 CASE WHEN p.oid='public.zasp_production_security_agent_run_context_lock_env(text,text,text)'::regprocedure THEN public.zasp_audit_export_source_catalog_role(p.proowner,(SELECT relowner FROM pg_class WHERE oid='public.zasp_environments'::regclass)) ELSE r.rolname END,
 p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),
 CASE WHEN p.oid='public.zasp_production_security_agent_run_context_lock_env(text,text,text)'::regprocedure THEN public.zasp_audit_export_source_catalog_acl(p.proacl,(SELECT relowner FROM pg_class WHERE oid='public.zasp_environments'::regclass))::text ELSE COALESCE(p.proacl::text,'') END,
 public.zasp_production_security_agent_run_context_function_identity(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='zasp_run_context_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_production_security_agent_run_context')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_live_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_live_fingerprint() FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_run_context_readiness(expected_checksum text,expected_fingerprint text)
 RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $readiness$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$'
 AND expected_checksum = '-- compiled run context checksum'
 AND expected_fingerprint = '-- compiled run context fingerprint'
 AND (SELECT count(*)=54 FROM public.zasp_schema_versions)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version<1 OR version>54)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_budgets_predecessor_releases() p LEFT JOIN public.zasp_schema_versions r USING(version) WHERE r.name IS DISTINCT FROM p.name OR r.checksum IS DISTINCT FROM p.checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=53 AND name='production_security_agent_budgets' AND checksum='-- run context predecessor checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_budgets_checksum' AND value='-- run context predecessor checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_budgets_fingerprint' AND value='-- run context predecessor fingerprint')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=54 AND name='production_security_agent_run_context' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_fingerprint' AND value=expected_fingerprint)
 AND public.zasp_production_runtime_sandbox_binding_security_ready()
 AND public.zasp_audit_export_policy_state_ready()
 AND public.zasp_audit_export_worker_security_ready()
 AND public.zasp_audit_export_source_acl_ready()
 AND public.zasp_audit_export_workflow_acl_ready()
 AND public.zasp_production_security_agent_run_context_live_fingerprint()=expected_fingerprint,false)
$readiness$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_readiness(text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_run_context_client_ready(expected_checksum text,expected_fingerprint text)
 RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $client$
 SELECT public.zasp_production_security_agent_run_context_readiness(expected_checksum,expected_fingerprint)
$client$;
ALTER FUNCTION public.zasp_production_security_agent_run_context_client_ready(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_run_context_client_ready(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_run_context_client_ready(text,text) TO zasp_discovery_api,zasp_runtime_ingest,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_audit_export_worker,zasp_audit_export_outbox;

-- This inherited SQL path uses mutable metadata only to call the independently
-- pinned54 gate. Never embed54 pins in a wrapper hashed by predecessor code.
CREATE OR REPLACE FUNCTION public.zasp_production_audit_exports_readiness(expected_checksum text,expected_fingerprint text)
 RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $compatibility$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=52 AND name='production_audit_exports' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_audit_exports_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_audit_exports_fingerprint' AND value=expected_fingerprint)
 AND public.zasp_production_security_agent_run_context_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=54),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_fingerprint')),false)
$compatibility$;
