-- v53 release envelope draft. Install only after checking exact v52 readiness
-- and acquiring migration cutover locks. The runner supplies immutable release
-- metadata; this fragment never learns an expected fingerprint from live code.
CREATE FUNCTION public.zasp_security_agent_budgets_predecessor_releases()
 RETURNS TABLE(version bigint,name text,checksum text) LANGUAGE sql IMMUTABLE
 SET search_path TO pg_catalog,public AS $releases$
 SELECT * FROM public.zasp_audit_exports_predecessor_releases()
 UNION ALL SELECT 52::bigint,'production_audit_exports'::text,'-- budget predecessor checksum'::text
$releases$;
ALTER FUNCTION public.zasp_security_agent_budgets_predecessor_releases() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_budgets_predecessor_releases() FROM PUBLIC;

DO $compatibility_limits$
DECLARE signature text;definition text;needle text;expected integer;occurrences integer;
BEGIN
 FOREACH signature IN ARRAY ARRAY['zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','zasp_production_security_agent_attack_path_security_ready()','zasp_production_workflow_compatibility_security_ready()'] LOOP
  definition:=pg_get_functiondef(('public.'||signature)::regprocedure);
  occurrences:=0;
  expected:=CASE WHEN split_part(signature,'(',1) IN('zasp_workflow_mutate','zasp_risk_mutate') THEN 1 ELSE 3 END;
  FOREACH needle IN ARRAY ARRAY['later_release."version" > 52','later."version">52','later."version" > 52'] LOOP
   occurrences:=occurrences+(length(definition)-length(replace(definition,needle,'')))/length(needle);
   definition:=replace(definition,needle,replace(needle,'52','53'));
  END LOOP;
  IF occurrences<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='budget compatibility predecessor rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility_limits$;

-- Extend the inherited fingerprint without a self-reference through v53's
-- own metadata. Keep the v52 function and its historical pinned identity intact.
DO $fingerprint_base$
DECLARE definition text;needle text;
BEGIN
 definition:=pg_get_functiondef('public.zasp_production_audit_exports_live_fingerprint()'::regprocedure);
 needle:='''production_audit_exports_checksum'', ''production_audit_exports_fingerprint''';
 -- pg_get_functiondef preserves SQL dollar-body spacing from the migration.
 IF position(needle IN definition)=0 THEN needle:='''production_audit_exports_checksum'',''production_audit_exports_fingerprint''';END IF;
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='budget fingerprint predecessor rejected';END IF;
 definition:=replace(definition,needle,needle||',''production_security_agent_budgets_checksum'',''production_security_agent_budgets_fingerprint''');
 definition:=replace(definition,'FUNCTION public.zasp_production_audit_exports_live_fingerprint(','FUNCTION zasp_security_agent_budgets_predecessor.zasp_production_audit_exports_live_fingerprint(');
 EXECUTE definition;
 ALTER FUNCTION zasp_security_agent_budgets_predecessor.zasp_production_audit_exports_live_fingerprint() OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_security_agent_budgets_predecessor.zasp_production_audit_exports_live_fingerprint() FROM PUBLIC;
END
$fingerprint_base$;

-- Normalize only the two compiled pin literals to avoid circular hashing.
-- The rest of readiness's body and its catalog authority remain fingerprinted.
CREATE FUNCTION public.zasp_security_agent_budgets_function_identity(function_value oid)
 RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $identity$
 SELECT CASE WHEN function_value=to_regprocedure('public.zasp_production_security_agent_budgets_readiness(text,text)')
 THEN regexp_replace(pg_get_functiondef(function_value),$$expected_(checksum|fingerprint) = '[a-f0-9]{64}'$$,$$expected_\1 = '<compiled-pin>'$$,'g')
 ELSE pg_get_functiondef(function_value) END
$identity$;
ALTER FUNCTION public.zasp_security_agent_budgets_function_identity(oid) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_budgets_function_identity(oid) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_budgets_live_fingerprint()
 RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_security_agent_budgets_predecessor.zasp_production_audit_exports_live_fingerprint())
 UNION ALL SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_security_agent_budgets_predecessor'
 UNION ALL SELECT concat_ws('|','function',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),public.zasp_security_agent_budgets_function_identity(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='zasp_security_agent_budgets_predecessor' OR n.nspname='public' AND (starts_with(p.proname,'zasp_security_agent_') OR starts_with(p.proname,'zasp_production_security_agent_budgets') OR p.proname='zasp_policy_deployment_store_temporary_source')
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,r.rolname,COALESCE(c.relacl::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname IN('zasp_security_agent_org_admissions','zasp_security_agent_run_budgets','zasp_security_agent_step_reservations','zasp_security_agent_provider_reservations')
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,a.attcollation::regcollation::text,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE c.oid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,k.convalidated,pg_get_constraintdef(k.oid,true)) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.oid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
 UNION ALL SELECT concat_ws('|','index',c.relname,i.indexrelid::regclass::text,i.indisvalid,i.indisready,i.indislive,pg_get_indexdef(i.indexrelid)) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.oid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polpermissive,p.polcmd,(SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(p.polroles) r),pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.oid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,true),t.tgfoid::regprocedure::text) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.oid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass) AND NOT t.tgisinternal
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
ALTER FUNCTION public.zasp_production_security_agent_budgets_live_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_budgets_live_fingerprint() FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_budgets_readiness(expected_checksum text,expected_fingerprint text)
 RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $readiness$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$'
 AND expected_checksum = '-- compiled budget checksum'
 AND expected_fingerprint = '-- compiled budget fingerprint'
 AND (SELECT count(*)=53 FROM public.zasp_schema_versions)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version<1 OR version>53)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_budgets_predecessor_releases() p LEFT JOIN public.zasp_schema_versions r USING(version) WHERE r.name IS DISTINCT FROM p.name OR r.checksum IS DISTINCT FROM p.checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=53 AND name='production_security_agent_budgets' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_budgets_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_budgets_fingerprint' AND value=expected_fingerprint)
 AND public.zasp_production_runtime_sandbox_binding_security_ready()
 AND public.zasp_audit_export_policy_state_ready()
 AND public.zasp_audit_export_worker_security_ready()
 AND public.zasp_audit_export_source_acl_ready()
 AND public.zasp_audit_export_workflow_acl_ready()
 AND public.zasp_production_security_agent_budgets_live_fingerprint()=expected_fingerprint,false)
$readiness$;
ALTER FUNCTION public.zasp_production_security_agent_budgets_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_budgets_readiness(text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.zasp_production_audit_exports_readiness(expected_checksum text,expected_fingerprint text)
 RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $compatibility$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=52 AND name='production_audit_exports' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_audit_exports_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_audit_exports_fingerprint' AND value=expected_fingerprint)
 AND public.zasp_production_security_agent_budgets_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=53),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_security_agent_budgets_fingerprint')),false)
$compatibility$;

-- Updated clients supply pins compiled into the application, independently
-- of the mutable catalog metadata used by inherited SQL wrappers.
CREATE FUNCTION public.zasp_production_security_agent_budgets_client_ready(expected_checksum text,expected_fingerprint text)
 RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $client$
 SELECT public.zasp_production_security_agent_budgets_readiness(expected_checksum,expected_fingerprint)
$client$;
ALTER FUNCTION public.zasp_production_security_agent_budgets_client_ready(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_budgets_client_ready(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_budgets_client_ready(text,text) TO zasp_discovery_api,zasp_runtime_ingest,zasp_security_agent_worker,zasp_security_agent_action_worker;

-- Forced RLS is intentional. Inspect retention as the table authority, never
-- as an inheriting migration login whose SELECT can hide retained history.
CREATE FUNCTION public.zasp_security_agent_budget_assert_rollback_empty()
 RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $retained$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_org_admissions)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_run_budgets)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_planner_receipts WHERE outcome='budget_stopped')
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retained security agent budget authority';END IF;
END
$retained$;
ALTER FUNCTION public.zasp_security_agent_budget_assert_rollback_empty() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_budget_assert_rollback_empty() FROM PUBLIC;
