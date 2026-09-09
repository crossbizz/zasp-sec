DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>37)
 OR NOT public.zasp_production_red_team_safety_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=37 AND name='production_red_team_safety'),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_red_team_safety_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team invocation prerequisite rejected';
 END IF;
END
$guard$;

DO $terminal$
DECLARE definition text; prior text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_red_team_claim_run(text,text,text,text,text,bytea,integer)'::regprocedure) INTO STRICT definition;
 prior:=definition;
 definition:=replace(definition,'state=''cancelled'',completed_at=transaction_timestamp()','state=''cancelled'',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,completed_at=transaction_timestamp()');
 IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team cancellation patch rejected';END IF;
 prior:=definition;
 definition:=replace(definition,'state=''failed'',error_code=''exhausted'',completed_at=transaction_timestamp()','state=''failed'',error_code=''exhausted'',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,completed_at=transaction_timestamp()');
 IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team exhaustion patch rejected';END IF;
 EXECUTE definition;
END
$terminal$;

DO $compatibility$
DECLARE definition text; prior text; function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 37','later_release."version" > 38'),'later."version">37','later."version">38'),'later."version" > 37','later."version" > 38');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team invocation compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

ALTER FUNCTION public.zasp_red_team_resolve_target(text,text,text,text,text) RENAME TO zasp_red_team_resolve_target_v37;
REVOKE ALL ON FUNCTION public.zasp_red_team_resolve_target_v37(text,text,text,text,text) FROM PUBLIC,zasp_red_team_adapter;
CREATE FUNCTION public.zasp_red_team_resolve_target(organization_value text,workspace_value text,environment_value text,target_value text,target_kind_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $legacy$
BEGIN
 RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team live invocation authority required';
END
$legacy$;
ALTER FUNCTION public.zasp_red_team_resolve_target(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_red_team_resolve_target(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_resolve_target(text,text,text,text,text) TO zasp_red_team_adapter;

CREATE FUNCTION public.zasp_red_team_resolve_invocation(organization_value text,workspace_value text,environment_value text,target_value text,target_kind_value text,run_value text,lease_value text,category_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $invocation$
BEGIN
 IF NOT zasp_red_team_principal_ready('zasp_red_team_adapter') OR NOT zasp_valid_product_id(run_value) OR lease_value!~'^[a-f0-9]{32}$' OR category_value NOT IN('prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team invocation rejected';END IF;
 PERFORM 1 FROM zasp_red_team_runs run_row JOIN zasp_red_team_definitions definition_row
 ON (definition_row.organization_id,definition_row.workspace_id,definition_row.environment_id,definition_row.definition_id,definition_row.version)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.definition_id,run_row.definition_version)
 WHERE (run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id,run_row.state)=(organization_value,workspace_value,environment_value,run_value,'leased')
 AND run_row.lease_token=convert_to(lease_value,'UTF8') AND run_row.lease_expires_at>transaction_timestamp() AND NOT run_row.cancel_requested
 AND definition_row.enabled AND (definition_row.target_id,definition_row.target_kind)=(target_value,target_kind_value) AND definition_row.categories ? category_value
 AND zasp_red_team_safety_authorized(organization_value,workspace_value,environment_value,target_value,target_kind_value,definition_row.safety);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team invocation rejected';END IF;
 -- Retain the exact winning source/snapshot/evidence joins in the private resolver.
 RETURN zasp_red_team_resolve_target_v37(organization_value,workspace_value,environment_value,target_value,target_kind_value);
END
$invocation$;
ALTER FUNCTION public.zasp_red_team_resolve_invocation(text,text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_red_team_resolve_invocation(text,text,text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_resolve_invocation(text,text,text,text,text,text,text,text) TO zasp_red_team_adapter;

CREATE FUNCTION public.zasp_production_red_team_invocation_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_red_team_safety_security_ready()

 AND EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE procedure.oid='public.zasp_red_team_resolve_invocation(text,text,text,text,text,text,text,text)'::regprocedure AND owner.rolname='zasp_discovery_authority' AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT has_function_privilege('public',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_security_agent_api',procedure.oid,'EXECUTE') AND has_function_privilege('zasp_red_team_adapter',procedure.oid,'EXECUTE'))
$security$;

CREATE FUNCTION public.zasp_production_red_team_invocation_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_red_team_safety_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_red_team_invocation_security_ready')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_production_red_team_invocation_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=38 AND name='production_red_team_invocation' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>38) AND zasp_production_red_team_invocation_security_ready() AND zasp_production_red_team_invocation_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_red_team_invocation_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_red_team_invocation_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_red_team_invocation_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_red_team_invocation_security_ready(),public.zasp_production_red_team_invocation_live_fingerprint(),public.zasp_production_red_team_invocation_readiness(text,text) FROM PUBLIC;

ALTER FUNCTION public.zasp_production_red_team_safety_readiness(text,text) RENAME TO zasp_production_red_team_safety_readiness_v37;
CREATE FUNCTION public.zasp_production_red_team_safety_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=37 AND name='production_red_team_safety' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_red_team_safety_fingerprint' AND value=expected_fingerprint) AND zasp_production_red_team_invocation_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=38),(SELECT value FROM zasp_schema_metadata WHERE key='production_red_team_invocation_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_red_team_safety_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_red_team_safety_readiness(text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_red_team_invocation_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $adapter$
 SELECT zasp_production_red_team_invocation_readiness(expected_checksum,expected_fingerprint) AND zasp_red_team_principal_ready('zasp_red_team_adapter')
$adapter$;
ALTER FUNCTION public.zasp_red_team_invocation_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_red_team_invocation_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_invocation_readiness(text,text) TO zasp_red_team_adapter;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_red_team_invocation_fingerprint', '8c373c0aa7c2fabcfd2e46b0d2bf05a078f68b0f1257e2866083e996de880a0b');
