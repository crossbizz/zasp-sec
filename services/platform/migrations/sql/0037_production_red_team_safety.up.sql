DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>36)
 OR NOT public.zasp_production_runtime_queue_replay_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=36 AND name='production_runtime_queue_replay'),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_queue_replay_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety prerequisite rejected';
 END IF;
END
$guard$;

DO $compatibility$
DECLARE definition text; prior text; function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 36','later_release."version" > 37'),'later."version">36','later."version">37'),'later."version" > 36','later."version" > 37');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

DO $target$
DECLARE definition text; anchor text := $anchor$ AND target_kind_value IN('agent_endpoint','mcp_server','coding_agent')
$anchor$;
BEGIN
 SELECT pg_get_functiondef('public.zasp_red_team_target_valid(text,text,text,text,text)'::regprocedure) INTO STRICT definition;
 IF position(anchor IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety target source rejected';END IF;
 EXECUTE replace(definition,anchor,anchor||$inserted$ AND EXISTS(SELECT 1 FROM zasp_environments environment_row WHERE (environment_row.organization_id,environment_row.workspace_id,environment_row.id)=(organization_value,workspace_value,environment_value) AND environment_row.environment_class IN('development','test','staging'))
$inserted$);
END
$target$;

CREATE FUNCTION public.zasp_red_team_safety_authorized(organization_value text,workspace_value text,environment_value text,target_value text,target_kind_value text,safety_value jsonb) RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $safety$
 SELECT COALESCE(
 zasp_red_team_target_valid(organization_value,workspace_value,environment_value,target_value,target_kind_value)
 AND zasp_red_team_definition_valid('Safety check',target_value,target_kind_value,'["prompt_injection"]'::jsonb,safety_value)
 AND EXISTS(SELECT 1 FROM zasp_environments environment_row WHERE (environment_row.organization_id,environment_row.workspace_id,environment_row.id)=(organization_value,workspace_value,environment_value) AND environment_row.environment_class=safety_value->>'environment')
 AND EXISTS(SELECT 1 FROM zasp_inventory_entities entity_value JOIN zasp_attack_lab_credential_bindings binding
 ON (binding.organization_id,binding.workspace_id,binding.environment_id,binding.target_id,binding.credential_reference)=(entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.winning_attributes->'red_team'->>'credential_reference')
 WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id)=(organization_value,workspace_value,environment_value,target_value)
 AND binding.state='active' AND binding.valid_until>transaction_timestamp() AND binding.credential_class=safety_value->>'credential_class'),false)
$safety$;
ALTER FUNCTION public.zasp_red_team_safety_authorized(text,text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_red_team_safety_authorized(text,text,text,text,text,jsonb) FROM PUBLIC;

DO $admission$
DECLARE definition text; original text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_red_team_create_definition(text,text,text,text,text,text,text,text,text,jsonb,jsonb,text)'::regprocedure) INTO STRICT definition;original:=definition;
 definition:=replace(definition,'zasp_red_team_target_valid(organization_value,workspace_value,environment_value,target_value,target_kind_value)','zasp_red_team_safety_authorized(organization_value,workspace_value,environment_value,target_value,target_kind_value,safety_value)');
 IF definition=original THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety admission source rejected';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_red_team_update_definition(text,text,text,text,text,text,bigint,text,text,text,jsonb,jsonb,boolean,text)'::regprocedure) INTO STRICT definition;original:=definition;
 definition:=replace(definition,'zasp_red_team_target_valid(organization_value,workspace_value,environment_value,target_value,target_kind_value)','zasp_red_team_safety_authorized(organization_value,workspace_value,environment_value,target_value,target_kind_value,safety_value)');
 IF definition=original THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety admission source rejected';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)'::regprocedure) INTO STRICT definition;original:=definition;
 definition:=replace(definition,'zasp_red_team_target_valid(organization_id,workspace_id,environment_id,target_id,target_kind)','zasp_red_team_safety_authorized(organization_id,workspace_id,environment_id,target_id,target_kind,safety)');
 IF definition=original THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety admission source rejected';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_red_team_claim_run(text,text,text,text,text,bytea,integer)'::regprocedure) INTO STRICT definition;original:=definition;
 definition:=replace(definition,'zasp_red_team_target_valid(organization_id,workspace_id,environment_id,target_id,target_kind)','zasp_red_team_safety_authorized(organization_id,workspace_id,environment_id,target_id,target_kind,safety)');
 IF definition=original THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety admission source rejected';END IF;
 EXECUTE definition;
END
$admission$;


CREATE FUNCTION public.zasp_production_red_team_safety_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_runtime_queue_replay_security_ready()

 AND EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE procedure.oid='public.zasp_red_team_safety_authorized(text,text,text,text,text,jsonb)'::regprocedure AND owner.rolname='zasp_discovery_authority' AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT has_function_privilege('public',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_security_agent_api',procedure.oid,'EXECUTE'))
$security$;

CREATE FUNCTION public.zasp_production_red_team_safety_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_queue_replay_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_red_team_safety_security_ready')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_production_red_team_safety_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=37 AND name='production_red_team_safety' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>37) AND zasp_production_red_team_safety_security_ready() AND zasp_production_red_team_safety_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_red_team_safety_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_red_team_safety_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_red_team_safety_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_red_team_safety_security_ready(),public.zasp_production_red_team_safety_live_fingerprint(),public.zasp_production_red_team_safety_readiness(text,text) FROM PUBLIC;

ALTER FUNCTION public.zasp_production_runtime_queue_replay_readiness(text,text) RENAME TO zasp_production_runtime_queue_replay_readiness_v36;
CREATE FUNCTION public.zasp_production_runtime_queue_replay_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=36 AND name='production_runtime_queue_replay' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_queue_replay_fingerprint' AND value=expected_fingerprint) AND zasp_production_red_team_safety_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=37),(SELECT value FROM zasp_schema_metadata WHERE key='production_red_team_safety_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_runtime_queue_replay_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_queue_replay_readiness(text,text) FROM PUBLIC;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_red_team_safety_fingerprint', 'ad8addf9cc9d2ecd620253234f01030d694612a6246135c437fc667e33eb35ca');
