DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>38)
 OR NOT public.zasp_production_red_team_invocation_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=38 AND name='production_red_team_invocation'),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_red_team_invocation_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team artifacts prerequisite rejected';
 END IF;
END
$guard$;

CREATE FUNCTION public.zasp_red_team_valid_input_artifact(organization_value text,workspace_value text,environment_value text,input_value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog, public AS $input$
DECLARE reference_value text; key_value text; prefix_value text;
BEGIN
 IF input_value IS NULL OR jsonb_typeof(input_value)<>'object' THEN RETURN false;END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(input_value))<>4 OR NOT input_value ?& ARRAY['reference','version_id','sha256','size_bytes']
 OR jsonb_typeof(input_value->'reference')<>'string' OR jsonb_typeof(input_value->'version_id')<>'string' OR jsonb_typeof(input_value->'sha256')<>'string' OR jsonb_typeof(input_value->'size_bytes')<>'number'
 OR input_value->>'sha256' !~ '^[a-f0-9]{64}$' OR input_value->>'sha256'=repeat('0',64)
 OR length(input_value->>'version_id') NOT BETWEEN 1 AND 512 OR input_value->>'version_id' ~ '[[:space:][:cntrl:]]'
 OR input_value->>'size_bytes' !~ '^[1-9][0-9]{0,4}$' THEN RETURN false;END IF;
 IF (input_value->>'size_bytes')::bigint>65536 THEN RETURN false;END IF;
 reference_value:=input_value->>'reference';
 IF NOT zasp_discovery_s3_object_reference(reference_value) THEN RETURN false;END IF;
 key_value:=substring(reference_value FROM '^s3://[^/]+/(.+)$');
 prefix_value:='organizations/'||organization_value||'/workspaces/'||workspace_value||'/environments/'||environment_value||'/artifacts/';
 RETURN COALESCE(zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value) AND zasp_valid_product_id(environment_value) AND left(key_value,length(prefix_value))=prefix_value AND zasp_valid_product_id(substring(key_value FROM length(prefix_value)+1)),false);
END
$input$;
ALTER FUNCTION public.zasp_red_team_valid_input_artifact(text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_red_team_valid_input_artifact(text,text,text,jsonb) FROM PUBLIC;
ALTER TABLE public.zasp_red_team_attempts ADD COLUMN input_artifact jsonb;
ALTER TABLE public.zasp_red_team_attempts ADD CONSTRAINT zasp_red_team_attempt_input_artifact CHECK(input_artifact IS NULL OR zasp_red_team_valid_input_artifact(organization_id,workspace_id,environment_id,input_artifact));

ALTER FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint) RENAME TO zasp_red_team_finish_run_v38;
REVOKE ALL ON FUNCTION public.zasp_red_team_finish_run_v38(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint) FROM PUBLIC,zasp_red_team_worker;
CREATE FUNCTION public.zasp_red_team_finish_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,token_value bytea,input_digest_value bytea,verdict_value text,objective_value text,behavior_value text,error_value text,evidence_value jsonb,reference_value text,key_value text,version_value text,checksum_value bytea,size_value bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $legacy$
BEGIN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team input artifact required';END
$legacy$;
CREATE FUNCTION public.zasp_red_team_finish_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,token_value bytea,input_digest_value bytea,verdict_value text,objective_value text,behavior_value text,error_value text,evidence_value jsonb,reference_value text,key_value text,version_value text,checksum_value bytea,size_value bigint,input_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $finish$
DECLARE result_value jsonb;
BEGIN
 IF NOT zasp_red_team_principal_ready('zasp_red_team_worker') OR NOT zasp_red_team_valid_input_artifact(organization_value,workspace_value,environment_value,input_value) OR input_value->>'reference'=reference_value THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team input artifact rejected';
 END IF;
 result_value:=zasp_red_team_finish_run_v38(organization_value,workspace_value,environment_value,run_value,worker_value,token_value,input_digest_value,verdict_value,objective_value,behavior_value,error_value,evidence_value,reference_value,key_value,version_value,checksum_value,size_value);
 UPDATE zasp_red_team_attempts SET input_artifact=input_value WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(organization_value,workspace_value,environment_value,run_value,(result_value->>'attempt')::integer) AND input_artifact IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='red team input artifact conflict';END IF;
 RETURN result_value;
END
$finish$;
ALTER FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint),public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint),public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb) TO zasp_red_team_worker;

DO $detail$
DECLARE definition text; prior text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_red_team_get_run(text,text,text,text)'::regprocedure) INTO STRICT definition;prior:=definition;
 definition:=replace(definition,'''evidence_reference'',evidence_reference','''evidence_reference'',evidence_reference,''input_artifact'',input_artifact');
 IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team input detail patch rejected';END IF;
 EXECUTE definition;
END
$detail$;

DO $compatibility$
DECLARE definition text; prior text; function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 38','later_release."version" > 39'),'later."version">38','later."version">39'),'later."version" > 38','later."version" > 39');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team artifacts compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_red_team_artifacts_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_red_team_invocation_security_ready()
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.zasp_red_team_attempts'::regclass AND conname='zasp_red_team_attempt_input_artifact' AND convalidated)
 AND EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE procedure.oid='public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb)'::regprocedure AND owner.rolname='zasp_discovery_authority' AND procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT has_function_privilege('public',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_security_agent_api',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_red_team_adapter',procedure.oid,'EXECUTE') AND has_function_privilege('zasp_red_team_worker',procedure.oid,'EXECUTE'))
 AND NOT has_function_privilege('zasp_red_team_worker','public.zasp_red_team_finish_run_v38(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint)','EXECUTE')
$security$;

CREATE FUNCTION public.zasp_production_red_team_artifacts_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_red_team_invocation_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_red_team_artifacts_readiness','zasp_production_red_team_artifacts_security_ready','zasp_red_team_valid_input_artifact','zasp_red_team_finish_run','zasp_red_team_finish_run_v38','zasp_red_team_get_run')
 UNION ALL SELECT concat_ws('|','constraint',conname,pg_get_constraintdef(oid),convalidated) FROM pg_constraint WHERE conrelid='public.zasp_red_team_attempts'::regclass
 UNION ALL SELECT concat_ws('|','column',attname,format_type(atttypid,atttypmod),attnotnull) FROM pg_attribute WHERE attrelid='public.zasp_red_team_attempts'::regclass AND attnum>0 AND NOT attisdropped
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_production_red_team_artifacts_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=39 AND name='production_red_team_artifacts' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>39) AND zasp_production_red_team_artifacts_security_ready() AND zasp_production_red_team_artifacts_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_red_team_artifacts_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_red_team_artifacts_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_red_team_artifacts_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_red_team_artifacts_security_ready(),public.zasp_production_red_team_artifacts_live_fingerprint(),public.zasp_production_red_team_artifacts_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_red_team_artifacts_readiness(text,text) TO zasp_red_team_worker;

ALTER FUNCTION public.zasp_production_red_team_invocation_readiness(text,text) RENAME TO zasp_production_red_team_invocation_readiness_v38;
CREATE FUNCTION public.zasp_production_red_team_invocation_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=38 AND name='production_red_team_invocation' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_red_team_invocation_fingerprint' AND value=expected_fingerprint) AND zasp_production_red_team_artifacts_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=39),(SELECT value FROM zasp_schema_metadata WHERE key='production_red_team_artifacts_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_red_team_invocation_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_red_team_invocation_readiness(text,text) FROM PUBLIC;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_red_team_artifacts_fingerprint', '945775780a1752765398d6da17ce9aaf75c2fec8877d20c14c871020bfb0039c');
