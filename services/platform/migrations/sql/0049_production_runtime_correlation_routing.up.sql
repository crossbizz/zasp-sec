DO $guard$
BEGIN
 IF NOT COALESCE(public.zasp_production_runtime_acceptance_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=48),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_acceptance_fingerprint')),false) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime routing prerequisite rejected';
 END IF;
END
$guard$;

-- Derive one shared implementation from the verified predecessor. Both entry
-- points retain its stage-wide lock, fairness, delivery and predecessor fences.
DO $claims$
DECLARE definition text;needle text:='WHERE stage_row.stage=stage_value AND';
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_claim_stage(text,text,integer,integer)'::regprocedure) INTO STRICT definition;
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>2
 OR strpos(definition,'FUNCTION public.zasp_runtime_claim_stage(worker_value text, lease_token_value text, lease_seconds integer, claim_limit integer)')=0
 OR strpos(definition,' stage_value:=zasp_runtime_stage_for_session();')=0 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime routing claim predecessor rejected';
 END IF;
 definition:=replace(definition,'FUNCTION public.zasp_runtime_claim_stage(worker_value text, lease_token_value text, lease_seconds integer, claim_limit integer)','FUNCTION public.zasp_runtime_claim_stage_compatible(worker_value text, lease_token_value text, lease_seconds integer, claim_limit integer, allow_v2 boolean)');
 definition:=replace(definition,needle,'WHERE stage_row.stage=stage_value AND (stage_value<>''correlate'' OR stage_row.implementation_version=''runtime-correlation-v1'' OR allow_v2 AND stage_row.implementation_version=''runtime-correlation-v2'') AND');
 definition:=replace(definition,'DECLARE stage_value text;authority_value text;result_value jsonb;','DECLARE stage_value text;authority_value text;result_value jsonb;prior_capability text;');
 definition:=replace(definition,' stage_value:=zasp_runtime_stage_for_session();',E' stage_value:=zasp_runtime_stage_for_session();\n IF worker_value IS NULL OR lease_token_value IS NULL OR lease_seconds IS NULL OR claim_limit IS NULL OR allow_v2 IS NULL OR (allow_v2 AND stage_value<>''correlate'') THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''runtime routing capability rejected'';END IF;');
 definition:=replace(definition,' WITH exhausted AS (',E' prior_capability:=COALESCE(current_setting(''zasp.runtime_correlation_claim_version'',true),'''');\n PERFORM set_config(''zasp.runtime_correlation_claim_version'',CASE WHEN allow_v2 THEN ''runtime-correlation-v2'' ELSE ''runtime-correlation-v1'' END,true);\n WITH exhausted AS (');
 definition:=replace(definition,' RETURN result_value;',E' PERFORM set_config(''zasp.runtime_correlation_claim_version'',prior_capability,true);\n RETURN result_value;');
 EXECUTE definition;
END
$claims$;
ALTER FUNCTION public.zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean) FROM PUBLIC;

-- A previously entered v48 body can survive CREATE OR REPLACE while waiting on
-- its advisory lock. Fence the mutation too, not only the new selection query.
-- This marker declares compatibility, not authority or binary attestation: the
-- registered principal already has the upgraded entrypoint's EXECUTE grant.
CREATE FUNCTION public.zasp_runtime_correlation_claim_version_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF NEW.stage='correlate' AND NEW.implementation_version<>'runtime-correlation-v1'
 AND (NEW.attempt>OLD.attempt OR (NEW.state='failed' AND NEW.last_error_class='exhausted' AND (OLD.state IN('pending','retryable') OR OLD.state='leased' AND OLD.lease_expires_at<=transaction_timestamp())))
 AND NOT COALESCE(NEW.implementation_version='runtime-correlation-v2' AND current_setting('zasp.runtime_correlation_claim_version',true)='runtime-correlation-v2' AND zasp_runtime_stage_for_session()='correlate' AND zasp_runtime_principal_ready('zasp_runtime_correlation_worker'),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime correlation claim version rejected';END IF;
 RETURN NEW;
END
$guard$;
ALTER FUNCTION public.zasp_runtime_correlation_claim_version_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_correlation_claim_version_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_correlation_claim_version BEFORE UPDATE ON public.zasp_runtime_stage_work FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_correlation_claim_version_guard();

CREATE OR REPLACE FUNCTION public.zasp_runtime_claim_stage(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
BEGIN
 IF NOT COALESCE(zasp_production_runtime_correlation_routing_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=49),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_correlation_routing_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime routing authority unavailable';END IF;
 RETURN zasp_runtime_claim_stage_compatible(worker_value,lease_token_value,lease_seconds,claim_limit,false);
END
$claim$;
CREATE FUNCTION public.zasp_runtime_claim_correlation_v2(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
BEGIN
 IF zasp_runtime_stage_for_session() IS DISTINCT FROM 'correlate' OR NOT COALESCE(zasp_runtime_principal_ready('zasp_runtime_correlation_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime routing principal rejected';END IF;
 IF NOT COALESCE(zasp_production_runtime_correlation_routing_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=49),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_correlation_routing_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime routing authority unavailable';END IF;
 RETURN zasp_runtime_claim_stage_compatible(worker_value,lease_token_value,lease_seconds,claim_limit,true);
END
$claim$;
ALTER FUNCTION public.zasp_runtime_claim_correlation_v2(text,text,integer,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_claim_correlation_v2(text,text,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_claim_correlation_v2(text,text,integer,integer) TO zasp_runtime_correlation_worker;

-- New acceptances only. Existing leases, receipts and replay stages are immutable.
DO $routing$
DECLARE definition text;needle text:='(''correlate'',3,''runtime-correlation-v1'')';
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text)'::regprocedure) INTO STRICT definition;
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime routing producer predecessor rejected';END IF;
 EXECUTE replace(definition,needle,'(''correlate'',3,''runtime-correlation-v2'')');
END
$routing$;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 48','later_release."version" > 49'),'later."version">48','later."version">49'),'later."version" > 48','later."version" > 49');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime routing compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_runtime_correlation_routing_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_runtime_acceptance_security_ready()
 AND (SELECT count(*) FROM pg_proc p WHERE p.oid IN('public.zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean)'::regprocedure,'public.zasp_runtime_claim_correlation_v2(text,text,integer,integer)'::regprocedure,'public.zasp_runtime_correlation_claim_version_guard()'::regprocedure)
  AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.is_grantable OR (acl.grantee<>p.proowner AND NOT (p.proname='zasp_runtime_claim_correlation_v2' AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_runtime_correlation_worker')))))=3
 AND has_function_privilege('zasp_runtime_correlation_worker','public.zasp_runtime_claim_correlation_v2(text,text,integer,integer)','EXECUTE')
 AND EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_runtime_correlation_claim_version' AND t.tgfoid='public.zasp_runtime_correlation_claim_version_guard()'::regprocedure AND t.tgenabled='O' AND NOT t.tgisinternal)
$security$;
CREATE FUNCTION public.zasp_production_runtime_correlation_routing_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_acceptance_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_claim_stage_compatible','zasp_runtime_claim_correlation_v2','zasp_runtime_correlation_claim_version_guard','zasp_production_runtime_correlation_routing_security_ready','zasp_production_runtime_correlation_routing_readiness','zasp_production_runtime_acceptance_readiness_v48')
 UNION ALL SELECT concat_ws('|','trigger',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,true)) FROM pg_trigger t WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_runtime_correlation_claim_version'
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_correlation_routing_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=49 AND name='production_runtime_correlation_routing' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_correlation_routing_checksum' AND value=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_correlation_routing_fingerprint' AND value=expected_fingerprint) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>49) AND zasp_production_runtime_correlation_routing_security_ready() AND zasp_production_runtime_correlation_routing_live_fingerprint()=expected_fingerprint,false)
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_correlation_routing_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_correlation_routing_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_correlation_routing_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_correlation_routing_security_ready(),public.zasp_production_runtime_correlation_routing_live_fingerprint(),public.zasp_production_runtime_correlation_routing_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_correlation_routing_readiness(text,text) TO zasp_runtime_ingest,zasp_runtime_correlation_worker,zasp_discovery_worker,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;

ALTER FUNCTION public.zasp_production_runtime_acceptance_readiness(text,text) RENAME TO zasp_production_runtime_acceptance_readiness_v48;
CREATE FUNCTION public.zasp_production_runtime_acceptance_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=48 AND name='production_runtime_acceptance' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_acceptance_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_correlation_routing_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=49),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_correlation_routing_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_runtime_acceptance_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_acceptance_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_acceptance_readiness(text,text) TO zasp_runtime_ingest,zasp_runtime_correlation_worker,zasp_discovery_worker,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_correlation_routing_fingerprint', 'cf721c487211ffef1a0706d0a7b2f55bf2eb3db8a2a8486b6c1f56021b180a6b');
