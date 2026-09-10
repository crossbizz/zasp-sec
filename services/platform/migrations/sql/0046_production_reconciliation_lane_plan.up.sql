-- Keep deployed checksums and all claim semantics; isolate global lane eligibility.
DO $guard$
BEGIN
 IF NOT public.zasp_production_runtime_enrollment_pairing_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=45),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_enrollment_pairing_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='reconciliation plan predecessor rejected';
 END IF;
END
$guard$;
DO $rewrite$
DECLARE definition text; original_body text; rewritten text;
BEGIN
 SELECT pg_get_functiondef(oid),prosrc INTO STRICT definition,original_body FROM pg_proc WHERE oid='public.zasp_connector_claim_reconciliation(text,integer,integer)'::regprocedure;
 IF encode(digest(convert_to(original_body,'UTF8'),'sha256'),'hex')<>'93de1fd6a09761ee6eb5317907d090a30014dd6ce46b33accc85ce23e140dd07' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='reconciliation claim definition drift';
 END IF;
 rewritten:=replace(definition,$old$ AND NOT EXISTS(SELECT 1 FROM zasp_connector_effects live WHERE live.provider=candidate.provider AND live.operation=candidate.operation AND live.status='unknown' AND live.lease_expires_at>transaction_timestamp())$old$,'');
 rewritten:=replace(rewritten,'WITH candidates AS',$new$WITH eligible_lanes AS MATERIALIZED (SELECT lane.* FROM zasp_connector_effect_lane_scopes lane WHERE NOT EXISTS(SELECT 1 FROM zasp_connector_effects live WHERE live.provider=lane.provider AND live.operation=lane.operation AND live.status='unknown' AND live.lease_expires_at>transaction_timestamp())), candidates AS$new$);
 rewritten:=replace(rewritten,'FROM zasp_connector_effect_lane_scopes lane CROSS JOIN LATERAL','FROM eligible_lanes lane CROSS JOIN LATERAL');
 IF rewritten=definition THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='reconciliation claim rewrite rejected';END IF;
 EXECUTE rewritten;
END
$rewrite$;
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 45','later_release."version" > 46'),'later."version">45','later."version">46'),'later."version" > 45','later."version" > 46');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='reconciliation plan compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;


CREATE FUNCTION public.zasp_production_reconciliation_lane_plan_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_runtime_enrollment_pairing_security_ready()
 AND EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='public.zasp_connector_claim_reconciliation(text,integer,integer)'::regprocedure AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, public']
  AND has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE') AND has_function_privilege('zasp_discovery_worker',p.oid,'EXECUTE')
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.grantee NOT IN(p.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api'),(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_worker')) OR acl.is_grantable))
$security$;
CREATE FUNCTION public.zasp_production_reconciliation_lane_plan_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_enrollment_pairing_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_connector_claim_reconciliation','zasp_production_reconciliation_lane_plan_readiness','zasp_production_reconciliation_lane_plan_security_ready')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_reconciliation_lane_plan_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=46 AND name='production_reconciliation_lane_plan' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>46) AND zasp_production_reconciliation_lane_plan_security_ready() AND zasp_production_reconciliation_lane_plan_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_reconciliation_lane_plan_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_reconciliation_lane_plan_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_reconciliation_lane_plan_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_reconciliation_lane_plan_security_ready(),public.zasp_production_reconciliation_lane_plan_live_fingerprint(),public.zasp_production_reconciliation_lane_plan_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_reconciliation_lane_plan_readiness(text,text) TO zasp_discovery_worker,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;

ALTER FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness(text,text) RENAME TO zasp_production_runtime_enrollment_pairing_readiness_v45;
CREATE FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=45 AND name='production_runtime_enrollment_pairing' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_enrollment_pairing_fingerprint' AND value=expected_fingerprint) AND zasp_production_reconciliation_lane_plan_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=46),(SELECT value FROM zasp_schema_metadata WHERE key='production_reconciliation_lane_plan_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness(text,text) TO zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_reconciliation_lane_plan_fingerprint', '1ea4724c2dc08814f8f46cbc34c5f0613ffc9b21a28dd1384e9d3e26dcbeb5b6');
