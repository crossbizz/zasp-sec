DO $guard$
BEGIN
 IF NOT public.zasp_production_runtime_session_query_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=43),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_session_query_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session evidence prerequisite rejected';
 END IF;
END
$guard$;

LOCK TABLE public.zasp_runtime_session_events IN SHARE ROW EXCLUSIVE MODE;
ALTER TABLE public.zasp_runtime_session_events DROP CONSTRAINT zasp_runtime_session_events_event_class_check;
ALTER TABLE public.zasp_runtime_session_events DROP CONSTRAINT zasp_runtime_session_events_action_check;
ALTER TABLE public.zasp_runtime_session_events ADD CONSTRAINT zasp_runtime_session_events_event_class_check CHECK(event_class IN('tool','process','file','network','credential','policy'));
ALTER TABLE public.zasp_runtime_session_events ADD CONSTRAINT zasp_runtime_session_events_action_check CHECK(action IN('invoke','exec','exit','read','write','connect','accept','use','allow','monitor','block'));
ALTER TABLE public.zasp_runtime_session_events ADD CONSTRAINT zasp_runtime_session_event_source_action_v44 CHECK(
 (source='otlp' AND ((event_class='tool' AND action='invoke') OR (event_class='credential' AND action='use') OR (event_class='policy' AND action IN('allow','monitor','block'))))
 OR (source='tetragon' AND ((event_class='process' AND action IN('exec','exit')) OR (event_class='file' AND action IN('read','write')) OR (event_class='network' AND action IN('connect','accept'))))
);

-- This endpoint returns canonical evidence metadata, never raw archive content
-- or a provider enforcement/credential-ownership attestation.
CREATE FUNCTION public.zasp_runtime_session_event_get(organization_value text,workspace_value text,environment_value text,principal_value text,id_value text,event_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $event$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(id_value='unattributed' OR zasp_valid_product_id(id_value),false) OR NOT COALESCE(zasp_valid_product_id(event_value),false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session evidence query rejected';
 END IF;
 IF NOT zasp_runtime_session_read_authorized(organization_value,workspace_value,environment_value,principal_value) THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('id',event_id,'session_id',session_id,'agent_id',agent_id,
  'class',CASE WHEN event_class='process' THEN 'runtime' ELSE event_class END,'action',action,
  'label',title,'evidence_id',evidence_id,'source',source,'confidence',confidence,'at',event_time,'projected_at',projected_at)
 INTO result_value FROM zasp_runtime_session_events
 WHERE (organization_id,workspace_id,environment_id,event_id)=(organization_value,workspace_value,environment_value,event_value)
 AND COALESCE(session_id,'unattributed')=id_value;
 RETURN result_value;
END
$event$;
ALTER FUNCTION public.zasp_runtime_session_event_get(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_session_event_get(text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_session_event_get(text,text,text,text,text,text) TO zasp_discovery_api;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 43','later_release."version" > 44'),'later."version">43','later."version">44'),'later."version" > 43','later."version" > 44');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session evidence compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_runtime_session_evidence_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_runtime_session_query_security_ready()
 AND (SELECT count(*)=1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname='zasp_runtime_session_event_get')
 AND NOT EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname='zasp_runtime_session_event_get'
 AND (procedure.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure.prosecdef OR NOT COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public']
 OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee NOT IN(procedure.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api')))))
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.zasp_runtime_session_events'::regclass AND conname='zasp_runtime_session_event_source_action_v44' AND convalidated)
$security$;
CREATE FUNCTION public.zasp_production_runtime_session_evidence_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_session_query_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_session_event_get','zasp_production_runtime_session_evidence_readiness','zasp_production_runtime_session_evidence_security_ready')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_session_evidence_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=44 AND name='production_runtime_session_evidence' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>44) AND zasp_production_runtime_session_evidence_security_ready() AND zasp_production_runtime_session_evidence_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_session_evidence_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_session_evidence_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_session_evidence_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_session_evidence_security_ready(),public.zasp_production_runtime_session_evidence_live_fingerprint(),public.zasp_production_runtime_session_evidence_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_session_evidence_readiness(text,text) TO zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;

ALTER FUNCTION public.zasp_production_runtime_session_query_readiness(text,text) RENAME TO zasp_production_runtime_session_query_readiness_v43;
CREATE FUNCTION public.zasp_production_runtime_session_query_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=43 AND name='production_runtime_session_query' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_session_query_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_session_evidence_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=44),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_session_evidence_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_runtime_session_query_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_session_query_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_session_query_readiness(text,text) TO zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_session_evidence_fingerprint', '4e72e5fbd7ba47641d5241a9392e58956c94611bcbb36de5b0341868b3a5fe33');
