DO $guard$
BEGIN
 IF NOT public.zasp_production_runtime_session_search_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=42),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_session_search_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session query prerequisite rejected';
 END IF;
END
$guard$;

-- Scope-local bounded backlog scans and a single newest checkpoint lookup.
CREATE INDEX zasp_runtime_session_query_pending_idx ON public.zasp_runtime_session_search_outbox(organization_id,workspace_id,environment_id,created_at) WHERE state IN('pending','leased');
CREATE INDEX zasp_runtime_session_query_quarantine_idx ON public.zasp_runtime_session_search_outbox(organization_id,workspace_id,environment_id,created_at) WHERE state='quarantined';
CREATE INDEX zasp_runtime_session_query_indexed_idx ON public.zasp_runtime_session_search_outbox(organization_id,workspace_id,environment_id,indexed_at DESC) WHERE state='indexed';

CREATE FUNCTION public.zasp_runtime_session_query_status(organization_value text,workspace_value text,environment_value text,principal_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $status$
DECLARE pending_value bigint;quarantined_value bigint;last_indexed_value timestamptz;oldest_pending_value timestamptz;
BEGIN
 IF NOT zasp_runtime_session_read_authorized(organization_value,workspace_value,environment_value,principal_value) THEN RETURN NULL;END IF;
 SELECT count(*),min(created_at) INTO pending_value,oldest_pending_value FROM (
  SELECT created_at FROM zasp_runtime_session_search_outbox WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND state IN('pending','leased') ORDER BY created_at LIMIT 1001
 ) pending;
 SELECT count(*) INTO quarantined_value FROM (
  SELECT created_at FROM zasp_runtime_session_search_outbox WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND state='quarantined' ORDER BY created_at LIMIT 1001
 ) quarantined;
 SELECT indexed_at INTO last_indexed_value FROM zasp_runtime_session_search_outbox WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND state='indexed' ORDER BY indexed_at DESC LIMIT 1;
 RETURN jsonb_build_object('state',CASE WHEN quarantined_value>0 THEN 'blocked' WHEN pending_value>0 THEN 'catching_up' WHEN last_indexed_value IS NULL THEN 'empty' ELSE 'current' END,
 'pending_batches',least(pending_value,1000),'pending_batches_capped',pending_value>1000,'quarantined_batches',least(quarantined_value,1000),'quarantined_batches_capped',quarantined_value>1000,
 'last_indexed_at',last_indexed_value,'oldest_pending_at',oldest_pending_value,'checked_at',statement_timestamp(),'selector_coverage','observed_only');
END
$status$;

CREATE FUNCTION public.zasp_runtime_session_query_hydrate(organization_value text,workspace_value text,environment_value text,principal_value text,ids_value text[]) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $hydrate$
DECLARE status_value jsonb;items_value jsonb;actual_ids text[];
BEGIN
 IF ids_value IS NULL OR cardinality(ids_value)>101 OR array_ndims(ids_value)>1
 OR EXISTS(SELECT 1 FROM unnest(ids_value) id WHERE id IS NULL OR (id<>'unattributed' AND NOT zasp_valid_product_id(id)))
 OR ids_value IS DISTINCT FROM ARRAY(SELECT DISTINCT id FROM unnest(ids_value) id ORDER BY id) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session candidates rejected';
 END IF;
 status_value:=zasp_runtime_session_query_status(organization_value,workspace_value,environment_value,principal_value);
 IF status_value IS NULL THEN RETURN NULL;END IF;
 SELECT COALESCE(jsonb_agg(zasp_runtime_session_summary_json(summary_value) ORDER BY id),'[]'::jsonb),COALESCE(array_agg(id ORDER BY id),'{}'::text[])
 INTO items_value,actual_ids FROM zasp_runtime_session_summaries summary_value
 WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND id=ANY(ids_value);
 IF actual_ids IS DISTINCT FROM ids_value THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session candidates unavailable';END IF;
 RETURN jsonb_build_object('items',items_value,'search',status_value);
END
$hydrate$;
ALTER FUNCTION public.zasp_runtime_session_query_status(text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_session_query_hydrate(text,text,text,text,text[]) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_session_query_status(text,text,text,text),public.zasp_runtime_session_query_hydrate(text,text,text,text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_session_query_status(text,text,text,text),public.zasp_runtime_session_query_hydrate(text,text,text,text,text[]) TO zasp_discovery_api;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 42','later_release."version" > 43'),'later."version">42','later."version">43'),'later."version" > 42','later."version" > 43');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session query compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_runtime_session_query_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_runtime_session_search_security_ready()
 AND (SELECT count(*)=2 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_session_query_status','zasp_runtime_session_query_hydrate'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_session_query_status','zasp_runtime_session_query_hydrate')
 AND (procedure.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure.prosecdef OR NOT COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public']
 OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee NOT IN(procedure.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api')))))
$security$;
CREATE FUNCTION public.zasp_production_runtime_session_query_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_session_search_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_session_query_status','zasp_runtime_session_query_hydrate','zasp_production_runtime_session_query_readiness','zasp_production_runtime_session_query_security_ready')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_session_query_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=43 AND name='production_runtime_session_query' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>43) AND zasp_production_runtime_session_query_security_ready() AND zasp_production_runtime_session_query_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_session_query_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_session_query_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_session_query_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_session_query_security_ready(),public.zasp_production_runtime_session_query_live_fingerprint(),public.zasp_production_runtime_session_query_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_session_query_readiness(text,text) TO zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;

ALTER FUNCTION public.zasp_production_runtime_session_search_readiness(text,text) RENAME TO zasp_production_runtime_session_search_readiness_v42;
CREATE FUNCTION public.zasp_production_runtime_session_search_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=42 AND name='production_runtime_session_search' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_session_search_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_session_query_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=43),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_session_query_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_runtime_session_search_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_session_search_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_session_search_readiness(text,text) TO zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_session_query_fingerprint', '8eb43aee1ab876b49caa65fd6cc5bffd8e24c8aa90d5ce0690bc02339f95fda1');
