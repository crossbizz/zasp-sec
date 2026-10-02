-- Exactly one policy compiler and the two fingerprint views needed to project
-- that change. Every other predecessor object remains live and unnormalized.
INSERT INTO zasp_temporal77.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'::regprocedure,'zasp_temporal67.base_fingerprint()'::regprocedure,'zasp_temporal67.fingerprint()'::regprocedure);
DO $compiler$ DECLARE d text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal77.predecessor_functions WHERE signature='zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'
  AND owner_name='zasp_discovery_authority' AND acl='{zasp_discovery_authority=X/zasp_discovery_authority}'
  AND encode(digest(convert_to(definition,'UTF8'),'sha256'),'hex')='26cafd835aeb6e7203b913753d39cf9390c29cb6a20594edc637db862d3f9767';
 EXECUTE replace(d,'FUNCTION zasp_sa_multistep_prior.deployment_compile(', 'FUNCTION zasp_temporal77.legacy_deployment_compile(');
END $compiler$;
CREATE FUNCTION zasp_temporal77.deployment_compile(p jsonb,persistent boolean) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $compile$
DECLARE result_value jsonb;
BEGIN
 IF NOT p ? 'risk' THEN RETURN zasp_temporal77.legacy_deployment_compile(p,persistent);END IF;
 IF jsonb_typeof(p->'risk') IS DISTINCT FROM 'string' OR NOT COALESCE(p->>'risk' IN('low','medium','high','critical'),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='policy risk annotation rejected';END IF;
 result_value:=zasp_temporal77.legacy_deployment_compile(p-'risk',persistent);
 IF result_value IS NULL THEN RETURN NULL;END IF;
 -- NUL bytes are part of the Go hash contract but cannot appear in PostgreSQL
 -- text. Concatenate bytea, not chr(0) or an escaped text approximation.
 RETURN result_value||jsonb_build_object('risk',p->>'risk','digest',encode(digest(convert_to(result_value->>'rego','UTF8')||decode('00','hex')||convert_to('policy-risk-v1','UTF8')||decode('00','hex')||convert_to(p->>'risk','UTF8'),'sha256'),'hex'));
END $compile$;
CREATE OR REPLACE FUNCTION zasp_sa_multistep_prior.deployment_compile(p jsonb,persistent boolean) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $compile$
 SELECT zasp_temporal77.deployment_compile(p,persistent)
$compile$;

DO $projection$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal77.predecessor_functions WHERE signature='zasp_temporal67.base_fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal67.base_fingerprint()', 'FUNCTION zasp_temporal77.base67_fingerprint()');
 needle:='public.zasp_sa_multistep_function_identity(p.oid)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'automatic policy base projection predecessor changed';END IF;
 EXECUTE replace(d,needle,$new$CASE WHEN p.oid='zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'::regprocedure THEN (SELECT definition FROM zasp_temporal77.predecessor_functions WHERE signature='zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)') ELSE public.zasp_sa_multistep_function_identity(p.oid) END$new$);
 SELECT definition INTO STRICT d FROM zasp_temporal77.predecessor_functions WHERE signature='zasp_temporal67.fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal67.fingerprint()', 'FUNCTION zasp_temporal77.domain67_fingerprint()');
 needle:='pg_get_functiondef(p.oid)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'automatic policy domain projection predecessor changed';END IF;
 EXECUTE replace(d,needle,$new$CASE WHEN p.oid IN('zasp_temporal67.base_fingerprint()'::regprocedure,'zasp_temporal67.fingerprint()'::regprocedure) THEN (SELECT definition FROM zasp_temporal77.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$new$);
END $projection$;
CREATE OR REPLACE FUNCTION zasp_temporal67.base_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_temporal77.catalog_ready() THEN zasp_temporal77.base67_fingerprint() ELSE NULL END
$fingerprint$;
CREATE OR REPLACE FUNCTION zasp_temporal67.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_temporal77.catalog_ready() THEN zasp_temporal77.domain67_fingerprint() ELSE NULL END
$fingerprint$;
