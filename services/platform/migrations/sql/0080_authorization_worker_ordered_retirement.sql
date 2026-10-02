-- Fresh current-worker installation only. Historical0069 and existing installed
-- worker profiles are not replayed/upgraded by this module.
DO $ordered69_retirement$ DECLARE d text;p record;n integer:=0;BEGIN
 -- These copies must already exist and retain the original native behavior.
 PERFORM 'zasp_authorization80_worker.ordered69_inspect_inner(jsonb)'::regprocedure;
 PERFORM 'zasp_authorization80_worker.ordered69_message_inner(jsonb)'::regprocedure;
 PERFORM 'zasp_authorization80_worker.ordered69_stop_inner(jsonb)'::regprocedure;
 FOR p IN SELECT live.oid,s.definition,s.owner_name,s.acl FROM pg_proc live
  JOIN zasp_authorization80_worker.predecessor_functions s ON to_regprocedure(s.signature)=live.oid
  WHERE live.oid IN('zasp_temporal69.inspect(jsonb)'::regprocedure,'zasp_temporal69.inspect_message(jsonb)'::regprocedure,'zasp_temporal69.stop(jsonb)'::regprocedure) LOOP
  n:=n+1;
  IF p.owner_name<>'zasp_discovery_authority' OR NOT EXISTS(SELECT 1 FROM pg_proc live WHERE live.oid=p.oid AND pg_get_functiondef(live.oid)=p.definition AND live.proowner::regrole::text=p.owner_name AND COALESCE(live.proacl::text,'')=p.acl)
   OR p.acl IS DISTINCT FROM (CASE p.oid
    WHEN 'zasp_temporal69.inspect(jsonb)'::regprocedure THEN '{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}'
    WHEN 'zasp_temporal69.inspect_message(jsonb)'::regprocedure THEN '{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority}'
    WHEN 'zasp_temporal69.stop(jsonb)'::regprocedure THEN '{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}' END)
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retirement69 exact lifecycle predecessor changed';END IF;
 END LOOP;
 IF n<>3 OR (SELECT count(DISTINCT to_regprocedure(signature)) FROM zasp_authorization80_worker.predecessor_functions WHERE to_regprocedure(signature) IN('zasp_temporal69.inspect(jsonb)'::regprocedure,'zasp_temporal69.inspect_message(jsonb)'::regprocedure,'zasp_temporal69.stop(jsonb)'::regprocedure))<>3 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retirement69 predecessor set changed';END IF;
 -- Exact unchanged native69 recipe captured from the retained release. Check
 -- its complete definition/frame/ACL before trusting its returned digest.
 IF NOT EXISTS(SELECT 1 FROM pg_proc f JOIN pg_language l ON l.oid=f.prolang WHERE f.oid='zasp_temporal69.fingerprint()'::regprocedure
  AND encode(digest(convert_to(pg_get_functiondef(f.oid),'UTF8'),'sha256'),'hex')='1d91724a967194f8d876e640dd75c7bda451377e40c3143bff4934bd215dfd3c'
  AND f.proowner='zasp_discovery_authority'::regrole AND f.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}'
  AND NOT f.prosecdef AND f.provolatile='s' AND l.lanname='sql' AND f.proconfig=ARRAY['search_path=pg_catalog, public'])
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retirement69 fingerprint predecessor changed';END IF;
 IF zasp_temporal69.fingerprint() IS DISTINCT FROM '-- retirement69 original fingerprint' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retirement69 retained catalog changed';END IF;
 INSERT INTO zasp_authorization80_worker.predecessor_functions
  SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid='zasp_temporal69.fingerprint()'::regprocedure;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE to_regprocedure(signature)='zasp_temporal69.fingerprint()'::regprocedure;
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal69.fingerprint()', 'FUNCTION zasp_authorization80_worker.projected69()');
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$COALESCE(p.proacl::text,'')$old$,$new$CASE WHEN p.oid IN('zasp_temporal69.inspect(jsonb)'::regprocedure,'zasp_temporal69.inspect_message(jsonb)'::regprocedure,'zasp_temporal69.stop(jsonb)'::regprocedure) THEN(SELECT s.acl FROM zasp_authorization80_worker.predecessor_functions s WHERE to_regprocedure(s.signature)=p.oid) ELSE COALESCE(p.proacl::text,'') END$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,'pg_get_functiondef(p.oid)',$new$CASE WHEN p.oid='zasp_temporal69.fingerprint()'::regprocedure THEN(SELECT s.definition FROM zasp_authorization80_worker.predecessor_functions s WHERE to_regprocedure(s.signature)=p.oid) ELSE pg_get_functiondef(p.oid) END$new$);
 EXECUTE d;
END $ordered69_retirement$;
ALTER FUNCTION zasp_authorization80_worker.projected69() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80_worker.projected69() FROM PUBLIC;

REVOKE EXECUTE ON FUNCTION zasp_temporal69.inspect(jsonb) FROM zasp_temporal_executor,zasp_temporal_compensation;
REVOKE EXECUTE ON FUNCTION zasp_temporal69.inspect_message(jsonb) FROM zasp_temporal_executor;
REVOKE EXECUTE ON FUNCTION zasp_temporal69.stop(jsonb) FROM zasp_temporal_compensation;

-- The retained digest projects only the exact changed facts. Independent worker
-- catalog facts still bind all live target ACLs/bodies/owners, this wrapper,
-- the private recipe and every saved byte. Preserve the native invoker frame.
CREATE OR REPLACE FUNCTION zasp_temporal69.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $retirement69_gate$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')='-- worker catalog body digest' AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND l.lanname='sql' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}') AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum='-- worker profile checksum') AND zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.projected69() ELSE NULL END
$retirement69_gate$;
DO $retirement69_sealed$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid IN('zasp_temporal69.inspect(jsonb)'::regprocedure,'zasp_temporal69.inspect_message(jsonb)'::regprocedure,'zasp_temporal69.stop(jsonb)'::regprocedure,'zasp_temporal69.fingerprint()'::regprocedure,'zasp_authorization80_worker.projected69()'::regprocedure) AND(p.proowner<>'zasp_discovery_authority'::regrole OR p.proacl::text IS DISTINCT FROM '{zasp_discovery_authority=X/zasp_discovery_authority}')) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retirement69 owner-only sealing changed';END IF;
END $retirement69_sealed$;
