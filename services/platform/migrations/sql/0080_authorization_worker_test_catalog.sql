-- Exact effective predecessor projections.76 already projects its own changed
-- helper through78, so its fingerprint wrapper stays byte-for-byte unchanged.
DO $test_boundaries$ DECLARE d text;p record;needle text:=E'BEGIN\n';op text;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN('zasp_temporal74.plan(jsonb)','zasp_temporal74.planning_state(jsonb)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' OR(length(p.definition)-length(replace(p.definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker74 planning predecessor rejected';END IF;
  op:=CASE p.signature WHEN 'zasp_temporal74.plan(jsonb)' THEN 'q->>''operation''' ELSE '''state''' END;
  d:=replace(p.definition,needle,needle||' PERFORM zasp_authorization80_worker.require_planning74('||op||',q);'||E'\n');
  IF p.signature='zasp_temporal74.plan(jsonb)' THEN
   FOREACH op IN ARRAY ARRAY['recover_plan','record_late_usage'] LOOP
    IF(length(d)-length(replace(d,'RETURN zasp_temporal74.'||op||'(q);','')))/length('RETURN zasp_temporal74.'||op||'(q);')<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker74 recovery predecessor rejected';END IF;
    d:=replace(d,'RETURN zasp_temporal74.'||op||'(q);','RETURN zasp_authorization80_worker.planning74_recovery_result(zasp_temporal74.'||op||'(q));');
   END LOOP;
  END IF;
  EXECUTE d;
 END LOOP;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal74.serialize_revocation()';
 needle:=' RETURN NEW;';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker74 revocation predecessor rejected';END IF;
 EXECUTE replace(d,needle,' PERFORM zasp_authorization80_worker.capture_test_revocation(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,NEW.definition_version);'||E'\n'||needle);

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_authorization79.pending(integer)';
 needle:='WHERE desired<>applied ORDER BY';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker expiry queue predecessor rejected';END IF;
 EXECUTE replace(d,needle,'WHERE desired<>applied OR EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_state s WHERE s.organization_id=zasp_authorization79.organizations.organization_id AND s.target_current AND s.fresh_until<=clock_timestamp()) ORDER BY');
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_authorization79.snapshot(text)';
 needle:=$old$ IF EXISTS(SELECT 1 FROM public.zasp_environments WHERE organization_id=o GROUP BY id HAVING count(*)>1)$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker expiry snapshot predecessor rejected';END IF;
 EXECUTE replace(d,needle,' PERFORM zasp_authorization80_worker.expire_test_targets(o);'||E'\n'||needle);

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_authorization80_temporal.projected68()';
 d:=replace(d,'FUNCTION zasp_authorization80_temporal.projected68()', 'FUNCTION zasp_authorization80_worker.projected68()');
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker68 fingerprint predecessor rejected';END IF;
 EXECUTE replace(d,needle,$projection$CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal76.executor74_fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal76.executor74_fingerprint()', 'FUNCTION zasp_authorization80_worker.projected74()');
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>4 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker74 fingerprint predecessor rejected';END IF;
 EXECUTE replace(d,needle,$projection$CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_authorization80_temporal.projected_domain()';
 d:=replace(d,'FUNCTION zasp_authorization80_temporal.projected_domain()', 'FUNCTION zasp_authorization80_worker.projected_domain()');
 needle:='WHERE NOT t.tgisinternal AND NOT(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker target domain predecessor rejected';END IF;
 EXECUTE replace(d,needle,$projection$WHERE NOT t.tgisinternal AND NOT(t.tgname IN('zasp_authorization80_worker_target_capture','zasp_authorization80_worker_target_no_truncate') AND t.tgrelid IN('public.zasp_inventory_entities'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_source_observations'::regclass)) AND NOT($projection$);

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_authorization80_temporal.fingerprint()';
 d:=replace(d,'FUNCTION zasp_authorization80_temporal.fingerprint()', 'FUNCTION zasp_authorization80_worker.projected_temporal_profile()');
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker temporal profile predecessor rejected';END IF;
 EXECUTE replace(d,needle,$projection$CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);
END $test_boundaries$;
CREATE OR REPLACE FUNCTION zasp_temporal76.executor74_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $test_gate$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')='-- worker catalog body digest' AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND l.lanname='sql' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}') AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum='-- worker profile checksum') AND zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.projected74() ELSE NULL END
$test_gate$;
CREATE OR REPLACE FUNCTION zasp_authorization80_temporal.projected68() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $planner_gate$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')='-- worker catalog body digest' AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND l.lanname='sql' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}') AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum='-- worker profile checksum') AND zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.projected68() ELSE NULL END
$planner_gate$;
CREATE OR REPLACE FUNCTION zasp_authorization80_temporal.projected_domain() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $domain_gate$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')='-- worker catalog body digest' AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND l.lanname='sql' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}') AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum='-- worker profile checksum') AND zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.projected_domain() ELSE NULL END
$domain_gate$;
CREATE OR REPLACE FUNCTION zasp_authorization80_temporal.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $temporal_gate$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')='-- worker catalog body digest' AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND l.lanname='sql' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}') AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum='-- worker profile checksum') AND zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.projected_temporal_profile() ELSE NULL END
$temporal_gate$;
