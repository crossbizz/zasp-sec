-- Extend the effective projections after other installed worker families, not
-- their older saved bodies. Live replacements and these exact triggers remain
-- independently included in the worker fingerprint.
DO $ordered_catalog$ DECLARE d text;needle text;replacement text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.projected_domain()'::regprocedure) INTO d;
 needle:='WHERE NOT t.tgisinternal AND NOT(';
 replacement:=$triggers$WHERE NOT t.tgisinternal AND NOT(t.tgrelid IN('public.zasp_inventory_entities'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_source_observations'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_target','zasp_authorization80_worker_ordered_no_truncate')) AND NOT($triggers$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered target catalog predecessor changed';END IF;
 EXECUTE replace(d,needle,replacement);
 SELECT pg_get_functiondef('zasp_authorization79.pending(integer)'::regprocedure) INTO d;
 needle:=' ORDER BY COALESCE(last_attempt_at,pending_since)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered expiry queue predecessor changed';END IF;
 EXECUTE replace(d,needle,' OR EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_state s WHERE s.organization_id=zasp_authorization79.organizations.organization_id AND s.target_current AND s.fresh_until<=clock_timestamp())'||needle);
 SELECT pg_get_functiondef('zasp_authorization79.snapshot(text)'::regprocedure) INTO d;
 needle:=$old$ IF EXISTS(SELECT 1 FROM public.zasp_environments WHERE organization_id=o GROUP BY id HAVING count(*)>1)$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered expiry snapshot predecessor changed';END IF;
 EXECUTE replace(d,needle,' PERFORM zasp_authorization80_worker.expire_ordered_targets(o);'||E'\n'||needle);
END $ordered_catalog$;
