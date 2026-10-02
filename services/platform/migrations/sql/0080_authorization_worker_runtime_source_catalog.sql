-- The two77 source relations are immutable native evidence. Project only the
-- four added trigger rows from the exact effective predecessor catalog.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal78.predecessor77_fingerprint()'::regprocedure,'zasp_temporal78.predecessor76_fingerprint()'::regprocedure);
DO $runtime_source_catalog$ DECLARE d text;needle text;BEGIN
 --76 independently measures the effective74 entry bodies. Its catalog gates
 --74, which in turn gates the retained65/66 identities used below68. Preserve
 --exactly these four prior bodies; live owner/ACL facts remain unchanged and
 --the worker catalog independently measures every saved signature's live body.
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal78.predecessor76_fingerprint()';
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime76 executor body catalog changed';END IF;
 EXECUTE replace(d,needle,$new$CASE WHEN p.oid IN('zasp_temporal74.takeover(text,text,text,text)'::regprocedure,'zasp_temporal74.context(text,text,text,text)'::regprocedure,'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure,'zasp_temporal74.load_plan(jsonb)'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$new$);

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal78.predecessor77_fingerprint()';
 needle:=$old$WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal77'::regnamespace$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime77 source trigger catalog changed';END IF;
 d:=replace(d,needle,needle||$new$ AND NOT(t.tgrelid IN('zasp_temporal77.runtime_evaluations'::regclass,'zasp_temporal77.source_events'::regclass) AND t.tgname IN('zasp_authorization80_worker_runtime_capture','zasp_authorization80_worker_runtime_no_truncate'))$new$);
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime77 source writer catalog changed';END IF;
 EXECUTE replace(d,needle,$new$CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$new$);
END $runtime_source_catalog$;
