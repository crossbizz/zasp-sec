-- Run after the runtime ancestry module. Preserve its existing source-trigger
-- and native-body projections; extend only the live77 base recipe identity.
-- The first saved78 identity is authoritative for the enclosing worker78 view.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid='zasp_temporal78.predecessor77_fingerprint()'::regprocedure
 ON CONFLICT(signature) DO NOTHING;
DO $ordered_writer_late_catalog$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal78.predecessor77_fingerprint()'::regprocedure) INTO d;
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered effective77 identity anchors changed';
 END IF;
 EXECUTE replace(d,needle,$identity$CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN zasp_authorization80_worker.ordered_writer_definition(p.oid) ELSE pg_get_functiondef(p.oid) END$identity$);
END $ordered_writer_late_catalog$;
