-- Precise completion draft. No activation or worker grants.
-- The registered precision migration must replace inherited schema50 readiness
-- with its complete fingerprint and install compatible search enqueue routing.
DO $precise_completion$
DECLARE definition text; needle text; replacement text; expected integer;
BEGIN
 IF NOT COALESCE(public.zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=50),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precise completion predecessor unavailable';
 END IF;
 SELECT pg_get_functiondef('public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure) INTO STRICT definition;
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  ('FUNCTION public.zasp_runtime_finish_sandbox_session_projection(', 'FUNCTION public.zasp_runtime_finish_precise_session_projection(', 1),
  ('''runtime-complete-v2''', '''runtime-complete-v3''', 2),
  ('''runtime-projection-v2''', '''runtime-projection-v3''', 2),
  ('''runtime-projection-receipt-v2''', '''runtime-projection-receipt-v3''', 1),
  ('  event_value.sandbox_id:=', '  IF item->>''source'' IS DISTINCT FROM ''tetragon'' OR item->>''confidence''=''exact'' THEN RAISE EXCEPTION USING ERRCODE=''22023'',MESSAGE=''runtime precise session source rejected'';END IF;'||chr(10)||'  event_value.sandbox_id:=', 1)
 ) AS changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precise completion predecessor rejected';END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 EXECUTE definition;
END
$precise_completion$;
ALTER FUNCTION public.zasp_runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) FROM PUBLIC;
