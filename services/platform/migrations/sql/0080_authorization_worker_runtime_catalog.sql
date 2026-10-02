-- Preserve the effective72 precision handoff and both unchanged50 catalog
-- definitions. Only the nine explicitly changed guard bodies are projected.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal72.retained_precision_fingerprint()'::regprocedure,'public.zasp_production_runtime_sandbox_search_live_fingerprint()'::regprocedure,'public.zasp_production_runtime_sandbox_binding_live_fingerprint()'::regprocedure,'public.zasp_production_runtime_sessions_live_fingerprint()'::regprocedure);

DO $runtime_projection$ DECLARE d text;needle text;replacement text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE to_regprocedure(signature)='public.zasp_production_runtime_sessions_live_fingerprint()'::regprocedure AND owner_name='zasp_discovery_authority';
 needle:='FUNCTION public.zasp_production_runtime_sessions_live_fingerprint()';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session catalog header changed';END IF;
 d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.runtime_projected40()');
 needle:='pg_get_functiondef(procedure.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session catalog body changed';END IF;
 replacement:=$projection$CASE WHEN procedure.oid='public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure THEN(SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE to_regprocedure(signature)=procedure.oid) ELSE pg_get_functiondef(procedure.oid) END$projection$;
 EXECUTE replace(d,needle,replacement);
 -- The wrapper's live definition is independently bound through this saved
 -- predecessor OID. The runtime catalog binds the changed public writer.
 EXECUTE $wrapper$CREATE OR REPLACE FUNCTION public.zasp_production_runtime_sessions_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $body$
 SELECT CASE WHEN zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.runtime_projected40() ELSE NULL END
 $body$$wrapper$;

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE to_regprocedure(signature)='public.zasp_production_runtime_sandbox_search_live_fingerprint()'::regprocedure AND owner_name='zasp_discovery_authority';
 needle:='FUNCTION public.zasp_production_runtime_sandbox_search_live_fingerprint()';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime search catalog header changed';END IF;
 d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.runtime_projected50_search()');
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>3 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime search catalog body changed';END IF;
 replacement:=$guards$CASE WHEN p.oid IN('public.zasp_runtime_legacy_search_insert_guard()'::regprocedure,'public.zasp_runtime_sandbox_search_mutation_guard()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE to_regprocedure(signature)=p.oid) ELSE pg_get_functiondef(p.oid) END$guards$;
 EXECUTE replace(d,needle,replacement);

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE to_regprocedure(signature)='public.zasp_production_runtime_sandbox_binding_live_fingerprint()'::regprocedure AND owner_name='zasp_discovery_authority';
 needle:='FUNCTION public.zasp_production_runtime_sandbox_binding_live_fingerprint()';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime binding catalog header changed';END IF;
 d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.runtime_projected50_binding()');
 needle:='zasp_production_runtime_sandbox_search_live_fingerprint()';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime binding catalog dependency changed';END IF;
 EXECUTE replace(d,needle,'zasp_authorization80_worker.runtime_projected50_search()');

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal72.retained_precision_fingerprint()' AND owner_name='zasp_discovery_authority';
 needle:='zasp_production_runtime_sandbox_binding_live_fingerprint()';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision catalog dependency changed';END IF;
 d:=replace(d,needle,'zasp_authorization80_worker.runtime_projected50_binding()');
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision catalog bodies changed';END IF;
 replacement:=$guards$CASE WHEN p.oid IN('public.zasp_runtime_precision_batch_insert_guard()'::regprocedure,'public.zasp_runtime_precision_batch_update_guard()'::regprocedure,'public.zasp_runtime_precision_stage_insert_guard()'::regprocedure,'public.zasp_runtime_precision_claim_version_guard()'::regprocedure,'public.zasp_runtime_precision_reconciliation_guard()'::regprocedure,'public.zasp_runtime_precision_outbox_guard()'::regprocedure,'public.zasp_runtime_precision_delivery_guard()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE to_regprocedure(signature)=p.oid) ELSE pg_get_functiondef(p.oid) END$guards$;
 d:=replace(d,needle,replacement);
 -- Preserve the retained72 outbox exclusion and every original trigger row.
 -- The single new statement fence is independently pinned by the live worker
 -- and runtime catalogs, including its enabled state and private function.
 needle:='AND NOT t.tgisinternal';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision statement trigger branch changed';END IF;
 EXECUTE replace(d,needle,needle||' AND NOT(t.tgrelid=''public.zasp_runtime_stage_work''::regclass AND t.tgname=''zasp_authorization80_runtime_stage_insert'')');

 -- The existing worker projected72 reads every saved predecessor dynamically,
 -- including the just-saved retained precision function. Its body is unchanged.
 SELECT pg_get_functiondef('zasp_authorization80_worker.projected_domain()'::regprocedure) INTO STRICT d;
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime outbox catalog body changed';END IF;
 EXECUTE replace(d,needle,$guard$CASE WHEN p.oid='public.zasp_runtime_precision_outbox_guard()'::regprocedure THEN(SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE to_regprocedure(signature)=p.oid) ELSE pg_get_functiondef(p.oid) END$guard$);
END $runtime_projection$;
