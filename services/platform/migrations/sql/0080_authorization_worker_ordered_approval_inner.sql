-- The public decide_resource call retains its complete readiness fences before
-- and after all nested work. These fixed, owner-only decide copies share that
-- bracket; no other caller, operation, mutable cache or skip flag is admitted.
DO $ordered_approval_inner$ DECLARE d text;outer_definition text;mutate_definition text;needle text;expected62 text;p regprocedure;BEGIN
 SELECT pg_get_functiondef(oid) INTO STRICT outer_definition FROM pg_proc
 WHERE oid='zasp_ordered_public62.api(text,text,jsonb)'::regprocedure AND proowner='zasp_discovery_authority'::regrole
 AND proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_api=X/zasp_discovery_authority}';
 SELECT pg_get_functiondef(oid) INTO STRICT mutate_definition FROM pg_proc
 WHERE oid='zasp_ordered_public62.mutate(text,text,jsonb)'::regprocedure AND proowner='zasp_discovery_authority'::regrole
 AND proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}';
 -- These are the already fenced bodies created immediately before this module,
 -- not historical bare62 copies. The saved originals stay unchanged for67.
 IF position('zasp_authorization80_worker.require_ordered62_approval(q,true)' IN outer_definition)=0
 OR position('zasp_authorization80_worker.require_ordered62_approval(q,false)' IN outer_definition)=0
 OR position('zasp_authorization80_worker.require_ordered62_approval(q,true)' IN mutate_definition)=0
 OR position('zasp_authorization80_worker.require_ordered62_approval(q,false)' IN mutate_definition)=0
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered approval fenced predecessor absent';END IF;
 expected62:=zasp_authorization80_worker.projected62();
 IF expected62 IS NULL OR expected62!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered approval projected identity absent';END IF;
 SELECT pg_get_functiondef(oid) INTO STRICT d FROM pg_proc WHERE oid='zasp_ordered_public62.ready(text,text)'::regprocedure
 AND proowner='zasp_discovery_authority'::regrole AND proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}';
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_ordered_public62.ready(','FUNCTION zasp_authorization80_worker.ordered62_inner_ready(');
 -- Native67's effective ready body has compiled62 argument pins and delegates
 -- to67.current_ready. The latter remains at both ends of the public call.
 d:=zasp_authorization80_worker.ordered62_replace(d,' AND zasp_temporal67.current_ready()',
 ' AND zasp_authorization80_worker.catalog_ready() AND (SELECT count(*)=1 FROM zasp_ordered_public62.registration) AND EXISTS(SELECT 1 FROM zasp_ordered_public62.registration WHERE singleton AND checksum=c AND fingerprint=f) AND zasp_authorization80_worker.projected62()='||quote_literal(expected62));
 EXECUTE d;

 d:=zasp_authorization80_worker.ordered62_replace(mutate_definition,'FUNCTION zasp_ordered_public62.mutate(','FUNCTION zasp_authorization80_worker.ordered62_mutate_inner(');
 d:=zasp_authorization80_worker.ordered62_replace(d,E'BEGIN\n',E'BEGIN\n IF q->>''operation'' IS DISTINCT FROM ''decide'' THEN RAISE EXCEPTION USING ERRCODE=''22023'',MESSAGE=''private ordered approval operation rejected'';END IF;\n');
 IF (length(d)-length(replace(d,'zasp_ordered_public62.ready(c,f)','')))/length('zasp_ordered_public62.ready(c,f)')<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered approval mutation readiness count changed';END IF;
 d:=replace(d,'zasp_ordered_public62.ready(c,f)','zasp_authorization80_worker.ordered62_inner_ready(c,f)');
 EXECUTE d;

 d:=zasp_authorization80_worker.ordered62_replace(outer_definition,'FUNCTION zasp_ordered_public62.api(','FUNCTION zasp_authorization80_worker.ordered62_decide_inner(');
 d:=zasp_authorization80_worker.ordered62_replace(d,E'BEGIN\n',E'BEGIN\n IF q->>''operation'' IS DISTINCT FROM ''decide'' THEN RAISE EXCEPTION USING ERRCODE=''22023'',MESSAGE=''private ordered approval operation rejected'';END IF;\n');
 needle:=$entry$ IF NOT COALESCE(zasp_ordered_public62.ready(c,f),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public ordered release unavailable';END IF;$entry$;
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,replace(needle,'zasp_ordered_public62.ready(c,f)','zasp_authorization80_worker.ordered62_inner_ready(c,f)'));
 needle:=$exit$ IF result_value IS NULL OR octet_length(result_value::text)>65536 OR NOT zasp_ordered_public62.ready(c,f) OR NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered authority changed';END IF;$exit$;
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,replace(needle,'zasp_ordered_public62.ready(c,f)','zasp_authorization80_worker.ordered62_inner_ready(c,f)'));
 needle:=$mutate$ ELSIF op IN('decide','cancel') THEN result_value:=zasp_ordered_public62.mutate(c,f,q);$mutate$;
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,replace(needle,'zasp_ordered_public62.mutate(c,f,q)','zasp_authorization80_worker.ordered62_mutate_inner(c,f,q)'));
 EXECUTE d;

 -- Only this complete branch has already checked the outer resource request;
 -- trigger recursion and public direct decide/cancel remain untouched.
 needle:=$caller$  inner_result:=zasp_ordered_public62.api(c,f,inner_q);
  result_value:=jsonb_build_object('mutation',inner_result,'resource',zasp_ordered_public62.resource_run(o,w,e,approval_row.run_id));$caller$;
 EXECUTE zasp_authorization80_worker.ordered62_replace(outer_definition,needle,replace(needle,'zasp_ordered_public62.api(c,f,inner_q)','zasp_authorization80_worker.ordered62_decide_inner(c,f,inner_q)'));
 FOREACH p IN ARRAY ARRAY['zasp_authorization80_worker.ordered62_inner_ready(text,text)'::regprocedure,'zasp_authorization80_worker.ordered62_mutate_inner(text,text,jsonb)'::regprocedure,'zasp_authorization80_worker.ordered62_decide_inner(text,text,jsonb)'::regprocedure] LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p);
 END LOOP;
END $ordered_approval_inner$;
