-- Current runtime consumer module. The composing installer verifies the full
-- predecessor before reading source and binds the retained catalog handoff.
-- Source15 gives this table only authority-owned access and its one authority
-- policy. Reject inherited drift before registering the live permission facts.
-- Hold the table lock through registration so concurrent DDL cannot replace the
-- admitted baseline between this check and the catalog pin.
DO $stage_baseline$
BEGIN
 LOCK TABLE public.zasp_runtime_stage_work IN ACCESS EXCLUSIVE MODE;
 IF NOT EXISTS(
  SELECT 1 FROM pg_class c WHERE c.oid='public.zasp_runtime_stage_work'::regclass
  AND c.relkind='r' AND c.relowner='zasp_discovery_authority'::regrole
  AND c.relrowsecurity AND c.relforcerowsecurity
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>c.relowner OR a.grantor<>c.relowner)
  AND NOT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) p WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND(p.grantee<>c.relowner OR p.grantor<>c.relowner))
  AND (SELECT count(*)=1 FROM pg_policy p WHERE p.polrelid=c.oid)
  AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid
   AND p.polname='zasp_runtime_stage_work_authority' AND p.polpermissive AND p.polcmd='*'
   AND p.polroles=ARRAY['zasp_discovery_authority'::regrole::oid]
   AND pg_get_expr(p.polqual,p.polrelid)='true' AND pg_get_expr(p.polwithcheck,p.polrelid)='true')
 ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime stage permission baseline rejected';END IF;
END $stage_baseline$;
CREATE SCHEMA zasp_authorization80_runtime AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_authorization80_runtime FROM PUBLIC;
CREATE TABLE zasp_authorization80_runtime.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_authorization80_runtime.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions'] LOOP
  EXECUTE format('ALTER TABLE zasp_authorization80_runtime.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_runtime.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_runtime.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_authorization80_runtime.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_runtime.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;

CREATE FUNCTION zasp_authorization80_runtime.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $runtime_fingerprint$
 WITH facts(v) AS(
 SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,nspacl::text) FROM pg_namespace WHERE nspname='zasp_authorization80_runtime'
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner::regrole::text,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_runtime'::regnamespace OR p.oid IN(SELECT to_regprocedure(signature) FROM zasp_authorization80_runtime.predecessor_functions WHERE signature LIKE '%guard()') OR p.oid='public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',p.polrelid::regclass::text,p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND(c.relnamespace='zasp_authorization80_runtime'::regnamespace OR t.tgfoid IN(SELECT to_regprocedure(signature) FROM zasp_authorization80_runtime.predecessor_functions WHERE signature LIKE '%guard()'))
 UNION ALL SELECT concat_ws('|','stage-insert-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_authorization80_runtime_stage_insert'
 UNION ALL SELECT concat_ws('|','stage-table',c.oid::regclass::text,c.relkind,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.oid='public.zasp_runtime_stage_work'::regclass
 UNION ALL SELECT concat_ws('|','stage-column-acl',a.attnum,a.attname,a.attacl::text) FROM pg_attribute a WHERE a.attrelid='public.zasp_runtime_stage_work'::regclass AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','stage-policy',p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p WHERE p.polrelid='public.zasp_runtime_stage_work'::regclass
 UNION ALL SELECT concat_ws('|','saved',signature,definition,owner_name,acl) FROM zasp_authorization80_runtime.predecessor_functions
 ) SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$runtime_fingerprint$;
CREATE FUNCTION zasp_authorization80_runtime.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $runtime_catalog$
 SELECT COALESCE((SELECT count(*)=1 FROM zasp_authorization80_runtime.registration) AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE checksum='-- runtime profile checksum' AND fingerprint=zasp_authorization80_runtime.fingerprint()),false)
$runtime_catalog$;
CREATE FUNCTION zasp_authorization80_runtime.current_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $current$
 -- The full78 chain reaches68.ready and the composed temporal catalog. That
 -- catalog checks80/79 registration and live fingerprints, profile and audit;
 -- public61 is the already-checked68 predicate. Their exact bodies/ACLs remain
 -- pinned by those catalogs. Only80's identity predicate is independent.
 -- Each entry/exit invocation re-evaluates this expression, without a cache.
 SELECT COALESCE(zasp_temporal78.current_ready() AND zasp_authorization80.runtime_identity_ready(),false)
$current$;
CREATE FUNCTION zasp_authorization80_runtime.ready(c text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- runtime profile checksum' AND zasp_authorization80_runtime.current_ready() AND CASE
 WHEN r IN('zasp_runtime_ingest','zasp_outbox_worker') THEN public.zasp_discovery_principal_ready(r)
 WHEN r IN('zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker') THEN public.zasp_runtime_principal_ready(r)
 ELSE false END,false)
$ready$;
-- Application pin/own-login preflight only, never a health or mutation gate.
-- Each consuming native entry retains its full current entry/exit checks.
CREATE FUNCTION zasp_authorization80_runtime.ingest_profile_identity(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ingest_identity$
 SELECT COALESCE(c='-- runtime profile checksum'
 AND (SELECT count(*)=1 FROM zasp_authorization80_runtime.registration)
 AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum=c)
 AND public.zasp_discovery_principal_ready('zasp_runtime_ingest'),false)
$ingest_identity$;
CREATE FUNCTION zasp_authorization80_runtime.require_current() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $require$
BEGIN
 IF NOT zasp_authorization80_runtime.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='current runtime profile unavailable';END IF;
END $require$;
CREATE FUNCTION zasp_authorization80_runtime.source_ready(v integer,c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $source$
 SELECT COALESCE(v IN(48,50,51)
 AND c=CASE v WHEN 48 THEN '-- runtime source48 checksum' WHEN 50 THEN '-- runtime source50 checksum' WHEN 51 THEN '-- runtime source51 checksum' END
 AND f=CASE v WHEN 48 THEN '-- runtime source48 fingerprint' WHEN 50 THEN '-- runtime source50 fingerprint' WHEN 51 THEN '-- runtime source51 fingerprint' END
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=v AND checksum=c AND name=CASE v WHEN 48 THEN 'production_runtime_acceptance' WHEN 50 THEN 'production_runtime_sandbox_binding' WHEN 51 THEN 'production_runtime_precision' END)
 -- Release48 records its checksum in schema_versions, not schema_metadata.
 AND (v=48 OR EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key=CASE v WHEN 50 THEN 'production_runtime_sandbox_binding_checksum' WHEN 51 THEN 'production_runtime_precision_checksum' END AND value=c))
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key=CASE v WHEN 48 THEN 'production_runtime_acceptance_fingerprint' WHEN 50 THEN 'production_runtime_sandbox_binding_fingerprint' WHEN 51 THEN 'production_runtime_precision_fingerprint' END AND value=f)
 AND zasp_authorization80_runtime.current_ready(),false)
$source$;

-- Only these installed source identities can enter the current namespace.
INSERT INTO zasp_authorization80_runtime.predecessor_functions
 SELECT p.oid::regprocedure::text,pg_get_functiondef(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,'') FROM pg_proc p WHERE p.oid IN(
 'public.zasp_runtime_authenticate_sensor(bytea,bytea,text)'::regprocedure,
 'public.zasp_runtime_sensor_heartbeat(bytea,bytea,text,bigint,text,jsonb,text,boolean,bigint,bigint)'::regprocedure,
 'public.zasp_runtime_reserve_batch_v17(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer)'::regprocedure,
 'public.zasp_runtime_reserve_batch_v15_internal(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer)'::regprocedure,
 'public.zasp_runtime_finalize_batch_v17(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text)'::regprocedure,
 'public.zasp_runtime_finalize_batch_v15_internal(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text)'::regprocedure,
 'public.zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text)'::regprocedure,
 'public.zasp_runtime_reconcile_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text)'::regprocedure,
 'public.zasp_runtime_lookup_acceptance(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer,text,text,text,text)'::regprocedure,
 'public.zasp_runtime_claim_reconciliation_v2(text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_precision_claim_reconciliation(text,text,integer,integer,boolean)'::regprocedure,
 'public.zasp_runtime_precision_reconciliation_ready()'::regprocedure,
 'public.zasp_runtime_release_reconciliation(text,text,text,text,bigint,text,text,integer,text)'::regprocedure,
 'public.zasp_runtime_finish_reconciliation(text,text,text,text,bigint,text,text,text,text,text,text,text,bytea,bigint,text)'::regprocedure,
 'public.zasp_runtime_quarantine_reconciliation(text,text,text,text,bigint,text,text)'::regprocedure,
 'public.zasp_runtime_claim_outbox_v2(text,text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_precision_claim_outbox(text,text,text,integer,integer,boolean)'::regprocedure,
 'public.zasp_runtime_precision_transport_ready()'::regprocedure,
 'public.zasp_runtime_heartbeat_outbox(text,text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_ack_outbox(text,text,text,text,text,text,text,text)'::regprocedure,
 'public.zasp_runtime_retry_outbox(text,text,text,text,text,text,text,integer,text)'::regprocedure,
 'public.zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_heartbeat_delivery(text,text,text,text,bigint,text,bytea,text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_release_delivery(text,text,text,text,bigint,text,bytea,text,text,text,text)'::regprocedure,
 'public.zasp_runtime_ack_delivery(text,text,text,text,bigint,text,bytea,text,text,bytea)'::regprocedure,
 'public.zasp_runtime_claim_archive_v2(text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_claim_index_v2(text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_claim_correlation_v4(text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_claim_projection_v3(text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_claim_completion_v3(text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_claim_stage_precision_compatible(text,text,integer,integer,text)'::regprocedure,
 'public.zasp_runtime_heartbeat_stage(text,text,text,text,bigint,text,text,integer)'::regprocedure,
 'public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer)'::regprocedure,
 'public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure,
 'public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure,
 'public.zasp_runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure,
 'public.zasp_runtime_freeze_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)'::regprocedure,
 'public.zasp_runtime_freeze_sandbox_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)'::regprocedure,
 'public.zasp_runtime_freeze_precise_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)'::regprocedure,
 'public.zasp_runtime_sandbox_search_worker_ready()'::regprocedure,
 'public.zasp_runtime_precise_search_claim(text,text,integer)'::regprocedure,
 'public.zasp_runtime_sandbox_search_heartbeat(text,text,text,text,bigint,text,text,integer,integer)'::regprocedure,
 'public.zasp_runtime_sandbox_search_finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer)'::regprocedure);

DO $clone$ DECLARE p record;callee record;d text;n text;needle text;fence text;return_count integer;BEGIN
 IF(SELECT count(*) FROM zasp_authorization80_runtime.predecessor_functions)<>43 OR EXISTS(SELECT 1 FROM zasp_authorization80_runtime.predecessor_functions WHERE owner_name<>'zasp_discovery_authority') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='current runtime source manifest rejected';END IF;
 -- SQL-language claim wrappers resolve their private helper at CREATE time.
 -- The other copied bodies are PL/pgSQL and keep their original validation.
 FOR p IN SELECT saved.*,l.lanname FROM zasp_authorization80_runtime.predecessor_functions saved JOIN pg_proc f ON f.oid=to_regprocedure(saved.signature) JOIN pg_language l ON l.oid=f.prolang ORDER BY signature LIKE '%runtime_claim_reconciliation_v2(%' OR signature LIKE '%runtime_claim_outbox_v2(%',signature LOOP
  n:=split_part(replace(p.signature,'public.',''),'(',1);d:=p.definition;
  needle:='FUNCTION public.'||n||'(';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='current runtime source header rejected';END IF;
  d:=replace(d,needle,'FUNCTION zasp_authorization80_runtime.'||substr(n,6)||'(');
  FOR callee IN SELECT split_part(replace(signature,'public.',''),'(',1) name FROM zasp_authorization80_runtime.predecessor_functions LOOP
   d:=replace(d,'public.'||callee.name||'(','zasp_authorization80_runtime.'||substr(callee.name,6)||'(');
   d:=replace(d,callee.name||'(','zasp_authorization80_runtime.'||substr(callee.name,6)||'(');
  END LOOP;
  IF n='zasp_runtime_lookup_acceptance' THEN
   needle:='zasp_production_runtime_acceptance_readiness(';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='current runtime acceptance gates rejected';END IF;
   d:=replace(d,needle,'zasp_authorization80_runtime.source_ready(48,');
  END IF;
  d:=replace(d,'public.zasp_production_runtime_precision_readiness(','zasp_authorization80_runtime.source_ready(51,');
  d:=replace(d,'zasp_production_runtime_precision_readiness(','zasp_authorization80_runtime.source_ready(51,');
  d:=replace(d,'public.zasp_production_runtime_sandbox_binding_readiness(','zasp_authorization80_runtime.source_ready(50,');
  d:=replace(d,'zasp_production_runtime_sandbox_binding_readiness(','zasp_authorization80_runtime.source_ready(50,');
  -- Preserve the source's post-lock checks. Entry and return fences also cover
  -- old receipt versions whose predecessor had no release gate of its own.
  IF p.lanname='plpgsql' THEN
   IF regexp_count(d,'\mBEGIN\M')<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='current runtime entry shape rejected';END IF;
   return_count:=regexp_count(d,'\mRETURN\M');
   fence:=E' PERFORM zasp_authorization80_runtime.require_current();\n';
   -- Every credential-bearing entry calls this leaf. Service-role membership
   -- alone, including the migration authority, is not a registered ingest login.
   IF n='zasp_runtime_authenticate_sensor' THEN
    fence:=fence||E' IF NOT public.zasp_discovery_principal_ready(''zasp_runtime_ingest'') THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''current runtime ingest principal rejected'';END IF;\n';
   END IF;
   d:=regexp_replace(d,'\mBEGIN\M',E'BEGIN\n'||fence);
   d:=regexp_replace(d,'\mRETURN\M',fence||' RETURN','g');
   needle:='PERFORM zasp_authorization80_runtime.require_current();';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>return_count+1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='current runtime return shape rejected';END IF;
  ELSIF p.lanname<>'sql' OR n NOT IN('zasp_runtime_claim_reconciliation_v2','zasp_runtime_claim_outbox_v2') THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='current runtime wrapper shape rejected';
  END IF;
  EXECUTE d;
 END LOOP;
END $clone$;

-- Fixed owner-only bodies are callable only from the fenced entries below.
-- Strip only this module's added release gates; every native credential,
-- principal, data, replay, quarantine and lock check remains byte-for-byte.
DO $inner$ DECLARE old_name text;new_name text;d text;needle text;callee text;replacement text;p record;BEGIN
 FOR old_name,new_name IN SELECT * FROM(VALUES
 ('runtime_authenticate_sensor','inner_authenticate_sensor'),
 ('runtime_reserve_batch_v15_internal','inner_reserve_batch_v15'),
 ('runtime_finalize_batch_v15_internal','inner_finalize_batch_v15'),
 ('runtime_commit_reserved_batch','inner_commit_reserved_batch'),
 ('runtime_reconcile_batch','inner_reconcile_batch')) names(old_name,new_name) LOOP
  SELECT pg_get_functiondef(oid) INTO STRICT d FROM pg_proc WHERE pronamespace='zasp_authorization80_runtime'::regnamespace AND proname=old_name;
  needle:='FUNCTION zasp_authorization80_runtime.'||old_name||'(';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime inner header changed';END IF;
  d:=replace(d,needle,'FUNCTION zasp_authorization80_runtime.'||new_name||'(');
  needle:='PERFORM zasp_authorization80_runtime.require_current();';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>regexp_count(d,'\mRETURN\M')+1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime inner fence count changed';END IF;
  d:=replace(d,needle,'');
  FOR callee,replacement IN SELECT * FROM(VALUES
   ('runtime_authenticate_sensor','inner_authenticate_sensor'),
   ('runtime_commit_reserved_batch','inner_commit_reserved_batch')) calls(callee,replacement)
   WHERE(old_name IN('runtime_reserve_batch_v15_internal','runtime_finalize_batch_v15_internal') AND calls.callee='runtime_authenticate_sensor')
    OR(old_name IN('runtime_finalize_batch_v15_internal','runtime_reconcile_batch') AND calls.callee='runtime_commit_reserved_batch') LOOP
   needle:='zasp_authorization80_runtime.'||callee||'(';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime inner call changed';END IF;
   d:=replace(d,needle,'zasp_authorization80_runtime.'||replacement||'(');
  END LOOP;
  EXECUTE d;
 END LOOP;
 FOR old_name,callee,replacement IN SELECT * FROM(VALUES
 ('runtime_reserve_batch_v17','runtime_authenticate_sensor','inner_authenticate_sensor'),
 ('runtime_reserve_batch_v17','runtime_reserve_batch_v15_internal','inner_reserve_batch_v15'),
 ('runtime_finalize_batch_v17','runtime_authenticate_sensor','inner_authenticate_sensor'),
 ('runtime_finalize_batch_v17','runtime_finalize_batch_v15_internal','inner_finalize_batch_v15'),
 ('runtime_sensor_heartbeat','runtime_authenticate_sensor','inner_authenticate_sensor'),
 ('runtime_lookup_acceptance','runtime_authenticate_sensor','inner_authenticate_sensor'),
 ('runtime_finish_reconciliation','runtime_reconcile_batch','inner_reconcile_batch')) calls(old_name,callee,replacement) LOOP
  SELECT pg_get_functiondef(oid) INTO STRICT d FROM pg_proc WHERE pronamespace='zasp_authorization80_runtime'::regnamespace AND proname=old_name;
  needle:='zasp_authorization80_runtime.'||callee||'(';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 OR d ~ ('\mRETURN\s+'||replace(needle,'(',E'\\(')) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime fenced inner call changed';END IF;
  EXECUTE replace(d,needle,'zasp_authorization80_runtime.'||replacement||'(');
 END LOOP;
 -- These owner-only void helpers already perform their full pinned source51
 -- gate and have no writes/returns. Do not add a second identical entry gate.
 FOR p IN SELECT oid FROM pg_proc WHERE pronamespace='zasp_authorization80_runtime'::regnamespace AND proname IN('runtime_precision_transport_ready','runtime_precision_reconciliation_ready') LOOP
  d:=pg_get_functiondef(p.oid);needle:='PERFORM zasp_authorization80_runtime.require_current();';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 OR regexp_count(d,'\mRETURN\M')<>0 OR regexp_count(d,'zasp_authorization80_runtime.source_ready\(51,')<>1 OR d ~* '\m(INSERT|UPDATE|DELETE|TRUNCATE)\M' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime void gate shape changed';END IF;
  EXECUTE replace(d,needle,'');
 END LOOP;
END $inner$;

-- Exact, body-only guard deltas. Trigger OIDs/bindings and every capability,
-- source tuple, hold and post-wait condition remain in the copied source.
DO $guards$ DECLARE n text;needle text;replacement text;expected integer;d text;BEGIN
 FOR n,needle,replacement,expected IN SELECT * FROM(VALUES
 ('zasp_runtime_precision_batch_insert_guard','zasp_production_runtime_precision_readiness(','zasp_authorization80_runtime.source_ready(51,',1),
 ('zasp_runtime_precision_batch_update_guard','zasp_runtime_precision_transport_ready()','zasp_authorization80_runtime.runtime_precision_transport_ready()',1),
 ('zasp_runtime_precision_stage_insert_guard','zasp_production_runtime_precision_readiness(','zasp_authorization80_runtime.source_ready(51,',1),
 ('zasp_runtime_precision_claim_version_guard','zasp_production_runtime_precision_readiness(','zasp_authorization80_runtime.source_ready(51,',1),
 ('zasp_runtime_precision_reconciliation_guard','zasp_production_runtime_precision_readiness(','zasp_authorization80_runtime.source_ready(51,',1),
 ('zasp_runtime_precision_outbox_guard','zasp_runtime_precision_transport_ready()','zasp_authorization80_runtime.runtime_precision_transport_ready()',1),
 ('zasp_runtime_precision_delivery_guard','zasp_runtime_precision_transport_ready()','zasp_authorization80_runtime.runtime_precision_transport_ready()',1),
 ('zasp_runtime_sandbox_search_mutation_guard','zasp_production_runtime_sandbox_binding_readiness(','zasp_authorization80_runtime.source_ready(50,',2),
 ('zasp_runtime_legacy_search_insert_guard','zasp_production_runtime_sandbox_binding_readiness(','zasp_authorization80_runtime.source_ready(50,',1)
 )changes(n,needle,replacement,expected) LOOP
  SELECT pg_get_functiondef(('public.'||n||'()')::regprocedure) INTO STRICT d;
  INSERT INTO zasp_authorization80_runtime.predecessor_functions SELECT oid::regprocedure::text,d,proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid=('public.'||n||'()')::regprocedure;
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='current runtime guard source rejected';END IF;
  EXECUTE replace(d,needle,replacement);
 END LOOP;
END $guards$;

-- One five-row stage insertion is one atomic statement. Keep the original
-- per-row source/implementation tuple validation; its full profile fence now
-- runs after all row and immediate FK waits, including on zero-row statements.
DO $stage_statement$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_precision_stage_insert_guard()'::regprocedure) INTO STRICT d;
 needle:=$gate$IF NOT COALESCE(zasp_authorization80_runtime.source_ready(51,(SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision authority unavailable';END IF;$gate$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime stage row gate changed';END IF;
 EXECUTE replace(d,needle,'');
END $stage_statement$;
CREATE FUNCTION zasp_authorization80_runtime.stage_insert_statement_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $stage_statement_guard$
BEGIN
 IF NOT COALESCE(zasp_authorization80_runtime.source_ready(51,(SELECT checksum FROM public.zasp_schema_versions WHERE version=51),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision authority unavailable';END IF;
 RETURN NULL;
END $stage_statement_guard$;
CREATE TRIGGER zasp_authorization80_runtime_stage_insert AFTER INSERT ON public.zasp_runtime_stage_work FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80_runtime.stage_insert_statement_guard();

-- runtime projection writer definitions

DO $owners$ DECLARE p regprocedure;BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_authorization80_runtime'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p);
 END LOOP;
END $owners$;
-- Narrow source ACLs are retained for entry points; owner-only internal leaves
-- never gain an execution grant from this module.
DO $grants$ DECLARE p record;a record;target text;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_runtime.predecessor_functions WHERE signature NOT LIKE '%guard()' LOOP
  target:='zasp_authorization80_runtime.'||substr(replace(p.signature,'public.',''),6);
  FOR a IN SELECT r.rolname FROM pg_proc f CROSS JOIN LATERAL aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) x JOIN pg_roles r ON r.oid=x.grantee WHERE f.oid=to_regprocedure(p.signature) AND x.privilege_type='EXECUTE' AND r.rolname IN('zasp_runtime_ingest','zasp_outbox_worker','zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker') LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I',target,a.rolname);
  END LOOP;
 END LOOP;
END $grants$;
GRANT USAGE ON SCHEMA zasp_authorization80_runtime TO zasp_runtime_ingest,zasp_outbox_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker;
GRANT EXECUTE ON FUNCTION zasp_authorization80_runtime.ready(text,text) TO zasp_runtime_ingest,zasp_outbox_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker;
GRANT EXECUTE ON FUNCTION zasp_authorization80_runtime.ingest_profile_identity(text) TO zasp_runtime_ingest;
INSERT INTO zasp_authorization80_runtime.registration VALUES(true,'-- runtime profile checksum',zasp_authorization80_runtime.fingerprint());
