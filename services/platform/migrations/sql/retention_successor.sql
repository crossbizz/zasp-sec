-- Exact separately pinned successor. Historical source and registrations are untouched.
-- Live catalog substitutions cover only this closed manifest and are themselves
-- independently bound to actual definitions/owners/ACL by fingerprint().
CREATE FUNCTION zasp_retention_v1.independent_seal(pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $seal$
 SELECT coalesce(pin='-- retention checksum' AND(SELECT count(*)=1 FROM zasp_retention_v1.activation) AND EXISTS(SELECT 1 FROM zasp_retention_v1.activation WHERE singleton AND checksum=pin AND successor_fingerprint=zasp_retention_v1.fingerprint()),false)
$seal$;
-- No parent readiness or stored catalog fingerprint is returned as live truth.
CREATE FUNCTION zasp_retention_v1.projected_definition(target oid) RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $definition$
 SELECT coalesce((SELECT definition FROM zasp_retention_v1.preimages WHERE target_oid=target AND kind='catalog'),pg_get_functiondef(target))
$definition$;
CREATE FUNCTION zasp_retention_v1.projected_source(target oid) RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $source$
 SELECT coalesce((SELECT source FROM zasp_retention_v1.preimages WHERE target_oid=target AND kind='catalog'),(SELECT prosrc FROM pg_proc WHERE oid=target))
$source$;
CREATE FUNCTION zasp_retention_v1.replace_exact(body text,needle text,replacement text,expected integer) RETURNS text LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $replace$
BEGIN
 IF needle IS NULL OR length(needle)=0 OR expected<1 OR(length(body)-length(replace(body,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention exact source anchor changed';END IF;
 RETURN replace(body,needle,replacement);
END $replace$;
CREATE FUNCTION zasp_retention_v1.effective_catalog_ready(pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $effective$
 SELECT zasp_retention_v1.independent_seal(pin) AND zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_runtime.catalog_ready() AND zasp_authorization80_runtime.current_ready()
$effective$;
-- These identities are captured only after the installer verified the complete
-- exact compiled Audit parent. No caller may supply a definition or target.
INSERT INTO zasp_retention_v1.preimages
 SELECT signature,p.oid,kind,pg_get_functiondef(p.oid),p.prosrc,p.proowner,p.proacl::text FROM(VALUES
 ('public.zasp_production_runtime_session_reads_live_fingerprint()','catalog'),
 ('zasp_temporal72.retained_precision_fingerprint()','catalog'),
 ('zasp_authorization80_worker.projected_domain()','catalog'),
 ('zasp_authorization80_worker.catalog_ready()','catalog'),
 ('zasp_temporal76.executor74_fingerprint()','catalog'),
 ('zasp_authorization80_temporal.projected68()','catalog'),
 ('zasp_authorization80_temporal.projected_domain()','catalog'),
 ('zasp_authorization80_temporal.fingerprint()','catalog'),
 ('zasp_temporal78.fingerprint()','catalog'),
 ('zasp_authorization79.fingerprint()','catalog'),
 ('zasp_temporal69.fingerprint()','catalog'),
 ('zasp_ordered_public62.fingerprint()','catalog'),
 ('zasp_authorization80_temporal.projected72()','catalog'),
 ('zasp_temporal68.predecessor_ready(text,text)','catalog'),
 ('zasp_temporal68.ready(text,text)','catalog'),
 ('zasp_temporal78.ready(text,text)','catalog'),
 ('zasp_temporal77.base67_fingerprint()','catalog'),
 ('zasp_authorization80_runtime.runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)','writer'),
 ('public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)','writer'),
 ('zasp_authorization80_runtime.runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)','writer'),
 ('public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)','writer'),
 ('zasp_authorization80_runtime.runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)','writer'),
 ('public.zasp_runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)','writer')
 ) manifest(signature,kind) JOIN pg_proc p ON p.oid=to_regprocedure(signature);
DO $preimages$ BEGIN
 IF(SELECT count(*) FROM zasp_retention_v1.preimages)<>23 OR EXISTS(SELECT 1 FROM zasp_retention_v1.preimages WHERE owner_oid<>'zasp_discovery_authority'::regrole) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention exact Audit preimage closure required';END IF;
END $preimages$;

-- Enforce every current original row NOT NULL/CHECK before skipping an expired
-- row. Canonical receipts, duplicate IDs, whole receipt IDs and native leases
-- stay in the complete original bodies. Unexpected constraint families refuse.
DO $validator$ DECLARE conditions text;predicate text;r record;d text;BEGIN
 -- PostgreSQL 18 also catalogs column NOT NULL constraints. Accept only
 -- their exact live attnotnull column; the validator below retains its check.
 IF EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid='public.zasp_runtime_session_events'::regclass AND(
  c.contype NOT IN('c','p','n') OR(c.contype='n' AND(
   cardinality(c.conkey) IS DISTINCT FROM 1 OR NOT EXISTS(
    SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.conrelid AND a.attnum=c.conkey[1] AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull
   )
  ))
 )) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention runtime constraint family changed';END IF;
 SELECT string_agg(format('%I IS NOT NULL',attname),' AND ' ORDER BY attnum) INTO conditions FROM pg_attribute WHERE attrelid='public.zasp_runtime_session_events'::regclass AND attnum>0 AND NOT attisdropped AND attnotnull;
 FOR r IN SELECT pg_get_expr(conbin,conrelid) expression FROM pg_constraint WHERE conrelid='public.zasp_runtime_session_events'::regclass AND contype='c' ORDER BY conname LOOP
  conditions:=conditions||' AND COALESCE(('||r.expression||'),true)';
 END LOOP;
 d:='CREATE FUNCTION zasp_retention_v1.validate_runtime_event(v public.zasp_runtime_session_events) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public SET timezone=''UTC'' AS '||quote_literal('SELECT '||conditions||' FROM(SELECT(v).*) AS item');
 EXECUTE d;
END $validator$;
CREATE FUNCTION zasp_retention_v1.skip_runtime_event(v public.zasp_runtime_session_events) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $skip$
DECLARE saved text;BEGIN
 IF NOT zasp_retention_v1.effective_catalog_ready('-- retention checksum') OR NOT coalesce(zasp_retention_v1.validate_runtime_event(v),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='retention runtime row validation rejected';END IF;
 SELECT source_digest INTO saved FROM zasp_retention_v1.tombstones WHERE(organization_id,workspace_id,environment_id,class,parent_id,source_id)=(v.organization_id,v.workspace_id,v.environment_id,'runtime_event','',v.event_id);
 IF NOT FOUND THEN RETURN false;END IF;
 IF saved IS DISTINCT FROM zasp_retention_v1.source_digest('runtime_event',to_jsonb(v)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='expired runtime event replay changed';END IF;
 RETURN true;
END $skip$;
DO $writers$ DECLARE p record;d text;new_name text;source_name text;BEGIN
 FOR p IN SELECT * FROM zasp_retention_v1.preimages WHERE kind='writer' ORDER BY signature LOOP
  source_name:=split_part(p.signature,'(',1);
  new_name:=CASE WHEN starts_with(source_name,'public.') THEN 'underlying_finish_'||substring(source_name FROM length('public.zasp_runtime_finish_')+1) ELSE 'current_finish_'||substring(source_name FROM length('zasp_authorization80_runtime.runtime_finish_')+1) END;
  d:=zasp_retention_v1.replace_exact(p.definition,'FUNCTION '||source_name||'(','FUNCTION zasp_retention_v1.'||new_name||'(',1);
  d:=zasp_retention_v1.replace_exact(d,'  ids:=array_append(ids,event_value.event_id);','  ids:=array_append(ids,event_value.event_id);'||chr(10)||'  IF zasp_retention_v1.skip_runtime_event(event_value) THEN CONTINUE;END IF;',1);
  -- All full receipts and original entry/exit fences are retained. The new
  -- ACTIVE seal is also checked even on exceptional non-row/no-item paths.
  d:=zasp_retention_v1.replace_exact(d,chr(10)||'BEGIN'||chr(10),chr(10)||'BEGIN'||chr(10)||' IF NOT zasp_retention_v1.caller_ready(''runtime-coordinator'',''-- retention checksum'') THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''active retention writer required'';END IF;'||chr(10),1);
  EXECUTE d;
  EXECUTE format('ALTER FUNCTION zasp_retention_v1.%I(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) SET timezone=''UTC''',new_name);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_retention_v1.%I(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) FROM PUBLIC',new_name);
  IF starts_with(new_name,'current_') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_retention_v1.%I(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) TO zasp_runtime_coordinator',new_name);END IF;
 END LOOP;
END $writers$;

CREATE FUNCTION zasp_retention_v1.source_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $guard$
DECLARE class_value text;id_value text;source_value text;scope_value jsonb;saved text;BEGIN
 IF NOT zasp_retention_v1.effective_catalog_ready('-- retention checksum') OR TG_OP NOT IN('INSERT','UPDATE') OR TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME NOT IN('zasp_runtime_session_events','zasp_inventory_evidence') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention source guard rejected';END IF;
 class_value:=CASE TG_TABLE_NAME WHEN 'zasp_runtime_session_events' THEN 'runtime_event' ELSE 'inventory_evidence' END;
 scope_value:=to_jsonb(NEW);id_value:=CASE class_value WHEN 'runtime_event' THEN scope_value->>'event_id' ELSE scope_value->>'id' END;
 SELECT source_digest INTO saved FROM zasp_retention_v1.tombstones WHERE(organization_id,workspace_id,environment_id,class,parent_id,source_id)=(scope_value->>'organization_id',scope_value->>'workspace_id',scope_value->>'environment_id',class_value,'',id_value);
 IF NOT FOUND THEN RETURN NEW;END IF;
 IF class_value='inventory_evidence' AND TG_OP='INSERT' AND saved=zasp_retention_v1.source_digest(class_value,scope_value) THEN RETURN NULL;END IF;
 RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='expired source identity cannot be restored';
END $guard$;

-- Construct candidate definitions from only the captured exact current family.
-- Metadata is projected for closed catalog targets; all unrelated metadata,
-- frames, original ACL checks and fallback branches remain live and unchanged.
DO $successors$ DECLARE p record;d text;s text;n text;expected integer;helper text;BEGIN
 FOR p IN SELECT * FROM zasp_retention_v1.preimages WHERE kind='catalog' ORDER BY signature LOOP
  s:=p.source;
  IF p.signature='public.zasp_production_runtime_session_reads_live_fingerprint()' THEN
   s:=zasp_retention_v1.replace_exact(s,'AND NOT tgisinternal','AND NOT tgisinternal AND NOT(tgrelid=''public.zasp_runtime_session_events''::regclass AND tgname=''zasp_000_retention_v1_runtime_event'')',1);
  ELSIF p.signature='zasp_temporal72.retained_precision_fingerprint()' THEN
   s:=zasp_retention_v1.replace_exact(s,'AND NOT t.tgisinternal','AND NOT t.tgisinternal AND NOT(t.tgrelid=''public.zasp_runtime_session_events''::regclass AND t.tgname=''zasp_000_retention_v1_runtime_event'')',1);
  ELSIF p.signature='zasp_authorization80_worker.projected_domain()' THEN
   s:=zasp_retention_v1.replace_exact(s,'WHERE NOT t.tgisinternal','WHERE NOT t.tgisinternal AND NOT(t.tgrelid=''public.zasp_inventory_evidence''::regclass AND t.tgname=''zasp_000_retention_v1_inventory_evidence'')',1);
  END IF;
  -- These are SQL bodies, never caller text or dynamic SQL. The bound parent
  -- source contains metadata reads; do not alter pg_proc ownership/ACL reads.
  s:=replace(s,'pg_get_functiondef(p.oid)','zasp_retention_v1.projected_definition(p.oid)');
  s:=replace(s,'pg_get_functiondef(procedure.oid)','zasp_retention_v1.projected_definition(procedure.oid)');
  s:=regexp_replace(s,'\mp[.]prosrc\M','zasp_retention_v1.projected_source(p.oid)','g');
  s:=regexp_replace(btrim(s),';[[:space:]]*$','');
  IF p.signature='zasp_authorization80_worker.catalog_ready()' THEN
   -- Full original inline catalog expression is retained and recomputed.
   s:='SELECT zasp_retention_v1.independent_seal(''-- retention checksum'') AND ('||s||')';
  ELSIF p.signature IN('zasp_temporal68.predecessor_ready(text,text)','zasp_temporal68.ready(text,text)','zasp_temporal78.ready(text,text)') THEN
   s:='SELECT zasp_retention_v1.independent_seal(''-- retention checksum'') AND ('||s||')';
  ELSE
   s:='SELECT CASE WHEN zasp_retention_v1.independent_seal(''-- retention checksum'') THEN ('||s||') ELSE NULL END';
  END IF;
  d:=zasp_retention_v1.replace_exact(p.definition,p.source,chr(10)||s||chr(10),1);
  INSERT INTO zasp_retention_v1.successors VALUES(p.signature,d);
 END LOOP;
END $successors$;

CREATE FUNCTION zasp_retention_v1.record_cutover(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $cutover$
DECLARE receipt_value text;database_value oid;BEGIN
 IF NOT zasp_authorization79.operator() OR NOT zasp_retention_v1.prepared_ready('-- retention checksum') OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['profile_checksum','release_digest','consumer_manifest_digest','deployment_evidence_digest','credential_withdrawal_digest']) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention cutover registration rejected';END IF;
 IF q->>'profile_checksum' IS DISTINCT FROM '-- retention checksum' OR EXISTS(SELECT 1 FROM jsonb_each(q) item WHERE jsonb_typeof(item.value)<>'string' OR item.value#>>'{}'!~'^[0-9a-f]{64}$') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='retention cutover digest rejected';END IF;
 SELECT oid INTO STRICT database_value FROM pg_database WHERE datname=current_database();
 receipt_value:=encode(digest(convert_to(jsonb_build_object('artifact',q,'database',current_database(),'database_oid',database_value,'parent_worker','-- retention worker checksum','parent_runtime','-- retention runtime checksum')::text,'UTF8'),'sha256'),'hex');
 INSERT INTO zasp_retention_v1.cutover_receipts VALUES(receipt_value,'-- retention checksum',current_database(),database_value,'-- retention worker checksum','-- retention runtime checksum',session_user::regrole,q,clock_timestamp()) ON CONFLICT DO NOTHING;
 RETURN jsonb_build_object('receipt_digest',receipt_value);
END $cutover$;
CREATE FUNCTION zasp_retention_v1.activate(pin text,receipt_value text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $activate$
DECLARE p record;r record;BEGIN
 IF NOT zasp_authorization79.operator() OR pin IS DISTINCT FROM '-- retention checksum' OR receipt_value IS NULL OR receipt_value!~'^[0-9a-f]{64}$' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention activation rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));
 IF EXISTS(SELECT 1 FROM zasp_retention_v1.activation) THEN
  IF NOT EXISTS(SELECT 1 FROM zasp_retention_v1.activation WHERE singleton AND checksum=pin AND cutover_digest=receipt_value) OR NOT zasp_retention_v1.effective_catalog_ready(pin) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention activation drift';END IF;RETURN true;
 END IF;
 IF NOT zasp_retention_v1.prepared_ready(pin) OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_authorization80_runtime.catalog_ready() OR NOT EXISTS(SELECT 1 FROM zasp_retention_v1.cutover_receipts c JOIN pg_database d ON(d.oid,d.datname)=(c.database_oid,c.database_name) WHERE c.receipt_digest=receipt_value AND c.profile_checksum=pin AND c.database_name=current_database() AND c.parent_worker='-- retention worker checksum' AND c.parent_runtime='-- retention runtime checksum') OR(SELECT count(*) FROM zasp_retention_v1.principals)<>4 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention prepared cutover evidence required';END IF;
 -- Exact live preimages are rechecked after the schema lock; never repair drift.
 FOR p IN SELECT * FROM zasp_retention_v1.preimages LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_proc f WHERE f.oid=p.target_oid AND pg_get_functiondef(f.oid)=p.definition AND f.proowner=p.owner_oid AND f.proacl::text IS NOT DISTINCT FROM p.acl) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention live predecessor changed';END IF;
 END LOOP;
 PERFORM zasp_retention_v1.install_product_guard();
 FOR p IN SELECT * FROM zasp_retention_v1.successors ORDER BY signature LOOP EXECUTE p.definition;END LOOP;
 CREATE TRIGGER zasp_000_retention_v1_runtime_event BEFORE INSERT OR UPDATE ON public.zasp_runtime_session_events FOR EACH ROW EXECUTE FUNCTION zasp_retention_v1.source_guard();
 CREATE TRIGGER zasp_000_retention_v1_inventory_evidence BEFORE INSERT OR UPDATE ON public.zasp_inventory_evidence FOR EACH ROW EXECUTE FUNCTION zasp_retention_v1.source_guard();
 SELECT login_name INTO STRICT r FROM zasp_retention_v1.principals WHERE purpose='runtime-index';
 EXECUTE format('GRANT USAGE ON SCHEMA zasp_retention_v1 TO %I',r.login_name);
 EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_retention_v1.cleanup_settle(jsonb) TO %I',r.login_name);
 INSERT INTO zasp_retention_v1.activation VALUES(true,pin,zasp_retention_v1.fingerprint(),receipt_value);
 IF NOT zasp_retention_v1.effective_catalog_ready(pin) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention successor catalog equivalence rejected';END IF;
 RETURN true;
END $activate$;
