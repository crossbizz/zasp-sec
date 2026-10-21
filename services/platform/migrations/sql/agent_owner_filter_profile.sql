CREATE SCHEMA zasp_agent_owner_filter_v1 AUTHORIZATION zasp_discovery_authority;
-- owner authority definitions
REVOKE ALL ON SCHEMA zasp_agent_owner_filter_v1 FROM PUBLIC;
CREATE TABLE zasp_agent_owner_filter_v1.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),name text NOT NULL,checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),parent79 text NOT NULL,parent80 text NOT NULL,temporal text NOT NULL,audit text NOT NULL,identity text NOT NULL,fingerprint text NOT NULL);
ALTER TABLE zasp_agent_owner_filter_v1.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_agent_owner_filter_v1.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_agent_owner_filter_v1.registration FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_agent_owner_filter_v1.registration FROM PUBLIC,zasp_discovery_api;
CREATE POLICY authority ON zasp_agent_owner_filter_v1.registration TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_agent_owner_filter_v1.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE FUNCTION zasp_agent_owner_filter_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS (
 SELECT concat_ws('|','schema',nspowner,nspacl::text) FROM pg_namespace WHERE nspname='zasp_agent_owner_filter_v1'
 UNION ALL SELECT concat_ws('|','type',t.oid,t.typname,t.typowner,t.typacl::text,t.typtype,t.typcategory,t.typrelid,t.typelem,t.typarray,t.typbasetype,t.typisdefined,t.typnotnull,t.typndims,t.typcollation,t.typinput,t.typoutput,t.typreceive,t.typsend,t.typmodin,t.typmodout,t.typanalyze,t.typsubscript,t.typlen,t.typbyval,t.typalign,t.typstorage,t.typdelim,t.typdefaultbin::text,t.typdefault) FROM pg_type t WHERE t.typnamespace='zasp_agent_owner_filter_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_agent_owner_filter_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_agent_owner_filter_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_agent_owner_filter_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid WHERE c.relnamespace='zasp_agent_owner_filter_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','index',i.indexrelid::regclass::text,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_agent_owner_filter_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_agent_owner_filter_v1'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','policy',p.polrelid,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_agent_owner_filter_v1'::regnamespace
 ) SELECT encode(public.digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_agent_owner_filter_v1.catalog_ready(c text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE r zasp_agent_owner_filter_v1.registration;manifest_text constant text:=$owner_manifest$-- owner function manifest$owner_manifest$;p jsonb;f record;BEGIN
 SELECT * INTO r FROM zasp_agent_owner_filter_v1.registration WHERE singleton;
 IF NOT COALESCE(c='-- owner filter checksum' AND r.checksum=c AND r.name='-- owner filter name' AND r.parent79='-- owner parent79' AND r.parent80='-- owner parent80' AND r.temporal='-- owner temporal' AND r.audit='-- owner audit' AND r.identity='-- owner identity',false) THEN RETURN false;END IF;
 IF NOT zasp_authorization79.ready(r.parent79) OR NOT zasp_authorization80.ready(r.parent80) OR NOT zasp_authorization80_temporal.ready() OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_temporal.registration WHERE singleton AND checksum=r.temporal) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode='-- owner audit mode' AND identity_mode='-- owner identity mode') OR(SELECT count(*) FROM zasp_authorization80.runtime_profile)<>1 THEN RETURN false;END IF;
 -- owner selected parent predicate
 IF NOT public.zasp_inventory_security_ready() OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=14 AND name='typed_inventory_cutover' AND checksum='-- owner typed14') OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='typed_inventory_cutover_fingerprint' AND value='-- owner typed14 fingerprint') THEN RETURN false;END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(manifest_text::jsonb->'parents') LOOP
  SELECT x.*,l.lanname INTO STRICT f FROM pg_proc x JOIN pg_language l ON l.oid=x.prolang WHERE x.oid=(p->>'signature')::regprocedure;
  IF encode(public.digest(convert_to(f.prosrc,'UTF8'),'sha256'),'hex')<>p->>'source' OR f.proowner::regrole::text<>p->>'owner' OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR f.proacl::text IS DISTINCT FROM p->>'acl' THEN RETURN false;END IF;
 END LOOP;
 IF(SELECT count(*) FROM pg_proc WHERE pronamespace='zasp_agent_owner_filter_v1'::regnamespace)<>4 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_agent_owner_filter_v1'::regnamespace AND relkind='r')<>1 OR EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='zasp_agent_owner_filter_v1'::regnamespace AND relkind NOT IN('r','i')) THEN RETURN false;END IF;

 -- Only the table's actual composite and implicit array belong to this profile.
 IF(SELECT count(*) FROM pg_type WHERE typnamespace='zasp_agent_owner_filter_v1'::regnamespace)<>2 OR NOT EXISTS(
  SELECT 1 FROM pg_class r JOIN pg_type c ON c.oid=r.reltype JOIN pg_type a ON a.oid=c.typarray
  WHERE r.oid='zasp_agent_owner_filter_v1.registration'::regclass AND c.typnamespace=r.relnamespace AND a.typnamespace=r.relnamespace
  AND c.typname='registration' AND a.typname='_registration' AND c.typowner='zasp_discovery_authority'::regrole AND a.typowner='zasp_discovery_authority'::regrole
  AND c.typacl IS NULL AND a.typacl IS NULL AND c.typtype='c' AND c.typcategory='C' AND c.typrelid=r.oid AND c.typelem=0
  AND a.typtype='b' AND a.typcategory='A' AND a.typrelid=0 AND a.typelem=c.oid AND a.typarray=0
  AND c.typisdefined AND a.typisdefined AND c.typbasetype=0 AND a.typbasetype=0 AND NOT c.typnotnull AND NOT a.typnotnull
  AND c.typndims=0 AND a.typndims=0 AND c.typdefaultbin IS NULL AND a.typdefaultbin IS NULL AND c.typdefault IS NULL AND a.typdefault IS NULL
 ) THEN RETURN false;END IF;
 -- These fixed PostgreSQL17 namespace catalogs have no profile objects.
 IF EXISTS(SELECT 1 FROM pg_operator WHERE oprnamespace='zasp_agent_owner_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_collation WHERE collnamespace='zasp_agent_owner_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_conversion WHERE connamespace='zasp_agent_owner_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_opclass WHERE opcnamespace='zasp_agent_owner_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_opfamily WHERE opfnamespace='zasp_agent_owner_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_config WHERE cfgnamespace='zasp_agent_owner_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_dict WHERE dictnamespace='zasp_agent_owner_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_parser WHERE prsnamespace='zasp_agent_owner_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_template WHERE tmplnamespace='zasp_agent_owner_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_statistic_ext WHERE stxnamespace='zasp_agent_owner_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_extension WHERE extnamespace='zasp_agent_owner_filter_v1'::regnamespace) THEN RETURN false;END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(manifest_text::jsonb->'own') LOOP
  SELECT x.*,l.lanname INTO STRICT f FROM pg_proc x JOIN pg_language l ON l.oid=x.prolang WHERE x.oid=(p->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR NOT f.prosecdef OR f.provolatile<>'s' OR f.proparallel<>'u' OR f.proisstrict OR f.lanname NOT IN('sql','plpgsql') OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR encode(public.digest(convert_to(replace(replace(f.prosrc,c,'-- owner filter '||'checksum'),manifest_text,'-- owner function '||'manifest'),'UTF8'),'sha256'),'hex')<>p->>'source' THEN RETURN false;END IF;
  IF f.prokind<>'f' OR f.proretset OR f.proleakproof OR f.provariadic<>0 OR f.pronargdefaults<>0 OR f.proallargtypes IS NOT NULL OR f.proargmodes IS NOT NULL
  OR f.prorettype<>CASE f.proname WHEN 'fingerprint' THEN 'text'::regtype WHEN 'page' THEN 'jsonb'::regtype ELSE 'boolean'::regtype END
  OR f.lanname<>CASE WHEN f.proname IN('fingerprint','caller_ready') THEN 'sql' ELSE 'plpgsql' END
  OR f.proargnames IS DISTINCT FROM CASE f.proname WHEN 'fingerprint' THEN NULL::text[] WHEN 'page' THEN ARRAY['o','w','e','a','n','q','c'] ELSE ARRAY['c'] END THEN RETURN false;END IF;
  IF EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee NOT IN(f.proowner,CASE WHEN f.proname IN('page','caller_ready') THEN 'zasp_discovery_api'::regrole::oid ELSE f.proowner END)) OR NOT has_function_privilege(f.proowner,f.oid,'EXECUTE') OR(f.proname IN('page','caller_ready') AND NOT has_function_privilege('zasp_discovery_api',f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_agent_owner_filter_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT((a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE')) OR(a.grantee='zasp_discovery_api'::regrole AND a.privilege_type='USAGE')))) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class t WHERE t.oid='zasp_agent_owner_filter_v1.registration'::regclass AND t.relowner='zasp_discovery_authority'::regrole AND t.relrowsecurity AND t.relforcerowsecurity AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable)) OR EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='zasp_agent_owner_filter_v1.registration'::regclass AND attacl IS NOT NULL) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_policy WHERE polrelid='zasp_agent_owner_filter_v1.registration'::regclass)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid='zasp_agent_owner_filter_v1.registration'::regclass AND polname='authority' AND polcmd='*' AND polpermissive AND polroles=ARRAY['zasp_discovery_authority'::regrole::oid] AND pg_get_expr(polqual,polrelid)='true' AND pg_get_expr(polwithcheck,polrelid)='true') THEN RETURN false;END IF;

 IF NOT has_schema_privilege('zasp_discovery_api','zasp_agent_owner_filter_v1','USAGE') OR has_schema_privilege('zasp_discovery_api','zasp_agent_owner_filter_v1','CREATE') THEN RETURN false;END IF;
 IF(SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute WHERE attrelid='zasp_agent_owner_filter_v1.registration'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM ARRAY['singleton','name','checksum','parent79','parent80','temporal','audit','identity','fingerprint'] THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_agent_owner_filter_v1.registration'::regclass AND a.attnum>0 AND NOT a.attisdropped AND(NOT a.attnotnull OR a.attidentity<>'' OR a.attgenerated<>'' OR a.attacl IS NOT NULL OR a.atttypid<>CASE WHEN a.attnum=1 THEN 'boolean'::regtype ELSE 'text'::regtype END OR(a.attnum=1 AND pg_get_expr(d.adbin,d.adrelid) IS DISTINCT FROM 'true') OR(a.attnum>1 AND d.oid IS NOT NULL))) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_constraint WHERE conrelid='zasp_agent_owner_filter_v1.registration'::regclass AND contype<>'n')<>3 OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_owner_filter_v1.registration'::regclass AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated) OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_owner_filter_v1.registration'::regclass AND contype='c' AND pg_get_expr(conbin,conrelid)='singleton' AND convalidated) OR EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_owner_filter_v1.registration'::regclass AND contype='n' AND(cardinality(conkey) IS DISTINCT FROM 1 OR NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=conrelid AND a.attnum=conkey[1] AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull))) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_constraint WHERE conrelid='zasp_agent_owner_filter_v1.registration'::regclass AND contype='c')<>2 OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_owner_filter_v1.registration'::regclass AND contype='c' AND convalidated AND pg_get_expr(conbin,conrelid)=$checksum_expr$(checksum ~ '^[a-f0-9]{64}$'::text)$checksum_expr$) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='zasp_agent_owner_filter_v1' AND nspowner='zasp_discovery_authority'::regrole) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_index WHERE indrelid='zasp_agent_owner_filter_v1.registration'::regclass)<>1 OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid='zasp_agent_owner_filter_v1.registration'::regclass AND indisprimary AND indisunique AND indisvalid AND indisready AND indkey::text='1') THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_trigger WHERE tgrelid='zasp_agent_owner_filter_v1.registration'::regclass AND NOT tgisinternal)<>1 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='zasp_agent_owner_filter_v1.registration'::regclass AND NOT tgisinternal AND tgname='immutable' AND tgenabled='O' AND tgtype=58 AND tgnargs=0 AND tgfoid='zasp_temporal67.immutable()'::regprocedure) THEN RETURN false;END IF;
 RETURN r.fingerprint=zasp_agent_owner_filter_v1.fingerprint();
EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_agent_owner_filter_v1.caller_ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_agent_owner_filter_v1.catalog_ready(c) AND public.zasp_discovery_principal_ready('zasp_discovery_api')
$$;
CREATE FUNCTION zasp_agent_owner_filter_v1.page(o text,w text,e text,a text,n integer,q text,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;BEGIN
 IF NOT zasp_agent_owner_filter_v1.caller_ready(c) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent owner profile unavailable';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listAgents'],'view');
 IF o IS NULL OR w IS NULL OR e IS NULL OR n IS NULL OR NOT public.zasp_valid_product_id(o) OR NOT public.zasp_valid_product_id(w) OR NOT public.zasp_valid_product_id(e) OR a IS NOT NULL AND NOT public.zasp_valid_product_id(a) OR n NOT BETWEEN 1 AND 100 OR q IS NULL OR char_length(q)>128 OR octet_length(q)>512 OR q~'[\x01-\x1F\x7F]' OR public.zasp_inventory_scope_state(o,w,e)->>'phase' IS DISTINCT FROM 'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid agent owner page';END IF;
 WITH candidates AS(SELECT id FROM public.zasp_inventory_entities v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.state,v.product_kind)=(o,w,e,'active','agent') AND(a IS NULL OR id>a) AND zasp_authorization80.allowed(o,w,e,'agent',id) AND(public.zasp_inventory_annotation_value(o,w,e,id)->>'owner') COLLATE "C"=q COLLATE "C" ORDER BY id LIMIT n+1),visible AS(SELECT id FROM candidates ORDER BY id LIMIT n)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(public.zasp_inventory_detail(o,w,e,id,'agent')->'summary' ORDER BY id) FROM visible),'[]'::jsonb),'next_id',CASE WHEN(SELECT count(*) FROM candidates)>n THEN(SELECT max(id) FROM visible) END) INTO result;
 RETURN result;END
$$;
DO $owners$ DECLARE f regprocedure;BEGIN
 FOR f IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_agent_owner_filter_v1'::regnamespace LOOP
 EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api',f);END LOOP;
END $owners$;
GRANT USAGE ON SCHEMA zasp_agent_owner_filter_v1 TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_agent_owner_filter_v1.page(text,text,text,text,integer,text,text),zasp_agent_owner_filter_v1.caller_ready(text) TO zasp_discovery_api;
