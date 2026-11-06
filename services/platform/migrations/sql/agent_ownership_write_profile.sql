CREATE SCHEMA zasp_agent_ownership_write_v1 AUTHORIZATION zasp_discovery_authority;
-- ownership write authority definitions
REVOKE ALL ON SCHEMA zasp_agent_ownership_write_v1 FROM PUBLIC;
CREATE TABLE zasp_agent_ownership_write_v1.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),name text NOT NULL,checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),parent79 text NOT NULL,parent80 text NOT NULL,temporal text NOT NULL,audit text NOT NULL,identity text NOT NULL,fingerprint text NOT NULL);
ALTER TABLE zasp_agent_ownership_write_v1.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_agent_ownership_write_v1.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_agent_ownership_write_v1.registration FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_agent_ownership_write_v1.registration FROM PUBLIC,zasp_discovery_api;
CREATE POLICY authority ON zasp_agent_ownership_write_v1.registration TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_agent_ownership_write_v1.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE FUNCTION zasp_agent_ownership_write_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS (
 SELECT concat_ws('|','schema',nspowner,nspacl::text) FROM pg_namespace WHERE nspname='zasp_agent_ownership_write_v1'
 UNION ALL SELECT concat_ws('|','type',t.oid,t.typname,t.typowner,t.typacl::text,t.typtype,t.typcategory,t.typrelid,t.typelem,t.typarray,t.typbasetype,t.typisdefined,t.typnotnull,t.typndims,t.typcollation,t.typinput,t.typoutput,t.typreceive,t.typsend,t.typmodin,t.typmodout,t.typanalyze,t.typsubscript,t.typlen,t.typbyval,t.typalign,t.typstorage,t.typdelim,t.typdefaultbin::text,t.typdefault) FROM pg_type t WHERE t.typnamespace='zasp_agent_ownership_write_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_agent_ownership_write_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_agent_ownership_write_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_agent_ownership_write_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid WHERE c.relnamespace='zasp_agent_ownership_write_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','index',i.indexrelid::regclass::text,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_agent_ownership_write_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_agent_ownership_write_v1'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','policy',p.polrelid,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_agent_ownership_write_v1'::regnamespace
 ) SELECT encode(public.digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_agent_ownership_write_v1.catalog_ready(c text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE r zasp_agent_ownership_write_v1.registration;manifest_text constant text:=$ownership_write_manifest$-- ownership write function manifest$ownership_write_manifest$;p jsonb;f record;BEGIN
 SELECT * INTO r FROM zasp_agent_ownership_write_v1.registration WHERE singleton;
 IF NOT COALESCE(c='-- ownership write filter checksum' AND r.checksum=c AND r.name='-- ownership write filter name' AND r.parent79='-- ownership write parent79' AND r.parent80='-- ownership write parent80' AND r.temporal='-- ownership write temporal' AND r.audit='-- ownership write audit' AND r.identity='-- ownership write identity',false) THEN RETURN false;END IF;
 IF NOT zasp_authorization79.ready(r.parent79) OR NOT zasp_authorization80.ready(r.parent80) OR NOT zasp_authorization80_temporal.ready() OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_temporal.registration WHERE singleton AND checksum=r.temporal) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode='-- ownership write audit mode' AND identity_mode='-- ownership write identity mode') OR(SELECT count(*) FROM zasp_authorization80.runtime_profile)<>1 THEN RETURN false;END IF;
 -- ownership write selected parent predicate
 IF NOT public.zasp_inventory_security_ready() OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=14 AND name='typed_inventory_cutover' AND checksum='-- ownership write typed14') OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='typed_inventory_cutover_fingerprint' AND value='-- ownership write typed14 fingerprint') THEN RETURN false;END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(manifest_text::jsonb->'parents') LOOP
  SELECT x.*,l.lanname INTO STRICT f FROM pg_proc x JOIN pg_language l ON l.oid=x.prolang WHERE x.oid=(p->>'signature')::regprocedure;
  IF encode(public.digest(convert_to(f.prosrc,'UTF8'),'sha256'),'hex')<>p->>'source'
  OR f.proowner IS DISTINCT FROM CASE WHEN p->>'owner'='@registered-source' THEN (SELECT principal_name::regrole::oid FROM public.zasp_discovery_principal_bindings WHERE authority_role='zasp_discovery_authority') ELSE (p->>'owner')::regrole::oid END
  OR f.prosecdef IS DISTINCT FROM (p->>'secdef')::boolean
  OR f.proconfig IS DISTINCT FROM CASE WHEN (p->>'path')::boolean THEN ARRAY['search_path=pg_catalog, public'] ELSE NULL::text[] END
  OR f.proacl::text IS DISTINCT FROM p->>'acl' OR (COALESCE(p->>'volatility','')<>'' AND f.provolatile::text<>p->>'volatility') OR f.proisstrict IS DISTINCT FROM (p->>'strict')::boolean THEN RETURN false;END IF;
 END LOOP;
 IF(SELECT count(*) FROM pg_proc WHERE pronamespace='zasp_agent_ownership_write_v1'::regnamespace)<>5 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_agent_ownership_write_v1'::regnamespace AND relkind='r')<>1 OR EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='zasp_agent_ownership_write_v1'::regnamespace AND relkind NOT IN('r','i')) THEN RETURN false;END IF;

 -- Only the table's actual composite and implicit array belong to this profile.
 IF(SELECT count(*) FROM pg_type WHERE typnamespace='zasp_agent_ownership_write_v1'::regnamespace)<>2 OR NOT EXISTS(
  SELECT 1 FROM pg_class r JOIN pg_type c ON c.oid=r.reltype JOIN pg_type a ON a.oid=c.typarray
  WHERE r.oid='zasp_agent_ownership_write_v1.registration'::regclass AND c.typnamespace=r.relnamespace AND a.typnamespace=r.relnamespace
  AND c.typname='registration' AND a.typname='_registration' AND c.typowner='zasp_discovery_authority'::regrole AND a.typowner='zasp_discovery_authority'::regrole
  AND c.typacl IS NULL AND a.typacl IS NULL AND c.typtype='c' AND c.typcategory='C' AND c.typrelid=r.oid AND c.typelem=0
  AND a.typtype='b' AND a.typcategory='A' AND a.typrelid=0 AND a.typelem=c.oid AND a.typarray=0
  AND c.typisdefined AND a.typisdefined AND c.typbasetype=0 AND a.typbasetype=0 AND NOT c.typnotnull AND NOT a.typnotnull
  AND c.typndims=0 AND a.typndims=0 AND c.typdefaultbin IS NULL AND a.typdefaultbin IS NULL AND c.typdefault IS NULL AND a.typdefault IS NULL
 ) THEN RETURN false;END IF;
 -- These fixed PostgreSQL17 namespace catalogs have no profile objects.
 IF EXISTS(SELECT 1 FROM pg_operator WHERE oprnamespace='zasp_agent_ownership_write_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_collation WHERE collnamespace='zasp_agent_ownership_write_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_conversion WHERE connamespace='zasp_agent_ownership_write_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_opclass WHERE opcnamespace='zasp_agent_ownership_write_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_opfamily WHERE opfnamespace='zasp_agent_ownership_write_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_config WHERE cfgnamespace='zasp_agent_ownership_write_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_dict WHERE dictnamespace='zasp_agent_ownership_write_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_parser WHERE prsnamespace='zasp_agent_ownership_write_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_template WHERE tmplnamespace='zasp_agent_ownership_write_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_statistic_ext WHERE stxnamespace='zasp_agent_ownership_write_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_extension WHERE extnamespace='zasp_agent_ownership_write_v1'::regnamespace) THEN RETURN false;END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(manifest_text::jsonb->'own') LOOP
  SELECT x.*,l.lanname INTO STRICT f FROM pg_proc x JOIN pg_language l ON l.oid=x.prolang WHERE x.oid=(p->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR NOT f.prosecdef OR f.provolatile<>CASE WHEN f.proname IN('require_api','update_agent') THEN 'v'::"char" ELSE 's'::"char" END OR f.proparallel<>'u' OR f.proisstrict OR f.lanname NOT IN('sql','plpgsql') OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR encode(public.digest(convert_to(replace(replace(f.prosrc,c,'-- ownership write filter '||'checksum'),manifest_text,'-- ownership write function '||'manifest'),'UTF8'),'sha256'),'hex')<>p->>'source' THEN RETURN false;END IF;
  IF f.prokind<>'f' OR f.proretset OR f.proleakproof OR f.provariadic<>0 OR f.pronargdefaults<>0 OR f.proallargtypes IS NOT NULL OR f.proargmodes IS NOT NULL
  OR f.prorettype<>CASE f.proname WHEN 'fingerprint' THEN 'text'::regtype WHEN 'update_agent' THEN 'jsonb'::regtype WHEN 'require_api' THEN 'jsonb'::regtype ELSE 'boolean'::regtype END
  OR f.lanname<>CASE WHEN f.proname IN('fingerprint','caller_ready') THEN 'sql' ELSE 'plpgsql' END
  OR f.proargnames IS DISTINCT FROM CASE f.proname WHEN 'fingerprint' THEN NULL::text[] WHEN 'update_agent' THEN ARRAY['o','w','e','a','id','key','v','owner','team','tags','audit','correlation','c'] WHEN 'require_api' THEN ARRAY['o','w','e','a','id','c'] ELSE ARRAY['c'] END THEN RETURN false;END IF;
  IF EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee NOT IN(f.proowner,CASE WHEN f.proname IN('update_agent','caller_ready') THEN 'zasp_discovery_api'::regrole::oid ELSE f.proowner END)) OR NOT has_function_privilege(f.proowner,f.oid,'EXECUTE') OR(f.proname IN('update_agent','caller_ready') AND NOT has_function_privilege('zasp_discovery_api',f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_agent_ownership_write_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT((a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE')) OR(a.grantee='zasp_discovery_api'::regrole AND a.privilege_type='USAGE')))) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class t WHERE t.oid='zasp_agent_ownership_write_v1.registration'::regclass AND t.relowner='zasp_discovery_authority'::regrole AND t.relrowsecurity AND t.relforcerowsecurity AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable)) OR EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='zasp_agent_ownership_write_v1.registration'::regclass AND attacl IS NOT NULL) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_policy WHERE polrelid='zasp_agent_ownership_write_v1.registration'::regclass)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid='zasp_agent_ownership_write_v1.registration'::regclass AND polname='authority' AND polcmd='*' AND polpermissive AND polroles=ARRAY['zasp_discovery_authority'::regrole::oid] AND pg_get_expr(polqual,polrelid)='true' AND pg_get_expr(polwithcheck,polrelid)='true') THEN RETURN false;END IF;

 IF NOT has_schema_privilege('zasp_discovery_api','zasp_agent_ownership_write_v1','USAGE') OR has_schema_privilege('zasp_discovery_api','zasp_agent_ownership_write_v1','CREATE') THEN RETURN false;END IF;
 IF(SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute WHERE attrelid='zasp_agent_ownership_write_v1.registration'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM ARRAY['singleton','name','checksum','parent79','parent80','temporal','audit','identity','fingerprint'] THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_agent_ownership_write_v1.registration'::regclass AND a.attnum>0 AND NOT a.attisdropped AND(NOT a.attnotnull OR a.attidentity<>'' OR a.attgenerated<>'' OR a.attacl IS NOT NULL OR a.atttypid<>CASE WHEN a.attnum=1 THEN 'boolean'::regtype ELSE 'text'::regtype END OR(a.attnum=1 AND pg_get_expr(d.adbin,d.adrelid) IS DISTINCT FROM 'true') OR(a.attnum>1 AND d.oid IS NOT NULL))) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_constraint WHERE conrelid='zasp_agent_ownership_write_v1.registration'::regclass AND contype<>'n')<>3 OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_ownership_write_v1.registration'::regclass AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated) OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_ownership_write_v1.registration'::regclass AND contype='c' AND pg_get_expr(conbin,conrelid)='singleton' AND convalidated) OR EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_ownership_write_v1.registration'::regclass AND contype='n' AND(cardinality(conkey) IS DISTINCT FROM 1 OR NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=conrelid AND a.attnum=conkey[1] AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull))) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_constraint WHERE conrelid='zasp_agent_ownership_write_v1.registration'::regclass AND contype='c')<>2 OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_ownership_write_v1.registration'::regclass AND contype='c' AND convalidated AND pg_get_expr(conbin,conrelid)=$checksum_expr$(checksum ~ '^[a-f0-9]{64}$'::text)$checksum_expr$) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='zasp_agent_ownership_write_v1' AND nspowner='zasp_discovery_authority'::regrole) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_index WHERE indrelid='zasp_agent_ownership_write_v1.registration'::regclass)<>1 OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid='zasp_agent_ownership_write_v1.registration'::regclass AND indisprimary AND indisunique AND indisvalid AND indisready AND indkey::text='1') THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_trigger WHERE tgrelid='zasp_agent_ownership_write_v1.registration'::regclass AND NOT tgisinternal)<>1 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='zasp_agent_ownership_write_v1.registration'::regclass AND NOT tgisinternal AND tgname='immutable' AND tgenabled='O' AND tgtype=58 AND tgnargs=0 AND tgfoid='zasp_temporal67.immutable()'::regprocedure) THEN RETURN false;END IF;
 RETURN r.fingerprint=zasp_agent_ownership_write_v1.fingerprint();
EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_agent_ownership_write_v1.caller_ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_agent_ownership_write_v1.catalog_ready(c) AND public.zasp_discovery_principal_ready('zasp_discovery_api')
$$;
-- The current proof is the sole authority; private helper invocation by a
-- source LOGIN or worker cannot manufacture a registered API session or seal.
CREATE FUNCTION zasp_agent_ownership_write_v1.require_api(o text,w text,e text,a text,id text,c text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;r jsonb;t jsonb;BEGIN
 p:=zasp_authorization80.context();r:=p->'revision';t:=p->'targets'->0;
 IF NOT COALESCE(zasp_agent_ownership_write_v1.caller_ready(c)
 AND(p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id',p->>'operation_id',p->>'permission')=(o,w,e,a,'updateAgent','manage_workflows')
 AND p->>'credential_kind' IN('1','2') AND p->'fresh_auth'='false'::jsonb AND p->'collection'='false'::jsonb
 AND p->'path_parameters'=jsonb_build_object('id',id) AND jsonb_array_length(p->'targets')=1 AND p->'allowed'=p->'targets'
 AND(t->>'organization_id',t->>'workspace_id',t->>'environment_id',t->>'kind',t->>'id',COALESCE(NULLIF(t->>'source_id',''),t->>'id'))=(o,w,e,'agent',id,id)
 AND zasp_authorization80.allowed(o,w,e,'agent',id),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current agent ownership authority required';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['updateAgent'],'manage_workflows',false,a);
 PERFORM zasp_authorization79.revalidate(o,(r->>'desired')::bigint,(r->>'generation')::bigint,r->>'store_id',r->>'model_id');
 PERFORM zasp_authorization80.identity_fence(p);
 IF zasp_agent_ownership_write_v1.caller_ready(c) IS NOT TRUE OR zasp_authorization80.context() IS DISTINCT FROM p THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent ownership authority expired';END IF;
 RETURN p;
END
$$;
CREATE FUNCTION zasp_agent_ownership_write_v1.update_agent(o text,w text,e text,a text,id text,key text,v bigint,owner text,team text,tags jsonb,audit text,correlation text,c text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;result jsonb;BEGIN
 p:=zasp_agent_ownership_write_v1.require_api(o,w,e,a,id,c);
 -- Validate the exact canonical bounds before acquiring additional locks. Null
 -- values also fail here, rather than borrowing SQL three-valued input logic.
 IF o IS NULL OR w IS NULL OR e IS NULL OR a IS NULL OR id IS NULL OR key IS NULL OR v IS NULL OR owner IS NULL OR team IS NULL OR tags IS NULL OR audit IS NULL OR correlation IS NULL
 OR NOT public.zasp_valid_product_id(o) OR NOT public.zasp_valid_product_id(w) OR NOT public.zasp_valid_product_id(e) OR NOT public.zasp_valid_product_id(a) OR NOT public.zasp_valid_product_id(id) OR NOT public.zasp_valid_product_id(audit) OR NOT public.zasp_valid_product_id(correlation)
 OR key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' OR v NOT BETWEEN 1 AND 999999
 OR length(owner) NOT BETWEEN 1 AND 128 OR owner<>btrim(owner) OR owner~'[[:cntrl:]]'
 OR length(team) NOT BETWEEN 1 AND 128 OR team<>btrim(team) OR team~'[[:cntrl:]]'
 OR jsonb_typeof(tags)<>'array' OR jsonb_array_length(tags)>32 OR octet_length(tags::text)>4096
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(tags) tag WHERE jsonb_typeof(tag)<>'string' OR length(tag#>>'{}') NOT BETWEEN 1 AND 64 OR tag#>>'{}'<>btrim(tag#>>'{}') OR tag#>>'{}'~'[[:cntrl:]]')
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(tags) WITH ORDINALITY prior(tag,position) JOIN jsonb_array_elements_text(tags) WITH ORDINALITY following(tag,position) ON following.position=prior.position+1 WHERE prior.tag>=following.tag)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid current agent ownership mutation';END IF;
 -- The outer80 fence already holds79 organization FOR UPDATE and target FOR
 -- SHARE. Preserve canonical principal/scope/key advisory -> active row order;
 -- trusted legacy writers may still conflict and must roll back/fresh-check.
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,a,'updateAgent',key),0));
 PERFORM 1 FROM public.zasp_inventory_entities entity WHERE(entity.organization_id,entity.workspace_id,entity.environment_id,entity.id,entity.state,entity.product_kind)=(o,w,e,id,'active','agent') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='current ownership agent missing';END IF;
 -- No annotation-version predicate here: same-intent canonical replay must be
 -- admitted with its original expected version, after fresh authority checks.
 p:=zasp_agent_ownership_write_v1.require_api(o,w,e,a,id,c);
 result:=public.zasp_inventory_update_agent(o,w,e,a,id,key,v,owner,team,tags,audit,correlation);
 -- Original posture refresh may INSERT a finding and advance79desired inside
 -- this transaction. Revalidating the OLD revision here would reject that real
 -- effect. Retain the original held79 lock; check live identity/expiry/catalog.
 PERFORM zasp_authorization80.identity_fence(p);
 IF zasp_authorization80.context() IS DISTINCT FROM p OR zasp_agent_ownership_write_v1.caller_ready(c) IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent ownership authority changed';END IF;
 RETURN result;
END
$$;
DO $owners$ DECLARE f regprocedure;BEGIN
 FOR f IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_agent_ownership_write_v1'::regnamespace LOOP
 EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api',f);END LOOP;
END $owners$;
GRANT USAGE ON SCHEMA zasp_agent_ownership_write_v1 TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_agent_ownership_write_v1.update_agent(text,text,text,text,text,text,bigint,text,text,jsonb,text,text,text),zasp_agent_ownership_write_v1.caller_ready(text) TO zasp_discovery_api;
